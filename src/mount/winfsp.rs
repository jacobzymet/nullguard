//! Windows adapter: serves a vault as a drive letter through WinFsp
//! (<https://winfsp.dev>), the Windows counterpart of FUSE.
//!
//! WinFsp is installed separately by the user. Its DLL is loaded at run
//! time from WinFsp's install folder (read from the registry, which only
//! administrators can change), so nullguard runs without WinFsp and only
//! `mount` needs it. The bindings to WinFsp's C interface are our own and
//! cover only what nullguard uses; together with `platform.rs`, this is the
//! only module with `unsafe` code. Each WinFsp callback is a thin shim that
//! turns WinFsp's pointers into ordinary Rust values and then calls the
//! same `Fs` operations the FUSE adapter uses.
//!
//! Deliberately minimal: plain files and directories only. No alternate
//! data streams, extended attributes, reparse points or stored Windows
//! permissions. Symbolic links in a vault (made on Linux or macOS) and names
//! Windows can't represent are not shown. Every file has one fixed security
//! descriptor that gives the mounting user full access and nobody else any,
//! and keeps low-integrity (sandboxed) processes out.

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, HANDLE, LocalFree, NTSTATUS, STATUS_ACCESS_DENIED, STATUS_BUFFER_OVERFLOW,
    STATUS_DIRECTORY_NOT_EMPTY, STATUS_DISK_FULL, STATUS_END_OF_FILE, STATUS_FILE_CORRUPT_ERROR,
    STATUS_FILE_IS_A_DIRECTORY, STATUS_FILE_TOO_LARGE, STATUS_INVALID_PARAMETER, STATUS_IO_DEVICE_ERROR,
    STATUS_MEDIA_WRITE_PROTECTED, STATUS_NAME_TOO_LONG, STATUS_NOT_A_DIRECTORY, STATUS_OBJECT_NAME_COLLISION,
    STATUS_OBJECT_NAME_INVALID, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND, STATUS_SUCCESS,
    WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
};
use windows_sys::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RRF_SUBKEY_WOW6432KEY, RegGetValueW};
use windows_sys::Win32::System::Threading::{
    CreateEventW, EVENT_MODIFY_STATE, GetCurrentProcess, OpenEventW, OpenProcessToken, SetEvent, WaitForSingleObject,
};

use super::MountOptions;
use crate::vault::Error;
use crate::vault::fs::{Attr, Fs, Kind, ROOT_INO, SetAttr, Timestamp};

const INSTALL_HINT: &str = "WinFsp is needed to mount vaults on Windows. Install it from https://winfsp.dev \
     (free), then try again. Without it, use `nullguard ls`, `get`, `put`, `rm` and `mkdir`.";

// ----------------------------------------------------------------------
// WinFsp's C interface (winfsp.h / fsctl.h, WinFsp 2.x): only what we use
// ----------------------------------------------------------------------

/// `FSP_FILE_SYSTEM *`: only ever passed back to WinFsp.
type FspFs = *mut c_void;
/// A NUL-terminated UTF-16 string from WinFsp.
type Wstr = *const u16;

/// `FSP_FSCTL_FILE_INFO`
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FileInfo {
    file_attributes: u32,
    reparse_tag: u32,
    allocation_size: u64,
    file_size: u64,
    creation_time: u64,
    last_access_time: u64,
    last_write_time: u64,
    change_time: u64,
    index_number: u64,
    hard_links: u32,
    ea_size: u32,
}

/// `FSP_FSCTL_VOLUME_INFO`
#[repr(C)]
struct VolumeInfo {
    total_size: u64,
    free_size: u64,
    volume_label_length: u16,
    volume_label: [u16; 32],
}

/// `FSP_FSCTL_DIR_INFO`, with room for the longest name a vault allows.
#[repr(C)]
struct DirInfo {
    size: u16,
    file_info: FileInfo,
    padding: [u8; 24],
    name: [u16; 255],
}

/// `FSP_FSCTL_VOLUME_PARAMS` (the full, current version).
#[repr(C)]
struct VolumeParams {
    version: u16,
    sector_size: u16,
    sectors_per_allocation_unit: u16,
    max_component_length: u16,
    volume_creation_time: u64,
    volume_serial_number: u32,
    transact_timeout: u32,
    irp_timeout: u32,
    irp_capacity: u32,
    file_info_timeout: u32,
    flags: u32,
    prefix: [u16; 192],
    file_system_name: [u16; 16],
    flags2: u32,
    volume_info_timeout: u32,
    dir_info_timeout: u32,
    security_timeout: u32,
    stream_info_timeout: u32,
    ea_timeout: u32,
    fsext_control_code: u32,
    reserved32: [u32; 1],
    reserved64: [u64; 2],
}

// Bits of `VolumeParams::flags` (C bit fields, lowest bit first).
const CASE_SENSITIVE_SEARCH: u32 = 1 << 0;
const CASE_PRESERVED_NAMES: u32 = 1 << 1;
const UNICODE_ON_DISK: u32 = 1 << 2;
const PERSISTENT_ACLS: u32 = 1 << 3;
const READ_ONLY_VOLUME: u32 = 1 << 9;
/// Keep closed files' contents off Windows' standby list (less plaintext
/// lingering in RAM).
const FLUSH_AND_PURGE_ON_CLEANUP: u32 = 1 << 14;
/// The `FileContext` WinFsp passes us is the per-handle value we returned.
const UM_FILE_CONTEXT_IS_USER_CONTEXT2: u32 = 1 << 16;

/// `FSP_FILE_SYSTEM_INTERFACE`: 64 slots; the ones we leave empty make
/// WinFsp answer "not supported" (streams, reparse points, EAs, ioctls...).
#[repr(C)]
struct Interface {
    get_volume_info: Option<unsafe extern "C" fn(FspFs, *mut VolumeInfo) -> NTSTATUS>,
    set_volume_label: Option<unsafe extern "C" fn()>,
    get_security_by_name: Option<unsafe extern "C" fn(FspFs, Wstr, *mut u32, *mut c_void, *mut usize) -> NTSTATUS>,
    create: Option<
        unsafe extern "C" fn(FspFs, Wstr, u32, u32, u32, *mut c_void, u64, *mut *mut c_void, *mut FileInfo) -> NTSTATUS,
    >,
    open: Option<unsafe extern "C" fn(FspFs, Wstr, u32, u32, *mut *mut c_void, *mut FileInfo) -> NTSTATUS>,
    overwrite: Option<unsafe extern "C" fn(FspFs, *mut c_void, u32, u8, u64, *mut FileInfo) -> NTSTATUS>,
    cleanup: Option<unsafe extern "C" fn(FspFs, *mut c_void, Wstr, u32)>,
    close: Option<unsafe extern "C" fn(FspFs, *mut c_void)>,
    read: Option<unsafe extern "C" fn(FspFs, *mut c_void, *mut c_void, u64, u32, *mut u32) -> NTSTATUS>,
    write:
        Option<unsafe extern "C" fn(FspFs, *mut c_void, *mut c_void, u64, u32, u8, u8, *mut u32, *mut FileInfo) -> NTSTATUS>,
    flush: Option<unsafe extern "C" fn(FspFs, *mut c_void, *mut FileInfo) -> NTSTATUS>,
    get_file_info: Option<unsafe extern "C" fn(FspFs, *mut c_void, *mut FileInfo) -> NTSTATUS>,
    set_basic_info: Option<unsafe extern "C" fn(FspFs, *mut c_void, u32, u64, u64, u64, u64, *mut FileInfo) -> NTSTATUS>,
    set_file_size: Option<unsafe extern "C" fn(FspFs, *mut c_void, u64, u8, *mut FileInfo) -> NTSTATUS>,
    can_delete: Option<unsafe extern "C" fn(FspFs, *mut c_void, Wstr) -> NTSTATUS>,
    rename: Option<unsafe extern "C" fn(FspFs, *mut c_void, Wstr, Wstr, u8) -> NTSTATUS>,
    get_security: Option<unsafe extern "C" fn(FspFs, *mut c_void, *mut c_void, *mut usize) -> NTSTATUS>,
    set_security: Option<unsafe extern "C" fn()>,
    read_directory: Option<unsafe extern "C" fn(FspFs, *mut c_void, Wstr, Wstr, *mut c_void, u32, *mut u32) -> NTSTATUS>,
    unused: [Option<unsafe extern "C" fn()>; 45],
}

// The layouts must match WinFsp's exactly (these sizes are asserted in its
// own headers too).
const _: () = assert!(size_of::<FileInfo>() == 72);
const _: () = assert!(size_of::<VolumeInfo>() == 88);
const _: () = assert!(std::mem::offset_of!(DirInfo, name) == 104);
const _: () = assert!(size_of::<VolumeParams>() == 504);
const _: () = assert!(size_of::<Interface>() == 64 * size_of::<usize>());

// The WinFsp DLL functions we call, with their exact C signatures.
type RawFn = unsafe extern "system" fn() -> isize;
type CreateFn = unsafe extern "C" fn(*const u16, *const VolumeParams, *const Interface, *mut FspFs) -> NTSTATUS;
type DeleteFn = unsafe extern "C" fn(FspFs);
type SetMountPointFn = unsafe extern "C" fn(FspFs, *const u16) -> NTSTATUS;
type StartDispatcherFn = unsafe extern "C" fn(FspFs, u32) -> NTSTATUS;
type StopDispatcherFn = unsafe extern "C" fn(FspFs);
type AddDirInfoFn = unsafe extern "C" fn(*mut DirInfo, *mut c_void, u32, *mut u32) -> u8;

struct Api {
    create: CreateFn,
    delete: DeleteFn,
    set_mount_point: SetMountPointFn,
    start_dispatcher: StartDispatcherFn,
    stop_dispatcher: StopDispatcherFn,
    add_dir_info: AddDirInfoFn,
}

impl Api {
    /// Load WinFsp's DLL by full path from its install folder.
    fn load() -> Result<Self, Error> {
        let dir = winfsp_install_dir().ok_or_else(|| Error::Usage(INSTALL_HINT.into()))?;
        let arch = if cfg!(target_arch = "aarch64") { "a64" } else { "x64" };
        let dll = dir.join("bin").join(format!("winfsp-{arch}.dll"));
        let wide_path = to_wide(&dll.to_string_lossy());
        // SAFETY: a NUL-terminated absolute path. The DLL's own dependencies
        // are looked up only next to it and in System32, never in the
        // current folder (no DLL planting).
        let module = unsafe {
            LoadLibraryExW(wide_path.as_ptr(), null_mut(), LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32)
        };
        if module.is_null() {
            return Err(Error::Usage(format!("could not load {}. {INSTALL_HINT}", dll.display())));
        }
        let sym = |name: &[u8]| -> Result<RawFn, Error> {
            // SAFETY: `module` is a loaded module and `name` is NUL-terminated.
            unsafe { GetProcAddress(module, name.as_ptr()) }
                .ok_or_else(|| Error::Usage(format!("{} is too old; update WinFsp", dll.display())))
        };
        // SAFETY: each symbol has exactly this signature in WinFsp 2.x
        // (winfsp.h), and on the platforms we build for "system" and "C"
        // are the same calling convention.
        unsafe {
            Ok(Self {
                create: std::mem::transmute::<RawFn, CreateFn>(sym(b"FspFileSystemCreate\0")?),
                delete: std::mem::transmute::<RawFn, DeleteFn>(sym(b"FspFileSystemDelete\0")?),
                set_mount_point: std::mem::transmute::<RawFn, SetMountPointFn>(sym(b"FspFileSystemSetMountPoint\0")?),
                start_dispatcher: std::mem::transmute::<RawFn, StartDispatcherFn>(sym(
                    b"FspFileSystemStartDispatcher\0",
                )?),
                stop_dispatcher: std::mem::transmute::<RawFn, StopDispatcherFn>(sym(b"FspFileSystemStopDispatcher\0")?),
                add_dir_info: std::mem::transmute::<RawFn, AddDirInfoFn>(sym(b"FspFileSystemAddDirInfo\0")?),
            })
        }
    }
}

/// WinFsp's install folder, from `HKLM\SOFTWARE\WinFsp\InstallDir`.
fn winfsp_install_dir() -> Option<PathBuf> {
    let key = to_wide("SOFTWARE\\WinFsp");
    let value = to_wide("InstallDir");
    let mut buf = [0u16; 1024];
    let mut size = (buf.len() * 2) as u32;
    // SAFETY: valid NUL-terminated names; `buf` holds `size` bytes.
    let err = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_SZ | RRF_SUBKEY_WOW6432KEY,
            null_mut(),
            buf.as_mut_ptr().cast(),
            &mut size,
        )
    };
    if err != 0 {
        return None;
    }
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    Some(PathBuf::from(String::from_utf16(&buf[..len]).ok()?))
}

/// A security descriptor that gives the current user full access and
/// nobody else (not other users, not administrators' normal access) any.
fn user_only_security_descriptor() -> Result<Vec<u8>, Error> {
    let fail = |what: &str| Error::Io(std::io::Error::other(format!("{what}: {}", std::io::Error::last_os_error())));
    // SAFETY: standard token query of our own process; every out-pointer
    // is valid, and the buffers are sized as Windows reports.
    unsafe {
        let mut token: HANDLE = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(fail("reading the current user"));
        }
        let mut len = 0u32;
        GetTokenInformation(token, TokenUser, null_mut(), 0, &mut len);
        let mut buf = vec![0u64; (len as usize).div_ceil(8)];
        let ok = GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len);
        CloseHandle(token);
        if ok == 0 {
            return Err(fail("reading the current user"));
        }
        let user = &*(buf.as_ptr() as *const TOKEN_USER);
        let mut sid_str: *mut u16 = null_mut();
        if ConvertSidToStringSidW(user.User.Sid, &mut sid_str) == 0 {
            return Err(fail("reading the current user"));
        }
        let sid = from_wide(sid_str);
        LocalFree(sid_str.cast());
        let sid = sid.ok_or_else(|| fail("reading the current user"))?;
        // Owner and group: the user. DACL: protected (nothing inherited),
        // one entry: the user, full access. Integrity label: medium, with
        // no-read-up, no-write-up and no-execute-up, so sandboxed
        // low-integrity processes running as the same user (some browser
        // and document-viewer sandboxes) can't open the vault's files.
        let sddl = to_wide(&format!("O:{sid}G:{sid}D:P(A;;FA;;;{sid})S:(ML;;NRNWNX;;;ME)"));
        let mut sd: *mut c_void = null_mut();
        let mut size = 0u32;
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut sd, &mut size) == 0 {
            return Err(fail("building the drive's permissions"));
        }
        let bytes = std::slice::from_raw_parts(sd as *const u8, size as usize).to_vec();
        LocalFree(sd);
        Ok(bytes)
    }
}

// ----------------------------------------------------------------------
// State shared with the callbacks
// ----------------------------------------------------------------------

struct State {
    /// `None` once unmounted (the `Fs` is taken out, committed and dropped,
    /// which wipes its keys).
    fs: Mutex<Option<Fs>>,
    /// Set if a panic poisoned the state: refuse all further operations
    /// (and never commit possibly inconsistent metadata).
    broken: AtomicBool,
    security: Vec<u8>,
    add_dir_info: AddDirInfoFn,
}

/// One mount per process (the command line mounts one vault and exits).
static STATE: OnceLock<State> = OnceLock::new();

type Res<T> = Result<T, NTSTATUS>;

fn status(e: Error) -> NTSTATUS {
    match e {
        Error::NotFound => STATUS_OBJECT_NAME_NOT_FOUND,
        Error::Exists => STATUS_OBJECT_NAME_COLLISION,
        Error::NotADirectory => STATUS_NOT_A_DIRECTORY,
        Error::IsADirectory => STATUS_FILE_IS_A_DIRECTORY,
        Error::NotEmpty => STATUS_DIRECTORY_NOT_EMPTY,
        Error::InvalidName => STATUS_OBJECT_NAME_INVALID,
        Error::InvalidArgument => STATUS_INVALID_PARAMETER,
        Error::NameTooLong => STATUS_NAME_TOO_LONG,
        Error::FileTooBig => STATUS_FILE_TOO_LARGE,
        Error::NoSpace => STATUS_DISK_FULL,
        Error::ReadOnly => STATUS_MEDIA_WRITE_PROTECTED,
        e @ (Error::ChunkAuth { .. } | Error::Rollback { .. } | Error::Corrupt(_)) => {
            // Integrity failures are security events: always report them.
            eprintln!("nullguard: SECURITY WARNING: {e}");
            STATUS_FILE_CORRUPT_ERROR
        }
        other => {
            eprintln!("nullguard: I/O error: {other}");
            STATUS_IO_DEVICE_ERROR
        }
    }
}

trait OrStatus<T> {
    fn st(self) -> Res<T>;
}

impl<T> OrStatus<T> for Result<T, Error> {
    fn st(self) -> Res<T> {
        self.map_err(status)
    }
}

/// Run one filesystem operation. A panic (a bug) is caught here, before it
/// can unwind with half-updated state: the filesystem is poisoned so nothing
/// more is written, and the vault keeps its last commit.
fn run<T>(f: impl FnOnce(&mut Fs) -> Res<T>) -> Res<T> {
    let state = STATE.get().ok_or(STATUS_IO_DEVICE_ERROR)?;
    if state.broken.load(Ordering::SeqCst) {
        return Err(STATUS_IO_DEVICE_ERROR);
    }
    let mut guard = state.fs.lock().map_err(|_| {
        state.broken.store(true, Ordering::SeqCst);
        STATUS_IO_DEVICE_ERROR
    })?;
    let fs = guard.as_mut().ok_or(STATUS_IO_DEVICE_ERROR)?;
    match catch_unwind(AssertUnwindSafe(|| f(fs))) {
        Ok(r) => r,
        Err(_) => {
            fs.poison();
            state.broken.store(true, Ordering::SeqCst);
            eprintln!("nullguard: internal error; refusing further operations until remounted (the last commit is kept)");
            Err(STATUS_IO_DEVICE_ERROR)
        }
    }
}

/// Every callback goes through here: nothing may unwind into WinFsp.
fn shim(f: impl FnOnce() -> Res<()>) -> NTSTATUS {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => STATUS_SUCCESS,
        Ok(Err(s)) => s,
        Err(_) => STATUS_IO_DEVICE_ERROR,
    }
}

// ----------------------------------------------------------------------
// Conversions (safe)
// ----------------------------------------------------------------------

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

/// A NUL-terminated UTF-16 string from Windows, if it is valid.
fn from_wide(p: *const u16) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let mut n = 0;
    // SAFETY: Windows and WinFsp pass NUL-terminated strings; the bound
    // stops at the longest path Windows allows.
    while n < 32768 && unsafe { *p.add(n) } != 0 {
        n += 1;
    }
    // SAFETY: the `n` units before the NUL were just read.
    String::from_utf16(unsafe { std::slice::from_raw_parts(p, n) }).ok()
}

/// Write an out-parameter, if WinFsp passed one.
fn put<T>(p: *mut T, v: T) {
    if !p.is_null() {
        // SAFETY: WinFsp's out-pointers are valid for writes of `T`.
        unsafe { p.write(v) }
    }
}

/// Per-handle context: just the inode number (never zero), so there is no
/// heap pointer to get wrong.
fn ctx_of(ino: u64) -> *mut c_void {
    std::ptr::without_provenance_mut(ino as usize)
}

fn ino_of(ctx: *mut c_void) -> u64 {
    ctx.addr() as u64
}

const FILE_ATTRIBUTE_READONLY: u32 = 0x1;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x20;
const INVALID_FILE_ATTRIBUTES: u32 = u32::MAX;
const FILE_DIRECTORY_FILE: u32 = 0x1;
const CLEANUP_DELETE: u32 = 0x1;

const FILETIME_UNIX_EPOCH_SECS: i64 = 11_644_473_600;

fn to_filetime(t: Timestamp) -> u64 {
    match u64::try_from(t.secs.saturating_add(FILETIME_UNIX_EPOCH_SECS)) {
        Ok(s) => s.saturating_mul(10_000_000).saturating_add(t.nanos as u64 / 100),
        Err(_) => 0,
    }
}

fn from_filetime(ft: u64) -> Timestamp {
    Timestamp { secs: (ft / 10_000_000) as i64 - FILETIME_UNIX_EPOCH_SECS, nanos: (ft % 10_000_000) as u32 * 100 }
}

fn attributes(a: &Attr) -> u32 {
    match a.kind {
        Kind::Dir => FILE_ATTRIBUTE_DIRECTORY,
        _ if a.perm & 0o200 == 0 => FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_READONLY,
        _ => FILE_ATTRIBUTE_ARCHIVE,
    }
}

fn file_info(fs: &Fs, ino: u64) -> Res<FileInfo> {
    let a = fs.attr(ino).st()?;
    let block = (a.blksize as u64).max(1);
    Ok(FileInfo {
        file_attributes: attributes(&a),
        allocation_size: a.size.div_ceil(block) * block,
        file_size: a.size,
        creation_time: to_filetime(a.crtime),
        last_access_time: to_filetime(a.atime),
        last_write_time: to_filetime(a.mtime),
        change_time: to_filetime(a.ctime),
        index_number: ino,
        ..Default::default()
    })
}

/// A vault entry's name as Windows sees it, or `None` if it is hidden on
/// Windows: symbolic links, names that aren't valid UTF-8, and names
/// Windows can't represent.
fn windows_name(name: &[u8], kind: Kind) -> Option<Vec<u16>> {
    if kind == Kind::Symlink {
        return None;
    }
    let s = std::str::from_utf8(name).ok()?;
    let bad = |c: char| (c as u32) < 32 || matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*');
    if s.chars().any(bad) || s.ends_with([' ', '.']) {
        return None;
    }
    Some(s.encode_utf16().collect())
}

/// Split a WinFsp path (`\dir\file`) into its components.
fn components(path: &str) -> Res<Vec<&str>> {
    let parts: Vec<&str> = path.split('\\').filter(|p| !p.is_empty()).collect();
    if parts.iter().any(|p| *p == "." || *p == "..") {
        return Err(STATUS_OBJECT_NAME_INVALID);
    }
    Ok(parts)
}

fn lookup(fs: &Fs, parts: &[&str]) -> Res<u64> {
    let mut ino = ROOT_INO;
    for (i, part) in parts.iter().enumerate() {
        let last = i + 1 == parts.len();
        let missing = if last { STATUS_OBJECT_NAME_NOT_FOUND } else { STATUS_OBJECT_PATH_NOT_FOUND };
        ino = match fs.lookup(ino, part.as_bytes()) {
            Ok(child) => child,
            Err(Error::NotFound | Error::NotADirectory) => return Err(missing),
            Err(e) => return Err(status(e)),
        };
        // Hidden on Windows (see `windows_name`).
        if fs.attr(ino).st()?.kind == Kind::Symlink {
            return Err(missing);
        }
    }
    Ok(ino)
}

fn resolve(fs: &Fs, path: Wstr) -> Res<u64> {
    let path = from_wide(path).ok_or(STATUS_OBJECT_NAME_INVALID)?;
    lookup(fs, &components(&path)?)
}

/// The parent directory of `path` and the last component's name.
fn parent_and_name(fs: &Fs, path: Wstr) -> Res<(u64, String)> {
    let path = from_wide(path).ok_or(STATUS_OBJECT_NAME_INVALID)?;
    let parts = components(&path)?;
    let (name, dirs) = parts.split_last().ok_or(STATUS_ACCESS_DENIED)?; // the root itself
    let parent = lookup(fs, dirs).map_err(|_| STATUS_OBJECT_PATH_NOT_FOUND)?;
    Ok((parent, (*name).to_owned()))
}

fn copy_security(sd: *mut c_void, psize: *mut usize) -> Res<()> {
    let state = STATE.get().ok_or(STATUS_IO_DEVICE_ERROR)?;
    let len = state.security.len();
    if psize.is_null() {
        return Ok(());
    }
    // SAFETY: WinFsp passes a valid size pointer, and a buffer of that many
    // bytes (or null) for the descriptor.
    unsafe {
        if *psize < len {
            *psize = len;
            return Err(STATUS_BUFFER_OVERFLOW);
        }
        *psize = len;
        if !sd.is_null() {
            std::ptr::copy_nonoverlapping(state.security.as_ptr(), sd.cast::<u8>(), len);
        }
    }
    Ok(())
}

// ----------------------------------------------------------------------
// Callbacks
// ----------------------------------------------------------------------

extern "C" fn get_volume_info(_: FspFs, out: *mut VolumeInfo) -> NTSTATUS {
    shim(|| {
        let s = run(|fs| Ok(fs.statfs()))?;
        let mut label = [0u16; 32];
        let name: Vec<u16> = "nullguard".encode_utf16().collect();
        label[..name.len()].copy_from_slice(&name);
        let block = s.block_size as u64;
        put(
            out,
            VolumeInfo {
                total_size: s.total_blocks.saturating_mul(block),
                free_size: s.free_blocks.saturating_mul(block),
                volume_label_length: (name.len() * 2) as u16,
                volume_label: label,
            },
        );
        Ok(())
    })
}

extern "C" fn get_security_by_name(
    _: FspFs,
    name: Wstr,
    pattributes: *mut u32,
    sd: *mut c_void,
    psize: *mut usize,
) -> NTSTATUS {
    shim(|| {
        let attrs = run(|fs| {
            let ino = resolve(fs, name)?;
            Ok(attributes(&fs.attr(ino).st()?))
        })?;
        put(pattributes, attrs);
        copy_security(sd, psize)
    })
}

#[allow(clippy::too_many_arguments)]
extern "C" fn create(
    _: FspFs,
    name: Wstr,
    options: u32,
    _granted: u32,
    attrs: u32,
    _sd: *mut c_void,
    _allocation: u64,
    pctx: *mut *mut c_void,
    pinfo: *mut FileInfo,
) -> NTSTATUS {
    shim(|| {
        let (ino, info) = run(|fs| {
            let (parent, n) = parent_and_name(fs, name)?;
            let ino = if options & FILE_DIRECTORY_FILE != 0 {
                fs.mkdir(parent, n.as_bytes(), 0o700).st()?
            } else {
                let perm = if attrs & FILE_ATTRIBUTE_READONLY != 0 { 0o400 } else { 0o600 };
                fs.create_file(parent, n.as_bytes(), perm).st()?
            };
            fs.open_file(ino).st()?;
            Ok((ino, file_info(fs, ino)?))
        })?;
        put(pctx, ctx_of(ino));
        put(pinfo, info);
        Ok(())
    })
}

extern "C" fn open(
    _: FspFs,
    name: Wstr,
    _options: u32,
    _granted: u32,
    pctx: *mut *mut c_void,
    pinfo: *mut FileInfo,
) -> NTSTATUS {
    shim(|| {
        let (ino, info) = run(|fs| {
            let ino = resolve(fs, name)?;
            fs.open_file(ino).st()?;
            Ok((ino, file_info(fs, ino)?))
        })?;
        put(pctx, ctx_of(ino));
        put(pinfo, info);
        Ok(())
    })
}

extern "C" fn overwrite(_: FspFs, ctx: *mut c_void, _attrs: u32, _replace: u8, _alloc: u64, pinfo: *mut FileInfo) -> NTSTATUS {
    shim(|| {
        let info = run(|fs| {
            let ino = ino_of(ctx);
            fs.set_attr(ino, &SetAttr { size: Some(0), ..Default::default() }).st()?;
            file_info(fs, ino)
        })?;
        put(pinfo, info);
        Ok(())
    })
}

extern "C" fn cleanup(_: FspFs, ctx: *mut c_void, name: Wstr, flags: u32) {
    if flags & CLEANUP_DELETE == 0 {
        return;
    }
    let _ = shim(|| {
        run(|fs| {
            let (parent, n) = parent_and_name(fs, name)?;
            // Delete what this handle has open, never whatever the name
            // happens to point to now.
            if fs.lookup(parent, n.as_bytes()).st()? != ino_of(ctx) {
                return Err(STATUS_OBJECT_NAME_NOT_FOUND);
            }
            if fs.attr(ino_of(ctx)).st()?.kind == Kind::Dir {
                fs.rmdir(parent, n.as_bytes()).st()
            } else {
                fs.unlink(parent, n.as_bytes()).st()
            }
        })
    });
}

extern "C" fn close(_: FspFs, ctx: *mut c_void) {
    let _ = shim(|| {
        run(|fs| {
            fs.release_file(ino_of(ctx));
            Ok(())
        })
    });
}

extern "C" fn read(_: FspFs, ctx: *mut c_void, buf: *mut c_void, offset: u64, len: u32, pdone: *mut u32) -> NTSTATUS {
    shim(|| {
        let data = run(|fs| {
            let ino = ino_of(ctx);
            if offset >= fs.attr(ino).st()?.size {
                return Err(STATUS_END_OF_FILE);
            }
            fs.read(ino, offset, len as usize).st()
        })?;
        let n = data.len().min(len as usize);
        // SAFETY: WinFsp's buffer holds `len` bytes; we copy at most that.
        unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), buf.cast::<u8>(), n) };
        put(pdone, n as u32);
        Ok(())
    })
}

#[allow(clippy::too_many_arguments)]
extern "C" fn write(
    _: FspFs,
    ctx: *mut c_void,
    buf: *mut c_void,
    offset: u64,
    len: u32,
    to_end: u8,
    constrained: u8,
    pdone: *mut u32,
    pinfo: *mut FileInfo,
) -> NTSTATUS {
    shim(|| {
        // SAFETY: WinFsp's buffer holds `len` bytes of data to write.
        let data = unsafe { std::slice::from_raw_parts(buf.cast::<u8>(), len as usize) };
        let (done, info) = run(|fs| {
            let ino = ino_of(ctx);
            let size = fs.attr(ino).st()?.size;
            let offset = if to_end != 0 { size } else { offset };
            // Paging I/O ("constrained") never extends the file.
            let n = if constrained != 0 { data.len().min(size.saturating_sub(offset) as usize) } else { data.len() };
            if n > 0 {
                fs.write(ino, offset, &data[..n]).st()?;
            }
            Ok((n as u32, file_info(fs, ino)?))
        })?;
        put(pdone, done);
        put(pinfo, info);
        Ok(())
    })
}

extern "C" fn flush(_: FspFs, ctx: *mut c_void, pinfo: *mut FileInfo) -> NTSTATUS {
    shim(|| {
        let info = run(|fs| {
            fs.commit().st()?;
            if ctx.is_null() { Ok(None) } else { file_info(fs, ino_of(ctx)).map(Some) }
        })?;
        if let Some(info) = info {
            put(pinfo, info);
        }
        Ok(())
    })
}

extern "C" fn get_file_info(_: FspFs, ctx: *mut c_void, pinfo: *mut FileInfo) -> NTSTATUS {
    shim(|| {
        let info = run(|fs| file_info(fs, ino_of(ctx)))?;
        put(pinfo, info);
        Ok(())
    })
}

#[allow(clippy::too_many_arguments)]
extern "C" fn set_basic_info(
    _: FspFs,
    ctx: *mut c_void,
    attrs: u32,
    _creation: u64,
    access: u64,
    written: u64,
    _change: u64,
    pinfo: *mut FileInfo,
) -> NTSTATUS {
    shim(|| {
        let info = run(|fs| {
            let ino = ino_of(ctx);
            let a = fs.attr(ino).st()?;
            let mut set = SetAttr {
                atime: (access != 0).then(|| from_filetime(access)),
                mtime: (written != 0).then(|| from_filetime(written)),
                ..Default::default()
            };
            // The read-only attribute maps to the write permission bits.
            if attrs != INVALID_FILE_ATTRIBUTES && a.kind == Kind::File {
                let perm = if attrs & FILE_ATTRIBUTE_READONLY != 0 { a.perm & !0o222 } else { a.perm | 0o200 };
                if perm != a.perm {
                    set.perm = Some(perm);
                }
            }
            if set.atime.is_some() || set.mtime.is_some() || set.perm.is_some() {
                fs.set_attr(ino, &set).st()?;
            }
            file_info(fs, ino)
        })?;
        put(pinfo, info);
        Ok(())
    })
}

extern "C" fn set_file_size(_: FspFs, ctx: *mut c_void, new_size: u64, allocation: u8, pinfo: *mut FileInfo) -> NTSTATUS {
    shim(|| {
        let info = run(|fs| {
            let ino = ino_of(ctx);
            let size = fs.attr(ino).st()?.size;
            // Shrinking the allocation below the file size truncates the
            // file; growing it is a no-op (space is allocated on write).
            if allocation == 0 || new_size < size {
                fs.set_attr(ino, &SetAttr { size: Some(new_size), ..Default::default() }).st()?;
            }
            file_info(fs, ino)
        })?;
        put(pinfo, info);
        Ok(())
    })
}

extern "C" fn can_delete(_: FspFs, ctx: *mut c_void, _name: Wstr) -> NTSTATUS {
    shim(|| {
        run(|fs| {
            let ino = ino_of(ctx);
            if ino == ROOT_INO {
                return Err(STATUS_ACCESS_DENIED);
            }
            if fs.attr(ino).st()?.kind == Kind::Dir && fs.readdir(ino).st()?.len() > 2 {
                return Err(STATUS_DIRECTORY_NOT_EMPTY);
            }
            Ok(())
        })
    })
}

extern "C" fn rename(_: FspFs, _ctx: *mut c_void, name: Wstr, new_name: Wstr, replace: u8) -> NTSTATUS {
    shim(|| {
        run(|fs| {
            let (parent, n) = parent_and_name(fs, name)?;
            let (new_parent, new_n) = parent_and_name(fs, new_name)?;
            // Windows never replaces a directory by renaming onto it.
            if let Ok(existing) = fs.lookup(new_parent, new_n.as_bytes())
                && replace != 0
                && fs.attr(existing).st()?.kind == Kind::Dir
                && !(new_parent == parent && new_n == n)
            {
                return Err(STATUS_ACCESS_DENIED);
            }
            fs.rename(parent, n.as_bytes(), new_parent, new_n.as_bytes(), replace == 0).st()
        })
    })
}

extern "C" fn get_security(_: FspFs, _ctx: *mut c_void, sd: *mut c_void, psize: *mut usize) -> NTSTATUS {
    shim(|| copy_security(sd, psize))
}

extern "C" fn read_directory(
    _: FspFs,
    ctx: *mut c_void,
    _pattern: Wstr,
    marker: Wstr,
    buf: *mut c_void,
    len: u32,
    pdone: *mut u32,
) -> NTSTATUS {
    shim(|| {
        let state = STATE.get().ok_or(STATUS_IO_DEVICE_ERROR)?;
        let marker = from_wide(marker);
        let entries = run(|fs| {
            let ino = ino_of(ctx);
            let mut out = Vec::new();
            for e in fs.readdir(ino).st()? {
                // "." and ".." are listed except in the root.
                let dot = e.name == b"." || e.name == b"..";
                if dot && ino == ROOT_INO {
                    continue;
                }
                // Resume after the marker (the last name already returned).
                if let Some(m) = &marker {
                    let past = match m.as_str() {
                        "." => e.name != b".",
                        ".." => !dot,
                        m => !dot && &*e.name > m.as_bytes(),
                    };
                    if !past {
                        continue;
                    }
                }
                let Some(name) = windows_name(&e.name, e.kind) else { continue };
                out.push((name, file_info(fs, e.ino)?));
            }
            Ok(out)
        })?;
        put(pdone, 0);
        for (name, info) in entries {
            let mut d = DirInfo { size: (104 + 2 * name.len()) as u16, file_info: info, padding: [0; 24], name: [0; 255] };
            d.name[..name.len()].copy_from_slice(&name);
            // SAFETY: `d` is a valid entry; `buf`, `len` and `pdone` are
            // WinFsp's own buffer bookkeeping, passed through unchanged.
            if unsafe { (state.add_dir_info)(&mut d, buf, len, pdone) } == 0 {
                return Ok(()); // buffer full: WinFsp asks again from the last name
            }
        }
        // SAFETY: a null entry marks the end of the listing.
        unsafe { (state.add_dir_info)(null_mut(), buf, len, pdone) };
        Ok(())
    })
}

static INTERFACE: Interface = Interface {
    get_volume_info: Some(get_volume_info),
    set_volume_label: None,
    get_security_by_name: Some(get_security_by_name),
    create: Some(create),
    open: Some(open),
    overwrite: Some(overwrite),
    cleanup: Some(cleanup),
    close: Some(close),
    read: Some(read),
    write: Some(write),
    flush: Some(flush),
    get_file_info: Some(get_file_info),
    set_basic_info: Some(set_basic_info),
    set_file_size: Some(set_file_size),
    can_delete: Some(can_delete),
    rename: Some(rename),
    get_security: Some(get_security),
    set_security: None,
    read_directory: Some(read_directory),
    unused: [None; 45],
};

// ----------------------------------------------------------------------
// Mount and unmount
// ----------------------------------------------------------------------

/// The drive letter in a mount point like `X:` or `x:\`.
pub fn drive_letter(mountpoint: &Path) -> Option<char> {
    let s = mountpoint.to_str()?.trim_end_matches(['\\', '/']);
    let mut chars = s.chars();
    match (chars.next(), chars.next(), chars.next()) {
        (Some(c), Some(':'), None) if c.is_ascii_alphabetic() => Some(c.to_ascii_uppercase()),
        _ => None,
    }
}

/// Check before unlocking: the mount point is a free drive letter, and
/// WinFsp is installed.
pub fn check_mountpoint(mountpoint: &Path) -> Result<(), Error> {
    let letter = drive_letter(mountpoint).ok_or_else(|| {
        Error::Usage(format!("on Windows, mount on a free drive letter such as X: (got {})", mountpoint.display()))
    })?;
    if Path::new(&format!("{letter}:\\")).exists() {
        return Err(Error::Usage(format!("drive {letter}: is already in use")));
    }
    if winfsp_install_dir().is_none() {
        return Err(Error::Usage(INSTALL_HINT.into()));
    }
    Ok(())
}

/// The named event `nullguard unmount` signals. "Local\" keeps it inside
/// this Windows session.
fn unmount_event_name(letter: char) -> Vec<u16> {
    to_wide(&format!("Local\\nullguard-unmount-{letter}"))
}

pub fn mount(fs: Fs, mountpoint: &Path, opts: &MountOptions) -> Result<(), Error> {
    if opts.no_exec {
        return Err(Error::Usage("--no-exec isn't available on Windows".into()));
    }
    check_mountpoint(mountpoint)?;
    let letter = drive_letter(mountpoint).expect("checked above");
    let api = Api::load()?;
    let state = State {
        fs: Mutex::new(Some(fs)),
        broken: AtomicBool::new(false),
        security: user_only_security_descriptor()?,
        add_dir_info: api.add_dir_info,
    };
    if STATE.set(state).is_err() {
        return Err(Error::Usage("a vault is already mounted by this process".into()));
    }
    let state = STATE.get().expect("just set");
    let result = serve(&api, letter, opts);
    // Unmounted (or failed to mount): commit, then drop the filesystem,
    // which wipes its keys.
    let fs = state.fs.lock().ok().and_then(|mut g| g.take());
    if state.broken.load(Ordering::SeqCst) {
        return Err(Error::Corrupt("an internal error occurred; the last changes were not committed".into()));
    }
    let commit = match fs {
        Some(mut fs) => fs.commit(),
        None => Err(Error::Corrupt("internal error; the last changes were not committed".into())),
    };
    result?;
    commit
}

fn serve(api: &Api, letter: char, opts: &MountOptions) -> Result<(), Error> {
    let event_name = unmount_event_name(letter);
    // SAFETY: a valid NUL-terminated name; default security (this user).
    let event = unsafe { CreateEventW(null(), 1, 0, event_name.as_ptr()) };
    if event.is_null() {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    // SAFETY: reads the error of the CreateEventW call just made.
    if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        // Another nullguard is serving this letter.
        unsafe { CloseHandle(event) };
        return Err(Error::Usage(format!("drive {letter}: is already in use")));
    }

    let mut params = VolumeParams {
        version: size_of::<VolumeParams>() as u16,
        sector_size: 4096,
        sectors_per_allocation_unit: 1,
        max_component_length: 255,
        volume_creation_time: to_filetime(Timestamp::now()),
        volume_serial_number: (Timestamp::now().nanos ^ 0x6e67_7664) | 1,
        transact_timeout: 0,
        irp_timeout: 0,
        irp_capacity: 0,
        file_info_timeout: 1000,
        flags: CASE_SENSITIVE_SEARCH
            | CASE_PRESERVED_NAMES
            | UNICODE_ON_DISK
            | PERSISTENT_ACLS
            | FLUSH_AND_PURGE_ON_CLEANUP
            | UM_FILE_CONTEXT_IS_USER_CONTEXT2,
        prefix: [0; 192],
        file_system_name: [0; 16],
        flags2: 0,
        volume_info_timeout: 0,
        dir_info_timeout: 0,
        security_timeout: 0,
        stream_info_timeout: 0,
        ea_timeout: 0,
        fsext_control_code: 0,
        reserved32: [0],
        reserved64: [0; 2],
    };
    if opts.read_only {
        params.flags |= READ_ONLY_VOLUME;
    }
    let fs_name: Vec<u16> = "nullguard".encode_utf16().collect();
    params.file_system_name[..fs_name.len()].copy_from_slice(&fs_name);

    let device = to_wide("WinFsp.Disk");
    let mount_point = to_wide(&format!("{letter}:"));
    let fail = |what: &str, st: NTSTATUS| Error::Usage(format!("{what} (WinFsp status {:#010x})", st as u32));
    let mut fsp: FspFs = null_mut();
    // SAFETY: valid parameters; `INTERFACE` is static, so it outlives the
    // file system as WinFsp requires.
    let st = unsafe { (api.create)(device.as_ptr(), &params, &INTERFACE, &mut fsp) };
    if st != STATUS_SUCCESS {
        unsafe { CloseHandle(event) };
        return Err(fail("could not create the WinFsp file system", st));
    }
    // SAFETY: `fsp` was created above; WinFsp copies the mount point.
    let st = unsafe { (api.set_mount_point)(fsp, mount_point.as_ptr()) };
    if st != STATUS_SUCCESS {
        unsafe {
            (api.delete)(fsp);
            CloseHandle(event);
        }
        return Err(fail(&format!("could not mount on {letter}:"), st));
    }
    // SAFETY: as above; 0 lets WinFsp pick the number of threads.
    let st = unsafe { (api.start_dispatcher)(fsp, 0) };
    if st != STATUS_SUCCESS {
        unsafe {
            (api.delete)(fsp);
            CloseHandle(event);
        }
        return Err(fail("could not start serving the drive", st));
    }

    // Ctrl-C, closing the console window, logoff and shutdown all unmount.
    let event_addr = event as usize;
    if ctrlc::set_handler(move || {
        eprintln!("\nnullguard: unmounting...");
        // SAFETY: the event outlives this handler (closed only after the
        // wait loop below has ended).
        unsafe { SetEvent(event_addr as HANDLE) };
    })
    .is_err()
    {
        eprintln!("nullguard: WARNING: could not install the Ctrl-C handler; use `nullguard unmount` to lock the vault");
    }

    if let Some(ready) = &opts.on_ready {
        ready();
    }
    // Wait for `nullguard unmount` or Ctrl-C, committing while dirty.
    let state = STATE.get().expect("set before serving");
    loop {
        // SAFETY: a valid event handle.
        if unsafe { WaitForSingleObject(event, 500) } == WAIT_OBJECT_0 {
            break;
        }
        if state.broken.load(Ordering::SeqCst) {
            continue;
        }
        let Ok(mut guard) = state.fs.lock() else { break };
        let Some(fs) = guard.as_mut() else { break };
        // Same rule as for file operations: a panic must not leave
        // half-updated state that a later commit could persist.
        match catch_unwind(AssertUnwindSafe(|| fs.maybe_commit())) {
            Ok(Ok(())) => {}
            Ok(Err(e)) => eprintln!("nullguard: commit failed: {e}"),
            Err(_) => {
                fs.poison();
                state.broken.store(true, Ordering::SeqCst);
                eprintln!("nullguard: internal error while committing; refusing further operations");
            }
        }
    }
    // SAFETY: stop serving (no callback runs after this), then remove the
    // drive and free WinFsp's file system object. The event stays open
    // until the process exits, so a late Ctrl-C never touches a closed
    // handle.
    unsafe {
        (api.stop_dispatcher)(fsp);
        (api.delete)(fsp);
    }
    Ok(())
}

/// Unmount a vault mounted by `nullguard mount` in this Windows session.
pub fn unmount(mountpoint: &Path) -> Result<(), Error> {
    let letter = drive_letter(mountpoint)
        .ok_or_else(|| Error::Usage(format!("on Windows, give the drive letter, e.g. X: (got {})", mountpoint.display())))?;
    let name = unmount_event_name(letter);
    // SAFETY: a valid NUL-terminated name.
    let event = unsafe { OpenEventW(EVENT_MODIFY_STATE, 0, name.as_ptr()) };
    if event.is_null() {
        return Err(Error::Usage(format!("no nullguard vault is mounted on {letter}:")));
    }
    // SAFETY: a valid event handle, closed right after.
    unsafe {
        SetEvent(event);
        CloseHandle(event);
    }
    // Return once the drive is gone (the mounting process then commits).
    let root = format!("{letter}:\\");
    for _ in 0..300 {
        if !Path::new(&root).exists() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(Error::Usage(format!("drive {letter}: is still mounted; is a program still using it?")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drive_letters() {
        for (s, want) in [("X:", Some('X')), ("x:\\", Some('X')), ("q:/", Some('Q'))] {
            assert_eq!(drive_letter(Path::new(s)), want, "{s}");
        }
        for bad in ["X", "XY:", "1:", "C:\\dir", "", "\\\\?\\X:"] {
            assert_eq!(drive_letter(Path::new(bad)), None, "{bad}");
        }
    }

    #[test]
    fn filetimes_roundtrip() {
        for t in [Timestamp { secs: 0, nanos: 0 }, Timestamp { secs: 1_700_000_000, nanos: 123_456_700 }] {
            assert_eq!(from_filetime(to_filetime(t)), t);
        }
        assert_eq!(to_filetime(Timestamp { secs: 0, nanos: 0 }), 116_444_736_000_000_000);
        assert_eq!(to_filetime(Timestamp { secs: i64::MIN, nanos: 0 }), 0, "before 1601 clamps");
    }

    #[test]
    fn names_windows_cannot_show_are_hidden() {
        assert_eq!(windows_name(b"report.pdf", Kind::File), Some("report.pdf".encode_utf16().collect()));
        assert!(windows_name("ünïcødé".as_bytes(), Kind::Dir).is_some());
        for bad in [&b"a:b"[..], b"a\\b", b"what?", b"x*", b"tab\t", b"trailing.", b"trailing ", b"\xff\xfe"] {
            assert_eq!(windows_name(bad, Kind::File), None, "{bad:?}");
        }
        assert_eq!(windows_name(b"link", Kind::Symlink), None);
    }

    #[test]
    fn paths_split_and_refuse_dot_components() {
        assert_eq!(components("\\").unwrap(), Vec::<&str>::new());
        assert_eq!(components("\\a\\b").unwrap(), vec!["a", "b"]);
        assert!(components("\\a\\..\\b").is_err());
        assert!(components("\\.").is_err());
    }

    #[test]
    fn security_descriptor_is_built_for_the_current_user() {
        use windows_sys::Win32::Security::Authorization::ConvertSecurityDescriptorToStringSecurityDescriptorW;
        use windows_sys::Win32::Security::{
            DACL_SECURITY_INFORMATION, LABEL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        };
        let sd = user_only_security_descriptor().unwrap();
        let mut text: *mut u16 = null_mut();
        let what = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION;
        // SAFETY: a valid self-relative descriptor; the string is freed below.
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd.as_ptr() as *mut c_void,
                SDDL_REVISION_1,
                what,
                &mut text,
                null_mut(),
            )
        };
        assert_ne!(ok, 0);
        let sddl = from_wide(text).unwrap();
        // SAFETY: allocated by the call above.
        unsafe { LocalFree(text.cast()) };
        // Exactly one access entry, for one user, nothing inherited...
        assert!(sddl.contains("D:P(A;;FA;;;S-1-"), "{sddl}");
        assert_eq!(sddl.matches("(A;").count(), 1, "{sddl}");
        // ...and low-integrity processes can't read, write or run anything.
        let label = sddl.split("S:").nth(1).expect("an integrity label");
        assert!(label.contains(";;;ME)") && ["NR", "NW", "NX"].iter().all(|f| label.contains(f)), "{sddl}");
    }

    #[test]
    fn wide_strings_roundtrip() {
        let w = to_wide("héllo");
        assert_eq!(from_wide(w.as_ptr()).as_deref(), Some("héllo"));
        assert_eq!(from_wide(null()), None);
    }
}
