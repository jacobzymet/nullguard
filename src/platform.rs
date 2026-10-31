//! Process hardening and small OS helpers.
//!
//! With `mount/winfsp.rs`, the only module allowed to use `unsafe`, for
//! plain libc and Windows API calls.

#![allow(unsafe_code)]

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) mod key_memory;

/// Reduce what an attacker with access to this machine could extract from
/// the running process: no core dumps (which would contain keys), and on
/// Linux no ptrace attach or `/proc/<pid>/mem` access by other processes of
/// the same user.
/// On Windows, refuse new memory-access/injection handles before accepting
/// secrets. This is process-object hardening, not a sandbox or a replacement
/// for driver-enforced isolation. Existing handles and administrators with
/// debug privileges remain outside this protection.
pub fn harden_process() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let zero = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        // SAFETY: setrlimit with a valid pointer to an initialized rlimit.
        if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &zero) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    #[cfg(target_os = "linux")]
    {
        // SAFETY: prctl(PR_SET_DUMPABLE, 0) takes no pointers.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    #[cfg(windows)]
    {
        win::suppress_crash_reports();
        win::restrict_process_access()?;
    }
    #[cfg(target_os = "macos")]
    {
        // The macOS counterpart: refuse debugger attachment (lldb, dtrace
        // and task_for_pid-based memory readers) for this process's lifetime.
        // SAFETY: PT_DENY_ATTACH ignores the pid/addr/data arguments.
        if unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Harden the headless worker before it reads any request or credentials.
/// Windows workers need neither generated executable code nor child processes.
/// This reduces available mechanisms after a compromise; it is not a full
/// filesystem/network sandbox.
pub fn harden_worker_process() -> std::io::Result<()> {
    #[cfg(windows)]
    win::restrict_worker_capabilities()?;
    harden_process()
}

/// Real user id of this process (0 on Windows).
pub fn uid() -> u32 {
    #[cfg(unix)]
    {
        // SAFETY: getuid has no preconditions and cannot fail.
        unsafe { libc::getuid() }
    }
    #[cfg(not(unix))]
    {
        0
    }
}

/// Real group id of this process (0 on Windows).
pub fn gid() -> u32 {
    #[cfg(unix)]
    {
        // SAFETY: getgid has no preconditions and cannot fail.
        unsafe { libc::getgid() }
    }
    #[cfg(not(unix))]
    {
        0
    }
}

/// Current umask, without changing it (unix only).
pub fn umask() -> u32 {
    #[cfg(unix)]
    {
        // SAFETY: umask is async-signal-safe and has no preconditions. Reading
        // it requires setting it, so it is immediately restored.
        unsafe {
            let m = libc::umask(0o077);
            libc::umask(m);
            m as u32
        }
    }
    #[cfg(not(unix))]
    {
        0o077
    }
}

/// Directory-relative file operations that never follow a symbolic link at
/// the name they act on (unix). `get` writes through these, holding each
/// destination folder open, so nobody can redirect the copy elsewhere by
/// swapping a folder for a link while it runs.
#[cfg(unix)]
pub mod at {
    use std::ffi::{CString, OsStr};
    use std::fs::File;
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;

    /// What a name in a directory is, without following a symbolic link.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Entry {
        Missing,
        File,
        Dir,
        Symlink,
        Other,
    }

    fn c_name(name: &OsStr) -> io::Result<CString> {
        if name.as_bytes().contains(&b'/') {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "a file name can't contain '/'"));
        }
        CString::new(name.as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "a file name can't contain a NUL byte"))
    }

    fn check(ret: libc::c_int) -> io::Result<libc::c_int> {
        if ret < 0 { Err(io::Error::last_os_error()) } else { Ok(ret) }
    }

    /// What `name` in `dir` is (a symbolic link is reported as one).
    pub fn entry(dir: &File, name: &OsStr) -> io::Result<Entry> {
        let n = c_name(name)?;
        let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: a valid directory fd, a NUL-terminated name, and room for
        // one `stat`, which is only read if the call succeeded.
        let ret = unsafe { libc::fstatat(dir.as_raw_fd(), n.as_ptr(), st.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW) };
        if ret < 0 {
            let e = io::Error::last_os_error();
            return if e.kind() == io::ErrorKind::NotFound { Ok(Entry::Missing) } else { Err(e) };
        }
        // SAFETY: fstatat succeeded, so `st` is initialized.
        #[allow(clippy::unnecessary_cast)] // mode_t is u16 on macOS
        let fmt = unsafe { st.assume_init() }.st_mode as u32 & libc::S_IFMT as u32;
        #[allow(clippy::unnecessary_cast)]
        Ok(match fmt {
            f if f == libc::S_IFREG as u32 => Entry::File,
            f if f == libc::S_IFDIR as u32 => Entry::Dir,
            f if f == libc::S_IFLNK as u32 => Entry::Symlink,
            _ => Entry::Other,
        })
    }

    /// Open the directory `name` in `dir`. Fails if it is a symbolic link
    /// or not a directory.
    pub fn open_dir(dir: &File, name: &OsStr) -> io::Result<File> {
        let n = c_name(name)?;
        let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        // SAFETY: a valid directory fd and a NUL-terminated name.
        let fd = check(unsafe { libc::openat(dir.as_raw_fd(), n.as_ptr(), flags) })?;
        // SAFETY: `fd` was just opened and is owned by nothing else.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    /// Create the directory `name` in `dir`.
    pub fn make_dir(dir: &File, name: &OsStr, mode: u32) -> io::Result<()> {
        let n = c_name(name)?;
        // SAFETY: a valid directory fd and a NUL-terminated name.
        check(unsafe { libc::mkdirat(dir.as_raw_fd(), n.as_ptr(), mode as libc::mode_t) })?;
        Ok(())
    }

    /// Create a new file `name` in `dir` for writing: never an existing
    /// file, never through a symbolic link.
    pub fn create_file(dir: &File, name: &OsStr, mode: u32) -> io::Result<File> {
        let n = c_name(name)?;
        let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        // SAFETY: a valid directory fd and a NUL-terminated name; the mode
        // is passed as the variadic argument O_CREAT requires.
        let fd = check(unsafe { libc::openat(dir.as_raw_fd(), n.as_ptr(), flags, mode as libc::c_uint) })?;
        // SAFETY: `fd` was just opened and is owned by nothing else.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    /// Remove the file (or symbolic link) `name` from `dir`.
    pub fn remove_file(dir: &File, name: &OsStr) -> io::Result<()> {
        let n = c_name(name)?;
        // SAFETY: a valid directory fd and a NUL-terminated name.
        check(unsafe { libc::unlinkat(dir.as_raw_fd(), n.as_ptr(), 0) })?;
        Ok(())
    }

    /// Atomically publish a completed file within an open directory. The
    /// destination entry is replaced, never followed if it became a link.
    pub fn rename_file(dir: &File, from: &OsStr, to: &OsStr) -> io::Result<()> {
        let from = c_name(from)?;
        let to = c_name(to)?;
        // SAFETY: a valid directory fd and NUL-terminated entry names.
        check(unsafe { libc::renameat(dir.as_raw_fd(), from.as_ptr(), dir.as_raw_fd(), to.as_ptr()) })?;
        Ok(())
    }

    /// Open `name` in `dir` for reading, never through a symbolic link, and
    /// without blocking: a named pipe opens at once instead of waiting for a
    /// writer, so the caller can look at what it got (`File::metadata`) and
    /// refuse anything that isn't a regular file or a directory.
    pub fn open_read(dir: &File, name: &OsStr) -> io::Result<File> {
        let n = c_name(name)?;
        let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;
        // SAFETY: a valid directory fd and a NUL-terminated name.
        let fd = check(unsafe { libc::openat(dir.as_raw_fd(), n.as_ptr(), flags) })?;
        // SAFETY: `fd` was just opened and is owned by nothing else.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    /// The names in the directory `dir` (without `.` and `..`), read from
    /// the open directory itself, not from a path that could be swapped.
    pub fn list(dir: &File) -> io::Result<Vec<std::ffi::OsString>> {
        // `fdopendir` takes over the descriptor it gets: give it a duplicate.
        // SAFETY: duplicating a valid fd.
        let fd = check(unsafe { libc::fcntl(dir.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) })?;
        // SAFETY: `fd` is a fresh duplicate of an open directory.
        let stream = unsafe { libc::fdopendir(fd) };
        if stream.is_null() {
            let e = io::Error::last_os_error();
            // SAFETY: `fdopendir` failed, so `fd` is still ours to close.
            unsafe { libc::close(fd) };
            return Err(e);
        }
        // The duplicate shares the read position: start from the top.
        // SAFETY: a valid directory stream.
        unsafe { libc::rewinddir(stream) };
        let mut names = Vec::new();
        let result = loop {
            // `readdir` returns null at the end and on error; only errno
            // tells them apart, so clear it first.
            // SAFETY: the calling thread's errno.
            unsafe { *errno() = 0 };
            // SAFETY: a valid directory stream.
            let entry = unsafe { libc::readdir(stream) };
            if entry.is_null() {
                // SAFETY: as above.
                let code = unsafe { *errno() };
                break if code == 0 { Ok(()) } else { Err(io::Error::from_raw_os_error(code)) };
            }
            // SAFETY: `d_name` is a NUL-terminated name inside the entry,
            // valid until the next `readdir` on this stream.
            let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if name != b"." && name != b".." {
                names.push(OsStr::from_bytes(name).to_owned());
            }
        };
        // SAFETY: closes the stream (and with it the duplicate fd).
        unsafe { libc::closedir(stream) };
        result.map(|()| names)
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn errno() -> *mut libc::c_int {
        // SAFETY: returns the calling thread's errno location.
        unsafe { libc::__errno_location() }
    }

    #[cfg(target_os = "macos")]
    fn errno() -> *mut libc::c_int {
        // SAFETY: returns the calling thread's errno location.
        unsafe { libc::__error() }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn open_read_never_follows_links_or_waits_on_pipes() {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(dir.path().join("file"), b"data").unwrap();
            std::os::unix::fs::symlink(dir.path().join("file"), dir.path().join("link")).unwrap();
            let fifo = std::ffi::CString::new(dir.path().join("fifo").as_os_str().as_bytes()).unwrap();
            // SAFETY: a NUL-terminated path.
            assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
            let d = File::open(dir.path()).unwrap();

            assert!(open_read(&d, OsStr::new("file")).unwrap().metadata().unwrap().is_file());
            assert!(open_read(&d, OsStr::new("link")).is_err(), "followed a symbolic link");
            // Opens at once (no writer needed) and is visibly not a file.
            let f = open_read(&d, OsStr::new("fifo")).unwrap();
            assert!(!f.metadata().unwrap().is_file());
            assert_eq!(entry(&d, OsStr::new("link")).unwrap(), Entry::Symlink);
            assert_eq!(entry(&d, OsStr::new("fifo")).unwrap(), Entry::Other);
            assert_eq!(entry(&d, OsStr::new("gone")).unwrap(), Entry::Missing);
            assert!(open_read(&d, OsStr::new("a/b")).is_err(), "a name must not be a path");
        }

        #[test]
        fn list_reads_the_open_directory() {
            let dir = tempfile::tempdir().unwrap();
            for n in ["a", "b", "c"] {
                std::fs::write(dir.path().join(n), b"").unwrap();
            }
            let d = File::open(dir.path()).unwrap();
            let mut names = list(&d).unwrap();
            names.sort();
            assert_eq!(names, ["a", "b", "c"]);
            // Listing again (the descriptor is shared) gives the same.
            assert_eq!(list(&d).unwrap().len(), 3);
            // It is this directory, even after its path names another one.
            std::fs::rename(dir.path().join("a"), dir.path().join("z")).unwrap();
            let moved = dir.path().with_extension("moved");
            std::fs::rename(dir.path(), &moved).unwrap();
            std::fs::create_dir(dir.path()).unwrap();
            let mut names = list(&d).unwrap();
            names.sort();
            assert_eq!(names, ["b", "c", "z"]);
            std::fs::remove_dir_all(&moved).unwrap();
        }
    }

}

/// Windows counterparts of the unix file safety measures: files readable
/// only by their owner (like mode `0600`), folders held open so they can't
/// be swapped for a link mid-copy, and permission checks on keyfiles.
#[cfg(windows)]
pub mod win {
    use std::ffi::c_void;
    use std::fs::{File, OpenOptions};
    use std::io;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::path::Path;
    use std::ptr::null_mut;

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
        SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, GetAce, GetSidSubAuthority,
        GetSidSubAuthorityCount, GetTokenInformation, IsTokenRestricted, OWNER_SECURITY_INFORMATION, PSID,
        SECURITY_ATTRIBUTES, TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TOKEN_USER, TokenIntegrityLevel,
        TokenIsAppContainer, TokenUser,
    };
    use windows_sys::Win32::Storage::FileSystem::{CREATE_NEW, CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_NORMAL};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    // Access rights and flags (winnt.h / fileapi.h).
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const GENERIC_ALL: u32 = 0x1000_0000;
    const FILE_READ_DATA: u32 = 0x1;
    pub const FILE_SHARE_READ: u32 = 0x1;
    const FILE_SHARE_WRITE: u32 = 0x2;
    const SECURITY_MANDATORY_MEDIUM_RID: u32 = 0x2000;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
    const ACCESS_ALLOWED_COMPOUND_ACE_TYPE: u8 = 4;
    const ACCESS_ALLOWED_OBJECT_ACE_TYPE: u8 = 5;
    const ACCESS_ALLOWED_CALLBACK_ACE_TYPE: u8 = 9;
    const ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE: u8 = 11;
    const INHERIT_ONLY_ACE: u8 = 0x8;

    fn from_wide(p: *const u16) -> Option<String> {
        if p.is_null() {
            return None;
        }
        let mut n = 0;
        // SAFETY: Windows returns NUL-terminated strings.
        while unsafe { *p.add(n) } != 0 {
            n += 1;
        }
        // SAFETY: the `n` units before the NUL were just read.
        String::from_utf16(unsafe { std::slice::from_raw_parts(p, n) }).ok()
    }

    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain([0]).collect()
    }

    /// A SID in its string form (`S-1-5-...`).
    ///
    /// # Safety
    /// `sid` must point to a valid SID.
    unsafe fn sid_string(sid: PSID) -> Option<String> {
        let mut text: *mut u16 = null_mut();
        // SAFETY: valid SID (caller); the string is freed below.
        if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
            return None;
        }
        let s = from_wide(text);
        // SAFETY: allocated by ConvertSidToStringSidW.
        unsafe { LocalFree(text.cast()) };
        s
    }

    /// Restrict future OpenProcess calls, including calls by this user.
    /// OWNER RIGHTS deliberately replaces the owner's implicit WRITE_DAC
    /// grant: otherwise another process of the same user could undo this.
    /// Keep limited queries, waiting, termination and READ_CONTROL available
    /// for process supervision. SYSTEM retains full access. This cannot
    /// revoke handles opened before startup hardening, protect thread
    /// objects, or stop an administrator exercising debug privileges.
    pub(super) fn restrict_process_access() -> io::Result<()> {
        use std::sync::OnceLock;
        use windows_sys::Win32::Security::{PROTECTED_DACL_SECURITY_INFORMATION, SetKernelObjectSecurity};
        use windows_sys::Win32::Storage::FileSystem::READ_CONTROL;
        use windows_sys::Win32::System::Threading::{
            PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
        };

        // Applying the ACL removes ordinary WRITE_DAC access, so do it only
        // once. Cache failures too: callers must not silently continue.
        static RESULT: OnceLock<Result<(), i32>> = OnceLock::new();
        (*RESULT.get_or_init(|| {
            let allowed = READ_CONTROL | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE | PROCESS_TERMINATE;
            let sddl = to_wide(&format!("D:P(A;;GA;;;SY)(A;;0x{allowed:08x};;;OW)"));
            let mut sd: *mut c_void = null_mut();
            // SAFETY: valid NUL-terminated SDDL; Windows allocates sd. Only
            // this process's DACL is changed, and sd is freed after use.
            unsafe {
                if ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut sd, null_mut()) == 0 {
                    return Err(io::Error::last_os_error().raw_os_error().unwrap_or(1));
                }
                let ok = SetKernelObjectSecurity(
                    GetCurrentProcess(),
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    sd,
                );
                let result = if ok == 0 { Err(io::Error::last_os_error().raw_os_error().unwrap_or(1)) } else { Ok(()) };
                LocalFree(sd);
                result
            }
        }))
        .map_err(io::Error::from_raw_os_error)
    }

    pub(super) fn restrict_worker_capabilities() -> io::Result<()> {
        use windows_sys::Win32::System::Threading::{SetProcessMitigationPolicy,
            ProcessDynamicCodePolicy, ProcessExtensionPointDisablePolicy, ProcessChildProcessPolicy};
        use windows_sys::Win32::System::SystemServices::{
            PROCESS_MITIGATION_DYNAMIC_CODE_POLICY, PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY,
            PROCESS_MITIGATION_CHILD_PROCESS_POLICY,
        };
        let mut dynamic = PROCESS_MITIGATION_DYNAMIC_CODE_POLICY::default();
        dynamic.Anonymous.Flags = 1; // ProhibitDynamicCode, no opt-out/downgrade
        let mut extension = PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY::default();
        extension.Anonymous.Flags = 1; // DisableExtensionPoints
        let mut child = PROCESS_MITIGATION_CHILD_PROCESS_POLICY::default();
        child.Anonymous.Flags = 1; // NoChildProcessCreation
        // SAFETY: documented Windows structures with only their first policy
        // bit enabled. Policies apply solely to this worker, before keys are
        // read. GUI processes retain their ordinary graphics/launch behavior.
        unsafe {
            if SetProcessMitigationPolicy(ProcessDynamicCodePolicy, (&dynamic as *const PROCESS_MITIGATION_DYNAMIC_CODE_POLICY).cast(), std::mem::size_of_val(&dynamic)) == 0
                || SetProcessMitigationPolicy(ProcessExtensionPointDisablePolicy, (&extension as *const PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY).cast(), std::mem::size_of_val(&extension)) == 0
                || SetProcessMitigationPolicy(ProcessChildProcessPolicy, (&child as *const PROCESS_MITIGATION_CHILD_PROCESS_POLICY).cast(), std::mem::size_of_val(&child)) == 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    /// Encrypt one retained 256-bit key in place for this process only.
    pub(crate) fn protect_key_memory(key: &mut [u8; crate::crypto::KEY_LEN]) -> io::Result<()> {
        use windows_sys::Win32::Security::Cryptography::{
            CRYPTPROTECTMEMORY_BLOCK_SIZE, CRYPTPROTECTMEMORY_SAME_PROCESS, CryptProtectMemory,
        };
        const { assert!(crate::crypto::KEY_LEN.is_multiple_of(CRYPTPROTECTMEMORY_BLOCK_SIZE as usize)) };
        // SAFETY: the array is writable for its full length, a multiple of
        // the API's block size. SAME_PROCESS is also used when decrypting.
        let ok = unsafe { CryptProtectMemory(key.as_mut_ptr().cast(), key.len() as u32, CRYPTPROTECTMEMORY_SAME_PROCESS) };
        if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
    }

    /// Decrypt a copy of a key encrypted by [`protect_key_memory`]. The
    /// caller owns the zeroizing buffer and wipes it on success or failure.
    pub(crate) fn unprotect_key_memory(key: &mut [u8; crate::crypto::KEY_LEN]) -> io::Result<()> {
        use windows_sys::Win32::Security::Cryptography::{CRYPTPROTECTMEMORY_SAME_PROCESS, CryptUnprotectMemory};
        // SAFETY: the writable array has the same fixed size and flags as
        // the buffer passed to CryptProtectMemory. No pointer is retained.
        let ok = unsafe { CryptUnprotectMemory(key.as_mut_ptr().cast(), key.len() as u32, CRYPTPROTECTMEMORY_SAME_PROCESS) };
        if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
    }

    /// Keep keys and decrypted data out of crash reports (the Windows
    /// counterpart of disabling core dumps), for this process only:
    ///
    /// * no "program stopped working" dialog or critical-error boxes;
    /// * any Windows Error Reporting report leaves out heap memory, where
    ///   keys, file names and cached plaintext live;
    /// * a crash that reaches the last-chance handler ends the process at
    ///   once, before Windows Error Reporting can take a dump.
    pub fn suppress_crash_reports() {
        use windows_sys::Win32::System::Diagnostics::Debug::{
            SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX, SEM_NOOPENFILEERRORBOX, SetErrorMode,
            SetUnhandledExceptionFilter,
        };
        use windows_sys::Win32::System::ErrorReporting::{WER_FAULT_REPORTING_FLAG_NOHEAP, WerSetFlags};
        // SAFETY: process-wide settings with no pointers; the filter is a
        // plain function that only ends the process.
        unsafe {
            SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
            WerSetFlags(WER_FAULT_REPORTING_FLAG_NOHEAP);
            SetUnhandledExceptionFilter(Some(end_without_dump));
        }
    }

    /// Last-chance exception filter: end the process now, so no crash dump
    /// (with keys in it) is written.
    unsafe extern "system" fn end_without_dump(
        _: *const windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_POINTERS,
    ) -> i32 {
        use windows_sys::Win32::System::Threading::TerminateProcess;
        // SAFETY: ends this process.
        unsafe { TerminateProcess(GetCurrentProcess(), 0xC000_0409) };
        1 // EXCEPTION_EXECUTE_HANDLER (not reached)
    }

    /// Exclude this program (by its path) from Windows Error Reporting for
    /// the current user, so it never collects a report or dump of it, even
    /// for failures no handler sees. This is a per-user setting that stays
    /// (in HKCU\Software\Microsoft\Windows\Windows Error Reporting    /// ExcludedApplications); `mount` sets it, since a mounted vault keeps
    /// keys in memory for a long time.
    pub fn exclude_from_crash_reports() -> io::Result<()> {
        use windows_sys::Win32::System::ErrorReporting::WerAddExcludedApplication;
        let exe = std::env::current_exe()?;
        let name = wide_path(&exe)?;
        // SAFETY: a NUL-terminated path; FALSE = current user only.
        let hr = unsafe { WerAddExcludedApplication(name.as_ptr(), 0) };
        if hr < 0 { Err(io::Error::from_raw_os_error(hr)) } else { Ok(()) }
    }

    /// The user an access token belongs to, as a SID string.
    ///
    /// # Safety
    /// `token` must be a handle this process owns, open with `TOKEN_QUERY`
    /// (a handle to anything else just makes the call fail).
    pub unsafe fn token_user(token: HANDLE) -> io::Result<String> {
        let mut len = 0u32;
        // SAFETY: a size query (null buffer), then a buffer of that size,
        // 8-byte aligned for TOKEN_USER.
        unsafe {
            GetTokenInformation(token, TokenUser, null_mut(), 0, &mut len);
            let mut buf = vec![0u64; (len as usize).div_ceil(8)];
            if GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len) == 0 {
                return Err(io::Error::last_os_error());
            }
            let user = &*(buf.as_ptr() as *const TOKEN_USER);
            sid_string(user.User.Sid).ok_or_else(|| io::Error::other("unreadable user SID"))
        }
    }

    /// The user this process runs as, as a SID string.
    pub fn current_user_sid() -> io::Result<String> {
        let mut token: HANDLE = null_mut();
        // SAFETY: opens a query handle to our own token, closed below.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: just opened with TOKEN_QUERY.
        let user = unsafe { token_user(token) };
        // SAFETY: opened above.
        unsafe { CloseHandle(token) };
        user
    }

    /// The permissions nullguard gives the files and folders it creates, in
    /// SDDL form: protected (nothing inherited), full access for you and
    /// SYSTEM, nothing for anyone else.
    fn private_sddl() -> io::Result<String> {
        Ok(format!("D:P(A;;FA;;;{})(A;;FA;;;SY)", current_user_sid()?))
    }

    /// The private security descriptor as Windows writes it back (it shortens some
    /// well-known accounts, such as the built-in Administrator to "LA"):
    /// what [`permissions_sddl`] reports for a private file.
    pub fn private_permissions_sddl() -> io::Result<String> {
        use windows_sys::Win32::Security::Authorization::ConvertSecurityDescriptorToStringSecurityDescriptorW;
        let sddl = to_wide(&private_sddl()?);
        let mut sd: *mut c_void = null_mut();
        // SAFETY: a valid SDDL string; the descriptor and string are freed.
        unsafe {
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut sd, null_mut())
                == 0
            {
                return Err(io::Error::last_os_error());
            }
            let mut text: *mut u16 = null_mut();
            let ok = ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut text,
                null_mut(),
            );
            LocalFree(sd);
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            let s = from_wide(text);
            LocalFree(text.cast());
            s.ok_or_else(|| io::Error::other("unreadable permissions"))
        }
    }

    /// A path as a NUL-terminated UTF-16 string for the Windows API, in the
    /// `\\?\` form for long paths (as the standard library does).
    fn wide_path(path: &Path) -> io::Result<Vec<u16>> {
        use std::os::windows::ffi::OsStrExt;
        let mut p = path.to_path_buf();
        if p.as_os_str().len() >= 248 {
            p = std::path::absolute(&p)?;
            let s = p.as_os_str().to_string_lossy().into_owned();
            if !s.starts_with(r"\\") {
                p = format!(r"\\?\{s}").into();
            } else if !s.starts_with(r"\\?\") {
                p = format!(r"\\?\UNC\{}", &s[2..]).into();
            }
        }
        Ok(p.as_os_str().encode_wide().chain([0]).collect())
    }

    /// Run `f` with security attributes carrying the private permissions
    /// ([`private_sddl`]), so a new object is private from the moment it
    /// exists: there is no instant in which it has the permissions its
    /// folder would pass on, when someone else could open it.
    fn with_private_attributes<T>(f: impl FnOnce(*const SECURITY_ATTRIBUTES) -> T) -> io::Result<T> {
        with_attributes(&private_sddl()?, f)
    }

    /// Run `f` with security attributes carrying the permissions `sddl`.
    fn with_attributes<T>(sddl: &str, f: impl FnOnce(*const SECURITY_ATTRIBUTES) -> T) -> io::Result<T> {
        let sddl = to_wide(sddl);
        let mut sd: *mut c_void = null_mut();
        // SAFETY: a valid SDDL string; the descriptor lives until after `f`.
        unsafe {
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut sd, null_mut())
                == 0
            {
                return Err(io::Error::last_os_error());
            }
            let sa = SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd,
                bInheritHandle: 0,
            };
            let result = f(&sa);
            LocalFree(sd);
            Ok(result)
        }
    }

    /// Create a new file (never an existing one) for reading and writing,
    /// private from the start: you and SYSTEM have access, nobody else
    /// (the counterpart of mode `0600`). `share` says what others may do
    /// while it is open (`FILE_SHARE_*`; 0 for nothing).
    pub fn create_private_file(path: &Path, share: u32) -> io::Result<File> {
        create_file_with(path, share, &private_sddl()?)
    }

    /// Create a new file for reading and writing with the permissions `sddl`.
    fn create_file_with(path: &Path, share: u32, sddl: &str) -> io::Result<File> {
        let name = wide_path(path)?;
        let handle = with_attributes(sddl, |sa| {
            // SAFETY: a NUL-terminated path and valid security attributes.
            unsafe {
                // FILE_FLAG_OPEN_REPARSE_POINT: a link at `path` (even a
                // dangling one, planted after any check) counts as an
                // existing file, so CREATE_NEW fails instead of creating the
                // file wherever the link points.
                CreateFileW(
                    name.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    share,
                    sa,
                    CREATE_NEW,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                    null_mut(),
                )
            }
        })?;
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a handle just opened, owned by nothing else.
        Ok(unsafe { File::from_raw_handle(handle) })
    }

    /// Create a folder that only you can open (private from the start, like
    /// mode `0700`), and hold it (see [`open_dir`]).
    pub fn create_private_dir(path: &Path) -> io::Result<File> {
        let name = wide_path(path)?;
        // SAFETY: a NUL-terminated path and valid security attributes.
        let ok = with_private_attributes(|sa| unsafe { CreateDirectoryW(name.as_ptr(), sa) })?;
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        open_dir(path, true)
    }

    /// Whether a folder (or file) belongs to you. Folders made by an
    /// elevated administrator may belong to the Administrators group, which
    /// counts too (administrators are trusted with everything anyway).
    pub fn owned_by_me(file: &File) -> io::Result<bool> {
        let me = current_user_sid()?;
        let mut owner: PSID = null_mut();
        let mut sd: *mut c_void = null_mut();
        // SAFETY: `file` is open for reading (READ_CONTROL); the owner SID
        // points into the descriptor, which is freed after it is read.
        unsafe {
            let err = GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                null_mut(),
                null_mut(),
                &mut sd,
            );
            if err != 0 {
                return Err(io::Error::from_raw_os_error(err as i32));
            }
            let sid = if owner.is_null() { None } else { sid_string(owner) };
            LocalFree(sd);
            Ok(matches!(sid.as_deref(), Some(s) if s == me || s == "S-1-5-32-544"))
        }
    }

    /// Whether an access token belongs to a sandboxed process: an app
    /// container, a restricted token, or an integrity level below medium
    /// (browser and document-viewer sandboxes use these). Such processes
    /// run as you but must not get at the vault's files.
    ///
    /// # Safety
    /// As for [`token_user`].
    pub unsafe fn token_is_sandboxed(token: HANDLE) -> io::Result<bool> {
        // SAFETY: fixed-size queries into local buffers, then a sized query
        // for the integrity label; the SID read points into that buffer.
        unsafe {
            let mut len = 0u32;
            let mut app_container = 0u32;
            if GetTokenInformation(token, TokenIsAppContainer, (&mut app_container as *mut u32).cast(), 4, &mut len) == 0 {
                return Err(io::Error::last_os_error());
            }
            if app_container != 0 || IsTokenRestricted(token) != 0 {
                return Ok(true);
            }
            GetTokenInformation(token, TokenIntegrityLevel, null_mut(), 0, &mut len);
            let mut buf = vec![0u64; (len as usize).div_ceil(8)];
            if GetTokenInformation(token, TokenIntegrityLevel, buf.as_mut_ptr().cast(), len, &mut len) == 0 {
                return Err(io::Error::last_os_error());
            }
            let label = &*(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL);
            let count = *GetSidSubAuthorityCount(label.Label.Sid);
            if count == 0 {
                return Ok(true);
            }
            let level = *GetSidSubAuthority(label.Label.Sid, count as u32 - 1);
            Ok(level < SECURITY_MANDATORY_MEDIUM_RID)
        }
    }

    /// Open a folder and hold it: while the handle is open, nobody can
    /// rename, delete or replace it (it is opened without delete sharing),
    /// so paths through it keep meaning the same folder. With `no_follow`,
    /// a link (symlink or junction) is opened as itself and refused.
    pub fn open_dir(path: &Path, no_follow: bool) -> io::Result<File> {
        let flags = FILE_FLAG_BACKUP_SEMANTICS | if no_follow { FILE_FLAG_OPEN_REPARSE_POINT } else { 0 };
        let dir = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(flags)
            .open(path)?;
        let meta = dir.metadata()?;
        if meta.file_type().is_symlink() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "it is a symbolic link or junction"));
        }
        if !meta.is_dir() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a directory"));
        }
        Ok(dir)
    }

    /// Open a file for reading without following a link: a symlink or
    /// junction is opened as itself (and is then not a regular file).
    pub fn open_no_follow(path: &Path) -> io::Result<File> {
        OpenOptions::new().read(true).custom_flags(FILE_FLAG_OPEN_REPARSE_POINT).open(path)
    }

    /// Whether anyone besides you, SYSTEM and the Administrators group may
    /// read `file` (the rule OpenSSH for Windows applies to private keys).
    pub fn readable_by_others(file: &File) -> io::Result<bool> {
        let me = current_user_sid()?;
        let mut dacl: *mut ACL = null_mut();
        let mut sd: *mut c_void = null_mut();
        // SAFETY: `file` is open for reading, which includes READ_CONTROL;
        // the descriptor is freed below, and `dacl` points into it. Each ACE
        // is read only after GetAce returned it, within the ACL.
        unsafe {
            let err = GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut sd,
            );
            if err != 0 {
                return Err(io::Error::from_raw_os_error(err as i32));
            }
            let result = (|| {
                if dacl.is_null() {
                    return Ok(true); // no DACL at all: everyone has access
                }
                for i in 0..(*dacl).AceCount as u32 {
                    let mut ace: *mut c_void = null_mut();
                    if GetAce(dacl, i, &mut ace) == 0 {
                        return Err(io::Error::last_os_error());
                    }
                    let header = &*(ace as *const ACE_HEADER);
                    if header.AceFlags & INHERIT_ONLY_ACE != 0 {
                        continue; // applies only to things created inside it
                    }
                    match header.AceType {
                        // Plain and conditional ("callback") grants: same
                        // layout up to the SID, checked below.
                        ACCESS_ALLOWED_ACE_TYPE | ACCESS_ALLOWED_CALLBACK_ACE_TYPE => {}
                        // Other kinds of grant (compound, object): who they
                        // grant to isn't read here, so assume someone else.
                        ACCESS_ALLOWED_COMPOUND_ACE_TYPE
                        | ACCESS_ALLOWED_OBJECT_ACE_TYPE
                        | ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE => return Ok(true),
                        // Denials, auditing and labels grant nothing.
                        _ => continue,
                    }
                    let allowed = &*(ace as *const ACCESS_ALLOWED_ACE);
                    if allowed.Mask & (FILE_READ_DATA | GENERIC_READ | GENERIC_ALL) == 0 {
                        continue;
                    }
                    let sid = sid_string(std::ptr::addr_of!(allowed.SidStart) as PSID).unwrap_or_default();
                    if sid != me && sid != "S-1-5-18" && sid != "S-1-5-32-544" {
                        return Ok(true);
                    }
                }
                Ok(false)
            })();
            LocalFree(sd);
            result
        }
    }

    /// A file's or folder's access rules in SDDL form, such as
    /// `D:P(A;;FA;;;S-1-5-21-...)(A;;FA;;;SY)` (for tests and diagnostics).
    pub fn permissions_sddl(file: &File) -> io::Result<String> {
        use windows_sys::Win32::Security::Authorization::ConvertSecurityDescriptorToStringSecurityDescriptorW;
        let mut sd: *mut c_void = null_mut();
        // SAFETY: `file` is open for reading (READ_CONTROL); the descriptor
        // and the string are freed below.
        unsafe {
            let err = GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                &mut sd,
            );
            if err != 0 {
                return Err(io::Error::from_raw_os_error(err as i32));
            }
            let mut text: *mut u16 = null_mut();
            let ok = ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut text,
                null_mut(),
            );
            LocalFree(sd);
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            let s = from_wide(text);
            LocalFree(text.cast());
            s.ok_or_else(|| io::Error::other("unreadable permissions"))
        }
    }

    /// A copy of this process's token lowered to low integrity, as browser
    /// sandboxes run (for tests). The caller closes it.
    #[cfg(test)]
    pub(crate) fn low_integrity_token() -> HANDLE {
        use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
        use windows_sys::Win32::Security::{
            DuplicateTokenEx, SID_AND_ATTRIBUTES, SecurityImpersonation, SetTokenInformation, TOKEN_ADJUST_DEFAULT,
            TOKEN_DUPLICATE, TokenPrimary,
        };
        const SE_GROUP_INTEGRITY: u32 = 0x20;
        // SAFETY: token handles of this process; the SID is freed once the
        // token has copied it.
        unsafe {
            let mut mine: HANDLE = null_mut();
            assert_ne!(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &mut mine), 0);
            let mut low: HANDLE = null_mut();
            let access = TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_DUPLICATE;
            assert_ne!(DuplicateTokenEx(mine, access, null_mut(), SecurityImpersonation, TokenPrimary, &mut low), 0);
            CloseHandle(mine);
            let mut sid: PSID = null_mut();
            assert_ne!(ConvertStringSidToSidW(to_wide("S-1-16-4096").as_ptr(), &mut sid), 0);
            let label = TOKEN_MANDATORY_LABEL { Label: SID_AND_ATTRIBUTES { Sid: sid, Attributes: SE_GROUP_INTEGRITY } };
            let size = (size_of::<TOKEN_MANDATORY_LABEL>() + 12) as u32;
            assert_ne!(SetTokenInformation(low, TokenIntegrityLevel, (&label as *const TOKEN_MANDATORY_LABEL).cast(), size), 0);
            LocalFree(sid);
            low
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn private_files_are_private_and_shared_ones_are_detected() {
            let dir = tempfile::tempdir().unwrap();
            let me = current_user_sid().unwrap();
            let f = create_private_file(&dir.path().join("secret"), 0).unwrap();
            assert!(!readable_by_others(&f).unwrap());
            assert_eq!(permissions_sddl(&f).unwrap().replacen("D:PAI(", "D:P(", 1), private_permissions_sddl().unwrap());
            // Private from the start, even in a folder that passes on
            // access for Everyone.
            let open = dir.path().join("open");
            with_attributes("D:P(A;OICI;FA;;;WD)", |sa| {
                let name = wide_path(&open).unwrap();
                // SAFETY: a NUL-terminated path and valid attributes.
                assert_ne!(unsafe { CreateDirectoryW(name.as_ptr(), sa) }, 0);
            })
            .unwrap();
            let f = create_private_file(&open.join("secret"), 0).unwrap();
            assert!(!readable_by_others(&f).unwrap());

            // Files others may read are caught: a plain grant to Everyone,
            // and a conditional ("callback") one.
            for (name, grant) in [("shared", "(A;;FR;;;WD)"), ("conditional", "(XA;;FR;;;WD;(Exists Department))")] {
                let f = create_file_with(&dir.path().join(name), FILE_SHARE_READ, &format!("D:P(A;;FA;;;{me}){grant}")).unwrap();
                assert!(readable_by_others(&f).unwrap(), "{name}");
            }
        }

        /// Crash reports leave out heap memory (where keys live), and no
        /// crash dialog is shown.
        #[test]
        fn crash_reports_leave_out_keys() {
            use windows_sys::Win32::System::Diagnostics::Debug::{GetErrorMode, SEM_NOGPFAULTERRORBOX};
            use windows_sys::Win32::System::ErrorReporting::{WER_FAULT_REPORTING_FLAG_NOHEAP, WerGetFlags};
            suppress_crash_reports();
            let mut flags = 0u32;
            // SAFETY: queries this process's settings into a local.
            unsafe {
                assert!(WerGetFlags(GetCurrentProcess(), &mut flags) >= 0);
                assert_ne!(flags & WER_FAULT_REPORTING_FLAG_NOHEAP, 0);
                assert_ne!(GetErrorMode() & SEM_NOGPFAULTERRORBOX, 0);
            }
        }

        /// A new file is never created through a link at its name, even a
        /// dangling one (which is how a planted link would redirect it).
        #[test]
        fn new_files_are_never_created_through_a_link() {
            let dir = tempfile::tempdir().unwrap();
            let target = dir.path().join("elsewhere.txt");
            let link = dir.path().join("out.txt");
            if std::os::windows::fs::symlink_file(&target, &link).is_err() {
                eprintln!("skipped: creating symbolic links needs Developer Mode or an administrator");
                return;
            }
            let err = create_private_file(&link, 0).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::AlreadyExists, "{err}");
            assert!(!target.exists(), "the file was created where the link points");
        }

        #[test]
        fn ownership_is_checked() {
            let dir = tempfile::tempdir().unwrap();
            let mine = create_private_dir(&dir.path().join("mine")).unwrap();
            assert!(owned_by_me(&mine).unwrap());
            // The Windows folder belongs to TrustedInstaller.
            let windows = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
            assert!(!owned_by_me(&open_dir(Path::new(&windows), false).unwrap()).unwrap());
        }

        /// A token lowered to low integrity (as browser sandboxes run) counts
        /// as sandboxed; this process's own token doesn't.
        #[test]
        fn sandboxed_tokens_are_recognized() {
            // SAFETY: token handles of this process, closed below.
            unsafe {
                let mut mine: HANDLE = null_mut();
                assert_ne!(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut mine), 0);
                assert!(!token_is_sandboxed(mine).unwrap());
                let low = low_integrity_token();
                assert!(token_is_sandboxed(low).unwrap());
                assert_eq!(token_user(low).unwrap(), current_user_sid().unwrap(), "same user, yet sandboxed");
                CloseHandle(low);
                CloseHandle(mine);
            }
        }

        #[test]
        fn held_folders_cannot_be_renamed_and_links_are_refused() {
            let dir = tempfile::tempdir().unwrap();
            let held = dir.path().join("held");
            let handle = create_private_dir(&held).unwrap();
            assert!(std::fs::rename(&held, dir.path().join("moved")).is_err(), "a held folder was renamed");
            drop(handle);
            std::fs::rename(&held, dir.path().join("moved")).unwrap();
            // A file is not a folder.
            std::fs::write(dir.path().join("file"), b"x").unwrap();
            assert!(open_dir(&dir.path().join("file"), true).is_err());
        }
    }
}
