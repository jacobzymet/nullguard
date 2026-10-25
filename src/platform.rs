//! Process hardening and small OS helpers.
//!
//! With `mount/winfsp.rs`, the only module allowed to use `unsafe`, for
//! plain libc and Windows API calls.

#![allow(unsafe_code)]

/// Reduce what an attacker with access to this machine could extract from
/// the running process: no core dumps (which would contain keys), and on
/// Linux no ptrace attach or /proc/<pid>/mem access by other processes of
/// the same user.
pub fn harden_process() {
    #[cfg(unix)]
    {
        let zero = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        // SAFETY: setrlimit with a valid pointer to an initialized rlimit.
        unsafe {
            libc::setrlimit(libc::RLIMIT_CORE, &zero);
        }
    }
    #[cfg(target_os = "linux")]
    {
        // SAFETY: prctl(PR_SET_DUMPABLE, 0) takes no pointers.
        unsafe {
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        }
    }
    #[cfg(target_os = "macos")]
    {
        // The macOS counterpart: refuse debugger attachment (lldb, dtrace
        // and task_for_pid-based memory readers) for this process's lifetime.
        // SAFETY: PT_DENY_ATTACH ignores the pid/addr/data arguments.
        unsafe {
            libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0);
        }
    }
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
    use std::os::windows::io::AsRawHandle;
    use std::path::Path;
    use std::ptr::null_mut;

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
        SDDL_REVISION_1, SE_FILE_OBJECT, SetSecurityInfo,
    };
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, GetAce, GetSecurityDescriptorDacl,
        GetTokenInformation, PROTECTED_DACL_SECURITY_INFORMATION, PSID, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    // Access rights and flags (winnt.h / fileapi.h).
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const GENERIC_ALL: u32 = 0x1000_0000;
    const READ_CONTROL: u32 = 0x0002_0000;
    const WRITE_DAC: u32 = 0x0004_0000;
    const FILE_READ_DATA: u32 = 0x1;
    const FILE_SHARE_READ: u32 = 0x1;
    const FILE_SHARE_WRITE: u32 = 0x2;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
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

    /// The permissions [`make_private`] applies, in SDDL form.
    fn private_sddl() -> io::Result<String> {
        Ok(format!("D:P(A;;FA;;;{})(A;;FA;;;SY)", current_user_sid()?))
    }

    /// [`private_sddl`] as Windows writes it back (it shortens some
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

    /// Replace a file's or folder's permissions with: you and the system
    /// (SYSTEM) have full access, nobody else any, nothing inherited. The
    /// Windows counterpart of mode `0600`/`0700`. `file` must be open with
    /// `WRITE_DAC` access.
    pub fn make_private(file: &File) -> io::Result<()> {
        let sddl = to_wide(&private_sddl()?);
        let mut sd: *mut c_void = null_mut();
        // SAFETY: a valid SDDL string; the descriptor is freed below, after
        // its DACL (which points into it) has been applied.
        unsafe {
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut sd, null_mut())
                == 0
            {
                return Err(io::Error::last_os_error());
            }
            let mut present = 0;
            let mut defaulted = 0;
            let mut dacl: *mut ACL = null_mut();
            let mut result = Ok(());
            if GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted) == 0 || present == 0 {
                result = Err(io::Error::other("could not build the private permissions"));
            } else {
                let err = SetSecurityInfo(
                    file.as_raw_handle(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    null_mut(),
                    null_mut(),
                    dacl,
                    null_mut(),
                );
                if err != 0 {
                    result = Err(io::Error::from_raw_os_error(err as i32));
                }
            }
            LocalFree(sd);
            result
        }
    }

    /// `OpenOptions` for creating a new file whose permissions can then be
    /// made private (they carry `WRITE_DAC`), and that nobody may rename or
    /// delete while it is open.
    pub fn private_create_options() -> OpenOptions {
        let mut o = OpenOptions::new();
        o.read(true)
            .write(true)
            .create_new(true)
            .access_mode(GENERIC_READ | GENERIC_WRITE | READ_CONTROL | WRITE_DAC)
            .share_mode(FILE_SHARE_READ);
        o
    }

    /// Create a new file (never an existing one) that only you can read.
    pub fn create_private_file(path: &Path) -> io::Result<File> {
        let file = private_create_options().open(path)?;
        if let Err(e) = make_private(&file) {
            drop(file);
            let _ = std::fs::remove_file(path);
            return Err(e);
        }
        Ok(file)
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

    /// Create a folder only you can open, and hold it (see [`open_dir`]).
    pub fn create_private_dir(path: &Path) -> io::Result<File> {
        std::fs::create_dir(path)?;
        let dir = OpenOptions::new()
            .access_mode(GENERIC_READ | READ_CONTROL | WRITE_DAC)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        let meta = dir.metadata()?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a directory"));
        }
        make_private(&dir)?;
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
                    if header.AceType != ACCESS_ALLOWED_ACE_TYPE || header.AceFlags & INHERIT_ONLY_ACE != 0 {
                        continue;
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

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn private_files_are_private_and_shared_ones_are_detected() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("secret");
            let f = create_private_file(&path).unwrap();
            drop(f);
            let f = File::open(&path).unwrap();
            assert!(!readable_by_others(&f).unwrap());

            // A file that grants Everyone (WD) read access is caught.
            let shared = dir.path().join("shared");
            let f = private_create_options().open(&shared).unwrap();
            let sddl = to_wide("D:P(A;;FA;;;SY)(A;;FR;;;WD)");
            let mut sd: *mut c_void = null_mut();
            // SAFETY: as in `make_private`.
            unsafe {
                assert_ne!(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut sd, null_mut()), 0);
                let (mut present, mut defaulted, mut dacl) = (0, 0, null_mut());
                assert_ne!(GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted), 0);
                let err = SetSecurityInfo(f.as_raw_handle(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, null_mut(), null_mut(), dacl, null_mut());
                assert_eq!(err, 0);
                LocalFree(sd);
            }
            assert!(readable_by_others(&f).unwrap());
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
