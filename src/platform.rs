//! Process hardening and small OS helpers.
//!
//! With `mount/winfsp.rs`, the only module allowed to use `unsafe`, for
//! plain libc calls.

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
}
