//! Process hardening and small OS helpers.
//!
//! This is the only module allowed to use `unsafe`, for plain libc calls.

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
