//! Irreversible Linux confinement after the vault and FUSE handles are open.
//! No path opens, network syscalls, exec, namespace changes, or descriptor
//! acquisition from other processes. TSYNC covers existing and future threads.
use std::io;

fn instruction(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

/// Keep only operations needed to serve an already-open vault. Installation
/// failure is fatal to worker startup; there is no unconfined fallback.
pub fn confine() -> io::Result<()> {
    #[cfg(target_arch = "x86_64")]
    const ARCH: u32 = 0xc000_003e;
    #[cfg(target_arch = "aarch64")]
    const ARCH: u32 = 0xc000_00b7;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    return Err(io::Error::new(io::ErrorKind::Unsupported, "unsupported worker sandbox architecture"));

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        const LOAD: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
        const EQUAL: u16 = 0x15;
        const BITS: u16 = 0x45; // BPF_JMP | BPF_JSET | BPF_K
        const RETURN: u16 = 0x06;
        const ALLOW: u32 = 0x7fff_0000;
        const ERRNO: u32 = 0x0005_0000;
        const KILL: u32 = 0x8000_0000;
        let mut filter = vec![
            instruction(LOAD, 0, 0, 4), // seccomp_data.arch
            instruction(EQUAL, 1, 0, ARCH),
            instruction(RETURN, 0, 0, KILL), // reject alternate syscall ABIs
            instruction(LOAD, 0, 0, 0), // seccomp_data.nr
            // pthreads falls back to clone when clone3 reports ENOSYS.
            instruction(EQUAL, 0, 1, libc::SYS_clone3 as u32),
            instruction(RETURN, 0, 0, ERRNO | libc::ENOSYS as u32),
        ];
        // Thread creation is needed by FUSE. Fork-like clone calls are not.
        filter.extend([
            instruction(EQUAL, 0, 4, libc::SYS_clone as u32),
            instruction(LOAD, 0, 0, 16), // args[0]: clone flags
            instruction(BITS, 1, 0, libc::CLONE_THREAD as u32),
            instruction(RETURN, 0, 0, ERRNO | libc::EPERM as u32),
            instruction(RETURN, 0, 0, ALLOW),
        ]);
        // Guarded key pages need mprotect; never permit executable mappings.
        for syscall in [libc::SYS_mmap, libc::SYS_mprotect] {
            filter.extend([
                instruction(EQUAL, 0, 4, syscall as u32),
                instruction(LOAD, 0, 0, 32), // args[2]: protection
                instruction(BITS, 0, 1, libc::PROT_EXEC as u32),
                instruction(RETURN, 0, 0, ERRNO | libc::EPERM as u32),
                instruction(RETURN, 0, 0, ALLOW),
            ]);
        }
        let allowed = [
            libc::SYS_read, libc::SYS_write, libc::SYS_readv, libc::SYS_writev,
            libc::SYS_pread64, libc::SYS_pwrite64, libc::SYS_preadv, libc::SYS_pwritev,
            libc::SYS_close, libc::SYS_lseek, libc::SYS_fstat, libc::SYS_fstatfs,
            libc::SYS_fsync, libc::SYS_fdatasync, libc::SYS_flock, libc::SYS_fcntl,
            libc::SYS_munmap, libc::SYS_mremap, libc::SYS_madvise, libc::SYS_brk,
            libc::SYS_mlock, libc::SYS_munlock, libc::SYS_getrandom,
            libc::SYS_futex, libc::SYS_set_robust_list, libc::SYS_get_robust_list,
            libc::SYS_set_tid_address, libc::SYS_rseq,
            libc::SYS_clock_gettime, libc::SYS_clock_getres, libc::SYS_clock_nanosleep,
            libc::SYS_nanosleep, libc::SYS_gettimeofday, libc::SYS_times,
            libc::SYS_getpid, libc::SYS_getppid, libc::SYS_gettid,
            libc::SYS_getuid, libc::SYS_geteuid, libc::SYS_getgid, libc::SYS_getegid,
            libc::SYS_rt_sigaction, libc::SYS_rt_sigprocmask, libc::SYS_rt_sigreturn,
            libc::SYS_sigaltstack, libc::SYS_rt_sigtimedwait, libc::SYS_rt_sigsuspend,
            libc::SYS_sched_yield, libc::SYS_sched_getaffinity,
            libc::SYS_getrusage, libc::SYS_prctl,
            libc::SYS_ppoll, libc::SYS_pselect6,
            libc::SYS_pipe2, libc::SYS_eventfd2, libc::SYS_epoll_create1,
            libc::SYS_epoll_ctl, libc::SYS_epoll_pwait,
            libc::SYS_exit, libc::SYS_exit_group,
        ];
        for syscall in allowed {
            filter.push(instruction(EQUAL, 0, 1, syscall as u32));
            filter.push(instruction(RETURN, 0, 0, ALLOW));
        }
        #[cfg(target_arch = "x86_64")]
        {
            filter.push(instruction(EQUAL, 0, 1, libc::SYS_poll as u32));
            filter.push(instruction(RETURN, 0, 0, ALLOW));
        }
        filter.push(instruction(RETURN, 0, 0, ERRNO | libc::EPERM as u32));
        let program = libc::sock_fprog { len: filter.len() as u16, filter: filter.as_mut_ptr() };
        // SAFETY: initialized immutable BPF instructions; the kernel copies
        // them synchronously. TSYNC must succeed for every existing thread.
        unsafe {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            let result = libc::syscall(libc::SYS_seccomp, 1, 1, &program);
            if result < 0 { return Err(io::Error::last_os_error()); }
            if result != 0 { return Err(io::Error::other("could not confine every worker thread")); }
        }
        Ok(())
    }
}
