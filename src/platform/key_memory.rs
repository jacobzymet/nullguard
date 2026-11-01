//! Dedicated, locked pages for Unix RAM-wrapping keys. No ordinary heap
//! allocation ever contains the retained wrapping key. Access is read-only
//! during a serialized callback and PROT_NONE at all other times.

use std::ptr::NonNull;
use std::sync::Mutex;

use zeroize::Zeroize;

use crate::crypto::{CryptoError, KEY_LEN, random};

pub(crate) struct KeyPage {
    mapping: NonNull<libc::c_void>,
    mapping_len: usize,
    page: NonNull<u8>,
    page_size: usize,
    owner: libc::pid_t,
    secret_written: bool,
    access: Mutex<()>,
}

// SAFETY: the mapping is uniquely owned. Every read/protection transition
// is serialized by `access`; no reference into it can escape the callback.
// Drop requires exclusive ownership, and inherited objects reject access
// before touching a possibly inherited mutex or mapping.
unsafe impl Send for KeyPage {}
unsafe impl Sync for KeyPage {}

impl KeyPage {
    pub(crate) fn generate() -> Result<Self, CryptoError> {
        // SAFETY: sysconf/getpid have no pointer arguments or side effects.
        let page_size = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
            .ok().filter(|&n| n >= KEY_LEN && n.is_power_of_two())
            .ok_or(CryptoError::MemoryProtection)?;
        let mapping_len = page_size.checked_mul(3).ok_or(CryptoError::MemoryProtection)?;
        // SAFETY: anonymous private memory, no file descriptor. The outer
        // pages remain PROT_NONE guards for the entire allocation lifetime.
        let raw = unsafe {
            libc::mmap(std::ptr::null_mut(), mapping_len, libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANON, -1, 0)
        };
        if raw == libc::MAP_FAILED {
            return Err(CryptoError::MemoryProtection);
        }
        let Some(mapping) = NonNull::new(raw) else {
            // SAFETY: mmap succeeded at address zero; release that mapping.
            unsafe { libc::munmap(raw, mapping_len) };
            return Err(CryptoError::MemoryProtection);
        };
        // SAFETY: the center page lies inside the three-page mapping.
        let page = unsafe { NonNull::new_unchecked(raw.cast::<u8>().add(page_size)) };
        let mut memory = Self {
            mapping, mapping_len, page, page_size,
            owner: unsafe { libc::getpid() },
            secret_written: false,
            access: Mutex::new(()),
        };
        memory.protect(libc::PROT_READ | libc::PROT_WRITE)?;
        // Strict: never generate a wrapping key on a swappable page.
        // SAFETY: the center page is a valid page-aligned mapping.
        if unsafe { libc::mlock(memory.page.as_ptr().cast(), page_size) } != 0 {
            return Err(CryptoError::MemoryProtection);
        }
        memory.configure_mapping()?;
        memory.secret_written = true; // also wipe a partially filled key
        // SAFETY: unique writable access to exactly KEY_LEN bytes within
        // the center page. Randomness is written directly into that page.
        random::fill(unsafe { std::slice::from_raw_parts_mut(memory.page.as_ptr(), KEY_LEN) })?;
        memory.protect(libc::PROT_NONE)?;
        Ok(memory)
    }

    fn configure_mapping(&self) -> Result<(), CryptoError> {
        #[cfg(target_os = "linux")]
        // SAFETY: both advice operations cover our complete valid mapping.
        // Keep the wrapping key out of ordinary core dumps and fork children.
        unsafe {
            if libc::madvise(self.mapping.as_ptr(), self.mapping_len, libc::MADV_DONTDUMP) != 0
                || libc::madvise(self.mapping.as_ptr(), self.mapping_len, libc::MADV_DONTFORK) != 0
            {
                return Err(CryptoError::MemoryProtection);
            }
        }
        #[cfg(target_os = "macos")]
        // SAFETY: valid owned ranges; VM_INHERIT_NONE excludes the mapping
        // from fork children. ZERO_WIRED_PAGES adds zeroing on deallocation
        // without unwiring, including process exit. It is not a dump flag.
        unsafe {
            if libc::minherit(self.mapping.as_ptr(), self.mapping_len, libc::VM_INHERIT_NONE) != 0
                || libc::madvise(self.page.as_ptr().cast(), self.page_size, libc::MADV_ZERO_WIRED_PAGES) != 0
            {
                return Err(CryptoError::MemoryProtection);
            }
        }
        Ok(())
    }

    fn protect(&self, permissions: libc::c_int) -> Result<(), CryptoError> {
        // SAFETY: only the owned, page-aligned center page is affected.
        if unsafe { libc::mprotect(self.page.as_ptr().cast(), self.page_size, permissions) } != 0 {
            Err(CryptoError::MemoryProtection)
        } else {
            Ok(())
        }
    }

    pub(crate) fn with_key<T>(&self, use_key: impl FnOnce(&[u8; KEY_LEN]) -> T) -> Result<T, CryptoError> {
        // Check before locking: a fork child can inherit a locked mutex,
        // but intentionally does not inherit this mapping.
        if unsafe { libc::getpid() } != self.owner {
            return Err(CryptoError::MemoryProtection);
        }
        let _exclusive = self.access.lock().map_err(|_| CryptoError::MemoryProtection)?;
        self.protect(libc::PROT_READ)?;
        let _hide = HideOnDrop(self);
        // SAFETY: the guard keeps this page readable and immutable until
        // the callback returns/unwinds, then restores PROT_NONE first.
        Ok(use_key(unsafe { &*self.page.as_ptr().cast::<[u8; KEY_LEN]>() }))
    }
}

struct HideOnDrop<'a>(&'a KeyPage);

impl Drop for HideOnDrop<'_> {
    fn drop(&mut self) {
        if self.0.protect(libc::PROT_NONE).is_err() {
            // Leaving a wrapping key readable would violate the contract.
            // Exit without a core dump or callbacks that could retain keys.
            unsafe { libc::_exit(1) };
        }
    }
}

impl Drop for KeyPage {
    fn drop(&mut self) {
        if unsafe { libc::getpid() } != self.owner {
            return; // the mapping is absent in this fork child
        }
        if self.secret_written {
            if self.protect(libc::PROT_READ | libc::PROT_WRITE).is_err() {
                unsafe { libc::_exit(1) };
            }
            // SAFETY: uniquely owned writable center page, cleared before
            // unmapping. No munlock first: retain macOS wired-page zeroing.
            unsafe { std::slice::from_raw_parts_mut(self.page.as_ptr(), self.page_size) }.zeroize();
        }
        // SAFETY: release exactly the original mapping and its locked page.
        if unsafe { libc::munmap(self.mapping.as_ptr(), self.mapping_len) } != 0 {
            unsafe { libc::_exit(1) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::process::{Command, ExitStatus, Stdio};
    use std::time::{Duration, Instant};

    fn probe(mode: &str) -> ExitStatus {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "platform::key_memory::tests::page_probe_child"])
            .env("NULLGUARD_TEST_KEY_PAGE_PROBE", mode)
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::inherit())
            .spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                return status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("key-page probe did not exit");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn page_probe_child() {
        let Ok(mode) = std::env::var("NULLGUARD_TEST_KEY_PAGE_PROBE") else { return };
        // These probes deliberately fault in a disposable process. Never
        // generate a core dump containing test-process memory.
        let zero = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_CORE, &zero) }, 0);
        if mode == "lock-limit" {
            // Only this disposable process changes identity/limits. Drop
            // root first so privilege cannot bypass the zero lock limit.
            if unsafe { libc::geteuid() } == 0 {
                assert_eq!(unsafe { libc::setuid(65534) }, 0);
            }
            assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &zero) }, 0);
            assert!(matches!(KeyPage::generate(), Err(CryptoError::MemoryProtection)));
            return;
        }
        let memory = KeyPage::generate().unwrap();
        match mode.as_str() {
            "fork" => {
                let pid = memory.with_key(|_| {
                    // Fork while the mutex is held: the child must reject
                    // the inherited key before touching that mutex. In the
                    // child only getpid/alarm/_exit and pure Rust run.
                    let pid = unsafe { libc::fork() };
                    assert!(pid >= 0);
                    if pid == 0 {
                        unsafe { libc::alarm(5) };
                        let rejected = memory.with_key(|_| ()).is_err();
                        unsafe { libc::_exit(if rejected { 0 } else { 1 }) };
                    }
                    pid
                }).unwrap();
                let mut status = 0;
                assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
                assert!(libc::WIFEXITED(status));
                assert_eq!(libc::WEXITSTATUS(status), 0);
                memory.with_key(|key| assert!(key.iter().any(|&byte| byte != 0))).unwrap();
                return;
            }
            "restore-failure" => {
                let _ = memory.with_key(|_| {
                    // Removing our own page makes the guard's restore call
                    // fail. The process must exit immediately without a dump.
                    assert_eq!(unsafe { libc::munmap(memory.page.as_ptr().cast(), memory.page_size) }, 0);
                });
                panic!("protection restoration failure did not stop the process");
            }
            "unwind" => {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _ = memory.with_key(|_| panic!("simulated protected access panic"));
                }));
                assert!(result.is_err());
            }
            "leading" | "trailing" | "idle" => {}
            _ => panic!("unknown key-page probe"),
        }
        let pointer = match mode.as_str() {
            "leading" => memory.mapping.as_ptr().cast::<u8>(),
            "trailing" => unsafe { memory.mapping.as_ptr().cast::<u8>().add(2 * memory.page_size) },
            _ => memory.page.as_ptr(),
        };
        // SAFETY: this test intentionally reads a known inaccessible page
        // in a disposable child to verify the kernel's access protection.
        unsafe { std::ptr::read_volatile(pointer) };
        panic!("a protected page was readable");
    }

    #[test]
    fn idle_key_and_guard_pages_cannot_be_read() {
        for mode in ["idle", "leading", "trailing"] {
            let status = probe(mode);
            assert!(matches!(status.signal(), Some(libc::SIGSEGV | libc::SIGBUS)), "{mode}: {status}");
        }
    }

    #[test]
    fn panic_restores_no_access_before_unlocking() {
        let status = probe("unwind");
        assert!(matches!(status.signal(), Some(libc::SIGSEGV | libc::SIGBUS)), "{status}");
    }

    #[test]
    fn failed_restore_exits_without_a_core_dump() {
        assert_eq!(probe("restore-failure").code(), Some(1));
    }

    #[test]
    fn exhausted_lock_limit_has_no_unlocked_fallback() {
        assert!(probe("lock-limit").success());
    }

    #[test]
    fn fork_child_rejects_inherited_keys_without_deadlocking() {
        assert!(probe("fork").success());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn wrapping_page_is_locked_and_excluded_from_dumps_and_fork() {
        let memory = KeyPage::generate().unwrap();
        let address = memory.page.as_ptr() as usize;
        let maps = std::fs::read_to_string("/proc/self/smaps").unwrap();
        let mut selected = false;
        for line in maps.lines() {
            if let Some((start, end)) = line.split_whitespace().next().and_then(|range| range.split_once('-'))
                && let (Ok(start), Ok(end)) = (usize::from_str_radix(start, 16), usize::from_str_radix(end, 16))
            {
                selected = start <= address && address < end;
            }
            if selected && let Some(flags) = line.strip_prefix("VmFlags:") {
                let flags: Vec<_> = flags.split_whitespace().collect();
                for expected in ["lo", "dd", "dc"] {
                    assert!(flags.contains(&expected), "missing kernel memory flag {expected}");
                }
                return;
            }
        }
        panic!("wrapping page not found in smaps");
    }
}
