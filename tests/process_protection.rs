#![cfg(windows)]

//! Exercise process protection in a child so the test runner's ACL stays
//! untouched. The probing process opens fresh handles, just as a separate
//! same-user memory reader would; the parent's existing Child handle is
//! deliberately not used to test access restrictions. Probe with privileges
//! removed from a thread-local token: elevated CI runners may otherwise
//! exercise the documented SeDebugPrivilege/ownership bypasses.
use std::io::{BufRead, BufReader, Write};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{CloseHandle, ERROR_NO_TOKEN, HANDLE};
use windows_sys::Win32::Security::{
    CreateRestrictedToken, DISABLE_MAX_PRIVILEGE, GetTokenInformation, ImpersonateLoggedOnUser,
    LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, PRIVILEGE_SET, PrivilegeCheck,
    SE_DEBUG_NAME, SE_PRIVILEGE_ENABLED, SE_RESTORE_NAME, SE_TAKE_OWNERSHIP_NAME,
    TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_QUERY, TOKEN_STATISTICS, TokenStatistics,
};
use windows_sys::Win32::Storage::FileSystem::{READ_CONTROL, WRITE_DAC, WRITE_OWNER};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcess, OpenProcessToken, OpenThreadToken,
    PROCESS_CREATE_PROCESS, PROCESS_CREATE_THREAD, PROCESS_DUP_HANDLE,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SET_INFORMATION, PROCESS_SET_QUOTA,
    PROCESS_SUSPEND_RESUME, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE, PROCESS_VM_OPERATION,
    PROCESS_VM_READ, PROCESS_VM_WRITE, SetThreadToken,
};

const CHILD_ENV: &str = "NULLGUARD_TEST_PROTECTED_CHILD";
const TIMEOUT: Duration = Duration::from_secs(30);
const RESTRICTED_ACCESS: [(&str, u32); 11] = [
    ("VM_READ", PROCESS_VM_READ),
    ("VM_WRITE", PROCESS_VM_WRITE),
    ("VM_OPERATION", PROCESS_VM_OPERATION),
    ("CREATE_THREAD", PROCESS_CREATE_THREAD),
    ("CREATE_PROCESS", PROCESS_CREATE_PROCESS),
    ("DUP_HANDLE", PROCESS_DUP_HANDLE),
    ("SET_INFORMATION", PROCESS_SET_INFORMATION),
    ("SET_QUOTA", PROCESS_SET_QUOTA),
    ("SUSPEND_RESUME", PROCESS_SUSPEND_RESUME),
    ("WRITE_DAC", WRITE_DAC),
    ("WRITE_OWNER", WRITE_OWNER),
];

fn process_token() -> std::io::Result<OwnedHandle> {
    let mut token = std::ptr::null_mut();
    // SAFETY: valid output pointer; success transfers one owned handle.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &mut token) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(token) })
}

fn thread_token() -> std::io::Result<Option<OwnedHandle>> {
    let mut token = std::ptr::null_mut();
    // SAFETY: current thread, valid output; OpenAsSelf permits inspection
    // of an existing impersonation token without changing that context.
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE, 1, &mut token) } == 0 {
        let error = std::io::Error::last_os_error();
        return if error.raw_os_error() == Some(ERROR_NO_TOKEN as i32) { Ok(None) } else { Err(error) };
    }
    Ok(Some(unsafe { OwnedHandle::from_raw_handle(token) }))
}

fn privilege_enabled(token: HANDLE, name: windows_sys::core::PCWSTR) -> std::io::Result<bool> {
    let mut luid = Default::default();
    // SAFETY: callers pass static Windows privilege names and a valid token.
    // The one-entry set is correctly sized; no pointers escape these calls.
    unsafe {
        if LookupPrivilegeValueW(std::ptr::null(), name, &mut luid) == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut required = PRIVILEGE_SET {
            PrivilegeCount: 1,
            Control: 0,
            Privilege: [LUID_AND_ATTRIBUTES { Luid: luid, Attributes: SE_PRIVILEGE_ENABLED }],
        };
        let mut enabled = 0;
        if PrivilegeCheck(token, &mut required, &mut enabled) == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(enabled != 0)
    }
}

struct UnprivilegedProbe {
    previous: Option<OwnedHandle>,
    // An impersonation context must be restored on its creating thread.
    _thread: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl UnprivilegedProbe {
    fn enter() -> std::io::Result<Self> {
        let previous = thread_token()?;
        let process = process_token()?;
        let source = previous.as_ref().unwrap_or(&process).as_raw_handle();
        let mut restricted = std::ptr::null_mut();
        // SAFETY: remove privileges only; every SID count is zero, so user
        // identity/group membership are unchanged. No process token or
        // other test thread is modified. Success transfers one handle.
        if unsafe { CreateRestrictedToken(source, DISABLE_MAX_PRIVILEGE, 0, std::ptr::null(),
            0, std::ptr::null(), 0, std::ptr::null(), &mut restricted) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let restricted = unsafe { OwnedHandle::from_raw_handle(restricted) };
        // SAFETY: owned primary token with QUERY/DUPLICATE access, or an
        // impersonation token with QUERY/IMPERSONATE, from our own identity.
        // Drop restores the previous thread context.
        if unsafe { ImpersonateLoggedOnUser(restricted.as_raw_handle()) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let guard = Self { previous, _thread: std::marker::PhantomData };
        let effective = thread_token()?.expect("probe must impersonate its limited token");
        for name in [SE_DEBUG_NAME, SE_TAKE_OWNERSHIP_NAME, SE_RESTORE_NAME] {
            assert!(!privilege_enabled(effective.as_raw_handle(), name)?, "probe retained an ACL-bypassing privilege");
        }
        Ok(guard)
    }
}

fn thread_token_id() -> Option<(u32, i32)> {
    let token = thread_token().unwrap()?;
    let mut stats = TOKEN_STATISTICS::default();
    let mut size = 0;
    // SAFETY: aligned, correctly sized output for the fixed token-statistics
    // structure. The query handle stays alive until the call completes.
    let ok = unsafe { GetTokenInformation(token.as_raw_handle(), TokenStatistics,
        (&mut stats as *mut TOKEN_STATISTICS).cast(), std::mem::size_of_val(&stats) as u32, &mut size) };
    assert_ne!(ok, 0, "query token identity: {}", std::io::Error::last_os_error());
    Some((stats.TokenId.LowPart, stats.TokenId.HighPart))
}

#[test]
fn probe_restores_thread_context_after_unwinding() {
    let initial = thread_token_id();
    {
        let _outer = UnprivilegedProbe::enter().unwrap();
        let outer = thread_token_id();
        assert!(outer.is_some());
        let result = std::panic::catch_unwind(|| {
            let _inner = UnprivilegedProbe::enter().unwrap();
            assert_ne!(thread_token_id(), outer);
            panic!("simulated probe assertion failure");
        });
        let panic = result.expect_err("probe should unwind");
        assert_eq!(panic.downcast_ref::<&str>(), Some(&"simulated probe assertion failure"));
        assert_eq!(thread_token_id(), outer, "restore the exact original impersonation token");
    }
    assert_eq!(thread_token_id(), initial, "restore the harness thread context");
}

impl Drop for UnprivilegedProbe {
    fn drop(&mut self) {
        let previous = self.previous.as_ref().map_or(std::ptr::null_mut(), AsRawHandle::as_raw_handle);
        // SAFETY: restore this thread's original token (or clear the
        // temporary impersonation). The saved handle remains owned here.
        assert_ne!(unsafe { SetThreadToken(std::ptr::null(), previous) }, 0, "restore probe token: {}", std::io::Error::last_os_error());
    }
}

#[test]
fn protected_child() {
    if std::env::var_os(CHILD_ENV).is_none() {
        return;
    }
    let mut input = String::new();
    println!("unprotected");
    std::io::stdin().read_line(&mut input).unwrap();
    nullguard::platform::harden_process().unwrap();
    nullguard::platform::harden_process().unwrap(); // idempotent

    // A protected desktop still needs to launch and wait for its workers.
    let status = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "protected_child"])
        .env_remove(CHILD_ENV)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    println!("protected");
    input.clear();
    std::io::stdin().read_line(&mut input).unwrap();
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn open_process(pid: u32, access: u32) -> std::io::Result<()> {
    // SAFETY: Windows validates the PID/access mask. Every successful handle
    // is closed here; no process memory is read or modified by this test.
    unsafe {
        let handle = OpenProcess(access, 0, pid);
        if handle.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        CloseHandle(handle);
    }
    Ok(())
}

#[test]
fn fresh_handles_cannot_read_inject_duplicate_or_change_permissions() {
    let mut child = ChildGuard(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "protected_child", "--nocapture"])
            .env(CHILD_ENV, "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let output = child.0.stdout.take().unwrap();
    let (sender, receiver) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(output).lines() {
            let Ok(line) = line else { break };
            if sender.send(line).is_err() {
                break;
            }
        }
    });
    let await_line = |expected: &str| {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            let line = receiver
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .expect("child did not reach the expected protection state");
            if line == expected {
                break;
            }
        }
    };
    await_line("unprotected");
    let caller = thread_token().unwrap().unwrap_or_else(|| process_token().unwrap());
    let debug_enabled = privilege_enabled(caller.as_raw_handle(), SE_DEBUG_NAME).unwrap();
    let probe = UnprivilegedProbe::enter().expect("create an unprivileged probe");
    for (name, access) in RESTRICTED_ACCESS {
        open_process(child.0.id(), access)
            .unwrap_or_else(|error| panic!("baseline {name} ({access:#x}) should be allowed: {error}"));
    }
    writeln!(child.0.stdin.as_mut().unwrap(), "harden").unwrap();
    await_line("protected");

    for (name, access) in RESTRICTED_ACCESS {
        let error = open_process(child.0.id(), access)
            .expect_err(&format!("unsafe process handle {name} ({access:#x}) was granted"));
        assert_eq!(error.raw_os_error(), Some(5), "{name} ({access:#x}): {error}");
    }
    open_process(
        child.0.id(),
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE | PROCESS_TERMINATE | READ_CONTROL,
    )
    .expect("process supervision must remain available");
    drop(probe);
    // On elevated runners, also verify the documented privileged bypass.
    // The ordinary probes above must still deny every dangerous access.
    if debug_enabled {
        open_process(child.0.id(), PROCESS_VM_READ).expect("SeDebugPrivilege should bypass the DACL");
    }

    writeln!(child.0.stdin.as_mut().unwrap(), "exit").unwrap();
    let deadline = Instant::now() + TIMEOUT;
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(Instant::now() < deadline, "protected child did not exit");
        std::thread::sleep(Duration::from_millis(20));
    }
    reader.join().unwrap();
}
