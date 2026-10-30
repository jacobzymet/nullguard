#![cfg(windows)]

//! Exercise process protection in a child so the test runner's ACL stays
//! untouched. The probing process opens fresh handles, just as a separate
//! same-user memory reader would; the parent's existing Child handle is
//! deliberately not used to test access restrictions.
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::Storage::FileSystem::{READ_CONTROL, WRITE_DAC, WRITE_OWNER};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_CREATE_PROCESS, PROCESS_CREATE_THREAD, PROCESS_DUP_HANDLE,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SET_INFORMATION, PROCESS_SET_QUOTA,
    PROCESS_SUSPEND_RESUME, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE, PROCESS_VM_OPERATION,
    PROCESS_VM_READ, PROCESS_VM_WRITE,
};

const CHILD_ENV: &str = "NULLGUARD_TEST_PROTECTED_CHILD";
const TIMEOUT: Duration = Duration::from_secs(30);

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
    open_process(child.0.id(), PROCESS_VM_READ).expect("baseline memory handle should be allowed");
    writeln!(child.0.stdin.as_mut().unwrap(), "harden").unwrap();
    await_line("protected");

    for access in [
        PROCESS_VM_READ,
        PROCESS_VM_WRITE,
        PROCESS_VM_OPERATION,
        PROCESS_CREATE_THREAD,
        PROCESS_CREATE_PROCESS,
        PROCESS_DUP_HANDLE,
        PROCESS_SET_INFORMATION,
        PROCESS_SET_QUOTA,
        PROCESS_SUSPEND_RESUME,
        WRITE_DAC,
        WRITE_OWNER,
    ] {
        let error =
            open_process(child.0.id(), access).expect_err("unsafe process handle was granted");
        assert_eq!(error.raw_os_error(), Some(5), "access {access:#x}: {error}");
    }
    open_process(
        child.0.id(),
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE | PROCESS_TERMINATE | READ_CONTROL,
    )
    .expect("process supervision must remain available");

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
