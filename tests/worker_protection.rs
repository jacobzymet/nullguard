#![cfg(windows)]
//! Exercise irreversible worker mitigations only inside a disposable child.
use std::process::{Command, Stdio};
use windows_sys::Win32::System::SystemServices::{
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY, PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY,
    PROCESS_MITIGATION_CHILD_PROCESS_POLICY,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessMitigationPolicy,
    ProcessDynamicCodePolicy, ProcessExtensionPointDisablePolicy, ProcessChildProcessPolicy};

#[test]
fn hardened_worker_child() {
    if std::env::var_os("NULLGUARD_TEST_WORKER_PROTECTION").is_none() { return; }
    nullguard::platform::harden_worker_process().unwrap();
    let mut dynamic = PROCESS_MITIGATION_DYNAMIC_CODE_POLICY::default();
    let mut extension = PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY::default();
    let mut child = PROCESS_MITIGATION_CHILD_PROCESS_POLICY::default();
    // SAFETY: fixed, correctly aligned SDK structures and valid process
    // pseudo-handle. Inspect policies only; no foreign memory is accessed.
    unsafe {
        assert_ne!(GetProcessMitigationPolicy(GetCurrentProcess(), ProcessDynamicCodePolicy,
            (&mut dynamic as *mut PROCESS_MITIGATION_DYNAMIC_CODE_POLICY).cast(), std::mem::size_of_val(&dynamic)), 0);
        assert_eq!(dynamic.Anonymous.Flags, 1, "dynamic code must be prohibited without opt-outs");
        assert_ne!(GetProcessMitigationPolicy(GetCurrentProcess(), ProcessExtensionPointDisablePolicy,
            (&mut extension as *mut PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY).cast(), std::mem::size_of_val(&extension)), 0);
        assert_eq!(extension.Anonymous.Flags & 1, 1);
        assert_ne!(GetProcessMitigationPolicy(GetCurrentProcess(), ProcessChildProcessPolicy,
            (&mut child as *mut PROCESS_MITIGATION_CHILD_PROCESS_POLICY).cast(), std::mem::size_of_val(&child)), 0);
        assert_eq!(child.Anonymous.Flags & 1, 1);
    }
    assert!(Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "hardened_worker_child"])
        .env_remove("NULLGUARD_TEST_WORKER_PROTECTION")
        .stdout(Stdio::null()).stderr(Stdio::null()).spawn().is_err(),
        "the kernel must block worker child-process creation");
}

#[test]
fn windows_worker_mitigations_are_enforced() {
    let status = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "hardened_worker_child", "--nocapture"])
        .env("NULLGUARD_TEST_WORKER_PROTECTION", "1").status().unwrap();
    assert!(status.success());
}
