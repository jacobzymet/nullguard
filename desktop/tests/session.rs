//! Real GUI session transport and helper discovery, without creating a window.
use std::path::Path;
use std::process::Command;
use std::sync::mpsc;
use std::time::{Duration, Instant};
use nullguard_desktop::{session::{Session, Message}, protocol::{Request, Operation, LocalPath, Event}};
use nullguard::{vault::{Vault, CreateOptions}, crypto::Argon2Params};
use zeroize::Zeroizing;

const PASSWORD: &[u8] = b"session transport test password";

#[test]
fn session_child() {
    let Some(mode) = std::env::var_os("NULLGUARD_TEST_SESSION") else { return; };
    let executable = std::env::current_exe().unwrap();
    let path = executable.parent().unwrap().join("vault.ngv");
    let request = Request {
        operation: Operation::Verify, vault: LocalPath::new(&path), mountpoint: LocalPath::new(Path::new("")),
        keyfile: None, password: Zeroizing::new(String::from_utf8(PASSWORD.to_vec()).unwrap()),
        read_only: true, allow_expensive_kdf: false,
    };
    let (sender, receiver) = mpsc::channel();
    let result = Session::start(1, &request, sender, eframe::egui::Context::default());
    if mode != "valid" {
        assert!(result.is_err(), "missing/incompatible helper must fail before sending credentials");
        return;
    }
    let _session = result.unwrap();
    let mut verified = false;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())).unwrap() {
            Message::Event(_, Event::Verified { .. }) => verified = true,
            Message::Event(_, Event::Error(error)) => panic!("worker error: {error}"),
            Message::Exited(_, success) => { assert!(success && verified); break; }
            _ => {}
        }
    }
}

#[test]
fn session_uses_the_packaged_sibling_and_rejects_missing_or_wrong_helpers() {
    if std::env::var_os("NULLGUARD_TEST_SESSION").is_some() { return; }
    let binary_dir = Path::new(env!("CARGO_BIN_EXE_nullguard-desktop")).parent().unwrap();
    let worker_name = if cfg!(windows) { "nullguard-worker.exe" } else { "nullguard-worker" };
    let cli_name = if cfg!(windows) { "nullguard.exe" } else { "nullguard" };
    for mode in ["valid", "missing", "incompatible"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.ngv");
        Vault::create(&path, PASSWORD, &CreateOptions {
            size: 4 << 20, kdf: Argon2Params::LOW_MEMORY, chunk_size: Some(4096), fill_random: false,
        }, &mut |_, _| {}).unwrap();
        let probe = dir.path().join(if cfg!(windows) { "session-probe.exe" } else { "session-probe" });
        std::fs::copy(std::env::current_exe().unwrap(), &probe).unwrap();
        match mode {
            "valid" => { std::fs::copy(binary_dir.join(worker_name), dir.path().join(worker_name)).expect("build the worker with cargo test --workspace"); }
            "incompatible" => { std::fs::copy(binary_dir.join(cli_name), dir.path().join(worker_name)).unwrap(); }
            _ => {}
        }
        let status = Command::new(&probe).args(["--exact", "session_child", "--nocapture"])
            .env("NULLGUARD_TEST_SESSION", mode).status().unwrap();
        assert!(status.success(), "session transport failed: {mode}");
    }
}
