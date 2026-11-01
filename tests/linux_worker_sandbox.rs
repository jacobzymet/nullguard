#![cfg(target_os = "linux")]
//! Assert real kernel denials, including an existing thread and inherited FDs.
use std::io::{Read, Seek, SeekFrom, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc;

#[test]
fn confined_child() {
    let Some(directory) = std::env::var_os("NULLGUARD_TEST_CONFINEMENT") else { return };
    let path = std::path::Path::new(&directory).join("allowed-before-confinement");
    let mut file = std::fs::OpenOptions::new().create_new(true).read(true).write(true).open(&path).unwrap();
    file.write_all(b"before").unwrap();
    let (ready, wait) = mpsc::channel();
    let (reply, result) = mpsc::channel();
    let other_path = path.clone();
    let existing = std::thread::spawn(move || {
        wait.recv().unwrap();
        reply.send(std::fs::read(other_path).unwrap_err().raw_os_error()).unwrap();
    });
    nullguard::platform::harden_worker_process().unwrap();
    nullguard::platform::worker_sandbox::confine().unwrap();
    assert_eq!(std::fs::read(&path).unwrap_err().raw_os_error(), Some(libc::EPERM));
    assert_eq!(std::fs::write(path.with_file_name("forbidden"), b"no").unwrap_err().raw_os_error(), Some(libc::EPERM));
    assert_eq!(std::net::TcpStream::connect("127.0.0.1:9").unwrap_err().raw_os_error(), Some(libc::EPERM));
    assert_eq!(std::os::unix::net::UnixStream::connect("/tmp/forbidden.sock").unwrap_err().raw_os_error(), Some(libc::EPERM));
    assert!(Command::new("/bin/true").stdin(Stdio::null()).stdout(Stdio::null()).spawn().is_err());
    // Existing file capability still supports the worker's read/write/sync path.
    file.seek(SeekFrom::Start(0)).unwrap();
    file.write_all(b"after!").unwrap();
    file.sync_all().unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"after!");
    ready.send(()).unwrap();
    assert_eq!(result.recv().unwrap(), Some(libc::EPERM));
    existing.join().unwrap();
    let future = std::thread::spawn(move || std::fs::read(path).unwrap_err().raw_os_error());
    assert_eq!(future.join().unwrap(), Some(libc::EPERM));
}

#[test]
fn kernel_confinement_covers_all_threads_and_keeps_open_vault_handles_usable() {
    let directory = tempfile::tempdir().unwrap();
    let status = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "confined_child", "--nocapture"])
        .env("NULLGUARD_TEST_CONFINEMENT", directory.path()).status().unwrap();
    assert!(status.success());
    assert!(!directory.path().join("forbidden").exists());
    assert_eq!(std::fs::read(directory.path().join("allowed-before-confinement")).unwrap(), b"after!");
}
