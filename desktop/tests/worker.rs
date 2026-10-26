//! Exercise the actual desktop executable and its private pipe protocol.
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use nullguard::{
    crypto::Argon2Params,
    vault::{CreateOptions, Credential, Vault},
};
use serde_json::{Value, json};

const PASSWORD: &str = "test vault long password";

fn encoded(path: &Path) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        path.as_os_str().as_bytes().to_vec()
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        path.as_os_str()
            .encode_wide()
            .flat_map(u16::to_le_bytes)
            .collect()
    }
}

fn request(path: &Path, operation: Value) -> Value {
    json!({"operation": operation, "vault": encoded(path), "mountpoint": [],
        "keyfile": null, "password": PASSWORD, "read_only": false})
}

struct Worker {
    child: Child,
    input: Option<ChildStdin>,
    events: mpsc::Receiver<Value>,
}

impl Worker {
    fn start(request: Value) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_nullguard-desktop"));
        command
            .arg("--mount-worker")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().unwrap();
        let mut input = child.stdin.take().unwrap();
        serde_json::to_writer(&mut input, &request).unwrap();
        input.write_all(b"\n").unwrap();
        input.flush().unwrap();
        let output = child.stdout.take().unwrap();
        let (sender, events) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(output).lines() {
                let line = line.unwrap();
                assert!(
                    !line.contains(PASSWORD),
                    "status output leaked the password"
                );
                if sender.send(serde_json::from_str(&line).unwrap()).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            input: Some(input),
            events,
        }
    }

    fn send(&mut self, control: &str) {
        let input = self.input.as_mut().unwrap();
        serde_json::to_writer(&mut *input, control).unwrap();
        input.write_all(b"\n").unwrap();
        input.flush().unwrap();
    }

    fn until(&mut self, kind: &str) -> Value {
        let deadline = Instant::now() + Duration::from_secs(45);
        loop {
            let event = self
                .events
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .unwrap();
            if event == kind || event.get(kind).is_some() {
                return event;
            }
            assert!(event.get("Error").is_none(), "worker failed: {event}");
        }
    }

    fn exit(&mut self, success: bool) {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert_eq!(status.success(), success);
                return;
            }
            assert!(Instant::now() < deadline, "worker did not exit");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.input.take(); // production behavior: EOF requests a clean lock
        if self.child.try_wait().unwrap().is_none() {
            // Only a failed test reaches this timeout/termination fallback.
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                if self.child.try_wait().unwrap().is_some() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn vault(path: &Path) {
    Vault::create(
        path,
        PASSWORD.as_bytes(),
        &CreateOptions {
            size: 4 << 20,
            kdf: Argon2Params::LOW_MEMORY,
            chunk_size: Some(4096),
            fill_random: false,
        },
        &mut |_, _| {},
    )
    .unwrap();
}

#[test]
fn verifies_existing_vault_and_rejects_wrong_password() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.ngv");
    vault(&path);
    let mut worker = Worker::start(request(&path, json!("Verify")));
    worker.until("Verified");
    worker.exit(true);
    let mut wrong = request(&path, json!("Verify"));
    wrong["password"] = json!("a definitely wrong password");
    let mut worker = Worker::start(wrong);
    worker.until("Error");
    worker.exit(false);
}

#[test]
fn cancelling_creation_removes_partial_vault_and_preserves_existing_files() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cancelled.ngv");
    let create = json!({"Create": {"size": 1_u64 << 32, "low_memory": true}});
    let mut worker = Worker::start(request(&path, create.clone()));
    worker.until("Progress");
    worker.send("Cancel");
    worker.until("Cancelled");
    worker.exit(true);
    assert!(!path.exists());
    std::fs::write(&path, b"keep this file").unwrap();
    let mut worker = Worker::start(request(&path, create));
    worker.until("Error");
    worker.exit(false);
    assert_eq!(std::fs::read(&path).unwrap(), b"keep this file");
}

#[test]
fn verifies_with_a_keyfile_using_the_existing_permission_checks() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.ngv");
    vault(&path);
    let key = nullguard::crypto::Keyfile::generate().unwrap();
    let keypath = dir.path().join("recovery.key");
    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&keypath)
            .unwrap()
    };
    #[cfg(windows)]
    let mut file = nullguard::platform::win::create_private_file(&keypath, 0).unwrap();
    file.write_all(key.encode().as_bytes()).unwrap();
    drop(file);
    let mut opened = Vault::open(&path, Credential::Password(PASSWORD.as_bytes()), false).unwrap();
    opened.add_keyfile(&key).unwrap();
    drop(opened);
    let mut req = request(&path, json!("Verify"));
    req["password"] = json!("");
    req["keyfile"] = json!(encoded(&keypath));
    let mut worker = Worker::start(req);
    worker.until("Verified");
    worker.exit(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&keypath, std::fs::Permissions::from_mode(0o644)).unwrap();
        let mut req = request(&path, json!("Verify"));
        req["password"] = json!("");
        req["keyfile"] = json!(encoded(&keypath));
        let mut worker = Worker::start(req);
        worker.until("Error");
        worker.exit(false);
    }
}

#[test]
#[ignore = "requires an installed FUSE/WinFsp driver; run by native mount CI"]
fn mount_lock_reopen_and_parent_disconnect_commit_files() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.ngv");
    #[cfg(unix)]
    let mountpoint = {
        let p = dir.path().join("mounted");
        std::fs::create_dir(&p).unwrap();
        p
    };
    #[cfg(windows)]
    let mountpoint = (b'D'..=b'Z')
        .rev()
        .map(|c| std::path::PathBuf::from(format!("{}:", c as char)))
        .find(|p| nullguard::mount::check_mountpoint(p).is_ok())
        .expect("free drive letter");
    let mut req = request(
        &path,
        json!({"Create": {"size": 8 << 20, "low_memory": true}}),
    );
    req["mountpoint"] = json!(encoded(&mountpoint));
    let mut worker = Worker::start(req.clone());
    worker.until("Created");
    worker.until("Mounted");
    #[cfg(unix)]
    let file = mountpoint.join("saved.txt");
    #[cfg(windows)]
    let file = std::path::PathBuf::from(format!("{}\\saved.txt", mountpoint.display()));
    std::fs::write(&file, b"written before Lock").unwrap();
    worker.send("Lock");
    worker.until("Finished");
    worker.exit(true);
    req["operation"] = json!("Unlock");
    let mut worker = Worker::start(req.clone());
    worker.until("Mounted");
    assert_eq!(std::fs::read(&file).unwrap(), b"written before Lock");
    std::fs::write(&file, b"written before parent disconnect").unwrap();
    worker.input.take();
    worker.until("Finished");
    worker.exit(true);
    let mut worker = Worker::start(req);
    worker.until("Mounted");
    assert_eq!(
        std::fs::read(&file).unwrap(),
        b"written before parent disconnect"
    );
    worker.send("Lock");
    worker.until("Finished");
    worker.exit(true);
}
