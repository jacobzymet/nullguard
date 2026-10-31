use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::collections::HashSet;
use std::time::Duration;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};

use anyhow::{Context, Result, bail};

use crate::{
    paths,
    protocol::{Control, Event, Request},
};

pub enum Message {
    Event(u64, Event),
    Exited(u64, bool),
}

pub struct Session {
    pub input: std::process::ChildStdin,
    pub mountpoint: PathBuf,
    lock_pending: Arc<AtomicBool>,
}

/// Bound unsolicited status traffic without ever blocking diagnostic draining.
/// Lifecycle messages are one-shot; lock failures require a parent request.
struct EventFilter {
    creating: bool,
    verifying: bool,
    created: bool,
    mounted: bool,
    verified: bool,
    finished: bool,
    cancelled: bool,
    failed: bool,
    percent: Option<u8>,
    warnings: HashSet<String>,
    lock_pending: Arc<AtomicBool>,
}

impl EventFilter {
    fn new(request: &Request, lock_pending: Arc<AtomicBool>) -> Self {
        Self { creating: matches!(request.operation, crate::protocol::Operation::Create { .. }),
            verifying: matches!(request.operation, crate::protocol::Operation::Verify),
            created: false, mounted: false, verified: false, finished: false, cancelled: false,
            failed: false, percent: None, warnings: HashSet::new(), lock_pending }
    }

    fn accept(&mut self, event: &Event) -> bool {
        match event {
            Event::Ready { .. } => false,
            Event::Progress { fraction } => {
                if !self.creating || self.created || self.failed || !fraction.is_finite() { return false; }
                let percent = (fraction.clamp(0.0, 1.0) * 100.0) as u8;
                if self.percent.is_some_and(|old| percent <= old) { return false; }
                self.percent = Some(percent);
                true
            }
            Event::Created => {
                if !self.creating || self.failed { return false; }
                !std::mem::replace(&mut self.created, true)
            }
            Event::Mounted => {
                if self.verifying || self.failed || self.cancelled || (self.creating && !self.created) { return false; }
                !std::mem::replace(&mut self.mounted, true)
            }
            Event::Verified { .. } => {
                if !self.verifying || self.failed || self.cancelled { return false; }
                !std::mem::replace(&mut self.verified, true)
            }
            Event::Finished => self.mounted && !std::mem::replace(&mut self.finished, true),
            Event::Cancelled => !self.mounted && !std::mem::replace(&mut self.cancelled, true),
            Event::Error(_) => !std::mem::replace(&mut self.failed, true),
            Event::Warning(message) => self.warnings.len() < 16 && self.warnings.insert(message.clone()),
            Event::LockFailed(_) => self.lock_pending.swap(false, Ordering::AcqRel),
        }
    }
}

impl Session {
    pub fn start(
        id: u64,
        request: &Request,
        sender: mpsc::Sender<Message>,
        ctx: eframe::egui::Context,
    ) -> Result<Self> {
        let mut permit = crate::admission::acquire()?;
        let mountpoint = request.mountpoint.decode()?;
        let lock_pending = Arc::new(AtomicBool::new(false));
        let mut events = EventFilter::new(request, lock_pending.clone());
        let executable = std::env::current_exe()?;
        let worker = executable.parent().context("Could not locate the application folder")?
            .join(if cfg!(windows) { "nullguard-worker.exe" } else { "nullguard-worker" });
        let mut command = Command::new(worker);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        }
        let mut child = command
            .spawn()
            .context("Could not start the vault worker. Keep nullguard-worker beside the desktop app; reinstall the complete package if it is missing")?;
        let mut input = child
            .stdin
            .take()
            .context("Could not open the private worker pipe")?;
        let output = child
            .stdout
            .take()
            .context("Could not read worker status")?;
        let diagnostics = child
            .stderr
            .take()
            .context("Could not read worker diagnostics")?;
        // Start draining before sending the request: startup diagnostics
        // must not fill stderr while the parent is writing credentials.
        let diagnostic_sender = sender.clone();
        let diagnostic_ctx = ctx.clone();
        let diagnostic_thread = std::thread::spawn(move || {
            relay_diagnostics(BufReader::new(diagnostics), |message| {
                let _ = diagnostic_sender.send(Message::Event(id, Event::Warning(message)));
                diagnostic_ctx.request_repaint();
            });
        });
        // Verify the headless helper before sending credentials. A missing,
        // stale or hung helper must not leave startup blocked indefinitely.
        let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
        let handshake = std::thread::spawn(move || {
            let mut reader = BufReader::new(output);
            let mut line = String::new();
            let ready = reader.by_ref().take(4097).read_line(&mut line)
                .map_err(anyhow::Error::from).and_then(|_| check_ready(&line));
            let _ = ready_sender.send((reader, ready));
        });
        let startup = ready_receiver.recv_timeout(Duration::from_secs(10));
        let mut reader = match startup {
            Ok((reader, Ok(()))) => reader,
            result => {
                // No request or credentials were sent; this cannot kill a
                // legitimate vault writer. Drain/join the startup readers.
                drop(input);
                let _ = child.kill();
                let _ = child.wait();
                let _ = handshake.join();
                let _ = diagnostic_thread.join();
                match result {
                    Ok((_, Err(error))) => return Err(error),
                    _ => bail!("The vault worker did not become ready. Reinstall the complete app package."),
                }
            }
        };
        let _ = handshake.join();
        // This JSON is written directly to an anonymous pipe. No temporary
        // credential file, argument, environment variable, or saved setting.
        let result = serde_json::to_writer(&mut input, request)
            .map_err(anyhow::Error::from)
            .and_then(|_| {
                input.write_all(b"\n")?;
                input.flush()?;
                Ok(())
            });
        if result.is_err() {
            drop(input);
            let _ = child.wait();
            let _ = diagnostic_thread.join();
            bail!("Could not send the unlock request to the vault worker");
        }
        std::thread::spawn(move || {
            loop {
                let mut line = String::new();
                // Worker output contains no secrets; bound it nevertheless.
                match reader.by_ref().take(256 * 1024).read_line(&mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        if let Ok(event) = serde_json::from_str::<Event>(&line) {
                            if !events.accept(&event) { continue; }
                            if matches!(&event, Event::Mounted | Event::Verified { .. }) { permit.ready(); }
                            let _ = sender.send(Message::Event(id, event));
                            ctx.request_repaint();
                        } else {
                            break;
                        }
                    }
                }
            }
            let success = child.wait().is_ok_and(|s| s.success());
            // Drain diagnostics before reporting exit, so a late integrity
            // or commit warning cannot arrive in a newly opened session.
            let _ = diagnostic_thread.join();
            drop(permit);
            let _ = sender.send(Message::Exited(id, success));
            ctx.request_repaint();
        });
        Ok(Self { input, mountpoint, lock_pending })
    }

    pub fn send(&mut self, control: Control) -> Result<()> {
        let locking = matches!(control, Control::Lock);
        if locking { self.lock_pending.store(true, Ordering::Release); }
        let result = (|| {
            serde_json::to_writer(&mut self.input, &control)?;
            self.input.write_all(b"\n")?;
            self.input.flush()?;
            Ok(())
        })();
        if result.is_err() && locking { self.lock_pending.store(false, Ordering::Release); }
        result
    }
}

fn check_ready(line: &str) -> Result<()> {
    anyhow::ensure!(line.len() <= 4096 && line.ends_with('\n'), "Invalid vault worker handshake");
    match serde_json::from_str::<Event>(line)? {
        Event::Ready { protocol_version } if protocol_version == crate::protocol::PROTOCOL_VERSION => Ok(()),
        Event::Error(message) => bail!("Vault worker startup failed: {message}"),
        _ => bail!("Incompatible vault worker. Reinstall the complete app package."),
    }
}

/// Mount adapters report runtime integrity/durability failures on stderr.
/// Keep these visible without allowing repeated diagnostics to flood the
/// UI's unbounded event queue. Always drain the pipe, even after the limit,
/// so a full stderr pipe cannot block a filesystem operation or unmount.
fn relay_diagnostics(mut input: impl BufRead, mut emit: impl FnMut(String)) {
    const MAX_LINE: usize = 4096;
    const MAX_MESSAGES: usize = 16;
    let mut seen = HashSet::new();
    let mut suppressed = false;
    loop {
        let mut line = Vec::new();
        match input.by_ref().take((MAX_LINE + 1) as u64).read_until(b'\n', &mut line) {
            Ok(0) => break,
            Err(_) => {
                emit("Could not read vault worker diagnostics.".into());
                break;
            }
            Ok(_) => {}
        }
        let oversized = line.len() > MAX_LINE;
        if oversized && !line.ends_with(b"\n") && input.skip_until(b'\n').is_err() {
            emit("Could not read vault worker diagnostics.".into());
            break;
        }
        let message = if oversized {
            "A vault worker diagnostic exceeded the display limit.".to_owned()
        } else {
            match std::str::from_utf8(&line) {
                Ok(text) => text.trim().to_owned(),
                Err(_) => "A vault worker diagnostic was not valid UTF-8.".to_owned(),
            }
        };
        if message.is_empty() || seen.contains(&message) {
            continue;
        }
        if seen.len() < MAX_MESSAGES {
            seen.insert(message.clone());
            emit(message);
        } else if !suppressed {
            emit("Additional vault worker diagnostics were suppressed. Lock the vault and investigate the warnings above.".into());
            suppressed = true;
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // Closing the input pipe asks a live worker to unmount. Cleanup is
        // harmless before exit too: remove_dir never removes a mounted tree.
        paths::cleanup_mountpoint(&self.mountpoint);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_status_floods_cannot_replay_lifecycle_or_unsolicited_lock_failures() {
        let pending = Arc::new(AtomicBool::new(false));
        let request = Request {
            operation: crate::protocol::Operation::Create { size: 1 << 20, low_memory: true },
            vault: crate::protocol::LocalPath(Vec::new()), mountpoint: crate::protocol::LocalPath(Vec::new()),
            keyfile: None, password: zeroize::Zeroizing::new(String::new()), read_only: false, allow_expensive_kdf: false,
        };
        let mut filter = EventFilter::new(&request, pending.clone());
        assert!(!filter.accept(&Event::Mounted));
        let mut progress = 0;
        let mut warnings = 0;
        for i in 0..10_000 {
            progress += usize::from(filter.accept(&Event::Progress { fraction: i as f32 / 10_000.0 }));
            warnings += usize::from(filter.accept(&Event::Warning(format!("warning {i}"))));
        }
        assert!(progress <= 101);
        assert_eq!(warnings, 16);
        assert!(filter.accept(&Event::Created));
        assert!(!filter.accept(&Event::Created));
        assert!(filter.accept(&Event::Mounted));
        assert!(!filter.accept(&Event::Mounted));
        assert!(!filter.accept(&Event::LockFailed("unsolicited".into())));
        pending.store(true, Ordering::Release);
        assert!(filter.accept(&Event::LockFailed("requested".into())));
        assert!(!filter.accept(&Event::LockFailed("replayed".into())));
        assert!(filter.accept(&Event::Error("failed".into())));
        assert!(!filter.accept(&Event::Mounted));
        assert!(filter.accept(&Event::Finished));
        assert!(!filter.accept(&Event::Finished));
    }

    #[test]
    fn startup_requires_a_bounded_matching_protocol() {
        assert!(check_ready("{\"Ready\":{\"protocol_version\":1}}\n").is_ok());
        assert!(check_ready("{\"Ready\":{\"protocol_version\":2}}\n").is_err());
        assert!(check_ready("\"Mounted\"\n").is_err());
        assert!(check_ready("{\"Ready\":{\"protocol_version\":1}}").is_err());
        assert!(check_ready(&"x".repeat(4097)).is_err());
        assert!(check_ready("{\"Error\":\"protection failed\"}\n").unwrap_err().to_string().contains("protection failed"));
    }

    #[test]
    fn integrity_and_commit_diagnostics_are_visible_and_deduplicated() {
        let input = b"nullguard: SECURITY WARNING: chunk 12 failed authentication\nnullguard: commit failed: I/O error\nnullguard: commit failed: I/O error\n";
        let mut messages = Vec::new();
        relay_diagnostics(&input[..], |message| messages.push(message));
        assert_eq!(messages.len(), 2);
        assert!(messages[0].contains("SECURITY WARNING"));
        assert!(messages[1].contains("commit failed"));
    }

    #[test]
    fn diagnostic_floods_are_bounded_but_the_pipe_is_drained() {
        let mut input = "x".repeat(20_000);
        input.push('\n');
        for i in 0..1000 {
            input.push_str(&format!("warning {i}\n"));
        }
        let mut reader = std::io::Cursor::new(input.as_bytes());
        let mut messages = Vec::new();
        relay_diagnostics(&mut reader, |message| messages.push(message));
        assert_eq!(reader.position(), input.len() as u64);
        assert_eq!(messages.len(), 17);
        assert!(messages[0].contains("exceeded the display limit"));
        assert!(messages.last().unwrap().contains("suppressed"));
        assert!(messages.iter().all(|m| m.len() <= 4096));
    }

    #[test]
    fn invalid_utf8_diagnostics_do_not_hide_the_following_error() {
        let mut input = vec![0xff; 4095];
        input.extend_from_slice(b"\nnullguard: commit failed: I/O error\n");
        let mut messages = Vec::new();
        relay_diagnostics(&input[..], |message| messages.push(message));
        assert_eq!(messages.len(), 2);
        assert!(messages[0].contains("not valid UTF-8"));
        assert!(messages[1].contains("commit failed"));
        assert!(messages.iter().all(|m| m.len() <= 4096));
    }
}
