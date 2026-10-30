use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::collections::HashSet;

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
}

impl Session {
    pub fn start(
        id: u64,
        request: &Request,
        sender: mpsc::Sender<Message>,
        ctx: eframe::egui::Context,
    ) -> Result<Self> {
        let mountpoint = request.mountpoint.decode()?;
        let mut command = Command::new(std::env::current_exe()?);
        command
            .arg("--mount-worker")
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
            .context("Could not start the vault worker")?;
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
            let mut reader = BufReader::new(output);
            loop {
                let mut line = String::new();
                // Worker output contains no secrets; bound it nevertheless.
                match reader.by_ref().take(256 * 1024).read_line(&mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        if let Ok(event) = serde_json::from_str::<Event>(&line) {
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
            let _ = sender.send(Message::Exited(id, success));
            ctx.request_repaint();
        });
        Ok(Self { input, mountpoint })
    }

    pub fn send(&mut self, control: Control) -> Result<()> {
        serde_json::to_writer(&mut self.input, &control)?;
        self.input.write_all(b"\n")?;
        self.input.flush()?;
        Ok(())
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
