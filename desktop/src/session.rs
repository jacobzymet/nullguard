use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;

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
            .stderr(Stdio::null());
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

impl Drop for Session {
    fn drop(&mut self) {
        // Closing the input pipe asks a live worker to unmount. Cleanup is
        // harmless before exit too: remove_dir never removes a mounted tree.
        paths::cleanup_mountpoint(&self.mountpoint);
    }
}
