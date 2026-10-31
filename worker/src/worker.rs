use std::io::{self, Write};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use nullguard::{
    crypto::{Argon2Params, kdf},
    mount,
    vault::{CreateOptions, Credential, Vault},
};

use crate::protocol::{Control, Event, Operation, Request, read_packet};
use nullguard_worker::validate_password;

#[derive(Clone)]
struct Emitter(Arc<Mutex<io::Stdout>>);

impl Emitter {
    fn send(&self, event: &Event) {
        if let Ok(mut out) = self.0.lock() {
            let _ = serde_json::to_writer(&mut *out, event);
            let _ = out.write_all(b"\n");
            let _ = out.flush();
        }
    }
}

pub fn run() -> Result<()> {
    let emitter = Emitter(Arc::new(Mutex::new(io::stdout())));
    emitter.send(&Event::Ready { protocol_version: crate::protocol::PROTOCOL_VERSION });
    let result = serve(emitter.clone());
    if let Err(e) = &result {
        emitter.send(&Event::Error(format!("{e:#}")));
    }
    result
}

enum Command {
    Lock,
    Disconnected,
}

fn serve(out: Emitter) -> Result<()> {
    // No shared stdin buffer may retain the password for the mount's lifetime.
    #[cfg(unix)]
    let mut input =
        std::fs::File::from(std::os::fd::AsFd::as_fd(&io::stdin()).try_clone_to_owned()?);
    #[cfg(windows)]
    let mut input = std::fs::File::from(
        std::os::windows::io::AsHandle::as_handle(&io::stdin()).try_clone_to_owned()?,
    );
    let packet = read_packet(&mut input)?.context("the desktop app disconnected")?;
    let mut request: Request =
        serde_json::from_slice(&packet).context("invalid desktop request")?;
    drop(packet);
    if request.password.len() > nullguard::cli::MAX_PASSWORD_BYTES {
        bail!(
            "passwords are limited to {} bytes",
            nullguard::cli::MAX_PASSWORD_BYTES
        );
    }
    request.password = kdf::normalize_password(&request.password);
    let path = request.vault.decode()?;
    let mountpoint = request.mountpoint.decode()?;
    let cancelled = Arc::new(AtomicBool::new(false));
    let (commands, receiver) = mpsc::sync_channel(1);
    let control_cancelled = cancelled.clone();
    std::thread::spawn(move || {
        while let Ok(Some(packet)) = read_packet(&mut input) {
            match serde_json::from_slice::<Control>(&packet) {
                Ok(Control::Lock) => {
                    match commands.try_send(Command::Lock) {
                        Ok(()) | Err(mpsc::TrySendError::Full(_)) => {}
                        Err(mpsc::TrySendError::Disconnected(_)) => break,
                    }
                }
                Ok(Control::Cancel) => {
                    control_cancelled.store(true, Ordering::SeqCst);
                }
                Err(_) => break,
            }
        }
        control_cancelled.store(true, Ordering::SeqCst);
        let _ = commands.send(Command::Disconnected);
    });

    let creating = matches!(request.operation, Operation::Create { .. });
    if let Operation::Create { size, low_memory } = request.operation {
        validate_password(&request.password)?;
        let opts = CreateOptions {
            size,
            kdf: if low_memory {
                Argon2Params::LOW_MEMORY
            } else {
                Argon2Params::DEFAULT
            },
            chunk_size: None,
            fill_random: true,
        };
        let mut percent = u64::MAX;
        let result = Vault::create_cancellable(
            &path,
            request.password.as_bytes(),
            &opts,
            &mut |done, total| {
                let next = done.saturating_mul(100) / total.max(1);
                if next != percent {
                    percent = next;
                    out.send(&Event::Progress {
                        fraction: done as f32 / total.max(1) as f32,
                    });
                }
            },
            &|| cancelled.load(Ordering::SeqCst),
        );
        if let Err(e) = result {
            if cancelled.load(Ordering::SeqCst) {
                out.send(&Event::Cancelled);
                return Ok(());
            }
            return Err(e.into());
        }
        out.send(&Event::Created);
    }
    if cancelled.load(Ordering::SeqCst) {
        out.send(&Event::Cancelled);
        return Ok(());
    }
    let keyfile = request
        .keyfile
        .as_ref()
        .map(|p| -> Result<_> { nullguard::cli::read_keyfile(&p.decode()?) })
        .transpose()?;
    let credential = match &keyfile {
        Some(k) => Credential::Keyfile(k),
        None => Credential::Password(request.password.as_bytes()),
    };
    let verifying = matches!(request.operation, Operation::Verify);
    if !verifying {
        mount::check_mountpoint(&mountpoint)?;
    }
    let vault =
        Vault::open_with_kdf_limits(&path, credential, request.read_only || verifying,
            if request.allow_expensive_kdf && !creating { kdf::KdfLimits::FORMAT_MAX } else { kdf::KdfLimits::STANDARD }).with_context(|| {
            if creating {
                "The vault was created, but could not be unlocked"
            } else {
                "Could not unlock the vault"
            }
        })?;
    let mut warnings = vault.warnings.clone();
    if verifying {
        warnings.extend(vault.check_headers()?);
    }
    let mut fs = vault.into_fs()?;
    warnings.extend(fs.warnings.iter().cloned());
    // Drop the submitted password and keyfile as soon as they are no longer needed.
    let read_only = request.read_only;
    drop(request);
    drop(keyfile);
    if nullguard::crypto::secret::memory_lock_failed() {
        warnings.push("Key memory could not be locked into RAM. Use encrypted swap or increase the locked-memory limit.".into());
    }
    for warning in &warnings {
        out.send(&Event::Warning(warning.clone()));
    }
    if verifying {
        let report = fs.verify()?;
        if !warnings.is_empty() || !report.bad_blocks.is_empty() {
            bail!(
                "Integrity check found {} damaged block(s) and {} warning(s). Keep the original vault and check your backup.",
                report.bad_blocks.len(),
                warnings.len()
            );
        }
        out.send(&Event::Verified {
            files: report.files,
            blocks: report.blocks_checked,
        });
        return Ok(());
    }
    if cancelled.load(Ordering::SeqCst) {
        out.send(&Event::Cancelled);
        return Ok(());
    }
    // Windows' mounting adapter is intentionally one mount per process.
    // A worker per session also makes process exit the key-disposal boundary.
    let (ready, is_ready) = mpsc::channel();
    let control_out = out.clone();
    let control_mount = mountpoint.clone();
    std::thread::spawn(move || {
        if is_ready.recv().is_err() {
            return;
        }
        while let Ok(command) = receiver.recv() {
            match command {
                Command::Lock => match mount::unmount(&control_mount) {
                    Ok(()) => return,
                    Err(e) => control_out.send(&Event::LockFailed(format!(
                        "{e}. Close files and windows using the vault, then try Lock again."
                    ))),
                },
                Command::Disconnected => {
                    // If the GUI crashes, keep retrying a normal unmount.
                    // Never kill a writer or pretend a busy vault is locked.
                    loop {
                        if mount::unmount(&control_mount).is_ok() {
                            return;
                        }
                        std::thread::sleep(Duration::from_secs(1));
                    }
                }
            }
        }
    });
    let ready_out = out.clone();
    mount::mount(
        fs,
        &mountpoint,
        &mount::MountOptions {
            read_only,
            on_ready: Some(Box::new(move || {
                ready_out.send(&Event::Mounted);
                let _ = ready.send(());
            })),
            ..Default::default()
        },
    )?;
    // This means mount() returned after its final commit. The GUI additionally
    // waits for this process to exit before displaying Locked.
    out.send(&Event::Finished);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn new_password_policy_matches_the_cli() {
        assert!(validate_password("too short").is_err());
        assert!(validate_password("twelve characters").is_ok());
        assert!(validate_password(&"x".repeat(4097)).is_err());
    }
}
