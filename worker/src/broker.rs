//! Keyless unmount broker. Its private pipe permits only one fixed mountpoint
//! and never accepts credentials, arbitrary commands, or further paths.
use std::io::{BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use nullguard_worker::protocol::{LocalPath, read_packet};

#[derive(Serialize, Deserialize)]
enum Control { Activate, Lock }

pub struct Broker {
    child: Child,
    input: Option<ChildStdin>,
    output: BufReader<ChildStdout>,
    locked: bool,
}

impl Broker {
    pub fn spawn(path: &Path) -> Result<Self> {
        // Spawn before unlocking the vault. Anonymous pipes grant no general
        // IPC endpoint. The broker receives neither credentials nor vault FDs.
        let mut child = Command::new(std::env::current_exe()?)
            .arg("--unmount-broker")
            .env("PATH", "/usr/bin:/bin")
            .env_remove("LD_PRELOAD").env_remove("LD_LIBRARY_PATH")
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit())
            .spawn().context("could not start the keyless unmount broker")?;
        let input = child.stdin.take().context("missing broker input")?;
        let output = BufReader::new(child.stdout.take().context("missing broker output")?);
        let mut broker = Self { child, input: Some(input), output, locked: false };
        broker.send(&LocalPath::new(path))?;
        broker.reply()?;
        Ok(broker)
    }

    fn send(&mut self, message: &impl Serialize) -> Result<()> {
        let input = self.input.as_mut().context("unmount broker disconnected")?;
        serde_json::to_writer(&mut *input, message)?;
        input.write_all(b"\n")?;
        input.flush()?;
        Ok(())
    }

    fn reply(&mut self) -> Result<()> {
        let packet = read_packet(&mut self.output)?.context("unmount broker disconnected")?;
        match serde_json::from_slice::<std::result::Result<(), String>>(&packet)? {
            Ok(()) => Ok(()), Err(error) => bail!("{error}"),
        }
    }

    pub fn activate(&mut self) -> Result<()> {
        self.send(&Control::Activate)?;
        self.reply()
    }

    pub fn lock(&mut self) -> Result<()> {
        if self.locked { return Ok(()); }
        self.send(&Control::Lock)?;
        self.reply()?;
        self.locked = true;
        Ok(())
    }
}

impl Drop for Broker {
    fn drop(&mut self) {
        self.input.take(); // EOF: retry clean unmount if the worker crashed
        let _ = self.child.try_wait(); // never kill a live mount on teardown
    }
}

fn mount_id(path: &Path) -> Result<Option<u64>> {
    let table = std::fs::read("/proc/self/mountinfo")?;
    Ok(find_mount(&table, path))
}

fn find_mount(table: &[u8], path: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    for line in table.split(|&byte| byte == b'\n') {
        let fields: Vec<_> = line.split(|&byte| byte == b' ').collect();
        if fields.len() < 7 { continue; }
        let mut decoded = Vec::new();
        let mut cursor = fields[4];
        while !cursor.is_empty() {
            let escape = cursor.get(..4).and_then(|bytes| match bytes {
                b"\\040" => Some(b' '), b"\\011" => Some(b'\t'),
                b"\\012" => Some(b'\n'), b"\\134" => Some(b'\\'), _ => None,
            });
            if let Some(byte) = escape {
                decoded.push(byte);
                cursor = &cursor[4..];
            } else {
                decoded.push(cursor[0]);
                cursor = &cursor[1..];
            }
        }
        let Some(separator) = fields.iter().position(|field| *field == b"-") else { continue };
        let filesystem = fields.get(separator + 1).copied();
        let source = fields.get(separator + 2).copied();
        // Root can use fuser's direct mount path, which uses type `fuse` and
        // source `nullguard`; fusermount uses subtype `fuse.nullguard`.
        let vault_mount = filesystem == Some(b"fuse.nullguard".as_slice())
            || (filesystem == Some(b"fuse".as_slice()) && source == Some(b"nullguard".as_slice()));
        if decoded == path.as_os_str().as_bytes() && vault_mount {
            return std::str::from_utf8(fields[0]).ok()?.parse().ok();
        }
    }
    None
}

fn respond(result: Result<()>) -> Result<()> {
    let result = result.map_err(|error| error.to_string());
    let mut output = std::io::stdout().lock();
    serde_json::to_writer(&mut output, &result)?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(())
}

pub fn run() -> Result<()> {
    let mut input = std::io::stdin().lock();
    let packet = read_packet(&mut input)?.context("missing broker mountpoint")?;
    let path: PathBuf = serde_json::from_slice::<LocalPath>(&packet)?.decode()?;
    // Resolve before mounting. This also prevents option-like relative paths.
    let path = std::fs::canonicalize(path)?;
    nullguard::mount::check_mountpoint(&path)?;
    respond(Ok(()))?;
    let mut active = None;
    let outcome = (|| -> Result<()> {
        while let Some(packet) = read_packet(&mut input)? {
            match serde_json::from_slice::<Control>(&packet)? {
                Control::Activate if active.is_none() => {
                    let id = mount_id(&path)?.context("vault mount not found");
                    if let Err(error) = id {
                        respond(Err(error))?;
                        return Ok(());
                    }
                    active = Some(id?);
                    respond(Ok(()))?;
                }
                Control::Lock if active.is_some() => {
                    let result = match mount_id(&path)? {
                        None => Ok(()),
                        Some(id) if Some(id) == active => nullguard::mount::unmount(&path).map_err(anyhow::Error::from),
                        Some(_) => Err(anyhow::anyhow!("mountpoint was reused; refusing to unmount another filesystem")),
                    };
                    let success = result.is_ok();
                    respond(result)?;
                    if success { active = None; return Ok(()); }
                }
                _ => bail!("invalid unmount broker state"),
            }
        }
        Ok(())
    })();
    // Mountinfo remains readable even when a killed FUSE server makes stat()
    // return ENOTCONN. Never unmount a different mount that reused this path.
    while active.is_some() && mount_id(&path)? == active {
        if nullguard::mount::unmount(&path).is_ok() { break; }
        std::thread::sleep(Duration::from_secs(1));
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_identity_uses_kernel_records_and_escaped_paths() {
        let table = b"42 1 0:9 / /tmp/a\\040b\\134c rw - fuse.nullguard nullguard rw\n43 1 0:10 / /tmp/other rw - tmpfs tmpfs rw\n";
        assert_eq!(find_mount(table, Path::new("/tmp/a b\\c")), Some(42));
        assert_eq!(find_mount(table, Path::new("/tmp/other")), None);
        assert_eq!(find_mount(table, Path::new("/tmp/missing")), None);
        assert_eq!(find_mount(b"44 1 0:11 / /direct rw - fuse nullguard rw\n", Path::new("/direct")), Some(44));
    }
}
