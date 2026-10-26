//! Private parent/worker pipe protocol. Secrets never travel in argv or logs.

use std::ffi::OsString;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const MAX_PACKET: usize = 256 * 1024;

/// OS-native path encoding preserves non-UTF-8 Unix names and Windows UTF-16.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct LocalPath(pub Vec<u8>);

impl LocalPath {
    pub fn new(path: &Path) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            Self(path.as_os_str().as_bytes().to_vec())
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            Self(
                path.as_os_str()
                    .encode_wide()
                    .flat_map(u16::to_le_bytes)
                    .collect(),
            )
        }
    }

    pub fn decode(&self) -> Result<PathBuf> {
        if self.0.len() > 128 * 1024 {
            bail!("the selected path is too long");
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            if self.0.contains(&0) {
                bail!("invalid path");
            }
            Ok(OsString::from_vec(self.0.clone()).into())
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStringExt;
            if !self.0.len().is_multiple_of(2) {
                bail!("invalid path encoding");
            }
            let wide: Vec<_> = self
                .0
                .as_chunks::<2>()
                .0
                .iter()
                .map(|p| u16::from_le_bytes([p[0], p[1]]))
                .collect();
            if wide.contains(&0) {
                bail!("invalid path");
            }
            Ok(OsString::from_wide(&wide).into())
        }
    }
}

#[derive(Deserialize, Serialize)]
pub enum Operation {
    Create { size: u64, low_memory: bool },
    Unlock,
    Verify,
}

// Deliberately no Debug: it must never print the password.
#[derive(Deserialize, Serialize)]
pub struct Request {
    pub operation: Operation,
    pub vault: LocalPath,
    pub mountpoint: LocalPath,
    pub keyfile: Option<LocalPath>,
    pub password: Zeroizing<String>,
    pub read_only: bool,
}

#[derive(Deserialize, Serialize)]
pub enum Control {
    Lock,
    Cancel,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Event {
    Progress { fraction: f32 },
    Created,
    Mounted,
    Warning(String),
    LockFailed(String),
    Error(String),
    Cancelled,
    Finished,
    Verified { files: u64, blocks: u64 },
}

/// Avoid buffered stdin retaining a secret after the vault has been unlocked.
pub fn read_packet(input: &mut impl Read) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let mut packet = Zeroizing::new(Vec::with_capacity(MAX_PACKET));
    let mut byte = [0u8; 1];
    loop {
        match input.read(&mut byte) {
            Ok(0) if packet.is_empty() => return Ok(None),
            Ok(0) => bail!("the desktop app disconnected while sending a request"),
            Ok(_) if byte[0] == b'\n' => return Ok(Some(packet)),
            Ok(_) if packet.len() == MAX_PACKET => bail!("desktop request is too large"),
            Ok(_) => packet.push(byte[0]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packets_are_bounded_and_not_read_ahead() {
        let mut input = &b"first\nsecond\n"[..];
        assert_eq!(
            &**read_packet(&mut input).unwrap().as_ref().unwrap(),
            b"first"
        );
        assert_eq!(input, b"second\n");
        assert!(read_packet(&mut &vec![b'x'; MAX_PACKET + 1][..]).is_err());
        assert!(read_packet(&mut &b"incomplete"[..]).is_err());
    }

    #[test]
    fn paths_roundtrip_without_unicode_substitution() {
        let p = Path::new("a folder/vault.ngv");
        assert_eq!(LocalPath::new(p).decode().unwrap(), p);
        #[cfg(unix)]
        assert_eq!(
            LocalPath(vec![b'v', 0xff])
                .decode()
                .unwrap()
                .as_os_str()
                .as_encoded_bytes(),
            [b'v', 0xff]
        );
        assert!(LocalPath(vec![0, 0]).decode().is_err());
    }
}
