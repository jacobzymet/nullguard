//! Private parent/worker pipe protocol. Secrets never travel in argv or logs.

use std::ffi::OsString;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const MAX_PACKET: usize = 256 * 1024;
pub const PROTOCOL_VERSION: u32 = 1;

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
    #[serde(with = "password_bytes")]
    pub password: Zeroizing<String>,
    pub read_only: bool,
    #[serde(default)]
    pub allow_expensive_kdf: bool,
}

// JSON string escapes are decoded through serde_json's ordinary Vec scratch
// buffer, which is not wiped. A numeric byte array avoids putting a decoded
// password in that buffer. Bound the decoded bytes before allocating more,
// and keep both the byte buffer and the resulting string zeroizing.
mod password_bytes {
    use serde::{Deserializer, Serializer, de::{Error, SeqAccess, Visitor}};
    use zeroize::Zeroizing;

    pub fn serialize<S: Serializer>(password: &str, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(password.as_bytes())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Zeroizing<String>, D::Error> {
        struct Password;
        impl<'de> Visitor<'de> for Password {
            type Value = Zeroizing<String>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a bounded UTF-8 byte array")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
                let limit = nullguard::cli::MAX_PASSWORD_BYTES;
                let mut bytes = Zeroizing::new(Vec::with_capacity(limit));
                while let Some(byte) = sequence.next_element::<u8>()? {
                    if bytes.len() == limit {
                        return Err(A::Error::custom("password exceeds the byte limit"));
                    }
                    bytes.push(byte);
                }
                let text = std::str::from_utf8(&bytes)
                    .map_err(|_| A::Error::custom("password is not valid UTF-8"))?;
                Ok(Zeroizing::new(text.to_owned()))
            }
        }
        // Serde's default type errors can include the rejected value. Never
        // relay that value to the GUI if a malformed request uses a string.
        deserializer.deserialize_seq(Password)
            .map_err(|_| D::Error::custom("invalid password encoding or length"))
    }
}

#[derive(Deserialize, Serialize)]
pub enum Control {
    Lock,
    Cancel,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Event {
    Ready { protocol_version: u32 },
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

    fn request_with(password: &str) -> Request {
        Request {
            operation: Operation::Verify,
            vault: LocalPath::new(Path::new("test.ngv")),
            mountpoint: LocalPath::new(Path::new("")),
            keyfile: None,
            password: Zeroizing::new(password.to_owned()),
            read_only: true,
            allow_expensive_kdf: false,
        }
    }

    #[test]
    fn passwords_use_byte_arrays_and_roundtrip_special_characters() {
        let password = "quotes \" backslash \\ tab\t unicode 🔒";
        let request = request_with(password);
        let packet = serde_json::to_vec(&request).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&packet).unwrap();
        assert!(value["password"].is_array());
        let decoded: Request = serde_json::from_slice(&packet).unwrap();
        assert_eq!(&*decoded.password, password);
    }

    #[test]
    fn password_decode_limits_and_invalid_utf8_fail_without_echoing_input() {
        let request = request_with("");
        let mut value = serde_json::to_value(&request).unwrap();
        for invalid in [
            serde_json::json!([255]),
            serde_json::json!(vec![65u8; nullguard::cli::MAX_PASSWORD_BYTES + 1]),
            serde_json::json!("do not echo this password"),
        ] {
            value["password"] = invalid;
            let error = match serde_json::from_value::<Request>(value.clone()) {
                Ok(_) => panic!("invalid password encoding was accepted"),
                Err(error) => error.to_string(),
            };
            assert!(!error.contains("do not echo this password"));
        }
        let request = request_with(&"a".repeat(nullguard::cli::MAX_PASSWORD_BYTES));
        let packet = serde_json::to_vec(&request).unwrap();
        assert!(serde_json::from_slice::<Request>(&packet).is_ok());
    }

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
