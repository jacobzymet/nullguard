//! nullguard: encrypted vault containers that mount as drives.
//!
//! Layers, bottom to top:
//!
//! * [`crypto`]: wrappers over audited crypto crates (XChaCha20-Poly1305,
//!   Argon2id, HKDF/HMAC-SHA256), keyfiles, and zeroizing secret types.
//! * [`vault`]: the container format: versioned header with key slots,
//!   the authenticated chunk store, and the copy-on-write filesystem,
//!   which also authenticates the header.
//! * [`mount`]: exposes a vault's filesystem to the OS (FUSE).
//! * [`cli`]: the `nullguard` command line.
#![deny(unsafe_code)]

pub mod cli;
pub mod crypto;
pub mod mount;
pub mod platform;
pub mod vault;

/// Entry points for the fuzz tests in `fuzz/`. Only compiled into fuzz
/// builds (cargo-fuzz sets `--cfg fuzzing`), never into nullguard itself.
#[cfg(fuzzing)]
pub mod fuzzing {
    use crate::crypto::Keyfile;
    use crate::vault::header::{HEADER_AREA, Header};

    pub use crate::vault::fs::fuzzing::{metadata, superblock};

    /// Header parser. Input is zero-padded to one header copy. Anything it
    /// accepts must re-encode to exactly the same bytes (one valid encoding).
    pub fn header(data: &[u8]) {
        let mut buf = data.to_vec();
        buf.resize(buf.len().max(HEADER_AREA as usize), 0);
        if let Ok(h) = Header::parse(&buf) {
            assert_eq!(h.to_bytes(), buf[..HEADER_AREA as usize], "header encoding is not canonical");
        }
    }

    /// Keyfile parser. Anything it accepts must survive encode/decode.
    pub fn keyfile(data: &[u8]) {
        let Ok(text) = std::str::from_utf8(data) else { return };
        if let Ok(k) = Keyfile::decode(text) {
            let again = Keyfile::decode(&k.encode()).expect("an encoded keyfile must decode");
            assert_eq!(*k.encode(), *again.encode(), "keyfile changed in a round trip");
        }
    }
}
