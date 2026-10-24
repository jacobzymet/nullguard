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
