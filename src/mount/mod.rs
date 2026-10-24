//! Exposing a vault's filesystem to the operating system.
//!
//! * Linux: FUSE through `/dev/fuse`, implemented in pure Rust (no libfuse
//!   needed). Mounting uses the system's `fusermount3` helper, which every
//!   FUSE-enabled distribution ships.
//! * macOS: FUSE through macFUSE (or FUSE-T).
//! * Windows: WinFsp support is planned. Until then use the offline
//!   commands (`ls`, `get`, `put`, ...).

use std::path::Path;

use crate::vault::Error;
use crate::vault::fs::Fs;

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod fuse;

#[derive(Default)]
pub struct MountOptions {
    pub read_only: bool,
    /// Forbid executing programs stored in the vault.
    pub no_exec: bool,
    /// Called once the filesystem is mounted.
    pub on_ready: Option<Box<dyn Fn() + Send>>,
}

/// Whether this build can mount vaults.
pub const SUPPORTED: bool = cfg!(any(target_os = "linux", target_os = "macos"));

/// Mount `fs` at `mountpoint` and serve it until it is unmounted
/// (`nullguard unmount`, `fusermount3 -u`, or Ctrl-C). All changes are
/// committed before this returns.
pub fn mount(fs: Fs, mountpoint: &Path, opts: &MountOptions) -> Result<(), Error> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        fuse::mount(fs, mountpoint, opts)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (fs, mountpoint, opts);
        Err(unsupported())
    }
}

/// Unmount a vault mounted by `nullguard mount`.
pub fn unmount(mountpoint: &Path) -> Result<(), Error> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        fuse::unmount(mountpoint)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = mountpoint;
        Err(unsupported())
    }
}

/// The error returned where mounting isn't available.
pub fn unsupported() -> Error {
    Error::Usage(
        "mounting is not supported on this platform yet (Windows support via WinFsp is planned). \
         Meanwhile, use `nullguard ls`, `get`, `put`, `rm` and `mkdir` to work with the vault's files."
            .into(),
    )
}
