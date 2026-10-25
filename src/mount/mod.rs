//! Exposing a vault's filesystem to the operating system.
//!
//! * Linux: FUSE through `/dev/fuse`, implemented in pure Rust (no libfuse
//!   needed). Mounting uses the system's `fusermount3` helper, which every
//!   FUSE-enabled distribution ships.
//! * macOS: FUSE through macFUSE (or FUSE-T).
//! * Windows: a drive letter through WinFsp, which the user installs once
//!   (see `winfsp.rs`).

use std::path::Path;

use crate::vault::Error;
use crate::vault::fs::Fs;

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod fuse;
#[cfg(windows)]
mod winfsp;

#[derive(Default)]
pub struct MountOptions {
    pub read_only: bool,
    /// Forbid executing programs stored in the vault (not on Windows).
    pub no_exec: bool,
    /// Follow symbolic links that lead out of the vault (Linux, macOS).
    /// Off by default: in a vault someone else can write to, such a link
    /// could send files you save "into the vault" somewhere outside it.
    pub allow_outside_links: bool,
    /// Called once the filesystem is mounted.
    pub on_ready: Option<Box<dyn Fn() + Send>>,
}

/// Whether this build can mount vaults.
pub const SUPPORTED: bool = cfg!(any(target_os = "linux", target_os = "macos", windows));

/// Check a mount point before unlocking (which takes seconds): on Linux and
/// macOS an existing, empty directory (mounting over files would hide
/// them); on Windows a free drive letter.
pub fn check_mountpoint(mountpoint: &Path) -> Result<(), Error> {
    #[cfg(windows)]
    {
        winfsp::check_mountpoint(mountpoint)
    }
    #[cfg(not(windows))]
    {
        let meta = std::fs::metadata(mountpoint)
            .map_err(|_| Error::Usage(format!("mount point {} does not exist", mountpoint.display())))?;
        if !meta.is_dir() {
            return Err(Error::Usage(format!("mount point {} is not a directory", mountpoint.display())));
        }
        if std::fs::read_dir(mountpoint)?.next().is_some() {
            return Err(Error::Usage(format!("mount point {} is not empty", mountpoint.display())));
        }
        Ok(())
    }
}

/// Mount `fs` at `mountpoint` and serve it until it is unmounted
/// (`nullguard unmount` or Ctrl-C). All changes are committed before this
/// returns.
pub fn mount(fs: Fs, mountpoint: &Path, opts: &MountOptions) -> Result<(), Error> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        fuse::mount(fs, mountpoint, opts)
    }
    #[cfg(windows)]
    {
        winfsp::mount(fs, mountpoint, opts)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
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
    #[cfg(windows)]
    {
        winfsp::unmount(mountpoint)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = mountpoint;
        Err(unsupported())
    }
}

/// The error returned where mounting isn't available.
pub fn unsupported() -> Error {
    Error::Usage(
        "mounting is not supported on this platform. Use `nullguard ls`, `get`, `put`, `rm` and `mkdir` \
         to work with the vault's files."
            .into(),
    )
}
