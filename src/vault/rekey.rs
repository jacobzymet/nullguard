//! `rekey`: move a vault to a brand-new master key.
//!
//! Changing the password only re-wraps the existing master key, so anyone
//! holding an old copy of the vault file and the old password can still
//! recover that key. Rekeying replaces the master key itself, using only
//! code nullguard already has:
//!
//! 1. create a new vault (fresh master key, new password) next to the old
//!    one, with the same capacity;
//! 2. copy every file, directory and symlink across;
//! 3. authenticate every block of the copy and check nothing is missing;
//! 4. replace the old vault file with the new one in a single rename.
//!
//! If anything fails before step 4, the new file is deleted and the old
//! vault is untouched. Keyfiles are not carried over (they unlock the old
//! master key); add back the ones you still trust.

use std::path::{Path, PathBuf};

use super::fs::{Fs, Kind, ROOT_INO, SetAttr, Timestamp};
use super::{CreateOptions, Credential, Error, Vault};
use crate::crypto::Argon2Params;

/// What a rekey did.
#[derive(Debug, Default)]
pub struct RekeyReport {
    pub files: u64,
    pub dirs: u64,
    pub symlinks: u64,
    /// Keyfiles that unlocked the old vault and no longer work.
    pub keyfiles_dropped: usize,
    /// Warnings raised while opening the old vault (show them to the user).
    pub warnings: Vec<String>,
}

/// Where the new vault is built before it replaces the old one.
pub fn temp_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".rekey-tmp");
    path.with_file_name(name)
}

/// Rekey the vault at `path`: afterwards only `new_password` unlocks it,
/// under a new master key. `progress` reports the random fill of the new
/// vault, as for [`Vault::create`].
pub fn rekey(
    path: &Path,
    cred: Credential<'_>,
    new_password: &[u8],
    kdf: Argon2Params,
    progress: &mut dyn FnMut(u64, u64),
) -> Result<RekeyReport, Error> {
    // Work on the real file: renaming over a symbolic link would replace
    // the link and leave the old-key vault in place where it points.
    let shown = temp_path(path);
    let path = &std::fs::canonicalize(path)?;
    let tmp = temp_path(path);
    if tmp.exists() {
        return Err(Error::Usage(format!(
            "{} already exists, probably left by an interrupted rekey. The vault itself is intact; \
             delete that file and try again",
            shown.display()
        )));
    }
    // Opened for writing only to hold the exclusive lock: nothing else may
    // change the vault while it is being copied.
    let old = Vault::open(path, cred, false)?;
    let mut report = RekeyReport { keyfiles_dropped: old.header().keyfiles.len(), ..Default::default() };
    report.warnings = old.warnings.clone();
    let size = old.header().file_len();
    let chunk_size = old.header().chunk_size;
    let mut old_fs = old.into_fs()?;
    old_fs.set_auto_commit(false);
    report.warnings.extend(old_fs.warnings.iter().cloned());

    // Same chunk size and file size, so the new vault has the same capacity.
    let opts = CreateOptions { size, kdf, chunk_size: Some(chunk_size), fill_random: true };
    Vault::create(&tmp, new_password, &opts, progress)?;

    let result = (|| {
        let mut new_fs = Vault::open(&tmp, Credential::Password(new_password), false)?.into_fs()?;
        new_fs.set_auto_commit(false);
        copy_tree(&mut old_fs, &mut new_fs, &mut report)?;
        new_fs.commit()?;
        drop(new_fs);

        // Authenticate every block of the copy, and check nothing is missing.
        let mut check = Vault::open(&tmp, Credential::Password(new_password), true)?.into_fs()?;
        let v = check.verify()?;
        if !v.bad_blocks.is_empty() || !check.warnings.is_empty() {
            return Err(Error::Corrupt("the new vault failed verification; the old vault is unchanged".into()));
        }
        if (v.files, v.dirs, v.symlinks) != (report.files, report.dirs, report.symlinks) {
            return Err(Error::Corrupt("the new vault is missing entries; the old vault is unchanged".into()));
        }
        Ok(())
    })();
    if let Err(e) = result {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }

    // Close the old vault (Windows can't replace an open file), then swap.
    drop(old_fs);
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    sync_parent_dir(path);
    Ok(report)
}

/// Copy everything under the root of `from` into the root of `to`,
/// keeping names, permissions and access/modification times.
/// Blocks that are all zeros are left as holes. Iterative, so deep trees
/// can't overflow the stack.
fn copy_tree(from: &mut Fs, to: &mut Fs, report: &mut RekeyReport) -> Result<(), Error> {
    let mut dir_times = Vec::new();
    let mut stack = vec![(ROOT_INO, ROOT_INO)];
    while let Some((src_dir, dst_dir)) = stack.pop() {
        report.dirs += 1;
        let a = from.attr(src_dir)?;
        if dst_dir == ROOT_INO {
            to.set_attr(ROOT_INO, &SetAttr { perm: Some(a.perm), ..Default::default() })?;
        }
        dir_times.push((dst_dir, a.atime, a.mtime));
        for e in from.readdir(src_dir)? {
            if e.name == b"." || e.name == b".." {
                continue;
            }
            let a = from.attr(e.ino)?;
            let new = match a.kind {
                Kind::Dir => {
                    let d = to.mkdir(dst_dir, &e.name, a.perm)?;
                    stack.push((e.ino, d));
                    continue; // times are set once its contents are copied
                }
                Kind::Symlink => {
                    report.symlinks += 1;
                    to.symlink(dst_dir, &e.name, &from.readlink(e.ino)?)?
                }
                Kind::File => {
                    report.files += 1;
                    let f = to.create_file(dst_dir, &e.name, a.perm)?;
                    let block = a.blksize as usize;
                    let mut off = 0;
                    while off < a.size {
                        let data = from.read(e.ino, off, block)?;
                        if data.iter().any(|&b| b != 0) {
                            to.write(f, off, &data)?;
                        }
                        off += data.len() as u64;
                    }
                    to.set_attr(f, &SetAttr { size: Some(a.size), ..Default::default() })?;
                    f
                }
            };
            set_times(to, new, a.atime, a.mtime)?;
        }
    }
    // Last, because adding entries to a directory updates its times.
    for (dir, atime, mtime) in dir_times {
        set_times(to, dir, atime, mtime)?;
    }
    Ok(())
}

fn set_times(fs: &mut Fs, ino: u64, atime: Timestamp, mtime: Timestamp) -> Result<(), Error> {
    fs.set_attr(ino, &SetAttr { atime: Some(atime), mtime: Some(mtime), ..Default::default() })?;
    Ok(())
}

/// Make the rename itself durable (unix; Windows has no directory fsync).
fn sync_parent_dir(path: &Path) {
    #[cfg(unix)]
    if let Some(dir) = path.parent() {
        let dir = if dir.as_os_str().is_empty() { Path::new(".") } else { dir };
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}
