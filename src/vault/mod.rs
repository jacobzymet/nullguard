//! Vault containers: creation, unlocking, key management.
//!
//! A vault is one ordinary file:
//!
//! ```text
//! [ primary header 4 KiB ][ backup header 4 KiB ][ chunk 0 ][ chunk 1 ] ...
//! ```
//!
//! See `header` for the header, `chunks` for the encrypted chunk array and
//! `fs` for the filesystem stored in the chunks.
//!
//! **Which header is current.** A header copy is used only if it unlocks
//! with the given credentials *and* its SHA-256 is the one the newest
//! superblock records. A header change therefore takes effect at a single
//! filesystem commit.

pub mod chunks;
pub mod fs;
pub mod header;
pub mod rekey;

use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use crate::crypto::{Aead, Argon2Params, CryptoError, Keyfile, SecretKey, ct_eq, derive_subkey};
use crate::crypto::secret::ProtectedKey;
use chunks::{ChunkStore, read_exact_at, write_all_at};
use fs::Fs;
use header::{BACKUP_OFFSET, DATA_OFFSET, HEADER_AREA, Header, HeaderError, PRIMARY_OFFSET, chunk_stride};

const LABEL_DATA_KEY: &[u8] = b"nullguard/v2/data-key";

/// `FILE_SHARE_READ` from the Win32 API.
#[cfg(windows)]
const WIN_FILE_SHARE_READ: u32 = 0x1;

/// Everything that can go wrong with a vault.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error(transparent)]
    Header(#[from] HeaderError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error("wrong password or keyfile (or the vault header was modified)")]
    WrongCredentials,
    #[error(
        "these credentials open a vault header that is NOT the vault's current one. Either an old \
         header was put back (for example to undo a password change or a keyfile's removal), or the \
         header was modified. (If a password change was interrupted, try the new password.) Refusing to open"
    )]
    StaleHeader,
    #[error("chunk {chunk} failed authentication: the vault was modified or damaged")]
    ChunkAuth { chunk: u64 },
    #[error("chunk {chunk} is an older version than expected: the vault was rolled back or tampered with")]
    Rollback { chunk: u64 },
    #[error("vault is corrupt: {0}")]
    Corrupt(String),
    #[error("the vault is in use by another nullguard process")]
    InUse,
    #[error("the vault is opened read-only")]
    ReadOnly,
    #[error("no space left in the vault")]
    NoSpace,
    #[error("no such file or directory")]
    NotFound,
    #[error("already exists")]
    Exists,
    #[error("not a directory")]
    NotADirectory,
    #[error("is a directory")]
    IsADirectory,
    #[error("directory not empty")]
    NotEmpty,
    #[error("invalid file name")]
    InvalidName,
    #[error("file name too long")]
    NameTooLong,
    #[error("invalid argument")]
    InvalidArgument,
    #[error("file too large")]
    FileTooBig,
    #[error("{0}")]
    Usage(String),
}

/// How to unlock a vault.
pub enum Credential<'a> {
    Password(&'a [u8]),
    Keyfile(&'a Keyfile),
}

/// Options for [`Vault::create`].
pub struct CreateOptions {
    /// Total size of the vault file in bytes.
    pub size: u64,
    pub kdf: Argon2Params,
    /// Chunk size in bytes; `None` picks one from the vault size. (The
    /// command line always picks; tests use small chunks.)
    pub chunk_size: Option<u32>,
    /// Fill unused space with random bytes, so an observer can't tell how
    /// much of the vault is in use. (The command line always fills.)
    pub fill_random: bool,
}

/// A good default chunk size: small chunks for small vaults (less waste),
/// bigger chunks for big vaults (less metadata).
pub fn auto_chunk_size(size: u64) -> u32 {
    const GIB: u64 = 1 << 30;
    match size {
        s if s <= 8 * GIB => 16 * 1024,
        s if s <= 128 * GIB => 64 * 1024,
        s if s <= 2048 * GIB => 256 * 1024,
        _ => 1024 * 1024,
    }
}

/// An unlocked vault.
pub struct Vault {
    file: File,
    header: Header,
    master: ProtectedKey,
    path: PathBuf,
    read_only: bool,
    /// Security-relevant observations (a damaged header copy etc.). Callers
    /// must show these to the user.
    pub warnings: Vec<String>,
}

impl Vault {
    /// Create a new vault file at `path`. Never overwrites an existing file.
    pub fn create(
        path: &Path,
        password: &[u8],
        opts: &CreateOptions,
        progress: &mut dyn FnMut(u64, u64),
    ) -> Result<(), Error> {
        Self::create_cancellable(path, password, opts, progress, &|| false)
    }

    /// Create a vault with cooperative cancellation. A cancelled creation
    /// removes only the file this call created, as with any other failure.
    pub fn create_cancellable(
        path: &Path,
        password: &[u8],
        opts: &CreateOptions,
        progress: &mut dyn FnMut(u64, u64),
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), Error> {
        if cancelled() {
            return Err(Error::Usage("vault creation cancelled".into()));
        }
        opts.kdf.validate_for_new_slot()?;
        let chunk_size = opts.chunk_size.unwrap_or_else(|| auto_chunk_size(opts.size));
        let chunk_count = opts.size.saturating_sub(DATA_OFFSET) / chunk_stride(chunk_size);
        let master = SecretKey::generate()?;
        let header = Header::create(chunk_size, chunk_count, &master, password, opts.kdf).map_err(|e| match e {
            HeaderError::Malformed("too few chunks") => Error::Usage("vault size is too small".into()),
            other => other.into(),
        })?;
        let aead = data_aead(&master)?;
        drop(master); // do not retain a plaintext master during random filling

        // Only the owner may read the vault: other local users shouldn't even
        // get a copy to attack offline. (Private from the moment it exists,
        // on every OS.)
        #[cfg(unix)]
        let file = {
            let mut oo = OpenOptions::new();
            oo.read(true).write(true).create_new(true);
            std::os::unix::fs::OpenOptionsExt::mode(&mut oo, 0o600);
            oo.open(path)?
        };
        #[cfg(windows)]
        let file = crate::platform::win::create_private_file(path, 0)?;
        let result = (|| {
            file.try_lock().map_err(|_| Error::InUse)?;
            let len = header.file_len();
            file.set_len(len)?;
            if opts.fill_random {
                fill_random(&file, DATA_OFFSET, len, progress, cancelled)?;
            }
            if cancelled() {
                return Err(Error::Usage("vault creation cancelled".into()));
            }
            let bytes = header.to_bytes();
            write_all_at(&file, &bytes, PRIMARY_OFFSET)?;
            write_all_at(&file, &bytes, BACKUP_OFFSET)?;
            let store = ChunkStore::new(file.try_clone()?, &header, aead, false);
            let fs = Fs::format(store, header.hash())?;
            drop(fs);
            file.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            drop(file);
            let _ = std::fs::remove_file(path);
        }
        result
    }

    /// Read the header without unlocking (for `info`). Nothing in it is
    /// trusted until a vault is unlocked.
    pub fn peek_header(path: &Path) -> Result<Header, Error> {
        let file = File::open(path)?;
        let mut buf = vec![0u8; HEADER_AREA as usize];
        read_exact_at(&file, &mut buf, PRIMARY_OFFSET)?;
        match Header::parse(&buf) {
            Ok(h) => Ok(h),
            Err(e) => {
                read_exact_at(&file, &mut buf, BACKUP_OFFSET)?;
                Header::parse(&buf).map_err(|_| e.into())
            }
        }
    }

    /// Unlock a vault.
    ///
    /// The header used is the copy that unlocks with `cred` and whose hash
    /// the newest superblock records. If the other copy differs, it is stale
    /// (an interrupted change) or was tampered with: that is reported, and
    /// unless `read_only`, the copy is restored from the current header.
    pub fn open(path: &Path, cred: Credential<'_>, read_only: bool) -> Result<Self, Error> {
        let mut oo = OpenOptions::new();
        oo.read(true).write(!read_only);
        // Windows: while we write, no other process may open, rename or
        // delete the vault; while we only read, others may read too.
        #[cfg(windows)]
        std::os::windows::fs::OpenOptionsExt::share_mode(&mut oo, if read_only { WIN_FILE_SHARE_READ } else { 0 });
        let file = oo.open(path).map_err(|e| {
            // ERROR_SHARING_VIOLATION: another process has the vault open.
            if cfg!(windows) && e.raw_os_error() == Some(32) { Error::InUse } else { e.into() }
        })?;
        if read_only { file.try_lock_shared() } else { file.try_lock() }.map_err(|_| Error::InUse)?;

        let mut primary = vec![0u8; HEADER_AREA as usize];
        let mut backup = vec![0u8; HEADER_AREA as usize];
        read_exact_at(&file, &mut primary, PRIMARY_OFFSET)?;
        read_exact_at(&file, &mut backup, BACKUP_OFFSET)?;

        // Errors are ranked so the report names the most telling problem:
        // a stale or modified header beats a wrong password, which beats an
        // unreadable copy.
        let rank = |e: &Error| match e {
            Error::Header(_) => 0,
            Error::WrongCredentials | Error::Crypto(_) => 1,
            _ => 2,
        };
        let mut err: Option<Error> = None;
        let mut note = |e: Error| {
            if err.as_ref().is_none_or(|old| rank(&e) > rank(old)) {
                err = Some(e);
            }
        };
        // Parse both copies (one if they are identical), then try the one
        // whose password key derivation is cheaper first. Someone who can
        // write the file could set one copy's Argon2 cost to the maximum
        // nullguard accepts; trying that copy last means it only costs time
        // when the other copy doesn't open.
        let mut candidates = Vec::new();
        for (i, bytes) in [&primary, &backup].into_iter().enumerate() {
            if i == 1 && primary == backup {
                break; // identical: already parsed
            }
            match Header::parse(bytes) {
                Ok(h) => candidates.push((i, h)),
                Err(e) => note(e.into()),
            }
        }
        candidates.sort_by_key(|(i, h)| (kdf_cost(&h.kdf), *i));
        let mut found = None;
        for (i, header) in candidates {
            let unlocked = match &cred {
                Credential::Password(p) => header.unlock_with_password(p),
                Credential::Keyfile(k) => header.unlock_with_keyfile(k),
            };
            let master = match unlocked {
                Ok(Some(m)) => m,
                Ok(None) => {
                    note(Error::WrongCredentials);
                    continue;
                }
                Err(HeaderError::Crypto(CryptoError::MemoryProtection)) => {
                    return Err(CryptoError::MemoryProtection.into());
                }
                // E.g. a tampered copy demanding more memory than exists:
                // that must not stop us from trying the other copy.
                Err(e) => {
                    note(e.into());
                    continue;
                }
            };
            let master = ProtectedKey::new(master)?;
            let aead = master.with_key(data_aead)??;
            let store = ChunkStore::new(file.try_clone()?, &header, aead, true);
            match fs::current_header_hash(&store)? {
                Some(current) if ct_eq(&current, &header.hash()) => {
                    found = Some((i, header, master));
                    break;
                }
                Some(_) => note(Error::StaleHeader),
                None => note(Error::Corrupt(
                    "no superblock can be read: the vault is damaged or was tampered with".into(),
                )),
            }
        }
        let Some((i, header, master)) = found else {
            return Err(err.unwrap_or(Error::WrongCredentials));
        };

        // Check the complete container geometry before repairing either
        // header. Otherwise appended bytes pass verification unnoticed.
        let actual_len = file.metadata()?.len();
        if actual_len != header.file_len() {
            let problem = if actual_len < header.file_len() { "is truncated" } else { "has unexpected trailing bytes" };
            return Err(Error::Corrupt(format!(
                "the vault file {problem} ({actual_len} bytes, expected {})", header.file_len()
            )));
        }
        let mut warnings = Vec::new();
        let current = header.to_bytes();
        let (name, offset, other) = if i == 0 { ("backup", BACKUP_OFFSET, &backup) } else { ("primary", PRIMARY_OFFSET, &primary) };
        if *other != current {
            if read_only {
                warnings.push(stale_copy_warning(name));
            } else {
                write_all_at(&file, &current, offset)?;
                file.sync_data()?;
                warnings.push(format!(
                    "the {name} header copy did not match the vault's current header (an interrupted \
                     password or keyfile change, or tampering). It has been restored from the current header."
                ));
            }
        }
        Ok(Self { file, header, master, path: path.to_owned(), read_only, warnings })
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Open the filesystem inside the vault. The filesystem's own warnings
    /// are in `Fs::warnings`; the vault's stay in [`Vault::warnings`].
    pub fn into_fs(self) -> Result<Fs, Error> {
        let aead = self.master.with_key(data_aead)??;
        let store = ChunkStore::new(self.file.try_clone()?, &self.header, aead, self.read_only);
        Fs::open(store, self.header.hash())
    }

    /// Re-read both header copies and report each one that isn't
    /// byte-for-byte the current header. Empty means both are intact.
    /// Used by `verify`.
    pub fn check_headers(&self) -> Result<Vec<String>, Error> {
        let current = self.header.to_bytes();
        let mut problems = Vec::new();
        for (name, offset) in [("primary", PRIMARY_OFFSET), ("backup", BACKUP_OFFSET)] {
            let mut buf = vec![0u8; HEADER_AREA as usize];
            read_exact_at(&self.file, &mut buf, offset)?;
            if buf != current {
                problems.push(stale_copy_warning(name));
            }
        }
        Ok(problems)
    }

    /// Replace the header, atomically:
    ///
    /// 1. Write the new header to the backup copy. Until step 2, the old
    ///    header stays current, and a crash keeps it.
    /// 2. Commit the filesystem twice, so both superblocks record the new
    ///    header's hash. This is the moment the change takes effect, and
    ///    from then on the old header is refused, even if the newest
    ///    superblock is later destroyed.
    /// 3. Write the new header to the primary copy. A crash before this
    ///    leaves a stale primary, which the next writable open restores.
    fn write_header(&mut self, new: Header) -> Result<(), Error> {
        if self.read_only {
            return Err(Error::ReadOnly);
        }
        let aead = self.master.with_key(data_aead)??;
        let bytes = new.to_bytes();
        write_all_at(&self.file, &bytes, BACKUP_OFFSET)?;
        self.file.sync_data()?;
        let store = ChunkStore::new(self.file.try_clone()?, &self.header, aead, false);
        let mut fs = Fs::open(store, self.header.hash())?;
        fs.commit_header_change(new.hash())?;
        drop(fs);
        write_all_at(&self.file, &bytes, PRIMARY_OFFSET)?;
        self.file.sync_data()?;
        self.header = new;
        Ok(())
    }

    /// Replace the password. Keyfiles are kept.
    pub fn change_password(&mut self, new_password: &[u8], kdf: Argon2Params) -> Result<(), Error> {
        kdf.validate_for_new_slot()?;
        let mut h = self.header.clone();
        self.master.with_key(|master| h.set_password(master, new_password, kdf))??;
        self.write_header(h)
    }

    /// Allow `keyfile` to unlock this vault.
    pub fn add_keyfile(&mut self, keyfile: &Keyfile) -> Result<(), Error> {
        let mut h = self.header.clone();
        self.master.with_key(|master| h.add_keyfile(master, keyfile))??;
        self.write_header(h)
    }

    /// Stop `keyfile` from unlocking this vault.
    pub fn remove_keyfile(&mut self, keyfile: &Keyfile) -> Result<(), Error> {
        let mut h = self.header.clone();
        if !h.remove_keyfile(keyfile)? {
            return Err(Error::Usage("that keyfile can't unlock this vault".into()));
        }
        self.write_header(h)
    }

    /// Remove every keyfile (for a lost keyfile: then add back the ones you
    /// still have). Returns how many were removed.
    pub fn remove_all_keyfiles(&mut self) -> Result<usize, Error> {
        let n = self.header.keyfiles.len();
        if n == 0 {
            return Err(Error::Usage("this vault has no keyfiles".into()));
        }
        let mut h = self.header.clone();
        h.keyfiles.clear();
        self.write_header(h)?;
        Ok(n)
    }
}

/// How much work a password key derivation with `kdf` takes (memory times
/// passes), for ordering only.
fn kdf_cost(kdf: &Argon2Params) -> u64 {
    kdf.memory_kib as u64 * kdf.iterations as u64
}

/// A warning to show *before* unlocking with a password, if a header copy
/// asks for a costlier key derivation than nullguard ever sets up
/// ([`Argon2Params::DEFAULT`]): the header was then probably tampered with,
/// and the derivation may take minutes or fail for lack of memory.
pub fn unusual_kdf_warning(path: &Path) -> Option<String> {
    let file = File::open(path).ok()?;
    let mut worst: Option<Argon2Params> = None;
    for offset in [PRIMARY_OFFSET, BACKUP_OFFSET] {
        let mut buf = vec![0u8; HEADER_AREA as usize];
        if read_exact_at(&file, &mut buf, offset).is_err() {
            continue;
        }
        if let Ok(h) = Header::parse(&buf) {
            let d = Argon2Params::DEFAULT;
            let unusual = h.kdf.memory_kib > d.memory_kib || h.kdf.iterations > d.iterations || h.kdf.parallelism > d.parallelism;
            if unusual && worst.is_none_or(|w| kdf_cost(&h.kdf) > kdf_cost(&w)) {
                worst = Some(h.kdf);
            }
        }
    }
    let k = worst?;
    Some(format!(
        "this vault's header asks for a much costlier key derivation ({} MiB, {} passes, {} lanes) than \
         nullguard ever sets up. The header was probably tampered with. Unlocking may take minutes or \
         run out of memory; the other header copy is tried first if it is cheaper.",
        k.memory_kib / 1024,
        k.iterations,
        k.parallelism
    ))
}

fn stale_copy_warning(name: &str) -> String {
    format!(
        "the {name} header copy does not match the vault's current header. This happens after an \
         interrupted password or keyfile change, but can also mean tampering."
    )
}

fn data_aead(master: &SecretKey) -> Result<Aead, Error> {
    Ok(Aead::new(derive_subkey(master, LABEL_DATA_KEY)?)?)
}

fn fill_random(file: &File, start: u64, end: u64, progress: &mut dyn FnMut(u64, u64), cancelled: &dyn Fn() -> bool) -> Result<(), Error> {
    const STEP: usize = 4 << 20;
    let mut buf = vec![0u8; STEP];
    let mut pos = start;
    while pos < end {
        if cancelled() {
            return Err(Error::Usage("vault creation cancelled".into()));
        }
        let n = STEP.min((end - pos) as usize);
        crate::crypto::random::fill(&mut buf[..n])?;
        write_all_at(file, &buf[..n], pos)?;
        pos += n as u64;
        progress(pos - start, end - start);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
