//! Vault containers: creation, unlocking, key management.
//!
//! A vault is one ordinary file:
//!
//! ```text
//! [ primary header 64 KiB ][ backup header 64 KiB ][ chunk 0 ][ chunk 1 ] ...
//! ```
//!
//! See `header` for the header, `chunks` for the encrypted chunk array and
//! `fs` for the filesystem stored in the chunks.

pub mod chunks;
pub mod fs;
pub mod header;

use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use crate::crypto::{Aead, Argon2Params, CipherSuite, CryptoError, HybridPublicKey, HybridSecretKey, SecretKey, derive_subkey};
use chunks::{ChunkStore, read_exact_at, write_all_at};
use fs::Fs;
use header::{BACKUP_OFFSET, DATA_OFFSET, HEADER_AREA, Header, HeaderError, KeySlot, PRIMARY_OFFSET, chunk_stride};

const LABEL_DATA_KEY: &[u8] = b"nullguard/v1/data-key";

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
        "the vault header failed its integrity check under the correct key. \
         It has been TAMPERED WITH or damaged; refusing to use it"
    )]
    HeaderTampered,
    #[error("chunk {chunk} failed authentication: the vault was modified or damaged")]
    ChunkAuth { chunk: u64 },
    #[error("chunk {chunk} is an older version than expected: the vault was rolled back or tampered with")]
    Rollback { chunk: u64 },
    #[error(
        "the vault header is OLDER than the vault's contents (header generation {header}, \
         but the data was last saved under generation {recorded}). An old header was put back, \
         for example to undo a password change or a recipient's removal. Refusing to open"
    )]
    HeaderRollback { header: u64, recorded: u64 },
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
    Keyfile(&'a HybridSecretKey),
}

/// Options for [`Vault::create`].
pub struct CreateOptions {
    /// Total size of the vault file in bytes.
    pub size: u64,
    pub cipher: CipherSuite,
    pub kdf: Argon2Params,
    /// Chunk size in bytes; `None` picks one from the vault size.
    pub chunk_size: Option<u32>,
    /// Fill unused space with random bytes, so an observer can't tell how
    /// much of the vault is in use. Strongly recommended.
    pub fill_random: bool,
    /// Extra recipients (keyfiles) that can unlock the vault.
    pub recipients: Vec<HybridPublicKey>,
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
    master: SecretKey,
    path: PathBuf,
    read_only: bool,
    /// Security-relevant observations (damaged backup header etc.). Callers
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
        opts.kdf.validate_for_new_slot()?;
        let chunk_size = opts.chunk_size.unwrap_or_else(|| auto_chunk_size(opts.size));
        let stride = chunk_stride(chunk_size);
        let chunk_count = opts.size.saturating_sub(DATA_OFFSET) / stride;
        let master = SecretKey::generate()?;
        let mut header = Header::new(opts.cipher, chunk_size, chunk_count).map_err(|e| match e {
            HeaderError::Malformed("too few chunks") => Error::Usage("vault size is too small".into()),
            other => other.into(),
        })?;
        header.add_password_slot(&master, password, opts.kdf)?;
        for r in &opts.recipients {
            header.add_recipient_slot(&master, r)?;
        }
        header.seal(&master)?;

        let mut oo = OpenOptions::new();
        oo.read(true).write(true).create_new(true);
        // Only the owner may read the vault: other local users shouldn't even
        // get a copy to attack offline.
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut oo, 0o600);
        #[cfg(windows)]
        std::os::windows::fs::OpenOptionsExt::share_mode(&mut oo, 0);
        let file = oo.open(path)?;
        let result = (|| {
            file.try_lock().map_err(|_| Error::InUse)?;
            let len = header.file_len();
            file.set_len(len)?;
            if opts.fill_random {
                fill_random(&file, DATA_OFFSET, len, progress)?;
            }
            write_headers(&file, &header)?;
            let store = ChunkStore::new(file.try_clone()?, &header, data_aead(&header, &master)?, false);
            let fs = Fs::format(store, crate::platform::uid(), crate::platform::gid(), header.generation)?;
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
    /// trusted until a vault is unlocked and the MAC is verified.
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

        let mut warnings = Vec::new();
        let mut first_err: Option<Error> = None;
        let copies: Vec<(&str, &[u8])> =
            if primary == backup { vec![("primary", &primary)] } else { vec![("primary", &primary), ("backup", &backup)] };
        if copies.len() == 2 {
            warnings.push(
                "the primary and backup headers differ. This happens after an interrupted password \
                 change, but can also mean tampering."
                    .into(),
            );
        }

        // Every copy that authenticates under these credentials is a
        // candidate; the newest generation wins. (After an interrupted
        // header change the backup is newer than the primary.)
        let mut best: Option<(&str, Header, SecretKey)> = None;
        let mut newest_seen = 0u64;
        for (name, bytes) in copies {
            let header = match Header::parse(bytes) {
                Ok(h) => h,
                Err(e) => {
                    warnings.push(format!("the {name} header is unreadable: {e}"));
                    first_err.get_or_insert(e.into());
                    continue;
                }
            };
            newest_seen = newest_seen.max(header.generation);
            let unlocked = match &cred {
                Credential::Password(p) => header.unlock_with_password(p),
                Credential::Keyfile(k) => header.unlock_with_keyfile(k),
            };
            // An error here (e.g. a tampered slot demanding more memory than
            // exists) must not stop us from trying the other copy.
            let master = match unlocked {
                Ok(m) => m,
                Err(e) => {
                    warnings.push(format!("the {name} header could not be processed: {e}"));
                    first_err.get_or_insert(e.into());
                    continue;
                }
            };
            let Some(master) = master else {
                first_err.get_or_insert(Error::WrongCredentials);
                continue;
            };
            if !header.verify_mac(&master)? {
                // The credentials are right but the header was modified.
                // Never use it; an untouched other copy is still safe to use.
                warnings.push(format!(
                    "SECURITY: the {name} header unlocked but FAILED its integrity check. \
                     It has been tampered with or damaged."
                ));
                first_err = Some(Error::HeaderTampered);
                continue;
            }
            if best.as_ref().is_none_or(|(_, b, _)| header.generation > b.generation) {
                best = Some((name, header, master));
            }
        }

        let Some((name, header, master)) = best else {
            // A tampered header outranks "wrong password" in the report.
            return Err(first_err.unwrap_or(Error::WrongCredentials));
        };
        if name == "backup" {
            warnings.push("the primary header copy was not usable; using the backup copy".into());
        }
        if newest_seen > header.generation {
            warnings.push(format!(
                "a newer header copy (generation {newest_seen}) exists but does not accept these \
                 credentials, so the older generation {} is in use. If you just changed the password \
                 or removed a key, that change was interrupted; redo it. Otherwise this can mean tampering.",
                header.generation
            ));
        }
        let actual_len = file.metadata()?.len();
        if actual_len < header.file_len() {
            return Err(Error::Corrupt(format!(
                "the vault file is truncated ({actual_len} bytes, expected {})",
                header.file_len()
            )));
        }
        Ok(Self { file, header, master, path: path.to_owned(), read_only, warnings })
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Open the filesystem inside the vault.
    /// Open the filesystem inside the vault. The filesystem's own warnings
    /// are in `Fs::warnings`; the vault's stay in [`Vault::warnings`].
    pub fn into_fs(self) -> Result<Fs, Error> {
        let store = ChunkStore::new(self.file.try_clone()?, &self.header, data_aead(&self.header, &self.master)?, self.read_only);
        Fs::open(store, self.header.generation)
    }

    /// Re-read both header copies and report every problem: a copy that
    /// doesn't parse, fails its MAC under this vault's key, or isn't the
    /// header in use (stale or substituted). Empty means both copies are
    /// authentic and identical. Used by `verify`.
    pub fn check_headers(&self) -> Result<Vec<String>, Error> {
        let mut problems = Vec::new();
        for (name, offset) in [("primary", PRIMARY_OFFSET), ("backup", BACKUP_OFFSET)] {
            let mut buf = vec![0u8; HEADER_AREA as usize];
            read_exact_at(&self.file, &mut buf, offset)?;
            match Header::parse(&buf) {
                Err(e) => problems.push(format!("{name} header copy is unreadable: {e}")),
                Ok(h) if !h.verify_mac(&self.master)? => {
                    problems.push(format!("{name} header copy FAILED its integrity check (tampered or damaged)"))
                }
                Ok(h) if h != self.header => {
                    problems.push(format!("{name} header copy is authentic but out of date (stale or substituted)"))
                }
                Ok(_) => {}
            }
        }
        Ok(problems)
    }

    /// Write a changed header as the next generation, then record that
    /// generation in a filesystem commit. From then on, putting back any
    /// older header (to revive a removed recipient or an old password) is
    /// detected when the vault is opened.
    ///
    /// Crash safety: the header is written first. If we stop before the
    /// commit, the data still records the previous generation, and a header
    /// *newer* than the data is accepted (the next commit catches up).
    fn write_header(&mut self, mut new: Header) -> Result<(), Error> {
        if self.read_only {
            return Err(Error::ReadOnly);
        }
        new.generation = self
            .header
            .generation
            .checked_add(1)
            .ok_or(Error::Corrupt("header generation overflow".into()))?;
        new.seal(&self.master)?;
        write_headers(&self.file, &new)?;
        self.header = new;
        let store = ChunkStore::new(self.file.try_clone()?, &self.header, data_aead(&self.header, &self.master)?, false);
        let mut fs = Fs::open(store, self.header.generation)?;
        fs.commit_header_change()?;
        Ok(())
    }

    /// Replace all password slots with a single slot for `new_password`.
    /// Recipient (keyfile) slots are kept.
    pub fn change_password(&mut self, new_password: &[u8], kdf: Argon2Params) -> Result<(), Error> {
        kdf.validate_for_new_slot()?;
        let mut h = self.header.clone();
        h.slots.retain(|s| !matches!(s, KeySlot::Password(_)));
        // Password slot goes first, so `info` lists it first.
        let recipients = std::mem::take(&mut h.slots);
        h.add_password_slot(&self.master, new_password, kdf)?;
        h.slots.extend(recipients);
        h.seal(&self.master)?;
        self.write_header(h)
    }

    /// Allow `recipient`'s keyfile to unlock this vault.
    pub fn add_recipient(&mut self, recipient: &HybridPublicKey) -> Result<(), Error> {
        let mut h = self.header.clone();
        h.add_recipient_slot(&self.master, recipient)?;
        h.seal(&self.master)?;
        self.write_header(h)
    }

    /// Remove the recipient slot whose fingerprint starts with `prefix` (hex).
    pub fn remove_recipient(&mut self, prefix: &str) -> Result<String, Error> {
        let prefix = prefix.to_ascii_lowercase();
        if prefix.len() < 8 {
            return Err(Error::Usage("give at least 8 hex digits of the fingerprint".into()));
        }
        let matches: Vec<usize> = self
            .header
            .slots
            .iter()
            .enumerate()
            .filter(|(_, s)| matches!(s, KeySlot::Recipient(r) if crate::crypto::hybrid::hex(&r.fingerprint).starts_with(&prefix)))
            .map(|(i, _)| i)
            .collect();
        let idx = match matches.as_slice() {
            [i] => *i,
            [] => return Err(Error::Usage("no recipient slot has that fingerprint".into())),
            _ => return Err(Error::Usage("that fingerprint prefix is ambiguous".into())),
        };
        let mut h = self.header.clone();
        let removed = h.slots.remove(idx);
        if h.slots.is_empty() {
            return Err(Error::Usage("refusing to remove the last key slot".into()));
        }
        h.seal(&self.master)?;
        self.write_header(h)?;
        match removed {
            KeySlot::Recipient(r) => Ok(crate::crypto::hybrid::hex(&r.fingerprint)),
            KeySlot::Password(_) => unreachable!("filtered to recipient slots"),
        }
    }
}

fn data_aead(header: &Header, master: &SecretKey) -> Result<Aead, Error> {
    Ok(Aead::new(header.cipher, derive_subkey(master, LABEL_DATA_KEY)?))
}

/// Write the backup copy, flush, then the primary. If interrupted, at
/// least one copy is complete and consistent.
fn write_headers(file: &File, header: &Header) -> Result<(), Error> {
    let bytes = header.to_bytes();
    write_all_at(file, &bytes, BACKUP_OFFSET)?;
    file.sync_data()?;
    write_all_at(file, &bytes, PRIMARY_OFFSET)?;
    file.sync_data()?;
    Ok(())
}

fn fill_random(file: &File, start: u64, end: u64, progress: &mut dyn FnMut(u64, u64)) -> Result<(), Error> {
    const STEP: usize = 4 << 20;
    let mut buf = vec![0u8; STEP];
    let mut pos = start;
    while pos < end {
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
