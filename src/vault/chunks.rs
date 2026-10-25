//! The encrypted chunk store: the vault's data area as an array of
//! fixed-size, individually authenticated chunks.
//!
//! On disk, chunk `i` lives at `8192 + i * (chunk_size + 40)`:
//!
//! ```text
//! nonce (24) || ciphertext (chunk_size) || tag (16)
//! ```
//!
//! Every write uses a fresh random 192-bit nonce. The associated data binds
//! each chunk to its vault and its position, so a chunk can't be moved,
//! copied into another vault, or read with another chunk size:
//!
//! ```text
//! aad = "NGCHUNK2" || vault_id (16) || chunk_size (u32) || index (u64)
//! ```
//!
//! Callers that know which nonce a chunk *should* have (the filesystem
//! records it in its authenticated metadata) pass it as `expected`, which
//! turns "replay an older version of this chunk" into a detected error.

use std::fs::File;
use std::io;

use crate::crypto::{Aead, NONCE_LEN, TAG_LEN, ct_eq};

use super::Error;
use super::header::{DATA_OFFSET, Header, VAULT_ID_LEN, chunk_stride};

const AAD_LABEL: &[u8; 8] = b"NGCHUNK2";
const AAD_LEN: usize = 8 + VAULT_ID_LEN + 4 + 8;

pub struct ChunkStore {
    file: File,
    aead: Aead,
    vault_id: [u8; VAULT_ID_LEN],
    chunk_size: u32,
    chunk_count: u64,
    read_only: bool,
}

impl ChunkStore {
    pub(crate) fn new(file: File, header: &Header, aead: Aead, read_only: bool) -> Self {
        Self {
            file,
            aead,
            vault_id: header.vault_id,
            chunk_size: header.chunk_size,
            chunk_count: header.chunk_count,
            read_only,
        }
    }

    pub fn chunk_size(&self) -> u32 {
        self.chunk_size
    }

    pub fn chunk_count(&self) -> u64 {
        self.chunk_count
    }

    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    fn aad(&self, index: u64) -> [u8; AAD_LEN] {
        let mut a = [0u8; AAD_LEN];
        a[..8].copy_from_slice(AAD_LABEL);
        a[8..24].copy_from_slice(&self.vault_id);
        a[24..28].copy_from_slice(&self.chunk_size.to_le_bytes());
        a[28..36].copy_from_slice(&index.to_le_bytes());
        a
    }

    fn offset(&self, index: u64) -> Result<u64, Error> {
        if index >= self.chunk_count {
            return Err(Error::Corrupt(format!("chunk index {index} out of range")));
        }
        Ok(DATA_OFFSET + index * chunk_stride(self.chunk_size))
    }

    /// Read and decrypt chunk `index` into `out` (exactly `chunk_size` bytes).
    ///
    /// If `expected` is given, the stored nonce must match it, otherwise
    /// the chunk is a stale or substituted copy ([`Error::Rollback`]).
    /// Returns the chunk's nonce.
    pub fn read(&self, index: u64, expected: Option<&[u8; NONCE_LEN]>, out: &mut [u8]) -> Result<[u8; NONCE_LEN], Error> {
        assert_eq!(out.len(), self.chunk_size as usize, "chunk buffer size");
        let off = self.offset(index)?;
        let mut nonce = [0u8; NONCE_LEN];
        let mut tag = [0u8; TAG_LEN];
        read_exact_at(&self.file, &mut nonce, off)?;
        read_exact_at(&self.file, out, off + NONCE_LEN as u64)?;
        read_exact_at(&self.file, &mut tag, off + NONCE_LEN as u64 + self.chunk_size as u64)?;
        if let Some(exp) = expected
            && !ct_eq(exp, &nonce)
        {
            zeroize::Zeroize::zeroize(out);
            return Err(Error::Rollback { chunk: index });
        }
        self.aead
            .open(&nonce, &self.aad(index), out, &tag)
            .map_err(|_| Error::ChunkAuth { chunk: index })?;
        Ok(nonce)
    }

    /// Encrypt `plaintext` (exactly `chunk_size` bytes) under a fresh nonce
    /// and write it to chunk `index`. Returns the new nonce.
    pub fn write(&self, index: u64, plaintext: &[u8]) -> Result<[u8; NONCE_LEN], Error> {
        if self.read_only {
            return Err(Error::ReadOnly);
        }
        assert_eq!(plaintext.len(), self.chunk_size as usize, "chunk buffer size");
        let off = self.offset(index)?;
        let stride = chunk_stride(self.chunk_size) as usize;
        let mut buf = zeroize::Zeroizing::new(vec![0u8; stride]);
        buf[NONCE_LEN..NONCE_LEN + plaintext.len()].copy_from_slice(plaintext);
        let (nonce, tag) = self.aead.seal(&self.aad(index), &mut buf[NONCE_LEN..NONCE_LEN + plaintext.len()])?;
        buf[..NONCE_LEN].copy_from_slice(&nonce);
        buf[NONCE_LEN + plaintext.len()..].copy_from_slice(&tag);
        write_all_at(&self.file, &buf, off)?;
        Ok(nonce)
    }

    /// Flush all writes to stable storage.
    pub fn sync(&self) -> Result<(), Error> {
        if !self.read_only {
            self.file.sync_data()?;
        }
        Ok(())
    }
}

pub(crate) fn read_exact_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        file.read_exact_at(buf, offset)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        let mut done = 0;
        while done < buf.len() {
            match file.seek_read(&mut buf[done..], offset + done as u64) {
                Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "vault file is truncated")),
                Ok(n) => done += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

pub(crate) fn write_all_at(file: &File, buf: &[u8], offset: u64) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        file.write_all_at(buf, offset)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        let mut done = 0;
        while done < buf.len() {
            match file.seek_write(&buf[done..], offset + done as u64) {
                Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "write returned zero")),
                Ok(n) => done += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}
