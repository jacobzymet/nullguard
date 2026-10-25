//! The vault header.
//!
//! One 4 KiB copy at offset 0 and an identical backup at 4 KiB. All
//! integers are little-endian:
//!
//! ```text
//! offset  size   field
//!      0     8   magic "NULLGARD"
//!      8     2   version = 4
//!     10    16   vault id (random)
//!     26     4   chunk size (power of two, 4 KiB to 1 MiB)
//!     30     8   chunk count (>= 16)
//!     38    12   Argon2id memory (KiB), iterations, parallelism
//!     50    32   Argon2id salt
//!     82   104   password slot: the wrapped master key
//!    186     2   keyfile slot count K (0 to 16)
//!    188 104*K   keyfile slots: the wrapped master key, once per keyfile
//!      …     …   zero padding to 4096 bytes
//! ```
//!
//! Every vault has exactly one password and up to 16 keyfiles. Parsing is
//! strict (unknown versions, out-of-range values and non-zero padding are
//! refused), so every header has exactly one valid encoding.
//!
//! **Integrity.** Each slot wraps the master key with an AEAD whose
//! associated data is the header's first 38 bytes (magic, version, vault
//! id, geometry), so a slot unlocks only the vault it was made for, with
//! the geometry it was made for. The header *as a whole* is authenticated
//! by the filesystem: every superblock records the SHA-256 of the exact
//! header it was committed under, and a vault opens only with that header
//! (see `Vault::open`).

use sha2::{Digest, Sha256};

use crate::crypto::kdf::{self, Argon2Params, SALT_LEN};
use crate::crypto::{
    Aead, COMMITMENT_LEN, CryptoError, KEY_LEN, Keyfile, NONCE_LEN, SecretKey, TAG_LEN, derive_subkey, key_commitment,
    random, verify_key_commitment,
};

pub const MAGIC: [u8; 8] = *b"NULLGARD";
/// The vault format: the only one this version reads or writes.
pub const FORMAT_VERSION: u16 = 4;

/// Size of one header copy on disk.
pub const HEADER_AREA: u64 = 4096;
pub const PRIMARY_OFFSET: u64 = 0;
pub const BACKUP_OFFSET: u64 = HEADER_AREA;
/// Where the chunk area starts: right after the two header copies.
pub const DATA_OFFSET: u64 = 2 * HEADER_AREA;

pub const VAULT_ID_LEN: usize = 16;
/// Most keyfiles a vault can have.
pub const MAX_KEYFILES: usize = 16;

pub const MIN_CHUNK_SIZE: u32 = 4 * 1024;
pub const MAX_CHUNK_SIZE: u32 = 1024 * 1024;
/// Fewest chunks a vault may have (2 superblocks + room for data).
pub const MIN_CHUNKS: u64 = 16;
/// Upper bound on vault size (2^50 bytes = 1 PiB) to keep arithmetic safe.
pub const MAX_VAULT_BYTES: u64 = 1 << 50;

/// Magic, version, vault id and geometry: bound into every key slot.
const CORE_LEN: usize = 8 + 2 + VAULT_ID_LEN + 4 + 8;
const WRAPPED_KEY_LEN: usize = NONCE_LEN + COMMITMENT_LEN + KEY_LEN + TAG_LEN;
const KEYFILES_OFFSET: usize = CORE_LEN + 12 + SALT_LEN + WRAPPED_KEY_LEN + 2;

const LABEL_SLOT_AAD: &[u8] = b"nullguard/v2/keyslot";
const LABEL_SLOT_ENCRYPTION: &[u8] = b"nullguard/v4/slot-encryption-key";
const LABEL_SLOT_COMMITMENT: &[u8] = b"nullguard/v4/slot-commitment-key";

/// The keys a slot's KEK is used through: `(encryption, commitment)`.
///
/// Two independent keys derived with HKDF, so no key is ever used by two
/// different primitives.
fn slot_keys(kek: &SecretKey) -> Result<(SecretKey, SecretKey), CryptoError> {
    Ok((derive_subkey(kek, LABEL_SLOT_ENCRYPTION)?, derive_subkey(kek, LABEL_SLOT_COMMITMENT)?))
}

/// Why a header could not be parsed or changed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HeaderError {
    #[error("not a nullguard vault (bad magic)")]
    NotAVault,
    #[error(
        "this vault was made by a different version of nullguard (vault version {0}) and can't be \
         opened by this one. Copy the files out with the nullguard version that made it (`get`), \
         then into a new vault made by this one (`put`)"
    )]
    UnsupportedVersion(u16),
    #[error("malformed vault header: {0}")]
    Malformed(&'static str),
    #[error("{0}")]
    Slots(&'static str),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// The master key wrapped under a key-encryption key (KEK):
/// `XChaCha20-Poly1305(KEK, nonce, master_key, aad)` plus a key commitment
/// to the KEK (see [`crate::crypto::key_commitment`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WrappedKey {
    pub nonce: [u8; NONCE_LEN],
    pub commitment: [u8; COMMITMENT_LEN],
    pub ciphertext: [u8; KEY_LEN],
    pub tag: [u8; TAG_LEN],
}

impl WrappedKey {
    fn seal(kek: &SecretKey, aad: &[u8], master: &SecretKey) -> Result<Self, CryptoError> {
        let (enc, commit) = slot_keys(kek)?;
        let mut buf = zeroize::Zeroizing::new(*master.expose());
        let nonce = random::array::<NONCE_LEN>()?;
        let commitment = key_commitment(&commit, &nonce, aad);
        let tag = Aead::new(enc).seal_with_nonce(&nonce, aad, buf.as_mut_slice())?;
        Ok(Self { nonce, commitment, ciphertext: *buf, tag })
    }

    /// Recover the master key. The commitment is checked first (in constant
    /// time), so this succeeds under at most one KEK.
    fn open(&self, kek: &SecretKey, aad: &[u8]) -> Result<SecretKey, CryptoError> {
        let (enc, commit) = slot_keys(kek)?;
        if !verify_key_commitment(&commit, &self.nonce, aad, &self.commitment) {
            return Err(CryptoError::AuthFailed);
        }
        let mut buf = zeroize::Zeroizing::new(self.ciphertext);
        Aead::new(enc).open(&self.nonce, aad, buf.as_mut_slice(), &self.tag)?;
        Ok(SecretKey::from_bytes(&mut buf))
    }

    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.commitment);
        out.extend_from_slice(&self.ciphertext);
        out.extend_from_slice(&self.tag);
    }

    fn parse(r: &mut Reader<'_>) -> Result<Self, HeaderError> {
        Ok(Self { nonce: r.array()?, commitment: r.array()?, ciphertext: r.array()?, tag: r.array()? })
    }
}

/// The parsed vault header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub vault_id: [u8; VAULT_ID_LEN],
    pub chunk_size: u32,
    pub chunk_count: u64,
    /// Argon2id parameters and salt of the password slot.
    pub kdf: Argon2Params,
    pub salt: [u8; SALT_LEN],
    pub password: WrappedKey,
    pub keyfiles: Vec<WrappedKey>,
}

/// Bytes each chunk occupies on disk: nonce || ciphertext || tag.
pub fn chunk_stride(chunk_size: u32) -> u64 {
    chunk_size as u64 + (NONCE_LEN + TAG_LEN) as u64
}

impl Header {
    /// A new header for a new vault, with `password` unlocking `master`.
    pub fn create(
        chunk_size: u32,
        chunk_count: u64,
        master: &SecretKey,
        password: &[u8],
        kdf: Argon2Params,
    ) -> Result<Self, HeaderError> {
        let mut h = Self {
            vault_id: random::array()?,
            chunk_size,
            chunk_count,
            kdf,
            salt: [0; SALT_LEN],
            password: WrappedKey::default(),
            keyfiles: Vec::new(),
        };
        h.validate_geometry()?;
        h.set_password(master, password, kdf)?;
        Ok(h)
    }

    fn validate_geometry(&self) -> Result<(), HeaderError> {
        if !self.chunk_size.is_power_of_two()
            || self.chunk_size < MIN_CHUNK_SIZE
            || self.chunk_size > MAX_CHUNK_SIZE
        {
            return Err(HeaderError::Malformed("chunk size must be a power of two between 4 KiB and 1 MiB"));
        }
        if self.chunk_count < MIN_CHUNKS {
            return Err(HeaderError::Malformed("too few chunks"));
        }
        let total = self
            .chunk_count
            .checked_mul(chunk_stride(self.chunk_size))
            .and_then(|n| n.checked_add(DATA_OFFSET))
            .ok_or(HeaderError::Malformed("vault size overflows"))?;
        if total > MAX_VAULT_BYTES {
            return Err(HeaderError::Malformed("vault too large"));
        }
        Ok(())
    }

    /// Total size of the vault file this header describes.
    pub fn file_len(&self) -> u64 {
        DATA_OFFSET + self.chunk_count * chunk_stride(self.chunk_size)
    }

    fn core_bytes(&self) -> [u8; CORE_LEN] {
        let mut c = [0u8; CORE_LEN];
        c[0..8].copy_from_slice(&MAGIC);
        c[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        c[10..26].copy_from_slice(&self.vault_id);
        c[26..30].copy_from_slice(&self.chunk_size.to_le_bytes());
        c[30..38].copy_from_slice(&self.chunk_count.to_le_bytes());
        c
    }

    /// Serialize to exactly [`HEADER_AREA`] bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        assert!(self.keyfiles.len() <= MAX_KEYFILES, "keyfile slot invariant");
        let mut out = Vec::with_capacity(HEADER_AREA as usize);
        out.extend_from_slice(&self.core_bytes());
        out.extend_from_slice(&self.kdf.memory_kib.to_le_bytes());
        out.extend_from_slice(&self.kdf.iterations.to_le_bytes());
        out.extend_from_slice(&self.kdf.parallelism.to_le_bytes());
        out.extend_from_slice(&self.salt);
        self.password.encode(&mut out);
        out.extend_from_slice(&(self.keyfiles.len() as u16).to_le_bytes());
        debug_assert_eq!(out.len(), KEYFILES_OFFSET);
        for k in &self.keyfiles {
            k.encode(&mut out);
        }
        out.resize(HEADER_AREA as usize, 0);
        out
    }

    /// SHA-256 of the encoded header: what the filesystem records in every
    /// commit, and the only header it will open with.
    pub fn hash(&self) -> [u8; 32] {
        Sha256::digest(self.to_bytes()).into()
    }

    /// Strictly parse a header copy. Nothing in it is trusted until a slot
    /// unlocks it and the filesystem confirms its hash (see `Vault::open`).
    pub fn parse(bytes: &[u8]) -> Result<Self, HeaderError> {
        if bytes.len() < HEADER_AREA as usize {
            return Err(HeaderError::Malformed("truncated header"));
        }
        let bytes = &bytes[..HEADER_AREA as usize];
        if bytes[0..8] != MAGIC {
            return Err(HeaderError::NotAVault);
        }
        let mut r = Reader::new(&bytes[8..]);
        let version = r.u16()?;
        if version != FORMAT_VERSION {
            return Err(HeaderError::UnsupportedVersion(version));
        }
        let vault_id = r.array()?;
        let chunk_size = r.u32()?;
        let chunk_count = r.u64()?;
        let kdf = Argon2Params { memory_kib: r.u32()?, iterations: r.u32()?, parallelism: r.u32()? };
        kdf.validate()?;
        let salt = r.array()?;
        let password = WrappedKey::parse(&mut r)?;
        let count = r.u16()? as usize;
        if count > MAX_KEYFILES {
            return Err(HeaderError::Malformed("too many keyfile slots"));
        }
        let keyfiles = (0..count).map(|_| WrappedKey::parse(&mut r)).collect::<Result<Vec<_>, _>>()?;
        if r.rest().iter().any(|&b| b != 0) {
            return Err(HeaderError::Malformed("header padding is not zero"));
        }
        let h = Self { vault_id, chunk_size, chunk_count, kdf, salt, password, keyfiles };
        h.validate_geometry()?;
        Ok(h)
    }

    /// Associated data of every key slot: binds the vault id and geometry,
    /// so a slot can't be moved to another vault or reinterpreted.
    fn slot_aad(&self) -> Vec<u8> {
        [LABEL_SLOT_AAD, &self.core_bytes()].concat()
    }

    /// Replace the password slot: `password` now unlocks `master`.
    pub fn set_password(&mut self, master: &SecretKey, password: &[u8], kdf: Argon2Params) -> Result<(), HeaderError> {
        kdf.validate()?;
        let salt = random::array::<SALT_LEN>()?;
        let kek = kdf::derive_key(password, &salt, &kdf)?;
        self.password = WrappedKey::seal(&kek, &self.slot_aad(), master)?;
        self.kdf = kdf;
        self.salt = salt;
        Ok(())
    }

    /// Add a slot that `keyfile` unlocks.
    pub fn add_keyfile(&mut self, master: &SecretKey, keyfile: &Keyfile) -> Result<(), HeaderError> {
        if self.keyfiles.len() >= MAX_KEYFILES {
            return Err(HeaderError::Slots("this vault already has the maximum of 16 keyfiles"));
        }
        if self.keyfile_slot(keyfile)?.is_some() {
            return Err(HeaderError::Slots("that keyfile can already unlock this vault"));
        }
        let kek = keyfile.kek(&self.vault_id)?;
        self.keyfiles.push(WrappedKey::seal(&kek, &self.slot_aad(), master)?);
        Ok(())
    }

    /// Remove the slot `keyfile` unlocks. Returns whether there was one.
    pub fn remove_keyfile(&mut self, keyfile: &Keyfile) -> Result<bool, HeaderError> {
        match self.keyfile_slot(keyfile)? {
            Some(i) => {
                self.keyfiles.remove(i);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// The index of the keyfile slot `keyfile` unlocks. Slots carry no
    /// identifier (which would tell anyone who has access), so each is
    /// tried; that costs one HMAC per slot.
    fn keyfile_slot(&self, keyfile: &Keyfile) -> Result<Option<usize>, HeaderError> {
        let kek = keyfile.kek(&self.vault_id)?;
        let aad = self.slot_aad();
        Ok(self.keyfiles.iter().position(|k| k.open(&kek, &aad).is_ok()))
    }

    /// Unlock with the password. `Ok(None)` means it's the wrong password.
    /// An error means the key derivation itself failed (for example a
    /// tampered header asking for more memory than the machine has).
    pub fn unlock_with_password(&self, password: &[u8]) -> Result<Option<SecretKey>, HeaderError> {
        let kek = kdf::derive_key(password, &self.salt, &self.kdf)?;
        Ok(self.password.open(&kek, &self.slot_aad()).ok())
    }

    /// Unlock with a keyfile. `Ok(None)` means no slot accepts it.
    pub fn unlock_with_keyfile(&self, keyfile: &Keyfile) -> Result<Option<SecretKey>, HeaderError> {
        let kek = keyfile.kek(&self.vault_id)?;
        let aad = self.slot_aad();
        Ok(self.keyfiles.iter().find_map(|k| k.open(&kek, &aad).ok()))
    }
}

/// Bounds-checked little-endian reader. Never panics on short input.
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], HeaderError> {
        let end = self.pos.checked_add(n).ok_or(HeaderError::Malformed("length overflow"))?;
        if end > self.buf.len() {
            return Err(HeaderError::Malformed("truncated"));
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], HeaderError> {
        Ok(self.take(N)?.try_into().expect("take returned N bytes"))
    }

    pub(crate) fn u8(&mut self) -> Result<u8, HeaderError> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16, HeaderError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    pub(crate) fn u32(&mut self) -> Result<u32, HeaderError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, HeaderError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    pub(crate) fn i64(&mut self) -> Result<i64, HeaderError> {
        Ok(i64::from_le_bytes(self.array()?))
    }

    pub(crate) fn rest(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.pos == self.buf.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::TEST_PARAMS;

    const PW: &[u8] = b"correct horse battery staple";

    fn sample() -> (Header, SecretKey) {
        let master = SecretKey::generate().unwrap();
        let h = Header::create(16 * 1024, 1000, &master, PW, TEST_PARAMS).unwrap();
        (h, master)
    }

    #[test]
    fn serialize_parse_roundtrip() {
        let (mut h, master) = sample();
        h.add_keyfile(&master, &Keyfile::generate().unwrap()).unwrap();
        let bytes = h.to_bytes();
        assert_eq!(bytes.len() as u64, HEADER_AREA);
        let parsed = Header::parse(&bytes).unwrap();
        assert_eq!(parsed, h);
        assert_eq!(parsed.to_bytes(), bytes, "encoding must be canonical");
        assert_eq!(parsed.hash(), h.hash());
    }

    #[test]
    fn password_unlock() {
        let (h, master) = sample();
        let k = h.unlock_with_password(PW).unwrap().unwrap();
        assert_eq!(k.expose(), master.expose());
        assert!(h.unlock_with_password(b"correct horse battery stapler").unwrap().is_none());
        assert!(h.unlock_with_password(b"").unwrap().is_none());
    }

    #[test]
    fn set_password_replaces_the_old_one() {
        let (mut h, master) = sample();
        let old_salt = h.salt;
        h.set_password(&master, b"another long password", TEST_PARAMS).unwrap();
        assert_ne!(h.salt, old_salt, "a new password gets a new salt");
        assert!(h.unlock_with_password(PW).unwrap().is_none());
        assert_eq!(h.unlock_with_password(b"another long password").unwrap().unwrap().expose(), master.expose());
    }

    #[test]
    fn keyfiles_unlock_and_can_be_removed() {
        let (mut h, master) = sample();
        let a = Keyfile::generate().unwrap();
        let b = Keyfile::generate().unwrap();
        assert!(h.unlock_with_keyfile(&a).unwrap().is_none());
        h.add_keyfile(&master, &a).unwrap();
        h.add_keyfile(&master, &b).unwrap();
        assert!(matches!(h.add_keyfile(&master, &a), Err(HeaderError::Slots(_))), "duplicate keyfile");
        let parsed = Header::parse(&h.to_bytes()).unwrap();
        for k in [&a, &b] {
            assert_eq!(parsed.unlock_with_keyfile(k).unwrap().unwrap().expose(), master.expose());
        }
        assert!(parsed.unlock_with_keyfile(&Keyfile::generate().unwrap()).unwrap().is_none());

        assert!(h.remove_keyfile(&a).unwrap());
        assert!(!h.remove_keyfile(&a).unwrap(), "already removed");
        assert!(h.unlock_with_keyfile(&a).unwrap().is_none());
        assert!(h.unlock_with_keyfile(&b).unwrap().is_some());
        assert!(h.unlock_with_password(PW).unwrap().is_some());
    }

    #[test]
    fn max_keyfiles_fit_in_header_area() {
        let (mut h, master) = sample();
        for _ in 0..MAX_KEYFILES {
            h.add_keyfile(&master, &Keyfile::generate().unwrap()).unwrap();
        }
        assert!(matches!(h.add_keyfile(&master, &Keyfile::generate().unwrap()), Err(HeaderError::Slots(_))));
        let parsed = Header::parse(&h.to_bytes()).unwrap();
        assert_eq!(parsed.keyfiles.len(), MAX_KEYFILES);
        // A crafted header claiming more keyfile slots is refused.
        let mut b = h.to_bytes();
        b[KEYFILES_OFFSET - 2..KEYFILES_OFFSET].copy_from_slice(&(MAX_KEYFILES as u16 + 1).to_le_bytes());
        assert_eq!(Header::parse(&b).unwrap_err(), HeaderError::Malformed("too many keyfile slots"));
    }

    /// Unwrapping needs both the commitment and the AEAD tag to verify under
    /// the same KEK, so no ciphertext can "unlock" under several keys.
    #[test]
    fn wrapped_key_is_key_committing() {
        let master = SecretKey::generate().unwrap();
        let kek_a = SecretKey::generate().unwrap();
        let kek_b = SecretKey::generate().unwrap();
        let aad = b"slot aad";
        let w = WrappedKey::seal(&kek_a, aad, &master).unwrap();
        assert_eq!(w.open(&kek_a, aad).unwrap().expose(), master.expose());
        assert!(w.open(&kek_b, aad).is_err());
        // Swap in an honest commitment for KEK B: B now passes the
        // commitment but fails the AEAD, and A fails the commitment.
        let mut forged = w.clone();
        let (_, commit_b) = slot_keys(&kek_b).unwrap();
        forged.commitment = key_commitment(&commit_b, &forged.nonce, aad);
        assert!(forged.open(&kek_b, aad).is_err());
        assert!(forged.open(&kek_a, aad).is_err());
        // The commitment also binds nonce and AAD.
        assert!(w.open(&kek_a, b"other aad").is_err());
        let mut bad = w.clone();
        bad.commitment[0] ^= 1;
        assert!(bad.open(&kek_a, aad).is_err());
    }

    /// A slot never uses the KEK itself: the commitment and the AEAD use two
    /// different keys derived from it, and neither is the KEK.
    #[test]
    fn slot_keys_are_separate() {
        let kek = SecretKey::generate().unwrap();
        let (enc, commit) = slot_keys(&kek).unwrap();
        assert_ne!(enc.expose(), commit.expose());
        assert_ne!(enc.expose(), kek.expose());
        assert_ne!(commit.expose(), kek.expose());
    }

    #[test]
    fn rejects_bad_magic_version_and_truncation() {
        let (h, _) = sample();
        let mut b = h.to_bytes();
        b[0] ^= 1;
        assert_eq!(Header::parse(&b).unwrap_err(), HeaderError::NotAVault);

        // A vault from an older or newer nullguard.
        for v in [1u16, 2, 3, FORMAT_VERSION + 1] {
            let mut b = h.to_bytes();
            b[8..10].copy_from_slice(&v.to_le_bytes());
            assert_eq!(Header::parse(&b).unwrap_err(), HeaderError::UnsupportedVersion(v));
        }

        let b = h.to_bytes();
        assert!(Header::parse(&b[..1000]).is_err());
        assert!(Header::parse(&[]).is_err());
    }

    #[test]
    fn rejects_bad_geometry() {
        let (h, _) = sample();
        let with = |off: usize, val: &[u8]| {
            let mut b = h.to_bytes();
            b[off..off + val.len()].copy_from_slice(val);
            Header::parse(&b)
        };
        assert!(with(26, &(16 * 1024u32 + 1).to_le_bytes()).is_err(), "chunk size not a power of two");
        assert!(with(26, &2048u32.to_le_bytes()).is_err(), "chunk size too small");
        assert!(with(26, &(2u32 << 20).to_le_bytes()).is_err(), "chunk size too large");
        assert!(with(30, &15u64.to_le_bytes()).is_err(), "too few chunks");
        assert!(with(30, &u64::MAX.to_le_bytes()).is_err(), "size overflows");
        assert!(with(30, &(1u64 << 40).to_le_bytes()).is_err(), "larger than 1 PiB");
        assert!(with(30, &16u64.to_le_bytes()).is_ok());
    }

    #[test]
    fn rejects_nonzero_padding() {
        let (h, _) = sample();
        let mut b = h.to_bytes();
        let last = b.len() - 1;
        b[last] = 1;
        assert_eq!(Header::parse(&b).unwrap_err(), HeaderError::Malformed("header padding is not zero"));
        // The first padding byte too (right after the keyfile count).
        let mut b = h.to_bytes();
        b[KEYFILES_OFFSET] = 1;
        assert!(Header::parse(&b).is_err());
    }

    #[test]
    fn rejects_hostile_kdf_params() {
        let (h, _) = sample();
        let mut b = h.to_bytes();
        b[38..42].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(Header::parse(&b).is_err());
    }

    /// Changing the KDF parameters (a downgrade attack) or the salt breaks
    /// the password slot.
    #[test]
    fn kdf_downgrade_breaks_unlock() {
        let master = SecretKey::generate().unwrap();
        let strong = Argon2Params { iterations: 3, ..TEST_PARAMS };
        let mut h = Header::create(16 * 1024, 1000, &master, PW, strong).unwrap();
        h.kdf.iterations = 1;
        assert!(h.unlock_with_password(PW).unwrap().is_none());
        let (mut h, _) = sample();
        h.salt[0] ^= 1;
        assert!(h.unlock_with_password(PW).unwrap().is_none());
    }

    /// Changing the vault id or geometry breaks every slot.
    #[test]
    fn parameter_tampering_breaks_unlock() {
        let kf = Keyfile::generate().unwrap();
        let tamper: [fn(&mut Header); 3] =
            [|h| h.chunk_count += 1, |h| h.chunk_size *= 2, |h| h.vault_id[0] ^= 1];
        for t in tamper {
            let (mut h, master) = sample();
            h.add_keyfile(&master, &kf).unwrap();
            t(&mut h);
            assert!(h.unlock_with_password(PW).unwrap().is_none());
            assert!(h.unlock_with_keyfile(&kf).unwrap().is_none());
        }
    }

    /// Slots copied from another vault (same password, same keyfile!) don't
    /// unlock: slots can't be moved between vaults.
    #[test]
    fn slots_are_bound_to_their_vault() {
        let kf = Keyfile::generate().unwrap();
        let (mut a, master_a) = sample();
        a.add_keyfile(&master_a, &kf).unwrap();
        let (mut b, _) = sample();
        b.kdf = a.kdf;
        b.salt = a.salt;
        b.password = a.password.clone();
        b.keyfiles = a.keyfiles.clone();
        assert!(b.unlock_with_password(PW).unwrap().is_none());
        assert!(b.unlock_with_keyfile(&kf).unwrap().is_none());
    }

    /// Any change to the header changes its hash, which is what the
    /// filesystem checks. (Injecting a keyfile slot needs no master key.)
    #[test]
    fn every_change_changes_the_hash() {
        let (h, master) = sample();
        let mut injected = h.clone();
        injected.add_keyfile(&SecretKey::generate().unwrap(), &Keyfile::generate().unwrap()).unwrap();
        assert_ne!(injected.hash(), h.hash());
        let mut other = h.clone();
        other.set_password(&master, PW, TEST_PARAMS).unwrap();
        assert_ne!(other.hash(), h.hash(), "even the same password rewrapped is a different header");
    }

    /// Cheap deterministic fuzzing: random corruption never panics.
    #[test]
    fn random_corruption_never_panics() {
        let (mut h, master) = sample();
        h.add_keyfile(&master, &Keyfile::generate().unwrap()).unwrap();
        let base = h.to_bytes();
        let mut state = 0x9E3779B97F4A7C15u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..5000 {
            let mut b = base.clone();
            for _ in 0..(next() % 8 + 1) {
                let pos = (next() % 400) as usize;
                b[pos] = next() as u8;
            }
            let _ = Header::parse(&b);
        }
        for _ in 0..500 {
            let len = (next() % 10_000) as usize;
            let b: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            let _ = Header::parse(&b);
        }
    }
}
