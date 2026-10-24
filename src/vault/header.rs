//! The versioned vault header.
//!
//! The header is stored twice (primary at offset 0, backup at 64 KiB) and
//! is parsed strictly: every field is range-checked, unknown versions,
//! algorithms or flags are refused, and unused bytes must be zero, so there
//! is exactly one valid encoding of any header.
//!
//! Integrity: each key slot wraps the master key with an AEAD whose
//! associated data covers the vault parameters and the slot's own fields.
//! After unwrapping, the whole header (all slots included) is checked with
//! HMAC-SHA256 under a key derived from the master key. This detects any
//! modification, slot swapping or parameter downgrade, and makes the
//! construction key-committing. See `README.md` for the byte layout.

use crate::crypto::hybrid::{self, HybridCiphertext, HybridPublicKey, HybridSecretKey};
use crate::crypto::kdf::{self, Argon2Params, SALT_LEN};
use crate::crypto::{
    Aead, COMMITMENT_LEN, CipherSuite, CryptoError, KEY_LEN, NONCE_LEN, SecretKey, TAG_LEN, derive_subkey,
    hmac_sha256, hmac_sha256_verify, key_commitment, random, verify_key_commitment,
};

pub const MAGIC: [u8; 8] = *b"NULLGARD";
pub const FORMAT_VERSION: u16 = 1;

/// Size of one header copy on disk.
pub const HEADER_AREA: u64 = 64 * 1024;
pub const PRIMARY_OFFSET: u64 = 0;
pub const BACKUP_OFFSET: u64 = HEADER_AREA;
/// Where the chunk area starts (v1: right after the two header copies).
pub const DATA_OFFSET: u64 = 2 * HEADER_AREA;

pub const VAULT_ID_LEN: usize = 16;
pub const MAC_LEN: usize = 32;
pub const MAX_SLOTS: usize = 32;
/// At most this many password slots. Each costs a full Argon2id run on
/// every unlock attempt, so a crafted vault with many expensive slots
/// could otherwise stall unlocking for a very long time.
pub const MAX_PASSWORD_SLOTS: usize = 4;

pub const MIN_CHUNK_SIZE: u32 = 4 * 1024;
pub const MAX_CHUNK_SIZE: u32 = 1024 * 1024;
/// Fewest chunks a vault may have (2 superblocks + room for data).
pub const MIN_CHUNKS: u64 = 16;
/// Upper bound on vault size (2^50 bytes = 1 PiB) to keep arithmetic safe.
pub const MAX_VAULT_BYTES: u64 = 1 << 50;

const CORE_LEN: usize = 64;
/// Bytes of the core bound into every key slot (everything except the slot
/// count and reserved bytes, so slots can be added without rewrapping).
const SLOT_AAD_CORE_LEN: usize = 52;
const SLOT_HEADER_LEN: usize = 4;

const SLOT_PASSWORD: u8 = 1;
const SLOT_RECIPIENT: u8 = 2;
const KDF_ARGON2ID: u8 = 1;
const KEM_MLKEM1024_X25519: u8 = 1;

const WRAPPED_KEY_LEN: usize = NONCE_LEN + COMMITMENT_LEN + KEY_LEN + TAG_LEN;
const PASSWORD_BODY_LEN: usize = 4 + 12 + SALT_LEN + WRAPPED_KEY_LEN;
const RECIPIENT_BODY_LEN: usize = 4 + hybrid::FINGERPRINT_LEN + hybrid::CIPHERTEXT_LEN + WRAPPED_KEY_LEN;

const LABEL_SLOT_AAD: &[u8] = b"nullguard/v1/keyslot";
const LABEL_HEADER_MAC: &[u8] = b"nullguard/v1/header-mac";

/// Why a header could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HeaderError {
    #[error("not a nullguard vault (bad magic)")]
    NotAVault,
    #[error("unsupported vault format version {0} (this build supports version {FORMAT_VERSION})")]
    UnsupportedVersion(u16),
    #[error("malformed vault header: {0}")]
    Malformed(&'static str),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// A key slot: one way to unlock the master key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeySlot {
    Password(PasswordSlot),
    Recipient(RecipientSlot),
}

/// The master key wrapped under a key-encryption key (KEK):
/// `XChaCha20-Poly1305(KEK, nonce, master_key, aad)` plus a key commitment
/// to the KEK (see [`crate::crypto::key_commitment`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrappedKey {
    pub nonce: [u8; NONCE_LEN],
    pub commitment: [u8; COMMITMENT_LEN],
    pub ciphertext: [u8; KEY_LEN],
    pub tag: [u8; TAG_LEN],
}

impl WrappedKey {
    fn seal(kek: SecretKey, aad: &[u8], master: &SecretKey) -> Result<Self, CryptoError> {
        let mut buf = zeroize::Zeroizing::new(*master.expose());
        let nonce = random::array::<NONCE_LEN>()?;
        let commitment = key_commitment(&kek, &nonce, aad);
        let aead = Aead::new(CipherSuite::XChaCha20Poly1305, kek);
        let tag = aead.seal_with_nonce(&nonce, aad, buf.as_mut_slice())?;
        Ok(Self { nonce, commitment, ciphertext: *buf, tag })
    }

    /// Recover the master key. The commitment is checked first (in constant
    /// time), so this succeeds under at most one KEK.
    fn open(&self, kek: SecretKey, aad: &[u8]) -> Result<SecretKey, CryptoError> {
        if !verify_key_commitment(&kek, &self.nonce, aad, &self.commitment) {
            return Err(CryptoError::AuthFailed);
        }
        let aead = Aead::new(CipherSuite::XChaCha20Poly1305, kek);
        let mut buf = zeroize::Zeroizing::new(self.ciphertext);
        aead.open(&self.nonce, aad, buf.as_mut_slice(), &self.tag)?;
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasswordSlot {
    pub kdf: Argon2Params,
    pub salt: [u8; SALT_LEN],
    pub key: WrappedKey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecipientSlot {
    pub fingerprint: [u8; hybrid::FINGERPRINT_LEN],
    pub kem: HybridCiphertext,
    pub key: WrappedKey,
}

/// The parsed vault header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub cipher: CipherSuite,
    pub vault_id: [u8; VAULT_ID_LEN],
    pub chunk_size: u32,
    pub chunk_count: u64,
    pub data_offset: u64,
    pub slots: Vec<KeySlot>,
    pub mac: [u8; MAC_LEN],
}

/// Bytes each chunk occupies on disk: nonce || ciphertext || tag.
pub fn chunk_stride(chunk_size: u32) -> u64 {
    chunk_size as u64 + (NONCE_LEN + TAG_LEN) as u64
}

impl Header {
    /// A new header with no key slots yet.
    pub fn new(cipher: CipherSuite, chunk_size: u32, chunk_count: u64) -> Result<Self, HeaderError> {
        let h = Self {
            cipher,
            vault_id: random::array()?,
            chunk_size,
            chunk_count,
            data_offset: DATA_OFFSET,
            slots: Vec::new(),
            mac: [0; MAC_LEN],
        };
        h.validate_geometry()?;
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
        if self.data_offset != DATA_OFFSET {
            return Err(HeaderError::Malformed("unexpected data offset"));
        }
        let total = self
            .chunk_count
            .checked_mul(chunk_stride(self.chunk_size))
            .and_then(|n| n.checked_add(self.data_offset))
            .ok_or(HeaderError::Malformed("vault size overflows"))?;
        if total > MAX_VAULT_BYTES {
            return Err(HeaderError::Malformed("vault too large"));
        }
        Ok(())
    }

    /// Total size of the vault file this header describes.
    pub fn file_len(&self) -> u64 {
        self.data_offset + self.chunk_count * chunk_stride(self.chunk_size)
    }

    fn core_bytes(&self) -> [u8; CORE_LEN] {
        let mut c = [0u8; CORE_LEN];
        c[0..8].copy_from_slice(&MAGIC);
        c[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        c[10..12].copy_from_slice(&self.cipher.id().to_le_bytes());
        c[12..16].copy_from_slice(&0u32.to_le_bytes()); // flags
        c[16..32].copy_from_slice(&self.vault_id);
        c[32..36].copy_from_slice(&self.chunk_size.to_le_bytes());
        c[36..44].copy_from_slice(&self.chunk_count.to_le_bytes());
        c[44..52].copy_from_slice(&self.data_offset.to_le_bytes());
        c[52..54].copy_from_slice(&(self.slots.len() as u16).to_le_bytes());
        // 54..64 reserved, zero
        c
    }

    /// Everything covered by the header MAC: core || slots.
    fn signed_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CORE_LEN + self.slots.len() * (SLOT_HEADER_LEN + RECIPIENT_BODY_LEN));
        out.extend_from_slice(&self.core_bytes());
        for slot in &self.slots {
            let (ty, body) = match slot {
                KeySlot::Password(p) => (SLOT_PASSWORD, p.body()),
                KeySlot::Recipient(r) => (SLOT_RECIPIENT, r.body()),
            };
            out.push(ty);
            out.push(0);
            out.extend_from_slice(&(body.len() as u16).to_le_bytes());
            out.extend_from_slice(&body);
        }
        out
    }

    /// Serialize to exactly [`HEADER_AREA`] bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        assert!(self.slots.len() <= MAX_SLOTS && !self.slots.is_empty(), "slot count invariant");
        let mut out = self.signed_bytes();
        out.extend_from_slice(&self.mac);
        assert!(out.len() as u64 <= HEADER_AREA);
        out.resize(HEADER_AREA as usize, 0);
        out
    }

    /// Strictly parse a header copy. Does not authenticate it (that needs
    /// the master key; see [`Header::verify_mac`]).
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
        let cipher = CipherSuite::from_id(r.u16()?).ok_or(HeaderError::Malformed("unknown cipher suite"))?;
        if r.u32()? != 0 {
            return Err(HeaderError::Malformed("unknown flags set"));
        }
        let vault_id = r.array::<VAULT_ID_LEN>()?;
        let chunk_size = r.u32()?;
        let chunk_count = r.u64()?;
        let data_offset = r.u64()?;
        let slot_count = r.u16()? as usize;
        if r.take(10)?.iter().any(|&b| b != 0) {
            return Err(HeaderError::Malformed("reserved bytes are not zero"));
        }
        if slot_count == 0 || slot_count > MAX_SLOTS {
            return Err(HeaderError::Malformed("bad key slot count"));
        }
        let mut slots = Vec::with_capacity(slot_count);
        for _ in 0..slot_count {
            let ty = r.u8()?;
            if r.u8()? != 0 {
                return Err(HeaderError::Malformed("reserved slot byte is not zero"));
            }
            let len = r.u16()? as usize;
            let body = r.take(len)?;
            slots.push(match ty {
                SLOT_PASSWORD => KeySlot::Password(PasswordSlot::parse(body)?),
                SLOT_RECIPIENT => KeySlot::Recipient(RecipientSlot::parse(body)?),
                _ => return Err(HeaderError::Malformed("unknown key slot type")),
            });
        }
        if slots.iter().filter(|s| matches!(s, KeySlot::Password(_))).count() > MAX_PASSWORD_SLOTS {
            return Err(HeaderError::Malformed("too many password slots"));
        }
        let mac = r.array::<MAC_LEN>()?;
        if r.rest().iter().any(|&b| b != 0) {
            return Err(HeaderError::Malformed("header padding is not zero"));
        }
        let h = Self { cipher, vault_id, chunk_size, chunk_count, data_offset, slots, mac };
        h.validate_geometry()?;
        Ok(h)
    }

    fn mac_key(master: &SecretKey) -> Result<SecretKey, CryptoError> {
        derive_subkey(master, LABEL_HEADER_MAC)
    }

    /// Recompute the header MAC (after any change to the header).
    pub fn seal(&mut self, master: &SecretKey) -> Result<(), CryptoError> {
        let key = Self::mac_key(master)?;
        self.mac = hmac_sha256(&key, &[&self.signed_bytes()]);
        Ok(())
    }

    /// Constant-time check of the header MAC under the master key.
    pub fn verify_mac(&self, master: &SecretKey) -> Result<bool, CryptoError> {
        let key = Self::mac_key(master)?;
        Ok(hmac_sha256_verify(&key, &[&self.signed_bytes()], &self.mac))
    }

    /// Associated data for a key slot: binds the vault parameters and the
    /// slot's non-secret fields, so none of them can be altered.
    fn slot_aad(&self, slot_type: u8, slot_fields: &[u8]) -> Vec<u8> {
        let core = self.core_bytes();
        [LABEL_SLOT_AAD, &core[..SLOT_AAD_CORE_LEN], &[slot_type], slot_fields].concat()
    }

    /// Add a password slot wrapping `master`.
    pub fn add_password_slot(
        &mut self,
        master: &SecretKey,
        password: &[u8],
        params: Argon2Params,
    ) -> Result<(), HeaderError> {
        self.check_slot_room()?;
        if self.password_slot_count() >= MAX_PASSWORD_SLOTS {
            return Err(HeaderError::Malformed("too many password slots"));
        }
        params.validate()?;
        let salt = random::array::<SALT_LEN>()?;
        let kek = kdf::derive_key(password, &salt, &params)?;
        let aad = self.slot_aad(SLOT_PASSWORD, &PasswordSlot::bound_fields(&params, &salt));
        let key = WrappedKey::seal(kek, &aad, master)?;
        self.slots.push(KeySlot::Password(PasswordSlot { kdf: params, salt, key }));
        Ok(())
    }

    /// Add a slot that `recipient`'s keyfile can unlock.
    pub fn add_recipient_slot(&mut self, master: &SecretKey, recipient: &HybridPublicKey) -> Result<(), HeaderError> {
        self.check_slot_room()?;
        let fingerprint = recipient.fingerprint();
        if self.slots.iter().any(|s| matches!(s, KeySlot::Recipient(r) if r.fingerprint == fingerprint)) {
            return Err(HeaderError::Malformed("that recipient already has a key slot"));
        }
        let (kem, kek) = hybrid::encapsulate(recipient)?;
        let aad = self.slot_aad(SLOT_RECIPIENT, &RecipientSlot::bound_fields(&fingerprint, &kem));
        let key = WrappedKey::seal(kek, &aad, master)?;
        self.slots.push(KeySlot::Recipient(RecipientSlot { fingerprint, kem, key }));
        Ok(())
    }

    fn check_slot_room(&self) -> Result<(), HeaderError> {
        if self.slots.len() >= MAX_SLOTS {
            return Err(HeaderError::Malformed("no free key slots"));
        }
        Ok(())
    }

    /// Try every password slot. Returns the master key on success.
    ///
    /// All password slots are tried even after a match would be found, so
    /// timing does not reveal which slot matched.
    pub fn unlock_with_password(&self, password: &[u8]) -> Result<Option<SecretKey>, HeaderError> {
        let mut found = None;
        for slot in &self.slots {
            if let KeySlot::Password(p) = slot {
                let kek = kdf::derive_key(password, &p.salt, &p.kdf)?;
                let aad = self.slot_aad(SLOT_PASSWORD, &PasswordSlot::bound_fields(&p.kdf, &p.salt));
                if let Ok(k) = p.key.open(kek, &aad) {
                    found.get_or_insert(k);
                }
            }
        }
        Ok(found)
    }

    /// Try the recipient slot(s) matching `sk`'s public key.
    pub fn unlock_with_keyfile(&self, sk: &HybridSecretKey) -> Result<Option<SecretKey>, HeaderError> {
        let fp = sk.public_key().fingerprint();
        for slot in &self.slots {
            if let KeySlot::Recipient(r) = slot
                && r.fingerprint == fp
            {
                let kek = hybrid::decapsulate(sk, &r.kem)?;
                let aad = self.slot_aad(SLOT_RECIPIENT, &RecipientSlot::bound_fields(&r.fingerprint, &r.kem));
                if let Ok(k) = r.key.open(kek, &aad) {
                    return Ok(Some(k));
                }
            }
        }
        Ok(None)
    }

    pub fn password_slot_count(&self) -> usize {
        self.slots.iter().filter(|s| matches!(s, KeySlot::Password(_))).count()
    }
}

impl PasswordSlot {
    /// Fields bound into the wrap AAD (everything but the wrapped key).
    fn bound_fields(kdf: &Argon2Params, salt: &[u8; SALT_LEN]) -> Vec<u8> {
        let mut v = Vec::with_capacity(16 + SALT_LEN);
        v.extend_from_slice(&[KDF_ARGON2ID, 0, 0, 0]);
        v.extend_from_slice(&kdf.memory_kib.to_le_bytes());
        v.extend_from_slice(&kdf.iterations.to_le_bytes());
        v.extend_from_slice(&kdf.parallelism.to_le_bytes());
        v.extend_from_slice(salt);
        v
    }

    fn body(&self) -> Vec<u8> {
        let mut v = Self::bound_fields(&self.kdf, &self.salt);
        self.key.encode(&mut v);
        debug_assert_eq!(v.len(), PASSWORD_BODY_LEN);
        v
    }

    fn parse(body: &[u8]) -> Result<Self, HeaderError> {
        if body.len() != PASSWORD_BODY_LEN {
            return Err(HeaderError::Malformed("password slot has the wrong length"));
        }
        let mut r = Reader::new(body);
        if r.u8()? != KDF_ARGON2ID {
            return Err(HeaderError::Malformed("unknown key derivation function"));
        }
        if r.take(3)? != [0, 0, 0] {
            return Err(HeaderError::Malformed("reserved slot bytes are not zero"));
        }
        let kdf = Argon2Params { memory_kib: r.u32()?, iterations: r.u32()?, parallelism: r.u32()? };
        kdf.validate()?;
        Ok(Self { kdf, salt: r.array()?, key: WrappedKey::parse(&mut r)? })
    }
}

impl RecipientSlot {
    fn bound_fields(fingerprint: &[u8; hybrid::FINGERPRINT_LEN], kem: &HybridCiphertext) -> Vec<u8> {
        let mut v = Vec::with_capacity(4 + hybrid::FINGERPRINT_LEN + hybrid::CIPHERTEXT_LEN);
        v.extend_from_slice(&[KEM_MLKEM1024_X25519, 0, 0, 0]);
        v.extend_from_slice(fingerprint);
        v.extend_from_slice(&kem.to_bytes());
        v
    }

    fn body(&self) -> Vec<u8> {
        let mut v = Self::bound_fields(&self.fingerprint, &self.kem);
        self.key.encode(&mut v);
        debug_assert_eq!(v.len(), RECIPIENT_BODY_LEN);
        v
    }

    fn parse(body: &[u8]) -> Result<Self, HeaderError> {
        if body.len() != RECIPIENT_BODY_LEN {
            return Err(HeaderError::Malformed("recipient slot has the wrong length"));
        }
        let mut r = Reader::new(body);
        if r.u8()? != KEM_MLKEM1024_X25519 {
            return Err(HeaderError::Malformed("unknown key encapsulation mechanism"));
        }
        if r.take(3)? != [0, 0, 0] {
            return Err(HeaderError::Malformed("reserved slot bytes are not zero"));
        }
        let fingerprint = r.array()?;
        let kem = HybridCiphertext::from_bytes(r.take(hybrid::CIPHERTEXT_LEN)?)?;
        Ok(Self { fingerprint, kem, key: WrappedKey::parse(&mut r)? })
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

    fn sample() -> (Header, SecretKey) {
        let master = SecretKey::generate().unwrap();
        let mut h = Header::new(CipherSuite::XChaCha20Poly1305, 16 * 1024, 1000).unwrap();
        h.add_password_slot(&master, b"correct horse battery staple", TEST_PARAMS).unwrap();
        h.seal(&master).unwrap();
        (h, master)
    }

    #[test]
    fn serialize_parse_roundtrip() {
        let (h, master) = sample();
        let bytes = h.to_bytes();
        assert_eq!(bytes.len() as u64, HEADER_AREA);
        let parsed = Header::parse(&bytes).unwrap();
        assert_eq!(parsed, h);
        assert!(parsed.verify_mac(&master).unwrap());
        assert_eq!(parsed.to_bytes(), bytes, "encoding must be canonical");
    }

    #[test]
    fn roundtrip_with_recipients_and_aes() {
        let master = SecretKey::generate().unwrap();
        let mut h = Header::new(CipherSuite::Aes256Gcm, 64 * 1024, 5000).unwrap();
        h.add_password_slot(&master, b"pw-one-is-long-enough", TEST_PARAMS).unwrap();
        let sk = HybridSecretKey::generate().unwrap();
        h.add_recipient_slot(&master, &sk.public_key()).unwrap();
        h.seal(&master).unwrap();
        let parsed = Header::parse(&h.to_bytes()).unwrap();
        assert_eq!(parsed, h);
        let k = parsed.unlock_with_keyfile(&sk).unwrap().expect("keyfile unlocks");
        assert_eq!(k.expose(), master.expose());
        // A different keyfile does not unlock.
        let other = HybridSecretKey::generate().unwrap();
        assert!(parsed.unlock_with_keyfile(&other).unwrap().is_none());
    }

    /// Unwrapping needs both the commitment and the AEAD tag to verify under
    /// the same KEK, so no ciphertext can "unlock" under several keys.
    #[test]
    fn wrapped_key_is_key_committing() {
        let master = SecretKey::generate().unwrap();
        let kek_a = SecretKey::generate().unwrap();
        let kek_b = SecretKey::generate().unwrap();
        let aad = b"slot aad";
        let w = WrappedKey::seal(kek_a.duplicate(), aad, &master).unwrap();
        assert_eq!(w.open(kek_a.duplicate(), aad).unwrap().expose(), master.expose());
        assert!(w.open(kek_b.duplicate(), aad).is_err());
        // Swap in an honest commitment for KEK B: B now passes the commitment
        // but fails the AEAD, and A fails the commitment.
        let mut forged = w.clone();
        forged.commitment = key_commitment(&kek_b, &forged.nonce, aad);
        assert!(forged.open(kek_b, aad).is_err());
        assert!(forged.open(kek_a.duplicate(), aad).is_err());
        // The commitment also binds nonce and AAD.
        assert!(w.open(kek_a.duplicate(), b"other aad").is_err());
        let mut bad = w.clone();
        bad.commitment[0] ^= 1;
        assert!(bad.open(kek_a, aad).is_err());
    }

    #[test]
    fn password_slots_are_capped() {
        let master = SecretKey::generate().unwrap();
        let mut h = Header::new(CipherSuite::XChaCha20Poly1305, 16 * 1024, 1000).unwrap();
        for _ in 0..MAX_PASSWORD_SLOTS {
            h.add_password_slot(&master, b"pw", TEST_PARAMS).unwrap();
        }
        assert!(h.add_password_slot(&master, b"pw", TEST_PARAMS).is_err());
        // A crafted header with more password slots is refused when parsing.
        let extra = h.slots[0].clone();
        h.slots.push(extra);
        h.seal(&master).unwrap();
        assert_eq!(Header::parse(&h.to_bytes()).unwrap_err(), HeaderError::Malformed("too many password slots"));
    }

    #[test]
    fn max_slots_fit_in_header_area() {
        let master = SecretKey::generate().unwrap();
        let mut h = Header::new(CipherSuite::XChaCha20Poly1305, 16 * 1024, 1000).unwrap();
        h.add_password_slot(&master, b"pw", TEST_PARAMS).unwrap();
        while h.slots.len() < MAX_SLOTS {
            h.add_recipient_slot(&master, &HybridSecretKey::generate().unwrap().public_key()).unwrap();
        }
        assert!(h.add_recipient_slot(&master, &HybridSecretKey::generate().unwrap().public_key()).is_err());
        h.seal(&master).unwrap();
        let parsed = Header::parse(&h.to_bytes()).unwrap();
        assert_eq!(parsed.slots.len(), MAX_SLOTS);
    }

    #[test]
    fn password_unlock() {
        let (h, master) = sample();
        let k = h.unlock_with_password(b"correct horse battery staple").unwrap().unwrap();
        assert_eq!(k.expose(), master.expose());
        assert!(h.unlock_with_password(b"correct horse battery stapler").unwrap().is_none());
        assert!(h.unlock_with_password(b"").unwrap().is_none());
    }

    #[test]
    fn rejects_bad_magic_version_and_truncation() {
        let (h, _) = sample();
        let mut b = h.to_bytes();
        b[0] ^= 1;
        assert_eq!(Header::parse(&b).unwrap_err(), HeaderError::NotAVault);

        let mut b = h.to_bytes();
        b[8] = 2;
        assert_eq!(Header::parse(&b).unwrap_err(), HeaderError::UnsupportedVersion(2));

        let b = h.to_bytes();
        assert!(Header::parse(&b[..1000]).is_err());
        assert!(Header::parse(&[]).is_err());
    }

    #[test]
    fn rejects_unknown_cipher_flags_and_geometry() {
        let (h, _) = sample();
        let cases: [(usize, u8); 6] = [
            (10, 99), // cipher id
            (12, 1),  // flags
            (32, 1),  // chunk size not a power of two
            (55, 1),  // reserved
            (52, 0),  // slot count 1 -> 0
            (44, 1),  // data offset
        ];
        for (off, val) in cases {
            let mut b = h.to_bytes();
            b[off] = val;
            assert!(Header::parse(&b).is_err(), "byte {off} = {val} should be rejected");
        }
    }

    #[test]
    fn rejects_nonzero_padding() {
        let (h, _) = sample();
        let mut b = h.to_bytes();
        let last = b.len() - 1;
        b[last] = 1;
        assert_eq!(Header::parse(&b).unwrap_err(), HeaderError::Malformed("header padding is not zero"));
    }

    #[test]
    fn rejects_hostile_kdf_params() {
        let (h, _) = sample();
        // The password slot's memory cost sits at core(64) + slot header(4) + 4.
        let mut b = h.to_bytes();
        b[72..76].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(Header::parse(&b).is_err());
    }

    /// Every single-bit change in the authenticated region is either
    /// rejected by the parser, prevents unlocking, or is caught by the MAC.
    #[test]
    fn every_bit_flip_is_detected() {
        let (h, master) = sample();
        let bytes = h.to_bytes();
        let signed_len = h.signed_bytes().len() + MAC_LEN;
        for i in 0..signed_len * 8 {
            let mut b = bytes.clone();
            b[i / 8] ^= 1 << (i % 8);
            let Ok(parsed) = Header::parse(&b) else { continue };
            // Parsed fine: the MAC must now fail under the real master key.
            assert!(!parsed.verify_mac(&master).unwrap(), "bit {i} flip went undetected");
        }
    }

    /// Changing a slot's KDF params (a downgrade attack) breaks the wrap.
    #[test]
    fn kdf_downgrade_breaks_unlock() {
        let master = SecretKey::generate().unwrap();
        let strong = Argon2Params { iterations: 3, ..TEST_PARAMS };
        let mut h = Header::new(CipherSuite::XChaCha20Poly1305, 16 * 1024, 1000).unwrap();
        h.add_password_slot(&master, b"pw", strong).unwrap();
        if let KeySlot::Password(p) = &mut h.slots[0] {
            p.kdf.iterations = 1;
        }
        assert!(h.unlock_with_password(b"pw").unwrap().is_none());
    }

    /// Changing vault parameters (e.g. cipher) breaks every slot's wrap.
    #[test]
    fn parameter_tampering_breaks_unlock() {
        let (mut h, _) = sample();
        h.cipher = CipherSuite::Aes256Gcm;
        assert!(h.unlock_with_password(b"correct horse battery staple").unwrap().is_none());
        let (mut h, _) = sample();
        h.chunk_count += 1;
        assert!(h.unlock_with_password(b"correct horse battery staple").unwrap().is_none());
        let (mut h, _) = sample();
        h.vault_id[0] ^= 1;
        assert!(h.unlock_with_password(b"correct horse battery staple").unwrap().is_none());
    }

    /// A slot copied from another vault (same password!) does not unlock,
    /// and slots can't be moved between vaults.
    #[test]
    fn slots_are_bound_to_their_vault() {
        let (a, _) = sample();
        let (mut b, _) = sample();
        b.slots = a.slots.clone();
        assert!(b.unlock_with_password(b"correct horse battery staple").unwrap().is_none());
    }

    /// Adding a slot to a sealed header without the master key is detected.
    #[test]
    fn injected_slot_detected_by_mac() {
        let (mut h, master) = sample();
        let attacker_key = SecretKey::generate().unwrap();
        h.add_password_slot(&attacker_key, b"attacker", TEST_PARAMS).unwrap();
        let parsed = Header::parse(&h.to_bytes()).unwrap();
        assert!(!parsed.verify_mac(&master).unwrap());
    }

    /// Cheap deterministic fuzzing: random corruption never panics.
    #[test]
    fn random_corruption_never_panics() {
        let (h, _) = sample();
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
            let len = (next() % 70_000) as usize;
            let b: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            let _ = Header::parse(&b);
        }
    }
}
