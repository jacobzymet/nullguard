//! Hybrid post-quantum public-key encryption: ML-KEM-1024 + X25519.
//!
//! A vault master key can be wrapped to a *recipient public key* (your own
//! keyfile, or someone you share the vault with). The key-encryption key is
//! derived from **both** an ML-KEM-1024 (FIPS 203) shared secret and an
//! X25519 shared secret, so an attacker has to break both: X25519 protects
//! against flaws in the young post-quantum scheme, and ML-KEM protects
//! against a future quantum computer ("harvest now, decrypt later").
//!
//! Combiner (in the spirit of X-Wing, with the full transcript bound in):
//!
//! ```text
//! prk = HKDF-Extract(salt = "nullguard/v1/hybrid-kem/mlkem1024+x25519",
//!                    ikm  = ss_mlkem || ss_x25519)
//! kek = HKDF-Expand(prk, info = ct_x25519 || ct_mlkem || pk_x25519 || SHA-256(pk_mlkem), 32)
//! ```
//!
//! ML-KEM comes from `libcrux-ml-kem`, which is formally verified
//! (hax/F*) for panic freedom and functional correctness, and is the same
//! code used by OpenSSH and NSS/Firefox. X25519 is `x25519-dalek`.

use base64ct::{Base64, Encoding};
use libcrux_ml_kem::mlkem1024;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey as XPublic, StaticSecret as XSecret};
use zeroize::{Zeroize, Zeroizing};

use super::aead::{Aead, CipherSuite, NONCE_LEN, TAG_LEN};
use super::kdf::{self, Argon2Params, SALT_LEN};
use super::secret::lock_in_ram;
use super::{COMMITMENT_LEN, CryptoError, SecretKey, key_commitment, random, verify_key_commitment};

pub const X25519_LEN: usize = 32;
pub const MLKEM_PUBLIC_LEN: usize = 1568;
pub const MLKEM_CIPHERTEXT_LEN: usize = 1568;
pub const PUBLIC_KEY_LEN: usize = X25519_LEN + MLKEM_PUBLIC_LEN;
pub const CIPHERTEXT_LEN: usize = X25519_LEN + MLKEM_CIPHERTEXT_LEN;
/// Secret key = X25519 scalar (32) || ML-KEM-1024 key generation seed (d || z, 64).
pub const SECRET_SEED_LEN: usize = 32 + 64;
pub const FINGERPRINT_LEN: usize = 16;

const COMBINER_SALT: &[u8] = b"nullguard/v1/hybrid-kem/mlkem1024+x25519";
const FINGERPRINT_LABEL: &[u8] = b"nullguard/v1/recipient-fingerprint";

const PUBLIC_PREFIX: &str = "nullguard-public-key-1:";
const SECRET_PREFIX: &str = "nullguard-secret-key-1:";
const ENC_SECRET_PREFIX: &str = "nullguard-encrypted-secret-key-1:";
const CHECKSUM_LEN: usize = 4;

/// A hybrid secret key (your "keyfile"). Locked in RAM, zeroized on drop.
pub struct HybridSecretKey {
    seed: Box<[u8; SECRET_SEED_LEN]>,
}

/// A hybrid public key (the `.pub` file you hand out).
#[derive(Clone, PartialEq, Eq)]
pub struct HybridPublicKey {
    x25519: [u8; X25519_LEN],
    mlkem: Box<[u8; MLKEM_PUBLIC_LEN]>,
}

/// The encapsulated key material stored in a recipient key slot.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HybridCiphertext {
    pub x25519_ephemeral: [u8; X25519_LEN],
    pub mlkem: Box<[u8; MLKEM_CIPHERTEXT_LEN]>,
}

impl HybridSecretKey {
    fn empty() -> Self {
        let seed = Box::new([0u8; SECRET_SEED_LEN]);
        lock_in_ram(seed.as_ptr(), SECRET_SEED_LEN);
        Self { seed }
    }

    /// Generate a new random key pair.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut sk = Self::empty();
        random::fill(sk.seed.as_mut_slice())?;
        Ok(sk)
    }

    fn from_seed_slice(seed: &[u8]) -> Result<Self, CryptoError> {
        if seed.len() != SECRET_SEED_LEN {
            return Err(CryptoError::InvalidEncoding("secret key has the wrong length"));
        }
        let mut sk = Self::empty();
        sk.seed.copy_from_slice(seed);
        Ok(sk)
    }

    fn x25519(&self) -> XSecret {
        let mut s = Zeroizing::new([0u8; 32]);
        s.copy_from_slice(&self.seed[..32]);
        XSecret::from(*s)
    }

    /// Run ML-KEM key generation from the stored seed, hand the key pair to
    /// `f`, then wipe the expanded private key.
    fn with_mlkem<R>(&self, f: impl FnOnce(&mlkem1024::MlKem1024KeyPair) -> R) -> R {
        let mut seed = Zeroizing::new([0u8; 64]);
        seed.copy_from_slice(&self.seed[32..]);
        let kp = mlkem1024::generate_key_pair(*seed);
        let out = f(&kp);
        let (mut sk, _pk) = kp.into_parts();
        sk[0..].zeroize();
        out
    }

    pub fn public_key(&self) -> HybridPublicKey {
        let x = XPublic::from(&self.x25519()).to_bytes();
        let mut mlkem = Box::new([0u8; MLKEM_PUBLIC_LEN]);
        self.with_mlkem(|kp| mlkem.copy_from_slice(kp.pk()));
        HybridPublicKey { x25519: x, mlkem }
    }

    /// Serialize as keyfile text. With a passphrase, the key is encrypted
    /// with Argon2id + XChaCha20-Poly1305 (recommended).
    pub fn to_keyfile(&self, passphrase: Option<(&[u8], Argon2Params)>) -> Result<Zeroizing<String>, CryptoError> {
        // Sized up front so the buffer never reallocates (a reallocation
        // would leave an unwiped copy of the encoded secret behind).
        let mut text = Zeroizing::new(String::with_capacity(1024));
        text.push_str("# nullguard secret key (ML-KEM-1024 + X25519). KEEP THIS FILE SECRET.\n");
        text.push_str(&format!("# public key fingerprint: {}\n", self.public_key().fingerprint_hex()));
        match passphrase {
            None => {
                let mut raw = Zeroizing::new(Vec::with_capacity(SECRET_SEED_LEN + CHECKSUM_LEN));
                raw.extend_from_slice(self.seed.as_slice());
                raw.extend_from_slice(&checksum(self.seed.as_slice()));
                text.push_str(SECRET_PREFIX);
                text.push_str(&encode_secret(&raw));
            }
            Some((pass, params)) => {
                params.validate_for_new_slot()?;
                let salt = random::array::<SALT_LEN>()?;
                let mut header = Vec::with_capacity(12 + SALT_LEN);
                header.extend_from_slice(&params.memory_kib.to_le_bytes());
                header.extend_from_slice(&params.iterations.to_le_bytes());
                header.extend_from_slice(&params.parallelism.to_le_bytes());
                header.extend_from_slice(&salt);
                let kek = kdf::derive_key(pass, &salt, &params)?;
                let mut body = Zeroizing::new(self.seed.to_vec());
                let aad = [ENC_SECRET_PREFIX.as_bytes(), &header].concat();
                let nonce = random::array::<NONCE_LEN>()?;
                let commitment = key_commitment(&kek, &nonce, &aad);
                let aead = Aead::new(CipherSuite::XChaCha20Poly1305, kek);
                let tag = aead.seal_with_nonce(&nonce, &aad, &mut body)?;
                let mut raw = header;
                raw.extend_from_slice(&nonce);
                raw.extend_from_slice(&commitment);
                raw.extend_from_slice(&body);
                raw.extend_from_slice(&tag);
                text.push_str(ENC_SECRET_PREFIX);
                text.push_str(&Base64::encode_string(&raw));
            }
        }
        text.push('\n');
        Ok(text)
    }

    /// Whether keyfile text is passphrase-protected.
    pub fn keyfile_is_encrypted(text: &str) -> bool {
        payload_line(text).is_some_and(|l| l.starts_with(ENC_SECRET_PREFIX))
    }

    /// Parse keyfile text produced by [`Self::to_keyfile`].
    pub fn from_keyfile(text: &str, passphrase: Option<&[u8]>) -> Result<Self, CryptoError> {
        let line = payload_line(text).ok_or(CryptoError::InvalidEncoding("not a nullguard keyfile"))?;
        if let Some(b64) = line.strip_prefix(SECRET_PREFIX) {
            let mut raw = Zeroizing::new([0u8; SECRET_SEED_LEN + CHECKSUM_LEN]);
            let decoded = Base64::decode(b64.trim(), raw.as_mut_slice())
                .map_err(|_| CryptoError::InvalidEncoding("keyfile is not valid base64"))?;
            if decoded.len() != SECRET_SEED_LEN + CHECKSUM_LEN {
                return Err(CryptoError::InvalidEncoding("keyfile has the wrong length"));
            }
            let (seed, sum) = raw.split_at(SECRET_SEED_LEN);
            if !bool::from(checksum(seed).ct_eq(sum)) {
                return Err(CryptoError::InvalidEncoding("keyfile checksum mismatch (damaged file?)"));
            }
            return Self::from_seed_slice(seed);
        }
        if let Some(b64) = line.strip_prefix(ENC_SECRET_PREFIX) {
            let pass = passphrase.ok_or(CryptoError::PassphraseRequired)?;
            let raw = Base64::decode_vec(b64.trim())
                .map_err(|_| CryptoError::InvalidEncoding("keyfile is not valid base64"))?;
            let hdr_len = 12 + SALT_LEN;
            if raw.len() != hdr_len + NONCE_LEN + COMMITMENT_LEN + SECRET_SEED_LEN + TAG_LEN {
                return Err(CryptoError::InvalidEncoding("keyfile has the wrong length"));
            }
            let u32_at = |i: usize| u32::from_le_bytes(raw[i..i + 4].try_into().expect("4 bytes"));
            let params = Argon2Params { memory_kib: u32_at(0), iterations: u32_at(4), parallelism: u32_at(8) };
            let salt: [u8; SALT_LEN] = raw[12..hdr_len].try_into().expect("salt length");
            let nonce: [u8; NONCE_LEN] = raw[hdr_len..hdr_len + NONCE_LEN].try_into().expect("nonce length");
            let commit_start = hdr_len + NONCE_LEN;
            let commitment: [u8; COMMITMENT_LEN] =
                raw[commit_start..commit_start + COMMITMENT_LEN].try_into().expect("commitment length");
            let body_start = commit_start + COMMITMENT_LEN;
            let tag: [u8; TAG_LEN] = raw[body_start + SECRET_SEED_LEN..].try_into().expect("tag length");
            let mut body = Zeroizing::new(raw[body_start..body_start + SECRET_SEED_LEN].to_vec());
            let kek = kdf::derive_key(pass, &salt, &params)?;
            let aad = [ENC_SECRET_PREFIX.as_bytes(), &raw[..hdr_len]].concat();
            if !verify_key_commitment(&kek, &nonce, &aad, &commitment) {
                return Err(CryptoError::WrongPassphrase);
            }
            let aead = Aead::new(CipherSuite::XChaCha20Poly1305, kek);
            aead.open(&nonce, &aad, &mut body, &tag)
                .map_err(|_| CryptoError::WrongPassphrase)?;
            return Self::from_seed_slice(&body);
        }
        Err(CryptoError::InvalidEncoding("not a nullguard secret keyfile"))
    }
}

impl Drop for HybridSecretKey {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

impl zeroize::ZeroizeOnDrop for HybridSecretKey {}

impl std::fmt::Debug for HybridSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HybridSecretKey(<redacted>)")
    }
}

impl HybridPublicKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        [self.x25519.as_slice(), self.mlkem.as_slice()].concat()
    }

    /// Parse and validate a raw public key. The ML-KEM key is checked with
    /// the FIPS 203 encapsulation-key modulus check.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != PUBLIC_KEY_LEN {
            return Err(CryptoError::InvalidEncoding("public key has the wrong length"));
        }
        let mut x25519 = [0u8; X25519_LEN];
        x25519.copy_from_slice(&bytes[..X25519_LEN]);
        let mut mlkem = Box::new([0u8; MLKEM_PUBLIC_LEN]);
        mlkem.copy_from_slice(&bytes[X25519_LEN..]);
        if !mlkem1024::validate_public_key(&mlkem1024::MlKem1024PublicKey::from(*mlkem)) {
            return Err(CryptoError::InvalidKey);
        }
        if x25519 == [0u8; X25519_LEN] {
            return Err(CryptoError::InvalidKey);
        }
        Ok(Self { x25519, mlkem })
    }

    /// Short identifier stored in key slots so the right slot can be found.
    pub fn fingerprint(&self) -> [u8; FINGERPRINT_LEN] {
        let mut h = Sha256::new();
        h.update(FINGERPRINT_LABEL);
        h.update(self.x25519);
        h.update(self.mlkem.as_slice());
        let d = h.finalize();
        let mut out = [0u8; FINGERPRINT_LEN];
        out.copy_from_slice(&d[..FINGERPRINT_LEN]);
        out
    }

    pub fn fingerprint_hex(&self) -> String {
        hex(&self.fingerprint())
    }

    pub fn encode(&self) -> String {
        format!(
            "# nullguard public key (ML-KEM-1024 + X25519), fingerprint {}\n{}{}\n",
            self.fingerprint_hex(),
            PUBLIC_PREFIX,
            Base64::encode_string(&self.to_bytes())
        )
    }

    pub fn decode(text: &str) -> Result<Self, CryptoError> {
        let line = payload_line(text).ok_or(CryptoError::InvalidEncoding("not a nullguard public key"))?;
        let b64 = line
            .strip_prefix(PUBLIC_PREFIX)
            .ok_or(CryptoError::InvalidEncoding("not a nullguard public key"))?;
        let raw = Base64::decode_vec(b64.trim()).map_err(|_| CryptoError::InvalidEncoding("public key is not valid base64"))?;
        Self::from_bytes(&raw)
    }
}

impl std::fmt::Debug for HybridPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HybridPublicKey({})", self.fingerprint_hex())
    }
}

impl HybridCiphertext {
    pub fn to_bytes(&self) -> Vec<u8> {
        [self.x25519_ephemeral.as_slice(), self.mlkem.as_slice()].concat()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != CIPHERTEXT_LEN {
            return Err(CryptoError::InvalidEncoding("hybrid ciphertext has the wrong length"));
        }
        let mut x25519_ephemeral = [0u8; X25519_LEN];
        x25519_ephemeral.copy_from_slice(&bytes[..X25519_LEN]);
        let mut mlkem = Box::new([0u8; MLKEM_CIPHERTEXT_LEN]);
        mlkem.copy_from_slice(&bytes[X25519_LEN..]);
        Ok(Self { x25519_ephemeral, mlkem })
    }
}

/// Create a fresh key-encryption key for `recipient`.
/// Returns the ciphertext to store and the KEK (use once, then drop).
pub fn encapsulate(recipient: &HybridPublicKey) -> Result<(HybridCiphertext, SecretKey), CryptoError> {
    // ML-KEM-1024
    let mut coins = Zeroizing::new(random::array::<32>()?);
    let pk = mlkem1024::MlKem1024PublicKey::from(*recipient.mlkem);
    let (ct, ss_m) = mlkem1024::encapsulate(&pk, *coins);
    coins.zeroize();
    let ss_m = Zeroizing::new(ss_m);

    // X25519 (ephemeral-static)
    let mut eph_bytes = Zeroizing::new(random::array::<32>()?);
    let eph = XSecret::from(*eph_bytes);
    eph_bytes.zeroize();
    let eph_pub = XPublic::from(&eph).to_bytes();
    let shared = eph.diffie_hellman(&XPublic::from(recipient.x25519));
    if !shared.was_contributory() {
        return Err(CryptoError::InvalidKey);
    }
    let ss_x = Zeroizing::new(shared.to_bytes());

    let mut mlkem_ct = Box::new([0u8; MLKEM_CIPHERTEXT_LEN]);
    mlkem_ct.copy_from_slice(ct.as_ref());
    let hct = HybridCiphertext { x25519_ephemeral: eph_pub, mlkem: mlkem_ct };
    let kek = combine(&ss_m, &ss_x, &hct, recipient)?;
    Ok((hct, kek))
}

/// Recover the key-encryption key from a recipient slot.
///
/// ML-KEM uses implicit rejection: a ciphertext for a different key yields
/// an unrelated KEK rather than an error, so the caller learns about a
/// mismatch only when unwrapping (authenticated) fails.
pub fn decapsulate(sk: &HybridSecretKey, ct: &HybridCiphertext) -> Result<SecretKey, CryptoError> {
    let mlkem_ct = mlkem1024::MlKem1024Ciphertext::from(&*ct.mlkem);
    let ss_m = Zeroizing::new(sk.with_mlkem(|kp| mlkem1024::decapsulate(kp.private_key(), &mlkem_ct)));
    let shared = sk.x25519().diffie_hellman(&XPublic::from(ct.x25519_ephemeral));
    if !shared.was_contributory() {
        return Err(CryptoError::InvalidKey);
    }
    let ss_x = Zeroizing::new(shared.to_bytes());
    combine(&ss_m, &ss_x, ct, &sk.public_key())
}

fn combine(
    ss_m: &[u8; 32],
    ss_x: &[u8; 32],
    ct: &HybridCiphertext,
    pk: &HybridPublicKey,
) -> Result<SecretKey, CryptoError> {
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(ss_m);
    ikm[32..].copy_from_slice(ss_x);
    let hk = hkdf::Hkdf::<Sha256>::new(Some(COMBINER_SALT), ikm.as_slice());
    let pk_m_hash = Sha256::digest(pk.mlkem.as_slice());
    let mut kek = SecretKey::zeroed();
    hk.expand_multi_info(
        &[&ct.x25519_ephemeral, ct.mlkem.as_slice(), &pk.x25519, &pk_m_hash],
        kek.expose_mut(),
    )
    .map_err(|_| CryptoError::Kdf)?;
    Ok(kek)
}

fn checksum(data: &[u8]) -> [u8; CHECKSUM_LEN] {
    let d = Sha256::digest([b"nullguard/v1/keyfile-checksum".as_slice(), data].concat());
    [d[0], d[1], d[2], d[3]]
}

fn encode_secret(raw: &[u8]) -> Zeroizing<String> {
    let mut buf = Zeroizing::new(vec![0u8; Base64::encoded_len(raw)]);
    let s = Base64::encode(raw, &mut buf).expect("buffer sized by encoded_len");
    Zeroizing::new(s.to_owned())
}

/// The first non-empty, non-comment line.
fn payload_line(text: &str) -> Option<&str> {
    text.lines().map(str::trim).find(|l| !l.is_empty() && !l.starts_with('#'))
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::TEST_PARAMS;

    #[test]
    fn encapsulate_decapsulate_roundtrip() {
        let sk = HybridSecretKey::generate().unwrap();
        let pk = sk.public_key();
        let (ct, kek1) = encapsulate(&pk).unwrap();
        let kek2 = decapsulate(&sk, &ct).unwrap();
        assert_eq!(kek1.expose(), kek2.expose());
    }

    #[test]
    fn each_encapsulation_is_fresh() {
        let pk = HybridSecretKey::generate().unwrap().public_key();
        let (ct1, k1) = encapsulate(&pk).unwrap();
        let (ct2, k2) = encapsulate(&pk).unwrap();
        assert_ne!(ct1, ct2);
        assert_ne!(k1.expose(), k2.expose());
    }

    #[test]
    fn wrong_secret_key_gives_different_kek() {
        let alice = HybridSecretKey::generate().unwrap();
        let mallory = HybridSecretKey::generate().unwrap();
        let (ct, kek) = encapsulate(&alice.public_key()).unwrap();
        let wrong = decapsulate(&mallory, &ct).unwrap();
        assert_ne!(kek.expose(), wrong.expose());
    }

    /// Tampering with either half of the hybrid ciphertext changes the KEK,
    /// so a wrapped key under it will fail authentication.
    #[test]
    fn tampering_either_component_changes_kek() {
        let sk = HybridSecretKey::generate().unwrap();
        let (ct, kek) = encapsulate(&sk.public_key()).unwrap();

        let mut t = ct.clone();
        t.mlkem[100] ^= 1;
        assert_ne!(decapsulate(&sk, &t).unwrap().expose(), kek.expose());

        let mut t = ct.clone();
        t.x25519_ephemeral[5] ^= 1;
        match decapsulate(&sk, &t) {
            Ok(k) => assert_ne!(k.expose(), kek.expose()),
            Err(e) => assert_eq!(e, CryptoError::InvalidKey),
        }
    }

    #[test]
    fn low_order_x25519_point_rejected() {
        let sk = HybridSecretKey::generate().unwrap();
        let (mut ct, _) = encapsulate(&sk.public_key()).unwrap();
        ct.x25519_ephemeral = [0u8; 32];
        assert_eq!(decapsulate(&sk, &ct).unwrap_err(), CryptoError::InvalidKey);
    }

    #[test]
    fn public_key_derivation_is_deterministic() {
        let sk = HybridSecretKey::generate().unwrap();
        assert_eq!(sk.public_key(), sk.public_key());
        assert_eq!(sk.public_key().fingerprint(), sk.public_key().fingerprint());
    }

    #[test]
    fn public_key_encoding_roundtrip_and_validation() {
        let pk = HybridSecretKey::generate().unwrap().public_key();
        let text = pk.encode();
        assert_eq!(HybridPublicKey::decode(&text).unwrap(), pk);
        assert!(HybridPublicKey::from_bytes(&pk.to_bytes()[1..]).is_err());
        // An ML-KEM key with out-of-range coefficients must be rejected.
        let mut raw = pk.to_bytes();
        for b in &mut raw[X25519_LEN..X25519_LEN + 384] {
            *b = 0xFF;
        }
        assert_eq!(HybridPublicKey::from_bytes(&raw).unwrap_err(), CryptoError::InvalidKey);
    }

    #[test]
    fn plain_keyfile_roundtrip_and_checksum() {
        let sk = HybridSecretKey::generate().unwrap();
        let text = sk.to_keyfile(None).unwrap();
        assert!(!HybridSecretKey::keyfile_is_encrypted(&text));
        let back = HybridSecretKey::from_keyfile(&text, None).unwrap();
        assert_eq!(back.public_key(), sk.public_key());

        // Corrupt one base64 character in the payload.
        let line = text.lines().find(|l| l.starts_with(SECRET_PREFIX)).unwrap();
        let mut bad = line.to_string();
        let pos = SECRET_PREFIX.len() + 10;
        let c = if &bad[pos..pos + 1] == "A" { "B" } else { "A" };
        bad.replace_range(pos..pos + 1, c);
        assert!(HybridSecretKey::from_keyfile(&bad, None).is_err());
    }

    #[test]
    fn encrypted_keyfile_roundtrip() {
        // validate_for_new_slot needs >= 64 MiB; use the minimum.
        let params = Argon2Params { memory_kib: Argon2Params::MIN_CREATE_MEMORY_KIB, iterations: 2, parallelism: 1 };
        let sk = HybridSecretKey::generate().unwrap();
        let text = sk.to_keyfile(Some((b"correct horse battery", params))).unwrap();
        assert!(HybridSecretKey::keyfile_is_encrypted(&text));
        assert_eq!(HybridSecretKey::from_keyfile(&text, None).unwrap_err(), CryptoError::PassphraseRequired);
        assert_eq!(
            HybridSecretKey::from_keyfile(&text, Some(b"wrong horse battery")).unwrap_err(),
            CryptoError::WrongPassphrase
        );
        let back = HybridSecretKey::from_keyfile(&text, Some(b"correct horse battery")).unwrap();
        assert_eq!(back.public_key(), sk.public_key());
        let _ = TEST_PARAMS;
    }
}
