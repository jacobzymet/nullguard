//! Authenticated encryption for vault chunks and key wrapping.
//!
//! Both cipher suites take a 192-bit random nonce, so nonces never need
//! to be tracked or counted and a collision is negligible (2^-96 after
//! 2^48 writes):
//!
//! * **XChaCha20-Poly1305** (default) uses the 24-byte nonce directly.
//! * **AES-256-GCM** only has a 96-bit nonce, which is too short for random
//!   nonces at disk scale. nullguard therefore derives a fresh one-time
//!   AES key per message: `subkey = HKDF-SHA256(key, label || nonce[0..12])`
//!   and uses `nonce[12..24]` as the GCM nonce. This is the same idea as
//!   XChaCha's HChaCha step and XAES-256-GCM: every (key, nonce) pair GCM
//!   ever sees is unique with overwhelming probability.

use aes_gcm::Aes256Gcm;
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use zeroize::Zeroizing;

use super::{CryptoError, SecretKey, random};

/// Nonce length stored with every ciphertext (both suites).
pub const NONCE_LEN: usize = 24;
/// Authentication tag length (both suites).
pub const TAG_LEN: usize = 16;

const AES_SUBKEY_LABEL: &[u8] = b"nullguard/v1/aes-256-gcm/subkey";

/// The data encryption algorithm of a vault. The numeric id is stored in
/// the vault header, so algorithms can be added without breaking old vaults.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum CipherSuite {
    XChaCha20Poly1305 = 1,
    Aes256Gcm = 2,
}

impl CipherSuite {
    pub fn id(self) -> u16 {
        self as u16
    }

    pub fn from_id(id: u16) -> Option<Self> {
        match id {
            1 => Some(Self::XChaCha20Poly1305),
            2 => Some(Self::Aes256Gcm),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::XChaCha20Poly1305 => "xchacha20-poly1305",
            Self::Aes256Gcm => "aes-256-gcm",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().replace('_', "-").as_str() {
            "xchacha20-poly1305" | "xchacha20poly1305" | "xchacha" => Some(Self::XChaCha20Poly1305),
            "aes-256-gcm" | "aes256gcm" | "aes" => Some(Self::Aes256Gcm),
            _ => None,
        }
    }
}

/// An AEAD key bound to a cipher suite.
pub struct Aead {
    suite: CipherSuite,
    key: SecretKey,
}

impl Aead {
    pub fn new(suite: CipherSuite, key: SecretKey) -> Self {
        Self { suite, key }
    }

    pub fn suite(&self) -> CipherSuite {
        self.suite
    }

    /// Encrypt `buf` in place under a fresh random nonce.
    /// Returns `(nonce, tag)`; both must be stored with the ciphertext.
    pub fn seal(
        &self,
        aad: &[u8],
        buf: &mut [u8],
    ) -> Result<([u8; NONCE_LEN], [u8; TAG_LEN]), CryptoError> {
        let nonce = random::array::<NONCE_LEN>()?;
        let tag = self.seal_with_nonce(&nonce, aad, buf)?;
        Ok((nonce, tag))
    }

    /// Encrypt with a caller-supplied nonce. Only for known-answer tests and
    /// internal use where the nonce was just generated randomly.
    pub(crate) fn seal_with_nonce(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buf: &mut [u8],
    ) -> Result<[u8; TAG_LEN], CryptoError> {
        match self.suite {
            CipherSuite::XChaCha20Poly1305 => {
                let cipher = XChaCha20Poly1305::new_from_slice(self.key.expose())
                    .map_err(|_| CryptoError::InvalidKey)?;
                let tag = cipher
                    .encrypt_inout_detached(&(*nonce).into(), aad, buf.into())
                    .map_err(|_| CryptoError::Encrypt)?;
                Ok(tag.into())
            }
            CipherSuite::Aes256Gcm => {
                let (cipher, gcm_nonce) = self.aes_for_nonce(nonce)?;
                let tag = cipher
                    .encrypt_inout_detached(&gcm_nonce.into(), aad, buf.into())
                    .map_err(|_| CryptoError::Encrypt)?;
                Ok(tag.into())
            }
        }
    }

    /// Decrypt `buf` in place. On failure `buf` is wiped and
    /// [`CryptoError::AuthFailed`] is returned: the data was modified, the
    /// wrong key was used, or the nonce/AAD don't match.
    pub fn open(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), CryptoError> {
        let result = match self.suite {
            CipherSuite::XChaCha20Poly1305 => {
                let cipher = XChaCha20Poly1305::new_from_slice(self.key.expose())
                    .map_err(|_| CryptoError::InvalidKey)?;
                cipher.decrypt_inout_detached(&(*nonce).into(), aad, buf.into(), &(*tag).into())
            }
            CipherSuite::Aes256Gcm => {
                let (cipher, gcm_nonce) = self.aes_for_nonce(nonce)?;
                cipher.decrypt_inout_detached(&gcm_nonce.into(), aad, buf.into(), &(*tag).into())
            }
        };
        if result.is_err() {
            zeroize::Zeroize::zeroize(buf);
            return Err(CryptoError::AuthFailed);
        }
        Ok(())
    }

    /// The one-time AES-256-GCM instance and 96-bit nonce for a 192-bit nonce.
    fn aes_for_nonce(&self, nonce: &[u8; NONCE_LEN]) -> Result<(Aes256Gcm, [u8; 12]), CryptoError> {
        let hk = hkdf::Hkdf::<sha2::Sha256>::from_prk(self.key.expose())
            .map_err(|_| CryptoError::Kdf)?;
        let mut subkey = Zeroizing::new([0u8; 32]);
        hk.expand_multi_info(&[AES_SUBKEY_LABEL, &nonce[..12]], subkey.as_mut_slice())
            .map_err(|_| CryptoError::Kdf)?;
        let cipher = Aes256Gcm::new_from_slice(subkey.as_slice()).map_err(|_| CryptoError::InvalidKey)?;
        let mut gcm_nonce = [0u8; 12];
        gcm_nonce.copy_from_slice(&nonce[12..]);
        Ok((cipher, gcm_nonce))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUITES: [CipherSuite; 2] = [CipherSuite::XChaCha20Poly1305, CipherSuite::Aes256Gcm];

    fn aead(suite: CipherSuite) -> Aead {
        Aead::new(suite, SecretKey::generate().unwrap())
    }

    #[test]
    fn roundtrip() {
        for suite in SUITES {
            let a = aead(suite);
            let msg = b"attack at dawn, bring snacks".to_vec();
            let mut buf = msg.clone();
            let (nonce, tag) = a.seal(b"aad", &mut buf).unwrap();
            assert_ne!(buf, msg, "{suite:?} did not encrypt");
            a.open(&nonce, b"aad", &mut buf, &tag).unwrap();
            assert_eq!(buf, msg);
        }
    }

    #[test]
    fn nonces_are_unique_and_ciphertexts_differ() {
        for suite in SUITES {
            let a = aead(suite);
            let mut seen = std::collections::HashSet::new();
            let mut last = Vec::new();
            for _ in 0..256 {
                let mut buf = vec![0u8; 64];
                let (nonce, _) = a.seal(b"", &mut buf).unwrap();
                assert!(seen.insert(nonce), "nonce reused");
                assert_ne!(buf, last, "same plaintext produced same ciphertext");
                last = buf;
            }
        }
    }

    #[test]
    fn any_bit_flip_is_rejected() {
        for suite in SUITES {
            let a = aead(suite);
            let mut ct = vec![0x5Au8; 48];
            let (nonce, tag) = a.seal(b"position-7", &mut ct).unwrap();
            for i in 0..ct.len() * 8 {
                let mut t = ct.clone();
                t[i / 8] ^= 1 << (i % 8);
                assert_eq!(a.open(&nonce, b"position-7", &mut t, &tag), Err(CryptoError::AuthFailed));
            }
            for i in 0..TAG_LEN * 8 {
                let mut t = tag;
                t[i / 8] ^= 1 << (i % 8);
                assert!(a.open(&nonce, b"position-7", &mut ct.clone(), &t).is_err());
            }
            for i in 0..NONCE_LEN * 8 {
                let mut n = nonce;
                n[i / 8] ^= 1 << (i % 8);
                assert!(a.open(&n, b"position-7", &mut ct.clone(), &tag).is_err());
            }
            // Wrong AAD (e.g. chunk moved to another position) is rejected.
            assert!(a.open(&nonce, b"position-8", &mut ct.clone(), &tag).is_err());
            // And the untouched ciphertext still opens.
            a.open(&nonce, b"position-7", &mut ct, &tag).unwrap();
        }
    }

    #[test]
    fn wrong_key_is_rejected_and_buffer_wiped() {
        for suite in SUITES {
            let a = aead(suite);
            let b = aead(suite);
            let mut buf = vec![1u8; 32];
            let (nonce, tag) = a.seal(b"", &mut buf).unwrap();
            assert_eq!(b.open(&nonce, b"", &mut buf, &tag), Err(CryptoError::AuthFailed));
            assert!(buf.iter().all(|&x| x == 0));
        }
    }

    #[test]
    fn suites_are_not_interchangeable() {
        let key = SecretKey::generate().unwrap();
        let x = Aead::new(CipherSuite::XChaCha20Poly1305, key.duplicate());
        let g = Aead::new(CipherSuite::Aes256Gcm, key);
        let mut buf = vec![9u8; 32];
        let (nonce, tag) = x.seal(b"", &mut buf).unwrap();
        assert!(g.open(&nonce, b"", &mut buf, &tag).is_err());
    }

    /// The AES-GCM construction must give a different one-time key for every
    /// nonce prefix, and the same key for the same nonce (determinism).
    #[test]
    fn aes_subkey_depends_on_nonce() {
        let a = aead(CipherSuite::Aes256Gcm);
        let n1 = [1u8; NONCE_LEN];
        let mut n2 = n1;
        n2[0] = 2; // differs only in the HKDF part
        let mut c1 = vec![0u8; 32];
        let mut c2 = vec![0u8; 32];
        let mut c1b = vec![0u8; 32];
        a.seal_with_nonce(&n1, b"", &mut c1).unwrap();
        a.seal_with_nonce(&n2, b"", &mut c2).unwrap();
        a.seal_with_nonce(&n1, b"", &mut c1b).unwrap();
        assert_ne!(c1, c2);
        assert_eq!(c1, c1b);
    }

    /// XChaCha20-Poly1305 known-answer test from draft-irtf-cfrg-xchacha-03
    /// appendix A.3.1, to prove we wire the audited crate up correctly.
    #[test]
    fn xchacha_known_answer() {
        fn hex(s: &str) -> Vec<u8> {
            (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"));
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&hex("404142434445464748494a4b4c4d4e4f5051525354555657"));
        let aad = hex("50515253c0c1c2c3c4c5c6c7");
        let mut buf = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".to_vec();
        let a = Aead::new(CipherSuite::XChaCha20Poly1305, SecretKey::from_bytes(&mut key));
        let tag = a.seal_with_nonce(&nonce, &aad, &mut buf).unwrap();
        assert_eq!(
            buf,
            hex("bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e")
        );
        assert_eq!(tag.to_vec(), hex("c0875924c1c7987947deafd8780acf49"));
    }
}
