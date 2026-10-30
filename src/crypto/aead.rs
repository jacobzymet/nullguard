//! Authenticated encryption for vault chunks and key wrapping.
//!
//! nullguard uses one cipher, **XChaCha20-Poly1305**, for every vault.
//!
//! Its 192-bit nonce is large enough to be picked at random for every
//! write, so nonces never need to be tracked or counted (a collision is
//! about 2^-96 likely even after 2^48 writes).

use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{AeadInOut, KeyInit};

use super::{CryptoError, SecretKey, random};
use super::secret::ProtectedKey;

/// Nonce length stored with every ciphertext.
pub const NONCE_LEN: usize = 24;
/// Authentication tag length.
pub const TAG_LEN: usize = 16;
/// Name of the one cipher, as shown to users.
pub const CIPHER_NAME: &str = "xchacha20-poly1305";

/// An XChaCha20-Poly1305 key.
pub struct Aead {
    key: ProtectedKey,
}

impl Aead {
    /// Retain the key, encrypted in memory. Refuse to construct
    /// a cipher if the operating system cannot protect it.
    pub fn new(key: SecretKey) -> Result<Self, CryptoError> {
        Ok(Self { key: ProtectedKey::new(key)? })
    }

    #[cfg(test)]
    pub(crate) fn fail_once_after(&mut self, successful_uses: usize) {
        self.key.fail_once_after(successful_uses);
    }

    fn cipher(&self) -> Result<XChaCha20Poly1305, CryptoError> {
        self.key.with_key(|key| {
            XChaCha20Poly1305::new_from_slice(key.expose()).map_err(|_| CryptoError::InvalidKey)
        })?
    }

    /// Encrypt `buf` in place under a fresh random nonce.
    /// Returns `(nonce, tag)`; both must be stored with the ciphertext.
    pub fn seal(&self, aad: &[u8], buf: &mut [u8]) -> Result<([u8; NONCE_LEN], [u8; TAG_LEN]), CryptoError> {
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
        let tag = self
            .cipher()?
            .encrypt_inout_detached(&(*nonce).into(), aad, buf.into())
            .map_err(|_| CryptoError::Encrypt)?;
        Ok(tag.into())
    }

    /// Decrypt `buf` in place, wiping it on any failure. Authentication
    /// failures return [`CryptoError::AuthFailed`]; local key-memory
    /// failures return [`CryptoError::MemoryProtection`].
    pub fn open(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), CryptoError> {
        let result = self.cipher().and_then(|cipher| {
            cipher.decrypt_inout_detached(&(*nonce).into(), aad, buf.into(), &(*tag).into())
                .map_err(|_| CryptoError::AuthFailed)
        });
        if result.is_err() {
            zeroize::Zeroize::zeroize(buf);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn aead() -> Aead {
        Aead::new(SecretKey::generate().unwrap()).unwrap()
    }

    #[test]
    fn local_key_failure_wipes_output_and_can_be_retried() {
        let mut aead = aead();
        let mut bytes = b"a plaintext block".to_vec();
        let (nonce, tag) = aead.seal(b"test", &mut bytes).unwrap();
        let ciphertext = bytes.clone();
        aead.fail_once_after(0);
        assert_eq!(aead.open(&nonce, b"test", &mut bytes, &tag), Err(CryptoError::MemoryProtection));
        assert!(bytes.iter().all(|&byte| byte == 0));
        bytes.copy_from_slice(&ciphertext);
        aead.open(&nonce, b"test", &mut bytes, &tag).unwrap();
        assert_eq!(bytes, b"a plaintext block");
    }

    #[test]
    fn roundtrip() {
        let a = aead();
        let msg = b"attack at dawn, bring snacks".to_vec();
        let mut buf = msg.clone();
        let (nonce, tag) = a.seal(b"aad", &mut buf).unwrap();
        assert_ne!(buf, msg, "did not encrypt");
        a.open(&nonce, b"aad", &mut buf, &tag).unwrap();
        assert_eq!(buf, msg);
    }

    #[test]
    fn nonces_are_unique_and_ciphertexts_differ() {
        let a = aead();
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

    #[test]
    fn any_bit_flip_is_rejected() {
        let a = aead();
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

    #[test]
    fn wrong_key_is_rejected_and_buffer_wiped() {
        let a = aead();
        let b = aead();
        let mut buf = vec![1u8; 32];
        let (nonce, tag) = a.seal(b"", &mut buf).unwrap();
        assert_eq!(b.open(&nonce, b"", &mut buf, &tag), Err(CryptoError::AuthFailed));
        assert!(buf.iter().all(|&x| x == 0));
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
        let a = Aead::new(SecretKey::from_bytes(&mut key)).unwrap();
        let tag = a.seal_with_nonce(&nonce, &aad, &mut buf).unwrap();
        assert_eq!(
            buf,
            hex("bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e")
        );
        assert_eq!(tag.to_vec(), hex("c0875924c1c7987947deafd8780acf49"));
    }
}
