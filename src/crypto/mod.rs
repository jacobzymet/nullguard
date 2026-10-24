//! Cryptographic building blocks.
//!
//! nullguard never implements cryptographic primitives itself. Everything
//! here is a thin, misuse-resistant wrapper around audited or formally
//! verified crates:
//!
//! | Purpose                | Algorithm                     | Crate                        |
//! |------------------------|-------------------------------|------------------------------|
//! | Data encryption        | XChaCha20-Poly1305 (default)  | `chacha20poly1305`           |
//! | Data encryption        | AES-256-GCM                   | `aes-gcm`                    |
//! | Password hashing       | Argon2id                      | `argon2`                     |
//! | Post-quantum KEM       | ML-KEM-1024 (FIPS 203)        | `libcrux-ml-kem`             |
//! | Classical KEM          | X25519                        | `x25519-dalek`               |
//! | Key derivation / MAC   | HKDF-SHA256, HMAC-SHA256      | `hkdf`, `hmac`, `sha2`       |
//! | Memory hygiene         | zeroize on drop, mlock        | `zeroize`, `region`          |

pub mod aead;
pub mod hybrid;
pub mod kdf;
pub mod random;
pub mod secret;

pub use aead::{Aead, CipherSuite, NONCE_LEN, TAG_LEN};
pub use hybrid::{HybridCiphertext, HybridPublicKey, HybridSecretKey};
pub use kdf::Argon2Params;
pub use secret::{KEY_LEN, SecretKey, derive_subkey};

use hmac::{KeyInit, Mac};

/// Errors from the crypto layer. Messages are deliberately generic so they
/// leak nothing about secrets.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    #[error("authentication failed: data was modified, or the key is wrong")]
    AuthFailed,
    #[error("invalid key")]
    InvalidKey,
    #[error("encryption failed")]
    Encrypt,
    #[error("key derivation failed")]
    Kdf,
    #[error("the operating system's random number generator failed")]
    Rng,
    #[error("invalid parameters: {0}")]
    InvalidParams(&'static str),
    #[error("invalid encoding: {0}")]
    InvalidEncoding(&'static str),
    #[error("this keyfile is protected by a passphrase")]
    PassphraseRequired,
    #[error("wrong keyfile passphrase")]
    WrongPassphrase,
}

/// HMAC-SHA256 tag over `parts` (concatenated).
pub fn hmac_sha256(key: &SecretKey, parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = <hmac::Hmac<sha2::Sha256> as KeyInit>::new_from_slice(key.expose())
        .expect("HMAC accepts any key length");
    for p in parts {
        mac.update(p);
    }
    mac.finalize().into_bytes().into()
}

/// Constant-time HMAC-SHA256 verification.
pub fn hmac_sha256_verify(key: &SecretKey, parts: &[&[u8]], tag: &[u8; 32]) -> bool {
    let mut mac = <hmac::Hmac<sha2::Sha256> as KeyInit>::new_from_slice(key.expose())
        .expect("HMAC accepts any key length");
    for p in parts {
        mac.update(p);
    }
    mac.verify_slice(tag).is_ok()
}

/// Length of a key commitment.
pub const COMMITMENT_LEN: usize = 32;
const COMMITMENT_LABEL: &[u8] = b"nullguard/v1/key-commitment";

/// Key commitment for a wrapped key:
/// `HMAC-SHA256(kek, "nullguard/v1/key-commitment" || nonce || aad)`.
///
/// Poly1305 and GHASH are not key-committing: one ciphertext can be built
/// to authenticate under many keys at once, which enables "partitioning
/// oracle" attacks on password-derived keys. HMAC-SHA256 is
/// collision-resistant in its key, so checking this value before
/// decrypting makes unwrapping succeed for exactly one key.
pub fn key_commitment(kek: &SecretKey, nonce: &[u8], aad: &[u8]) -> [u8; COMMITMENT_LEN] {
    hmac_sha256(kek, &[COMMITMENT_LABEL, nonce, aad])
}

/// Constant-time check of a [`key_commitment`].
pub fn verify_key_commitment(kek: &SecretKey, nonce: &[u8], aad: &[u8], commitment: &[u8; COMMITMENT_LEN]) -> bool {
    hmac_sha256_verify(kek, &[COMMITMENT_LABEL, nonce, aad], commitment)
}

/// Constant-time equality for secrets or authenticators.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_verifies_and_rejects() {
        let key = SecretKey::generate().unwrap();
        let tag = hmac_sha256(&key, &[b"hello ", b"world"]);
        assert!(hmac_sha256_verify(&key, &[b"hello world"], &tag));
        assert!(!hmac_sha256_verify(&key, &[b"hello worle"], &tag));
        let other = SecretKey::generate().unwrap();
        assert!(!hmac_sha256_verify(&other, &[b"hello world"], &tag));
    }

    /// RFC 4231 test case 2 to confirm HMAC-SHA256 wiring.
    #[test]
    fn hmac_rfc4231_case2() {
        // Key "Jefe" is not 32 bytes; test via the hmac crate directly.
        let mut mac = <hmac::Hmac<sha2::Sha256> as KeyInit>::new_from_slice(b"Jefe").unwrap();
        mac.update(b"what do ya want for nothing?");
        let out: [u8; 32] = mac.finalize().into_bytes().into();
        assert_eq!(
            hybrid::hex(&out),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn ct_eq_works() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }
}
