//! Keyfiles: a random 256-bit secret in a small text file.
//!
//! A keyfile is just a key. It uses no public-key cryptography, so a
//! quantum computer doesn't help against it (a 256-bit key keeps 128
//! bits of security against Grover's algorithm), and anyone holding the
//! file can unlock every vault it was added to. Keep it secret, like the
//! vault password: on a separate USB stick, or printed as a recovery key.
//!
//! File format (one payload line; blank lines and `#` comments are ignored):
//!
//! ```text
//! nullguard-keyfile-v2:<base64(secret, 32 bytes)>
//! ```
//!
//! The key-encryption key for a vault's keyfile slot is
//! `HKDF-SHA256(salt = vault_id, ikm = secret, info = "nullguard/v2/keyfile-kek")`,
//! so the same keyfile gives an unrelated KEK in every vault.

use base64ct::{Base64, Encoding};
use zeroize::Zeroizing;

use super::{CryptoError, KEY_LEN, SecretKey};

const PREFIX: &str = "nullguard-keyfile-v2:";
const KEK_LABEL: &[u8] = b"nullguard/v2/keyfile-kek";

/// A keyfile's secret. Locked in RAM, zeroized on drop.
pub struct Keyfile {
    secret: SecretKey,
}

impl Keyfile {
    /// A new random keyfile.
    pub fn generate() -> Result<Self, CryptoError> {
        Ok(Self { secret: SecretKey::generate()? })
    }

    /// The keyfile's text form.
    pub fn encode(&self) -> Zeroizing<String> {
        let mut b64 = Zeroizing::new([0u8; 64]);
        let encoded = Base64::encode(self.secret.expose(), b64.as_mut_slice()).expect("64 bytes fit 32 encoded");
        // Sized up front so the string never reallocates (which would leave
        // an unwiped copy of the secret behind).
        let mut text = Zeroizing::new(String::with_capacity(256));
        text.push_str("# nullguard keyfile. Anyone with this file can unlock the vaults it was added to.\n");
        text.push_str("# KEEP IT SECRET, and keep a backup.\n");
        text.push_str(PREFIX);
        text.push_str(encoded);
        text.push('\n');
        text
    }

    /// Parse keyfile text produced by [`Keyfile::encode`].
    pub fn decode(text: &str) -> Result<Self, CryptoError> {
        let line = text
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty() && !l.starts_with('#'))
            .ok_or(CryptoError::InvalidEncoding("not a nullguard keyfile"))?;
        let b64 = line
            .strip_prefix(PREFIX)
            .ok_or(CryptoError::InvalidEncoding(
                "not a nullguard keyfile (keyfiles from nullguard 0.1 don't work with this version)",
            ))?;
        let mut raw = Zeroizing::new([0u8; KEY_LEN]);
        let decoded = Base64::decode(b64, raw.as_mut_slice())
            .map_err(|_| CryptoError::InvalidEncoding("keyfile is damaged (not valid base64 of a 32-byte key)"))?;
        if decoded.len() != KEY_LEN {
            return Err(CryptoError::InvalidEncoding("keyfile is damaged (wrong length)"));
        }
        Ok(Self { secret: SecretKey::from_bytes(&mut raw) })
    }

    /// The key-encryption key for this keyfile's slot in the vault `vault_id`.
    pub(crate) fn kek(&self, vault_id: &[u8]) -> Result<SecretKey, CryptoError> {
        let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(vault_id), self.secret.expose());
        let mut kek = SecretKey::zeroed();
        hk.expand(KEK_LABEL, kek.expose_mut()).map_err(|_| CryptoError::Kdf)?;
        Ok(kek)
    }
}

impl std::fmt::Debug for Keyfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Keyfile(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let k = Keyfile::generate().unwrap();
        let back = Keyfile::decode(&k.encode()).unwrap();
        assert_eq!(k.secret.expose(), back.secret.expose());
    }

    #[test]
    fn keyfiles_are_random() {
        let a = Keyfile::generate().unwrap();
        let b = Keyfile::generate().unwrap();
        assert_ne!(a.secret.expose(), b.secret.expose());
    }

    #[test]
    fn kek_depends_on_vault_and_keyfile() {
        let a = Keyfile::generate().unwrap();
        let b = Keyfile::generate().unwrap();
        let k1 = a.kek(b"vault-one-id-16b").unwrap();
        assert_eq!(k1.expose(), a.kek(b"vault-one-id-16b").unwrap().expose());
        assert_ne!(k1.expose(), a.kek(b"vault-two-id-16b").unwrap().expose());
        assert_ne!(k1.expose(), b.kek(b"vault-one-id-16b").unwrap().expose());
        assert_ne!(k1.expose(), a.secret.expose());
    }

    #[test]
    fn rejects_damaged_and_foreign_files() {
        let k = Keyfile::generate().unwrap();
        let text = k.encode();
        let line = text.lines().find(|l| l.starts_with(PREFIX)).unwrap();
        for bad in [
            "",
            "# only a comment\n",
            "nullguard-secret-key-1:AAAA\n", // a nullguard 0.1 keyfile
            &line[..line.len() - 4],          // truncated
            &format!("{line}AAAA"),           // too long
            &line.replace(PREFIX, "nullguard-keyfile-v1:"),
        ] {
            assert!(Keyfile::decode(bad).is_err(), "{bad:?}");
        }
        // Comments and surrounding whitespace are fine.
        assert!(Keyfile::decode(&format!("\n# note\n  {line}  \n")).is_ok());
    }

    #[test]
    fn debug_is_redacted() {
        let k = Keyfile::generate().unwrap();
        assert_eq!(format!("{k:?}"), "Keyfile(<redacted>)");
    }
}
