//! Platform-specific protection for a retained key. Unix uses the existing
//! audited AEAD directly to avoid recursing through the protected Aead type.

use super::{CryptoError, KEY_LEN};

#[cfg(any(target_os = "linux", target_os = "macos"))]
use chacha20poly1305::{XChaCha20Poly1305, aead::{AeadInOut, KeyInit}};

pub(super) struct KeyProtection {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    wrapping: crate::platform::key_memory::KeyPage,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    nonce: [u8; super::NONCE_LEN],
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    tag: [u8; super::TAG_LEN],
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
const AAD: &[u8] = b"nullguard/ram-key/v1";

impl KeyProtection {
    pub(super) fn seal(bytes: &mut [u8; KEY_LEN]) -> Result<Self, CryptoError> {
        #[cfg(windows)]
        {
            crate::platform::win::protect_key_memory(bytes).map_err(|_| CryptoError::MemoryProtection)?;
            Ok(Self {})
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let wrapping = crate::platform::key_memory::KeyPage::generate()?;
            let nonce = super::random::array()?;
            let tag = wrapping.with_key(|key| {
                XChaCha20Poly1305::new(key.into())
                    .encrypt_inout_detached((&nonce).into(), AAD, bytes.as_mut_slice().into())
                    .map_err(|_| CryptoError::MemoryProtection)
            })??;
            Ok(Self { wrapping, nonce, tag: tag.into() })
        }
        #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
        {
            let _ = bytes;
            Err(CryptoError::MemoryProtection)
        }
    }

    pub(super) fn open(&self, bytes: &mut [u8; KEY_LEN]) -> Result<(), CryptoError> {
        #[cfg(windows)]
        {
            crate::platform::win::unprotect_key_memory(bytes).map_err(|_| CryptoError::MemoryProtection)
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let result = self.wrapping.with_key(|key| {
                XChaCha20Poly1305::new(key.into())
                    .decrypt_inout_detached((&self.nonce).into(), AAD, bytes.as_mut_slice().into(), (&self.tag).into())
                    .map_err(|_| CryptoError::MemoryProtection)
            }).and_then(|result| result);
            if result.is_err() {
                zeroize::Zeroize::zeroize(bytes);
            }
            result
        }
        #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
        {
            let _ = bytes;
            Err(CryptoError::MemoryProtection)
        }
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;

    #[test]
    fn tampered_memory_capsules_are_rejected_and_wiped() {
        for part in 0..3 {
            let mut bytes = [0xA7; KEY_LEN];
            let mut protection = KeyProtection::seal(&mut bytes).unwrap();
            match part {
                0 => bytes[0] ^= 1,
                1 => protection.nonce[0] ^= 1,
                _ => protection.tag[0] ^= 1,
            }
            assert_eq!(protection.open(&mut bytes), Err(CryptoError::MemoryProtection));
            assert_eq!(bytes, [0; KEY_LEN]);
        }
    }

    #[test]
    fn swapping_a_capsule_into_another_key_is_rejected() {
        let mut first = [0x19; KEY_LEN];
        let mut second = [0x63; KEY_LEN];
        let mut protection = KeyProtection::seal(&mut first).unwrap();
        let other = KeyProtection::seal(&mut second).unwrap();
        first = second;
        protection.nonce = other.nonce;
        protection.tag = other.tag;
        assert_eq!(protection.open(&mut first), Err(CryptoError::MemoryProtection));
        assert_eq!(first, [0; KEY_LEN]);
    }
}
