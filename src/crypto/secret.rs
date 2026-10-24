//! Containers for secret key material.
//!
//! Every long-lived secret lives in a heap allocation that is
//! (best effort) locked into RAM so it is never written to swap, and is
//! overwritten with zeros when dropped.

use std::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{CryptoError, random};

/// Length in bytes of every symmetric key nullguard uses.
pub const KEY_LEN: usize = 32;

/// Ask the OS to keep the pages holding `len` bytes at `ptr` in RAM.
///
/// Failure is not fatal (for example when `RLIMIT_MEMLOCK` is exhausted):
/// the secret is still zeroized on drop. The lock is intentionally never
/// released: pages are shared between small allocations, so unlocking when
/// one secret drops could unlock another secret that is still alive. The
/// kernel drops the lock when the process exits or the memory is unmapped.
pub(crate) fn lock_in_ram<T>(ptr: *const T, len: usize) {
    match region::lock(ptr, len) {
        Ok(guard) => std::mem::forget(guard),
        Err(_) => LOCK_FAILED.store(true, std::sync::atomic::Ordering::Relaxed),
    }
}

static LOCK_FAILED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Whether locking any secret into RAM has failed in this process, meaning
/// a key could end up in swap. Callers should tell the user.
pub fn memory_lock_failed() -> bool {
    LOCK_FAILED.load(std::sync::atomic::Ordering::Relaxed)
}

/// A 256-bit secret key. Locked in RAM where possible, zeroized on drop,
/// never printed by `Debug`.
pub struct SecretKey {
    bytes: Box<[u8; KEY_LEN]>,
}

impl SecretKey {
    /// An all-zero key, to be filled in place (for example by a KDF).
    pub(crate) fn zeroed() -> Self {
        let bytes = Box::new([0u8; KEY_LEN]);
        lock_in_ram(bytes.as_ptr(), KEY_LEN);
        Self { bytes }
    }

    /// A fresh key from the operating system's CSPRNG.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut key = Self::zeroed();
        random::fill(key.bytes.as_mut_slice())?;
        Ok(key)
    }

    /// Copy `bytes` into a new key and wipe the source.
    pub fn from_bytes(bytes: &mut [u8; KEY_LEN]) -> Self {
        let mut key = Self::zeroed();
        key.bytes.copy_from_slice(bytes);
        bytes.zeroize();
        key
    }

    /// Borrow the raw key bytes. Keep the borrow as short as possible.
    pub fn expose(&self) -> &[u8; KEY_LEN] {
        &self.bytes
    }

    pub(crate) fn expose_mut(&mut self) -> &mut [u8; KEY_LEN] {
        &mut self.bytes
    }

    /// Duplicate the key into a second locked, zeroizing allocation.
    pub fn duplicate(&self) -> Self {
        let mut key = Self::zeroed();
        key.bytes.copy_from_slice(self.bytes.as_slice());
        key
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl ZeroizeOnDrop for SecretKey {}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(<redacted>)")
    }
}

/// Derive an independent subkey from `key` with HKDF-SHA256.
///
/// `key` must already be uniformly random (it is a master key or KEK), so it
/// is used directly as the HKDF pseudo-random key (RFC 5869 section 3.3).
/// `info` gives domain separation: distinct labels give unrelated keys.
pub fn derive_subkey(key: &SecretKey, info: &[u8]) -> Result<SecretKey, CryptoError> {
    let hk = hkdf::Hkdf::<sha2::Sha256>::from_prk(key.expose())
        .map_err(|_| CryptoError::Kdf)?;
    let mut out = SecretKey::zeroed();
    hk.expand(info, out.expose_mut()).map_err(|_| CryptoError::Kdf)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_gives_distinct_keys() {
        let a = SecretKey::generate().unwrap();
        let b = SecretKey::generate().unwrap();
        assert_ne!(a.expose(), b.expose());
        assert_ne!(a.expose(), &[0u8; KEY_LEN]);
    }

    #[test]
    fn from_bytes_wipes_source() {
        let mut raw = [7u8; KEY_LEN];
        let key = SecretKey::from_bytes(&mut raw);
        assert_eq!(raw, [0u8; KEY_LEN]);
        assert_eq!(key.expose(), &[7u8; KEY_LEN]);
    }

    #[test]
    fn debug_is_redacted() {
        let key = SecretKey::from_bytes(&mut [0xAB; KEY_LEN]);
        let shown = format!("{key:?}");
        assert!(!shown.to_lowercase().contains("ab"));
    }

    #[test]
    fn subkeys_are_domain_separated_and_deterministic() {
        let master = SecretKey::generate().unwrap();
        let a1 = derive_subkey(&master, b"label-a").unwrap();
        let a2 = derive_subkey(&master, b"label-a").unwrap();
        let b = derive_subkey(&master, b"label-b").unwrap();
        assert_eq!(a1.expose(), a2.expose());
        assert_ne!(a1.expose(), b.expose());
        assert_ne!(a1.expose(), master.expose());
    }
}
