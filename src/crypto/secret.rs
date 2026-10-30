//! Containers for secret key material.
//!
//! Working keys use zeroizing allocations with best-effort page locking.
//! Retained vault keys stay encrypted between operations. Unix wrapping
//! keys occupy separate, strictly locked pages with guarded access.

use std::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{CryptoError, random};
use super::memory::KeyProtection;

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

/// A plaintext 256-bit key for a cryptographic operation. Locked in RAM
/// where possible, zeroized on drop, never printed by `Debug`. Retained
/// vault master/data keys use an internal encrypted container instead.
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

/// A retained vault encryption key, encrypted between operations. Windows
/// uses OS memory encryption; Linux/macOS wrap it under a key in a locked,
/// inaccessible page. Decryption always uses a separate zeroizing buffer.
pub(crate) struct ProtectedKey {
    key: SecretKey,
    protection: KeyProtection,
    #[cfg(test)]
    failure_after: std::sync::Mutex<Option<usize>>,
}

impl ProtectedKey {
    pub(crate) fn new(key: SecretKey) -> Result<Self, CryptoError> {
        Self::new_with(key, KeyProtection::seal)
    }

    fn new_with(mut key: SecretKey, protect: impl FnOnce(&mut [u8; KEY_LEN]) -> Result<KeyProtection, CryptoError>) -> Result<Self, CryptoError> {
        // If protection fails, SecretKey's Drop wipes the input allocation.
        let protection = protect(key.expose_mut())?;
        Ok(Self {
            key, protection,
            #[cfg(test)]
            failure_after: std::sync::Mutex::new(None),
        })
    }

    pub(crate) fn with_key<T>(&self, use_key: impl FnOnce(&SecretKey) -> T) -> Result<T, CryptoError> {
        #[cfg(test)]
        {
            // One transient, instance-local failure lets recovery tests
            // prove they stop even when a subsequent retry could succeed.
            let mut failure = self.failure_after.lock().unwrap();
            match *failure {
                Some(0) => { *failure = None; return Err(CryptoError::MemoryProtection); }
                Some(remaining) => *failure = Some(remaining - 1),
                None => {}
            }
        }
        self.with_decrypted_key(|bytes| self.protection.open(bytes), use_key)
    }

    #[cfg(test)]
    pub(crate) fn fail_once_after(&mut self, successful_uses: usize) {
        *self.failure_after.get_mut().unwrap() = Some(successful_uses);
    }

    fn with_decrypted_key<T>(
        &self,
        decrypt: impl FnOnce(&mut [u8; KEY_LEN]) -> Result<(), CryptoError>,
        use_key: impl FnOnce(&SecretKey) -> T,
    ) -> Result<T, CryptoError> {
        let mut plain = SecretKey::zeroed();
        plain.expose_mut().copy_from_slice(self.key.expose());
        decrypt(plain.expose_mut())?;
        // `plain` is wiped on normal return, error, and panic. The retained
        // allocation is never decrypted, so concurrent readers are safe.
        Ok(use_key(&plain))
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
    fn retained_key_recovers_without_decrypting_its_storage() {
        let key = ProtectedKey::new(SecretKey::from_bytes(&mut [0xA7; KEY_LEN])).unwrap();
        let stored = zeroize::Zeroizing::new(*key.key.expose());
        assert_ne!(*stored, [0xA7; KEY_LEN], "retained key must be encrypted");
        for _ in 0..4 {
            key.with_key(|plain| assert_eq!(plain.expose(), &[0xA7; KEY_LEN])).unwrap();
            assert_eq!(key.key.expose(), &*stored);
        }
    }

    #[test]
    fn retained_key_supports_concurrent_use() {
        let key = ProtectedKey::new(SecretKey::from_bytes(&mut [0x36; KEY_LEN])).unwrap();
        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| key.with_key(|plain| assert_eq!(plain.expose(), &[0x36; KEY_LEN])).unwrap());
            }
        });
    }

    #[test]
    fn failed_protection_never_produces_a_retained_key() {
        let key = SecretKey::from_bytes(&mut [0x42; KEY_LEN]);
        let result = ProtectedKey::new_with(key, |bytes| {
            bytes.fill(0xFF); // the OS may modify a buffer before failing
            Err(CryptoError::MemoryProtection)
        });
        assert!(matches!(result, Err(CryptoError::MemoryProtection)));
    }

    #[test]
    fn failed_unprotection_never_calls_the_key_user_or_changes_storage() {
        let key = ProtectedKey::new(SecretKey::from_bytes(&mut [0x19; KEY_LEN])).unwrap();
        let stored = zeroize::Zeroizing::new(*key.key.expose());
        let called = std::cell::Cell::new(false);
        let result = key.with_decrypted_key(
            |bytes| { bytes.fill(0xFF); Err(CryptoError::MemoryProtection) },
            |_| called.set(true),
        );
        assert_eq!(result, Err(CryptoError::MemoryProtection));
        assert!(!called.get());
        assert_eq!(key.key.expose(), &*stored);
        key.with_key(|plain| assert_eq!(plain.expose(), &[0x19; KEY_LEN])).unwrap();
    }

    #[test]
    fn panicking_key_user_leaves_the_retained_key_usable() {
        let key = ProtectedKey::new(SecretKey::from_bytes(&mut [0x63; KEY_LEN])).unwrap();
        let result = std::panic::catch_unwind(|| key.with_key(|_| panic!("simulated operation panic")));
        assert!(result.is_err());
        key.with_key(|plain| assert_eq!(plain.expose(), &[0x63; KEY_LEN])).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn same_process_key_child() {
        use std::io::Read;
        if std::env::var_os("NULLGUARD_TEST_RAM_KEY_CHILD").is_none() {
            return;
        }
        let mut key = SecretKey::zeroed();
        std::io::stdin().read_exact(key.expose_mut()).unwrap();
        let result = crate::platform::win::unprotect_key_memory(key.expose_mut());
        // The API need not authenticate ciphertext: failure or a different
        // output both show that another process cannot recover this key.
        assert!(result.is_err() || key.expose() != &[0xA7; KEY_LEN], "another process recovered the key");
    }

    #[cfg(windows)]
    #[test]
    fn same_process_key_cannot_be_recovered_in_another_process() {
        use std::io::Write;
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};
        let key = ProtectedKey::new(SecretKey::from_bytes(&mut [0xA7; KEY_LEN])).unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "crypto::secret::tests::same_process_key_child"])
            .env("NULLGUARD_TEST_RAM_KEY_CHILD", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn().unwrap();
        child.stdin.take().unwrap().write_all(key.key.expose()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("memory-protection child did not exit");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

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
