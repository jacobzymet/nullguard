//! Password-based key derivation with Argon2id (RFC 9106).

use argon2::{Algorithm, Argon2, Block, Params, Version};
use zeroize::Zeroizing;
use std::sync::atomic::{AtomicU64, Ordering};

use super::{CryptoError, SecretKey};

/// Length of the per-slot random salt.
pub const SALT_LEN: usize = 32;

/// Operational approval for an untrusted header, checked at derivation time.
/// Raising these limits never lowers a vault's password-hashing cost.
#[derive(Clone, Copy, Debug)]
pub struct KdfLimits {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl KdfLimits {
    pub const STANDARD: Self = Self { memory_kib: Argon2Params::DEFAULT.memory_kib,
        iterations: Argon2Params::DEFAULT.iterations, parallelism: Argon2Params::DEFAULT.parallelism };
    /// Explicit opt-in for vaults exceeding the normal creation defaults.
    pub const FORMAT_MAX: Self = Self {
        memory_kib: Argon2Params::MAX_MEMORY_KIB,
        iterations: Argon2Params::MAX_ITERATIONS,
        parallelism: Argon2Params::MAX_PARALLELISM,
    };

    fn check(self, params: &Argon2Params) -> Result<(), CryptoError> {
        if params.memory_kib > self.memory_kib || params.iterations > self.iterations
            || params.parallelism > self.parallelism {
            return Err(CryptoError::ResourceLimit("password hashing exceeds approved limits; approve expensive unlocking only for a trusted vault"));
        }
        Ok(())
    }
}

// Cap simultaneous Argon2 allocations across library callers in this process.
static RESERVED_KIB: AtomicU64 = AtomicU64::new(0);
const TOTAL_KDF_KIB: u64 = 4 * 1024 * 1024;

struct Reservation<'a> { counter: &'a AtomicU64, kib: u64 }

impl<'a> Reservation<'a> {
    fn reserve(counter: &'a AtomicU64, limit: u64, kib: u32) -> Result<Self, CryptoError> {
        let kib = u64::from(kib);
        let mut used = counter.load(Ordering::Acquire);
        loop {
            let total = used.checked_add(kib).filter(|&n| n <= limit)
                .ok_or(CryptoError::ResourceLimit("too many simultaneous key derivations; wait for another unlock to finish"))?;
            match counter.compare_exchange_weak(used, total, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => break,
                Err(current) => used = current,
            }
        }
        Ok(Self { counter, kib })
    }
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) { self.counter.fetch_sub(self.kib, Ordering::AcqRel); }
}

/// Argon2id cost parameters, stored per key slot in the vault header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Argon2Params {
    /// Memory in KiB.
    pub memory_kib: u32,
    /// Number of passes over memory.
    pub iterations: u32,
    /// Lanes (computed in parallel).
    pub parallelism: u32,
}

impl Argon2Params {
    /// Defaults for new vaults: 1 GiB, 4 passes, 4 lanes.
    ///
    /// This is well above the RFC 9106 "second recommended option"
    /// (64 MiB, t=3) and OWASP's minimums, on purpose: unlocking a vault is
    /// rare, and each guess an attacker makes costs 1 GiB of memory-hard work.
    pub const DEFAULT: Self = Self { memory_kib: 1024 * 1024, iterations: 4, parallelism: 4 };

    /// For machines that can't spare 1 GiB (`--low-memory`): RFC 9106's
    /// recommended setting for memory-constrained environments, 64 MiB,
    /// 3 passes, 4 lanes.
    pub const LOW_MEMORY: Self = Self { memory_kib: 64 * 1024, iterations: 3, parallelism: 4 };

    /// Lowest memory cost `create` and `change-password` accept (64 MiB).
    pub const MIN_CREATE_MEMORY_KIB: u32 = 64 * 1024;
    /// Lowest pass count `create` and `change-password` accept.
    pub const MIN_CREATE_ITERATIONS: u32 = 2;

    /// Hard ceilings applied when *reading* a header, so a crafted vault
    /// cannot make us allocate unbounded memory or spin forever.
    pub const MAX_MEMORY_KIB: u32 = 4 * 1024 * 1024; // 4 GiB
    pub const MAX_ITERATIONS: u32 = 64;
    pub const MAX_PARALLELISM: u32 = 64;

    /// Check the parameters are within Argon2's and nullguard's limits.
    pub fn validate(&self) -> Result<(), CryptoError> {
        if self.parallelism == 0 || self.parallelism > Self::MAX_PARALLELISM {
            return Err(CryptoError::InvalidParams("argon2 parallelism out of range"));
        }
        if self.iterations == 0 || self.iterations > Self::MAX_ITERATIONS {
            return Err(CryptoError::InvalidParams("argon2 iterations out of range"));
        }
        if self.memory_kib < 8 * self.parallelism || self.memory_kib > Self::MAX_MEMORY_KIB {
            return Err(CryptoError::InvalidParams("argon2 memory out of range"));
        }
        Ok(())
    }

    /// Check the parameters are strong enough for a *new* key slot.
    pub fn validate_for_new_slot(&self) -> Result<(), CryptoError> {
        self.validate()?;
        if self.memory_kib < Self::MIN_CREATE_MEMORY_KIB {
            return Err(CryptoError::InvalidParams("argon2 memory must be at least 64 MiB"));
        }
        if self.iterations < Self::MIN_CREATE_ITERATIONS {
            return Err(CryptoError::InvalidParams("argon2 iterations must be at least 2"));
        }
        Ok(())
    }
}

/// Derive a 256-bit key-encryption key from a password.
pub fn derive_key(
    password: &[u8],
    salt: &[u8; SALT_LEN],
    params: &Argon2Params,
) -> Result<SecretKey, CryptoError> {
    params.validate()?;
    let _reservation = Reservation::reserve(&RESERVED_KIB, TOTAL_KDF_KIB, params.memory_kib)?;
    let p = Params::new(params.memory_kib, params.iterations, params.parallelism, Some(32))
        .map_err(|_| CryptoError::InvalidParams("argon2 rejected parameters"))?;
    // Provide the working memory ourselves: the crate frees its own buffer
    // without wiping it, and the final key can be recomputed from that
    // memory. Ours is zeroized on drop. Allocation failure is an error, not
    // an abort.
    let mut memory: Zeroizing<Vec<Block>> = Zeroizing::new(Vec::new());
    memory
        .try_reserve_exact(p.block_count())
        .map_err(|_| CryptoError::InvalidParams("not enough memory for the key derivation"))?;
    memory.resize(p.block_count(), Block::default());
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut out = SecretKey::zeroed();
    argon
        .hash_password_into_with_memory(password, salt, out.expose_mut(), memory.as_mut_slice())
        .map_err(|_| CryptoError::Kdf)?;
    Ok(out)
}

/// Derive under a caller-approved resource ceiling. Check before allocation
/// or hashing, including when the header changed since a UI preflight.
pub fn derive_key_with_limits(password: &[u8], salt: &[u8; SALT_LEN], params: &Argon2Params,
    limits: KdfLimits) -> Result<SecretKey, CryptoError> {
    params.validate()?;
    limits.check(params)?;
    derive_key(password, salt, params)
}

/// Canonical form of a password before key derivation: Unicode NFC,
/// encoded as UTF-8. The same password can arrive as different code points
/// (for example "é" as one precomposed character or as "e" plus a combining
/// accent, depending on OS and keyboard); normalizing makes it unlock
/// everywhere.
pub fn normalize_password(password: &str) -> Zeroizing<String> {
    use unicode_normalization::UnicodeNormalization;
    // Reserve generously so the buffer never reallocates (which would leave
    // an unwiped copy behind).
    let mut out = Zeroizing::new(String::with_capacity(password.len() * 3 + 16));
    out.extend(password.nfc());
    out
}

#[cfg(test)]
pub(crate) const TEST_PARAMS: Argon2Params = Argon2Params { memory_kib: 64, iterations: 1, parallelism: 1 };

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unapproved_cost_is_refused_before_allocation() {
        let params = Argon2Params { memory_kib: Argon2Params::MAX_MEMORY_KIB, iterations: 64, parallelism: 4 };
        assert!(matches!(derive_key_with_limits(b"test", &[0; SALT_LEN], &params, KdfLimits::STANDARD), Err(CryptoError::ResourceLimit(_))));
        let tiny_limits = KdfLimits { memory_kib: TEST_PARAMS.memory_kib, iterations: 1, parallelism: 1 };
        let a = derive_key_with_limits(b"test", &[0; SALT_LEN], &TEST_PARAMS, tiny_limits).unwrap();
        let b = derive_key(b"test", &[0; SALT_LEN], &TEST_PARAMS).unwrap();
        assert_eq!(a.expose(), b.expose());
    }

    #[test]
    fn aggregate_reservations_release_on_error_and_unwind() {
        let counter = AtomicU64::new(0);
        {
            let _first = Reservation::reserve(&counter, 8, 5).unwrap();
            assert!(Reservation::reserve(&counter, 8, 4).is_err());
            let result = std::panic::catch_unwind(|| {
                let _rest = Reservation::reserve(&counter, 8, 3).unwrap();
                panic!("derivation failed");
            });
            assert!(result.is_err());
            assert_eq!(counter.load(Ordering::Relaxed), 5);
        }
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn deterministic_and_salted() {
        let s1 = [1u8; SALT_LEN];
        let s2 = [2u8; SALT_LEN];
        let a = derive_key(b"hunter2hunter2", &s1, &TEST_PARAMS).unwrap();
        let b = derive_key(b"hunter2hunter2", &s1, &TEST_PARAMS).unwrap();
        let c = derive_key(b"hunter2hunter2", &s2, &TEST_PARAMS).unwrap();
        let d = derive_key(b"hunter3hunter3", &s1, &TEST_PARAMS).unwrap();
        assert_eq!(a.expose(), b.expose());
        assert_ne!(a.expose(), c.expose());
        assert_ne!(a.expose(), d.expose());
    }

    #[test]
    fn params_change_output() {
        let s = [3u8; SALT_LEN];
        let a = derive_key(b"pw", &s, &TEST_PARAMS).unwrap();
        let more = Argon2Params { iterations: 2, ..TEST_PARAMS };
        let b = derive_key(b"pw", &s, &more).unwrap();
        assert_ne!(a.expose(), b.expose());
    }

    /// RFC 9106 section 5.3 Argon2id test vector, to prove the crate is
    /// configured as genuine Argon2id v1.3.
    #[test]
    fn rfc9106_argon2id_vector() {
        let params = argon2::ParamsBuilder::new()
            .m_cost(32)
            .t_cost(3)
            .p_cost(4)
            .data(argon2::AssociatedData::new(&[4u8; 12]).unwrap())
            .output_len(32)
            .build()
            .unwrap();
        let argon = Argon2::new_with_secret(&[3u8; 8], Algorithm::Argon2id, Version::V0x13, params).unwrap();
        let mut out = [0u8; 32];
        argon.hash_password_into(&[1u8; 32], &[2u8; 16], &mut out).unwrap();
        assert_eq!(
            out,
            [
                0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c, 0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b, 0x53, 0xc9,
                0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e, 0xb5, 0x25, 0x20, 0xe9, 0x6b, 0x01, 0xe6, 0x59,
            ]
        );
    }

    #[test]
    fn hostile_params_are_rejected() {
        let bad = [
            Argon2Params { memory_kib: u32::MAX, ..TEST_PARAMS },
            Argon2Params { iterations: 0, ..TEST_PARAMS },
            Argon2Params { iterations: 10_000, ..TEST_PARAMS },
            Argon2Params { parallelism: 0, ..TEST_PARAMS },
            Argon2Params { memory_kib: 4, ..TEST_PARAMS },
        ];
        for p in bad {
            assert!(p.validate().is_err(), "{p:?} should be rejected");
            assert!(derive_key(b"x", &[0; SALT_LEN], &p).is_err());
        }
    }

    #[test]
    fn nfc_normalization_unifies_equivalent_passwords() {
        let composed = normalize_password("caf\u{e9} cr\u{e8}me br\u{fb}l\u{e9}e");
        let decomposed = normalize_password("cafe\u{301} cre\u{300}me bru\u{302}le\u{301}e");
        assert_ne!(
            "caf\u{e9} cr\u{e8}me br\u{fb}l\u{e9}e".as_bytes(),
            "cafe\u{301} cre\u{300}me bru\u{302}le\u{301}e".as_bytes()
        );
        assert_eq!(composed.as_str(), decomposed.as_str());
        assert_eq!(normalize_password("plain ascii").as_str(), "plain ascii");
        let s = [0u8; SALT_LEN];
        let a = derive_key(composed.as_bytes(), &s, &TEST_PARAMS).unwrap();
        let b = derive_key(decomposed.as_bytes(), &s, &TEST_PARAMS).unwrap();
        assert_eq!(a.expose(), b.expose());
    }

    #[test]
    fn weak_params_rejected_for_new_slots() {
        assert!(TEST_PARAMS.validate().is_ok());
        assert!(TEST_PARAMS.validate_for_new_slot().is_err());
        assert!(Argon2Params::DEFAULT.validate_for_new_slot().is_ok());
        assert!(Argon2Params::LOW_MEMORY.validate_for_new_slot().is_ok());
    }
}
