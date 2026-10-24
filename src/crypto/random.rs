//! Randomness, always from the operating system's CSPRNG.

use super::CryptoError;

/// Fill `buf` with random bytes from the OS (getrandom / BCryptGenRandom).
pub fn fill(buf: &mut [u8]) -> Result<(), CryptoError> {
    getrandom::fill(buf).map_err(|_| CryptoError::Rng)
}

/// A random byte array. Do not use for long-lived secrets (use
/// [`super::SecretKey`] instead): plain arrays are not zeroized.
pub fn array<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut out = [0u8; N];
    fill(&mut out)?;
    Ok(out)
}
