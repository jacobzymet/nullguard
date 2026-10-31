//! Shared bounded protocol and credential policy; vault operations live only
//! in the separate headless executable. No GUI dependencies.
#![deny(unsafe_code)]

pub mod protocol;

/// Shared new-password policy, without exposing vault operations to the GUI.
pub fn validate_password(password: &str) -> anyhow::Result<()> {
    anyhow::ensure!(password.len() <= nullguard::cli::MAX_PASSWORD_BYTES, "The password is too long (maximum 4096 bytes).");
    anyhow::ensure!(password.chars().count() >= nullguard::cli::MIN_PASSWORD_CHARS, "Use at least 12 characters. A few random words work well.");
    Ok(())
}
