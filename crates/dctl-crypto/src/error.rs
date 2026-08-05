//! Error type for the crypto core. Kept small and non-leaky: no error message
//! ever contains key material, plaintext, or a distinguishing oracle beyond
//! "authentication failed".

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    /// Argon2id key derivation failed (bad params, etc.).
    #[error("kdf: {0}")]
    Kdf(String),

    /// KDF cost parameters are outside the mandatory ceilings (rejected before
    /// the KDF runs — an untrusted envelope must not force OOM/CPU exhaustion).
    #[error("kdf parameters out of range: {0}")]
    InvalidKdfParams(String),

    /// AEAD encrypt/decrypt failed: wrong key, tampered ciphertext, or wrong
    /// AAD/context. Deliberately does NOT distinguish these — that distinction
    /// would be a decryption oracle.
    #[error("aead authentication failed (wrong key, tampered, or wrong context)")]
    Aead,

    /// A container/header did not parse or failed a structural invariant.
    #[error("format: {0}")]
    Format(String),

    /// HKDF-SHA512 expansion failed (output length out of range).
    #[error("hkdf expand failed")]
    Hkdf,
}

impl CryptoError {
    /// Stable, FFI-safe numeric error code for this variant.
    ///
    /// Codes are **FROZEN**
    /// ([the error-code reference](https://doc.dctl.sh/reference/error-codes)):
    /// a number is never renumbered or reused, and new variants only ever take
    /// new, unused numbers — a one-way door like `crates/dctl-decode/FORMAT.md`
    /// §8. The `1xxx` range is reserved for the crypto layer. `0` is reserved
    /// for success/none and is never returned here.
    pub fn code(&self) -> u32 {
        match self {
            CryptoError::Kdf(_) => 1001,
            CryptoError::InvalidKdfParams(_) => 1002,
            CryptoError::Aead => 1003,
            CryptoError::Format(_) => 1004,
            CryptoError::Hkdf => 1005,
        }
    }
}

pub type Result<T> = std::result::Result<T, CryptoError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn representative_codes_are_frozen() {
        assert_eq!(CryptoError::Kdf(String::new()).code(), 1001);
        assert_eq!(CryptoError::Aead.code(), 1003);
        assert_eq!(CryptoError::Hkdf.code(), 1005);
    }

    #[test]
    fn codes_are_unique_and_in_domain() {
        let codes = [
            CryptoError::Kdf(String::new()).code(),
            CryptoError::InvalidKdfParams(String::new()).code(),
            CryptoError::Aead.code(),
            CryptoError::Format(String::new()).code(),
            CryptoError::Hkdf.code(),
        ];
        // Every crypto code lives in the 1xxx domain and is never 0 (success).
        assert!(codes.iter().all(|c| (1001..2000).contains(c)));
        // Unique within the crate.
        let mut sorted = codes;
        sorted.sort_unstable();
        let unique = sorted.windows(2).all(|w| w[0] != w[1]);
        assert!(unique, "duplicate crypto error codes: {sorted:?}");
    }
}
