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

pub type Result<T> = std::result::Result<T, CryptoError>;
