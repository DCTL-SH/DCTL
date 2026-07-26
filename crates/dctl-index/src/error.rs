//! Typed index errors.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum IndexError {
    /// Underlying embedded-database failure.
    #[error("index database error: {0}")]
    Db(String),

    /// Record could not be (de)serialized.
    #[error("record (de)serialization failed")]
    Serialize,

    /// Record decryption/authentication failed (wrong key or tampered entry).
    #[error("record decryption/authentication failed")]
    Crypto,
}

pub type Result<T> = std::result::Result<T, IndexError>;
