//! Typed index errors.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum IndexError {
    /// Underlying embedded-database failure.
    ///
    /// For a SQLCipher-encrypted store this also covers an open/read with the
    /// **wrong** whole-database key: SQLite reports the file as "not a database"
    /// (`SQLITE_NOTADB`) because the page header cannot be decrypted.
    #[error("index database error: {0}")]
    Db(String),

    /// Record could not be (de)serialized.
    #[error("record (de)serialization failed")]
    Serialize,

    /// Record decryption/authentication failed (wrong key or tampered entry).
    #[error("record decryption/authentication failed")]
    Crypto,
}

/// Map any `rusqlite` failure onto the crate's opaque database-error variant so
/// callers never see the backend type and lib code can use `?` (no `unwrap`).
impl From<rusqlite::Error> for IndexError {
    fn from(e: rusqlite::Error) -> Self {
        IndexError::Db(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, IndexError>;
