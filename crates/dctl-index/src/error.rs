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

impl IndexError {
    /// Stable, FFI-safe numeric error code for this variant.
    ///
    /// Codes are **FROZEN** (`docs/ERROR_CODES.md`): a number is never
    /// renumbered or reused, and new variants only ever take new, unused
    /// numbers — a one-way door like `docs/FORMAT.md` §8. The `3xxx` range is
    /// reserved for the index layer. `0` is reserved for success/none and is
    /// never returned here.
    pub fn code(&self) -> u32 {
        match self {
            IndexError::Db(_) => 3001,
            IndexError::Serialize => 3002,
            IndexError::Crypto => 3003,
        }
    }
}

/// Map any `rusqlite` failure onto the crate's opaque database-error variant so
/// callers never see the backend type and lib code can use `?` (no `unwrap`).
impl From<rusqlite::Error> for IndexError {
    fn from(e: rusqlite::Error) -> Self {
        IndexError::Db(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, IndexError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn representative_codes_are_frozen() {
        assert_eq!(IndexError::Db(String::new()).code(), 3001);
        assert_eq!(IndexError::Serialize.code(), 3002);
        assert_eq!(IndexError::Crypto.code(), 3003);
    }

    #[test]
    fn codes_are_unique_and_in_domain() {
        let codes = [
            IndexError::Db(String::new()).code(),
            IndexError::Serialize.code(),
            IndexError::Crypto.code(),
        ];
        // Every index code lives in the 3xxx domain and is never 0 (success).
        assert!(codes.iter().all(|c| (3001..4000).contains(c)));
        // Unique within the crate.
        let mut sorted = codes;
        sorted.sort_unstable();
        let unique = sorted.windows(2).all(|w| w[0] != w[1]);
        assert!(unique, "duplicate index error codes: {sorted:?}");
    }
}
