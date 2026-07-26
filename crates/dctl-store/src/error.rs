//! Typed storage errors. Transient vs permanent classification lives in the
//! higher retry layer; this enumerates what a backend can report.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum StoreError {
    /// The requested object does not exist.
    #[error("object not found: {0}")]
    NotFound(String),

    /// The stored bytes did not match the expected content hash — a verified
    /// write refused to (or a verified read refused to accept) commit corruption.
    #[error("checksum mismatch: expected {expected}, got {actual}")]
    ChecksumMismatch { expected: String, actual: String },

    /// The object key is malformed or unsafe (e.g. path traversal).
    #[error("invalid object key: {0}")]
    InvalidKey(String),

    /// A requested read range starts beyond the object's size.
    #[error("range offset out of bounds for object of size {size}")]
    RangeOutOfBounds { size: u64 },

    /// Underlying I/O failure.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Backend-specific failure (network, auth, quota, provider error).
    #[error("backend error: {0}")]
    Backend(String),
}

impl StoreError {
    /// Stable, FFI-safe numeric error code for this variant.
    ///
    /// Codes are **FROZEN** (`docs/ERROR_CODES.md`): a number is never
    /// renumbered or reused, and new variants only ever take new, unused
    /// numbers — a one-way door like `docs/FORMAT.md` §8. The `2xxx` range is
    /// reserved for the store layer. `0` is reserved for success/none and is
    /// never returned here.
    pub fn code(&self) -> u32 {
        match self {
            StoreError::NotFound(_) => 2001,
            StoreError::ChecksumMismatch { .. } => 2002,
            StoreError::InvalidKey(_) => 2003,
            StoreError::RangeOutOfBounds { .. } => 2004,
            StoreError::Io(_) => 2005,
            StoreError::Backend(_) => 2006,
        }
    }
}

pub type Result<T> = std::result::Result<T, StoreError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn representative_codes_are_frozen() {
        assert_eq!(StoreError::NotFound(String::new()).code(), 2001);
        assert_eq!(
            StoreError::ChecksumMismatch {
                expected: String::new(),
                actual: String::new(),
            }
            .code(),
            2002
        );
        assert_eq!(StoreError::Backend(String::new()).code(), 2006);
    }

    #[test]
    fn codes_are_unique_and_in_domain() {
        let codes = [
            StoreError::NotFound(String::new()).code(),
            StoreError::ChecksumMismatch {
                expected: String::new(),
                actual: String::new(),
            }
            .code(),
            StoreError::InvalidKey(String::new()).code(),
            StoreError::RangeOutOfBounds { size: 0 }.code(),
            StoreError::Io(std::io::Error::other("x")).code(),
            StoreError::Backend(String::new()).code(),
        ];
        // Every store code lives in the 2xxx domain and is never 0 (success).
        assert!(codes.iter().all(|c| (2001..3000).contains(c)));
        // Unique within the crate.
        let mut sorted = codes;
        sorted.sort_unstable();
        let unique = sorted.windows(2).all(|w| w[0] != w[1]);
        assert!(unique, "duplicate store error codes: {sorted:?}");
    }
}
