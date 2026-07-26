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

pub type Result<T> = std::result::Result<T, StoreError>;
