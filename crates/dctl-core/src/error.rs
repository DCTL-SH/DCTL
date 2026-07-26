//! Typed core errors, wrapping the layer errors beneath.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CoreError {
    /// Wrong password/factor, or the envelope is missing/corrupted.
    #[error("unlock failed: wrong password or corrupted envelope")]
    Unlock,

    /// No index record for the given logical path.
    #[error("not found in vault: {0}")]
    NotFound(String),

    /// A stored object failed its integrity check on read.
    #[error("integrity check failed: {0}")]
    Integrity(String),

    #[error(transparent)]
    Crypto(#[from] dctl_crypto::CryptoError),

    #[error(transparent)]
    Store(#[from] dctl_store::StoreError),

    #[error(transparent)]
    Index(#[from] dctl_index::IndexError),
}

pub type Result<T> = std::result::Result<T, CoreError>;
