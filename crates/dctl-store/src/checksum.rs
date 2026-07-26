//! Content hashing for verified writes and integrity checks.
//!
//! BLAKE3 is DCTL's primary content hash. SHA-1 and SHA-256 are provided because
//! providers verify uploads with them (Backblaze B2 uses SHA-1; S3 uses SHA-256/
//! CRC32C), so the storage layer can present the checksum a given backend expects.

use sha1::{Digest as _, Sha1};
use sha2::{Digest as _, Sha256};

/// Supported content-hash algorithms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlgo {
    Blake3,
    Sha1,
    Sha256,
}

/// A content hash: an algorithm tag plus the raw digest bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContentHash {
    pub algo: HashAlgo,
    pub bytes: Vec<u8>,
}

impl ContentHash {
    /// Compute the hash of `data` under `algo`.
    #[must_use]
    pub fn compute(algo: HashAlgo, data: &[u8]) -> Self {
        let bytes = match algo {
            HashAlgo::Blake3 => blake3::hash(data).as_bytes().to_vec(),
            HashAlgo::Sha1 => Sha1::digest(data).to_vec(),
            HashAlgo::Sha256 => Sha256::digest(data).to_vec(),
        };
        Self { algo, bytes }
    }

    #[must_use]
    pub fn blake3(data: &[u8]) -> Self {
        Self::compute(HashAlgo::Blake3, data)
    }

    #[must_use]
    pub fn sha1(data: &[u8]) -> Self {
        Self::compute(HashAlgo::Sha1, data)
    }

    #[must_use]
    pub fn sha256(data: &[u8]) -> Self {
        Self::compute(HashAlgo::Sha256, data)
    }

    /// Lowercase hex encoding of the digest.
    #[must_use]
    pub fn hex(&self) -> String {
        hex::encode(&self.bytes)
    }

    /// True iff same algorithm and same digest bytes.
    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        self.algo == other.algo && self.bytes == other.bytes
    }
}
