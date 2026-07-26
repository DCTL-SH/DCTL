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

/// A streaming content hasher: feed bytes incrementally with [`update`](Hasher::update),
/// then [`finalize`](Hasher::finalize) to a [`ContentHash`].
///
/// This is what lets a **verified write hash a file that never fully resides in RAM** —
/// the constant-memory streaming path folds each buffer through here, so peak memory is
/// `O(buffer)` rather than `O(file_size)`. `blake3::Hasher` carries a large internal state,
/// so it is boxed to keep the enum's variants close in size.
pub enum Hasher {
    Blake3(Box<blake3::Hasher>),
    Sha1(Sha1),
    Sha256(Sha256),
}

impl Hasher {
    /// A fresh streaming hasher for `algo`.
    #[must_use]
    pub fn new(algo: HashAlgo) -> Self {
        match algo {
            HashAlgo::Blake3 => Self::Blake3(Box::new(blake3::Hasher::new())),
            HashAlgo::Sha1 => Self::Sha1(Sha1::default()),
            HashAlgo::Sha256 => Self::Sha256(Sha256::default()),
        }
    }

    /// Fold `data` into the running digest.
    pub fn update(&mut self, data: &[u8]) {
        match self {
            Self::Blake3(h) => {
                h.update(data);
            }
            Self::Sha1(h) => h.update(data),
            Self::Sha256(h) => h.update(data),
        }
    }

    /// Consume the hasher and return the final [`ContentHash`].
    #[must_use]
    pub fn finalize(self) -> ContentHash {
        match self {
            Self::Blake3(h) => ContentHash {
                algo: HashAlgo::Blake3,
                bytes: h.finalize().as_bytes().to_vec(),
            },
            Self::Sha1(h) => ContentHash {
                algo: HashAlgo::Sha1,
                bytes: h.finalize().to_vec(),
            },
            Self::Sha256(h) => ContentHash {
                algo: HashAlgo::Sha256,
                bytes: h.finalize().to_vec(),
            },
        }
    }
}
