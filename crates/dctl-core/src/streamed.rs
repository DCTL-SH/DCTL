//! What a constant-memory transfer establishes about the bytes it moved.
//!
//! Every streaming path in this crate already folds a BLAKE3 over the plaintext
//! as it passes — the read path to check it against the object's own recorded
//! hash, the write path to put it in the index — so the digest exists at the
//! moment the last byte goes by and costs nothing to return.
//!
//! Returning it is what keeps the layer above honest. The transfer engine has to
//! put a plaintext digest in every audit record, and while the whole file was
//! resident it took that digest from the buffer it already held. Once nothing
//! holds the file, the only other way to answer is to read it a second time —
//! which doubles the I/O on a 10 GB object and, worse, hashes whatever the
//! source says *now* rather than what was actually stored. A source that changed
//! between the two passes would be recorded under a digest of bytes that were
//! never written, and the audit log would attest to a file that never existed.

/// The outcome of moving one object in bounded windows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Streamed {
    /// Plaintext bytes that passed through, counted as they went.
    pub bytes: u64,
    /// BLAKE3 of the whole plaintext, folded in the same single pass.
    ///
    /// On the read path this is the value that was *checked* against the
    /// object's own DEK-authenticated `content_blake3`, so a caller receiving it
    /// is receiving a digest that has already been agreed with the writer rather
    /// than merely computed here.
    pub plaintext_hash: [u8; 32],
}

impl Streamed {
    /// The plaintext digest as lowercase hex — the spelling an audit record and
    /// a `--checksum` comparison both speak.
    #[must_use]
    pub fn hash_hex(&self) -> String {
        hex::encode(self.plaintext_hash)
    }
}
