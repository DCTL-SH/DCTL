//! DSF1 nonce derivation (§3). Chunk and metadata nonces occupy disjoint spaces
//! via a reserved domain byte (`byte[23]`), so both safely share the DEK.

use crate::constants::{NONCE_DOMAIN_BYTE, NONCE_DOMAIN_CHUNK, NONCE_DOMAIN_META, NONCE_LEN};

/// A fresh chunk-stream base nonce: CSPRNG-random with the chunk domain marker
/// (`0x00`) in `byte[23]`.
pub fn base_nonce() -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    crate::rng::fill(&mut n);
    n[NONCE_DOMAIN_BYTE] = NONCE_DOMAIN_CHUNK;
    n
}

/// A fresh metadata nonce: CSPRNG-random with the metadata domain marker (`0x01`)
/// in `byte[23]` — never collides with a chunk nonce.
pub fn metadata_nonce() -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    crate::rng::fill(&mut n);
    n[NONCE_DOMAIN_BYTE] = NONCE_DOMAIN_META;
    n
}

/// Chunk `index` nonce: `base_nonce` with `bytes[0..8] XOR= index` (LE). `byte[23]`
/// is untouched (stays `0x00`), keeping chunk nonces disjoint from the metadata nonce.
pub fn chunk_nonce(base_nonce: &[u8; NONCE_LEN], index: u64) -> [u8; NONCE_LEN] {
    let mut n = *base_nonce;
    let ib = index.to_le_bytes();
    for (a, b) in n.iter_mut().zip(ib.iter()) {
        *a ^= *b;
    }
    n
}

/// Plaintext length of chunk `index` given the total and chunk size.
pub fn chunk_plaintext_len(total: u64, chunk_size: u64, index: u64) -> u64 {
    let start = index.saturating_mul(chunk_size);
    total.saturating_sub(start).min(chunk_size)
}
