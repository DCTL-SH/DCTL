//! Deterministic, privacy-preserving keying for index entries.
//!
//! The database key for a path is a *keyed* BLAKE3 hash of the path — equal paths
//! map to equal keys (point lookups work), but the on-disk database never reveals
//! the plaintext paths. Record values are AEAD-encrypted and bound (via AAD) to
//! their key, so the at-rest database leaks neither paths nor metadata.

/// 32-byte database key for `path` under the keying key.
pub(crate) fn index_key(keying_key: &[u8; 32], path: &str) -> [u8; 32] {
    *blake3::keyed_hash(keying_key, path.as_bytes()).as_bytes()
}
