//! The index record — everything needed to locate and decrypt one stored file.

use serde::{Deserialize, Serialize};

/// One index entry. Every field is also recoverable by scanning object headers,
/// so a lost index never means lost data.
///
/// The DSF1 object is self-describing — it embeds its own root-wrapped DEK — so the
/// record no longer carries a separately-wrapped DEK; `object_key` + the vault root
/// are all that a read needs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// Logical (plaintext) path of the file within the vault.
    pub path: String,
    /// Opaque object key in the storage backend.
    pub object_key: String,
    /// Plaintext size in bytes.
    pub size: u64,
    /// Last-modified time (unix seconds), if known.
    pub modified_unix: Option<i64>,
    /// Content hash of the plaintext (integrity manifest).
    pub content_hash: Vec<u8>,
}
