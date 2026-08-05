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

impl Record {
    /// Whether nobody has ever measured this file.
    ///
    /// A rebuilt index is a list-only pass over the backend, so it maps every
    /// object without opening one, and those rows carry a zero size. That zero
    /// is *not* a claim that the file is empty — and the two are distinguishable
    /// only here, because `blake3::hash(b"")` is a full digest rather than
    /// nothing, so a genuinely empty file that was written through this tool
    /// always has a hash. A row with neither is one nobody has read.
    ///
    /// It matters because the alternative is silent: a caller that believed the
    /// zero would read no bytes and report success. The predicate lived in the
    /// CLI's vault source, which was the only reader that needed it; the index
    /// needs it too now that it keeps running totals, and one definition in the
    /// crate that owns the record is what keeps the two from drifting apart.
    #[must_use]
    pub fn unmeasured(&self) -> bool {
        self.size == 0 && self.content_hash.is_empty()
    }
}

/// What the whole index holds, maintained rather than counted.
///
/// `statfs` has to answer "how big is this filesystem" on every `df`, and the
/// only true answer for a mounted vault is the total under its root. That used
/// to be computed by listing the entire vault and summing it — the same
/// whole-index scan that made `readdir` quadratic. These three numbers are
/// carried forward by [`Index::put`](crate::Index::put) and
/// [`Index::delete`](crate::Index::delete) instead, so the answer costs one row
/// read at any vault size.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Totals {
    /// Files in the index.
    pub objects: u64,
    /// Plaintext bytes across every *measured* file.
    pub bytes: u64,
    /// Files whose size nobody has established — see [`Record::unmeasured`].
    ///
    /// Kept separately rather than folded into `bytes` because a total that
    /// silently omits some files is the same misreport a zero would be, only
    /// harder to notice. A caller with any unmeasured file has no true total,
    /// and [`Totals::measured_bytes`] is what says so.
    pub unmeasured: u64,
}

impl Totals {
    /// The byte total, or [`None`] when some file has never been measured.
    ///
    /// Absorbing, exactly as `dctl lsd`'s column is: one unmeasured object in a
    /// vault means the vault has no known size, and reporting the sum of the
    /// rest as though it were the whole would be a quiet lie.
    #[must_use]
    pub const fn measured_bytes(&self) -> Option<u64> {
        if self.unmeasured == 0 {
            Some(self.bytes)
        } else {
            None
        }
    }
}
