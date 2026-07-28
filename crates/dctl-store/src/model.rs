//! Provider-neutral data model for the storage layer.

use crate::checksum::ContentHash;

/// Opaque object key (path) within a backend.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ObjectKey(String);

impl ObjectKey {
    #[must_use]
    pub fn new(key: impl Into<String>) -> Self {
        Self(key.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ObjectKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A byte range for random-access reads. `length == None` means "to end".
#[derive(Clone, Copy, Debug)]
pub struct ByteRange {
    pub offset: u64,
    pub length: Option<u64>,
}

impl ByteRange {
    #[must_use]
    pub fn new(offset: u64, length: Option<u64>) -> Self {
        Self { offset, length }
    }

    /// A range from `offset` to the end of the object.
    #[must_use]
    pub fn from_offset(offset: u64) -> Self {
        Self {
            offset,
            length: None,
        }
    }
}

/// Metadata about a stored object.
#[derive(Clone, Debug)]
pub struct ObjectMeta {
    pub key: ObjectKey,
    pub size: u64,
    pub modified_unix: Option<i64>,
}

/// One page of a listing — pagination keeps listings constant-memory even for
/// millions of objects. `next_cursor == None` means the listing is exhausted.
#[derive(Clone, Debug, Default)]
pub struct Page {
    pub items: Vec<ObjectMeta>,
    pub next_cursor: Option<String>,
    /// What the walk behind this page did about the symbolic links it met.
    ///
    /// Empty for every provider that has no such thing to report — an object
    /// store holds keys and bytes and nothing that could be a link — and
    /// populated by the two backends that walk a real filesystem, `local:` and
    /// `sftp:`. It travels *with the page* rather than being fetched separately
    /// because a listing that had to ask a second question to learn what it had
    /// skipped is a listing whose callers will forget to ask; the silence that
    /// followed is the defect [`crate::links`] exists to remove.
    pub links: crate::links::LinkReport,
    /// What the walk behind this page passed over that was neither a file, a
    /// directory nor a link — a fifo, a socket, a device node.
    ///
    /// Beside [`links`](Page::links) and for the identical reason, because it is
    /// the identical failure: a tree holding a named pipe listed as one file,
    /// `Errors: 0`, exit 0, with the pipe appearing nowhere in any output at any
    /// verbosity. Also empty for the object stores, which hold no such thing.
    /// See [`crate::specials`].
    pub specials: crate::specials::SpecialReport,
}

/// Result of a verified put: the backend-confirmed size and content hash.
#[derive(Clone, Debug)]
pub struct PutOutcome {
    pub size: u64,
    pub verified: ContentHash,
}
