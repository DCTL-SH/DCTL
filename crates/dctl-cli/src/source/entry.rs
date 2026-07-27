//! One readable object, described the same way whatever produced it.
//!
//! A sealed vault answers from its encrypted index and knows the *plaintext*
//! size and the plaintext BLAKE3 of every file it holds. A plain object store
//! answers from a provider listing and knows only what the provider volunteered:
//! a key, a byte count and — usually — a modification time. Those two are
//! genuinely different amounts of knowledge, and the whole value of this type is
//! that it says so instead of papering over the difference.
//!
//! ## Why the hash is an `Option` and not an empty `Vec`
//!
//! "No hash was recorded" and "the hash is zero bytes long" are the same value
//! if the field is a `Vec`, and a caller that renders `""` into a checksum column
//! has just told an operator that the object hashes to nothing. `dctl hashsum`
//! and `dctl lsjson` both have to distinguish *unknown* from *known*, because the
//! honest output for unknown is to omit the field entirely rather than to invent
//! a value for it (`PLAN.md` §6).
//!
//! The index itself can hold an empty hash: [`Vault::get_file`] warms a record
//! from the authoritative name record on a cross-device read and has no
//! plaintext hash to put in it until the object is actually read. That record is
//! real, and its hash is genuinely unknown, so the conversion in
//! [`super::vault`] maps empty to [`None`] rather than passing the emptiness on.
//!
//! ## Why the fields are public
//!
//! This is a data carrier between two layers, in the same spirit as
//! [`dctl_index::Record`] and [`dctl_store::ObjectMeta`], both of which are plain
//! public structs. Accessors would buy encapsulation over four values that have
//! no invariant between them, and the layers above — the listing family's own
//! [`Entry`](crate::commands::listing::Entry), which *does* enforce invariants
//! about roots and relative paths — build their richer view by consuming this
//! one, field by field.
//!
//! [`Vault::get_file`]: dctl_core::Vault::get_file

/// One object a source can enumerate, stat or read.
///
/// The path is always a **logical path**: `/`-separated, NFC, relative to the
/// source's root and never carrying a leading separator. Both implementations
/// produce it that way — the vault because that is what its index stores, the
/// plain store because [`Backend::list_page`](dctl_store::Backend::list_page)
/// yields root-relative forward-slash keys — so a caller never has to ask which
/// kind of source a path came from before joining or comparing it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Logical path within the source.
    pub path: String,

    /// Size in bytes of what a [`read`](super::Source::read) would return, when
    /// the source recorded one.
    ///
    /// For a vault this is the **plaintext** length, which is smaller than the
    /// stored object: reporting the ciphertext length would make `dctl ls` and
    /// `dctl cat | wc -c` disagree about the same file.
    ///
    /// [`None`] rather than `0`, for exactly the reason the hash below is an
    /// [`Option`] rather than an empty `Vec`. "Nobody has measured this object"
    /// and "this object is zero bytes long" are the same value if the field is a
    /// `u64`, and the first of those is a real, reachable state: a vault index
    /// rebuilt by [`Vault::rebuild_index`](dctl_core::Vault::rebuild_index) is a
    /// list-only pass, so every row it writes carries no size until the file is
    /// next read. Rendering that absence as the number 0 told a capacity monitor
    /// that a forty-terabyte vault held nothing, and told `dctl scrub`'s audit
    /// trail that it had verified zero bytes — both of them stated as fact
    /// (`PLAN.md` §6).
    ///
    /// A plain object store always fills this in: the provider's listing carries
    /// a byte count for every key, so `None` there would be a bug rather than an
    /// honest unknown.
    pub size: Option<u64>,

    /// Last-modified time in unix seconds, when the source recorded one.
    ///
    /// Absent rather than defaulted. A filesystem that does not keep mtimes, or
    /// a vault record written before one was captured, must not be rendered as
    /// though the file were modified at the epoch — a `sync` comparing
    /// timestamps would then rewrite every file on every run.
    pub modified_unix: Option<i64>,

    /// BLAKE3 of the plaintext, when the source knows it.
    ///
    /// Only a vault does: it recorded the hash at write time, under the same
    /// verified-write contract that refused to commit unless the stored bytes
    /// matched. A plain object store knows the provider's checksum of whatever
    /// it happens to be holding, which is not the same claim, so this stays
    /// [`None`] there rather than being filled with a value that means something
    /// else.
    pub content_hash: Option<Vec<u8>>,
}

impl Entry {
    /// An entry with only what every source can always answer.
    ///
    /// The optional halves are added by the builders below, so a source that
    /// learns a modification time later — or never — does not have to spell out
    /// two `None`s at every construction site and cannot get their order wrong.
    #[must_use]
    pub fn new(path: impl Into<String>, size: u64) -> Self {
        Self {
            path: path.into(),
            size: Some(size),
            modified_unix: None,
            content_hash: None,
        }
    }

    /// An entry whose size nobody has ever measured.
    ///
    /// A separate constructor rather than `new(path, None)` so that the case has
    /// a name at every construction site. There is exactly one source of it —
    /// an index row written by a rebuild, which lists object names without
    /// reading their bodies — and a caller reaching for this should be able to
    /// find the reasoning from the call itself rather than from an argument that
    /// happens to be `None`. See [`super::vault::from_record`].
    #[must_use]
    pub fn unmeasured(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            size: None,
            modified_unix: None,
            content_hash: None,
        }
    }

    /// Attach a modification time, if there is one.
    ///
    /// Takes the [`Option`] rather than the value so a caller can pass the
    /// provider's answer straight through: every source this is built from
    /// already models "no mtime" as `None`, and unwrapping it here to re-wrap it
    /// there is where a `unwrap_or(0)` eventually gets written.
    #[must_use]
    pub const fn with_modified(mut self, modified_unix: Option<i64>) -> Self {
        self.modified_unix = modified_unix;
        self
    }

    /// Attach a plaintext content hash, treating an empty digest as unknown.
    ///
    /// The index stores `Vec<u8>` and legitimately holds an empty one for a
    /// record warmed from a name record that has not been read back yet. That is
    /// *unknown*, not *zero-length*, and collapsing the two here is what stops
    /// every consumer from having to remember the distinction.
    #[must_use]
    pub fn with_content_hash(mut self, digest: Vec<u8>) -> Self {
        self.content_hash = if digest.is_empty() {
            None
        } else {
            Some(digest)
        };
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_optional_halves_default_to_absent() {
        let entry = Entry::new("photos/a.jpg", 12);
        assert_eq!(entry.path, "photos/a.jpg");
        assert_eq!(entry.size, Some(12));
        assert_eq!(entry.modified_unix, None);
        assert_eq!(entry.content_hash, None);
    }

    #[test]
    fn an_unmeasured_entry_is_not_a_zero_byte_one() {
        // The distinction the whole field exists for: a rebuilt index row and a
        // genuinely empty file are two different facts, and a `u64` cannot hold
        // both.
        assert_eq!(Entry::unmeasured("a.txt").size, None);
        assert_eq!(Entry::new("empty.txt", 0).size, Some(0));
        assert_ne!(Entry::unmeasured("a.txt").size, Entry::new("a.txt", 0).size);
    }

    #[test]
    fn a_modification_time_passes_through_in_both_states() {
        assert_eq!(
            Entry::new("a", 0)
                .with_modified(Some(1_700_000_000))
                .modified_unix,
            Some(1_700_000_000)
        );
        assert_eq!(Entry::new("a", 0).with_modified(None).modified_unix, None);
    }

    #[test]
    fn an_empty_digest_is_unknown_rather_than_a_hash_of_nothing() {
        // The index really does hold empty hashes — a record warmed from the
        // authoritative name record has no plaintext hash yet. Rendering that as
        // a checksum would tell an operator the object hashes to nothing.
        assert_eq!(
            Entry::new("a", 0)
                .with_content_hash(Vec::new())
                .content_hash,
            None
        );
        assert_eq!(
            Entry::new("a", 0)
                .with_content_hash(vec![0xab, 0xcd])
                .content_hash,
            Some(vec![0xab, 0xcd])
        );
    }
}
