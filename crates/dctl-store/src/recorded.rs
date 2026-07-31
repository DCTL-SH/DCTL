//! What a provider recorded about the bytes it stored, and what it is worth.
//!
//! This is the missing half of `dctl verify` on a **plain** remote, and the
//! defect it closes is the sharpest kind: silent, and in the direction that
//! loses data. `verify` re-read every byte of a plain object, found that every
//! byte came back, and printed `ok` — over a store where a flipped byte and a
//! truncation both read back perfectly, because there was nothing on that side
//! to compare against. Measured on the shipped binary: a byte flipped in place
//! and a 4 KiB object truncated to 100 bytes on a plain `local:` and a plain
//! `sftp:` remote, `ok` in the table and **exit 0** on all four.
//!
//! ## Why a provider's checksum is enough, and why a re-read is not
//!
//! An object's bytes and a digest recorded when it was written live in
//! different places: B2 keeps `contentSha1` in its file metadata, and the bytes
//! sit on its storage. Rot moves one and not the other, so comparing a fresh
//! read against the recorded digest detects it — which is the whole mechanism,
//! and it is why the comparison must be against a value *recorded at write
//! time* rather than one computed now. Hashing what was just read and comparing
//! it against itself is the check that cannot fail.
//!
//! A filesystem records nothing of the sort. `local:` and `sftp:` hold bytes
//! and a length; a hash of a file on either is a hash of whatever the file says
//! today. That is a real and permanent difference between the backends, so it
//! is a value each one states rather than a default anybody can inherit.
//!
//! ## The two questions, asked separately
//!
//! [`ChecksumSupport`] is about the **backend** and is answered without a
//! request, because a report has to say what a run can prove *before* the run
//! spends an hour proving it. [`StoredChecksum`] is about **one object**,
//! because a backend that records digests can still hold an object it has none
//! for — a B2 large file carries `contentSha1: "none"`, and whether it carries
//! `large_file_sha1` in its `fileInfo` depends on the tool that uploaded it.
//!
//! Collapsing the two would force a caller to choose between announcing a
//! capability it might not have for the object in hand, and asking a question
//! per object before it can print its first line.

use crate::checksum::{ContentHash, HashAlgo};

/// What a backend records about every object it stores, asked of the backend
/// rather than of an object.
///
/// Deliberately not a `bool`: the algorithm is what a re-read has to be folded
/// through for the comparison to be possible at all, and a caller that had to
/// guess it would guess BLAKE3 — which no provider on this list records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChecksumSupport {
    /// The provider computes a digest of the bytes it accepted, keeps it in its
    /// own metadata, and will report it back later. `algo` is the algorithm a
    /// re-read must be folded through to be comparable with it.
    Recorded(HashAlgo),
    /// This backend records no digest of its own, and this is why.
    ///
    /// A sentence rather than a flag, because it is printed: an operator told
    /// that `verify` will not certify their remote is owed the reason in the
    /// same breath.
    None(&'static str),
}

impl ChecksumSupport {
    /// The algorithm a re-read must be folded through, when there is one to
    /// compare against.
    #[must_use]
    pub const fn algo(self) -> Option<HashAlgo> {
        match self {
            Self::Recorded(algo) => Some(algo),
            Self::None(_) => None,
        }
    }

    /// Whether comparing a re-read against this backend can detect a changed
    /// byte.
    ///
    /// The question a report has to answer before it prints `ok`.
    #[must_use]
    pub const fn detects_corruption(self) -> bool {
        matches!(self, Self::Recorded(_))
    }
}

/// What the provider recorded for **one** object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoredChecksum {
    /// The digest the provider is holding for these bytes, in the algorithm
    /// [`ChecksumSupport::Recorded`] named.
    Recorded(ContentHash),
    /// The object is there and the provider has no digest for it, and this is
    /// why.
    ///
    /// An owned `String` rather than a `&'static str`, because the reason names
    /// the object's own circumstances — which upload path produced it, what its
    /// metadata does and does not carry — and a fixed sentence could only say
    /// the general case.
    ///
    /// Never an answer to "the object is not there": that is
    /// [`crate::StoreError::NotFound`], and folding the two together is how a
    /// missing object gets reported as an unverifiable one and sends an
    /// operator to the wrong place.
    Absent(String),
}

/// Why a filesystem-shaped backend records nothing, in the words the report
/// prints.
///
/// One sentence shared by `local:` and `sftp:`, so an operator verifying a
/// local mirror and an SFTP mirror on the same night is not told two different
/// things about one fact. It states the *cause* — a filesystem stores bytes and
/// a length, and nothing that survives a change to the bytes — because the fix
/// an operator can act on follows from the cause and not from the symptom.
pub const NO_RECORDED_CHECKSUM_FILESYSTEM: &str = "a filesystem stores bytes and a length and no digest of either, so there is nothing \
     recorded here that a re-read could disagree with";

/// Why S3 and R2 have nothing this build can compare against, in the words the
/// report prints.
///
/// Not a protocol limitation and stated as what it is: S3 records a checksum
/// for objects written with one, and DCTL's write path sends none. The ETag it
/// mints instead is the body's MD5 **only** for an object stored in a single
/// request; for a multipart object it is a digest of digests with a part count
/// appended, which no re-read can reproduce without knowing the part boundaries
/// the writer chose. Comparing against it would therefore pass on small objects
/// and fail on large ones, for reasons that have nothing to do with the data.
///
/// Closing it is a change to the **write** side — send `x-amz-checksum-*` on
/// every PUT and every part, then read it back with `x-amz-checksum-mode` —
/// which is a bigger piece of work than reading a value that is already there,
/// and one that cannot be proved against a live account here. Until it is done
/// this sentence is the honest answer and `verify` refuses rather than
/// approximates.
pub const NO_COMPARABLE_CHECKSUM_S3: &str = "this build sends no checksum of its own when it writes here, and the ETag the \
     provider mints instead is a digest of the body only for an object stored in one \
     request — so there is nothing recorded that a re-read can be compared against";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_recorded_digest_can_detect_a_changed_byte() {
        // The distinction the type exists for, and the defect it closes: a plain
        // store returning altered bytes reads back perfectly.
        assert!(ChecksumSupport::Recorded(HashAlgo::Sha1).detects_corruption());
        assert!(!ChecksumSupport::None(NO_RECORDED_CHECKSUM_FILESYSTEM).detects_corruption());
    }

    #[test]
    fn the_algorithm_travels_with_the_capability() {
        // A caller that had to guess would guess BLAKE3, which no provider here
        // records — so the comparison would fail on every intact object.
        assert_eq!(
            ChecksumSupport::Recorded(HashAlgo::Sha1).algo(),
            Some(HashAlgo::Sha1)
        );
        assert_eq!(ChecksumSupport::None("none here").algo(), None);
    }

    #[test]
    fn the_filesystem_reason_names_the_cause_rather_than_the_symptom() {
        assert!(NO_RECORDED_CHECKSUM_FILESYSTEM.contains("digest"));
        assert!(!NO_RECORDED_CHECKSUM_FILESYSTEM.is_empty());
    }
}
