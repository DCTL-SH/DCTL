//! The uploads a provider is still holding open, and what a sweep may do with
//! them.
//!
//! A multipart upload is three calls: start, one per part, finish. The parts
//! between the first and the last are **stored and billed the moment the provider
//! accepts them**, and until the finish arrives they belong to no object — so
//! `b2_list_file_names` does not return them, `ListObjectsV2` does not return
//! them, and nothing DCTL could ask about *objects* can see them. A 4 GiB upload
//! killed at the third part therefore leaves three hundred megabytes on somebody's
//! monthly invoice, invisible, forever.
//!
//! DCTL already cancels its own: every multipart path in this crate wraps its
//! parts in a `match` whose error arm cancels the upload before returning. What
//! that cannot cover is the process not being there to run the arm — a `SIGKILL`,
//! an OOM kill, a power cut — and those are exactly the interruptions a sweep
//! exists for. `dctl cleanup --class multipart` used to answer `unsupported`,
//! naming the missing capability, which was honest and reclaimed nothing.
//!
//! ## Why this is a second question and not part of the object listing
//!
//! The same argument [`staging`](crate::staging) makes, arriving from the other
//! side. An unfinished upload is not an object: it has no bytes anyone can read,
//! `head` on its key answers `NotFound`, and offering it in `list_page` would put
//! a phantom row in every `ls`, make `sync` believe a destination holds something
//! it does not, and give `copy` a key that cannot be fetched. It is a third class
//! of thing in a store, alongside committed objects and staging debris, and it
//! gets its own question.
//!
//! ## Why there is no default implementation
//!
//! For the reason [`Backend::store_identity`](crate::Backend::store_identity) and
//! [`Backend::list_staging`](crate::Backend::list_staging) have none: a provided
//! method answering "none" would hand every backend added later a silent false
//! all-clear, and a false all-clear about billed storage is the precise failure
//! this closes. A new provider cannot compile without deciding, and
//! [`IncompleteUploads::NotMultipart`] is how it says "nothing here is ever
//! uploaded in parts, and here is why".

use crate::model::ObjectKey;

/// One upload a provider started and never finished.
///
/// The handle is the provider's own — B2's `fileId`, S3's `uploadId` — and it is
/// what [`abort_incomplete_upload`](crate::Backend::abort_incomplete_upload)
/// cancels by. It is carried rather than reconstructed from the key because the
/// two providers disagree about whether a key even identifies an upload: S3
/// allows any number of concurrent multipart uploads to the same key, so on S3
/// the key alone names a set and the id names the member.
#[derive(Clone, Debug)]
pub struct IncompleteUpload {
    /// The key this upload was going to become.
    ///
    /// Reported so an operator sweeping a store can see *what* was being uploaded
    /// rather than only that something was, and so the sweep can scope itself to
    /// a prefix the way every other listing does.
    pub key: ObjectKey,
    /// The provider's handle for this upload.
    pub id: String,
    /// When the upload was started, in whole unix seconds, or [`None`] when the
    /// provider does not say.
    ///
    /// This is the field `--min-age` reads, and it is the difference between a
    /// sweep that can run and one that cannot: an upload three seconds old is
    /// either abandoned or in flight from another process, and nothing about it
    /// says which. A provider that will not date its uploads gets [`None`], and
    /// the sweep holds them rather than guessing — unknown is not old.
    pub started_unix: Option<i64>,
}

/// One page of the uploads a backend is still holding open.
///
/// A distinct type from [`Page`](crate::Page) for the reason the whole method
/// exists: an unfinished upload is not an object, and the moment the two share a
/// type is the moment one call site starts serving both.
#[derive(Clone, Debug, Default)]
pub struct IncompletePage {
    /// The uploads found.
    pub items: Vec<IncompleteUpload>,
    /// Pass back to continue; [`None`] means the enumeration is exhausted.
    pub next_cursor: Option<String>,
}

/// What a backend has to say when asked which uploads it left open.
///
/// Two answers, never a bare number, for the reason [`StagingListing`](crate::StagingListing)
/// has two:
///
/// * [`Page`](IncompleteUploads::Page) — this backend looked, and here is what is
///   there. An empty page means the provider really is holding nothing.
/// * [`NotMultipart`](IncompleteUploads::NotMultipart) — this backend has no
///   multipart protocol at all, so no upload of its can be left half-done.
///   Reported as the sentence it carries rather than as `removed: 0`, which is a
///   true number and an untrue answer.
#[derive(Clone, Debug)]
pub enum IncompleteUploads {
    /// One page of open uploads this backend enumerated.
    Page(IncompletePage),
    /// This backend does not upload in parts, and this is why.
    NotMultipart(&'static str),
}

/// Why a filesystem-shaped backend has no unfinished uploads, in the words
/// `cleanup` prints.
///
/// One sentence shared by `local:` and `sftp:` so an operator sweeping both on
/// the same night is not told two different things about one fact. Their
/// interrupted writes leave a **staging file**, which is a different class, is
/// enumerable, and is already swept.
pub const NOT_MULTIPART_REASON: &str = "this backend writes an object in a single stream to a staging file rather than in \
     parts, so an interrupted write leaves staging debris and never a half-finished \
     upload";
