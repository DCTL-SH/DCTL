//! DCTL storage layer — a provider-neutral `Backend` abstraction plus backends.
//!
//! `Backend` moves opaque encrypted objects to/from a provider with two
//! properties the higher layers depend on: **first-class random-access reads**
//! (for streaming huge media) and **verified writes** (never reports success
//! unless the stored bytes match the expected content hash). Encryption lives one
//! layer up (`dctl-crypto`); this layer is content-agnostic.
//!
//! [`retry`] wraps any of them. It is a decorator rather than five copies of a
//! schedule, because retrying used to exist for B2 alone while every other
//! provider's first failure was final — and every one of those failures still
//! reached the operator claiming that retries had been exhausted.
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// Inline unit tests may use unwrap/expect; library code may not.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod b2;
pub mod backend;
pub mod checksum;
pub mod deadline;
pub mod durable;
pub mod error;
pub mod guard;
pub mod incoming;
pub mod links;
pub mod local;
pub mod meter;
pub mod model;
pub mod modified;
pub mod multipart;
pub mod r2;
pub mod retry;
pub mod s3;
pub mod sftp;
pub mod specials;
pub mod staging;
mod streaming;
#[cfg(test)]
pub(crate) mod testing;
mod tls;

pub use backend::{Backend, UploadTicket};
pub use checksum::{ContentHash, HashAlgo, Hasher};
pub use deadline::{Deadlines, Exceeded, Expired, IdleWatch, Left, RunDeadline};
pub use error::{Result, StoreError};
pub use guard::{Guarded, StoreIdentity};
pub use incoming::{ObjectStream, ObjectWriter, object_stream};
pub use links::{
    LINK_POLICY_CHOICES, LinkNote, LinkPolicy, LinkReport, LinkVerdict, UnknownLinkPolicy,
};
pub use local::LocalFs;
pub use meter::{Meter, Unmetered, unmetered};
pub use model::{ByteRange, ObjectKey, ObjectMeta, Page, PutOutcome};
pub use modified::SourceModified;
pub use multipart::{IncompletePage, IncompleteUpload, IncompleteUploads};
pub use r2::R2Backend;
pub use retry::{RetryPolicy, Retrying};
pub use s3::{S3Backend, S3Config};
pub use sftp::base::Base as SftpBase;
pub use sftp::{SftpBackend, SftpConfig};
pub use specials::{SPECIAL_NOTE_SAMPLE, SpecialKind, SpecialNote, SpecialReport};
pub use staging::{
    STAGING_NAME_PREFIX, StagingListing, StagingPage, Want, is_staging_key, is_staging_name,
};
