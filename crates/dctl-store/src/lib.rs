//! DCTL storage layer — a provider-neutral `Backend` abstraction plus backends.
//!
//! `Backend` moves opaque encrypted objects to/from a provider with two
//! properties the higher layers depend on: **first-class random-access reads**
//! (for streaming huge media) and **verified writes** (never reports success
//! unless the stored bytes match the expected content hash). Encryption lives one
//! layer up (`dctl-crypto`); this layer is content-agnostic.
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// Inline unit tests may use unwrap/expect; library code may not.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod b2;
pub mod backend;
pub mod checksum;
pub mod error;
pub mod local;
pub mod model;
pub mod r2;
pub mod s3;
mod tls;

pub use backend::Backend;
pub use checksum::{ContentHash, HashAlgo, Hasher};
pub use error::{Result, StoreError};
pub use local::LocalFs;
pub use model::{ByteRange, ObjectKey, ObjectMeta, Page, PutOutcome};
pub use r2::R2Backend;
pub use s3::{S3Backend, S3Config};
