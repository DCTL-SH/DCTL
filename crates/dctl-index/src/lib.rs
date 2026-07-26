//! DCTL encrypted, metadata-private index.
//!
//! Maps logical file paths to the location + wrapped key + integrity data of each
//! stored object. Path keys are keyed-hashed and record values are AEAD-encrypted,
//! so the on-disk database reveals neither paths nor metadata at rest. The index is
//! a fast local cache — it is rebuildable by scanning object headers, so losing it
//! never means losing data (`PLAN.md` §13).
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod keying;

pub mod error;
pub mod index;
pub mod record;

pub use error::{IndexError, Result};
pub use index::Index;
pub use record::Record;
