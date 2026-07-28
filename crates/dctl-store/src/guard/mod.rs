//! Refusing to write into a store that is no longer the one the run has been
//! using — on every backend, not only `local:`.
//!
//! [`identity`] is what a container *is* as far as its provider can tell, and
//! how much that answer is worth; [`backend`] is the decorator that records it
//! once per run and refuses a write when it has changed. The defect both exist
//! for, and the evidence that it reaches SFTP as well as `local:`, is in
//! [`identity`]'s own documentation.
//!
//! What each provider can actually answer:
//!
//! | Backend | Identity | Strength |
//! |---|---|---|
//! | `local:` | `(st_dev, st_ino)` of the root | distinguishing |
//! | `b2:` | the bucket id, re-resolved by name | distinguishing |
//! | `sftp:` | the base directory is still a directory | existence-only |
//! | `s3:` / `r2:` | `HEAD` on the bucket | existence-only |
//!
//! The two existence-only rows are a limit of their protocols and not of this
//! module: SFTP version 3's `SSH_FXP_STAT` carries no inode, and S3 gives a
//! bucket no identifier at all. Saying so on the value ([`identity::Strength`])
//! and in the log line is the alternative to a guard that quietly does less than
//! it looks like it does.

pub mod backend;
pub mod constants;
pub mod identity;

pub use backend::Guarded;
pub use identity::{StoreIdentity, Strength};
