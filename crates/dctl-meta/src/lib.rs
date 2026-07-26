//! DCTL identity & paths — the single, renameable source of product branding.
//!
//! Rename the product here and the binary name, config/data/cache directories, and
//! environment-variable prefix all follow. **On-disk format identifiers are NOT
//! defined here** — those are frozen and brand-neutral in `dctl-crypto::constants`,
//! so a rebrand never touches stored data.
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod identity;
pub mod paths;

pub use identity::{APP_NAME, BINARY_NAME, env_prefix, env_var};
