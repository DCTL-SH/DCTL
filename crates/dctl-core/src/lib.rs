//! DCTL core — the vault that composes crypto + storage + index into verified,
//! metadata-private file operations.
//!
//! A [`Vault`] wraps a [`Backend`](dctl_store::Backend) with a never-changing root
//! key (unwrapped from a password-protected envelope) and a local encrypted index.
//! Every [`put_file`](Vault::put_file) encrypts to a self-describing object, does a
//! verified write to the backend, then commits the index — success is reported only
//! after the durable index commit.
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod error;
mod vault;

/// §12 asymmetric-recipient types (hybrid X25519 + ML-KEM-768), re-exported so callers can
/// name the recipient public keys that [`Vault::put_file_shared`] and
/// [`Vault::fetch_recipient`] speak in (`dctl_core::kem::Drk1Public`).
pub use dctl_crypto::kem;
pub use dctl_index::Record;
pub use error::{CoreError, Result};
pub use vault::Vault;
