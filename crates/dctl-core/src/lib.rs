//! DCTL core — the vault that composes crypto + storage + index into verified,
//! metadata-private file operations.
//!
//! A [`Vault`] wraps a [`Backend`](dctl_store::Backend) with a never-changing root
//! key (unwrapped from a password-protected envelope) and a local encrypted index.
//! Every [`put_file`](Vault::put_file) encrypts to a self-describing object, does a
//! verified write to the backend, then commits the index — success is reported only
//! after the durable index commit.
//!
//! Reads come in three shapes and the cost difference between them is the point:
//! [`get_file`](Vault::get_file) buffers a whole object,
//! [`get_file_to_path`](Vault::get_file_to_path) streams one at `O(chunk_size)`, and
//! [`open_range_reader`](Vault::open_range_reader) serves a byte window by fetching only
//! the chunks covering it — `O(window)` in egress as well as memory, which is what makes
//! a mount and a seek possible. See [`range`] for what a partial read authenticates and
//! what it deliberately cannot.
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod constants;
pub mod error;
pub mod range;
pub mod spool;
pub mod streamed;
mod vault;

/// §12 asymmetric-recipient types (hybrid X25519 + ML-KEM-768), re-exported so callers can
/// name the recipient public keys that [`Vault::put_file_shared`] and
/// [`Vault::fetch_recipient`] speak in (`dctl_core::kem::Drk1Public`).
pub use dctl_crypto::kem;
pub use dctl_index::Record;

/// The Argon2id cost a new vault's key slots are wrapped at.
///
/// Re-exported because a host has two reasons to name it and neither is served
/// by reaching past this crate: [`Vault::init_with_cost`] takes one, and a host
/// that offers "create a vault" to a human has to be able to ask
/// [`KdfCost::is_production`] whether the build it is running would produce a
/// real vault or a test one. That question has to be answerable at the moment of
/// creation, because the answer is baked into the envelope from then on.
pub use dctl_crypto::kdf::Cost as KdfCost;
pub use error::{CoreError, Result};
pub use streamed::Streamed;
pub use vault::{Modified, NewVault, Rebuilt, UnlockKey, Vault};

/// Check a typed recovery phrase against BIP-39 without attempting an unlock.
///
/// Re-exported from the crypto core rather than reimplemented, because a host
/// that validated phrases with its own copy of the word list would eventually
/// accept one the KDF rejects — or worse, reject one it accepts, and tell
/// somebody holding a correct phrase that it is wrong.
///
/// Hosts need this because [`Vault::unlock`] cannot answer the question that
/// matters at recovery time. "No slot opened" covers both *you mistyped a word*
/// and *this phrase belongs to a different vault*, and those have opposite
/// remedies. BIP-39's checksum separates them, so a caller can say which one
/// happened before spending an Argon2id derivation finding out.
pub use dctl_crypto::kdf::validate_mnemonic as validate_recovery_phrase;
