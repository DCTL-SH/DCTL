//! `dctl-crypto` — clean-room, streaming-first, post-quantum-ready encryption core.
//!
//! Layers (bottom to top):
//! - [`kdf`] — Argon2id derives a KEK from password (+ optional factor).
//! - [`envelope`] — `DKE1` slot-list: each KEK-wrapped slot recovers the same root.
//! - [`keys`] — root key + HKDF-SHA512 domain-separated sub-keys + random DEKs.
//! - [`aead`] — context-bound XChaCha20-Poly1305 (slot/DEK wraps, metadata, chunks).
//! - [`object`] — `DSF1` self-describing, chunked, seekable encrypted object.
//! - [`kem`] — §12 hybrid X25519 + ML-KEM-768 recipient layer (`kem_id=1`).
//! - [`names`] — `n/*` authoritative path→object records; [`path`] — §5 validation.
//!
//! The normative on-disk layout is `docs/FORMAT.md`. All format identifiers live
//! in [`constants`] and are intentionally independent of the product name, which
//! may be rebranded without touching the format.
#![forbid(unsafe_code)]
// Professional error handling: library code never panics on bad input — it
// returns a typed `Result`. Enforced, with one audited exception (see `rng`).
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// …but a test asserts, and an assertion that cannot panic is not an assertion.
// The ban above is about *shipped* behaviour: a caller handed bad input gets a
// typed error, never a process that dies. Under `cfg(test)` the panic IS the
// report, so `unwrap` on a fixture is the clearest way to say "this setup must
// succeed or the test means nothing". Same allowance, same wording, as
// `dctl-core` and `dctl-store` — it applies only to code that is never compiled
// into the library.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod aead;
pub mod constants;
pub mod envelope;
pub mod error;
pub mod kdf;
pub mod kem;
pub mod keys;
pub mod names;
pub mod object;
pub mod path;
pub mod rng;

pub use error::{CryptoError, Result};
