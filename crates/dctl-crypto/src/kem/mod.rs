//! §12 asymmetric recipients & post-quantum KEM (`kem_id=1`) — hybrid X25519 +
//! ML-KEM-768.
//!
//! A writer holding only **public** keys can seal an object that only a **private**-key
//! holder can read (write-only backup + sharing). A per-object random 32-byte `KW`
//! wraps the DEK once (`wrapped_dek`, §3), and `KW` is independently hybrid-wrapped to
//! each recipient inside the `DKW1` `kem_wrap` block — so every recipient recovers the
//! **same** `KW → DEK → payload`. The hybrid combiner (§12.1) needs **both** the X25519
//! and the ML-KEM shared secret, so an algorithmic break of one primitive by a party
//! without the vault root cannot derive the wrapping key.
//!
//! Layers here:
//! - [`identity`] — `DRK1` public identity, `key_id`, root-derived keypair (§12.3–§12.4).
//! - `combine` — the pinned hybrid combiner + `wrapped_kw` AAD (§12.1, private).
//! - `wrap` — `DKW1` block serialize/parse + per-recipient encaps/decaps (§12.2, private).
//!
//! Object-level entry points live in [`crate::object`]: `seal_to_recipients` and
//! `open_as_recipient`.
//!
//! DEFERRED (additive, not needed for the core round-trip):
// TODO(task-13-followup): §12.6 `DGS1` grant sidecar (rewritable extra recipients at
// `g/<hex file_id>`) and §12.3 `DRR1` public registry object (at `r/<hex key_id>`).

pub(crate) mod combine;
pub mod identity;
pub(crate) mod wrap;

pub use identity::{Drk1Public, MlKemDecapKey, MlKemEncapKey, RecipientKeypair, derive_recipient};

/// Re-export the X25519 static secret type so callers can name it in
/// [`crate::object::open_as_recipient`] without depending on `x25519-dalek` directly.
pub use x25519_dalek::StaticSecret;

pub(crate) use wrap::{KemWrap, decapsulate_kw, encapsulate_to, serialize_block};
