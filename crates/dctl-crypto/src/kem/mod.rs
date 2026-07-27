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
//! - [`sidecar`] — `DGS1` rewritable grant sidecar (§12.6): add/remove recipients of an
//!   already-uploaded object without re-uploading its payload.
//! - [`imported`] — `DIK1` root-sealed imported-key store (§13): hold an external
//!   (non-root-derived) keypair so the vault also decrypts objects sealed to it.
//! - [`discovery`] — `DGD1` per-recipient shared-object discovery record (§14): a sealed
//!   enumeration pointer so a recipient can list which objects are shared to it.
//!
//! Object-level entry points live in [`crate::object`]: `seal_to_recipients`,
//! `open_as_recipient`, and `open_with_kw` (decode with an already-recovered `KW`).
//!
//! The §12.3 `DRR1` public recipient registry (at `r/<hex key_id>`) lives one layer up in
//! `dctl-core` (`publish_identity`/`fetch_recipient`).

pub(crate) mod combine;
pub mod discovery;
pub mod identity;
pub mod imported;
pub mod sidecar;
pub(crate) mod wrap;

pub use discovery::{DiscoveryInfo, open_dgd1, seal_dgd1};
pub use identity::{Drk1Public, MlKemDecapKey, MlKemEncapKey, RecipientKeypair, derive_recipient};
pub use imported::{generate_external, parse_dik1, serialize_dik1};

/// Re-export the X25519 static secret type so callers can name it in
/// [`crate::object::open_as_recipient`] without depending on `x25519-dalek` directly.
pub use x25519_dalek::StaticSecret;

pub(crate) use wrap::{KemWrap, decapsulate_kw, encapsulate_to, serialize_block};
