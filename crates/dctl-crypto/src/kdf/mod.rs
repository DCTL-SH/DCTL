//! KEK derivation for envelope key slots.
//!
//! - Password slot: `Argon2id(NFC(passphrase) ‖ BLAKE3(factor)?, salt, params)`.
//! - Mnemonic slot: `Argon2id(BIP39_seed(mnemonic), salt, params)`.
//!
//! Passphrases are NFC-normalized (cross-device stability, FORMAT.md §2/§10) and
//! cost params are validated against mandatory ceilings before the KDF runs.

mod calibrate;
mod derive;
mod mnemonic;
mod salt;

pub use calibrate::{CalibratedParams, calibrate};
pub use derive::{derive_kek, derive_kek_with_params, normalize_passphrase, validate_params};
pub use mnemonic::{derive_kek_from_mnemonic, generate_mnemonic};
pub use salt::generate_salt;
