//! KEK derivation for envelope key slots.
//!
//! - Password slot: `Argon2id(NFC(passphrase) ‖ BLAKE3(factor)?, salt, cost)`.
//! - Mnemonic slot: `Argon2id(BIP39_seed(mnemonic), salt, cost)`.
//!
//! Passphrases are NFC-normalized (cross-device stability, FORMAT.md §2/§10) and
//! the [`Cost`] is validated against mandatory ceilings before the KDF runs.
//!
//! Every derivation names its [`Cost`] explicitly — a slot's own recorded one
//! when re-deriving, [`Cost::shipped`] when writing a new slot. [`gate`] is what
//! makes `shipped` mean 128 MiB in anything that ships, and it is worth reading
//! before touching any of this.

mod calibrate;
mod cost;
mod derive;
pub mod gate;
mod mnemonic;
mod salt;

pub use calibrate::calibrate;
pub use cost::Cost;
pub use derive::{derive_kek, normalize_passphrase};
pub use mnemonic::{derive_kek_from_mnemonic, generate_mnemonic, validate_mnemonic};
pub use salt::generate_salt;
