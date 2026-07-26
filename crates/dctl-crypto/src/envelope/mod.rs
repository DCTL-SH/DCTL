//! DKE1 envelope — self-delimiting key-slot list (`docs/FORMAT.md` §2).
//!
//! Every slot (password / mnemonic / device / …) independently AEAD-wraps the *same*
//! 32-byte root key, and carries a `SUBKEY(KEK,·)` **key-commitment** checked in
//! constant time before unwrapping (defeats partitioning-oracle / multi-key attacks).
//! The wrap AAD binds `vault_id` and every wrap/KDF selector (anti-downgrade), so slots
//! cannot be transplanted across vaults or forged by algorithm downgrade.

mod model;
mod serialize;
mod wrap;

pub use model::{Envelope, Slot, WRAPPED_ROOT_LEN};
pub use serialize::{parse, serialize};
pub use wrap::{unwrap_slot, wrap_slot};

use crate::constants::VAULT_ID_LEN;

/// Generate a random `vault_id` binding all slots to one vault.
#[must_use]
pub fn generate_vault_id() -> [u8; VAULT_ID_LEN] {
    let mut id = [0u8; VAULT_ID_LEN];
    crate::rng::fill(&mut id);
    id
}
