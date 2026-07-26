//! Root key generation, random DEKs, and HKDF-SHA512 domain-separated sub-keys.
//!
//! The root key is generated once per vault and never changes. Purpose-specific
//! keys (index, cache, audit, …) are HKDF-expanded from it under distinct `info`
//! tags, so leaking one sub-key cannot recover another. Per-file DEKs are random
//! (not HKDF-derived) and wrapped by the root key.

mod generate;
mod subkey;

pub use crate::constants::{INFO_AUDIT, INFO_CACHE, INFO_INDEX};
pub use generate::generate_key;
pub use subkey::{derive_subkey, derive_subkey_from_ikm};
