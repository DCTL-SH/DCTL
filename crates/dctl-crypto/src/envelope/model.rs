//! DKE1 envelope data model (`docs/FORMAT.md` §2).

use crate::constants::{COMMIT_LEN, KEY_LEN, NONCE_LEN, TAG_LEN};

/// Wrapped-root blob length for `wrap_algo=1` (XChaCha20-Poly1305):
/// `nonce(24) + ct(32) + tag(16)`.
pub const WRAPPED_ROOT_LEN: usize = NONCE_LEN + KEY_LEN + TAG_LEN;

/// One key slot: an independent way to recover the same root key.
///
/// `commit` is `SUBKEY(KEK, "dctl-slot-commit-v1")` — the key-commitment checked
/// (constant-time) before unwrapping (§2, defeats partitioning-oracle attacks).
#[derive(Clone)]
pub struct Slot {
    pub slot_type: u8,
    pub flags: u8,
    pub kdf_id: u8,
    pub wrap_algo: u8,
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_lanes: u32,
    pub commit: [u8; COMMIT_LEN],
    pub salt: Vec<u8>,
    pub aux: Vec<u8>,
    /// AEAD(KEK, root_key): `nonce ‖ ct(32) ‖ tag(16)`.
    pub wrapped_root: Vec<u8>,
}

// Never derive Debug: a Slot holds wrap ciphertext + commitment; keep it out of logs.

/// A decoded DKE1 envelope: a `vault_id` and a self-delimiting list of slots that
/// all wrap the same 32-byte root key.
#[derive(Clone)]
pub struct Envelope {
    pub vault_id: [u8; 16],
    pub slots: Vec<Slot>,
}
