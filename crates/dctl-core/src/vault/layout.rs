//! Fixed layout constants for objects stored in the backend.

/// Object key holding the serialized `DKE1` vault envelope (wrapped root key).
pub(super) const ENVELOPE_OBJECT_KEY: &str = "system/envelope.bin";

/// Prefix for per-file content objects. The key is `o/` ‖ hex(file_id), where the
/// random `file_id` is bytes `[52..68]` of the sealed DSF1 object — a rename-stable,
/// path-independent id (`docs/FORMAT.md` §3).
pub(super) const OBJECT_KEY_PREFIX: &str = "o/";

/// Prefix for §5 name records: `n/` ‖ hex(BLAKE3_keyed(name-hash-key, NFC(path))).
/// The authoritative, backend-resident path→object map that makes a vault restorable
/// on any device with only the password (`docs/FORMAT.md` §5).
pub(super) const NAME_KEY_PREFIX: &str = "n/";

/// Prefix for the §12.3 public recipient registry: `r/` ‖ hex(key_id). Each entry is an
/// unencrypted `DRR1` container holding a recipient's public `DRK1` (no secrets), so a
/// writer can discover the public key of an already-pinned `key_id`. The stored bytes are
/// self-certifying: a reader recomputes `key_id` from the `DRK1` and requires it to match
/// the requested key, so a hostile backend cannot substitute a different pubkey.
pub(super) const RECIP_KEY_PREFIX: &str = "r/";

/// Prefix for §12.6 grant sidecars: `g/` ‖ hex(file_id). Each entry is a rewritable `DGS1`
/// container carrying ADDITIONAL recipients for the object with that `file_id`, so the
/// owner can add/remove recipients without re-uploading the (multi-GB) payload. The stored
/// bytes are self-binding: a reader verifies `file_id` and `head_hash` against THIS object
/// before honoring any grant, so a sidecar attached to the wrong object is rejected.
pub(super) const GRANT_KEY_PREFIX: &str = "g/";

/// Prefix for the §13 imported-key store: `k/` ‖ hex(key_id). Each entry is a root-sealed
/// `DIK1` container holding one imported (non-root-derived) recipient keypair, so the vault
/// can also decrypt objects sealed to that external identity (multi-identity, §12.4). The
/// private material is offline-restorable from the vault root alone; an entry whose
/// `version`/`hybrid_suite` is unknown is skipped, never the vault (one-way door, §8).
pub(super) const IMPORTED_KEY_PREFIX: &str = "k/";

/// Prefix for §14 shared-object discovery records: `d/` ‖ hex(recipient_key_id) ‖ `/` ‖
/// hex(file_id). Each entry is a `DGD1` sealed to the recipient so it can ENUMERATE the
/// objects shared to it (the owner's `n/*` name records are keyed to name keys the recipient
/// lacks). It grants no read access — it wraps only a pointer key, never the object KW/DEK.
pub(super) const DISCOVERY_KEY_PREFIX: &str = "d/";
