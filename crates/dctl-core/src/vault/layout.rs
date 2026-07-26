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
