//! Single source of truth for every crypto constant — no literal is duplicated
//! across the crate.
//!
//! Two categories, kept strictly separate:
//!
//! * **FROZEN FORMAT IDENTIFIERS** — part of the on-disk format (`docs/FORMAT.md`).
//!   They are intentionally **independent of the product/app name** (which may be
//!   rebranded freely) and **MUST NEVER CHANGE**, or previously written data
//!   becomes permanently unreadable. Do not derive these from the app name.
//! * **DEFAULT POLICY PARAMETERS** — tunable defaults (KDF cost, chunk size).
//!   These are recorded inside each object/envelope, so they can evolve later
//!   without breaking old data.
//!
//! This is **version 1** — the first and only DCTL format. There is no earlier
//! shipped version; the pre-production draft was removed, not versioned around.

// ─────────────────────────────────────────────────────────────────────────────
// FROZEN FORMAT IDENTIFIERS  (never change — brand-independent)
// ─────────────────────────────────────────────────────────────────────────────

/// Envelope container magic ("Data Key Envelope v1"). Opaque, brand-neutral.
pub const ENVELOPE_MAGIC: [u8; 4] = *b"DKE1";
/// Envelope format version byte.
pub const ENVELOPE_VERSION: u8 = 1;
/// Object container magic ("Data Stream Format v1"). Opaque, brand-neutral.
pub const OBJECT_MAGIC: [u8; 4] = *b"DSF1";
/// Object format version byte.
pub const OBJECT_VERSION: u8 = 1;

/// Chunk AEAD algorithm ids (§3/§8).
pub const ALGO_XCHACHA20_POLY1305: u8 = 1;
/// Reserved for a future AES-256-GCM archival profile.
pub const ALGO_AES256_GCM: u8 = 2;

/// Object flag: a BLAKE3 footer is present.
pub const FLAG_FOOTER: u8 = 0x01;

/// HKDF-SHA512 root sub-key domain-separation tags (§1). Frozen; brand-neutral.
pub const INFO_INDEX: &[u8] = b"index-key-v1";
pub const INFO_CACHE: &[u8] = b"cache-key-v1";
pub const INFO_AUDIT: &[u8] = b"audit-key-v1";
/// Name-layer sub-key labels (§1). `name-hash-key` keys the public path hash;
/// `name-value-key` encrypts the record value — split so publishing `n/*` keys never
/// exposes value-encryption key material.
pub const INFO_NAME_HASH: &[u8] = b"name-hash-key-v1";
pub const INFO_NAME_VALUE: &[u8] = b"name-value-key-v1";
pub const INFO_OBJECT_KEYING: &[u8] = b"object-keying-v1";

// ── Envelope `DKE1` slot-list — FROZEN (docs/FORMAT.md §2) ──
/// Envelope `vault_id` length (bytes).
pub const VAULT_ID_LEN: usize = 16;
/// Maximum slots in an envelope (`slot_count` is bounded `1..=64`).
pub const MAX_SLOT_COUNT: u16 = 64;
/// Slot fixed-prefix bytes = everything but salt/aux/wrapped_root:
/// `slot_len(4)+type(1)+flags(1)+kdf_id(1)+wrap_algo(1)+m(4)+t(4)+p(4)+commit(32)
/// +salt_len(1)+aux_len(2)+wrap_len(2)`. So `slot_len == 57 + salt_len + aux_len + wrap_len`.
pub const SLOT_FIXED_PREFIX_LEN: usize = 57;
/// Key-commitment length (bytes).
pub const COMMIT_LEN: usize = 32;
/// Slot types.
pub const SLOT_TYPE_DEVICE: u8 = 0;
pub const SLOT_TYPE_PASSWORD: u8 = 1;
pub const SLOT_TYPE_MNEMONIC: u8 = 2;
pub const SLOT_TYPE_SHAMIR: u8 = 3;
/// KDF ids (`0` = platform/none, `1` = Argon2id).
pub const KDF_ID_NONE: u8 = 0;
pub const KDF_ID_ARGON2ID: u8 = 1;
/// Slot wrap algorithms.
pub const WRAP_ALGO_XCHACHA20_POLY1305: u8 = 1;
pub const WRAP_ALGO_AES256_GCM: u8 = 2;
/// HKDF `info` label for the per-slot key-commitment. Frozen.
pub const SLOT_COMMIT_INFO: &[u8] = b"dctl-slot-commit-v1";
/// Slot wrap-AAD domain prefix. Frozen.
pub const SLOT_AAD_PREFIX: &[u8] = b"dctl-slot-v1::";

// ── Object `DSF1` self-describing — FROZEN (docs/FORMAT.md §3-§4) ──
/// Fixed head length (bytes) — also folded into every object AAD.
pub const OBJECT_HEAD_LEN: usize = 68;
/// KEM ids: 0 root-wrapped DEK · 1 recipient hybrid (X25519+ML-KEM-768, §12).
pub const KEM_ID_NONE: u8 = 0;
pub const KEM_ID_HYBRID: u8 = 1;
/// Wrapped-DEK blob length: `nonce(24) + ct(32) + tag(16)`.
pub const WRAPPED_DEK_LEN: usize = NONCE_LEN + KEY_LEN + TAG_LEN;
/// AAD domain prefix for the DEK wrap. Frozen.
pub const DEK_WRAP_AAD_PREFIX: &[u8] = b"dctl-dek-v1::";
/// AAD domain prefix for encrypted metadata. Frozen.
pub const META_AAD_PREFIX: &[u8] = b"dctl-meta-v1::";
/// Minimum §4 metadata plaintext (all fixed fields, zero-length variable regions).
pub const META_MIN_PLAINTEXT_LEN: usize = 76;
/// `enc_metadata` length bounds: `nonce(24) + min-plaintext(76) + tag(16) = 116` ..= 262144.
pub const META_MIN_LEN: usize = NONCE_LEN + META_MIN_PLAINTEXT_LEN + TAG_LEN;
pub const META_MAX_LEN: usize = 262_144;
/// Metadata schema version.
pub const META_SCHEMA_V1: u8 = 0x01;
/// Metadata flag bits (§4): mtime · birthtime · is-directory · tombstone.
pub const META_FLAG_MTIME: u8 = 0x01;
pub const META_FLAG_BIRTHTIME: u8 = 0x02;
pub const META_FLAG_IS_DIR: u8 = 0x04;
pub const META_FLAG_TOMBSTONE: u8 = 0x08;
/// Chunk-stream base-nonce MSB (byte[23]) marker = 0x00; metadata nonce MSB = 0x01.
/// Keeps chunk and metadata nonce spaces disjoint under the shared DEK (§3).
pub const NONCE_DOMAIN_CHUNK: u8 = 0x00;
pub const NONCE_DOMAIN_META: u8 = 0x01;
/// Index of the domain-marker byte within the 24-byte nonce.
pub const NONCE_DOMAIN_BYTE: usize = 23;

// ── Name records (§5) — FROZEN ──
/// Name-record value AEAD domain prefix. Frozen.
pub const NAME_AAD_PREFIX: &[u8] = b"dctl-name-v1::";
/// Name-record backend object-key prefix.
pub const NAME_KEY_PREFIX: &str = "n/";
/// §5 path length caps (measured on NFC-normalized UTF-8 bytes).
pub const MAX_PATH_SEGMENT_BYTES: usize = 255;
pub const MAX_PATH_BYTES: usize = 4096;

// ── §12 Asymmetric recipients & post-quantum KEM (`kem_id=1`) — FROZEN ──
//
// Hybrid X25519 + ML-KEM-768. Every ASCII label below is pinned VERBATIM with its
// exact byte length (§12.9); the `const _` length assertions lock those lengths at
// compile time so a stray edit can never silently change a frozen domain string.

/// Hybrid suite selector (`hybrid_suite` byte): X25519 + ML-KEM-768 (§12.1).
pub const KEM_SUITE_X25519_MLKEM768: u8 = 0x01;

/// X25519 sizes (RFC 7748): public / secret / shared (bytes).
pub const X25519_PK_LEN: usize = 32;
pub const X25519_SK_LEN: usize = 32;
pub const X25519_SHARED_LEN: usize = 32;
/// ML-KEM-768 sizes (FIPS 203, k=3): ek / dk / ciphertext / shared (bytes).
pub const MLKEM768_EK_LEN: usize = 1184;
pub const MLKEM768_DK_LEN: usize = 2400;
pub const MLKEM768_CT_LEN: usize = 1088;
pub const MLKEM768_SHARED_LEN: usize = 32;
/// Stable recipient key-id length (unkeyed BLAKE3-256, full 32 bytes; §12.3).
pub const KEY_ID_LEN: usize = 32;

// ── Recipient identity `DRK1` (§12.3) ──
/// Long-term hybrid public-key container magic.
pub const RECIP_ID_MAGIC: [u8; 4] = *b"DRK1";
/// `DRK1` version byte.
pub const RECIP_ID_VERSION: u8 = 0x01;
/// Encoded `DRK1` length: magic(4)+ver(1)+suite(1)+x_pk(32)+ek(1184) = 1222.
pub const DRK1_LEN: usize = 4 + 1 + 1 + X25519_PK_LEN + MLKEM768_EK_LEN;
/// key-id domain label (17 bytes, trailing NUL): `key_id = BLAKE3-256(LABEL ‖ DRK1)`.
pub const RECIP_ID_LABEL: &[u8] = b"dctl-recip-id-v1\x00";

// ── Root-derived recipient keypair labels (§12.4) ──
/// `rseed = SUBKEY(root, RECIP_SEED_LABEL ‖ idx(u32 LE))` (18-byte label).
pub const RECIP_SEED_LABEL: &[u8] = b"dctl-recip-seed-v1";
/// `x_sk = SUBKEY(rseed, RECIP_X25519_LABEL)` (20-byte label).
pub const RECIP_X25519_LABEL: &[u8] = b"dctl-recip-x25519-v1";
/// `d = SUBKEY(rseed, RECIP_MLKEM_D_LABEL)` (21-byte label).
pub const RECIP_MLKEM_D_LABEL: &[u8] = b"dctl-recip-mlkem-d-v1";
/// `z = SUBKEY(rseed, RECIP_MLKEM_Z_LABEL)` (21-byte label).
pub const RECIP_MLKEM_Z_LABEL: &[u8] = b"dctl-recip-mlkem-z-v1";
/// Default (and only launch) recipient identity index.
pub const RECIP_IDX_DEFAULT: u32 = 0;

// ── Hybrid combiner (§12.1) ──
/// HKDF `info` domain string (34 bytes) prefixed to the KEM transcript.
pub const KEM_HYBRID_INFO_LABEL: &[u8] = b"dctl-kem-hybrid-x25519-mlkem768-v1";
/// Total combiner `info` length: label(34)+suite(1)+head(68)+key_id(32)
/// +eph_pk(32)+ct_m(1088)+x_pk(32)+ek(1184) = 2471 bytes.
pub const KEM_HYBRID_INFO_LEN: usize = 34
    + 1
    + OBJECT_HEAD_LEN
    + KEY_ID_LEN
    + X25519_PK_LEN
    + MLKEM768_CT_LEN
    + X25519_PK_LEN
    + MLKEM768_EK_LEN;
/// Combiner IKM length: `ss_x(32) ‖ K_m(32)` (classical then PQ).
pub const KEM_HYBRID_IKM_LEN: usize = X25519_SHARED_LEN + MLKEM768_SHARED_LEN;
/// `wrapped_kw` AAD domain prefix (16 bytes).
pub const KEM_KW_AAD_PREFIX: &[u8] = b"dctl-kem-kw-v1::";
/// `wrapped_kw` blob length: `nonce(24) + ct(32) + tag(16)` = 72 (wraps the 32-byte KW).
pub const WRAPPED_KW_LEN: usize = NONCE_LEN + KEY_LEN + TAG_LEN;

// ── `kem_wrap` block `DKW1` (§12.2) ──
/// `kem_wrap` block magic.
pub const KEM_WRAP_MAGIC: [u8; 4] = *b"DKW1";
/// `kw_version` byte.
pub const KEM_WRAP_VERSION: u8 = 0x01;
/// `kem_wrap` block header length: magic(4)+ver(1)+suite(1)+flags(1)+reserved(1)+count(2).
pub const KEM_WRAP_HEADER_LEN: usize = 10;
/// `kw_flags` bit0: a grant sidecar (`g/…`, §12.6) MAY carry additional recipients.
/// Every other bit is reserved-CRITICAL (unknown bit set ⇒ reject the object).
pub const KEM_WRAP_FLAG_SIDECAR: u8 = 0x01;
/// Recipient sub-record total length (suite 1): rec_len(4)+key_id(32)+ct_m_len(2)
/// +ct_m(1088)+eph_pk_len(2)+eph_pk(32)+wrapped_len(2)+wrapped_kw(72) = 1234.
pub const RECIP_SUBRECORD_LEN: usize =
    4 + KEY_ID_LEN + 2 + MLKEM768_CT_LEN + 2 + X25519_PK_LEN + 2 + WRAPPED_KW_LEN;
/// Max inline recipients: `floor((65535 − 10) / 1234) = 53` (§3 `kem_ct_len ≤ 65535`).
pub const MAX_RECIP_COUNT: u16 = 53;

// Compile-time locks on the FROZEN label byte-lengths (§12.9).
const _: () = assert!(RECIP_ID_LABEL.len() == 17);
const _: () = assert!(RECIP_SEED_LABEL.len() == 18);
const _: () = assert!(RECIP_X25519_LABEL.len() == 20);
const _: () = assert!(RECIP_MLKEM_D_LABEL.len() == 21);
const _: () = assert!(RECIP_MLKEM_Z_LABEL.len() == 21);
const _: () = assert!(KEM_HYBRID_INFO_LABEL.len() == 34);
const _: () = assert!(KEM_KW_AAD_PREFIX.len() == 16);
const _: () = assert!(DRK1_LEN == 1222);
const _: () = assert!(KEM_HYBRID_INFO_LEN == 2471);
const _: () = assert!(RECIP_SUBRECORD_LEN == 1234);
const _: () = assert!(WRAPPED_KW_LEN == 72);
// `kem_ct_len ≤ 65535` ⇒ 53 recipients max for suite 1.
const _: () =
    assert!(KEM_WRAP_HEADER_LEN + RECIP_SUBRECORD_LEN * (MAX_RECIP_COUNT as usize) <= 65535);
const _: () =
    assert!(KEM_WRAP_HEADER_LEN + RECIP_SUBRECORD_LEN * (MAX_RECIP_COUNT as usize + 1) > 65535);

// Fixed framing sizes (bytes).
/// XChaCha20 nonce length.
pub const NONCE_LEN: usize = 24;
/// Poly1305 tag length.
pub const TAG_LEN: usize = 16;
/// Symmetric key length.
pub const KEY_LEN: usize = 32;
/// BLAKE3 footer length.
pub const FOOTER_LEN: usize = 32;

// ─────────────────────────────────────────────────────────────────────────────
// DEFAULT POLICY PARAMETERS  (tunable; recorded per object/envelope)
// ─────────────────────────────────────────────────────────────────────────────

/// Argon2id memory cost (KiB) — 128 MiB, ~10x the OWASP floor.
pub const DEFAULT_ARGON2_M_COST: u32 = 131_072;
/// Argon2id time cost (iterations).
pub const DEFAULT_ARGON2_T_COST: u32 = 3;
/// Argon2id parallelism lanes.
pub const DEFAULT_ARGON2_P_LANES: u32 = 4;
/// Argon2id salt length (bytes).
pub const DEFAULT_SALT_LEN: usize = 16;

// Mandatory Argon2id parameter ceilings (FORMAT.md §2). Because envelope KDF
// params are read from untrusted storage *before* the wrapped-root tag can be
// checked, decoders MUST reject out-of-range params before ever running the KDF —
// otherwise a corrupt slot can demand terabytes of RAM or hours of CPU just to
// attempt an unlock. Frozen constants so all decoders agree.
/// Minimum Argon2id memory cost (KiB).
pub const ARGON2_MIN_M_COST: u32 = 8;
/// Maximum Argon2id memory cost (KiB) — 1 GiB.
pub const ARGON2_MAX_M_COST: u32 = 1_048_576;
/// Maximum Argon2id time cost (iterations).
pub const ARGON2_MAX_T_COST: u32 = 16;
/// Maximum Argon2id parallelism lanes.
pub const ARGON2_MAX_P_LANES: u32 = 8;

/// Default chunk size for the media/streaming profile (1 MiB — FORMAT.md §7:
/// keeps player probes/seeks cheap and per-chunk memory low for FUSE/File-Provider).
pub const DEFAULT_CHUNK_SIZE: u32 = 1024 * 1024;
/// Hard upper bound on `chunk_size` (16 MiB); objects outside `(0, MAX]` are rejected.
pub const MAX_CHUNK_SIZE: u32 = 16 * 1024 * 1024;
