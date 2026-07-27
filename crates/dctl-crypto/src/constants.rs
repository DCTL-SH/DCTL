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
// exact byte length (§12.10); the `const _` length assertions lock those lengths at
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

// ── §12.6 grant sidecar `DGS1` — FROZEN ──
/// DSF1 `file_id` length (bytes) — head bytes `[52..68]`; binds a sidecar to its object.
pub const FILE_ID_LEN: usize = 16;
/// BLAKE3-256 head-hash length (bytes) — binds a sidecar to the exact 68-byte head.
pub const HEAD_HASH_LEN: usize = 32;
/// Grant sidecar container magic ("DCTL Grant Sidecar v1").
pub const GRANT_SIDECAR_MAGIC: [u8; 4] = *b"DGS1";
/// Grant sidecar version byte.
pub const GRANT_SIDECAR_VERSION: u8 = 0x01;
/// DGS1 header length: magic(4)+ver(1)+suite(1)+reserved(2)+file_id(16)+head_hash(32)
/// +grant_gen(8)+grant_count(2) = 66. `grant_count` grants (each [`RECIP_SUBRECORD_LEN`]
/// bytes, identical §12.2 sub-record format) follow at offset 66.
pub const GRANT_SIDECAR_HEADER_LEN: usize = 4 + 1 + 1 + 2 + FILE_ID_LEN + HEAD_HASH_LEN + 8 + 2;
/// Max grants carried in one sidecar (`0 ≤ G ≤ 4096`, §12.6).
pub const MAX_GRANT_COUNT: u16 = 4096;

// ── §13 imported-key store `DIK1` (`k/<hex key_id>`) — FROZEN ──
//
// A root-sealed container holding one IMPORTED (non-root-derived) recipient keypair, so a
// vault can also decrypt objects sealed to that external identity (multi-identity, §12.4).
// The private material is wrapped with the pinned §1 `SUBKEY` + XChaCha20-Poly1305 — no new
// primitive — and is offline-restorable from the vault root alone.

/// Imported-key store container magic ("DCTL Imported Key v1").
pub const IMPORTED_KEY_MAGIC: [u8; 4] = *b"DIK1";
/// `DIK1` version byte.
pub const IMPORTED_KEY_VERSION: u8 = 0x01;
/// `DIK1` cleartext header length: magic(4)+ver(1)+suite(1)+reserved(2)+key_id(32) = 40.
pub const DIK1_HEADER_LEN: usize = 4 + 1 + 1 + 2 + KEY_ID_LEN;
/// `DIK1` sealed plaintext length: x_sk(32)+dk(2400)+x_pk(32)+ek(1184) = 3648.
pub const DIK1_PLAINTEXT_LEN: usize =
    X25519_SK_LEN + MLKEM768_DK_LEN + X25519_PK_LEN + MLKEM768_EK_LEN;
/// Whole `DIK1` container length: header(40)+nonce(24)+ct(3648)+tag(16) = 3728.
pub const DIK1_LEN: usize = DIK1_HEADER_LEN + NONCE_LEN + DIK1_PLAINTEXT_LEN + TAG_LEN;
/// Root-derived imported-key wrapping-key label (15 bytes): `k_wrap = SUBKEY(root,
/// IK_WRAP_LABEL ‖ key_id)` — folding `key_id` makes `k_wrap` entry-specific (§13).
pub const IK_WRAP_LABEL: &[u8] = b"dctl-ik-wrap-v1";
/// `DIK1` sealed-body AAD domain prefix (12 bytes): `AAD = IK_AAD_PREFIX ‖ magic(4) ‖
/// hybrid_suite(1) ‖ key_id(32)` = 49 bytes (§13).
pub const IK_AAD_PREFIX: &[u8] = b"dctl-ik-v1::";

// ── §14 shared-object discovery `DGD1` (`d/<hex recipient_key_id>/<hex file_id>`) — FROZEN ──
//
// A per-(recipient, object) enumeration pointer sealed to the recipient: it wraps a fresh
// 32-byte discovery key `DW` (via one §12.2 sub-record, bound to the object head) and, under
// `DW`, an AEAD-sealed `disc_plaintext` carrying the object's authoritative path/size/hash.
// It grants NO read access by itself — `DW` never wraps the object `KW`/`DEK`.

/// Shared-object discovery container magic ("DCTL Discovery v1").
pub const DISCOVERY_MAGIC: [u8; 4] = *b"DGD1";
/// `DGD1` version byte.
pub const DISCOVERY_VERSION: u8 = 0x01;
/// `DGD1` cleartext header length: magic(4)+ver(1)+suite(1)+reserved(2)+recipient_key_id(32)
/// +file_id(16)+head_hash(32) = 88.
pub const DGD1_HEADER_LEN: usize = 4 + 1 + 1 + 2 + KEY_ID_LEN + FILE_ID_LEN + HEAD_HASH_LEN;
/// Object offset at which the `DGD1` sealed body (`nonce(24)‖ct(D)‖tag(16)`) begins:
/// header(88) + one §12.2 sub-record (`wrapped_dw`, [`RECIP_SUBRECORD_LEN`]) = 1322.
pub const DGD1_BODY_OFFSET: usize = DGD1_HEADER_LEN + RECIP_SUBRECORD_LEN;
/// `DGD1` sealed-body AAD domain prefix (14 bytes): `AAD = DISC_AAD_PREFIX ‖ dgd1_header(88)`.
pub const DISC_AAD_PREFIX: &[u8] = b"dctl-disc-v1::";
/// Discovery-plaintext schema version.
pub const DISC_SCHEMA_V1: u8 = 0x01;
/// Minimum `disc_plaintext` length (all fixed fields, zero-length path/ext regions):
/// schema(1)+obj_suite(1)+file_id(16)+size(8)+content_hash(32)+path_len(2)+ext_len(2) = 62.
/// (`path_len` MUST be ≥ 1 for a real record; the fixed floor is 62.)
pub const DISC_MIN_PLAINTEXT_LEN: usize = 62;

// Compile-time locks on the FROZEN label byte-lengths (§12.10).
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
const _: () = assert!(FILE_ID_LEN == 16);
const _: () = assert!(HEAD_HASH_LEN == 32);
const _: () = assert!(GRANT_SIDECAR_HEADER_LEN == 66);
// §13 DIK1 imported-key store frozen sizes/labels.
const _: () = assert!(IK_WRAP_LABEL.len() == 15);
const _: () = assert!(IK_AAD_PREFIX.len() == 12);
const _: () = assert!(DIK1_HEADER_LEN == 40);
const _: () = assert!(DIK1_PLAINTEXT_LEN == 3648);
const _: () = assert!(DIK1_LEN == 3728);
// §14 DGD1 shared-object discovery frozen sizes/labels.
const _: () = assert!(DISC_AAD_PREFIX.len() == 14);
const _: () = assert!(DGD1_HEADER_LEN == 88);
const _: () = assert!(DGD1_BODY_OFFSET == 1322);
const _: () = assert!(DISC_MIN_PLAINTEXT_LEN == 62);
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

/// Entropy behind a generated recovery mnemonic (bytes).
///
/// 32 bytes = 256 bits, which BIP-39 encodes as **24 words**. Matched to
/// [`KEY_LEN`] on purpose: the phrase is one of the ways into the *same* 32-byte
/// root key, so giving it less entropy than the key it protects would make the
/// recovery path the cheapest thing to attack. A 12-word (128-bit) phrase is the
/// common wallet choice and is rejected here for that reason — the extra twelve
/// words cost one more line on a sheet of paper and are the difference between
/// the key's own strength and half of it.
pub const RECOVERY_MNEMONIC_ENTROPY_BYTES: usize = KEY_LEN;
/// Words in a generated recovery phrase — a *derived* fact, not a free choice.
///
/// BIP-39 packs 11 bits of entropy per word plus a checksum of one bit per 32
/// bits of entropy, so 256 bits becomes `(256 + 8) / 11 = 24` words. Stated as a
/// constant because hosts print it ("write these 24 words down") and check it,
/// and the assertion below keeps it tied to the entropy rather than to memory.
pub const RECOVERY_MNEMONIC_WORDS: usize = 24;
const _: () = assert!(
    RECOVERY_MNEMONIC_WORDS
        == (RECOVERY_MNEMONIC_ENTROPY_BYTES * 8 + RECOVERY_MNEMONIC_ENTROPY_BYTES * 8 / 32) / 11
);

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

/// Leading bytes a random-access reader fetches to learn where an object's payload
/// starts (`object::range`).
///
/// A DSF1 header is self-describing but variable-length: `head(68) ‖ kem_ct_len(2) ‖
/// kem_wrap(K) ‖ wrapped_dek(72) ‖ meta_len(4) ‖ enc_metadata(M)`, with `K ≤ 65535` and
/// `M ≤ 262144`. Asking for the worst case every time would be a 320 KiB request per
/// object opened; asking for the minimum would be three round trips before a single byte
/// of payload. Neither is right for a mount that opens files constantly.
///
/// One page is the balance. For the ordinary `kem_id = 0` object it covers `146` fixed
/// bytes plus roughly 3.9 KiB of §4 metadata — a path hint, an mtime, a content type —
/// which is every object a filesystem will ever produce, since §5 caps a path at 4096
/// bytes and the rest of the record is fixed-width. It also covers a §12 single-recipient
/// hybrid object, whose `kem_wrap` block is about 1.3 KiB. An object that needs more (a
/// many-recipient share, an unusually large extension region) is not refused: the reader
/// is told the exact length it still needs and issues one further, precisely-sized read.
///
/// Below a page there is nothing to gain — a filesystem read, a TLS record and an HTTP
/// range response are all billed in units at least this large, so a smaller probe costs
/// the same and only makes the second round trip more likely.
pub const OBJECT_HEADER_PROBE_LEN: usize = 4096;
/// The probe must at least reach `meta_len` for the common `kem_id = 0` object, or the
/// "usually one request" claim above is simply false.
const _: () = assert!(OBJECT_HEADER_PROBE_LEN >= OBJECT_HEAD_LEN + 2 + WRAPPED_DEK_LEN + 4);
