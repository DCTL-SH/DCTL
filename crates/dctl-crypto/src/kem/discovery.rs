//! §14 shared-object discovery `DGD1`: a per-(recipient, object) enumeration pointer sealed
//! to the recipient, stored at `"d/" ‖ hex(recipient_key_id) ‖ "/" ‖ hex(file_id)`.
//!
//! A recipient can *decrypt* a shared object once it knows the `file_id` (its inline §12.2
//! sub-record, or a §12.6 `DGS1` grant), but it cannot *enumerate* which objects are shared
//! to it — the owner's `n/*` name records are keyed to name keys the recipient does not
//! hold. A `DGD1` solves enumeration: the recipient lists `d/<its key_id>/*` and opens each.
//!
//! No new primitive — the record reuses the §12 hybrid machinery exactly. It wraps a fresh
//! 32-byte **discovery key `DW`** (the discovery analogue of an object's `KW`) via ONE §12.2
//! sub-record bound to the object's `fixed_head(68)`, then AEAD-seals the `disc_plaintext`
//! (path/size/hash) under `DW`.
//!
//! ```text
//! Off    Size  Field  (cleartext header, 88 bytes)
//! 0      4     magic             "DGD1"
//! 4      1     version           0x01
//! 5      1     hybrid_suite      0x01
//! 6      2     reserved          0x0000
//! 8      32    recipient_key_id  §12.3 key_id this record is sealed to
//! 40     16    file_id           the DSF1 file_id
//! 56     32    head_hash         BLAKE3-256 of the DSF1 fixed 68-byte head
//! 88     1234  wrapped_dw        one §12.2 sub-record sealing DW to the recipient
//! 1322   24    nonce             sealed_body: XChaCha20-Poly1305(DW, disc_plaintext)
//! 1346   D     ct                AEAD ciphertext of disc_plaintext (D = 62 + P + E)
//! 1346+D 16    tag               Poly1305 tag
//! ```
//! `sealed_body` AAD = `"dctl-disc-v1::"(14) ‖ dgd1_header(88)`.
//!
//! **Grants no read access by itself:** `DGD1` wraps only `DW` — a pointer/index key — never
//! the object `KW`/`DEK`. A recipient still needs a valid inline §12.2 sub-record or a §12.6
//! grant to recover `KW` and read content.

use crate::aead;
use crate::constants::{
    DGD1_BODY_OFFSET, DGD1_HEADER_LEN, DISC_AAD_PREFIX, DISC_MIN_PLAINTEXT_LEN, DISC_SCHEMA_V1,
    DISCOVERY_MAGIC, DISCOVERY_VERSION, FILE_ID_LEN, HEAD_HASH_LEN, KEM_SUITE_X25519_MLKEM768,
    KEY_ID_LEN, NONCE_LEN, OBJECT_HEAD_LEN, RECIP_SUBRECORD_LEN, TAG_LEN,
};
use crate::error::{CryptoError, Result};
use crate::keys::generate_key;
use crate::object::parse_head;
use crate::path;

use super::identity::{Drk1Public, RecipientKeypair};
use super::wrap;

/// The discoverable facts about one shared object, recovered from a `DGD1` (§14). The
/// `size` is **NOT confidential** — it equals the cleartext `plaintext_len` of the DSF1
/// fixed head (§3), which a backend can `Range`-fetch directly; it is carried under `DW`
/// only for enumeration convenience, not as a confidentiality guarantee.
#[derive(Clone, Debug)]
pub struct DiscoveryInfo {
    /// Object `hybrid_suite` echo (0x01) — cross-checked against the suite on open.
    pub obj_suite: u8,
    /// The DSF1 object id (also the `o/<hex file_id>` storage key and the `.../<file_id>`
    /// path component).
    pub file_id: [u8; FILE_ID_LEN],
    /// Object plaintext size (`== head.plaintext_len`, §4 `size`). Not confidential.
    pub size: u64,
    /// BLAKE3-256 of the object plaintext (`== §4 content_blake3`).
    pub content_hash: [u8; 32],
    /// Authoritative NFC UTF-8 path (§5). Re-validated on open before any filesystem use.
    pub path: String,
    /// Trailing extension region (forward growth; unknown TLVs ignored by consumers).
    pub ext: Vec<u8>,
}

/// Seal a `DGD1` discovery record for `disc.file_id` to `recipient`, binding the object's
/// `head_bytes` (§14 seal). Generates a fresh `DW`, wraps it to the recipient via the
/// identical §12.2 sub-record used for a §12.6 grant (so `wrapped_dw` folds `fixed_head(68)`
/// and the recipient `key_id`), and AEAD-seals `disc_plaintext` under `DW` with
/// `AAD = "dctl-disc-v1::" ‖ header(88)`. The path is §5-validated before it ships.
pub fn seal_dgd1(
    recipient: &Drk1Public,
    head_bytes: &[u8; OBJECT_HEAD_LEN],
    disc: &DiscoveryInfo,
) -> Result<Vec<u8>> {
    // Re-validate the path per §5 before writing it into the record.
    path::validate(&disc.path)?;

    let recipient_key_id = recipient.key_id();
    let head_hash = blake3::hash(head_bytes);

    // Cleartext header (88 bytes).
    let mut header = [0u8; DGD1_HEADER_LEN];
    header[0..4].copy_from_slice(&DISCOVERY_MAGIC);
    header[4] = DISCOVERY_VERSION;
    header[5] = KEM_SUITE_X25519_MLKEM768;
    // reserved [6..8] already zero.
    header[8..8 + KEY_ID_LEN].copy_from_slice(&recipient_key_id);
    header[40..40 + FILE_ID_LEN].copy_from_slice(&disc.file_id);
    header[56..56 + HEAD_HASH_LEN].copy_from_slice(head_hash.as_bytes());

    // Fresh discovery key DW, wrapped to the recipient as one §12.2 sub-record. DW is a
    // pointer key only; it never wraps the object KW/DEK, so a DGD1 grants no read access.
    let dw = generate_key();
    let wrapped_dw = wrap::encapsulate_to(recipient, head_bytes, &dw)?;
    if wrapped_dw.len() != RECIP_SUBRECORD_LEN {
        return Err(CryptoError::Format("wrapped_dw wrong size".into()));
    }

    let disc_plaintext = build_disc_plaintext(disc)?;
    let aad = disc_aad(&header);
    let sealed_body = aead::encrypt(&dw, &disc_plaintext, &aad)?;

    let mut out = Vec::with_capacity(DGD1_HEADER_LEN + RECIP_SUBRECORD_LEN + sealed_body.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&wrapped_dw);
    out.extend_from_slice(&sealed_body);
    Ok(out)
}

/// Open + fully validate a `DGD1` record as `keypair` (§14 read). Verifies the header
/// (`magic`/`version`/`hybrid_suite`/`reserved`), that `recipient_key_id == keypair.key_id`,
/// and that the `wrapped_dw` sub-record `key_id` matches; then (given the object head)
/// verifies `head_hash == BLAKE3-256(head)` and `head.file_id == header.file_id`, recovers
/// `DW` via §12.2 decaps (the AEAD tag is the sole accept gate), opens `sealed_body`,
/// verifies `body.file_id == header.file_id`, and RE-validates the path per §5.
///
/// `head_bytes` is REQUIRED to recover `DW` (the §12.2 combiner folds `fixed_head(68)`); the
/// spec's §14 read step 2 fetches it via one Range request. `None` ⇒ an explicit error.
pub fn open_dgd1(
    bytes: &[u8],
    keypair: &RecipientKeypair,
    head_bytes: Option<&[u8; OBJECT_HEAD_LEN]>,
) -> Result<DiscoveryInfo> {
    // Smallest possible record: header + wrapped_dw + nonce + tag (empty ct is impossible,
    // but this is the pre-crypto lower bound before parsing the body).
    if bytes.len() < DGD1_BODY_OFFSET + NONCE_LEN + TAG_LEN {
        return Err(CryptoError::Format("DGD1 too short".into()));
    }
    if bytes[0..4] != DISCOVERY_MAGIC {
        return Err(CryptoError::Format("bad DGD1 magic".into()));
    }
    if bytes[4] != DISCOVERY_VERSION {
        return Err(CryptoError::Format("unsupported DGD1 version".into()));
    }
    if bytes[5] != KEM_SUITE_X25519_MLKEM768 {
        return Err(CryptoError::Format("unsupported DGD1 hybrid_suite".into()));
    }
    if bytes[6] != 0 || bytes[7] != 0 {
        return Err(CryptoError::Format("DGD1 reserved bytes nonzero".into()));
    }
    let mut recipient_key_id = [0u8; KEY_ID_LEN];
    recipient_key_id.copy_from_slice(&bytes[8..8 + KEY_ID_LEN]);
    if recipient_key_id != keypair.key_id {
        return Err(CryptoError::Format(
            "DGD1 recipient_key_id does not match this keypair".into(),
        ));
    }
    let mut file_id = [0u8; FILE_ID_LEN];
    file_id.copy_from_slice(&bytes[40..40 + FILE_ID_LEN]);
    let head_hash = &bytes[56..56 + HEAD_HASH_LEN];

    // wrapped_dw: one §12.2 sub-record. Its key_id (validated structurally) must equal the
    // header recipient_key_id (§14 read step 1).
    let wrapped_dw = &bytes[DGD1_HEADER_LEN..DGD1_BODY_OFFSET];
    let (sub_key_id, sub) = wrap::parse_subrecord(wrapped_dw)?;
    if sub_key_id != recipient_key_id {
        return Err(CryptoError::Format(
            "DGD1 wrapped_dw key_id != recipient_key_id".into(),
        ));
    }

    // The object head is required to recover DW and re-check the structural binding.
    let head_bytes = head_bytes
        .ok_or_else(|| CryptoError::Format("DGD1 open requires the object head".into()))?;
    if blake3::hash(head_bytes).as_bytes()[..] != *head_hash {
        return Err(CryptoError::Format("DGD1 head_hash mismatch".into()));
    }
    let head = parse_head(head_bytes)?;
    if head.file_id != file_id {
        return Err(CryptoError::Format(
            "DGD1 head.file_id != header.file_id".into(),
        ));
    }

    // Recover DW (§12.2 decaps). A key that is not this recipient's ⇒ the AEAD tag fails.
    let dw = wrap::decapsulate_kw(
        &sub,
        keypair.x_sk(),
        keypair.dk(),
        &keypair.public.x_pk,
        &keypair.public.ek,
        &keypair.key_id,
        head_bytes,
    )?;

    // Open the sealed body under DW.
    let aad = disc_aad_bytes(&bytes[0..DGD1_HEADER_LEN]);
    let disc_plaintext = aead::decrypt(&dw, &bytes[DGD1_BODY_OFFSET..], &aad)?;

    parse_disc_plaintext(&disc_plaintext, &file_id)
}

/// Serialize the §14 `disc_plaintext` (`62 + P + E` bytes). `path` must be non-empty.
fn build_disc_plaintext(disc: &DiscoveryInfo) -> Result<Vec<u8>> {
    let path = disc.path.as_bytes();
    let path_len: u16 = path
        .len()
        .try_into()
        .map_err(|_| CryptoError::Format("disc path too long".into()))?;
    if path_len == 0 {
        return Err(CryptoError::Format("disc path must be non-empty".into()));
    }
    let ext_len: u16 = disc
        .ext
        .len()
        .try_into()
        .map_err(|_| CryptoError::Format("disc ext too long".into()))?;

    let mut out = Vec::with_capacity(DISC_MIN_PLAINTEXT_LEN + path.len() + disc.ext.len());
    out.push(DISC_SCHEMA_V1);
    out.push(disc.obj_suite);
    out.extend_from_slice(&disc.file_id);
    out.extend_from_slice(&disc.size.to_le_bytes());
    out.extend_from_slice(&disc.content_hash);
    out.extend_from_slice(&path_len.to_le_bytes());
    out.extend_from_slice(path);
    out.extend_from_slice(&ext_len.to_le_bytes());
    out.extend_from_slice(&disc.ext);
    Ok(out)
}

/// Parse + validate a §14 `disc_plaintext`, cross-checking `file_id` against the header and
/// RE-validating the path per §5. An unknown `disc_schema` is rejected (the caller skips the
/// record per §8).
fn parse_disc_plaintext(pt: &[u8], header_file_id: &[u8; FILE_ID_LEN]) -> Result<DiscoveryInfo> {
    if pt.len() < DISC_MIN_PLAINTEXT_LEN {
        return Err(CryptoError::Format("disc_plaintext too short".into()));
    }
    if pt[0] != DISC_SCHEMA_V1 {
        return Err(CryptoError::Format("unsupported disc_schema".into()));
    }
    let obj_suite = pt[1];
    if obj_suite != KEM_SUITE_X25519_MLKEM768 {
        return Err(CryptoError::Format("disc obj_suite mismatch".into()));
    }
    let mut file_id = [0u8; FILE_ID_LEN];
    file_id.copy_from_slice(&pt[2..2 + FILE_ID_LEN]);
    if &file_id != header_file_id {
        return Err(CryptoError::Format(
            "disc_plaintext file_id != header.file_id".into(),
        ));
    }
    let size = u64::from_le_bytes(
        pt[18..26]
            .try_into()
            .map_err(|_| CryptoError::Format("disc bad size".into()))?,
    );
    let mut content_hash = [0u8; 32];
    content_hash.copy_from_slice(&pt[26..58]);
    let path_len = u16::from_le_bytes([pt[58], pt[59]]) as usize;
    if path_len == 0 {
        return Err(CryptoError::Format("disc path_len must be >= 1".into()));
    }
    let p_start: usize = 60;
    let p_end = p_start
        .checked_add(path_len)
        .ok_or_else(|| CryptoError::Format("disc path overruns".into()))?;
    if p_end + 2 > pt.len() {
        return Err(CryptoError::Format("disc truncated (ext_len)".into()));
    }
    let path = String::from_utf8(pt[p_start..p_end].to_vec())
        .map_err(|_| CryptoError::Format("disc path not UTF-8".into()))?;
    let ext_len = u16::from_le_bytes([pt[p_end], pt[p_end + 1]]) as usize;
    let ext_start = p_end + 2;
    let ext_end = ext_start
        .checked_add(ext_len)
        .ok_or_else(|| CryptoError::Format("disc ext overruns".into()))?;
    if ext_end != pt.len() {
        return Err(CryptoError::Format(
            "disc_plaintext length != 62 + P + E".into(),
        ));
    }
    let ext = pt[ext_start..ext_end].to_vec();

    // Reader-side §5 re-validation (the path is only DW-authenticated, not trusted).
    path::validate(&path)?;

    Ok(DiscoveryInfo {
        obj_suite,
        file_id,
        size,
        content_hash,
        path,
        ext,
    })
}

/// Build the §14 body AAD from a freshly-built header array.
fn disc_aad(header: &[u8; DGD1_HEADER_LEN]) -> Vec<u8> {
    disc_aad_bytes(header)
}

/// Build the §14 body AAD `"dctl-disc-v1::"(14) ‖ header(88)` from header bytes.
fn disc_aad_bytes(header: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(DISC_AAD_PREFIX.len() + DGD1_HEADER_LEN);
    aad.extend_from_slice(DISC_AAD_PREFIX);
    aad.extend_from_slice(header);
    aad
}
