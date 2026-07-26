//! §12.6 grant sidecar `DGS1`: a separate, rewritable container at backend key
//! `"g/" ‖ hex(file_id)` that carries **additional** recipients for an already-uploaded
//! DSF1 `kem_id=1` object, so the owner can add/remove recipients WITHOUT re-uploading the
//! (multi-GB) payload. The main object (`file_id`/`DEK`/`KW`/head/payload) is untouched.
//!
//! A grant is byte-for-byte a §12.2 recipient sub-record (`rec_len = 1234`): it wraps the
//! per-object `KW` to one recipient, still folding the object's 68-byte `fixed_head` into
//! its `wrapping_key` `info` and its `wrapped_kw` AAD (§12.1/§12.8), so it is
//! cryptographically bound to the exact object regardless of storage location. The sidecar
//! header additionally carries `file_id` + `head_hash` for fast structural binding, both
//! verified on parse — a sidecar attached to the wrong object is rejected.
//!
//! ```text
//! Off   Size  Field
//! 0     4     magic         "DGS1"
//! 4     1     version       0x01
//! 5     1     hybrid_suite  0x01
//! 6     2     reserved      0x0000 (MUST be 0)
//! 8     16    file_id       MUST equal the DSF1 file_id
//! 24    32    head_hash     BLAKE3-256 of the DSF1 fixed 68-byte head
//! 56    8     grant_gen     u64 LE (monotonic; higher wins on rewrite races)
//! 64    2     grant_count   u16 LE (0 ≤ G ≤ 4096)
//! 66    …     grants[G]     each a §12.2 sub-record (rec_len = 1234)
//! ```
//!
//! This module deliberately **reuses** the §12.2 machinery (`wrap::encapsulate_to`,
//! `wrap::decapsulate_kw`, `wrap::parse_subrecord`): a grant IS a §12.2 sub-record, and the
//! sidecar is just a bound header wrapping a list of them.

use zeroize::Zeroizing;

use crate::constants::{
    FILE_ID_LEN, GRANT_SIDECAR_HEADER_LEN, GRANT_SIDECAR_MAGIC, GRANT_SIDECAR_VERSION,
    HEAD_HASH_LEN, KEM_SUITE_X25519_MLKEM768, KEY_ID_LEN, KEY_LEN, MAX_GRANT_COUNT,
    OBJECT_HEAD_LEN, RECIP_SUBRECORD_LEN,
};
use crate::error::{CryptoError, Result};

use super::identity::{Drk1Public, RecipientKeypair};
use super::wrap;

/// One §12.6 grant: a standalone §12.2 recipient sub-record (`rec_len = 1234`) wrapping the
/// object `KW` to one recipient. Bit-identical framing to an inline `kem_wrap` sub-record,
/// so a grant is standalone-decodable from `{recipient private key, fixed_head}`.
#[derive(Clone)]
pub struct GrantRecord {
    /// Exactly [`RECIP_SUBRECORD_LEN`] bytes (enforced by every constructor).
    bytes: Vec<u8>,
}

impl GrantRecord {
    /// Wrap raw sub-record bytes, rejecting anything that is not exactly one sub-record.
    pub(crate) fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() != RECIP_SUBRECORD_LEN {
            return Err(CryptoError::Format("grant record wrong size".into()));
        }
        Ok(Self { bytes })
    }

    /// The raw §12.2 sub-record bytes (length [`RECIP_SUBRECORD_LEN`]).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The recipient `key_id` this grant is sealed to (sub-record bytes `[4..36]`).
    #[must_use]
    pub fn key_id(&self) -> [u8; KEY_ID_LEN] {
        let mut id = [0u8; KEY_ID_LEN];
        // Length is guaranteed RECIP_SUBRECORD_LEN by construction.
        id.copy_from_slice(&self.bytes[4..4 + KEY_ID_LEN]);
        id
    }
}

/// A parsed, fully validated `DGS1` sidecar (§12.6). Every binding check has already
/// passed by the time this is returned, so a caller may trust `file_id`/`head_hash` bound
/// it to the intended object.
pub struct ParsedSidecar {
    /// Monotonic generation counter (higher wins on rewrite races).
    pub grant_gen: u64,
    /// The grant sub-records, in stored order.
    pub grants: Vec<GrantRecord>,
}

/// Serialize a `DGS1` sidecar (§12.6) for `file_id`, binding `head_bytes` via its
/// BLAKE3-256 hash, carrying `grant_gen` and the `grants` list. Rejects more than
/// [`MAX_GRANT_COUNT`] grants (the §12.6 `G ≤ 4096` bound).
pub fn serialize(
    file_id: &[u8; FILE_ID_LEN],
    head_bytes: &[u8; OBJECT_HEAD_LEN],
    grant_gen: u64,
    grants: &[GrantRecord],
) -> Result<Vec<u8>> {
    let g = grants.len();
    if g > MAX_GRANT_COUNT as usize {
        return Err(CryptoError::Format("grant_count exceeds 4096".into()));
    }
    let head_hash = blake3::hash(head_bytes);

    let mut out = Vec::with_capacity(GRANT_SIDECAR_HEADER_LEN + g * RECIP_SUBRECORD_LEN);
    out.extend_from_slice(&GRANT_SIDECAR_MAGIC);
    out.push(GRANT_SIDECAR_VERSION);
    out.push(KEM_SUITE_X25519_MLKEM768);
    out.extend_from_slice(&[0u8, 0u8]); // reserved MUST be 0
    out.extend_from_slice(file_id);
    out.extend_from_slice(head_hash.as_bytes());
    out.extend_from_slice(&grant_gen.to_le_bytes());
    out.extend_from_slice(&(g as u16).to_le_bytes());
    for grant in grants {
        if grant.bytes.len() != RECIP_SUBRECORD_LEN {
            return Err(CryptoError::Format("grant record wrong size".into()));
        }
        out.extend_from_slice(&grant.bytes);
    }
    debug_assert_eq!(
        out.len(),
        GRANT_SIDECAR_HEADER_LEN + g * RECIP_SUBRECORD_LEN
    );
    Ok(out)
}

/// Parse + fully validate a `DGS1` sidecar (§12.6). Rejects on ANY mismatch — bad
/// magic/version/hybrid_suite, non-zero reserved, `file_id != expected_file_id`,
/// `head_hash != BLAKE3-256(head_bytes)`, an over-long `grant_count`, an inexact overall
/// length, or a malformed grant sub-record — so a sidecar attached to the wrong object (or
/// tampered) can never yield a grant. On success returns `{grant_gen, grants}`.
pub fn parse(
    bytes: &[u8],
    expected_file_id: &[u8; FILE_ID_LEN],
    head_bytes: &[u8; OBJECT_HEAD_LEN],
) -> Result<ParsedSidecar> {
    if bytes.len() < GRANT_SIDECAR_HEADER_LEN {
        return Err(CryptoError::Format("DGS1 shorter than header".into()));
    }
    if bytes[0..4] != GRANT_SIDECAR_MAGIC {
        return Err(CryptoError::Format("bad DGS1 magic".into()));
    }
    if bytes[4] != GRANT_SIDECAR_VERSION {
        return Err(CryptoError::Format("unsupported DGS1 version".into()));
    }
    if bytes[5] != KEM_SUITE_X25519_MLKEM768 {
        return Err(CryptoError::Format("unsupported DGS1 hybrid_suite".into()));
    }
    if bytes[6] != 0 || bytes[7] != 0 {
        return Err(CryptoError::Format("DGS1 reserved bytes nonzero".into()));
    }
    // Structural binding: this sidecar must be for exactly this object's file_id + head.
    if bytes[8..8 + FILE_ID_LEN] != expected_file_id[..] {
        return Err(CryptoError::Format("DGS1 file_id mismatch".into()));
    }
    let expected_hash = *blake3::hash(head_bytes).as_bytes();
    if bytes[24..24 + HEAD_HASH_LEN] != expected_hash[..] {
        return Err(CryptoError::Format("DGS1 head_hash mismatch".into()));
    }
    let grant_gen = u64::from_le_bytes(
        bytes[56..64]
            .try_into()
            .map_err(|_| CryptoError::Format("DGS1 bad grant_gen".into()))?,
    );
    let grant_count = u16::from_le_bytes([bytes[64], bytes[65]]) as usize;
    if grant_count > MAX_GRANT_COUNT as usize {
        return Err(CryptoError::Format("DGS1 grant_count exceeds 4096".into()));
    }
    // Exact length: header + G · 1234, no trailing bytes.
    let expected_len = GRANT_SIDECAR_HEADER_LEN + grant_count * RECIP_SUBRECORD_LEN;
    if bytes.len() != expected_len {
        return Err(CryptoError::Format("DGS1 length != header + G·1234".into()));
    }
    let mut grants = Vec::with_capacity(grant_count);
    for i in 0..grant_count {
        let base = GRANT_SIDECAR_HEADER_LEN + i * RECIP_SUBRECORD_LEN;
        let rec = &bytes[base..base + RECIP_SUBRECORD_LEN];
        // Reuse the §12.2 field-length validation before trusting the record.
        wrap::parse_subrecord(rec)?;
        grants.push(GrantRecord::from_bytes(rec.to_vec())?);
    }
    Ok(ParsedSidecar { grant_gen, grants })
}

/// Seal the object wrapping key `kw` to `recipient` as a §12.6 grant — a §12.2 sub-record
/// bound to `head_bytes` (§12.1). Reuses the identical §12.2 encaps path used for inline
/// recipients, so a grant and an inline sub-record are byte-compatible.
pub fn seal_kw_to_recipient(
    kw: &[u8; KEY_LEN],
    recipient: &Drk1Public,
    head_bytes: &[u8; OBJECT_HEAD_LEN],
) -> Result<GrantRecord> {
    let bytes = wrap::encapsulate_to(recipient, head_bytes, kw)?;
    GrantRecord::from_bytes(bytes)
}

/// Recover the pre-DEK secret `KW` from a §12.6 grant using `keypair`'s private material,
/// binding to `head_bytes` (§12.1/§12.8). This yields `KW` itself (not the DEK) so a
/// manager can re-wrap it to new recipients. Reuses the §12.2 decaps path; the grant's
/// `key_id` MUST match `keypair` (a grant sealed to R opens only with R's key). `KW` is
/// returned zeroizing.
pub fn recover_kw_as_recipient(
    grant: &GrantRecord,
    keypair: &RecipientKeypair,
    head_bytes: &[u8; OBJECT_HEAD_LEN],
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let (grant_key_id, sub) = wrap::parse_subrecord(grant.as_bytes())?;
    if grant_key_id != keypair.key_id {
        return Err(CryptoError::Format(
            "grant key_id does not match this keypair".into(),
        ));
    }
    // Recipient static pubkeys are taken from the (trusted) keypair, matching the combiner
    // `info` used at seal time (§12.1); they are consistent with the private material.
    let r_x_pk = keypair.public.x_pk;
    let r_ek = keypair.public.ek;
    wrap::decapsulate_kw(
        &sub,
        keypair.x_sk(),
        keypair.dk(),
        &r_x_pk,
        &r_ek,
        &keypair.key_id,
        head_bytes,
    )
}

/// Recover `KW` from an object's **inline** §12.2 `kem_wrap` block (offset-70 bytes), if
/// this `keypair` is an inline recipient. `Ok(None)` means "no inline sub-record for this
/// identity" (the clean signal to try the sidecar); `Err` means a structural/tamper
/// failure that MUST propagate. This is the "try inline first" half of the §12.6
/// first-successful-recovery-wins rule.
pub fn recover_kw_from_block(
    keypair: &RecipientKeypair,
    head_bytes: &[u8; OBJECT_HEAD_LEN],
    kem_wrap_block: &[u8],
) -> Result<Option<Zeroizing<[u8; KEY_LEN]>>> {
    let kemwrap = wrap::KemWrap::parse(kem_wrap_block)?;
    let Some(sub) = kemwrap.find(&keypair.key_id) else {
        return Ok(None);
    };
    let r_x_pk = keypair.public.x_pk;
    let r_ek = keypair.public.ek;
    let kw = wrap::decapsulate_kw(
        &sub,
        keypair.x_sk(),
        keypair.dk(),
        &r_x_pk,
        &r_ek,
        &keypair.key_id,
        head_bytes,
    )?;
    Ok(Some(kw))
}

/// The `key_id` of every inline recipient in a §12.2 `kem_wrap` block, so a caller adding
/// sidecar grants can skip identities that are already inline recipients (dedup). Runs the
/// same structural validation as a reader before returning.
pub fn inline_key_ids(kem_wrap_block: &[u8]) -> Result<Vec<[u8; KEY_ID_LEN]>> {
    let kemwrap = wrap::KemWrap::parse(kem_wrap_block)?;
    Ok(kemwrap.key_ids())
}
