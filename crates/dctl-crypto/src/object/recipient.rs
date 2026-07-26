//! DSF1 `kem_id=1` recipient-hybrid seal / open (§12).
//!
//! `seal_to_recipients` wraps the DEK once under a fresh per-object `KW` (the §3
//! `wrapped_dek`, unchanged bytes — only the key is `KW` instead of the root) and
//! independently hybrid-wraps `KW` to each recipient in the `DKW1` `kem_wrap` block, so
//! every recipient recovers the same `KW → DEK → payload`. `open_as_recipient` reverses
//! it for a private-key holder. DSF1 framing is unchanged; the block sits at offset 70,
//! then `wrapped_dek` at `70 + K` (§3/§12.2).

use ml_kem::EncodedSizeUser;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::constants::{
    KEM_ID_HYBRID, KEY_ID_LEN, MAX_RECIP_COUNT, MLKEM768_EK_LEN, OBJECT_HEAD_LEN, X25519_PK_LEN,
};
use crate::error::{CryptoError, Result};
use crate::kem::identity::{Drk1Public, MlKemDecapKey};
use crate::kem::{self};
use crate::keys::generate_key;

use super::head::parse_head;
use super::meta::Metadata;
use super::seal::{Opened, open_core, seal_core};

/// Seal `plaintext` + `meta` into a DSF1 object readable by every recipient in
/// `recipients` (§12, `kem_id=1`). Each recipient independently unwraps the same DEK.
/// `1 ≤ recipients.len() ≤ 53` (the §3 `kem_ct_len ≤ 65535` bound).
///
/// Durability note (§12.8, NORMATIVE for write-only backup): a caller SHOULD include the
/// vault owner's own root-derived recipient identity among `recipients`, since a
/// `kem_id=1` object has no symmetric fallback. This function encrypts to exactly the
/// identities it is given and does not add one implicitly.
pub fn seal_to_recipients(
    recipients: &[Drk1Public],
    plaintext: &[u8],
    meta: &Metadata,
    chunk_size: u32,
) -> Result<Vec<u8>> {
    let n = recipients.len();
    if n == 0 || n > MAX_RECIP_COUNT as usize {
        return Err(CryptoError::Format(
            "recipient count out of range (1..=53)".into(),
        ));
    }

    // Per-object wrapping key: fresh CSPRNG, wraps the DEK exactly once, never reused.
    let kw = generate_key();

    seal_core(
        KEM_ID_HYBRID,
        &kw,
        |fixed_head| {
            let mut sub_records = Vec::with_capacity(n);
            for r in recipients {
                sub_records.push(kem::encapsulate_to(r, fixed_head, &kw)?);
            }
            kem::serialize_block(&sub_records)
        },
        plaintext,
        meta,
        chunk_size,
    )
}

/// Open a `kem_id=1` DSF1 object as the recipient holding `(x_sk, dk)` with identity
/// `key_id` (§12). Recovers `KW` from the matching `kem_wrap` sub-record, then decodes
/// exactly like the symmetric path. Returns an error if this identity is not a recipient
/// (no matching `key_id`) or if any tag fails (the AEAD tag is the only accept gate).
///
/// `key_id` MUST be the key-id of the supplied keypair; it is re-derived from `(x_sk,
/// dk)` and checked, so a mismatched handle is rejected up front.
pub fn open_as_recipient(
    x_sk: &StaticSecret,
    dk: &MlKemDecapKey,
    key_id: &[u8; KEY_ID_LEN],
    blob: &[u8],
) -> Result<Opened> {
    let head = parse_head(blob)?;
    if head.kem_id != KEM_ID_HYBRID {
        return Err(CryptoError::Format(
            "not a kem_id=1 object (use object::open for kem_id=0)".into(),
        ));
    }

    // Recipient's own static public keys (authoritative — derived from the private key
    // material, not trusted from the object). These feed the combiner `info` (§12.1).
    let r_x_pk: [u8; X25519_PK_LEN] = PublicKey::from(x_sk).to_bytes();
    let mut r_ek = [0u8; MLKEM768_EK_LEN];
    r_ek.copy_from_slice(dk.encapsulation_key().as_bytes().as_slice());
    let derived = Drk1Public {
        x_pk: r_x_pk,
        ek: r_ek,
    };
    if derived.key_id() != *key_id {
        return Err(CryptoError::Format(
            "key_id does not match the provided keypair".into(),
        ));
    }

    // Read the kem_wrap block: kem_ct_len (u16 LE) at offset 68, block at offset 70.
    let kem_ct_len = read_u16(blob, OBJECT_HEAD_LEN)? as usize;
    let block_start = OBJECT_HEAD_LEN + 2;
    let block_end = block_start
        .checked_add(kem_ct_len)
        .ok_or_else(|| CryptoError::Format("kem_ct_len overflow".into()))?;
    if block_end > blob.len() {
        return Err(CryptoError::Format("object truncated (kem_wrap)".into()));
    }
    let block = &blob[block_start..block_end];

    let mut fixed_head = [0u8; OBJECT_HEAD_LEN];
    fixed_head.copy_from_slice(&blob[0..OBJECT_HEAD_LEN]);

    // Structural validation (§12.2) runs inside parse, before any crypto.
    let kem_wrap = kem::KemWrap::parse(block)?;
    let sub = kem_wrap.find(key_id).ok_or_else(|| {
        CryptoError::Format("no kem_wrap sub-record for this key_id (not a recipient)".into())
    })?;

    let kw = kem::decapsulate_kw(&sub, x_sk, dk, &r_x_pk, &r_ek, key_id, &fixed_head)?;

    // wrapped_dek follows the block at offset 70 + K.
    open_core(&kw, blob, &head, block_end)
}

fn read_u16(b: &[u8], off: usize) -> Result<u16> {
    if off + 2 > b.len() {
        return Err(CryptoError::Format("object truncated (u16)".into()));
    }
    Ok(u16::from_le_bytes([b[off], b[off + 1]]))
}
