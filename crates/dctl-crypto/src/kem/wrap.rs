//! §12.2 `kem_wrap` block `DKW1`: per-recipient hybrid encaps/decaps and the
//! serialize / structurally-validate-then-parse of the inline recipient list.
//!
//! Every framed length here is a pinned constant, cross-checked against `rec_len` and
//! the block length, and every payload is AEAD- or transcript-bound (§12.2), so a
//! malformed or reordered list can only deny service — never break confidentiality.

use ml_kem::{B32, Ciphertext, EncapsulateDeterministic, MlKem768, kem::Decapsulate};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::aead;
use crate::constants::{
    KEM_SUITE_X25519_MLKEM768, KEM_WRAP_FLAG_SIDECAR, KEM_WRAP_HEADER_LEN, KEM_WRAP_MAGIC,
    KEM_WRAP_VERSION, KEY_ID_LEN, KEY_LEN, MAX_RECIP_COUNT, MLKEM768_CT_LEN, MLKEM768_EK_LEN,
    OBJECT_HEAD_LEN, RECIP_SUBRECORD_LEN, WRAPPED_KW_LEN, X25519_PK_LEN,
};
use crate::error::{CryptoError, Result};
use crate::rng;

use super::combine::{self, Transcript};
use super::identity::{Drk1Public, MlKemDecapKey};

/// How many fresh ephemerals to try before declaring a recipient X25519 key low-order.
/// A valid key passes on the first attempt; only a low-order/all-zero recipient `x_pk`
/// ever fails the contributory check, and it fails every time — so this both satisfies
/// §12.1 step 2 ("regenerate") and rejects a malicious low-order recipient key.
const MAX_EPH_ATTEMPTS: u8 = 8;

/// Encapsulate the object wrapping key `kw` to one recipient, producing its 1234-byte
/// `kem_wrap` sub-record (§12.1 encaps + §12.2 sub-record layout).
pub(crate) fn encapsulate_to(
    recipient: &Drk1Public,
    fixed_head: &[u8; OBJECT_HEAD_LEN],
    kw: &[u8; KEY_LEN],
) -> Result<Vec<u8>> {
    let key_id = recipient.key_id();

    // ── Classical leg: fresh ephemeral X25519 with the mandatory contributory check. ──
    let their_pk = PublicKey::from(recipient.x_pk);
    let mut chosen: Option<([u8; X25519_PK_LEN], x25519_dalek::SharedSecret)> = None;
    for _ in 0..MAX_EPH_ATTEMPTS {
        let mut eph_bytes = Zeroizing::new([0u8; X25519_PK_LEN]);
        rng::fill(eph_bytes.as_mut());
        let eph_sk = StaticSecret::from(*eph_bytes); // clamps
        let ss_x = eph_sk.diffie_hellman(&their_pk);
        if ss_x.was_contributory() {
            let eph_pk = PublicKey::from(&eph_sk).to_bytes();
            chosen = Some((eph_pk, ss_x));
            break;
        }
        // Non-contributory ⇒ all-zero/low-order; discard and regenerate (§12.1 step 2).
    }
    let (eph_pk, ss_x) = chosen.ok_or_else(|| {
        CryptoError::Format("recipient X25519 key is low-order (non-contributory)".into())
    })?;

    // ── PQ leg: derandomized ML-KEM-768 Encaps_internal(ek, m), m = 32 CSPRNG bytes. ──
    let mut m_bytes = Zeroizing::new([0u8; 32]);
    rng::fill(m_bytes.as_mut());
    let mut m = B32::from(*m_bytes);
    let ml_ek = recipient.ml_ek()?;
    let (ct_arr, mut k_m_arr) = ml_ek
        .encapsulate_deterministic(&m)
        .map_err(|_| CryptoError::Format("ML-KEM encapsulation failed".into()))?;
    m.as_mut_slice().zeroize(); // wipe the ML-KEM encaps randomness
    let mut ct_m = [0u8; MLKEM768_CT_LEN];
    ct_m.copy_from_slice(ct_arr.as_slice());
    let k_m = combine::shared_to_array(k_m_arr.as_slice())?;
    k_m_arr.as_mut_slice().zeroize(); // the crate's SharedKey Array is not auto-wiped

    // ── Hybrid combine → wrapping_key_i, then AEAD-wrap KW. ──
    let transcript = Transcript {
        fixed_head,
        key_id: &key_id,
        eph_pk: &eph_pk,
        ct_m: &ct_m,
        r_x_pk: &recipient.x_pk,
        r_ek: &recipient.ek,
    };
    let wrapping_key = combine::wrapping_key(ss_x.as_bytes(), &k_m, &transcript)?;
    let aad = combine::kw_aad(fixed_head, &key_id);
    let wrapped_kw = aead::encrypt(&wrapping_key, kw, &aad)?;
    if wrapped_kw.len() != WRAPPED_KW_LEN {
        return Err(CryptoError::Format("wrapped_kw wrong size".into()));
    }

    Ok(build_subrecord(&key_id, &ct_m, &eph_pk, &wrapped_kw))
}

/// Assemble a recipient sub-record (§12.2), all integers little-endian.
fn build_subrecord(
    key_id: &[u8; KEY_ID_LEN],
    ct_m: &[u8; MLKEM768_CT_LEN],
    eph_pk: &[u8; X25519_PK_LEN],
    wrapped_kw: &[u8],
) -> Vec<u8> {
    let mut rec = Vec::with_capacity(RECIP_SUBRECORD_LEN);
    rec.extend_from_slice(&(RECIP_SUBRECORD_LEN as u32).to_le_bytes());
    rec.extend_from_slice(key_id);
    rec.extend_from_slice(&(MLKEM768_CT_LEN as u16).to_le_bytes());
    rec.extend_from_slice(ct_m);
    rec.extend_from_slice(&(X25519_PK_LEN as u16).to_le_bytes());
    rec.extend_from_slice(eph_pk);
    rec.extend_from_slice(&(WRAPPED_KW_LEN as u16).to_le_bytes());
    rec.extend_from_slice(wrapped_kw);
    debug_assert_eq!(rec.len(), RECIP_SUBRECORD_LEN);
    rec
}

/// Serialize a full `DKW1` `kem_wrap` block from N ready sub-records (§12.2).
/// Caller guarantees `1 ≤ N ≤ 53` and each record is `RECIP_SUBRECORD_LEN` bytes.
pub(crate) fn serialize_block(sub_records: &[Vec<u8>]) -> Result<Vec<u8>> {
    let n = sub_records.len();
    if n == 0 || n > MAX_RECIP_COUNT as usize {
        return Err(CryptoError::Format(
            "recip_count out of range (1..=53)".into(),
        ));
    }
    let mut out = Vec::with_capacity(KEM_WRAP_HEADER_LEN + n * RECIP_SUBRECORD_LEN);
    out.extend_from_slice(&KEM_WRAP_MAGIC);
    out.push(KEM_WRAP_VERSION);
    out.push(KEM_SUITE_X25519_MLKEM768);
    out.push(0u8); // kw_flags = 0 (no sidecar advertised inline)
    out.push(0u8); // reserved
    out.extend_from_slice(&(n as u16).to_le_bytes());
    for rec in sub_records {
        if rec.len() != RECIP_SUBRECORD_LEN {
            return Err(CryptoError::Format("sub-record wrong size".into()));
        }
        out.extend_from_slice(rec);
    }
    Ok(out)
}

/// One structurally-validated recipient sub-record (borrowed from the block). The
/// `key_id` is not carried here — matching happens in [`KemWrap::find`] and the caller
/// passes the authoritative `key_id` (derived from its own private key) to decaps.
pub(crate) struct SubRecord<'a> {
    pub ct_m: &'a [u8],
    pub eph_pk: &'a [u8],
    pub wrapped_kw: &'a [u8],
}

/// A parsed, fully validated `DKW1` block (§12.2).
pub(crate) struct KemWrap<'a> {
    block: &'a [u8],
    count: usize,
}

impl<'a> KemWrap<'a> {
    /// Parse + run the MANDATORY structural validation (§12.2) before any crypto: magic,
    /// version, suite, reserved, `kw_flags`, `recip_count` bound, and every field-length
    /// constant. `block` must be exactly the `kem_ct_len` bytes at object offset 70.
    pub(crate) fn parse(block: &'a [u8]) -> Result<Self> {
        if block.len() < KEM_WRAP_HEADER_LEN {
            return Err(CryptoError::Format("kem_wrap shorter than header".into()));
        }
        if block[0..4] != KEM_WRAP_MAGIC {
            return Err(CryptoError::Format("bad kem_wrap magic".into()));
        }
        if block[4] != KEM_WRAP_VERSION {
            return Err(CryptoError::Format("unsupported kw_version".into()));
        }
        if block[5] != KEM_SUITE_X25519_MLKEM768 {
            return Err(CryptoError::Format("unsupported hybrid_suite".into()));
        }
        // bit0 (sidecar) is the only defined flag; any other bit is reserved-CRITICAL.
        if block[6] & !KEM_WRAP_FLAG_SIDECAR != 0 {
            return Err(CryptoError::Format("unknown kw_flags bit set".into()));
        }
        if block[7] != 0 {
            return Err(CryptoError::Format("kem_wrap reserved byte nonzero".into()));
        }
        let count = u16::from_le_bytes([block[8], block[9]]) as usize;
        if count == 0 || count > MAX_RECIP_COUNT as usize {
            return Err(CryptoError::Format(
                "recip_count out of range (1..=53)".into(),
            ));
        }
        // kem_ct_len == 10 + Σ rec_len, with every rec_len == 1234 (suite 1).
        let expected = KEM_WRAP_HEADER_LEN + count * RECIP_SUBRECORD_LEN;
        if block.len() != expected {
            return Err(CryptoError::Format("kem_ct_len != 10 + Σ rec_len".into()));
        }
        // Validate every sub-record's length constants up front (before any crypto).
        for i in 0..count {
            let base = KEM_WRAP_HEADER_LEN + i * RECIP_SUBRECORD_LEN;
            validate_subrecord_fields(&block[base..base + RECIP_SUBRECORD_LEN])?;
        }
        Ok(Self { block, count })
    }

    /// Locate the sub-record for `key_id` (order is not significant, §12.2). Returns
    /// `None` when this reader holds no matching identity (expected — not a recipient).
    pub(crate) fn find(&self, key_id: &[u8; KEY_ID_LEN]) -> Option<SubRecord<'a>> {
        for i in 0..self.count {
            let base = KEM_WRAP_HEADER_LEN + i * RECIP_SUBRECORD_LEN;
            let rec = &self.block[base..base + RECIP_SUBRECORD_LEN];
            let rec_key_id = &rec[4..4 + KEY_ID_LEN];
            if rec_key_id == &key_id[..] {
                return Some(slice_subrecord(rec));
            }
        }
        None
    }
}

/// Validate the fixed field-length constants of one sub-record (§12.2). All four inner
/// length fields MUST equal their suite-1 constants exactly; any deviation ⇒ reject.
fn validate_subrecord_fields(rec: &[u8]) -> Result<()> {
    // Length is guaranteed RECIP_SUBRECORD_LEN by the caller's slicing.
    let rec_len = u32::from_le_bytes([rec[0], rec[1], rec[2], rec[3]]) as usize;
    if rec_len != RECIP_SUBRECORD_LEN {
        return Err(CryptoError::Format("rec_len != 1234".into()));
    }
    let ct_m_len = u16::from_le_bytes([rec[36], rec[37]]) as usize;
    if ct_m_len != MLKEM768_CT_LEN {
        return Err(CryptoError::Format("ct_m_len != 1088".into()));
    }
    let eph_pk_len = u16::from_le_bytes([rec[1126], rec[1127]]) as usize;
    if eph_pk_len != X25519_PK_LEN {
        return Err(CryptoError::Format("eph_pk_len != 32".into()));
    }
    let wrapped_len = u16::from_le_bytes([rec[1160], rec[1161]]) as usize;
    if wrapped_len != WRAPPED_KW_LEN {
        return Err(CryptoError::Format("wrapped_len != 72".into()));
    }
    Ok(())
}

/// Slice a validated sub-record into its fields (offsets are the §12.2 constants).
fn slice_subrecord(rec: &[u8]) -> SubRecord<'_> {
    SubRecord {
        ct_m: &rec[38..38 + MLKEM768_CT_LEN],          // 38..1126
        eph_pk: &rec[1128..1128 + X25519_PK_LEN],      // 1128..1160
        wrapped_kw: &rec[1162..1162 + WRAPPED_KW_LEN], // 1162..1234
    }
}

/// Decapsulate one matched sub-record → the 32-byte object wrapping key `KW` (§12.1
/// decaps). ML-KEM uses implicit rejection (always returns a `K_m`); the `wrapped_kw`
/// AEAD tag is the ONLY accept gate — a wrong/tampered record surfaces as an AEAD error.
#[allow(clippy::too_many_arguments)]
pub(crate) fn decapsulate_kw(
    sub: &SubRecord<'_>,
    x_sk: &StaticSecret,
    dk: &MlKemDecapKey,
    r_x_pk: &[u8; X25519_PK_LEN],
    r_ek: &[u8; MLKEM768_EK_LEN],
    key_id: &[u8; KEY_ID_LEN],
    fixed_head: &[u8; OBJECT_HEAD_LEN],
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    // Classical: ss_x = X25519(x_sk, eph_pk). No contributory check on decaps — the
    // AEAD tag is the sole gate, so a bad eph_pk simply fails Open (no oracle).
    let mut eph_pk = [0u8; X25519_PK_LEN];
    eph_pk.copy_from_slice(sub.eph_pk);
    let ss_x = x_sk.diffie_hellman(&PublicKey::from(eph_pk));

    // PQ: K_m = Decaps_internal(dk, ct_m) (implicit rejection → always 32 bytes).
    let ct = Ciphertext::<MlKem768>::try_from(sub.ct_m)
        .map_err(|_| CryptoError::Format("ct_m wrong length".into()))?;
    let mut k_m_arr = dk
        .decapsulate(&ct)
        .map_err(|_| CryptoError::Format("ML-KEM decapsulation error".into()))?;
    let k_m = combine::shared_to_array(k_m_arr.as_slice())?;
    k_m_arr.as_mut_slice().zeroize(); // the crate's SharedKey Array is not auto-wiped

    let mut ct_m = [0u8; MLKEM768_CT_LEN];
    ct_m.copy_from_slice(sub.ct_m);
    let transcript = Transcript {
        fixed_head,
        key_id,
        eph_pk: &eph_pk,
        ct_m: &ct_m,
        r_x_pk,
        r_ek,
    };
    let wrapping_key = combine::wrapping_key(ss_x.as_bytes(), &k_m, &transcript)?;
    let aad = combine::kw_aad(fixed_head, key_id);
    let kw_pt = aead::decrypt(&wrapping_key, sub.wrapped_kw, &aad)?;
    if kw_pt.len() != KEY_LEN {
        return Err(CryptoError::Format("unwrapped KW wrong length".into()));
    }
    let mut kw = Zeroizing::new([0u8; KEY_LEN]);
    kw.copy_from_slice(&kw_pt);
    // ct_m copy is public transcript material; wipe defensively (borrow ended above).
    ct_m.zeroize();
    Ok(kw)
}
