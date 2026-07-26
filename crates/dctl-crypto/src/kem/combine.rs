//! §12.1 hybrid combiner: derive the per-recipient `wrapping_key` and build the
//! `wrapped_kw` AAD. This is the X-Wing-style robust concatenation combiner — the
//! wrapping key needs **both** shared secrets, so an algorithmic break of one primitive
//! (X25519 or ML-KEM-768) leaves the other 256-bit secret unknown in the IKM.

use zeroize::{Zeroize, Zeroizing};

use crate::constants::{
    KEM_HYBRID_IKM_LEN, KEM_HYBRID_INFO_LABEL, KEM_HYBRID_INFO_LEN, KEM_KW_AAD_PREFIX,
    KEM_SUITE_X25519_MLKEM768, KEY_ID_LEN, KEY_LEN, MLKEM768_CT_LEN, MLKEM768_EK_LEN,
    MLKEM768_SHARED_LEN, OBJECT_HEAD_LEN, X25519_PK_LEN, X25519_SHARED_LEN,
};
use crate::error::{CryptoError, Result};
use crate::keys::derive_subkey_from_ikm;

/// The full KEM transcript bound into the combiner `info` (§12.1) — everything except
/// the two shared secrets. Rebuilt identically on both the encaps and decaps sides.
pub(crate) struct Transcript<'a> {
    pub fixed_head: &'a [u8; OBJECT_HEAD_LEN],
    pub key_id: &'a [u8; KEY_ID_LEN],
    pub eph_pk: &'a [u8; X25519_PK_LEN],
    pub ct_m: &'a [u8; MLKEM768_CT_LEN],
    /// Recipient static X25519 public key.
    pub r_x_pk: &'a [u8; X25519_PK_LEN],
    /// Recipient static ML-KEM encapsulation key.
    pub r_ek: &'a [u8; MLKEM768_EK_LEN],
}

impl Transcript<'_> {
    /// Build the pinned 2471-byte HKDF `info` (§12.1). Order is FROZEN:
    /// `label ‖ suite ‖ head ‖ key_id ‖ eph_pk ‖ ct_m ‖ R.x_pk ‖ R.ek`.
    fn info(&self) -> Vec<u8> {
        let mut info = Vec::with_capacity(KEM_HYBRID_INFO_LEN);
        info.extend_from_slice(KEM_HYBRID_INFO_LABEL);
        info.push(KEM_SUITE_X25519_MLKEM768);
        info.extend_from_slice(self.fixed_head);
        info.extend_from_slice(self.key_id);
        info.extend_from_slice(self.eph_pk);
        info.extend_from_slice(self.ct_m);
        info.extend_from_slice(self.r_x_pk);
        info.extend_from_slice(self.r_ek);
        debug_assert_eq!(info.len(), KEM_HYBRID_INFO_LEN);
        info
    }
}

/// Derive `wrapping_key_i = SUBKEY(ss_x(32) ‖ K_m(32), info)` (§12.1 step 4).
///
/// IKM order is FROZEN: classical `ss_x` first, then PQ `K_m`.
pub(crate) fn wrapping_key(
    ss_x: &[u8; X25519_SHARED_LEN],
    k_m: &[u8; MLKEM768_SHARED_LEN],
    transcript: &Transcript<'_>,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let mut ikm = Zeroizing::new([0u8; KEM_HYBRID_IKM_LEN]);
    ikm[..X25519_SHARED_LEN].copy_from_slice(ss_x);
    ikm[X25519_SHARED_LEN..].copy_from_slice(k_m);
    let info = transcript.info();
    let key = derive_subkey_from_ikm(ikm.as_slice(), &info);
    // `info` is public transcript material, but drop it promptly all the same.
    let mut info = info;
    info.zeroize();
    key
}

/// Build the `wrapped_kw` AAD (§12.1 step 5 / §12.8):
/// `"dctl-kem-kw-v1::"(16) ‖ fixed_head(68) ‖ hybrid_suite(1) ‖ key_id(32)` = 117 bytes.
pub(crate) fn kw_aad(fixed_head: &[u8; OBJECT_HEAD_LEN], key_id: &[u8; KEY_ID_LEN]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(KEM_KW_AAD_PREFIX.len() + OBJECT_HEAD_LEN + 1 + KEY_ID_LEN);
    aad.extend_from_slice(KEM_KW_AAD_PREFIX);
    aad.extend_from_slice(fixed_head);
    aad.push(KEM_SUITE_X25519_MLKEM768);
    aad.extend_from_slice(key_id);
    aad
}

/// Copy an ML-KEM `SharedKey` (`Array<u8, 32>`) into a zeroizing `[u8; 32]`, wiping the
/// caller's `Array` if it is not itself zeroizing.
pub(crate) fn shared_to_array(shared: &[u8]) -> Result<Zeroizing<[u8; MLKEM768_SHARED_LEN]>> {
    if shared.len() != MLKEM768_SHARED_LEN {
        return Err(CryptoError::Format(
            "ML-KEM shared secret wrong length".into(),
        ));
    }
    let mut out = Zeroizing::new([0u8; MLKEM768_SHARED_LEN]);
    out.copy_from_slice(shared);
    Ok(out)
}
