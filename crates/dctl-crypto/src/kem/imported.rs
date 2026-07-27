//! §13 imported-key store `DIK1`: a root-sealed container holding one **imported**
//! (non-root-derived) recipient keypair, so a vault can also decrypt objects sealed to that
//! external identity (multi-identity, §12.4). One `DIK1` per keypair lives at backend key
//! `"k/" ‖ hex(key_id)`.
//!
//! No new primitive: the private material is sealed with the pinned §1 `SUBKEY` +
//! XChaCha20-Poly1305 — exactly like every other DCTL wrap — and is offline-restorable from
//! the vault root alone.
//!
//! ```text
//! Off    Size  Field  (cleartext header)
//! 0      4     magic         "DIK1"
//! 4      1     version       0x01
//! 5      1     hybrid_suite  0x01 (unknown ⇒ reject THIS entry, §8)
//! 6      2     reserved      0x0000 (MUST be 0)
//! 8      32    key_id        §12.3 key_id recomputed from the imported PUBLIC keys
//! ── sealed body: XChaCha20-Poly1305(k_wrap, plaintext) ──
//! 40     24    nonce         fresh CSPRNG per write
//! 64     3648  ct            AEAD ciphertext of the 3648-byte plaintext
//! 3712   16    tag           Poly1305 tag
//! ```
//! `k_wrap = SUBKEY(root, "dctl-ik-wrap-v1" ‖ key_id)`;
//! `AAD = "dctl-ik-v1::" ‖ magic(4) ‖ hybrid_suite(1) ‖ key_id(32)` (49 bytes).
//!
//! Sealed plaintext (3648 bytes): `x_sk(32) ‖ dk(2400) ‖ x_pk(32) ‖ ek(1184)`.

use ml_kem::{B32, EncodedSizeUser, KemCore, MlKem768};
use x25519_dalek::StaticSecret;
use zeroize::{Zeroize, Zeroizing};

use crate::aead;
use crate::constants::{
    DIK1_HEADER_LEN, DIK1_LEN, DIK1_PLAINTEXT_LEN, IK_AAD_PREFIX, IK_WRAP_LABEL,
    IMPORTED_KEY_MAGIC, IMPORTED_KEY_VERSION, KEM_SUITE_X25519_MLKEM768, KEY_ID_LEN, KEY_LEN,
    MLKEM768_DK_LEN, MLKEM768_EK_LEN, X25519_PK_LEN, X25519_SK_LEN,
};
use crate::error::{CryptoError, Result};
use crate::keys::derive_subkey;
use crate::rng;

use super::identity::{MlKemDecapKey, RecipientKeypair};

// Field offsets inside the 3648-byte sealed plaintext.
const PT_X_SK: usize = 0;
const PT_DK: usize = PT_X_SK + X25519_SK_LEN; // 32
const PT_X_PK: usize = PT_DK + MLKEM768_DK_LEN; // 2432
const PT_EK: usize = PT_X_PK + X25519_PK_LEN; // 2464

/// Generate a fresh **external** (non-root-derived) recipient keypair with its computed
/// `key_id` (§12.3). The X25519 secret and the ML-KEM-768 `(d, z)` seeds are drawn from the
/// OS CSPRNG, so the resulting identity is independent of any vault root — the case a `DIK1`
/// import exists for. The public identity is recomputed from the private material, so the
/// returned keypair is always self-consistent.
#[must_use]
pub fn generate_external() -> RecipientKeypair {
    // Classical leg: fresh X25519 static secret (StaticSecret clamps on use).
    let mut x_bytes = Zeroizing::new([0u8; X25519_SK_LEN]);
    rng::fill(x_bytes.as_mut());
    let x_sk = StaticSecret::from(*x_bytes);

    // PQ leg: fresh ML-KEM-768 keypair via random KeyGen seeds (d, z).
    let mut d = Zeroizing::new([0u8; 32]);
    let mut z = Zeroizing::new([0u8; 32]);
    rng::fill(d.as_mut());
    rng::fill(z.as_mut());
    let mut d_b32 = B32::from(*d);
    let mut z_b32 = B32::from(*z);
    let (dk, _ek) = MlKem768::generate_deterministic(&d_b32, &z_b32);
    d_b32.as_mut_slice().zeroize();
    z_b32.as_mut_slice().zeroize();

    RecipientKeypair::from_private(x_sk, dk)
}

/// Derive the entry-specific imported-key wrapping key `k_wrap = SUBKEY(root,
/// "dctl-ik-wrap-v1" ‖ key_id)` (§13). Folding `key_id` makes distinct imported keys never
/// share a wrapping key, so a fresh 24-byte nonce per write can never repeat a `(key,
/// nonce)` pair.
fn derive_k_wrap(
    root: &[u8; KEY_LEN],
    key_id: &[u8; KEY_ID_LEN],
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let mut info = Vec::with_capacity(IK_WRAP_LABEL.len() + KEY_ID_LEN);
    info.extend_from_slice(IK_WRAP_LABEL);
    info.extend_from_slice(key_id);
    derive_subkey(root, &info)
}

/// Build the sealed-body AAD (§13): `"dctl-ik-v1::"(12) ‖ magic(4) ‖ hybrid_suite(1) ‖
/// key_id(32)` = 49 bytes. Binds the body to its container magic, suite, and identity.
fn body_aad(key_id: &[u8; KEY_ID_LEN]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(IK_AAD_PREFIX.len() + 4 + 1 + KEY_ID_LEN);
    aad.extend_from_slice(IK_AAD_PREFIX);
    aad.extend_from_slice(&IMPORTED_KEY_MAGIC);
    aad.push(KEM_SUITE_X25519_MLKEM768);
    aad.extend_from_slice(key_id);
    aad
}

/// Serialize `keypair` into a root-sealed 3728-byte `DIK1` container (§13). The private
/// `(x_sk, dk)` and public `(x_pk, ek)` are AEAD-sealed under the root-derived `k_wrap` with
/// a fresh nonce and the exact §13 AAD; the cleartext header carries the recomputed `key_id`.
pub fn serialize_dik1(root: &[u8; KEY_LEN], keypair: &RecipientKeypair) -> Result<[u8; DIK1_LEN]> {
    let key_id = keypair.key_id;
    let k_wrap = derive_k_wrap(root, &key_id)?;

    // Assemble the 3648-byte plaintext: x_sk ‖ dk ‖ x_pk ‖ ek. Wiped on drop.
    let mut plaintext = Zeroizing::new(vec![0u8; DIK1_PLAINTEXT_LEN]);
    plaintext[PT_X_SK..PT_DK].copy_from_slice(&keypair.x_sk().to_bytes());
    plaintext[PT_DK..PT_X_PK].copy_from_slice(keypair.dk().as_bytes().as_slice());
    plaintext[PT_X_PK..PT_EK].copy_from_slice(&keypair.public.x_pk);
    plaintext[PT_EK..DIK1_PLAINTEXT_LEN].copy_from_slice(&keypair.public.ek);

    let aad = body_aad(&key_id);
    // `aead::encrypt` returns nonce(24) ‖ ct(3648) ‖ tag(16) = 3688 bytes.
    let sealed = aead::encrypt(&k_wrap, plaintext.as_slice(), &aad)?;
    if sealed.len() != DIK1_LEN - DIK1_HEADER_LEN {
        return Err(CryptoError::Format("DIK1 sealed body wrong size".into()));
    }

    let mut out = [0u8; DIK1_LEN];
    out[0..4].copy_from_slice(&IMPORTED_KEY_MAGIC);
    out[4] = IMPORTED_KEY_VERSION;
    out[5] = KEM_SUITE_X25519_MLKEM768;
    // reserved [6..8] already zero.
    out[8..DIK1_HEADER_LEN].copy_from_slice(&key_id);
    out[DIK1_HEADER_LEN..].copy_from_slice(&sealed);
    Ok(out)
}

/// Parse + fully validate a `DIK1` container (§13), returning the imported recipient
/// keypair. Verifies `magic`/`version`/`hybrid_suite`/`reserved`, derives `k_wrap` from the
/// root and the header `key_id`, AEAD-opens the body (the tag is the sole accept gate), and
/// runs the MANDATORY self-consistency check: the public keys recovered from the body must
/// reproduce a `key_id` equal to the header `key_id`. Never panics; unknown `version` /
/// `hybrid_suite` and a non-zero `reserved` each surface as their own distinct error so the
/// caller can skip the entry per §8. Secrets live only in `Zeroizing` buffers.
pub fn parse_dik1(root: &[u8; KEY_LEN], bytes: &[u8]) -> Result<RecipientKeypair> {
    if bytes.len() != DIK1_LEN {
        return Err(CryptoError::Format("DIK1 wrong length".into()));
    }
    if bytes[0..4] != IMPORTED_KEY_MAGIC {
        return Err(CryptoError::Format("bad DIK1 magic".into()));
    }
    if bytes[4] != IMPORTED_KEY_VERSION {
        return Err(CryptoError::Format("unsupported DIK1 version".into()));
    }
    if bytes[5] != KEM_SUITE_X25519_MLKEM768 {
        return Err(CryptoError::Format("unsupported DIK1 hybrid_suite".into()));
    }
    if bytes[6] != 0 || bytes[7] != 0 {
        return Err(CryptoError::Format("DIK1 reserved bytes nonzero".into()));
    }
    let mut header_key_id = [0u8; KEY_ID_LEN];
    header_key_id.copy_from_slice(&bytes[8..DIK1_HEADER_LEN]);

    let k_wrap = derive_k_wrap(root, &header_key_id)?;
    let aad = body_aad(&header_key_id);
    // Open nonce(24) ‖ ct(3648) ‖ tag(16); the AEAD tag is the sole accept gate.
    let plaintext = aead::decrypt(&k_wrap, &bytes[DIK1_HEADER_LEN..], &aad)?;
    if plaintext.len() != DIK1_PLAINTEXT_LEN {
        return Err(CryptoError::Format("DIK1 plaintext wrong length".into()));
    }

    // Reconstruct the private material.
    let mut x_sk_bytes = Zeroizing::new([0u8; X25519_SK_LEN]);
    x_sk_bytes.copy_from_slice(&plaintext[PT_X_SK..PT_DK]);
    let x_sk = StaticSecret::from(*x_sk_bytes);

    let enc = ml_kem::Encoded::<MlKemDecapKey>::try_from(&plaintext[PT_DK..PT_X_PK])
        .map_err(|_| CryptoError::Format("DIK1 bad ML-KEM dk length".into()))?;
    let dk = MlKemDecapKey::from_bytes(&enc);

    // Recompute the public identity from the private material; this is the canonical
    // key_id (§12.3). from_private derives x_pk = X25519(x_sk, 9) and ek from dk.
    let keypair = RecipientKeypair::from_private(x_sk, dk);

    // Self-consistency (MANDATORY, §13 step 3): the recomputed public keys must match the
    // stored public keys, and the recomputed key_id must equal the header key_id. Any
    // mismatch ⇒ reject the entry. (The stored x_pk/ek being redundant with the recompute
    // is exactly what lets us catch a self-inconsistent import — a writer SHOULD verify
    // x_pk == X25519(x_sk, 9) and that ek matches dk before importing.)
    if keypair.public.x_pk[..] != plaintext[PT_X_PK..PT_EK] {
        return Err(CryptoError::Format(
            "DIK1 x_pk does not match X25519(x_sk, 9)".into(),
        ));
    }
    if keypair.public.ek[..] != plaintext[PT_EK..DIK1_PLAINTEXT_LEN] {
        return Err(CryptoError::Format(
            "DIK1 ek does not match the embedded ML-KEM dk".into(),
        ));
    }
    if keypair.key_id != header_key_id {
        return Err(CryptoError::Format(
            "DIK1 key_id != recompute(pubkeys)".into(),
        ));
    }
    // Touch the length constants so a size drift is caught at compile time by the asserts
    // in `constants` and here at the type level.
    debug_assert_eq!(keypair.public.ek.len(), MLKEM768_EK_LEN);
    Ok(keypair)
}
