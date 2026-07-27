//! §13 imported-key store `DIK1`: serialize→parse round-trip under a root, byte-exact
//! container framing, and rejection of a wrong root, tampered header/reserved bytes, an
//! unknown version/suite, a self-inconsistent body, and a `key_id ≠ recompute(pubkeys)`.

use dctl_crypto::aead;
use dctl_crypto::constants::{
    DIK1_HEADER_LEN, DIK1_LEN, DIK1_PLAINTEXT_LEN, IK_AAD_PREFIX, IK_WRAP_LABEL,
    IMPORTED_KEY_MAGIC, IMPORTED_KEY_VERSION, KEM_SUITE_X25519_MLKEM768, MLKEM768_DK_LEN,
};
use dctl_crypto::kem::{generate_external, parse_dik1, serialize_dik1};
use dctl_crypto::keys::{self, derive_subkey};
use ml_kem::EncodedSizeUser;

/// Hand-craft a `DIK1` container so a test can decouple the header `key_id`, the wrapping
/// key, and the body's public keys — reproducing the exact frozen §13 seal with public
/// building blocks (`derive_subkey` + `aead::encrypt`).
fn craft_dik1(
    root: &[u8; 32],
    header_key_id: &[u8; 32],
    x_sk: &[u8; 32],
    dk: &[u8],
    x_pk: &[u8; 32],
    ek: &[u8],
) -> Vec<u8> {
    let mut info = Vec::new();
    info.extend_from_slice(IK_WRAP_LABEL);
    info.extend_from_slice(header_key_id);
    let k_wrap = derive_subkey(root, &info).unwrap();

    let mut aad = Vec::new();
    aad.extend_from_slice(IK_AAD_PREFIX);
    aad.extend_from_slice(&IMPORTED_KEY_MAGIC);
    aad.push(KEM_SUITE_X25519_MLKEM768);
    aad.extend_from_slice(header_key_id);

    let mut pt = vec![0u8; DIK1_PLAINTEXT_LEN];
    pt[0..32].copy_from_slice(x_sk);
    pt[32..32 + MLKEM768_DK_LEN].copy_from_slice(dk);
    pt[2432..2464].copy_from_slice(x_pk);
    pt[2464..].copy_from_slice(ek);

    let sealed = aead::encrypt(&k_wrap, &pt, &aad).unwrap();
    let mut out = vec![0u8; DIK1_HEADER_LEN];
    out[0..4].copy_from_slice(&IMPORTED_KEY_MAGIC);
    out[4] = IMPORTED_KEY_VERSION;
    out[5] = KEM_SUITE_X25519_MLKEM768;
    out[8..DIK1_HEADER_LEN].copy_from_slice(header_key_id);
    out.extend_from_slice(&sealed);
    out
}

#[test]
fn dik1_roundtrip_recovers_every_secret_and_framing_is_exact() {
    let root = keys::generate_key();
    let kp = generate_external();
    let bytes = serialize_dik1(&root, &kp).unwrap();

    // Byte-exact frozen framing (§13).
    assert_eq!(bytes.len(), DIK1_LEN);
    assert_eq!(bytes.len(), 3728);
    assert_eq!(&bytes[0..4], b"DIK1");
    assert_eq!(bytes[4], 0x01, "version");
    assert_eq!(bytes[5], 0x01, "hybrid_suite");
    assert_eq!(&bytes[6..8], &[0u8, 0u8], "reserved MUST be 0");
    assert_eq!(&bytes[8..40], &kp.key_id[..], "header key_id");

    // Parse recovers the identity and every secret bit-for-bit.
    let back = parse_dik1(&root, &bytes).unwrap();
    assert_eq!(back.key_id, kp.key_id);
    assert_eq!(back.public.x_pk, kp.public.x_pk);
    assert_eq!(back.public.ek, kp.public.ek);
    assert_eq!(back.x_sk().to_bytes(), kp.x_sk().to_bytes());
    assert_eq!(
        back.dk().as_bytes().as_slice(),
        kp.dk().as_bytes().as_slice(),
        "imported ML-KEM dk must be bit-for-bit identical"
    );
}

#[test]
fn dik1_rejects_wrong_root() {
    let root = keys::generate_key();
    let other_root = keys::generate_key();
    let kp = generate_external();
    let bytes = serialize_dik1(&root, &kp).unwrap();
    // Wrong root ⇒ a different k_wrap ⇒ the AEAD tag fails.
    assert!(parse_dik1(&other_root, &bytes).is_err());
}

#[test]
fn dik1_rejects_tampered_header_and_reserved() {
    let root = keys::generate_key();
    let kp = generate_external();
    let good = serialize_dik1(&root, &kp).unwrap();

    // Bad magic.
    let mut b = good;
    b[0] ^= 0xFF;
    assert!(parse_dik1(&root, &b).is_err());

    // Non-zero reserved (checked before any crypto).
    let mut b = good;
    b[6] = 0x01;
    assert!(parse_dik1(&root, &b).is_err());

    // Tampered header key_id ⇒ derives a different k_wrap ⇒ AEAD fails.
    let mut b = good;
    b[8] ^= 0xFF;
    assert!(parse_dik1(&root, &b).is_err());

    // Tampered ciphertext body ⇒ AEAD tag fails.
    let mut b = good;
    let mid = b.len() / 2;
    b[mid] ^= 0xFF;
    assert!(parse_dik1(&root, &b).is_err());

    // Wrong length.
    assert!(parse_dik1(&root, &good[..DIK1_LEN - 1]).is_err());
}

#[test]
fn dik1_rejects_unknown_version_and_suite() {
    let root = keys::generate_key();
    let kp = generate_external();
    let good = serialize_dik1(&root, &kp).unwrap();

    // Unknown version (byte 4) — rejected before decryption (its own error).
    let mut b = good;
    b[4] = 0x02;
    assert!(parse_dik1(&root, &b).is_err());

    // Unknown hybrid_suite (byte 5) — rejected before decryption (its own error).
    let mut b = good;
    b[5] = 0x02;
    assert!(parse_dik1(&root, &b).is_err());
}

#[test]
fn dik1_rejects_key_id_not_equal_recompute() {
    // Header key_id names identity kp2, but the (consistent) body material is kp's. The body
    // AEAD-opens (k_wrap/AAD both use the header key_id), and the recomputed public keys are
    // self-consistent — but they reproduce kp.key_id ≠ header (kp2.key_id), so the MANDATORY
    // §13 self-consistency check rejects the entry.
    let root = keys::generate_key();
    let kp = generate_external();
    let kp2 = generate_external();
    assert_ne!(kp.key_id, kp2.key_id);

    let crafted = craft_dik1(
        &root,
        &kp2.key_id, // wrong header key_id
        &kp.x_sk().to_bytes(),
        kp.dk().as_bytes().as_slice(),
        &kp.public.x_pk,
        &kp.public.ek,
    );
    assert!(parse_dik1(&root, &crafted).is_err());
}

#[test]
fn dik1_rejects_self_inconsistent_pubkeys() {
    // Body carries kp's private material but kp2's PUBLIC x_pk/ek, with the header key_id set
    // to the (matching) recompute so we specifically exercise the "x_pk/ek != recompute"
    // legs rather than the key_id leg. from_private recomputes x_pk/ek from the private
    // material (kp's) and finds they differ from the stored (kp2's) → reject.
    let root = keys::generate_key();
    let kp = generate_external();
    let kp2 = generate_external();

    let crafted = craft_dik1(
        &root,
        &kp.key_id, // matches recompute-from-private
        &kp.x_sk().to_bytes(),
        kp.dk().as_bytes().as_slice(),
        &kp2.public.x_pk, // mismatched stored public key
        &kp2.public.ek,
    );
    assert!(parse_dik1(&root, &crafted).is_err());
}
