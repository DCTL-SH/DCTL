//! §12 hybrid X25519 + ML-KEM-768 recipient layer (`kem_id=1`): deterministic
//! root-derived keypairs, 1- and N-recipient round-trips, non-recipient rejection,
//! tamper rejection, and confirmation the symmetric `kem_id=0` path still works.

use dctl_crypto::constants::{
    DRK1_LEN, KEM_ID_HYBRID, MLKEM768_DK_LEN, MLKEM768_EK_LEN, OBJECT_HEAD_LEN,
};
use dctl_crypto::kem::{Drk1Public, derive_recipient};
use dctl_crypto::keys;
use dctl_crypto::object::{self, Metadata};
use ml_kem::EncodedSizeUser;

fn open_kp(
    kp: &dctl_crypto::kem::RecipientKeypair,
    blob: &[u8],
) -> dctl_crypto::Result<object::Opened> {
    object::open_as_recipient(kp.x_sk(), kp.dk(), &kp.key_id, blob)
}

#[test]
fn root_derived_keypair_is_deterministic() {
    let root = keys::generate_key();
    let a = derive_recipient(&root, 0).unwrap();
    let b = derive_recipient(&root, 0).unwrap();

    // Same root + idx ⇒ identical public identity, key_id, and both private keys.
    assert_eq!(a.key_id, b.key_id);
    assert_eq!(a.public.x_pk, b.public.x_pk);
    assert_eq!(a.public.ek, b.public.ek);
    assert_eq!(a.x_sk().to_bytes(), b.x_sk().to_bytes());
    assert_eq!(
        a.dk().as_bytes().as_slice(),
        b.dk().as_bytes().as_slice(),
        "ML-KEM dk must be bit-for-bit identical"
    );

    // Sizes match the frozen constants.
    assert_eq!(a.public.ek.len(), MLKEM768_EK_LEN);
    assert_eq!(a.dk().as_bytes().as_slice().len(), MLKEM768_DK_LEN);
    assert_eq!(a.public.encode().len(), DRK1_LEN);

    // A different identity index yields a different keypair.
    let other_idx = derive_recipient(&root, 1).unwrap();
    assert_ne!(a.key_id, other_idx.key_id);

    // A different root yields a different keypair.
    let root2 = keys::generate_key();
    let c = derive_recipient(&root2, 0).unwrap();
    assert_ne!(a.key_id, c.key_id);
    assert_ne!(a.public.x_pk, c.public.x_pk);
}

#[test]
fn drk1_encode_decode_roundtrip_and_key_id_stable() {
    let root = keys::generate_key();
    let kp = derive_recipient(&root, 0).unwrap();
    let encoded = kp.public.encode();
    let decoded = Drk1Public::decode(&encoded).unwrap();
    assert_eq!(decoded.x_pk, kp.public.x_pk);
    assert_eq!(decoded.ek, kp.public.ek);
    // key_id is a pure function of the DRK1 bytes.
    assert_eq!(decoded.key_id(), kp.key_id);

    // Corrupt magic ⇒ reject.
    let mut bad = encoded;
    bad[0] ^= 0xFF;
    assert!(Drk1Public::decode(&bad).is_err());
    // Wrong length ⇒ reject.
    assert!(Drk1Public::decode(&encoded[..DRK1_LEN - 1]).is_err());
}

#[test]
fn single_recipient_roundtrip() {
    let root = keys::generate_key();
    let alice = derive_recipient(&root, 0).unwrap();

    let data = b"the quick brown fox jumps over the lazy dog".repeat(20);
    let obj = object::seal_to_recipients(
        std::slice::from_ref(&alice.public),
        &data,
        &Metadata::new("dir/f.bin"),
        64,
    )
    .unwrap();

    // Head carries kem_id=1.
    assert_eq!(obj[6], KEM_ID_HYBRID);

    let opened = open_kp(&alice, &obj).unwrap();
    assert_eq!(opened.plaintext.as_slice(), data.as_slice());
    let md = opened.metadata.expect("metadata present");
    assert_eq!(md.path_hint, "dir/f.bin");
    assert_eq!(md.size, data.len() as u64);
}

#[test]
fn empty_and_boundary_sizes_roundtrip() {
    let root = keys::generate_key();
    let alice = derive_recipient(&root, 0).unwrap();
    for len in [0usize, 1, 63, 64, 65, 200, 1000] {
        let data: Vec<u8> = (0..len).map(|i| (i * 5 + 1) as u8).collect();
        let obj = object::seal_to_recipients(
            std::slice::from_ref(&alice.public),
            &data,
            &Metadata::new("f"),
            64,
        )
        .unwrap();
        let opened = open_kp(&alice, &obj).unwrap();
        assert_eq!(opened.plaintext.as_slice(), data.as_slice(), "len={len}");
    }
}

#[test]
fn multi_recipient_all_open_same_plaintext() {
    // Three independent vaults / identities.
    let (r1, r2, r3) = (
        keys::generate_key(),
        keys::generate_key(),
        keys::generate_key(),
    );
    let a = derive_recipient(&r1, 0).unwrap();
    let b = derive_recipient(&r2, 0).unwrap();
    let c = derive_recipient(&r3, 0).unwrap();

    let data = b"shared payload for three recipients".repeat(30);
    let recips = vec![a.public.clone(), b.public.clone(), c.public.clone()];
    let obj = object::seal_to_recipients(&recips, &data, &Metadata::new("shared"), 128).unwrap();

    for kp in [&a, &b, &c] {
        let opened = open_kp(kp, &obj).unwrap();
        assert_eq!(opened.plaintext.as_slice(), data.as_slice());
        assert_eq!(opened.metadata.unwrap().path_hint, "shared");
    }
}

#[test]
fn non_recipient_cannot_open() {
    let root = keys::generate_key();
    let alice = derive_recipient(&root, 0).unwrap();
    let data = b"secret".to_vec();
    let obj = object::seal_to_recipients(
        std::slice::from_ref(&alice.public),
        &data,
        &Metadata::new("f"),
        32,
    )
    .unwrap();

    // A different vault's identity is not a recipient (no matching key_id).
    let eve_root = keys::generate_key();
    let eve = derive_recipient(&eve_root, 0).unwrap();
    assert!(open_kp(&eve, &obj).is_err());

    // A different idx on the same vault is likewise not a recipient.
    let alice_idx1 = derive_recipient(&root, 1).unwrap();
    assert!(open_kp(&alice_idx1, &obj).is_err());
}

#[test]
fn tamper_in_kem_wrap_rejected() {
    let root = keys::generate_key();
    let alice = derive_recipient(&root, 0).unwrap();
    let data = b"tamper me".repeat(10);
    let obj = object::seal_to_recipients(
        std::slice::from_ref(&alice.public),
        &data,
        &Metadata::new("f"),
        32,
    )
    .unwrap();
    assert!(open_kp(&alice, &obj).is_ok());

    // Flip a byte inside the kem_wrap block (starts at offset 70): corrupts a ct_m /
    // eph_pk / wrapped_kw byte, so the wrapping_key differs or the wrapped_kw tag fails.
    let mut t = obj.clone();
    t[70 + 200] ^= 0x01;
    assert!(open_kp(&alice, &t).is_err());

    // Flip the DKW1 magic ⇒ structural rejection before any crypto.
    let mut t2 = obj.clone();
    t2[70] ^= 0xFF;
    assert!(open_kp(&alice, &t2).is_err());
}

#[test]
fn tamper_in_object_body_rejected() {
    let root = keys::generate_key();
    let alice = derive_recipient(&root, 0).unwrap();
    let data = b"body integrity".repeat(20);
    let obj = object::seal_to_recipients(
        std::slice::from_ref(&alice.public),
        &data,
        &Metadata::new("f"),
        32,
    )
    .unwrap();

    // Flip a byte near the end (payload/footer) ⇒ chunk AEAD or footer rejects.
    let mut t = obj.clone();
    let i = obj.len() - 20;
    t[i] ^= 0xFF;
    assert!(open_kp(&alice, &t).is_err());

    // Flip a head byte (chunk_size, offset 8) ⇒ head-bound wrapped_dek AAD fails.
    let mut t2 = obj.clone();
    t2[8] ^= 0x01;
    assert!(open_kp(&alice, &t2).is_err());

    // Truncate into the kem_wrap block ⇒ reject.
    assert!(open_kp(&alice, &obj[..OBJECT_HEAD_LEN + 100]).is_err());
}

#[test]
fn wrong_opener_for_kem_id() {
    let root = keys::generate_key();
    let alice = derive_recipient(&root, 0).unwrap();

    // A kem_id=1 object cannot be opened by the symmetric open().
    let obj = object::seal_to_recipients(
        std::slice::from_ref(&alice.public),
        b"x",
        &Metadata::new("f"),
        32,
    )
    .unwrap();
    assert!(object::open(&root, &obj).is_err());

    // A kem_id=0 object cannot be opened by open_as_recipient().
    let sym = object::seal(&root, b"x", &Metadata::new("f"), 32).unwrap();
    assert!(open_kp(&alice, &sym).is_err());
}

#[test]
fn symmetric_path_unchanged() {
    // The kem_id=0 owner path still round-trips exactly as before.
    let root = keys::generate_key();
    let data = b"symmetric still works".repeat(10);
    let obj = object::seal(&root, &data, &Metadata::new("s.bin"), 32).unwrap();
    assert_eq!(obj[6], 0, "kem_id byte must be 0 for the symmetric path");
    // kem_ct_len (offset 68) is 0 for kem_id=0.
    assert_eq!(u16::from_le_bytes([obj[68], obj[69]]), 0);
    let opened = object::open(&root, &obj).unwrap();
    assert_eq!(opened.plaintext.as_slice(), data.as_slice());
    assert_eq!(opened.metadata.unwrap().path_hint, "s.bin");
}
