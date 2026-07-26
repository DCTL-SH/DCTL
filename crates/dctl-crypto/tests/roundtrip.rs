//! Core primitive tests: AEAD context-binding, Argon2id KDF (determinism, NFC,
//! ceilings, mnemonic), and HKDF sub-key domain separation. The DKE1 envelope and
//! DSF1 object formats have their own suites (`tests/envelope.rs`, `tests/object.rs`).

use dctl_crypto::{aead, kdf, keys};

#[test]
fn aead_roundtrip_and_context_binding() {
    let key = [1u8; 32];
    let ct = aead::encrypt(&key, b"hello", b"ctx-A").unwrap();
    assert_eq!(
        aead::decrypt(&key, &ct, b"ctx-A").unwrap().as_slice(),
        b"hello"
    );
    // Wrong AAD (substitution) and wrong key both fail — no oracle.
    assert!(aead::decrypt(&key, &ct, b"ctx-B").is_err());
    assert!(aead::decrypt(&[2u8; 32], &ct, b"ctx-A").is_err());
}

#[test]
fn aead_explicit_nonce_roundtrip() {
    let key = [4u8; 32];
    let nonce = [9u8; 24];
    let ct = aead::encrypt_with_nonce(&key, &nonce, b"payload", b"aad").unwrap();
    assert_eq!(
        aead::decrypt_with_nonce(&key, &nonce, &ct, b"aad")
            .unwrap()
            .as_slice(),
        b"payload"
    );
    // Wrong nonce or AAD fails.
    assert!(aead::decrypt_with_nonce(&key, &[0u8; 24], &ct, b"aad").is_err());
    assert!(aead::decrypt_with_nonce(&key, &nonce, &ct, b"other").is_err());
}

#[test]
fn kdf_is_deterministic_and_factor_sensitive() {
    let salt = kdf::generate_salt();
    let a = kdf::derive_kek("password", None, &salt).unwrap();
    let b = kdf::derive_kek("password", None, &salt).unwrap();
    assert_eq!(*a, *b, "same inputs → same KEK");

    let c = kdf::derive_kek("password", Some(b"keyfile-bytes"), &salt).unwrap();
    assert_ne!(*a, *c, "adding a factor must change the KEK");

    let other_salt = kdf::generate_salt();
    let d = kdf::derive_kek("password", None, &other_salt).unwrap();
    assert_ne!(*a, *d, "different salt → different KEK");
}

#[test]
fn passphrase_is_nfc_normalized() {
    // "café" as NFC (U+00E9) vs NFD (e + U+0301) must derive the same KEK.
    let salt = kdf::generate_salt();
    let nfc = kdf::derive_kek("caf\u{00e9}", None, &salt).unwrap();
    let nfd = kdf::derive_kek("cafe\u{0301}", None, &salt).unwrap();
    assert_eq!(*nfc, *nfd, "NFC and NFD forms of a passphrase must match");
}

#[test]
fn kdf_rejects_out_of_range_params() {
    let salt = kdf::generate_salt();
    assert!(kdf::derive_kek_with_params("pw", None, &salt, 2_000_000, 3, 4).is_err()); // m > 1 GiB
    assert!(kdf::derive_kek_with_params("pw", None, &salt, 64, 100, 1).is_err()); // t > 16
    assert!(kdf::derive_kek_with_params("pw", None, &salt, 64, 1, 0).is_err()); // p = 0
    assert!(kdf::derive_kek_with_params("pw", None, &salt, 64, 1, 1).is_ok()); // valid
}

#[test]
fn mnemonic_kek_is_deterministic_and_unique() {
    let phrase = kdf::generate_mnemonic().unwrap();
    let salt = kdf::generate_salt();
    let a = kdf::derive_kek_from_mnemonic(&phrase, &salt, 64, 1, 1).unwrap();
    let b = kdf::derive_kek_from_mnemonic(&phrase, &salt, 64, 1, 1).unwrap();
    assert_eq!(*a, *b);
    let other = kdf::generate_mnemonic().unwrap();
    let c = kdf::derive_kek_from_mnemonic(&other, &salt, 64, 1, 1).unwrap();
    assert_ne!(*a, *c);
}

#[test]
fn subkeys_are_domain_separated() {
    let root = keys::generate_key();
    let idx = keys::derive_subkey(&root, keys::INFO_INDEX).unwrap();
    let cache = keys::derive_subkey(&root, keys::INFO_CACHE).unwrap();
    let audit = keys::derive_subkey(&root, keys::INFO_AUDIT).unwrap();
    assert_ne!(*idx, *cache);
    assert_ne!(*idx, *audit);
    assert_ne!(*cache, *audit);
    assert_eq!(*idx, *keys::derive_subkey(&root, keys::INFO_INDEX).unwrap());
}
