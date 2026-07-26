//! §5 name records: seal/open round-trip, fresh-nonce-per-write, vault/key binding,
//! and rename-safe self-consistency.

use dctl_crypto::names::NameKeys;
use dctl_crypto::{keys, path};

#[test]
fn name_record_roundtrip() {
    let root = keys::generate_key();
    let nk = NameKeys::derive(&root).unwrap();
    let vault_id = [3u8; 16];
    let file_id = [7u8; 16];
    let p = path::normalize("photos/2026/img.heic").unwrap();
    let (key, value) = nk.seal_record(&vault_id, &p, &file_id, 42).unwrap();
    assert!(key.starts_with("n/"));
    let rec = nk.open_record(&vault_id, &key, &value).unwrap();
    assert_eq!(rec.file_id, file_id);
    assert_eq!(rec.metadata_gen, 42);
    assert_eq!(rec.path, p);
}

#[test]
fn fresh_nonce_per_write() {
    let root = keys::generate_key();
    let nk = NameKeys::derive(&root).unwrap();
    let (vault_id, file_id) = ([1u8; 16], [2u8; 16]);
    let p = path::normalize("a/b").unwrap();
    let (_, v1) = nk.seal_record(&vault_id, &p, &file_id, 1).unwrap();
    let (_, v2) = nk.seal_record(&vault_id, &p, &file_id, 1).unwrap();
    assert_ne!(v1, v2, "each rewrite must use a fresh CSPRNG nonce");
}

#[test]
fn wrong_vault_or_key_rejected() {
    let root = keys::generate_key();
    let nk = NameKeys::derive(&root).unwrap();
    let (vault_id, file_id) = ([5u8; 16], [6u8; 16]);
    let p = path::normalize("x/y").unwrap();
    let (key, value) = nk.seal_record(&vault_id, &p, &file_id, 9).unwrap();

    assert!(
        nk.open_record(&[9u8; 16], &key, &value).is_err(),
        "wrong vault_id"
    );
    let other_key = nk.record_key(&path::normalize("z/w").unwrap());
    assert!(
        nk.open_record(&vault_id, &other_key, &value).is_err(),
        "wrong record key"
    );
    assert!(nk.open_record(&vault_id, &key, &value).is_ok());
}

#[test]
fn rename_changes_key_same_file() {
    let root = keys::generate_key();
    let nk = NameKeys::derive(&root).unwrap();
    let (vault_id, file_id) = ([0u8; 16], [1u8; 16]);
    let a = path::normalize("old/name").unwrap();
    let b = path::normalize("new/name").unwrap();
    let (ka, _) = nk.seal_record(&vault_id, &a, &file_id, 1).unwrap();
    let (kb, vb) = nk.seal_record(&vault_id, &b, &file_id, 2).unwrap();
    assert_ne!(ka, kb, "rename → different name-record key");
    let rec = nk.open_record(&vault_id, &kb, &vb).unwrap();
    assert_eq!(rec.file_id, file_id, "same file_id survives rename");
    assert_eq!(rec.path, "new/name");
    assert_eq!(rec.metadata_gen, 2);
}
