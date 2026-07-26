//! DSF1 self-describing object: seal/open round-trip, embedded metadata, head-bound
//! AAD (empty-object header tamper), footer/tamper/truncation rejection, tombstones.

use dctl_crypto::keys;
use dctl_crypto::object::{self, Metadata};

#[test]
fn seal_open_roundtrip_boundary_sizes() {
    let root = keys::generate_key();
    let cs = 64u32;
    for len in [0usize, 1, 63, 64, 65, 127, 128, 200, 1000] {
        let data: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
        let obj = object::seal(&root, &data, &Metadata::new("dir/file.bin"), cs).unwrap();
        let opened = object::open(&root, &obj).unwrap();
        assert_eq!(opened.plaintext.as_slice(), data.as_slice(), "len={len}");
        let md = opened.metadata.expect("metadata present");
        assert_eq!(md.path_hint, "dir/file.bin");
        assert_eq!(md.size, len as u64);
        assert_ne!(md.content_blake3, [0u8; 32]);
    }
}

#[test]
fn content_hash_is_deterministic() {
    let root = keys::generate_key();
    let data = b"same bytes, two seals".to_vec();
    let a = object::open(
        &root,
        &object::seal(&root, &data, &Metadata::new("f"), 8).unwrap(),
    )
    .unwrap();
    let b = object::open(
        &root,
        &object::seal(&root, &data, &Metadata::new("f"), 8).unwrap(),
    )
    .unwrap();
    // Different DEK/nonce/object bytes, but the same plaintext → same content hash.
    assert_eq!(
        a.metadata.unwrap().content_blake3,
        b.metadata.unwrap().content_blake3
    );
}

#[test]
fn tamper_and_wrong_key_rejected() {
    let root = keys::generate_key();
    let data = b"the quick brown fox jumps over the lazy dog".repeat(10);
    let obj = object::seal(&root, &data, &Metadata::new("f"), 32).unwrap();
    assert!(object::open(&root, &obj).is_ok());

    // Wrong wrapping key → DEK unwrap fails.
    let wrong = keys::generate_key();
    assert!(object::open(&wrong, &obj).is_err());

    // Flip a byte in the body → footer / per-chunk AEAD reject.
    let mut t = obj.clone();
    let i = obj.len() - 40;
    t[i] ^= 0xFF;
    assert!(object::open(&root, &t).is_err());

    // Truncate into the payload → reject.
    assert!(object::open(&root, &obj[..obj.len() - 40]).is_err());
}

#[test]
fn header_tamper_detected_on_empty_object() {
    let root = keys::generate_key();
    let obj = object::seal(&root, b"", &Metadata::new("empty"), 1024).unwrap();
    assert!(object::open(&root, &obj).is_ok());
    // Flip chunk_size (head offset 8): head-bound DEK-wrap AAD fails even with no chunks.
    let mut t = obj.clone();
    t[8] ^= 0x01;
    assert!(object::open(&root, &t).is_err());
}

#[test]
fn tombstone_allows_empty_path() {
    use dctl_crypto::constants::META_FLAG_TOMBSTONE;
    let root = keys::generate_key();
    let mut meta = Metadata::new("");
    meta.flags = META_FLAG_TOMBSTONE;
    let obj = object::seal(&root, b"", &meta, 1024).unwrap();
    let opened = object::open(&root, &obj).unwrap();
    assert!(opened.metadata.unwrap().path_hint.is_empty());
}
