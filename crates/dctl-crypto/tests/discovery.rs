//! §14 shared-object discovery `DGD1`: seal→open round-trip, byte-exact framing, rejection
//! of a wrong recipient / wrong file_id / wrong head / tampered header, and the DW-
//! indirection "grants no read access" proof — a holder of ONLY a `DGD1` learns the
//! path/size but cannot decrypt the object.

use dctl_crypto::constants::{DGD1_BODY_OFFSET, DGD1_HEADER_LEN, OBJECT_HEAD_LEN};
use dctl_crypto::kem::{DiscoveryInfo, RecipientKeypair, generate_external, open_dgd1, seal_dgd1};
use dctl_crypto::object::{self, Metadata};

/// Seal a small object to `recipient` and return `(head_bytes, file_id)` for building a
/// discovery record against a real DSF1 head.
fn object_head(recipient: &RecipientKeypair) -> ([u8; OBJECT_HEAD_LEN], [u8; 16]) {
    let obj = object::seal_to_recipients(
        std::slice::from_ref(&recipient.public),
        b"payload",
        &Metadata::new("orig/name"),
        65536,
    )
    .unwrap();
    let mut head = [0u8; OBJECT_HEAD_LEN];
    head.copy_from_slice(&obj[0..OBJECT_HEAD_LEN]);
    let mut file_id = [0u8; 16];
    file_id.copy_from_slice(&head[52..68]);
    (head, file_id)
}

fn disc_for(file_id: [u8; 16], path: &str) -> DiscoveryInfo {
    DiscoveryInfo {
        obj_suite: 0x01,
        file_id,
        size: 4242,
        content_hash: [0x5a; 32],
        path: path.to_string(),
        ext: Vec::new(),
    }
}

#[test]
fn dgd1_roundtrip_and_framing() {
    let recipient = generate_external();
    let (head, file_id) = object_head(&recipient);
    let disc = disc_for(file_id, "docs/2026/report.txt");

    let rec = seal_dgd1(&recipient.public, &head, &disc).unwrap();

    // Frozen framing (§14): 88-byte header, 1234-byte wrapped_dw, then the sealed body.
    assert_eq!(&rec[0..4], b"DGD1");
    assert_eq!(rec[4], 0x01, "version");
    assert_eq!(rec[5], 0x01, "hybrid_suite");
    assert_eq!(&rec[6..8], &[0u8, 0u8], "reserved");
    assert_eq!(&rec[8..40], &recipient.key_id[..], "recipient_key_id");
    assert_eq!(&rec[40..56], &file_id[..], "file_id");
    assert_eq!(DGD1_HEADER_LEN, 88);
    assert_eq!(DGD1_BODY_OFFSET, 1322);
    assert!(rec.len() > DGD1_BODY_OFFSET, "a sealed body follows");

    let opened = open_dgd1(&rec, &recipient, Some(&head)).unwrap();
    assert_eq!(opened.path, "docs/2026/report.txt");
    assert_eq!(opened.file_id, file_id);
    assert_eq!(opened.size, 4242);
    assert_eq!(opened.content_hash, [0x5a; 32]);
    assert_eq!(opened.obj_suite, 0x01);
}

#[test]
fn dgd1_rejects_wrong_recipient() {
    let recipient = generate_external();
    let stranger = generate_external();
    let (head, file_id) = object_head(&recipient);
    let rec = seal_dgd1(&recipient.public, &head, &disc_for(file_id, "a/b")).unwrap();

    // A different identity: the header recipient_key_id will not match, and even if it did
    // the DW decaps AEAD tag would fail.
    assert!(open_dgd1(&rec, &stranger, Some(&head)).is_err());
}

#[test]
fn dgd1_rejects_wrong_head_and_missing_head() {
    let recipient = generate_external();
    let (head, file_id) = object_head(&recipient);
    let rec = seal_dgd1(&recipient.public, &head, &disc_for(file_id, "a/b")).unwrap();

    // A DIFFERENT object's head ⇒ head_hash mismatch (anti-transplant).
    let (other_head, _other_id) = object_head(&recipient);
    assert!(open_dgd1(&rec, &recipient, Some(&other_head)).is_err());

    // No head at all ⇒ DW cannot be recovered.
    assert!(open_dgd1(&rec, &recipient, None).is_err());
}

#[test]
fn dgd1_rejects_tampered_header_and_body() {
    let recipient = generate_external();
    let (head, file_id) = object_head(&recipient);
    let good = seal_dgd1(&recipient.public, &head, &disc_for(file_id, "a/b")).unwrap();

    // Bad magic.
    let mut b = good.clone();
    b[0] ^= 0xFF;
    assert!(open_dgd1(&b, &recipient, Some(&head)).is_err());

    // Non-zero reserved.
    let mut b = good.clone();
    b[6] = 0x01;
    assert!(open_dgd1(&b, &recipient, Some(&head)).is_err());

    // Tampered head_hash field (bytes 56..88) ⇒ mismatch vs the real head.
    let mut b = good.clone();
    b[60] ^= 0xFF;
    assert!(open_dgd1(&b, &recipient, Some(&head)).is_err());

    // Tampered file_id field (bytes 40..56) ⇒ head.file_id mismatch.
    let mut b = good.clone();
    b[40] ^= 0xFF;
    assert!(open_dgd1(&b, &recipient, Some(&head)).is_err());

    // Tampered sealed body ⇒ AEAD tag fails.
    let mut b = good.clone();
    let last = b.len() - 1;
    b[last] ^= 0xFF;
    assert!(open_dgd1(&b, &recipient, Some(&head)).is_err());
}

#[test]
fn dgd1_grants_no_read_access() {
    // The DW-indirection proof: recipient B holds a DGD1 sealed to it (so it discovers the
    // path/size) but is NOT an object recipient (the object is sealed only to A), so B can
    // never decrypt the object itself. A discovery record wraps only DW, never KW/DEK.
    let a = generate_external(); // the sole object recipient
    let b = generate_external(); // discovery-only recipient

    let plaintext = b"the actual confidential object payload".repeat(8);
    let obj = object::seal_to_recipients(
        std::slice::from_ref(&a.public),
        &plaintext,
        &Metadata::new("secret/file"),
        65536,
    )
    .unwrap();
    let mut head = [0u8; OBJECT_HEAD_LEN];
    head.copy_from_slice(&obj[0..OBJECT_HEAD_LEN]);
    let mut file_id = [0u8; 16];
    file_id.copy_from_slice(&head[52..68]);

    // Owner writes a DGD1 to B (enumeration pointer only).
    let rec = seal_dgd1(&b.public, &head, &disc_for(file_id, "secret/file")).unwrap();

    // B CAN open the DGD1 — it gets the path/size.
    let disc = open_dgd1(&rec, &b, Some(&head)).unwrap();
    assert_eq!(disc.path, "secret/file");

    // …but B CANNOT decrypt the object: it is not a recipient of it (no kem_wrap sub-record
    // for B's key_id). The discovery record granted zero read access.
    assert!(
        object::open_as_recipient(b.x_sk(), b.dk(), &b.key_id, &obj).is_err(),
        "a discovery-only recipient must NOT be able to decrypt the object"
    );
    // Sanity: the real recipient A can.
    assert!(object::open_as_recipient(a.x_sk(), a.dk(), &a.key_id, &obj).is_ok());
}
