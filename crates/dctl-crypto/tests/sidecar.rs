//! §12.6 `DGS1` grant sidecar: (de)serialize round-trip, every structural/binding check,
//! and the "a grant sealed to R opens (→KW) only with R's key" property. A grant is a
//! §12.2 sub-record, so these also confirm the reuse of the existing seal/open machinery.

use dctl_crypto::constants::{
    FILE_ID_LEN, GRANT_SIDECAR_HEADER_LEN, GRANT_SIDECAR_MAGIC, OBJECT_HEAD_LEN,
    RECIP_SUBRECORD_LEN,
};
use dctl_crypto::kem::{derive_recipient, sidecar};
use dctl_crypto::keys;
use dctl_crypto::object::{self, Metadata};

/// Seal a real `kem_id=1` object to `recipients` and pull out the pieces a sidecar binds to.
fn seal_object(
    recipients: &[dctl_crypto::kem::Drk1Public],
    data: &[u8],
) -> (Vec<u8>, [u8; OBJECT_HEAD_LEN], [u8; FILE_ID_LEN], Vec<u8>) {
    let obj = object::seal_to_recipients(recipients, data, &Metadata::new("f"), 64).unwrap();
    let mut head = [0u8; OBJECT_HEAD_LEN];
    head.copy_from_slice(&obj[0..OBJECT_HEAD_LEN]);
    let mut file_id = [0u8; FILE_ID_LEN];
    file_id.copy_from_slice(&head[52..68]);
    let k = u16::from_le_bytes([obj[68], obj[69]]) as usize;
    let block = obj[70..70 + k].to_vec();
    (obj, head, file_id, block)
}

#[test]
fn grant_opens_only_with_r_and_reader_recovers_same_kw() {
    let a = derive_recipient(&keys::generate_key(), 0).unwrap();
    let b = derive_recipient(&keys::generate_key(), 0).unwrap();

    // Object shared to A only (A is the inline / durable recipient).
    let data = b"the multi-GB payload nobody re-uploads".repeat(9);
    let (obj, head, file_id, block) = seal_object(std::slice::from_ref(&a.public), &data);

    // A is inline and recovers KW; B is not an inline recipient.
    let kw = sidecar::recover_kw_from_block(&a, &head, &block)
        .unwrap()
        .expect("A is inline");
    assert!(
        sidecar::recover_kw_from_block(&b, &head, &block)
            .unwrap()
            .is_none(),
        "B is not an inline recipient"
    );

    // Add B via a sidecar grant (re-wrap KW to B) — no object re-upload.
    let grant_b = sidecar::seal_kw_to_recipient(&kw, &b.public, &head).unwrap();
    assert_eq!(grant_b.key_id(), b.key_id);
    let bytes = sidecar::serialize(&file_id, &head, 1, std::slice::from_ref(&grant_b)).unwrap();

    // Sidecar parses (binding checks pass) and B recovers the SAME KW A holds.
    let parsed = sidecar::parse(&bytes, &file_id, &head).unwrap();
    assert_eq!(parsed.grant_gen, 1);
    assert_eq!(parsed.grants.len(), 1);
    let kw_b = sidecar::recover_kw_as_recipient(&parsed.grants[0], &b, &head).unwrap();
    assert_eq!(kw_b.as_slice(), kw.as_slice(), "B recovers the same KW");

    // The grant sealed to B does NOT open with A's key (bound to B's key_id).
    assert!(sidecar::recover_kw_as_recipient(&parsed.grants[0], &a, &head).is_err());
    // Nor with an unrelated identity C.
    let c = derive_recipient(&keys::generate_key(), 0).unwrap();
    assert!(sidecar::recover_kw_as_recipient(&parsed.grants[0], &c, &head).is_err());

    // B decodes the exact object bytes via the recovered KW.
    let opened = object::open_with_kw(&kw_b, &obj).unwrap();
    assert_eq!(opened.plaintext.as_slice(), data.as_slice());
    assert_eq!(opened.metadata.unwrap().size, data.len() as u64);
}

#[test]
fn serialize_parse_roundtrip_and_empty_sidecar() {
    let a = derive_recipient(&keys::generate_key(), 0).unwrap();
    let (_obj, head, file_id, block) = seal_object(std::slice::from_ref(&a.public), b"payload");
    let kw = sidecar::recover_kw_from_block(&a, &head, &block)
        .unwrap()
        .unwrap();

    // Empty sidecar (G = 0) round-trips.
    let empty = sidecar::serialize(&file_id, &head, 0, &[]).unwrap();
    assert_eq!(empty.len(), GRANT_SIDECAR_HEADER_LEN);
    let p = sidecar::parse(&empty, &file_id, &head).unwrap();
    assert_eq!(p.grants.len(), 0);
    assert_eq!(p.grant_gen, 0);

    // Multi-grant sidecar round-trips, preserving order and grant_gen.
    let b = derive_recipient(&keys::generate_key(), 0).unwrap();
    let c = derive_recipient(&keys::generate_key(), 0).unwrap();
    let g_b = sidecar::seal_kw_to_recipient(&kw, &b.public, &head).unwrap();
    let g_c = sidecar::seal_kw_to_recipient(&kw, &c.public, &head).unwrap();
    let bytes = sidecar::serialize(&file_id, &head, 42, &[g_b, g_c]).unwrap();
    assert_eq!(
        bytes.len(),
        GRANT_SIDECAR_HEADER_LEN + 2 * RECIP_SUBRECORD_LEN
    );
    let parsed = sidecar::parse(&bytes, &file_id, &head).unwrap();
    assert_eq!(parsed.grant_gen, 42);
    assert_eq!(parsed.grants.len(), 2);
    assert_eq!(parsed.grants[0].key_id(), b.key_id);
    assert_eq!(parsed.grants[1].key_id(), c.key_id);
}

#[test]
fn parse_rejects_every_binding_and_structural_mismatch() {
    let a = derive_recipient(&keys::generate_key(), 0).unwrap();
    let b = derive_recipient(&keys::generate_key(), 0).unwrap();
    let (_obj, head, file_id, block) =
        seal_object(std::slice::from_ref(&a.public), b"bind me tightly");
    let kw = sidecar::recover_kw_from_block(&a, &head, &block)
        .unwrap()
        .unwrap();
    let grant_b = sidecar::seal_kw_to_recipient(&kw, &b.public, &head).unwrap();
    let good = sidecar::serialize(&file_id, &head, 5, std::slice::from_ref(&grant_b)).unwrap();
    assert!(sidecar::parse(&good, &file_id, &head).is_ok());

    // Wrong file_id (both as the expected arg and stored in the header).
    let mut wrong_id = file_id;
    wrong_id[0] ^= 0xFF;
    assert!(sidecar::parse(&good, &wrong_id, &head).is_err());
    let mut t = good.clone();
    t[8] ^= 0xFF;
    assert!(sidecar::parse(&t, &file_id, &head).is_err());

    // Tampered head_hash: a different head, or a corrupted stored hash.
    let mut other_head = head;
    other_head[8] ^= 0x01;
    assert!(sidecar::parse(&good, &file_id, &other_head).is_err());
    let mut t = good.clone();
    t[24] ^= 0xFF;
    assert!(sidecar::parse(&t, &file_id, &head).is_err());

    // Bad magic / version / hybrid_suite / reserved.
    for (off, val) in [(0usize, 0xFFu8), (4, 0x02), (5, 0x02), (6, 0x01), (7, 0x01)] {
        let mut t = good.clone();
        t[off] ^= val;
        assert!(
            sidecar::parse(&t, &file_id, &head).is_err(),
            "offset {off} tamper must reject"
        );
    }

    // Over-long grant_count (> 4096) rejected before any length/crypto work.
    let mut t = good.clone();
    t[64..66].copy_from_slice(&4097u16.to_le_bytes());
    assert!(sidecar::parse(&t, &file_id, &head).is_err());

    // Inexact length: a dropped byte and an extra trailing byte both reject.
    assert!(sidecar::parse(&good[..good.len() - 1], &file_id, &head).is_err());
    let mut t = good.clone();
    t.push(0);
    assert!(sidecar::parse(&t, &file_id, &head).is_err());

    // Corrupt a grant's inner rec_len field (structural §12.2 sub-record validation).
    let mut t = good.clone();
    t[GRANT_SIDECAR_HEADER_LEN] ^= 0xFF;
    assert!(sidecar::parse(&t, &file_id, &head).is_err());

    // Shorter than the header rejects.
    assert!(sidecar::parse(&good[..10], &file_id, &head).is_err());
    assert_eq!(GRANT_SIDECAR_MAGIC, *b"DGS1");
}

#[test]
fn serialize_rejects_overlong_grant_list() {
    // The serializer enforces the same G ≤ 4096 bound the parser does. Build cheaply from
    // clones of a single grant (no crypto per element).
    let a = derive_recipient(&keys::generate_key(), 0).unwrap();
    let b = derive_recipient(&keys::generate_key(), 0).unwrap();
    let (_obj, head, file_id, block) = seal_object(std::slice::from_ref(&a.public), b"x");
    let kw = sidecar::recover_kw_from_block(&a, &head, &block)
        .unwrap()
        .unwrap();
    let grant = sidecar::seal_kw_to_recipient(&kw, &b.public, &head).unwrap();
    let too_many = vec![grant; 4097];
    assert!(sidecar::serialize(&file_id, &head, 1, &too_many).is_err());
}
