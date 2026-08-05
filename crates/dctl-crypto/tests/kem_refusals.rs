//! What a `DKW1` recipient block refuses — §12.2's structural validation, which
//! runs *before* any key is touched.
//!
//! # Why these were unreached
//!
//! `tests/kem.rs` already tampers, and it is worth being exact about how far it
//! gets. It flips the `DKW1` magic, flips a byte 200 into the block, and
//! truncates an object mid-block — three cases, each asserted with a bare
//! `is_err()`. Between them they reach the magic check and the bounds check, and
//! nothing else: every one of those edits leaves a block whose *shape* is still
//! right, so the ten checks that decide whether a structurally **wrong** block
//! may be parsed at all were never executed by the workspace suite, and deleting
//! any of them left `cargo test --workspace` green.
//!
//! `is_err()` is the other half of why. A block that was refused for the wrong
//! reason satisfies it, so even the two checks `kem.rs` does reach are asserted
//! only as "something objected". Every case below names the refusal it expects.
//!
//! # The order is the whole point
//!
//! §12.2 is explicit that structural validation happens before any crypto, and
//! the reason is what the block is made of: `recip_count` is a number the object
//! supplies, and every sub-record is addressed as
//! `10 + i * 1234 .. 10 + (i+1) * 1234`. Nothing about those offsets is
//! authenticated. The AEAD tag on `wrapped_kw` is the sole *accept* gate — it is
//! not, and cannot be, a bounds check, because it is only reached once the
//! bounds have already been used to find it.
//!
//! So a block whose framing is wrong has exactly two possible fates. Either it
//! is refused here, by name, or it is indexed past the end of the object and the
//! process aborts — which for `dctl restore` means the recovery run dies on the
//! object it was started for, and [the plan](https://doc.dctl.sh/project/plan) forbids the panic besides.
//!
//! # Every case is one edit to a real object
//!
//! Sealed for a real recipient and opened by the real keypair, with a single
//! field overwritten. A block assembled from scratch would prove only that
//! nonsense is rejected; what has to be proved is that a block which is right in
//! every respect but one is rejected *for that one*.
//!
//! The `kem_wrap` block is not covered by anything that would notice these edits
//! on its behalf: the object's footer is an unkeyed BLAKE3 that anyone can
//! recompute (`tests/object_refusals.rs` does), and the per-chunk AEAD tags are
//! sealed under a DEK that is only recoverable *after* this block has parsed.

use dctl_crypto::constants::{
    FOOTER_LEN, KEM_WRAP_HEADER_LEN, KEY_ID_LEN, MAX_RECIP_COUNT, MLKEM768_CT_LEN, OBJECT_HEAD_LEN,
    RECIP_SUBRECORD_LEN, WRAPPED_KW_LEN, X25519_PK_LEN,
};
use dctl_crypto::kem::{RecipientKeypair, derive_recipient};
use dctl_crypto::keys;
use dctl_crypto::object::{self, Metadata};

/// Chunk size every object here is sealed at — small, so the payload really is
/// several chunks and nothing depends on a single-chunk special case.
const CHUNK: u32 = 32;

/// Where `kem_ct_len` sits: immediately after the 68-byte fixed head (§3).
const KEM_CT_LEN_AT: usize = OBJECT_HEAD_LEN;

/// Where the `DKW1` block itself starts (§12.2).
const BLOCK_AT: usize = OBJECT_HEAD_LEN + 2;

/// Where the first (and here only) sub-record starts.
const REC_AT: usize = BLOCK_AT + KEM_WRAP_HEADER_LEN;

/// Field offsets inside the `DKW1` header, relative to [`BLOCK_AT`] (§12.2).
mod block {
    /// `kw_version`, frozen at 1.
    pub const VERSION: usize = 4;
    /// `hybrid_suite`, frozen at 1 (X25519 + ML-KEM-768).
    pub const SUITE: usize = 5;
    /// `kw_flags`; bit 0 advertises a sidecar and every other bit is critical.
    pub const FLAGS: usize = 6;
    /// One reserved byte that MUST be zero.
    pub const RESERVED: usize = 7;
    /// `recip_count`, a u16 the object supplies and every offset multiplies.
    pub const COUNT: usize = 8;
}

/// Field offsets inside one sub-record, relative to [`REC_AT`] (§12.2).
mod rec {
    /// `ct_m_len`, frozen at 1088 for suite 1.
    pub const CT_M_LEN: usize = 36;
    /// `eph_pk_len`, frozen at 32.
    pub const EPH_PK_LEN: usize = 1126;
    /// `wrapped_len`, frozen at 72.
    pub const WRAPPED_LEN: usize = 1160;
}

/// A recipient and an object sealed to it — the control every case starts from.
fn sealed_to_one() -> (RecipientKeypair, Vec<u8>) {
    let root = keys::generate_key();
    let alice = derive_recipient(&root, 0).expect("a root derives a recipient");
    let object_bytes = object::seal_to_recipients(
        std::slice::from_ref(&alice.public),
        b"a payload long enough to be sealed across several chunks",
        &Metadata::new("dir/file.bin"),
        CHUNK,
    )
    .expect("the object seals");

    // The framing every offset below assumes, asserted once: one recipient means
    // a block of exactly header + one sub-record, and `kem_ct_len` says so.
    assert_eq!(
        u16::from_le_bytes([object_bytes[KEM_CT_LEN_AT], object_bytes[KEM_CT_LEN_AT + 1]]) as usize,
        KEM_WRAP_HEADER_LEN + RECIP_SUBRECORD_LEN
    );
    assert!(
        open(&alice, &object_bytes).is_ok(),
        "the control must open, or nothing below is about the edit"
    );
    (alice, object_bytes)
}

fn open(kp: &RecipientKeypair, blob: &[u8]) -> dctl_crypto::Result<object::Opened> {
    object::open_as_recipient(kp.x_sk(), kp.dk(), &kp.key_id, blob)
}

/// The text of the refusal, or a panic naming what was accepted.
fn refusal(kp: &RecipientKeypair, blob: &[u8]) -> String {
    refused(open(kp, blob), "the object")
}

/// The same for any decode result, naming `what` in the panic.
///
/// Spelled out rather than `expect_err` because [`object::Opened`] deliberately
/// has no `Debug`: it holds the plaintext, and a harness printing one into a CI
/// log is the leak that omission exists to prevent.
fn refused(result: dctl_crypto::Result<object::Opened>, what: &str) -> String {
    match result {
        Ok(opened) => panic!(
            "{what} was accepted and yielded {} bytes of plaintext",
            opened.plaintext.len()
        ),
        Err(error) => error.to_string(),
    }
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

#[test]
fn a_block_shorter_than_its_own_header_is_refused_before_any_field_is_read() {
    // `kem_ct_len` is the object's own statement of how long the block is, and
    // the ten bytes of header are read by direct indexing on the strength of it.
    // Nine is the largest value that is still short, so it is the one that
    // decides whether the bound is `<` or `<=`.
    let (alice, object_bytes) = sealed_to_one();
    for declared in [0u16, 1, KEM_WRAP_HEADER_LEN as u16 - 1] {
        let mut edited = object_bytes.clone();
        put_u16(&mut edited, KEM_CT_LEN_AT, declared);
        assert!(
            refusal(&alice, &edited).contains("kem_wrap shorter than header"),
            "a block of {declared} bytes must be refused as short"
        );
    }
}

#[test]
fn a_block_written_by_a_build_this_one_does_not_implement_is_refused_by_name() {
    // Forward compatibility in the only safe direction. `kw_version` and
    // `hybrid_suite` name the rules the block was written under; `kw_flags` bit 0
    // is the only defined flag and §12.2 makes every other bit **critical**; the
    // reserved byte is a field a later build may take.
    //
    // Reading any of these under this build's rules would mean decapsulating with
    // a suite that is not the suite the sender used — and the failure mode is not
    // an error, it is a wrapping key derived from the wrong transcript, which
    // surfaces as "not a recipient" for someone who is one.
    let (alice, object_bytes) = sealed_to_one();
    for (offset, value, expected) in [
        (block::VERSION, 2u8, "unsupported kw_version"),
        (block::SUITE, 2, "unsupported hybrid_suite"),
        (block::FLAGS, 0x02, "unknown kw_flags bit set"),
        (block::RESERVED, 1, "kem_wrap reserved byte nonzero"),
    ] {
        let mut edited = object_bytes.clone();
        edited[BLOCK_AT + offset] = value;
        assert!(
            refusal(&alice, &edited).contains(expected),
            "byte {offset} of the block set to {value} must be refused as {expected:?}"
        );
    }
    // Bit 0 is defined, so it must NOT be refused — the flag check has to read
    // the mask rather than the byte, and this is the row that tells the two
    // apart. A block that advertises a sidecar opens exactly like one that does
    // not: the flag is a hint to the *reader* about where else a key might be
    // found, and this recipient's key is inline.
    //
    // The footer is repaired for this one case, and repairing it is the point.
    // §3's trailing footer is an unkeyed BLAKE3 over everything before it, so
    // every byte edit above breaks it too — which is why each of those asserts
    // its own named refusal rather than merely `is_err`, and why this one, which
    // must come back `Ok`, has to put the footer back before it can say so.
    // That the four bad values are refused *by name* is itself the proof that
    // §12.2's structural validation runs before the footer is consulted.
    let mut sidecar = object_bytes.clone();
    sidecar[BLOCK_AT + block::FLAGS] = 0x01;
    assert!(
        refusal(&alice, &sidecar).contains("footer"),
        "unrepaired, the edit is caught by the footer and nothing else"
    );
    open(&alice, &refooted(&sidecar)).expect("a block advertising a sidecar is read normally");
}

/// `object_bytes` with its §3 footer recomputed over the edited body.
///
/// The footer is unkeyed, so anyone who can edit an object can do this — which
/// is exactly why it cannot be what refuses a malformed one, and why
/// `tests/object_refusals.rs` repairs it in every case.
fn refooted(object_bytes: &[u8]) -> Vec<u8> {
    let body = &object_bytes[..object_bytes.len() - FOOTER_LEN];
    let mut out = body.to_vec();
    out.extend_from_slice(blake3::hash(body).as_bytes());
    out
}

#[test]
fn a_recipient_count_outside_the_frozen_range_is_refused() {
    // Zero recipients is a block with nothing in it, which `find` would walk in
    // no iterations and report as "not a recipient" — the same answer a genuinely
    // foreign object gives, so the object would look like somebody else's rather
    // than like a damaged one.
    //
    // The upper bound is §3's `kem_ct_len <= 65535` expressed in records. Above
    // it the count is a multiplier on a `usize` offset that the length check
    // downstream is then asked to reconcile, and 53 is where those two stop
    // agreeing.
    let (alice, object_bytes) = sealed_to_one();
    for count in [0u16, MAX_RECIP_COUNT + 1, u16::MAX] {
        let mut edited = object_bytes.clone();
        put_u16(&mut edited, BLOCK_AT + block::COUNT, count);
        assert!(
            refusal(&alice, &edited).contains("recip_count out of range"),
            "a block claiming {count} recipients must be refused"
        );
    }
}

#[test]
fn a_count_the_block_is_not_long_enough_for_is_refused_before_it_is_indexed() {
    // The check that turns `recip_count` from a number into a bound. Two
    // recipients in a block sized for one is *within* the 1..=53 range, so the
    // range check above passes it — and the second sub-record then lives at
    // offsets 1244..2478 of a 1244-byte block.
    //
    // This is the guard whose absence is a panic rather than a wrong answer, and
    // the edit is two bytes on an object anyone can fetch.
    let (alice, object_bytes) = sealed_to_one();
    let mut edited = object_bytes.clone();
    put_u16(&mut edited, BLOCK_AT + block::COUNT, 2);
    assert!(refusal(&alice, &edited).contains("kem_ct_len != 10 + Σ rec_len"));

    // And the same disagreement reached from the other side: the count is honest
    // and `kem_ct_len` is one byte short. Both directions matter, because the
    // check is an equality and a `<` would let one of them through.
    let mut short = object_bytes.clone();
    put_u16(
        &mut short,
        KEM_CT_LEN_AT,
        (KEM_WRAP_HEADER_LEN + RECIP_SUBRECORD_LEN) as u16 - 1,
    );
    assert!(refusal(&alice, &short).contains("kem_ct_len != 10 + Σ rec_len"));
}

#[test]
fn every_frozen_field_length_inside_a_sub_record_is_checked_before_any_crypto() {
    // A sub-record is four runs at fixed offsets, each preceded by its own
    // length: `ct_m` at 1088, `eph_pk` at 32, `wrapped_kw` at 72. Suite 1 freezes
    // all three, and the slicing below uses the *constants* — so these fields are
    // pure redundancy, and redundancy that nobody compares is a format bug
    // waiting for its first suite 2.
    //
    // Deleting these checks does not corrupt anything today. It removes the
    // statement that this reader and the writer agree about the shape of a
    // record, which is the only thing that will stand between suite 2 and a
    // reader that slices it at suite 1's offsets.
    let (alice, object_bytes) = sealed_to_one();
    for (offset, value, expected) in [
        (
            rec::CT_M_LEN,
            MLKEM768_CT_LEN as u16 - 1,
            "ct_m_len != 1088",
        ),
        (
            rec::EPH_PK_LEN,
            X25519_PK_LEN as u16 + 1,
            "eph_pk_len != 32",
        ),
        (
            rec::WRAPPED_LEN,
            WRAPPED_KW_LEN as u16 - 1,
            "wrapped_len != 72",
        ),
    ] {
        let mut edited = object_bytes.clone();
        put_u16(&mut edited, REC_AT + offset, value);
        assert!(
            refusal(&alice, &edited).contains(expected),
            "sub-record field at {offset} set to {value} must be refused as {expected:?}"
        );
    }
}

#[test]
fn an_object_cut_off_inside_its_recipient_block_is_refused_rather_than_indexed_past() {
    // Two truncations, each landing on a different guard, and both are what a
    // half-finished upload leaves behind.
    //
    // Sixty-nine bytes is one short of `kem_ct_len` itself: the head parses, and
    // the very next read is a two-byte field with one byte in front of it.
    // Anything between the head and the end of the block is the second case —
    // `kem_ct_len` is honest, and the bytes it describes are not all there.
    let (alice, object_bytes) = sealed_to_one();
    assert!(
        refusal(&alice, &object_bytes[..OBJECT_HEAD_LEN + 1]).contains("object truncated (u16)"),
        "an object that stops inside kem_ct_len must be refused"
    );
    assert!(
        refusal(&alice, &object_bytes[..BLOCK_AT + KEM_WRAP_HEADER_LEN])
            .contains("object truncated (kem_wrap)"),
        "an object that stops inside its recipient block must be refused"
    );
}

#[test]
fn a_key_id_that_is_not_the_supplied_keypairs_is_refused_up_front() {
    // `open_as_recipient` takes the `key_id` as a separate argument, and a
    // handle that does not belong to the keys beside it is a caller bug that
    // must not become a crypto question. The `key_id` selects which sub-record
    // is decapsulated; a wrong one selects somebody else's record, which then
    // fails its AEAD tag and is reported as *tamper*.
    //
    // That is the wrong diagnosis in the one place it costs most: an operator
    // told their archive is tampered with reaches for a backup, and an operator
    // told they passed the wrong identity reaches for the right one.
    let (alice, object_bytes) = sealed_to_one();
    let bob = derive_recipient(&keys::generate_key(), 0).expect("a second identity");
    let error = refused(
        object::open_as_recipient(alice.x_sk(), alice.dk(), &bob.key_id, &object_bytes),
        "a key_id that is not this keypair's",
    );
    assert!(error.contains("key_id does not match"), "{error}");

    // The genuine "not a recipient" answer is still available and still distinct,
    // so the check above has not swallowed it.
    let stranger = refusal(&bob, &object_bytes);
    assert!(
        stranger.contains("not a recipient"),
        "an identity that is simply not in the block must say so: {stranger}"
    );
    assert_eq!(bob.key_id.len(), KEY_ID_LEN);
}

#[test]
fn the_recipient_count_a_sealer_is_asked_for_is_bounded_at_both_ends() {
    // The writer's side of `recip_count`. Zero recipients produces an object
    // nobody can ever open — including the vault that wrote it, since
    // `kem_id=1` has no symmetric fallback (§12.8) — and it would be written
    // without complaint, which is [the plan](https://doc.dctl.sh/project/plan) §6's forbidden outcome reached by
    // way of a successful `dctl share`.
    let root = keys::generate_key();
    let alice = derive_recipient(&root, 0).expect("a recipient");
    let none = object::seal_to_recipients(&[], b"payload", &Metadata::new("f"), CHUNK)
        .expect_err("an object nobody can open must not be sealed");
    assert!(none.to_string().contains("recipient count out of range"));

    let too_many: Vec<_> =
        std::iter::repeat_n(alice.public.clone(), usize::from(MAX_RECIP_COUNT) + 1).collect();
    let over = object::seal_to_recipients(&too_many, b"payload", &Metadata::new("f"), CHUNK)
        .expect_err("more recipients than kem_ct_len can frame must be refused");
    assert!(over.to_string().contains("recipient count out of range"));
}

#[test]
fn open_with_kw_refuses_an_object_that_is_not_a_recipient_object() {
    // The §12.6 sidecar fallback: the vault has already recovered `KW` by some
    // other route and hands it here to finish the decode. Both of its guards are
    // reached from the vault's own read path, and neither had a test.
    //
    // A `kem_id=0` object has no `kem_wrap` block at all, so offset 68 is
    // `wrapped_dek` rather than `kem_ct_len` — reading it as a length is reading
    // ciphertext as a number, and the block it describes is wherever that lands.
    let root = keys::generate_key();
    let symmetric =
        object::seal(&root, b"payload", &Metadata::new("f"), CHUNK).expect("a kem_id=0 object");
    let error = refused(
        object::open_with_kw(&root, &symmetric),
        "a kem_id=0 object handed to the hybrid path",
    );
    assert!(error.contains("not a kem_id=1 object"), "{error}");

    // …and a hybrid object whose block is not all there is refused on length
    // rather than handed to `open_core` with an end offset past the buffer.
    let (_, object_bytes) = sealed_to_one();
    let kw = [0u8; 32];
    let error = refused(
        object::open_with_kw(&kw, &object_bytes[..BLOCK_AT + KEM_WRAP_HEADER_LEN]),
        "a truncated recipient block",
    );
    assert!(error.contains("object truncated (kem_wrap)"), "{error}");
}
