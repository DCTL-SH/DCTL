//! What a DSF1 object refuses — the structural checks behind the footer, and the
//! head fields that decide whether this build may read the object at all.
//!
//! # Why these were unreached
//!
//! `tests/object.rs` already tampers and truncates: it flips a byte near the end,
//! it cuts forty bytes off, and it flips `chunk_size` in the head. The first two
//! stop at the **footer** — a whole-object BLAKE3 over everything before it —
//! and the truncation stops there for a reason worth stating, since the last
//! thirty-two bytes of what remains are payload read as though they were the
//! recorded hash. The third stops earlier still, at the `wrapped_dek` AAD that
//! binds the head. So the checks *behind* the footer — the per-chunk length
//! arithmetic, the trailing-bytes rule, the truncations inside the header region
//! — were never executed by the workspace suite, and deleting any of them left
//! the gate green.
//!
//! That matters because **the footer is unkeyed**. It proves an object was not
//! damaged in transit; it proves nothing at all against an edit, because whoever
//! made the edit can recompute it in one line — which is exactly what the helper
//! [`refooted`] below does. Every test here truncates or extends an object and
//! then *repairs the footer*, so what refuses it is the real guard: the AEAD tag
//! on each chunk, the `chunk_count` arithmetic bound into the head, and the
//! length invariants. Without the repair the tests would pass while asserting
//! nothing about any of them.
//!
//! # And the head, which is read before any key is used
//!
//! `parse_head` decides `version`, `algo`, `kem_id` and the flag word before a
//! byte is decrypted, and `crates/dctl-decode/FORMAT.md` §8 makes every undefined flag bit
//! **critical**: an object written by a later build must be refused, never
//! read past. Six of those refusals had no test, so a build that silently
//! accepted a format it does not implement would have passed the gate — and
//! "silently accepted" here means handing back plaintext assembled under rules
//! this version guessed at.

use std::io::Cursor;

use dctl_crypto::constants::{
    ALGO_XCHACHA20_POLY1305, FLAG_FOOTER, FOOTER_LEN, KEM_ID_NONE, MAX_CHUNK_SIZE, META_MAX_LEN,
    META_MIN_PLAINTEXT_LEN, NONCE_LEN, OBJECT_HEAD_LEN, OBJECT_VERSION, TAG_LEN, WRAPPED_DEK_LEN,
};
use dctl_crypto::keys;
use dctl_crypto::object::{self, Metadata};

/// Chunk size every object here is sealed at: small, so a handful of bytes of
/// payload is genuinely several chunks and the per-chunk arithmetic is exercised.
const CHUNK: u32 = 16;

fn sealed(root: &[u8; 32], bytes: &[u8]) -> Vec<u8> {
    object::seal(root, bytes, &Metadata::new("dir/file.bin"), CHUNK).expect("the object seals")
}

/// `body` with a **correct** footer appended.
///
/// The point of the whole file: anyone who can edit an object can do this, so a
/// test that skipped it would be asserting that BLAKE3 detects a change nobody
/// tried to hide. What must refuse these objects is everything else.
fn refooted(body: &[u8]) -> Vec<u8> {
    let mut out = body.to_vec();
    out.extend_from_slice(blake3::hash(body).as_bytes());
    out
}

/// The text of the refusal `open` gave, or a panic naming what was accepted.
fn refusal(root: &[u8; 32], blob: &[u8]) -> String {
    match object::open(root, blob) {
        Ok(opened) => panic!(
            "the object was accepted and yielded {} bytes of plaintext",
            opened.plaintext.len()
        ),
        Err(error) => error.to_string(),
    }
}

/// The same, through the constant-memory decoder.
fn stream_refusal(root: &[u8; 32], blob: &[u8]) -> String {
    let mut out = Vec::new();
    match object::open_stream(root, blob, &mut out) {
        Ok(_) => panic!("the streaming decoder accepted the object"),
        Err(error) => error.to_string(),
    }
}

/// And through the reader, which buffers only the header and is a third decoder.
fn reader_refusal(root: &[u8; 32], blob: &[u8]) -> String {
    let mut out = Vec::new();
    match object::open_reader(root, &mut Cursor::new(blob.to_vec()), &mut out) {
        Ok(_) => panic!("the reader accepted the object"),
        Err(error) => error.to_string(),
    }
}

// ── the head, decided before any key is used ─────────────────────────────────

#[test]
fn a_head_field_this_build_does_not_implement_is_refused_by_name() {
    // Forward compatibility, in the only direction that is safe: an object whose
    // head names a version, an algorithm or a KEM this build does not implement
    // must be **refused**, not read under this build's rules and handed back as
    // plaintext. Every one of these is a one-byte edit, all of them are what a
    // later DCTL will legitimately write, and none of them had a test.
    let root = keys::generate_key();
    let object_bytes = sealed(&root, b"a payload long enough to span several chunks");
    // The control: untouched, it opens.
    assert!(object::open(&root, &object_bytes).is_ok());

    for (offset, value, expected) in [
        (4, OBJECT_VERSION + 1, "unsupported object version"),
        (5, ALGO_XCHACHA20_POLY1305 + 1, "unsupported algo"),
        (6, 2u8, "unsupported kem_id"),
        // §8: every bit but FOOTER is undefined and undefined means critical.
        (7, FLAG_FOOTER | 0x02, "unknown critical object flag"),
    ] {
        let mut edited = object_bytes.clone();
        edited[offset] = value;
        let text = refusal(&root, &edited);
        assert!(
            text.contains(expected),
            "byte {offset} = {value:#04x} was refused for the wrong reason: {text}"
        );
        // The structural refusal has to arrive *before* the AEAD one. Both refuse,
        // and only one of them says what is actually wrong with the object — a
        // reader told "authentication failed" about a newer format goes looking
        // for a corrupted disk instead of for a newer build.
        assert!(
            !text.contains("authentication failed"),
            "byte {offset} reached the AEAD before the head check: {text}"
        );
    }

    // Shorter than the fixed head at all: there is nothing to parse.
    assert!(
        refusal(&root, &object_bytes[..OBJECT_HEAD_LEN - 1]).contains("object shorter than head"),
    );
}

#[test]
fn a_head_whose_chunk_count_does_not_match_its_length_is_refused() {
    // `chunk_count` is redundant with `plaintext_len` and `chunk_size`, and the
    // redundancy is the point: it is folded into every AAD, so a decoder that
    // trusted it over the arithmetic would loop a different number of times than
    // the sealer did. Refused before that can happen.
    let root = keys::generate_key();
    let mut edited = sealed(&root, b"several chunks worth of payload here");
    // chunk_count is the little-endian u64 at offset 20.
    let count = u64::from_le_bytes(edited[20..28].try_into().expect("eight bytes"));
    edited[20..28].copy_from_slice(&(count + 1).to_le_bytes());

    let text = refusal(&root, &edited);
    assert!(text.contains("chunk_count"), "{text}");
    assert!(!text.contains("authentication failed"), "{text}");
}

// ── behind the footer, where the real guards are ─────────────────────────────

#[test]
fn a_truncated_object_with_a_repaired_footer_is_still_refused() {
    // The whole reason this file exists. Every truncation test in the suite
    // stopped at the footer, and the footer is an unkeyed hash — so all of them
    // were really testing BLAKE3. Here the footer is recomputed over the
    // truncated body, exactly as anyone editing the object would, and what has
    // to refuse it is the chunk arithmetic bound into the authenticated head.
    let root = keys::generate_key();
    let payload = b"the quick brown fox jumps over the lazy dog".repeat(4);
    let object_bytes = sealed(&root, &payload);
    let body = &object_bytes[..object_bytes.len() - FOOTER_LEN];

    // One whole chunk short, and the footer says the result is intact.
    let short = refooted(&body[..body.len() - (CHUNK as usize + TAG_LEN)]);
    let text = refusal(&root, &short);
    assert!(text.contains("truncated"), "{text}");
    // …and the same object through the streaming decoder, because a guard on one
    // path is not a guard: a large file takes that one.
    assert!(stream_refusal(&root, &short).contains("truncated"));

    // The reader refuses it too, and says something different on purpose. It has
    // no `blob` to measure and reads forward, so the bytes missing from the last
    // chunk are made up out of the footer that follows — the length check cannot
    // fire, and what refuses the object is the chunk's own Poly1305 tag. Recorded
    // rather than smoothed over: the outcome is the same refusal, and an operator
    // reading "authentication failed" about a short download should be able to
    // find this line.
    assert!(reader_refusal(&root, &short).contains("authentication failed"));

    // Half a chunk short is the same finding: the last chunk's ciphertext is not
    // all there, and no amount of footer repair changes that.
    let ragged = refooted(&body[..body.len() - 5]);
    assert!(refusal(&root, &ragged).contains("truncated"));
    assert!(reader_refusal(&root, &ragged).contains("authentication failed"));
}

#[test]
fn bytes_appended_after_the_last_chunk_are_refused_rather_than_ignored() {
    // A decoder that stopped at `chunk_count` and ignored the rest would let an
    // object carry a payload nothing has authenticated — invisible to a reader,
    // and there for whatever reads the object next. The footer is repaired here
    // too, so the trailing-bytes rule is what refuses it.
    let root = keys::generate_key();
    let object_bytes = sealed(&root, b"a short payload");
    let mut body = object_bytes[..object_bytes.len() - FOOTER_LEN].to_vec();
    body.extend_from_slice(b"appended, authenticated by nothing");

    let extended = refooted(&body);
    assert!(refusal(&root, &extended).contains("trailing bytes"));
    assert!(stream_refusal(&root, &extended).contains("trailing bytes"));
    // The reader reaches the same refusal by the other road: reading forward, the
    // 32 bytes it takes to be the footer are the first 32 of the appended block,
    // so the whole-object hash it has been folding does not match them. Its own
    // trailing-bytes rule is what catches an object extended *after* the footer,
    // which is the next case.
    assert!(reader_refusal(&root, &extended).contains("footer mismatch"));

    let mut past_the_footer = object_bytes.clone();
    past_the_footer.extend_from_slice(b"after the footer entirely");
    assert!(reader_refusal(&root, &past_the_footer).contains("trailing bytes"));
    assert!(refusal(&root, &past_the_footer).contains("footer mismatch"));
}

#[test]
fn an_object_cut_off_inside_its_own_header_is_refused_at_the_field_that_is_missing() {
    // The header region is read before anything is authenticated, so every one of
    // these is a length check on attacker-supplied bytes and each has to refuse
    // rather than index past the end. Named individually because the difference
    // between them is the difference between a truncated upload and a corrupted
    // one, and an operator acts on that.
    let root = keys::generate_key();
    let object_bytes = sealed(&root, b"payload");

    // Past the head and the kem_ct_len, inside the wrapped DEK.
    let cut = OBJECT_HEAD_LEN + 2 + WRAPPED_DEK_LEN - 1;
    assert!(
        refusal(&root, &object_bytes[..cut]).contains("wrapped_dek"),
        "{}",
        refusal(&root, &object_bytes[..cut])
    );

    // Past the DEK and the meta_len, inside the encrypted metadata.
    let cut = OBJECT_HEAD_LEN + 2 + WRAPPED_DEK_LEN + 4 + 8;
    assert!(
        refusal(&root, &object_bytes[..cut]).contains("metadata"),
        "{}",
        refusal(&root, &object_bytes[..cut])
    );

    // And cut so that the declared footer cannot be there at all. The chunks are
    // gone with it, which is why the object is refused rather than served empty.
    let cut = object_bytes.len() - FOOTER_LEN - 1;
    let text = refusal(&root, &refooted(&object_bytes[..cut]));
    assert!(text.contains("truncated"), "{text}");
}

#[test]
fn a_meta_len_the_object_cannot_hold_is_refused_before_it_is_allocated() {
    // `meta_len` is a length taken from the object and used to size a read. A
    // decoder that believed a four-gigabyte metadata block would allocate one
    // before a single byte had authenticated, which is a denial of service any
    // stranger's object can trigger. Both bounds, because zero is as wrong as
    // huge and only one of them is obvious.
    let root = keys::generate_key();
    let object_bytes = sealed(&root, b"payload");
    let meta_len_at = OBJECT_HEAD_LEN + 2 + WRAPPED_DEK_LEN;

    for claimed in [0u32, u32::MAX] {
        let mut edited = object_bytes.clone();
        edited[meta_len_at..meta_len_at + 4].copy_from_slice(&claimed.to_le_bytes());
        let text = refusal(&root, &refooted(&edited[..edited.len() - FOOTER_LEN]));
        assert!(text.contains("meta_len out of range"), "{claimed}: {text}");
        // The reader path buffers the header itself and has its own copy of the
        // bound; it is the path a huge object takes, so it is the one that would
        // pay for a missing check.
        let text = reader_refusal(&root, &edited);
        assert!(text.contains("meta_len out of range"), "{claimed}: {text}");
    }
}

#[test]
fn a_kem_id_zero_object_that_claims_a_recipient_block_is_refused() {
    // `kem_ct_len` must be exactly zero when `kem_id` is zero, because every later
    // offset is computed from it: a non-zero value moves the wrapped DEK, the
    // metadata and the first chunk, and the decoder would read the object at the
    // wrong places while `kem_id` still said there is no recipient block.
    let root = keys::generate_key();
    let mut edited = sealed(&root, b"payload");
    edited[OBJECT_HEAD_LEN..OBJECT_HEAD_LEN + 2].copy_from_slice(&7u16.to_le_bytes());

    for text in [
        refusal(&root, &edited),
        stream_refusal(&root, &edited),
        reader_refusal(&root, &edited),
    ] {
        assert!(text.contains("kem_ct_len must be 0"), "{text}");
    }
    // And the head still says `kem_id = 0`, so this is the length field being
    // checked and not the KEM path being taken.
    assert_eq!(edited[6], KEM_ID_NONE);
}

#[test]
fn a_chunk_size_the_format_cannot_express_is_refused_before_anything_is_sealed() {
    // The sealer's own bound, and the reader's is already asserted through the
    // head. Zero would divide by zero deciding how many chunks there are; past
    // the ceiling would produce an object no conforming reader will open. Both
    // are caller mistakes and both have to be refused at the call rather than
    // written into an archive somebody restores from in five years.
    let root = keys::generate_key();
    for size in [0u32, MAX_CHUNK_SIZE + 1] {
        let error = object::seal(&root, b"x", &Metadata::new("f"), size)
            .expect_err("a chunk size outside the format must refuse");
        assert!(
            error.to_string().contains("chunk_size out of range"),
            "{size}: {error}"
        );
    }
    // The ceiling itself is inside the range, so the bound is `>` and not `>=`.
    assert!(object::seal(&root, b"x", &Metadata::new("f"), MAX_CHUNK_SIZE).is_ok());
}

#[test]
fn each_variable_length_metadata_field_is_capped_at_what_its_own_length_holds() {
    // §4 writes `path_hint`, `content_type` and `ext` behind `u16` lengths. A
    // field longer than its own length field would be written with a wrapped
    // count and read back as a different, shorter field — silently, and with the
    // remainder reinterpreted as the next field's bytes. Refused at build time
    // instead, by name, so the caller learns which field it was.
    let root = keys::generate_key();
    let too_long = usize::from(u16::MAX) + 1;

    for (meta, expected) in [
        (Metadata::new("x".repeat(too_long)), "path_hint too long"),
        (
            Metadata {
                content_type: Some("t".repeat(too_long)),
                ..Metadata::new("f")
            },
            "content_type too long",
        ),
        (
            Metadata {
                ext: vec![0u8; too_long],
                ..Metadata::new("f")
            },
            "ext too long",
        ),
    ] {
        let error = object::seal(&root, b"x", &meta, CHUNK)
            .expect_err("a field past its own length must refuse");
        assert!(error.to_string().contains(expected), "{error}");
    }
}

#[test]
fn the_sealers_own_metadata_cap_cannot_fire_and_the_arithmetic_says_why() {
    // `seal_core` re-checks `meta_len` against `META_MAX_LEN` after building the
    // metadata, and that check is **unreachable**: the three variable fields are
    // capped at `u16::MAX` each by the test above, so the largest metadata this
    // crate can produce is smaller than the cap by a wide margin.
    //
    // Written as arithmetic rather than as a comment because a comment does not
    // fail when somebody widens a length field to `u32`. If this assertion ever
    // goes red, the sealer's cap has become reachable and needs a test that
    // reaches it — which is the opposite of a coverage report telling the next
    // reader to go and hunt for one.
    let largest_plaintext = META_MIN_PLAINTEXT_LEN + 3 * usize::from(u16::MAX);
    let largest_meta_len = NONCE_LEN + largest_plaintext + TAG_LEN;
    assert!(
        largest_meta_len < META_MAX_LEN,
        "the sealer can now produce {largest_meta_len} bytes of metadata against a \
         {META_MAX_LEN}-byte cap, so `meta_len out of range` is reachable and untested"
    );
}

#[test]
fn an_object_that_stops_before_its_own_footer_is_refused() {
    // Distinct from a truncated *chunk*: here the object declares a footer in its
    // flags and ends before there is room for one. Reading the last thirty-two
    // bytes of whatever did arrive would compare the tail of the payload against
    // a hash, which fails for the wrong reason and sends the operator looking for
    // corruption instead of for the rest of the download.
    let root = keys::generate_key();
    let object_bytes = sealed(&root, b"a payload spanning several chunks of it");
    // `meta_len` is the little-endian u32 after head ‖ kem_ct_len ‖ wrapped_dek.
    let meta_len_at = OBJECT_HEAD_LEN + 2 + WRAPPED_DEK_LEN;
    let meta_len = u32::from_le_bytes(
        object_bytes[meta_len_at..meta_len_at + 4]
            .try_into()
            .expect("four bytes"),
    ) as usize;
    let first_chunk = meta_len_at + 4 + meta_len;

    // The **exact** message, not merely "footer". Asserting the substring alone
    // is what the first version of this test did, and it passed with the guard
    // deleted: without it the decoder computes a negative-in-spirit `body_end`,
    // reads thirty-two bytes of payload as though they were the footer, and
    // refuses with `footer mismatch` — which contains the word and means
    // something else entirely.
    let short = &object_bytes[..first_chunk + FOOTER_LEN - 1];
    assert_eq!(refusal(&root, short), "format: object truncated (footer)");
    assert_eq!(
        stream_refusal(&root, short),
        "format: object truncated (footer)"
    );
}

#[test]
fn a_length_field_that_runs_off_the_end_of_the_object_is_refused_not_indexed_past() {
    // Two fixed-width reads sit between the head and the metadata, and both take
    // their offsets from fields an attacker supplies. Reading either past the end
    // of a short object is the one failure a `#![forbid(unsafe_code)]` crate turns
    // into a panic instead of a refusal — a `dctl ls` that aborts with no exit
    // code, no message and no audit record.
    let root = keys::generate_key();
    let object_bytes = sealed(&root, b"payload");

    // One byte past the head: `kem_ct_len` needs two.
    assert!(
        refusal(&root, &object_bytes[..OBJECT_HEAD_LEN + 1]).contains("u16"),
        "{}",
        refusal(&root, &object_bytes[..OBJECT_HEAD_LEN + 1])
    );
    // Two bytes past the wrapped DEK: `meta_len` needs four.
    let cut = OBJECT_HEAD_LEN + 2 + WRAPPED_DEK_LEN + 2;
    assert!(
        refusal(&root, &object_bytes[..cut]).contains("u32"),
        "{}",
        refusal(&root, &object_bytes[..cut])
    );
}
