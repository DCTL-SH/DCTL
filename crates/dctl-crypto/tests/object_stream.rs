//! Constant-memory streaming seal/open (`object::seal_stream` / `object::open_stream`).
//!
//! The load-bearing property is **byte-format identity** with the buffered path: an object
//! produced by `seal_stream` (fed a `Cursor` over the plaintext) MUST decode via the
//! existing `object::open` and yield the same plaintext, `size`, `path_hint`, and the same
//! `content_blake3` the buffered `seal` records for that input. `open_stream` must
//! round-trip objects from BOTH sealers and reject tampered/truncated objects.

use std::io::Cursor;

use dctl_crypto::keys;
use dctl_crypto::object::{self, Metadata};

/// Deterministic pseudo-random plaintext of length `n`.
fn plaintext(n: usize) -> Vec<u8> {
    (0..n)
        .map(|i| (i.wrapping_mul(7).wrapping_add(3)) as u8)
        .collect()
}

/// `seal_stream` a `Cursor` over `data` into an owned object blob.
fn seal_stream_vec(root: &[u8; 32], data: &[u8], meta: &Metadata, chunk_size: u32) -> Vec<u8> {
    let mut input = Cursor::new(data.to_vec());
    let mut out = Vec::new();
    object::seal_stream(
        root,
        &mut input,
        data.len() as u64,
        meta,
        chunk_size,
        &mut out,
    )
    .expect("seal_stream");
    out
}

/// The whole point: a streamed object decodes with the *buffered* opener, bit-for-bit —
/// same plaintext, size, path_hint, and the same content hash the buffered seal produces.
#[test]
fn seal_stream_decodes_with_buffered_open() {
    let root = keys::generate_key();
    let cs = 64u32;
    for len in [0usize, 1, 63, 64, 65, 127, 128, 1000] {
        let data = plaintext(len);
        let meta = Metadata::new("dir/movie.mov");

        let streamed = seal_stream_vec(&root, &data, &meta, cs);
        let opened = object::open(&root, &streamed).expect("buffered open of streamed object");
        assert_eq!(opened.plaintext.as_slice(), data.as_slice(), "len={len}");

        let md = opened.metadata.expect("metadata present");
        assert_eq!(md.path_hint, "dir/movie.mov", "len={len}");
        assert_eq!(md.size, len as u64, "len={len}");
        assert_ne!(md.content_blake3, [0u8; 32], "len={len}");

        // content_blake3 is a pure function of the plaintext → identical to buffered seal.
        let buffered = object::seal(&root, &data, &meta, cs).expect("seal");
        let buffered_md = object::open(&root, &buffered)
            .expect("open buffered")
            .metadata
            .expect("buffered metadata");
        assert_eq!(
            md.content_blake3, buffered_md.content_blake3,
            "content hash must match the buffered seal, len={len}"
        );
    }
}

/// `open_stream` round-trips objects from BOTH sealers: its `Write` output equals the
/// plaintext, and it returns the same metadata the buffered opener does.
#[test]
fn open_stream_roundtrips_both_sealers() {
    let root = keys::generate_key();
    let cs = 64u32;
    for len in [0usize, 1, 63, 64, 65, 127, 128, 1000] {
        let data = plaintext(len);
        let meta = Metadata::new("clip.bin");

        let from_buffer = object::seal(&root, &data, &meta, cs).expect("seal");
        let from_stream = seal_stream_vec(&root, &data, &meta, cs);

        for (label, obj) in [("buffer", &from_buffer), ("stream", &from_stream)] {
            let mut out = Vec::new();
            let md = object::open_stream(&root, obj, &mut out)
                .unwrap_or_else(|_| panic!("open_stream {label} len={len}"));
            assert_eq!(out.as_slice(), data.as_slice(), "{label} len={len}");
            let md = md.expect("metadata present");
            assert_eq!(md.size, len as u64, "{label} len={len}");
            assert_eq!(md.path_hint, "clip.bin", "{label} len={len}");
        }
    }
}

/// A larger, multi-chunk object streams correctly through both directions.
#[test]
fn stream_multichunk_roundtrip() {
    let root = keys::generate_key();
    let data = plaintext(1_000_000); // ~15 chunks at 64 KiB
    let cs = 64 * 1024;
    let obj = seal_stream_vec(&root, &data, &Metadata::new("big.mov"), cs);

    // Buffered open agrees.
    assert_eq!(
        object::open(&root, &obj)
            .expect("open")
            .plaintext
            .as_slice(),
        data.as_slice()
    );
    // Streaming open agrees.
    let mut out = Vec::new();
    object::open_stream(&root, &obj, &mut out).expect("open_stream");
    assert_eq!(out.as_slice(), data.as_slice());
}

/// `open_stream` verifies every chunk tag: a flipped chunk byte is rejected even when the
/// whole-object footer is recomputed to match (so the footer check cannot mask it).
#[test]
fn open_stream_rejects_tampered_chunk() {
    let root = keys::generate_key();
    let data = plaintext(200);
    let cs = 64u32;
    let obj = seal_stream_vec(&root, &data, &Metadata::new("f"), cs);

    // Sanity: the untouched object streams out.
    let mut ok = Vec::new();
    assert!(object::open_stream(&root, &obj, &mut ok).is_ok());

    // Flip a byte inside the first chunk ciphertext, then rewrite the footer over the
    // tampered body so the redundant footer check passes — the per-chunk Poly1305 tag is
    // now the *only* gate, and it must still reject.
    let meta_len = u32::from_le_bytes([obj[142], obj[143], obj[144], obj[145]]) as usize;
    let first_chunk_off = 146 + meta_len;
    let mut t = obj.clone();
    t[first_chunk_off + 1] ^= 0xFF;
    let body_end = t.len() - 32;
    let refreshed = blake3::hash(&t[..body_end]);
    t[body_end..].copy_from_slice(refreshed.as_bytes());

    let mut sink = Vec::new();
    assert!(
        object::open_stream(&root, &t, &mut sink).is_err(),
        "tampered chunk must fail its Poly1305 tag"
    );
}

/// `open_stream` rejects truncation (a chunk's ciphertext/tag is cut short).
#[test]
fn open_stream_rejects_truncation() {
    let root = keys::generate_key();
    let data = plaintext(200);
    let obj = seal_stream_vec(&root, &data, &Metadata::new("f"), 64);
    let truncated = &obj[..obj.len() - 50];
    let mut sink = Vec::new();
    assert!(
        object::open_stream(&root, truncated, &mut sink).is_err(),
        "truncated object must be rejected"
    );
}

/// A wrong `plaintext_len` (not matching the bytes the reader yields) is rejected up front.
#[test]
fn seal_stream_rejects_length_mismatch() {
    let root = keys::generate_key();
    let data = plaintext(100);
    let mut input = Cursor::new(data);
    let mut out = Vec::new();
    // Claim 101 bytes for a 100-byte input.
    let r = object::seal_stream(&root, &mut input, 101, &Metadata::new("f"), 64, &mut out);
    assert!(r.is_err(), "declared length must match the input");
}
