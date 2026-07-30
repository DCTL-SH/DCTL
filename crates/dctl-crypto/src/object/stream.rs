//! Constant-memory streaming **open** for the symmetric `kem_id=0` DSF1 path (§3).
//!
//! [`open_stream`] and [`open_reader`] consume byte-for-byte the same objects as the
//! buffered [`super::open`] (and therefore the C reference decoder), but bound their
//! working set to `O(chunk_size)` instead of `O(file_size)` — the fix for the
//! ~2x-file-size RAM blow-up on huge video.
//!
//! The seal half used to live here too. It is now [`super::sealer`], which produces the
//! identical bytes and additionally answers, *before* the object exists, what its
//! `file_id` and its exact length will be — the two facts a caller needs to upload an
//! object it has not produced yet. Splitting the file put the two directions of one
//! format in two places, which is what the sealer's second phase made worth doing.

use std::io::{Read, Seek, Write};

use crate::constants::{
    FOOTER_LEN, KEM_ID_NONE, KEY_LEN, META_MAX_LEN, META_MIN_LEN, OBJECT_HEAD_LEN, TAG_LEN,
    WRAPPED_DEK_LEN,
};
use crate::error::{CryptoError, Result};

use super::head::parse_head;
use super::meta::Metadata;
use super::nonce::chunk_plaintext_len;
use super::seal::{decode_dek_and_meta, decrypt_chunk, open_core_streamed, read_u16};

/// Constant-memory streaming open of a symmetric `kem_id=0` DSF1 `blob` under
/// `wrapping_key` (root), writing the recovered plaintext in order to `output`.
///
/// Every chunk tag (and the footer, if present) is verified; each chunk's plaintext is
/// written the moment its tag verifies and then dropped, so the whole plaintext is never
/// held in RAM (peak ≈ the borrowed `blob` + one chunk). Returns the object's metadata
/// (absent only for an unknown `schema_version`, skipped-and-served per §8). A tampered or
/// truncated object is rejected via [`CryptoError`]; note that when some bytes have already
/// verified and streamed out, `output` may hold a partial prefix on the error path.
pub fn open_stream<W: Write>(
    wrapping_key: &[u8; KEY_LEN],
    blob: &[u8],
    output: &mut W,
) -> Result<Option<Metadata>> {
    let head = parse_head(blob)?;
    if head.kem_id != KEM_ID_NONE {
        return Err(CryptoError::Format(
            "kem_id=1 object needs the hybrid opener (§12)".into(),
        ));
    }
    let kem_ct_len = read_u16(blob, OBJECT_HEAD_LEN)?;
    if kem_ct_len != 0 {
        return Err(CryptoError::Format(
            "kem_ct_len must be 0 for kem_id=0".into(),
        ));
    }
    // wrapped_dek sits at offset 70 (68-byte head + 2-byte kem_ct_len).
    open_core_streamed(wrapping_key, blob, &head, OBJECT_HEAD_LEN + 2, |chunk| {
        output
            .write_all(chunk)
            .map_err(|_| CryptoError::Format("output write failed".into()))
    })
}

/// `read_exact` that maps any I/O shortfall (incl. premature EOF) to a truncation
/// [`CryptoError::Format`], so the reader path reports the same failure class as the
/// buffered `open`/`open_stream` on a short object.
fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<()> {
    r.read_exact(buf)
        .map_err(|_| CryptoError::Format("object truncated".into()))
}

/// Constant-memory streaming open of a symmetric `kem_id=0` DSF1 object read straight
/// from `object` (a `Read`), writing the recovered plaintext in order to `out`.
///
/// This is the reader-based twin of [`open_stream`]: where `open_stream` needs the whole
/// object as a borrowed `&[u8]`, this pulls the object through a reader and never holds
/// more than one chunk (`ct(this_pt) ‖ tag`) plus the bounded header prefix in memory, so
/// peak memory is `O(chunk_size)` over an arbitrarily large object — the fix for reading
/// huge video without a whole-object buffer. `open_stream`/`open`/`open_reader` share the
/// exact DEK-unwrap, metadata, and per-chunk decode logic
/// ([`decode_dek_and_meta`]/[`decrypt_chunk`]) so the decoders cannot drift.
///
/// **Order of operations (matches the buffered path):** read + validate the fixed head,
/// reject `kem_id != 0`, buffer the bounded `head ‖ kem_ct_len ‖ wrapped_dek ‖ meta_len ‖
/// enc_metadata` prefix (`meta_len ≤ 256 KiB`, so this is `O(1)` in the object size),
/// unwrap the DEK (authenticating the head) and decode metadata, then stream every chunk:
/// each chunk's plaintext is written to `out` only after its Poly1305 tag verifies, then
/// dropped. Returns the object's metadata (absent only for an unknown `schema_version`,
/// skipped-and-served per §8).
///
/// **Integrity & footer handling.** Every chunk tag and the metadata/DEK tags are verified
/// — the per-chunk Poly1305 tag (binding the head, hence `plaintext_len`/`chunk_count`/
/// `file_id`) is the real integrity gate, so truncation and reorder are caught with or
/// without the footer (§3). When the footer flag is set this fold-verifies it too, by
/// streaming a BLAKE3 over every byte read before the footer and comparing against the
/// trailing 32 bytes; it then rejects any bytes past the object's declared end. A tampered
/// chunk, tampered footer, or truncation is rejected via [`CryptoError`]; on the error
/// path — once some chunks have verified and streamed — `out` may hold a partial prefix
/// (the vault write-to-temp-then-rename wrapper makes the file-level result atomic).
pub fn open_reader<R: Read + Seek, W: Write>(
    wrapping_key: &[u8; KEY_LEN],
    object: &mut R,
    out: &mut W,
) -> Result<Option<Metadata>> {
    // ── Fixed head (68 bytes). ──
    let mut head_bytes = [0u8; OBJECT_HEAD_LEN];
    read_full(object, &mut head_bytes)?;
    let head = parse_head(&head_bytes)?;
    if head.kem_id != KEM_ID_NONE {
        return Err(CryptoError::Format(
            "kem_id=1 object needs the hybrid opener (§12)".into(),
        ));
    }

    // ── Buffer the bounded header prefix so the shared decoder sees a contiguous slice:
    //    head(68) ‖ kem_ct_len(2) ‖ wrapped_dek(72) ‖ meta_len(4) ‖ enc_metadata(meta_len).
    //    `meta_len ≤ META_MAX_LEN` (256 KiB) → O(1) in the object's size. ──
    let mut header = Vec::with_capacity(OBJECT_HEAD_LEN + 2 + WRAPPED_DEK_LEN + 4 + META_MIN_LEN);
    header.extend_from_slice(&head_bytes);

    let mut u16buf = [0u8; 2];
    read_full(object, &mut u16buf)?;
    if u16::from_le_bytes(u16buf) != 0 {
        return Err(CryptoError::Format(
            "kem_ct_len must be 0 for kem_id=0".into(),
        ));
    }
    header.extend_from_slice(&u16buf);

    let mut dek_buf = [0u8; WRAPPED_DEK_LEN];
    read_full(object, &mut dek_buf)?;
    header.extend_from_slice(&dek_buf);

    let mut lenbuf = [0u8; 4];
    read_full(object, &mut lenbuf)?;
    let meta_len = u32::from_le_bytes(lenbuf) as usize;
    if !(META_MIN_LEN..=META_MAX_LEN).contains(&meta_len) {
        return Err(CryptoError::Format("meta_len out of range".into()));
    }
    header.extend_from_slice(&lenbuf);

    let meta_start = header.len();
    header.resize(meta_start + meta_len, 0);
    read_full(object, &mut header[meta_start..])?;

    // ── DEK unwrap (authenticates the head) + metadata decode — shared with the buffered
    //    path so the two decoders can never drift. `off` lands at the first chunk. ──
    let (dek, metadata, off) =
        decode_dek_and_meta(wrapping_key, &header, &head, OBJECT_HEAD_LEN + 2)?;
    debug_assert_eq!(off, header.len());

    // Footer flag → fold a BLAKE3 over every byte read before the footer (the header we
    // buffered plus each chunk's ciphertext) for a redundant whole-object check.
    let mut footer_hasher = if head.has_footer() {
        let mut h = blake3::Hasher::new();
        h.update(&header);
        Some(h)
    } else {
        None
    };

    // ── Stream chunks: read `this_pt+16`, verify+decrypt, write plaintext, drop. The DEK
    //    unwrap above already authenticated `chunk_size` (≤ 16 MiB via `parse_head`), so
    //    this single working buffer is the whole peak — O(chunk_size), never O(file). ──
    let cs = head.chunk_size as u64;
    let mut buf = vec![0u8; head.chunk_size as usize + TAG_LEN];
    let mut produced: u64 = 0;
    for i in 0..head.chunk_count {
        let this_pt = chunk_plaintext_len(head.plaintext_len, cs, i) as usize;
        let ct_len = this_pt + TAG_LEN;
        read_full(object, &mut buf[..ct_len])?;
        if let Some(h) = footer_hasher.as_mut() {
            h.update(&buf[..ct_len]);
        }
        let pt = decrypt_chunk(&dek, &head, &head_bytes, i, &buf[..ct_len])?;
        out.write_all(&pt)
            .map_err(|_| CryptoError::Format("output write failed".into()))?;
        produced += pt.len() as u64;
    }
    if produced != head.plaintext_len {
        return Err(CryptoError::Format("decrypted length mismatch".into()));
    }

    // Footer (if present): read the trailing 32 bytes and compare to the streamed hash.
    if let Some(h) = footer_hasher {
        let mut footer = [0u8; FOOTER_LEN];
        read_full(object, &mut footer)?;
        if footer != *h.finalize().as_bytes() {
            return Err(CryptoError::Format("footer mismatch".into()));
        }
    }

    // Nothing may follow the last chunk (or the footer) — reject trailing bytes, matching
    // the buffered path's `p != body_end` check.
    let mut extra = [0u8; 1];
    match object.read(&mut extra) {
        Ok(0) => {}
        Ok(_) => {
            return Err(CryptoError::Format(
                "trailing bytes after last chunk".into(),
            ));
        }
        Err(_) => return Err(CryptoError::Format("input read failed".into())),
    }

    Ok(metadata)
}
