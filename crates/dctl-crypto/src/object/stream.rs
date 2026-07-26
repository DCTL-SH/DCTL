//! Constant-memory streaming seal / open for the symmetric `kem_id=0` DSF1 path (§3).
//!
//! [`seal_stream`] and [`open_stream`] produce and consume **byte-for-byte the same**
//! objects as the buffered [`super::seal`] / [`super::open`] (and therefore the C
//! reference decoder), but bound their working set to `O(chunk_size)` instead of
//! `O(file_size)` — the fix for the ~2×-file-size RAM blow-up on huge video.
//!
//! ## Why the sealer reads the input twice
//! `enc_metadata` ships *before* the payload chunks yet must carry `content_blake3` of the
//! **whole** plaintext (§4). A single forward pass cannot know that hash before it has to
//! write the metadata, so a constant-memory sealer streams the input twice (hence the
//! `Read + Seek` bound):
//! 1. **Pass 1** folds BLAKE3 over the entire input → `content_blake3`, then rewinds.
//! 2. **Pass 2** re-reads the input in `chunk_size` blocks, encrypting each in place of a
//!    scratch buffer and emitting `ct ‖ tag` straight to the writer.
//!
//! Output is written strictly in order to a plain `Write` (no output seek); the only
//! retained state is one chunk-sized scratch buffer plus the two BLAKE3 hashers.

use std::io::{Read, Seek, SeekFrom, Write};

use crate::aead;
use crate::constants::{
    ALGO_XCHACHA20_POLY1305, DEK_WRAP_AAD_PREFIX, FLAG_FOOTER, FOOTER_LEN, KEM_ID_NONE, KEY_LEN,
    MAX_CHUNK_SIZE, META_AAD_PREFIX, META_MAX_LEN, META_MIN_LEN, NONCE_LEN, OBJECT_HEAD_LEN,
    TAG_LEN, WRAPPED_DEK_LEN,
};
use crate::error::{CryptoError, Result};
use crate::keys::generate_key;
use crate::rng;

use super::head::{Head, build_head, parse_head};
use super::meta::{Metadata, build_metadata};
use super::nonce::{base_nonce, chunk_nonce, chunk_plaintext_len, metadata_nonce};
use super::seal::{decode_dek_and_meta, decrypt_chunk, open_core_streamed, prefixed_aad, read_u16};

/// Write `bytes` to `w` while folding them into the running footer hash `h`, so the
/// footer is computed in one streaming pass over exactly the bytes that hit the wire.
fn write_hashed<W: Write>(w: &mut W, h: &mut blake3::Hasher, bytes: &[u8]) -> Result<()> {
    h.update(bytes);
    w.write_all(bytes)
        .map_err(|_| CryptoError::Format("output write failed".into()))?;
    Ok(())
}

/// Constant-memory streaming seal of `input` (`plaintext_len` bytes) into a DSF1 object
/// under `wrapping_key` (root; `kem_id=0`), written in order to `output`.
///
/// Byte-identical to [`super::seal`] for the same input: it generates the same shape of
/// random DEK / `file_id` / `base_nonce`, and overwrites `meta.size = plaintext_len` and
/// `meta.content_blake3` with the streamed hash. `input` is read twice (§ module docs), so
/// it must be `Seek`; `plaintext_len` is supplied by the caller (typically the file size)
/// and MUST equal the number of bytes `input` yields, or the seal is rejected. Peak memory
/// is `O(chunk_size)` — one scratch buffer plus the content/footer BLAKE3 hashers.
pub fn seal_stream<R: Read + Seek, W: Write>(
    wrapping_key: &[u8; KEY_LEN],
    input: &mut R,
    plaintext_len: u64,
    meta: &Metadata,
    chunk_size: u32,
    output: &mut W,
) -> Result<()> {
    if chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE {
        return Err(CryptoError::Format("chunk_size out of range".into()));
    }
    let cs = chunk_size as usize;
    let chunk_count = plaintext_len.div_ceil(chunk_size as u64);

    // Fresh keying material — identical generation to the buffered `seal_core` path.
    let dek = generate_key();
    let mut file_id = [0u8; 16];
    rng::fill(&mut file_id);
    let bn = base_nonce();

    // The single retained buffer: reused for both passes → O(chunk_size), not O(file).
    let mut buf = vec![0u8; cs];

    // ── Pass 1: BLAKE3 over the entire input → content_blake3, then rewind. ──
    let mut content_hasher = blake3::Hasher::new();
    let mut total: u64 = 0;
    loop {
        let n = input
            .read(&mut buf)
            .map_err(|_| CryptoError::Format("input read failed".into()))?;
        if n == 0 {
            break;
        }
        content_hasher.update(&buf[..n]);
        total = total
            .checked_add(n as u64)
            .ok_or_else(|| CryptoError::Format("input longer than u64".into()))?;
    }
    if total != plaintext_len {
        return Err(CryptoError::Format("input length != plaintext_len".into()));
    }
    let content_blake3 = *content_hasher.finalize().as_bytes();
    input
        .seek(SeekFrom::Start(0))
        .map_err(|_| CryptoError::Format("input rewind failed".into()))?;

    // ── Build the head (byte-identical framing to `seal_core`, kem_id=0). ──
    let head = Head {
        algo: ALGO_XCHACHA20_POLY1305,
        kem_id: KEM_ID_NONE,
        flags: FLAG_FOOTER,
        chunk_size,
        plaintext_len,
        chunk_count,
        base_nonce: bn,
        file_id,
    };
    let head_bytes = build_head(&head);

    // ── wrapped_dek: root-wrapped DEK, random nonce, head-bound AAD (== buffer path). ──
    let wrapped_dek = aead::encrypt(
        wrapping_key,
        &dek[..],
        &prefixed_aad(DEK_WRAP_AAD_PREFIX, &head_bytes),
    )?;
    if wrapped_dek.len() != WRAPPED_DEK_LEN {
        return Err(CryptoError::Format("wrapped_dek wrong size".into()));
    }

    // ── enc_metadata: content_blake3 now known from pass 1; size = plaintext_len. ──
    let mut m = meta.clone();
    m.size = plaintext_len;
    m.content_blake3 = content_blake3;
    let meta_pt = build_metadata(&m)?;
    let mnonce = metadata_nonce();
    let meta_ct = aead::encrypt_with_nonce(
        &dek,
        &mnonce,
        &meta_pt,
        &prefixed_aad(META_AAD_PREFIX, &head_bytes),
    )?;
    let meta_len = NONCE_LEN + meta_ct.len();
    if !(META_MIN_LEN..=META_MAX_LEN).contains(&meta_len) {
        return Err(CryptoError::Format("meta_len out of range".into()));
    }
    let meta_len_u32: u32 = meta_len
        .try_into()
        .map_err(|_| CryptoError::Format("meta_len too large".into()))?;

    // ── Emit strictly in order, folding the footer BLAKE3 over every output byte.
    //    Layout: head ‖ kem_ct_len(0) ‖ wrapped_dek ‖ meta_len ‖ mnonce ‖ meta_ct ‖ … ──
    let mut footer_hasher = blake3::Hasher::new();
    write_hashed(output, &mut footer_hasher, &head_bytes)?;
    write_hashed(output, &mut footer_hasher, &0u16.to_le_bytes())?; // kem_ct_len = 0
    write_hashed(output, &mut footer_hasher, &wrapped_dek)?;
    write_hashed(output, &mut footer_hasher, &meta_len_u32.to_le_bytes())?;
    write_hashed(output, &mut footer_hasher, &mnonce)?;
    write_hashed(output, &mut footer_hasher, &meta_ct)?;

    // ── Pass 2: read each chunk, encrypt, emit ct‖tag, fold into the footer. ──
    // Stack AAD == `chunk_aad`: head(68) ‖ (i as u64 LE) — no per-chunk heap alloc.
    let mut aad = [0u8; OBJECT_HEAD_LEN + 8];
    aad[..OBJECT_HEAD_LEN].copy_from_slice(&head_bytes);
    for i in 0..chunk_count {
        let this_pt = chunk_plaintext_len(plaintext_len, cs as u64, i) as usize;
        input
            .read_exact(&mut buf[..this_pt])
            .map_err(|_| CryptoError::Format("input read failed".into()))?;
        let nonce = chunk_nonce(&bn, i);
        aad[OBJECT_HEAD_LEN..].copy_from_slice(&i.to_le_bytes());
        let ct = aead::encrypt_with_nonce(&dek, &nonce, &buf[..this_pt], &aad)?;
        write_hashed(output, &mut footer_hasher, &ct)?;
    }

    // ── footer = BLAKE3(all preceding output bytes) (§3, flags bit0). ──
    output
        .write_all(footer_hasher.finalize().as_bytes())
        .map_err(|_| CryptoError::Format("output write failed".into()))?;
    Ok(())
}

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
