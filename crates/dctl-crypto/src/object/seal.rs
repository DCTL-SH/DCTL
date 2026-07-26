//! DSF1 self-describing object: seal / open on the symmetric `kem_id=0` path (§3).
//!
//! The DEK is wrapped once under `wrapping_key` (root); chunks and metadata are sealed
//! under the DEK in disjoint nonce spaces. Every wrap's AAD folds the full 68-byte head,
//! so header tampering is detected even on an empty, footer-less object.

use zeroize::Zeroizing;

use crate::aead;
use crate::constants::{
    ALGO_XCHACHA20_POLY1305, DEK_WRAP_AAD_PREFIX, FLAG_FOOTER, FOOTER_LEN, KEM_ID_NONE, KEY_LEN,
    MAX_CHUNK_SIZE, META_AAD_PREFIX, META_MAX_LEN, META_MIN_LEN, META_SCHEMA_V1, NONCE_LEN,
    OBJECT_HEAD_LEN, TAG_LEN, WRAPPED_DEK_LEN,
};
use crate::error::{CryptoError, Result};
use crate::keys::generate_key;
use crate::rng;

use super::head::{Head, build_head, parse_head};
use super::meta::{Metadata, build_metadata, parse_metadata};
use super::nonce::{base_nonce, chunk_nonce, chunk_plaintext_len, metadata_nonce};

/// Shared assembly for both `kem_id` paths. Produces the DSF1 byte stream:
/// `head ‖ kem_ct_len(u16) ‖ kem_wrap ‖ wrapped_dek ‖ meta_len ‖ metadata ‖ chunks ‖
/// footer`. The DEK is generated here and wrapped under `dek_wrapping_key` (the root for
/// `kem_id=0`; the per-object `KW` for `kem_id=1`).
///
/// The head (`kem_id`, `file_id`, `base_nonce`, sizes) is built **first**, then handed to
/// `build_kem_wrap` so the recipient wraps bind exactly the head that ships in the object
/// (§12.1/§12.8 fold `fixed_head` into every AAD). For `kem_id=0` the closure returns an
/// empty block and `kem_ct_len` is 0, so the emitted bytes are byte-for-byte identical to
/// the original symmetric layout (§3).
pub(super) fn seal_core(
    kem_id: u8,
    dek_wrapping_key: &[u8; KEY_LEN],
    build_kem_wrap: impl FnOnce(&[u8; OBJECT_HEAD_LEN]) -> Result<Vec<u8>>,
    plaintext: &[u8],
    meta: &Metadata,
    chunk_size: u32,
) -> Result<Vec<u8>> {
    if chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE {
        return Err(CryptoError::Format("chunk_size out of range".into()));
    }
    let cs = chunk_size as usize;
    let dek = generate_key();
    let mut file_id = [0u8; 16];
    rng::fill(&mut file_id);
    let bn = base_nonce();
    let plaintext_len = plaintext.len() as u64;
    let chunk_count = plaintext_len.div_ceil(chunk_size as u64);

    let head = Head {
        algo: ALGO_XCHACHA20_POLY1305,
        kem_id,
        flags: FLAG_FOOTER,
        chunk_size,
        plaintext_len,
        chunk_count,
        base_nonce: bn,
        file_id,
    };
    let head_bytes = build_head(&head);

    // Build the recipient-wrap block against the finished head (empty for kem_id=0).
    let kem_wrap = build_kem_wrap(&head_bytes)?;
    let kem_ct_len: u16 = kem_wrap
        .len()
        .try_into()
        .map_err(|_| CryptoError::Format("kem_wrap too large".into()))?;

    // wrapped_dek: under `dek_wrapping_key`, random nonce, AAD binds the full head.
    // Identical to §3/`kem_id=0` — only the key differs (KW for `kem_id=1`).
    let wrapped_dek = aead::encrypt(
        dek_wrapping_key,
        &dek[..],
        &prefixed_aad(DEK_WRAP_AAD_PREFIX, &head_bytes),
    )?;
    if wrapped_dek.len() != WRAPPED_DEK_LEN {
        return Err(CryptoError::Format("wrapped_dek wrong size".into()));
    }

    // metadata: under DEK, nonce byte[23]=0x01, AAD binds head. Fill size + content hash.
    let mut m = meta.clone();
    m.size = plaintext_len;
    m.content_blake3 = *blake3::hash(plaintext).as_bytes();
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

    let mut out = Vec::with_capacity(
        OBJECT_HEAD_LEN
            + 2
            + kem_wrap.len()
            + WRAPPED_DEK_LEN
            + 4
            + meta_len
            + plaintext.len()
            + chunk_count as usize * TAG_LEN
            + FOOTER_LEN,
    );
    out.extend_from_slice(&head_bytes);
    out.extend_from_slice(&kem_ct_len.to_le_bytes());
    out.extend_from_slice(&kem_wrap);
    out.extend_from_slice(&wrapped_dek);
    out.extend_from_slice(&(meta_len as u32).to_le_bytes());
    out.extend_from_slice(&mnonce);
    out.extend_from_slice(&meta_ct);

    for (i, chunk) in plaintext.chunks(cs).enumerate() {
        let n = chunk_nonce(&bn, i as u64);
        let ct = aead::encrypt_with_nonce(&dek, &n, chunk, &chunk_aad(&head_bytes, i as u64))?;
        out.extend_from_slice(&ct);
    }

    let footer = blake3::hash(&out);
    out.extend_from_slice(footer.as_bytes());
    Ok(out)
}

/// Shared reader for both `kem_id` paths, streaming each verified chunk's plaintext to
/// `emit` — the single decode routine behind both the buffered [`open_core`] and the
/// constant-memory [`super::stream::open_stream`]. `off` points at `wrapped_dek` (offset
/// 70 for `kem_id=0`; `70 + K` for `kem_id=1`); `dek_wrapping_key` is the root or the
/// recovered `KW`. Unwraps the DEK, decrypts + schema-checks metadata, verifies the
/// footer (if present) and every chunk tag. `emit` is only ever called with plaintext
/// from a chunk whose Poly1305 tag has already verified, and never before the DEK unwrap
/// authenticates the head — so a caller may size buffers off `head.plaintext_len` inside
/// `emit` without exposing a pre-auth allocation to a forged header.
pub(super) fn open_core_streamed<F: FnMut(&[u8]) -> Result<()>>(
    dek_wrapping_key: &[u8; KEY_LEN],
    blob: &[u8],
    head: &Head,
    off: usize,
    mut emit: F,
) -> Result<Option<Metadata>> {
    let head_bytes = &blob[0..OBJECT_HEAD_LEN];

    // DEK unwrap + metadata decode is shared verbatim with the reader path
    // ([`super::stream::open_reader`]) so the two decoders can never drift.
    let (dek, metadata, off) = decode_dek_and_meta(dek_wrapping_key, blob, head, off)?;

    // Footer (redundant whole-object check). Hashing the borrowed ciphertext blob is
    // O(1) extra memory, so it stays cheap even on the streaming path.
    let footer_len = if head.flags & FLAG_FOOTER != 0 {
        FOOTER_LEN
    } else {
        0
    };
    if blob.len() < off + footer_len {
        return Err(CryptoError::Format("object truncated (footer)".into()));
    }
    let body_end = blob.len() - footer_len;
    if footer_len != 0 {
        let expected = blake3::hash(&blob[..body_end]);
        if blob[body_end..] != expected.as_bytes()[..] {
            return Err(CryptoError::Format("footer mismatch".into()));
        }
    }

    // Chunks — decrypted and emitted one at a time, so a streaming caller never holds
    // more than a single chunk's plaintext at once.
    let cs = head.chunk_size as u64;
    let mut p = off;
    let mut produced: u64 = 0;
    for i in 0..head.chunk_count {
        let this_pt = chunk_plaintext_len(head.plaintext_len, cs, i) as usize;
        let ct_len = this_pt + TAG_LEN;
        if p + ct_len > body_end {
            return Err(CryptoError::Format("object truncated (chunk)".into()));
        }
        let pt = decrypt_chunk(&dek, head, head_bytes, i, &blob[p..p + ct_len])?;
        emit(&pt)?;
        produced += pt.len() as u64;
        p += ct_len;
    }
    if p != body_end {
        return Err(CryptoError::Format(
            "trailing bytes after last chunk".into(),
        ));
    }
    if produced != head.plaintext_len {
        return Err(CryptoError::Format("decrypted length mismatch".into()));
    }

    Ok(metadata)
}

/// Unwrap the DEK and decode + validate the metadata from the fixed header region of an
/// object, starting at `off` (the `wrapped_dek` offset: 70 for `kem_id=0`, `70 + K` for
/// `kem_id=1`). `blob` need only contain the bytes through `enc_metadata` — the reader
/// path buffers exactly that bounded prefix (`meta_len ≤ 256 KiB`) and hands it here, so
/// the DEK/metadata decode is byte-identical to the buffered [`open_core_streamed`].
///
/// Returns the unwrapped DEK (authenticating the head), the metadata (absent only for an
/// unknown `schema_version`, skipped-and-served per §8), and the offset just past
/// `enc_metadata` (where the first chunk begins).
pub(super) fn decode_dek_and_meta(
    dek_wrapping_key: &[u8; KEY_LEN],
    blob: &[u8],
    head: &Head,
    mut off: usize,
) -> Result<(Zeroizing<[u8; KEY_LEN]>, Option<Metadata>, usize)> {
    let head_bytes = &blob[0..OBJECT_HEAD_LEN];
    let dek_aad = prefixed_aad(DEK_WRAP_AAD_PREFIX, head_bytes);
    let meta_aad = prefixed_aad(META_AAD_PREFIX, head_bytes);

    if blob.len() < off + WRAPPED_DEK_LEN {
        return Err(CryptoError::Format("object truncated (wrapped_dek)".into()));
    }
    let wrapped_dek = &blob[off..off + WRAPPED_DEK_LEN];
    off += WRAPPED_DEK_LEN;
    let dek_v = aead::decrypt(dek_wrapping_key, wrapped_dek, &dek_aad)?;
    if dek_v.len() != KEY_LEN {
        return Err(CryptoError::Format("unwrapped DEK wrong length".into()));
    }
    let mut dek = Zeroizing::new([0u8; KEY_LEN]);
    dek.copy_from_slice(&dek_v);

    let meta_len = read_u32(blob, off)? as usize;
    off += 4;
    if !(META_MIN_LEN..=META_MAX_LEN).contains(&meta_len) {
        return Err(CryptoError::Format("meta_len out of range".into()));
    }
    if blob.len() < off + meta_len {
        return Err(CryptoError::Format("object truncated (metadata)".into()));
    }
    let meta_blob = &blob[off..off + meta_len];
    off += meta_len;
    let mnonce: [u8; NONCE_LEN] = meta_blob[0..NONCE_LEN]
        .try_into()
        .map_err(|_| CryptoError::Format("bad metadata nonce".into()))?;
    let meta_pt = aead::decrypt_with_nonce(&dek, &mnonce, &meta_blob[NONCE_LEN..], &meta_aad)?;

    // Schema-gated: a supported schema is parsed + size-checked; an unknown one is
    // skipped-and-served (§8), so a future schema_version never breaks decode.
    let metadata = if !meta_pt.is_empty() && meta_pt[0] == META_SCHEMA_V1 {
        let md = parse_metadata(&meta_pt)?;
        if md.size != head.plaintext_len {
            return Err(CryptoError::Format("meta.size != plaintext_len".into()));
        }
        Some(md)
    } else {
        None
    };
    Ok((dek, metadata, off))
}

/// Decrypt + tag-verify chunk `index` (`ct_and_tag = ct(this_pt) ‖ tag(16)`) under `dek`,
/// deriving the chunk nonce (`base_nonce` with `bytes[0..8] XOR= index`) and AAD
/// (`head ‖ index`) exactly as §3 specifies. Shared by the buffered
/// [`open_core_streamed`] and the reader path so both paths verify chunks identically.
pub(super) fn decrypt_chunk(
    dek: &[u8; KEY_LEN],
    head: &Head,
    head_bytes: &[u8],
    index: u64,
    ct_and_tag: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let n = chunk_nonce(&head.base_nonce, index);
    aead::decrypt_with_nonce(dek, &n, ct_and_tag, &chunk_aad(head_bytes, index))
}

/// Buffered reader for both `kem_id` paths: opens an object fully into RAM. Thin wrapper
/// over [`open_core_streamed`] that concatenates the decrypted chunks into one plaintext
/// buffer. The buffer is sized off `head.plaintext_len` only on the first emitted chunk —
/// i.e. after the DEK unwrap has authenticated the head and the first chunk tag has
/// verified — so a forged oversized `plaintext_len` can never drive a pre-auth allocation.
pub(super) fn open_core(
    dek_wrapping_key: &[u8; KEY_LEN],
    blob: &[u8],
    head: &Head,
    off: usize,
) -> Result<Opened> {
    let cap = head.plaintext_len as usize;
    let mut plaintext: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    let mut reserved = false;
    let metadata = open_core_streamed(dek_wrapping_key, blob, head, off, |chunk| {
        if !reserved {
            plaintext.reserve_exact(cap);
            reserved = true;
        }
        plaintext.extend_from_slice(chunk);
        Ok(())
    })?;
    Ok(Opened {
        metadata,
        plaintext,
    })
}

/// Result of opening an object: its plaintext plus metadata (absent only when the
/// object carries an unknown `schema_version`, which is skipped-and-served per §8).
pub struct Opened {
    pub metadata: Option<Metadata>,
    pub plaintext: Zeroizing<Vec<u8>>,
}

pub(super) fn prefixed_aad(prefix: &[u8], head: &[u8]) -> Vec<u8> {
    let mut a = Vec::with_capacity(prefix.len() + head.len());
    a.extend_from_slice(prefix);
    a.extend_from_slice(head);
    a
}

fn chunk_aad(head: &[u8], index: u64) -> Vec<u8> {
    let mut a = Vec::with_capacity(head.len() + 8);
    a.extend_from_slice(head);
    a.extend_from_slice(&index.to_le_bytes());
    a
}

/// Seal `plaintext` + `meta` into a DSF1 object under `wrapping_key` (root; `kem_id=0`).
/// `meta.size` and `meta.content_blake3` are overwritten from `plaintext`.
///
/// This is the unchanged symmetric owner path; the `kem_id=1` recipient-hybrid sealer is
/// [`super::seal_to_recipients`].
pub fn seal(
    wrapping_key: &[u8; KEY_LEN],
    plaintext: &[u8],
    meta: &Metadata,
    chunk_size: u32,
) -> Result<Vec<u8>> {
    seal_core(
        KEM_ID_NONE,
        wrapping_key,
        |_head| Ok(Vec::new()),
        plaintext,
        meta,
        chunk_size,
    )
}

/// Open a DSF1 object under `wrapping_key` (root; `kem_id=0`), returning plaintext +
/// metadata. Verifies the footer (if present) and every chunk/metadata tag.
pub fn open(wrapping_key: &[u8; KEY_LEN], blob: &[u8]) -> Result<Opened> {
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
    open_core(wrapping_key, blob, &head, OBJECT_HEAD_LEN + 2)
}

pub(super) fn read_u16(b: &[u8], off: usize) -> Result<u16> {
    if off + 2 > b.len() {
        return Err(CryptoError::Format("object truncated (u16)".into()));
    }
    Ok(u16::from_le_bytes([b[off], b[off + 1]]))
}
fn read_u32(b: &[u8], off: usize) -> Result<u32> {
    if off + 4 > b.len() {
        return Err(CryptoError::Format("object truncated (u32)".into()));
    }
    Ok(u32::from_le_bytes([
        b[off],
        b[off + 1],
        b[off + 2],
        b[off + 3],
    ]))
}
