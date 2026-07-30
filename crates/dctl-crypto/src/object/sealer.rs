//! The streaming seal, in two phases — so an object can be **named and sized**
//! before a single one of its bytes exists.
//!
//! [`seal_stream`] is one call and is unchanged in what it produces. What is new
//! is that it is now a thin wrapper over [`PlannedSeal`], which stops between the
//! two passes the sealer already made and answers two questions:
//!
//! * **What is this object's `file_id`?** It is the key the vault stores the
//!   object under (`o/<hex file_id>`), and it is generated *here*, inside the
//!   sealer, along with the DEK and the base nonce. A caller that had to read it
//!   back out of the produced bytes could not know the destination key until the
//!   first 68 bytes had already been produced — which, for a caller streaming
//!   straight to a provider, is after the upload had to have been started.
//! * **Exactly how many bytes will it be?** Every term is fixed once the header
//!   is built: the header itself, the plaintext, one Poly1305 tag per chunk and
//!   the footer. A multipart upload needs that number before its first part, both
//!   to choose between the single-shot and multipart paths and to keep the part
//!   count inside the provider's ten-thousand-part cap.
//!
//! Neither answer is available from a one-phase `Write`-sink sealer, and the
//! absence of both is why every upload used to be staged to a scratch file first:
//! seal to disk, `stat` it, read the head back, *then* upload. The spool was not
//! there for memory — the sealer has always been `O(chunk_size)` — it was there
//! because the caller could not address or size the object without it. Removing
//! it needed this split and nothing else.
//!
//! ## Why the input is still read twice
//!
//! Unchanged, and it is a property of the format rather than of this code:
//! `enc_metadata` ships *before* the payload and must carry `content_blake3` of
//! the **whole** plaintext (§4). A single forward pass cannot know that hash when
//! it has to write the metadata. So [`PlannedSeal::prepare`] folds BLAKE3 over
//! the entire input and rewinds (hence `Read + Seek`), and [`PlannedSeal::emit`]
//! re-reads it in `chunk_size` blocks. Both passes are over the caller's *source*
//! — a real file — and neither writes anything anywhere.
//!
//! Output is written strictly in order to a plain [`Write`] (no output seek), and
//! the only retained state is one chunk-sized scratch buffer, the bounded header
//! and the two BLAKE3 hashers.

use std::io::{Read, Seek, SeekFrom, Write};

use zeroize::Zeroizing;

use crate::aead;
use crate::constants::{
    ALGO_XCHACHA20_POLY1305, DEK_WRAP_AAD_PREFIX, FLAG_FOOTER, FOOTER_LEN, KEM_ID_NONE, KEY_LEN,
    MAX_CHUNK_SIZE, META_AAD_PREFIX, META_MAX_LEN, META_MIN_LEN, NONCE_LEN, OBJECT_HEAD_LEN,
    TAG_LEN, WRAPPED_DEK_LEN,
};
use crate::error::{CryptoError, Result};
use crate::keys::generate_key;
use crate::rng;

use super::head::{Head, build_head};
use super::meta::{Metadata, build_metadata};
use super::nonce::{base_nonce, chunk_nonce, chunk_plaintext_len, metadata_nonce};
use super::seal::prefixed_aad;

/// Write `bytes` to `w` while folding them into the running footer hash `h`, so the
/// footer is computed in one streaming pass over exactly the bytes that hit the wire.
fn write_hashed<W: Write>(w: &mut W, h: &mut blake3::Hasher, bytes: &[u8]) -> Result<()> {
    h.update(bytes);
    w.write_all(bytes)
        .map_err(|_| CryptoError::Format("output write failed".into()))?;
    Ok(())
}

/// A sealed object that has been fully decided and not yet produced.
///
/// Everything that fixes the object's identity and its length is settled by
/// [`prepare`](Self::prepare): the DEK, the `file_id`, the base nonce, the head,
/// the wrapped DEK and the encrypted metadata. What remains is the payload, which
/// [`emit`](Self::emit) streams a chunk at a time.
///
/// Not `Debug` and not `Clone`: it holds the object's data-encryption key. The
/// key lives in a [`Zeroizing`] buffer and is wiped when this value is dropped,
/// whether or not the object was ever emitted.
pub struct PlannedSeal {
    /// The per-object data-encryption key, wiped on drop.
    dek: Zeroizing<[u8; KEY_LEN]>,
    /// The fixed 68-byte head, kept because every chunk's AAD contains it verbatim.
    head_bytes: [u8; OBJECT_HEAD_LEN],
    /// The chunk nonce base.
    base_nonce: [u8; NONCE_LEN],
    /// The object's identity, which is also the vault's key for it.
    file_id: [u8; 16],
    /// Everything before the first chunk:
    /// `head ‖ kem_ct_len(0) ‖ wrapped_dek ‖ meta_len ‖ mnonce ‖ meta_ct`.
    header: Vec<u8>,
    /// Plaintext bytes per chunk.
    chunk_size: u32,
    /// The declared plaintext length; the input must yield exactly this many bytes.
    plaintext_len: u64,
    /// `ceil(plaintext_len / chunk_size)`.
    chunk_count: u64,
    /// The exact total byte length of the object [`emit`](Self::emit) will write.
    object_len: u64,
    /// BLAKE3 of the whole plaintext, from phase one — the same value sealed into
    /// the metadata, handed back so the caller need not compute it again.
    content_blake3: [u8; 32],
}

impl PlannedSeal {
    /// Phase one: hash the input, choose the keying material, and build everything
    /// that precedes the payload.
    ///
    /// `input` is read once from wherever it currently is to EOF and then rewound
    /// to the start, so the same handle can be handed straight to
    /// [`emit`](Self::emit). `plaintext_len` is supplied by the caller (typically
    /// the file's size) and MUST equal the number of bytes `input` yields, or the
    /// seal is rejected before anything is produced.
    ///
    /// # Errors
    /// [`CryptoError::Format`] for a `chunk_size` outside the format's range, an
    /// input whose length disagrees with `plaintext_len`, metadata that will not
    /// serialize into the format's bounds, or an input that cannot be read or
    /// rewound.
    pub fn prepare<R: Read + Seek>(
        wrapping_key: &[u8; KEY_LEN],
        input: &mut R,
        plaintext_len: u64,
        meta: &Metadata,
        chunk_size: u32,
    ) -> Result<Self> {
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

        // ── Pass 1: BLAKE3 over the entire input → content_blake3, then rewind. ──
        let mut buf = vec![0u8; cs];
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

        // The header, assembled once rather than written in six pieces, because it
        // is also the thing whose *length* the caller is about to be told.
        let mut header = Vec::with_capacity(
            OBJECT_HEAD_LEN + 2 + WRAPPED_DEK_LEN + 4 + NONCE_LEN + meta_ct.len(),
        );
        header.extend_from_slice(&head_bytes);
        header.extend_from_slice(&0u16.to_le_bytes()); // kem_ct_len = 0
        header.extend_from_slice(&wrapped_dek);
        header.extend_from_slice(&meta_len_u32.to_le_bytes());
        header.extend_from_slice(&mnonce);
        header.extend_from_slice(&meta_ct);

        let object_len = total_len(header.len() as u64, plaintext_len, chunk_count)?;

        Ok(Self {
            dek,
            head_bytes,
            base_nonce: bn,
            file_id,
            header,
            chunk_size,
            plaintext_len,
            chunk_count,
            object_len,
            content_blake3,
        })
    }

    /// The object's `file_id` — the 16 bytes at `head[52..68]`, and the vault's key
    /// for it.
    ///
    /// Available before the object exists, which is the whole point of the split:
    /// a caller streaming straight to a provider must name the destination key in
    /// the request that starts the upload.
    #[must_use]
    pub const fn file_id(&self) -> [u8; 16] {
        self.file_id
    }

    /// Exactly how many bytes [`emit`](Self::emit) will write.
    ///
    /// Not an estimate and not a bound: every term is already decided. A
    /// multipart upload chooses its part count from this number, and a provider
    /// that is told a length must be told the true one.
    #[must_use]
    pub const fn object_len(&self) -> u64 {
        self.object_len
    }

    /// The plaintext length this object was planned for.
    #[must_use]
    pub const fn plaintext_len(&self) -> u64 {
        self.plaintext_len
    }

    /// BLAKE3 of the whole **plaintext**, computed by phase one.
    ///
    /// Handed back rather than kept private because the caller wants the same
    /// number: the vault records it on the index row, and re-deriving it would
    /// mean a third pass over the source for a digest this object already had to
    /// compute in order to seal the metadata. Three passes over a four-gigabyte
    /// file to learn one thing twice is a cost with nothing on the other side of
    /// it.
    #[must_use]
    pub const fn content_blake3(&self) -> [u8; 32] {
        self.content_blake3
    }

    /// Phase two: write the whole object, in order, to `output`.
    ///
    /// `input` must be positioned at the start and must yield exactly
    /// [`plaintext_len`](Self::plaintext_len) bytes — the same handle
    /// [`prepare`](Self::prepare) rewound is what this expects. Peak memory is one
    /// `chunk_size` scratch buffer plus the bounded header.
    ///
    /// # Errors
    /// [`CryptoError::Format`] when the input cannot be read (including an input
    /// that grew shorter between the two passes) or the output cannot be written.
    pub fn emit<R: Read, W: Write>(self, input: &mut R, output: &mut W) -> Result<()> {
        let cs = self.chunk_size as usize;
        let mut buf = vec![0u8; cs];
        let mut footer_hasher = blake3::Hasher::new();

        write_hashed(output, &mut footer_hasher, &self.header)?;

        // Stack AAD == `chunk_aad`: head(68) ‖ (i as u64 LE) — no per-chunk heap alloc.
        let mut aad = [0u8; OBJECT_HEAD_LEN + 8];
        aad[..OBJECT_HEAD_LEN].copy_from_slice(&self.head_bytes);
        for i in 0..self.chunk_count {
            let this_pt = chunk_plaintext_len(self.plaintext_len, cs as u64, i) as usize;
            input
                .read_exact(&mut buf[..this_pt])
                .map_err(|_| CryptoError::Format("input read failed".into()))?;
            let nonce = chunk_nonce(&self.base_nonce, i);
            aad[OBJECT_HEAD_LEN..].copy_from_slice(&i.to_le_bytes());
            let ct = aead::encrypt_with_nonce(&self.dek, &nonce, &buf[..this_pt], &aad)?;
            write_hashed(output, &mut footer_hasher, &ct)?;
        }

        // ── footer = BLAKE3(all preceding output bytes) (§3, flags bit0). ──
        output
            .write_all(footer_hasher.finalize().as_bytes())
            .map_err(|_| CryptoError::Format("output write failed".into()))?;
        Ok(())
    }
}

/// The exact byte length of a DSF1 object with this header, plaintext and chunk
/// count.
///
/// `header ‖ (ct‖tag per chunk) ‖ footer`, where the ciphertext of every chunk is
/// its plaintext plus one [`TAG_LEN`] Poly1305 tag — so the payload is the whole
/// plaintext plus one tag per chunk, whatever the chunking.
///
/// Written as checked arithmetic and returned fallibly rather than saturating: a
/// length handed to a provider as the size of an upload is one place a silently
/// wrapped number would be committed to before anybody could notice.
fn total_len(header_len: u64, plaintext_len: u64, chunk_count: u64) -> Result<u64> {
    let overflow = || CryptoError::Format("object length overflows u64".into());
    chunk_count
        .checked_mul(TAG_LEN as u64)
        .and_then(|tags| tags.checked_add(plaintext_len))
        .and_then(|payload| payload.checked_add(header_len))
        .and_then(|body| body.checked_add(FOOTER_LEN as u64))
        .ok_or_else(overflow)
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
///
/// The two phases underneath are [`PlannedSeal`], and a caller that needs the
/// object's key or its length before the bytes exist uses those directly. This
/// function is the shape for a caller that has neither question — it is written in
/// terms of the same type rather than as a second sealer, because two sealers is
/// two sets of framing that can drift apart, and drift in framing is an object
/// that will not open.
///
/// # Errors
/// Whatever [`PlannedSeal::prepare`] or [`PlannedSeal::emit`] reported.
pub fn seal_stream<R: Read + Seek, W: Write>(
    wrapping_key: &[u8; KEY_LEN],
    input: &mut R,
    plaintext_len: u64,
    meta: &Metadata,
    chunk_size: u32,
    output: &mut W,
) -> Result<()> {
    PlannedSeal::prepare(wrapping_key, input, plaintext_len, meta, chunk_size)?.emit(input, output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn root() -> [u8; KEY_LEN] {
        [7u8; KEY_LEN]
    }

    /// The property the whole split exists for: the length promised before the
    /// object is produced is the length produced.
    ///
    /// A multipart upload is planned from this number. If it were an
    /// over-estimate the last part would be short and the provider would reject
    /// the finish; if an under-estimate the upload would run out of parts with
    /// bytes left. Neither failure is visible until the object is most of the way
    /// to a bucket, so it is asserted here, offline, at every interesting
    /// chunking.
    #[test]
    fn the_promised_length_is_the_produced_length() {
        for (len, chunk) in [
            (0u64, 1024u32),
            (1, 1024),
            (1023, 1024),
            (1024, 1024),
            (1025, 1024),
            (4096, 1024),
            (100_000, 4096),
        ] {
            let plaintext: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let mut input = Cursor::new(plaintext);
            let plan =
                PlannedSeal::prepare(&root(), &mut input, len, &Metadata::new("a/b.bin"), chunk)
                    .expect("the plan is made");
            let promised = plan.object_len();

            let mut out = Vec::new();
            plan.emit(&mut input, &mut out)
                .expect("the object is emitted");
            assert_eq!(
                promised,
                out.len() as u64,
                "len={len} chunk={chunk}: promised {promised}, produced {}",
                out.len()
            );
        }
    }

    /// The other half of the split: the key the object will be stored under is
    /// known before the object exists, and it is the key the object turns out to
    /// carry.
    #[test]
    fn the_file_id_promised_is_the_file_id_in_the_head() {
        let plaintext = vec![3u8; 5000];
        let mut input = Cursor::new(plaintext);
        let plan = PlannedSeal::prepare(
            &root(),
            &mut input,
            5000,
            &Metadata::new("videos/clip.bin"),
            1024,
        )
        .expect("the plan is made");
        let promised = plan.file_id();

        let mut out = Vec::new();
        plan.emit(&mut input, &mut out)
            .expect("the object is emitted");
        assert_eq!(&out[52..68], &promised[..]);
    }

    /// A length that would wrap is refused rather than committed to.
    #[test]
    fn an_object_length_that_would_overflow_is_refused() {
        assert!(total_len(100, u64::MAX, 1).is_err());
        assert!(total_len(100, 0, u64::MAX).is_err());
        assert_eq!(total_len(100, 1000, 1).expect("fits"), 100 + 1000 + 16 + 32);
    }

    /// An input whose length disagrees with the caller's claim is refused in phase
    /// one, before anything is produced and before a provider has been told a size.
    #[test]
    fn a_declared_length_that_is_wrong_is_refused_before_anything_is_produced() {
        let mut input = Cursor::new(vec![1u8; 100]);
        let error = PlannedSeal::prepare(&root(), &mut input, 200, &Metadata::new("a"), 1024);
        assert!(error.is_err());
    }
}
