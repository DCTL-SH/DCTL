//! Random access into a `DSF1` object: authenticate and return **only** the chunks a
//! byte window touches (`crates/dctl-decode/FORMAT.md` §3, "Random-access").
//!
//! The format was designed for this. Chunk `i`'s ciphertext starts at
//! `payload_start + i·(chunk_size + 16)` and every chunk before the last is exactly
//! `chunk_size` plaintext bytes, so the chunks covering `[offset, offset + len)` are
//! `offset / chunk_size` through `(offset + len − 1) / chunk_size` and their byte extent
//! is *arithmetic*, not a search. One `Range:` request fetches them; nothing else is
//! transferred, decrypted, or allocated.
//!
//! Without this, serving a window means opening the whole object: a 10-byte read of a
//! 95 MiB file cost +97 MB of resident memory and 95 MiB of egress, and a media player
//! seeking through a 40 GB film re-downloaded 40 GB on every seek. That is the difference
//! between a mount that works and one that cannot exist.
//!
//! ## What a partial read can and cannot prove
//!
//! **Per-chunk Poly1305 is the integrity guarantee on this path, exactly as §3 intends.**
//! Every chunk carries its own tag, its nonce is derived from the object's `base_nonce`
//! and its index, and its AAD is `fixed_head(68) ‖ index`. The head in that AAD is itself
//! authenticated — it is folded into the `wrapped_dek` AAD, which is verified before any
//! chunk is touched — so a tag that verifies proves the bytes are chunk `i` **of this
//! object**, at this `chunk_size`, in an object of this `plaintext_len` and `chunk_count`,
//! under this `file_id`. Substitution, reordering, splicing from another object, and
//! truncation are all caught without reading a single byte outside the window.
//!
//! **The two whole-object checks cannot be evaluated here, and are not faked.** The
//! trailing footer is `BLAKE3(every preceding byte)` and the metadata's `content_blake3`
//! is `BLAKE3(the entire plaintext)`; neither is computable from a fragment, so a ranged
//! read neither checks them nor pretends to. That is not a gap this module papers over —
//! it is why `dctl verify` and `dctl scrub` exist and why they stream the object end to
//! end. A caller that needs the whole-object statement must ask for the whole object.
//!
//! ## Two reads, then one per window
//!
//! An object's header is self-describing but variable-length (`kem_wrap` up to 64 KiB,
//! `enc_metadata` up to 256 KiB), so a reader learns where the payload starts by reading a
//! bounded prefix — [`header_extent`] says whether the prefix in hand is enough and, if
//! not, exactly how many bytes to ask for. [`RangeHeader`] then holds the unwrapped DEK
//! and the geometry, so every subsequent window costs exactly **one** ranged request. The
//! header read is paid once per object, not once per window; see
//! [`OBJECT_HEADER_PROBE_LEN`](crate::constants::OBJECT_HEADER_PROBE_LEN) for why the
//! usual case is a single request.

use zeroize::Zeroizing;

use crate::constants::{
    KEM_ID_HYBRID, KEM_ID_NONE, KEY_LEN, META_MAX_LEN, META_MIN_LEN, OBJECT_HEAD_LEN, TAG_LEN,
    WRAPPED_DEK_LEN,
};
use crate::error::{CryptoError, Result};

use super::head::{Head, parse_head};
use super::meta::Metadata;
use super::nonce::chunk_plaintext_len;
use super::seal::{decode_dek_and_meta, decrypt_chunk, read_u16};

/// Whether the leading bytes a reader holds are enough to decode an object's header.
///
/// Returned by [`header_extent`] so a ranged reader can size its **next** request
/// exactly rather than guessing twice or fetching the whole object to find out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderExtent {
    /// The prefix in hand covers the entire header, which is this many bytes long.
    /// The first chunk's ciphertext begins at this offset.
    Complete(usize),
    /// The prefix is too short to decide. Re-read at least this many bytes from offset
    /// `0` and ask again. A read that returns *fewer* bytes than this means the object
    /// is truncated, not that another probe is needed — the caller must treat that as a
    /// failure rather than looping.
    Short(usize),
}

/// How many bytes of an object's head a reader must hold before [`header_extent`] can
/// say anything at all: the fixed head plus the `kem_ct_len` that follows it.
const MIN_PROBE_LEN: usize = OBJECT_HEAD_LEN + 2;

/// Decide whether `prefix` — the object's leading bytes, read from offset `0` — covers
/// its whole header, and how long that header is.
///
/// Walks the §3 header exactly as the buffered decoder does, validating as it goes:
/// `parse_head` enforces the mandatory structural checks (magic, version, `algo`,
/// `chunk_size ∈ (0, 16 MiB]`, `chunk_count == ceil(plaintext_len / chunk_size)`, no
/// unknown critical flags) before any length arithmetic, and `meta_len` is bounds-checked
/// against §3's `116 ≤ meta_len ≤ 262144` before it is added to an offset. Nothing here
/// allocates from a length the object supplied, so a forged header cannot drive a
/// pre-authentication allocation — it can only make this function return an error or ask
/// for a bounded number of further bytes.
///
/// # Errors
/// [`CryptoError::Format`] if the head is malformed, if `kem_ct_len` disagrees with
/// `kem_id` (§3 requires `0` exactly when `kem_id = 0`), or if `meta_len` is out of range.
pub fn header_extent(prefix: &[u8]) -> Result<HeaderExtent> {
    if prefix.len() < MIN_PROBE_LEN {
        return Ok(HeaderExtent::Short(MIN_PROBE_LEN));
    }
    // Structural validation first — every later offset is computed from fields this
    // rejects out-of-range values for.
    let head = parse_head(prefix)?;
    let kem_ct_len = read_u16(prefix, OBJECT_HEAD_LEN)? as usize;
    match head.kem_id {
        KEM_ID_NONE if kem_ct_len != 0 => {
            return Err(CryptoError::Format(
                "kem_ct_len must be 0 for kem_id=0".into(),
            ));
        }
        KEM_ID_HYBRID if kem_ct_len == 0 => {
            return Err(CryptoError::Format(
                "kem_ct_len must be non-zero for kem_id=1".into(),
            ));
        }
        _ => {}
    }

    // `meta_len` sits after head ‖ kem_ct_len ‖ kem_wrap ‖ wrapped_dek. Every term is a
    // small constant except `kem_ct_len`, which `read_u16` caps at 65535, so the sum
    // cannot overflow `usize` on any platform this builds for.
    let meta_len_at = MIN_PROBE_LEN + kem_ct_len + WRAPPED_DEK_LEN;
    let through_meta_len = meta_len_at + 4;
    if prefix.len() < through_meta_len {
        return Ok(HeaderExtent::Short(through_meta_len));
    }
    let meta_len = read_u32(prefix, meta_len_at)? as usize;
    if !(META_MIN_LEN..=META_MAX_LEN).contains(&meta_len) {
        return Err(CryptoError::Format("meta_len out of range".into()));
    }
    let header_len = through_meta_len + meta_len;
    if prefix.len() < header_len {
        Ok(HeaderExtent::Short(header_len))
    } else {
        Ok(HeaderExtent::Complete(header_len))
    }
}

/// An object opened for random access: its unwrapped DEK, its authenticated geometry, and
/// where its payload starts.
///
/// Constructed once per object from a bounded header prefix, then reused for every
/// window, which is what makes a seek cost one request instead of a fresh header read.
/// Holding the DEK is not an escalation of what is already in memory — the vault root
/// that wraps every DEK in the vault is resident for the whole session, and this is one
/// per-object key derived under it — and it is wiped on drop regardless.
///
/// See the module documentation for what a window served from here does and does not
/// prove: per-chunk Poly1305 authenticates every returned byte and binds it to this
/// object at this index; the footer and `content_blake3` are whole-object statements that
/// a fragment cannot make.
pub struct RangeHeader {
    /// Parsed head. Authenticated: the DEK unwrap folds all 68 bytes into its AAD, so if
    /// the unwrap succeeded these fields are the ones the writer sealed.
    head: Head,
    /// The same 68 bytes verbatim — chunk AAD is `head_bytes ‖ index`, and rebuilding
    /// them from `head` per chunk would be a second encoder that could drift from the one
    /// in `build_head`.
    head_bytes: [u8; OBJECT_HEAD_LEN],
    /// The object's data-encryption key, wiped on drop.
    dek: Zeroizing<[u8; KEY_LEN]>,
    /// Offset of chunk `0`'s ciphertext: `146 + K + M` in §3's notation.
    payload_start: u64,
    /// The object's own §4 metadata, absent only for an unknown `schema_version`
    /// (skipped-and-served per §8).
    metadata: Option<Metadata>,
}

impl RangeHeader {
    /// Open the header of a symmetric (`kem_id = 0`) object under the vault `root_key`.
    ///
    /// `prefix` must contain at least the object's whole header — ask [`header_extent`]
    /// first. Unwrapping the DEK authenticates the entire 68-byte head, and the metadata
    /// decode enforces §3's mandatory `meta.size == plaintext_len` cross-check, so the
    /// geometry every later window is computed from is verified before it is used.
    ///
    /// # Errors
    /// [`CryptoError::Format`] for a short prefix, a `kem_id ≠ 0` object (use
    /// [`open_with_kw`](RangeHeader::open_with_kw)), or a header that fails to decode;
    /// [`CryptoError::Aead`] if the DEK wrap or the metadata tag does not verify.
    pub fn open(root_key: &[u8; KEY_LEN], prefix: &[u8]) -> Result<Self> {
        Self::decode(root_key, prefix, KEM_ID_NONE)
    }

    /// Open the header of a recipient-hybrid (`kem_id = 1`, §12) object whose per-object
    /// `KW` the caller has already recovered — inline from the `kem_wrap` block or from a
    /// §12.6 grant sidecar. Identical to [`open`](RangeHeader::open) from the
    /// `wrapped_dek` onwards; only the wrapping key differs.
    ///
    /// # Errors
    /// As [`open`](RangeHeader::open), but rejects a `kem_id ≠ 1` object.
    pub fn open_with_kw(kw: &[u8; KEY_LEN], prefix: &[u8]) -> Result<Self> {
        Self::decode(kw, prefix, KEM_ID_HYBRID)
    }

    /// Shared decode for both `kem_id` paths — the DEK unwrap, metadata decode and
    /// payload-offset arithmetic are identical once the wrapping key is chosen, and a
    /// second copy is a second place that could compute a different `payload_start`.
    fn decode(wrapping_key: &[u8; KEY_LEN], prefix: &[u8], expected_kem_id: u8) -> Result<Self> {
        let HeaderExtent::Complete(header_len) = header_extent(prefix)? else {
            return Err(CryptoError::Format(
                "object header prefix too short to decode".into(),
            ));
        };
        let head = parse_head(prefix)?;
        if head.kem_id != expected_kem_id {
            return Err(CryptoError::Format(format!(
                "object kem_id {} needs the other range opener",
                head.kem_id
            )));
        }
        let kem_ct_len = read_u16(prefix, OBJECT_HEAD_LEN)? as usize;
        // `wrapped_dek` sits at 70 for kem_id=0 and 70 + K for kem_id=1 (§3/§12.2).
        let dek_offset = MIN_PROBE_LEN + kem_ct_len;

        // Handed exactly the header — `decode_dek_and_meta` is the same routine the
        // buffered and streaming openers use, so the three decoders cannot drift.
        let (dek, metadata, payload_start) =
            decode_dek_and_meta(wrapping_key, &prefix[..header_len], &head, dek_offset)?;
        // The two walks of the same header must land on the same first chunk. They are
        // computed independently — `header_extent` from the length fields,
        // `decode_dek_and_meta` by consuming each region — so agreement is what proves
        // neither drifted. Checked rather than `debug_assert`ed: a debug-build panic here
        // would be reached from inside a filesystem callback, and a panic there wedges the
        // mount instead of failing one read.
        if payload_start != header_len {
            return Err(CryptoError::Format(
                "object header length disagrees with its own field walk".into(),
            ));
        }

        let mut head_bytes = [0u8; OBJECT_HEAD_LEN];
        head_bytes.copy_from_slice(&prefix[..OBJECT_HEAD_LEN]);
        Ok(Self {
            head,
            head_bytes,
            dek,
            payload_start: payload_start as u64,
            metadata,
        })
    }

    /// Plaintext bytes per chunk — every chunk but the last carries exactly this many.
    #[must_use]
    pub const fn chunk_size(&self) -> u32 {
        self.head.chunk_size
    }

    /// Number of chunks in the object.
    #[must_use]
    pub const fn chunk_count(&self) -> u64 {
        self.head.chunk_count
    }

    /// The object's plaintext length, as authenticated by the DEK wrap's head-bound AAD
    /// and cross-checked against `meta.size`. Trustworthy without reading the payload,
    /// which is what lets a `stat` cost one bounded header read instead of a full object.
    #[must_use]
    pub const fn plaintext_len(&self) -> u64 {
        self.head.plaintext_len
    }

    /// The object's random per-object id (§3), authenticated with the rest of the head.
    ///
    /// Stable for the life of the object and independent of its path, which makes it the
    /// correct cache key for decrypted chunks: a rewritten file is a *new* `file_id`, so
    /// cached chunks can never be served for content that replaced them.
    #[must_use]
    pub const fn file_id(&self) -> &[u8; 16] {
        &self.head.file_id
    }

    /// Whether this object carries §3's trailing footer.
    ///
    /// Read from the authenticated head, so it is the writer's own statement rather than
    /// an inference from the object's length — which is what a reader folding the footer
    /// as it streams needs, since it must decide whether to expect one *before* it has
    /// reached the end.
    #[must_use]
    pub const fn has_footer(&self) -> bool {
        self.head.has_footer()
    }

    /// Offset of chunk `0`'s ciphertext, which is also the length of the header the
    /// footer hash covers before it reaches the payload (§3).
    #[must_use]
    pub const fn payload_start(&self) -> u64 {
        self.payload_start
    }

    /// The object's own §4 metadata — including the `content_blake3` of its whole
    /// plaintext, which a ranged read records but cannot itself verify (see the module
    /// documentation). [`None`] only for an unknown `schema_version`, skipped-and-served
    /// per §8.
    #[must_use]
    pub const fn metadata(&self) -> Option<&Metadata> {
        self.metadata.as_ref()
    }

    /// The chunks covering the plaintext window `[offset, offset + length)`, clamped to
    /// the object. `length` of [`None`] means "to the end".
    ///
    /// Clamps rather than refuses, matching a `seek` plus a bounded read on a local file:
    /// an offset at or past the end yields an empty span, and an over-long window is
    /// shortened. Refusing would make a mount's read past EOF an I/O error where every
    /// other filesystem returns zero bytes.
    ///
    /// # Errors
    /// [`CryptoError::Format`] if the window is longer than this platform can address, or
    /// if the object's declared geometry would overflow a byte offset — §3 requires
    /// checked offset arithmetic precisely because `i·(chunk_size + 16)` is attacker-
    /// influenced.
    pub fn span(&self, offset: u64, length: Option<u64>) -> Result<ChunkSpan> {
        let plaintext_len = self.head.plaintext_len;
        if offset >= plaintext_len {
            return Ok(ChunkSpan::EMPTY);
        }
        let available = plaintext_len - offset;
        let want = length.map_or(available, |len| len.min(available));
        if want == 0 {
            return Ok(ChunkSpan::EMPTY);
        }

        let chunk_size = u64::from(self.head.chunk_size);
        let first = offset / chunk_size;
        // `offset + want ≤ plaintext_len`, so the subtraction and the sum are both safe.
        let last = (offset + want - 1) / chunk_size;
        let mut span = self.chunk_span(first, last - first + 1)?;
        span.window_offset = usize::try_from(offset - first * chunk_size)
            .map_err(|_| CryptoError::Format("window offset exceeds this platform".into()))?;
        span.window_len = usize::try_from(want)
            .map_err(|_| CryptoError::Format("window longer than this platform".into()))?;
        Ok(span)
    }

    /// The ciphertext extent of chunks `[first, first + count)`, with the window set to
    /// the whole of their plaintext.
    ///
    /// The chunk-indexed twin of [`span`](RangeHeader::span), for a caller that thinks in
    /// whole chunks — a chunk cache repopulating a run of missing entries, say. `count` is
    /// clamped to the object's chunk count, so a run that reaches past the end yields only
    /// the chunks that exist.
    ///
    /// # Errors
    /// [`CryptoError::Format`] if the object's declared geometry overflows a byte offset.
    pub fn chunk_span(&self, first: u64, count: u64) -> Result<ChunkSpan> {
        let chunk_count = self.head.chunk_count;
        if first >= chunk_count || count == 0 {
            return Ok(ChunkSpan::EMPTY);
        }
        let count = count.min(chunk_count - first);
        let last = first + count - 1;

        // §3: chunk i's ciphertext starts at payload_start + i·(chunk_size + 16). Checked
        // throughout — the head is authenticated, but a 16 MiB chunk_size with a large
        // chunk_count is a legitimate object whose last offset must still not wrap.
        let stride = u64::from(self.head.chunk_size)
            .checked_add(TAG_LEN as u64)
            .ok_or_else(|| overflow("chunk stride"))?;
        let ciphertext_offset = first
            .checked_mul(stride)
            .and_then(|skip| self.payload_start.checked_add(skip))
            .ok_or_else(|| overflow("chunk offset"))?;

        // Only the object's final chunk may be short, so the extent is (count − 1) full
        // strides plus whatever the last chunk actually is — no per-chunk loop.
        let last_ct = chunk_plaintext_len(
            self.head.plaintext_len,
            u64::from(self.head.chunk_size),
            last,
        )
        .checked_add(TAG_LEN as u64)
        .ok_or_else(|| overflow("chunk length"))?;
        let ciphertext_len = (count - 1)
            .checked_mul(stride)
            .and_then(|full| full.checked_add(last_ct))
            .ok_or_else(|| overflow("span length"))?;
        // A span this reader cannot hold in one buffer is refused here rather than
        // failing later inside an allocator. Checked like every other term: an
        // unchecked `count · 16` would be a debug-build panic on a hostile geometry,
        // and a panic inside a filesystem callback wedges the mount.
        let window_len = usize::try_from(
            count
                .checked_mul(TAG_LEN as u64)
                .and_then(|tags| ciphertext_len.checked_sub(tags))
                .ok_or_else(|| overflow("span plaintext"))?,
        )
        .map_err(|_| CryptoError::Format("span longer than this platform".into()))?;

        Ok(ChunkSpan {
            first_chunk: first,
            chunk_count: count,
            ciphertext_offset,
            ciphertext_len,
            window_offset: 0,
            window_len,
        })
    }

    /// Authenticate and decrypt every chunk in `span`, handing each one's plaintext to
    /// `emit` along with its index.
    ///
    /// `ciphertext` must be exactly the bytes at
    /// [`ChunkSpan::ciphertext_offset`]`..+`[`ChunkSpan::ciphertext_len`] — the length is
    /// checked, so a backend that silently returned a short or over-long range is caught
    /// here rather than producing garbage plaintext.
    ///
    /// **`emit` is only ever called with bytes whose Poly1305 tag has already verified**,
    /// so a caller may write them out or cache them without a second gate. Decryption
    /// stops at the first tag failure and the error propagates; no unauthenticated byte
    /// is ever handed over.
    ///
    /// Each chunk's plaintext is handed over **owned**, not borrowed. Decryption has to
    /// allocate it anyway, so passing it by value lets a caching caller keep the buffer it
    /// was already given instead of copying every chunk a second time — which on a
    /// sequential read is a copy of the whole file. A caller with no use for it simply
    /// drops it, and the [`Zeroizing`] wrapper wipes it either way.
    ///
    /// # Errors
    /// [`CryptoError::Format`] if `ciphertext` is not the exact span,
    /// [`CryptoError::Aead`] if any chunk fails authentication, and whatever `emit`
    /// returned.
    pub fn open_chunks<F>(&self, span: &ChunkSpan, ciphertext: &[u8], mut emit: F) -> Result<()>
    where
        F: FnMut(u64, Zeroizing<Vec<u8>>) -> Result<()>,
    {
        if ciphertext.len() as u64 != span.ciphertext_len {
            return Err(CryptoError::Format(
                "ranged read returned the wrong number of bytes".into(),
            ));
        }
        let chunk_size = u64::from(self.head.chunk_size);
        let mut at = 0usize;
        for step in 0..span.chunk_count {
            let index = span.first_chunk + step;
            let this_pt = chunk_plaintext_len(self.head.plaintext_len, chunk_size, index) as usize;
            let end = at
                .checked_add(this_pt + TAG_LEN)
                .filter(|end| *end <= ciphertext.len())
                .ok_or_else(|| CryptoError::Format("ranged read truncated (chunk)".into()))?;
            let plaintext = decrypt_chunk(
                &self.dek,
                &self.head,
                &self.head_bytes,
                index,
                &ciphertext[at..end],
            )?;
            emit(index, plaintext)?;
            at = end;
        }
        Ok(())
    }

    /// Decrypt `span` and return just the window it was built for.
    ///
    /// The convenience form of [`open_chunks`](RangeHeader::open_chunks) for a caller with
    /// no use for the covering chunks beyond the bytes it asked for. A caller that *does*
    /// keep them — a chunk cache — should use `open_chunks` and slice the window out of
    /// what it cached, so the same chunk is never decrypted twice.
    ///
    /// # Errors
    /// As [`open_chunks`](RangeHeader::open_chunks).
    pub fn read_window(&self, span: &ChunkSpan, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let mut out: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(span.window_len));
        // Saturating because the two fields arrive from a `ChunkSpan` the caller could
        // have built by hand; `span`/`chunk_span` never produce a sum that overflows.
        let window_end = span.window_offset.saturating_add(span.window_len);
        // Plaintext bytes of the span already stepped over, so each chunk knows where it
        // sits relative to the window without recomputing chunk offsets.
        let mut seen = 0usize;
        self.open_chunks(span, ciphertext, |_index, plaintext| {
            let start = span.window_offset.saturating_sub(seen).min(plaintext.len());
            let end = window_end.saturating_sub(seen).min(plaintext.len());
            if end > start {
                out.extend_from_slice(&plaintext[start..end]);
            }
            seen += plaintext.len();
            Ok(())
        })?;
        if out.len() != span.window_len {
            return Err(CryptoError::Format("ranged read length mismatch".into()));
        }
        Ok(out)
    }
}

/// The chunks covering a window, and where their ciphertext lives in the object.
///
/// A plain value: computing it costs no I/O and touches no key material, so a caller can
/// decide whether a window is worth fetching — how many chunks, how many bytes — before
/// issuing the request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChunkSpan {
    first_chunk: u64,
    chunk_count: u64,
    ciphertext_offset: u64,
    ciphertext_len: u64,
    window_offset: usize,
    window_len: usize,
}

impl ChunkSpan {
    /// The span of a window that touches no chunk at all — an offset at or past the end
    /// of the object, or a zero-length read. Fetching it transfers nothing.
    pub const EMPTY: Self = Self {
        first_chunk: 0,
        chunk_count: 0,
        ciphertext_offset: 0,
        ciphertext_len: 0,
        window_offset: 0,
        window_len: 0,
    };

    /// Index of the first chunk the window touches.
    #[must_use]
    pub const fn first_chunk(self) -> u64 {
        self.first_chunk
    }

    /// How many consecutive chunks the window touches. Zero for an empty span.
    #[must_use]
    pub const fn chunk_count(self) -> u64 {
        self.chunk_count
    }

    /// Byte offset in the object where this span's ciphertext begins.
    #[must_use]
    pub const fn ciphertext_offset(self) -> u64 {
        self.ciphertext_offset
    }

    /// How many ciphertext bytes to fetch: the covering chunks plus their tags, and
    /// nothing else. This is the number that lands on an egress bill.
    #[must_use]
    pub const fn ciphertext_len(self) -> u64 {
        self.ciphertext_len
    }

    /// Where the requested window starts within the covering chunks' concatenated
    /// plaintext — non-zero whenever the window does not begin on a chunk boundary.
    #[must_use]
    pub const fn window_offset(self) -> usize {
        self.window_offset
    }

    /// How many plaintext bytes the window is, after clamping to the object.
    #[must_use]
    pub const fn window_len(self) -> usize {
        self.window_len
    }

    /// Whether this span touches nothing, so no request need be made.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.chunk_count == 0
    }
}

/// The one shape of arithmetic failure this module can hit: a declared geometry whose
/// offsets do not fit a `u64`. Named so every check reports the same way, and so §3's
/// "use checked offset arithmetic" is visibly honoured rather than assumed.
fn overflow(what: &str) -> CryptoError {
    CryptoError::Format(format!("object geometry overflows a byte offset ({what})"))
}

/// Little-endian `u32` at `off`, bounds-checked. A local copy rather than a shared one
/// because the buffered decoder's is private to it and widening its visibility would put
/// a raw byte reader in this crate's public surface for no caller's benefit.
fn read_u32(bytes: &[u8], off: usize) -> Result<u32> {
    let end = off
        .checked_add(4)
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| CryptoError::Format("object truncated (u32)".into()))?;
    let field: [u8; 4] = bytes[off..end]
        .try_into()
        .map_err(|_| CryptoError::Format("bad u32 field".into()))?;
    Ok(u32::from_le_bytes(field))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{FOOTER_LEN, OBJECT_HEADER_PROBE_LEN};
    use crate::object::{Metadata, seal};

    /// A sealed object plus the key that opens it, so every test states its own geometry.
    struct Sealed {
        key: [u8; KEY_LEN],
        bytes: Vec<u8>,
        plaintext: Vec<u8>,
    }

    fn seal_object(plaintext_len: usize, chunk_size: u32) -> Sealed {
        let key = [7u8; KEY_LEN];
        // A byte pattern with a long period, so a window served from the wrong chunk
        // cannot accidentally compare equal to the right one.
        let plaintext: Vec<u8> = (0..plaintext_len)
            .map(|i| (i % 251) as u8)
            .collect::<Vec<u8>>();
        let meta = Metadata::new("range/test.bin");
        let bytes = seal(&key, &plaintext, &meta, chunk_size).expect("the object seals");
        Sealed {
            key,
            bytes,
            plaintext,
        }
    }

    /// Serve a window the way a backend would: header probe, then exactly one ranged
    /// fetch of the covering chunks. Returns the bytes and what the fetch transferred.
    fn read_window(sealed: &Sealed, offset: u64, length: Option<u64>) -> (Vec<u8>, u64) {
        let probe = OBJECT_HEADER_PROBE_LEN.min(sealed.bytes.len());
        let header = RangeHeader::open(&sealed.key, &sealed.bytes[..probe]).expect("header opens");
        let span = header.span(offset, length).expect("a span is computable");
        let from = span.ciphertext_offset() as usize;
        let to = from + span.ciphertext_len() as usize;
        let window = header
            .read_window(&span, &sealed.bytes[from..to])
            .expect("the window authenticates");
        (window.to_vec(), span.ciphertext_len())
    }

    #[test]
    fn a_window_is_served_from_only_the_chunks_that_cover_it() {
        // The whole point, on an object with many chunks: a 10-byte window in the middle
        // fetches one chunk, not the object.
        let chunk_size = 64 * 1024u32;
        let sealed = seal_object(4 * 1024 * 1024, chunk_size);
        let offset = 2 * 1024 * 1024 + 7;
        let (window, fetched) = read_window(&sealed, offset, Some(10));

        assert_eq!(
            window,
            &sealed.plaintext[offset as usize..offset as usize + 10]
        );
        assert_eq!(
            fetched,
            u64::from(chunk_size) + TAG_LEN as u64,
            "one covering chunk and its tag, nothing else"
        );
        assert!(
            fetched < sealed.bytes.len() as u64 / 60,
            "the fetch must be a small fraction of the object"
        );
    }

    #[test]
    fn a_window_straddling_a_chunk_boundary_fetches_exactly_two_chunks() {
        let chunk_size = 1024u32;
        let sealed = seal_object(16 * 1024, chunk_size);
        // Four bytes either side of the boundary between chunk 3 and chunk 4.
        let (window, fetched) = read_window(&sealed, 4096 - 4, Some(8));
        assert_eq!(window, &sealed.plaintext[4092..4100]);
        assert_eq!(fetched, 2 * (u64::from(chunk_size) + TAG_LEN as u64));
    }

    #[test]
    fn every_window_of_a_multi_chunk_object_matches_the_plaintext() {
        // Exhaustive over boundaries: first byte, last byte, every chunk edge, and a run
        // that spans the short final chunk. A one-off in the covering-chunk arithmetic
        // shows up here and nowhere else.
        let chunk_size = 100u32;
        let sealed = seal_object(1050, chunk_size);
        for offset in 0..sealed.plaintext.len() as u64 {
            for len in [0u64, 1, 7, 100, 101, 250, 1050] {
                let (window, _) = read_window(&sealed, offset, Some(len));
                let start = offset as usize;
                let end = (start + len as usize).min(sealed.plaintext.len());
                assert_eq!(
                    window,
                    &sealed.plaintext[start..end],
                    "offset {offset} len {len}"
                );
            }
        }
    }

    #[test]
    fn a_window_to_the_end_and_a_window_past_it_both_behave_like_a_seek() {
        let sealed = seal_object(1050, 100);
        let (tail, _) = read_window(&sealed, 1040, None);
        assert_eq!(tail, &sealed.plaintext[1040..]);

        // At or past the end is zero bytes, not an error — what `seek` + `read` does.
        let (past, fetched) = read_window(&sealed, 1050, Some(10));
        assert!(past.is_empty());
        assert_eq!(fetched, 0, "an empty span must not issue a request");
        let (way_past, _) = read_window(&sealed, u64::MAX, None);
        assert!(way_past.is_empty());
    }

    #[test]
    fn an_empty_object_has_no_chunks_to_fetch() {
        let sealed = seal_object(0, 1024);
        let (window, fetched) = read_window(&sealed, 0, None);
        assert!(window.is_empty());
        assert_eq!(fetched, 0);
    }

    #[test]
    fn a_tampered_chunk_is_refused_rather_than_returned() {
        // The guarantee this path is allowed to make: per-chunk Poly1305, checked on the
        // window itself. Flip a byte inside chunk 2's ciphertext and read from chunk 2.
        let chunk_size = 256u32;
        let mut sealed = seal_object(4096, chunk_size);
        let header =
            RangeHeader::open(&sealed.key, &sealed.bytes).expect("the pristine header opens");
        let span = header.span(512, Some(16)).expect("a span");
        let at = span.ciphertext_offset() as usize;
        sealed.bytes[at + 3] ^= 0x40;

        let to = at + span.ciphertext_len() as usize;
        let error = header
            .read_window(&span, &sealed.bytes[at..to])
            .expect_err("a flipped ciphertext byte must not authenticate");
        assert!(matches!(error, CryptoError::Aead));
    }

    #[test]
    fn a_chunk_moved_to_another_index_does_not_authenticate() {
        // Chunk AAD is head ‖ index, so a reorder is caught even though both chunks are
        // genuine ciphertext from this very object under the same DEK.
        let chunk_size = 256u32;
        let sealed = seal_object(4096, chunk_size);
        let header = RangeHeader::open(&sealed.key, &sealed.bytes).expect("the header opens");

        let chunk_1 = header.chunk_span(1, 1).expect("chunk 1");
        let chunk_5 = header.chunk_span(5, 1).expect("chunk 5");
        let from = chunk_5.ciphertext_offset() as usize;
        let borrowed = &sealed.bytes[from..from + chunk_5.ciphertext_len() as usize];

        let error = header
            .read_window(&chunk_1, borrowed)
            .expect_err("chunk 5's bytes must not verify as chunk 1");
        assert!(matches!(error, CryptoError::Aead));
    }

    #[test]
    fn a_short_range_response_is_refused_rather_than_decoded() {
        // A backend that clamped or truncated the range must not be able to produce a
        // silently short read: the span's length is part of what is checked.
        let sealed = seal_object(4096, 256);
        let header = RangeHeader::open(&sealed.key, &sealed.bytes).expect("the header opens");
        let span = header.span(0, Some(1024)).expect("a span");
        let from = span.ciphertext_offset() as usize;
        let to = from + span.ciphertext_len() as usize - 1;
        let error = header
            .read_window(&span, &sealed.bytes[from..to])
            .expect_err("a short range must be refused");
        assert!(matches!(error, CryptoError::Format(_)));
    }

    #[test]
    fn the_wrong_key_cannot_open_the_header_at_all() {
        // No `expect_err` here: `RangeHeader` deliberately implements no `Debug`, because
        // the one thing it holds that a formatter could reach is the object's DEK.
        let sealed = seal_object(1024, 256);
        let Err(error) = RangeHeader::open(&[9u8; KEY_LEN], &sealed.bytes) else {
            panic!("a foreign key must not unwrap the DEK");
        };
        assert!(matches!(error, CryptoError::Aead));
    }

    #[test]
    fn the_header_extent_asks_for_exactly_what_it_still_needs() {
        let sealed = seal_object(1024, 256);
        // Nothing at all: the fixed head plus kem_ct_len is the first thing to fetch.
        assert_eq!(
            header_extent(&[]).expect("an empty prefix is a request, not an error"),
            HeaderExtent::Short(MIN_PROBE_LEN)
        );
        // Head only: enough to know K, so the next ask reaches through meta_len.
        assert_eq!(
            header_extent(&sealed.bytes[..MIN_PROBE_LEN]).expect("a head-only prefix decides"),
            HeaderExtent::Short(MIN_PROBE_LEN + WRAPPED_DEK_LEN + 4)
        );
        // Through meta_len: now the exact header length is known.
        let through_meta_len = MIN_PROBE_LEN + WRAPPED_DEK_LEN + 4;
        let HeaderExtent::Short(header_len) = header_extent(&sealed.bytes[..through_meta_len])
            .expect("a prefix through meta_len decides")
        else {
            panic!("the header is longer than meta_len's own offset");
        };
        assert_eq!(
            header_extent(&sealed.bytes[..header_len]).expect("the exact header decides"),
            HeaderExtent::Complete(header_len)
        );
        // And that length really is where chunk 0 starts.
        let header = RangeHeader::open(&sealed.key, &sealed.bytes).expect("the header opens");
        assert_eq!(
            header
                .chunk_span(0, 1)
                .expect("chunk 0")
                .ciphertext_offset(),
            header_len as u64
        );
    }

    #[test]
    fn a_forged_head_is_rejected_before_any_offset_is_computed() {
        let mut sealed = seal_object(1024, 256);
        // chunk_size = 0 is outside §3's (0, 16 MiB] and would make the covering-chunk
        // division a divide-by-zero if it were ever believed.
        sealed.bytes[8..12].copy_from_slice(&0u32.to_le_bytes());
        assert!(matches!(
            header_extent(&sealed.bytes),
            Err(CryptoError::Format(_))
        ));
    }

    #[test]
    fn the_geometry_is_readable_without_touching_the_payload() {
        // What a `stat` needs: size and the recorded content hash, from the header alone.
        let sealed = seal_object(4096, 256);
        let probe = OBJECT_HEADER_PROBE_LEN.min(sealed.bytes.len());
        let header = RangeHeader::open(&sealed.key, &sealed.bytes[..probe]).expect("opens");
        assert_eq!(header.plaintext_len(), 4096);
        assert_eq!(header.chunk_size(), 256);
        assert_eq!(header.chunk_count(), 16);
        let meta = header.metadata().expect("a v1 schema is parsed");
        assert_eq!(meta.size, 4096);
        assert_eq!(
            meta.content_blake3,
            *blake3::hash(&sealed.plaintext).as_bytes()
        );
        assert_eq!(header.file_id(), &sealed.bytes[52..68]);
    }

    #[test]
    fn the_last_chunk_is_measured_rather_than_assumed_full() {
        // The short final chunk is where a "count × stride" shortcut reads past the
        // footer and into nothing.
        let sealed = seal_object(650, 256);
        let header = RangeHeader::open(&sealed.key, &sealed.bytes).expect("opens");
        let span = header.chunk_span(2, 1).expect("the final chunk");
        assert_eq!(span.ciphertext_len(), 650 - 512 + TAG_LEN as u64);
        assert_eq!(
            span.ciphertext_offset() + span.ciphertext_len(),
            (sealed.bytes.len() - FOOTER_LEN) as u64,
            "the last chunk ends exactly where the footer begins"
        );
    }

    #[test]
    fn a_shared_object_is_windowed_the_same_way_the_owner_path_is() {
        // The §12 recipient-hybrid path (`kem_id = 1`) shares every byte of the payload
        // layout with the symmetric one — only the key wrapping the DEK differs — so a
        // window of a shared object must cost the same covering chunks and authenticate
        // the same way. Claimed in `RangeHeader::open_with_kw`; proved here, because a
        // path that is only reasoned about is a path that silently regresses.
        use crate::kem::{derive_recipient, sidecar};
        use crate::keys::generate_key;
        use crate::object::seal_to_recipients;

        let root = generate_key();
        let alice = derive_recipient(&root, 0).expect("a root-derived identity");
        let plaintext: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
        let object = seal_to_recipients(
            std::slice::from_ref(&alice.public),
            &plaintext,
            &Metadata::new("shared/f.bin"),
            256,
        )
        .expect("the object seals to a recipient");

        // A `kem_id = 1` header is longer than a symmetric one but still well inside one
        // probe — the claim `OBJECT_HEADER_PROBE_LEN` makes about a single-recipient
        // object, checked rather than assumed.
        let probe = OBJECT_HEADER_PROBE_LEN.min(object.len());
        let HeaderExtent::Complete(header_len) =
            header_extent(&object[..probe]).expect("the header decides")
        else {
            panic!("one probe must cover a single-recipient hybrid header");
        };

        // Recover `KW` the way the vault does, then open for random access with it.
        let mut head_bytes = [0u8; OBJECT_HEAD_LEN];
        head_bytes.copy_from_slice(&object[..OBJECT_HEAD_LEN]);
        let kem_ct_len = read_u16(&object, OBJECT_HEAD_LEN).expect("kem_ct_len") as usize;
        let block = &object[MIN_PROBE_LEN..MIN_PROBE_LEN + kem_ct_len];
        let kw = sidecar::recover_kw_from_block(&alice, &head_bytes, block)
            .expect("the block parses")
            .expect("this identity is a recipient");

        let header =
            RangeHeader::open_with_kw(&kw, &object[..header_len]).expect("the header opens");
        assert_eq!(header.plaintext_len(), 4096);
        // Bytes 1000..1100 straddle the boundary at 1024 between chunks 3 and 4, so the
        // fetch is exactly those two chunks — the same arithmetic as the owner path.
        let span = header.span(1000, Some(100)).expect("a span");
        assert_eq!(span.first_chunk(), 3);
        assert_eq!(span.ciphertext_len(), 2 * (256 + TAG_LEN as u64));
        let from = span.ciphertext_offset() as usize;
        let window = header
            .read_window(&span, &object[from..from + span.ciphertext_len() as usize])
            .expect("the window authenticates");
        assert_eq!(window.as_slice(), &plaintext[1000..1100]);

        // And the owner's root does not open it: a hybrid object has no symmetric
        // fallback, so the wrong opener must fail rather than half-succeed.
        assert!(RangeHeader::open(&root, &object[..header_len]).is_err());
    }

    #[test]
    fn a_chunk_run_past_the_end_is_clamped_to_the_chunks_that_exist() {
        let sealed = seal_object(650, 256);
        let header = RangeHeader::open(&sealed.key, &sealed.bytes).expect("opens");
        assert_eq!(header.chunk_span(1, 999).expect("clamped").chunk_count(), 2);
        assert!(header.chunk_span(3, 1).expect("past the end").is_empty());
    }
}
