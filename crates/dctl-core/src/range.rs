//! Ranged reads: serve a byte window by fetching only the chunks that cover it.
//!
//! [`Vault::get_file`](crate::Vault::get_file) is the whole-object read, and the only one
//! this crate had. Serving a window through it means downloading and decrypting
//! everything and then throwing nearly all of it away: an audit measured **+97 MB of
//! resident memory and a 95 MiB transfer to return a 10-byte window** of a 95 MiB object.
//! Mounted, a player seeking through a 40 GB film re-downloads 40 GB on every seek. There
//! is no filesystem on top of that, and there is no egress budget for it either.
//!
//! `docs/FORMAT.md` §3 specifies the alternative and every backend already implements the
//! primitive it needs. Chunk `i`'s ciphertext lives at
//! `payload_start + i·(chunk_size + 16)`, so the chunks covering a window are arithmetic;
//! [`Backend::get_range`] fetches exactly those bytes;
//! [`object::RangeHeader`](dctl_crypto::object::RangeHeader) authenticates each one's
//! Poly1305 tag before a byte of it is returned. This module is the join between the two.
//!
//! ## What it costs
//!
//! Opening a [`RangeReader`] costs one bounded header read — usually a single
//! [`OBJECT_HEADER_PROBE_LEN`]-byte request, at most one more if the object's `kem_wrap`
//! or metadata region is unusually large. After that **every window is exactly one
//! request** for exactly the covering chunks, because the reader holds the geometry and
//! the unwrapped DEK. Keeping a reader alive across reads is therefore the difference
//! between one round trip per window and three, which is what a mount depends on.
//!
//! ## What it proves
//!
//! Per-chunk Poly1305 authenticates every returned byte and binds it — through the
//! head-derived AAD — to this object, this index, this `chunk_size`, this
//! `plaintext_len`. Substitution, reordering, splicing and truncation are all caught.
//!
//! The **whole-object** checks are not evaluated on this path and are not faked: the
//! trailing footer BLAKE3 and the metadata's `content_blake3` both cover the entire
//! object, and no fragment can compute either. That is exactly the split `docs/FORMAT.md`
//! §3 describes ("the footer is a redundant whole-object check"), and it is why
//! [`Vault::verify_file`](crate::Vault::verify_file) — the read behind `dctl verify` and
//! `dctl scrub` — streams the object end to end and remains the command that makes the
//! whole-object statement. A caller that needs that statement must ask for the whole
//! object; a caller that needs a window gets per-chunk authentication, which is the
//! guarantee the format was designed to provide here.

use std::sync::Arc;

use dctl_crypto::constants::{FOOTER_LEN, OBJECT_HEADER_PROBE_LEN};
use dctl_crypto::object::{ChunkSpan, HeaderExtent, RangeHeader, header_extent};
use dctl_store::{Backend, ByteRange, ObjectKey};
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};

/// How many header probes a reader will issue before giving up.
///
/// The format bounds this at three by construction — the fixed head reveals `kem_ct_len`,
/// which reveals where `meta_len` sits, which reveals the total — so a fourth attempt
/// means the object is answering inconsistently (a racing rewrite, or a backend serving
/// different bytes for the same range). Bounding the loop turns that into an error
/// instead of a process that spins against a remote forever.
const MAX_HEADER_PROBES: usize = 3;

/// One authenticated chunk of plaintext, with the index it came from.
///
/// Carries the index because a caller repopulating a cache needs to know *which* chunk it
/// received, and inferring it from arrival order is the kind of assumption that survives
/// until the first partial span.
pub struct DecryptedChunk {
    /// The chunk's index within the object.
    pub index: u64,
    /// Its plaintext — the full chunk, not the caller's window — wiped on drop.
    pub plaintext: Zeroizing<Vec<u8>>,
}

/// An object opened for random access.
///
/// Holds the resolved backend key, the object's authenticated geometry and its unwrapped
/// DEK, so a window costs one request and no re-resolution. Cheap to keep: one 32-byte
/// key plus the bounded header state, all wiped on drop.
///
/// A reader is bound to the **object** it opened, not to the path it was opened by. If
/// the path is rewritten to point at a new object, this reader keeps serving the one it
/// resolved — the same guarantee an open file descriptor gives on a POSIX filesystem, and
/// the one a mount has to present. [`file_id`](RangeReader::file_id) identifies which
/// object that is, so a cache keyed by it can never serve one object's chunks for
/// another's.
pub struct RangeReader {
    backend: Arc<dyn Backend>,
    key: ObjectKey,
    header: RangeHeader,
    /// The object's header bytes exactly as stored — `[0, payload_start)`.
    ///
    /// Kept, rather than re-derived from the parsed [`RangeHeader`], because §3's footer
    /// is a BLAKE3 over *the bytes the writer emitted*, and a re-encoded header is a
    /// second encoder that can drift from the one that wrote the object. It is the first
    /// thing folded into a streaming footer check and it is already in hand: the header
    /// probe that opened this reader fetched exactly these bytes.
    header_bytes: bytes::Bytes,
    /// The logical path this reader was opened by — only ever used to name the file in an
    /// integrity error, since an operator cannot act on `o/3f9a…`.
    path: String,
}

impl RangeReader {
    /// Assemble a reader from an already-decoded header. `pub(crate)` because unwrapping
    /// the DEK needs the vault root (or a recovered §12 `KW`), which is
    /// [`Vault`](crate::Vault)'s to hold — see
    /// [`Vault::open_range_reader`](crate::Vault::open_range_reader).
    pub(crate) const fn new(
        backend: Arc<dyn Backend>,
        key: ObjectKey,
        header: RangeHeader,
        header_bytes: bytes::Bytes,
        path: String,
    ) -> Self {
        Self {
            backend,
            key,
            header,
            header_bytes,
            path,
        }
    }

    /// The object's plaintext length, from its authenticated head.
    ///
    /// Established, not guessed: the DEK unwrap folds the whole 68-byte head into its
    /// AAD, and the metadata decode enforces `meta.size == plaintext_len`. A `stat` can
    /// therefore be answered from a bounded header read rather than by reading the object.
    #[must_use]
    pub const fn plaintext_len(&self) -> u64 {
        self.header.plaintext_len()
    }

    /// Plaintext bytes per chunk. Every chunk but the last carries exactly this many,
    /// which is what makes the covering-chunk arithmetic exact.
    #[must_use]
    pub const fn chunk_size(&self) -> u32 {
        self.header.chunk_size()
    }

    /// Number of chunks in the object.
    #[must_use]
    pub const fn chunk_count(&self) -> u64 {
        self.header.chunk_count()
    }

    /// The object's random per-object id (§3) — stable across renames, different for
    /// every rewrite, and authenticated with the rest of the head. The correct key for a
    /// cache of decrypted chunks.
    #[must_use]
    pub const fn file_id(&self) -> &[u8; 16] {
        self.header.file_id()
    }

    /// The BLAKE3 of the object's **whole** plaintext, as the writer recorded it in the
    /// DEK-authenticated §4 metadata. [`None`] only for an unknown `schema_version`
    /// (skipped-and-served per §8).
    ///
    /// This is the recorded value, not a re-computation: a ranged read cannot hash bytes
    /// it never fetched. It is worth returning anyway because it is authenticated under
    /// the object's own key — strictly better than the copy in a local index, which no
    /// key protects — and because it is what a caller compares against when it later
    /// reads the object whole.
    #[must_use]
    pub fn content_blake3(&self) -> Option<&[u8; 32]> {
        self.header.metadata().map(|meta| &meta.content_blake3)
    }

    /// Read the plaintext window `[offset, offset + length)`; `length` of [`None`] means
    /// "to the end".
    ///
    /// One [`Backend::get_range`] for exactly the covering chunks, then per-chunk
    /// authentication, then the slice. A window past the end of the object yields fewer
    /// bytes than asked for rather than an error, matching a `seek` plus a bounded read.
    ///
    /// # Errors
    /// [`CoreError::Store`] if the range could not be fetched, [`CoreError::Crypto`] if
    /// any covering chunk fails authentication — in which case **no** bytes are returned.
    pub async fn read_range(&self, offset: u64, length: Option<u64>) -> Result<Zeroizing<Vec<u8>>> {
        let span = self.header.span(offset, length)?;
        if span.is_empty() {
            return Ok(Zeroizing::new(Vec::new()));
        }
        let ciphertext = self.fetch(&span).await?;
        Ok(self.header.read_window(&span, &ciphertext)?)
    }

    /// Read chunks `[first, first + count)` whole, authenticated, in **one** request.
    ///
    /// The form a chunk cache wants: it receives the full chunks rather than a window, so
    /// the next read that lands in the same chunk costs neither a request nor a decrypt.
    /// `count` is clamped to the object, so a run reaching past the end yields only the
    /// chunks that exist and an entirely out-of-range run yields nothing.
    ///
    /// # Errors
    /// As [`read_range`](RangeReader::read_range).
    pub async fn read_chunks(&self, first: u64, count: u64) -> Result<Vec<DecryptedChunk>> {
        self.read_chunks_inner(first, count, None).await
    }

    /// [`read_chunks`](RangeReader::read_chunks), folding each window's **ciphertext**
    /// into `footer` on its way past.
    ///
    /// The seam a constant-memory whole-object read needs. §3's footer is a BLAKE3 over
    /// the header bytes followed by every chunk's ciphertext, and a reader that never
    /// holds the object cannot hash it afterwards — but it does hold each window for as
    /// long as it takes to decrypt it, which is exactly long enough. Folding here rather
    /// than handing the ciphertext out keeps the buffer private and keeps the fold in the
    /// one place that knows the fetch actually happened.
    ///
    /// Start the hasher with [`footer_fold`](RangeReader::footer_fold) and finish it with
    /// [`confirm_footer`](RangeReader::confirm_footer); neither is optional if the object
    /// declares a footer, because a fold that is started and never compared is a check
    /// that reports success without running.
    ///
    /// # Errors
    /// As [`read_chunks`](RangeReader::read_chunks).
    pub async fn read_chunks_folding(
        &self,
        first: u64,
        count: u64,
        footer: &mut blake3::Hasher,
    ) -> Result<Vec<DecryptedChunk>> {
        self.read_chunks_inner(first, count, Some(footer)).await
    }

    /// The shared body of both, so the fetch and the decode cannot drift between them.
    async fn read_chunks_inner(
        &self,
        first: u64,
        count: u64,
        footer: Option<&mut blake3::Hasher>,
    ) -> Result<Vec<DecryptedChunk>> {
        let span = self.header.chunk_span(first, count)?;
        if span.is_empty() {
            return Ok(Vec::new());
        }
        let ciphertext = self.fetch(&span).await?;
        if let Some(footer) = footer {
            footer.update(&ciphertext);
        }

        // The decoder hands each chunk over owned, so this is a move rather than a copy —
        // on a sequential read of a large file the difference is one extra copy of the
        // whole file.
        let mut chunks = Vec::with_capacity(span.chunk_count() as usize);
        self.header
            .open_chunks(&span, &ciphertext, |index, plaintext| {
                chunks.push(DecryptedChunk { index, plaintext });
                Ok(())
            })?;
        Ok(chunks)
    }

    /// A footer hash seeded with this object's header bytes, or [`None`] if it declares
    /// no footer.
    ///
    /// [`None`] is a real answer and not a failure: §3 makes the footer a flag, and an
    /// object written without one is verified by its per-chunk tags alone. Returning an
    /// `Option` rather than an always-on hasher is what stops a caller comparing a fold
    /// against 32 bytes that are not there.
    #[must_use]
    pub fn footer_fold(&self) -> Option<blake3::Hasher> {
        if !self.header.has_footer() {
            return None;
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.header_bytes);
        Some(hasher)
    }

    /// Compare a completed [`footer_fold`](RangeReader::footer_fold) against the object's
    /// stored footer, in one bounded ranged request.
    ///
    /// This is the check that a windowed read would otherwise silently drop, and dropping
    /// it was not theoretical: flipping the last byte of every object in a vault — which
    /// lands in the footer — left `dctl verify` reporting every file intact. The footer is
    /// unkeyed and so stops no attacker who can rewrite the whole object, but it is the
    /// only thing covering bytes that no chunk tag claims, and bit rot does not care that
    /// the field it landed in was redundant.
    ///
    /// # Errors
    /// [`CoreError::Integrity`] if the object's own footer disagrees with the bytes that
    /// were streamed, or if the object is too short to hold the footer it declares, and
    /// whatever the backend reported.
    pub async fn confirm_footer(&self, fold: blake3::Hasher) -> Result<()> {
        let at = self.payload_end()?;
        let stored = self
            .backend
            .get_range(&self.key, ByteRange::new(at, Some(FOOTER_LEN as u64)))
            .await?;
        if stored.len() != FOOTER_LEN {
            return Err(CoreError::Integrity(format!(
                "{}: object declares a footer and holds {} of its {FOOTER_LEN} bytes",
                self.path,
                stored.len()
            )));
        }
        if stored.as_ref() != fold.finalize().as_bytes() {
            return Err(CoreError::Integrity(format!(
                "{}: the object's footer does not match the bytes it served",
                self.path
            )));
        }
        Ok(())
    }

    /// The byte after the last chunk's tag: where a footer would begin.
    fn payload_end(&self) -> Result<u64> {
        let Some(last) = self.header.chunk_count().checked_sub(1) else {
            return Ok(self.header.payload_start());
        };
        let span = self.header.chunk_span(last, 1)?;
        Ok(span
            .ciphertext_offset()
            .saturating_add(span.ciphertext_len()))
    }

    /// Confirm the stored object is exactly as long as its authenticated geometry says
    /// it should be, in one bounded metadata request and no body transfer.
    ///
    /// This is the check that survives the footer's absence on the streaming read path.
    /// `docs/FORMAT.md` §3's trailing footer is a BLAKE3 over the whole ciphertext, and a
    /// read that never holds the whole ciphertext cannot fold it — see
    /// [`Vault::verify_file`](crate::Vault::verify_file) for why that costs nothing an
    /// attacker could use. The one accidental corruption it *did* uniquely catch is bytes
    /// appended past the last chunk, which no per-chunk tag covers because no chunk claims
    /// them. So the length is asked of the provider instead and held to the number the head
    /// implies: the head is authenticated by the DEK unwrap, so `chunk_count`, `chunk_size`
    /// and `plaintext_len` are facts rather than hints, and the end of the last chunk's
    /// ciphertext is arithmetic from them.
    ///
    /// The footer itself is 32 bytes that may or may not be present (§3 makes it a flag), so
    /// both lengths are accepted; anything else is an object that is not the shape it says
    /// it is.
    ///
    /// An object with no chunks at all has no last chunk to measure from and is passed: its
    /// header is bounded, already authenticated, and holds no payload to append to.
    ///
    /// # Errors
    /// [`CoreError::Integrity`] if the stored length is neither of the two the geometry
    /// allows, and whatever the backend reported if it could not be asked.
    pub async fn confirm_object_length(&self) -> Result<()> {
        if self.header.chunk_count() == 0 {
            return Ok(());
        }
        let payload_end = self.payload_end()?;
        let stored = self.backend.head(&self.key).await?.size;
        if stored == payload_end || stored == payload_end + FOOTER_LEN as u64 {
            return Ok(());
        }
        Err(CoreError::Integrity(format!(
            "{}: stored object is {stored} bytes, its authenticated geometry accounts for \
             {payload_end}",
            self.path
        )))
    }

    /// The single ranged request behind both readers: exactly the span's ciphertext.
    ///
    /// A backend that answered with the wrong number of bytes is caught here rather than
    /// deeper in the decoder, so the error names the transfer rather than the format —
    /// the difference between "your provider truncated a range response" and "your object
    /// is corrupt", which lead an operator to entirely different places.
    async fn fetch(&self, span: &ChunkSpan) -> Result<bytes::Bytes> {
        let bytes = self
            .backend
            .get_range(
                &self.key,
                ByteRange::new(span.ciphertext_offset(), Some(span.ciphertext_len())),
            )
            .await?;
        if bytes.len() as u64 != span.ciphertext_len() {
            return Err(CoreError::Integrity(format!(
                "{}: ranged read returned {} bytes, expected {}",
                self.path,
                bytes.len(),
                span.ciphertext_len()
            )));
        }
        Ok(bytes)
    }
}

/// Fetch an object's header prefix, and return it with its exact header length.
///
/// The header is variable-length and self-describing, so this asks for
/// [`OBJECT_HEADER_PROBE_LEN`] bytes — which covers every ordinary object in one request —
/// and re-reads only if the object says it needs more, with the length it says. A read
/// that comes back shorter than the object claims its header to be is a truncated object,
/// reported as such rather than retried forever.
pub(crate) async fn fetch_header(
    backend: &dyn Backend,
    key: &ObjectKey,
    path: &str,
) -> Result<(bytes::Bytes, usize)> {
    let mut want = OBJECT_HEADER_PROBE_LEN;
    for _ in 0..MAX_HEADER_PROBES {
        let prefix = backend
            .get_range(key, ByteRange::new(0, Some(want as u64)))
            .await?;
        match header_extent(&prefix)? {
            HeaderExtent::Complete(header_len) => return Ok((prefix, header_len)),
            // The object needs more than we asked for. It can only *have* more if the
            // backend gave us everything we asked for; a short answer means the object
            // ends inside its own header.
            HeaderExtent::Short(need) if prefix.len() >= want => want = need,
            HeaderExtent::Short(_) => return Err(truncated(path)),
        }
    }
    Err(CoreError::Integrity(format!(
        "{path}: object header did not resolve in {MAX_HEADER_PROBES} reads"
    )))
}

/// An object whose bytes stop inside its own header. Integrity rather than "not found":
/// the object is there, and what is there is not a whole object.
fn truncated(path: &str) -> CoreError {
    CoreError::Integrity(format!("{path}: object truncated inside its header"))
}
