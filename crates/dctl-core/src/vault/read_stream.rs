//! The constant-memory sequential read: the one way this crate moves a whole
//! object without ever holding one.
//!
//! [`Vault::get_file`](super::Vault::get_file) returns a `Vec` and therefore
//! costs the object; that is its contract and it is the right shape for a small
//! file. Every *other* whole-object read in the system — a download, a `cat`, a
//! scrub — wants the same guarantee at a cost that does not move when the file
//! grows, and until this module there was nowhere to get it. Measured on the
//! release binary before it existed: `copy` of a 1 GiB object out of a vault
//! peaked at **2064 MiB** of resident memory, `copy` into one at **3090 MiB**,
//! and a 256 MiB object could not be moved inside a 512 MiB cap at all. Both
//! curves were dead straight in the object's size.
//!
//! ## The shape
//!
//! `crates/dctl-decode/FORMAT.md` §3 makes the payload a sequence of
//! independently sealed chunks, and
//! [`Backend::get_range`](dctl_store::Backend::get_range) — which every backend
//! implements as a genuine ranged request — can fetch any run of them. So a
//! whole-object read is a *window walk*: fetch
//! [`STREAM_WINDOW_CHUNKS`](crate::constants::STREAM_WINDOW_CHUNKS) chunks,
//! authenticate each one, write its plaintext out, drop it, advance. Nothing
//! that scales with the object is ever allocated, and the peak is a constant in
//! `constants.rs` rather than a property of the data.
//!
//! This is deliberately built on the ranged reader rather than on a streamed
//! HTTP body. A body stream is per-provider and exists on some backends and not
//! others; `get_range` is on the trait, is required to be a true ranged read,
//! and is already what the mount depends on. One implementation therefore
//! streams `local:`, `sftp:`, B2, S3 and R2 identically, and a backend added
//! later inherits it by implementing a primitive it already had to implement.
//!
//! ## What a streamed read proves
//!
//! **Exactly what the buffered read proves.** This is worth being precise about,
//! because a constant-memory read that quietly made a weaker statement would be
//! a bad trade dressed as a good one:
//!
//! * **Every byte is authenticated before it is written.** Each chunk carries a
//!   Poly1305 tag over an AAD binding the object's authenticated head — and so
//!   its `plaintext_len`, `chunk_count`, `chunk_size` and `file_id` — together
//!   with the chunk's own index. Substitution, reordering, splicing from another
//!   object and truncation are all caught (§3).
//! * **The whole-object hash is checked too.** A sequential read sees every byte
//!   in order, so it folds a BLAKE3 over the plaintext as it goes and compares
//!   the result against the object's own `content_blake3` — the value the writer
//!   recorded in the DEK-authenticated §4 metadata. That is the same comparison
//!   [`Vault::get_file`](super::Vault::get_file) makes, and it is the one a
//!   *windowed* read cannot make because it never sees the other bytes.
//!
//! * **The trailing footer is folded too**, from the same ciphertext each
//!   window was decrypted from. `crates/dctl-decode/FORMAT.md` §3's footer is a
//!   BLAKE3 over the header bytes followed by every chunk's ciphertext, so a
//!   reader that never holds the object cannot hash it *afterwards* — but it
//!   holds each window for exactly as long as it takes to decrypt, which is
//!   long enough to fold it. The stored 32 bytes are then fetched in one
//!   bounded request and compared.
//!
//! That last point was very nearly a silent regression, and it is worth recording
//! why. The first version of this module argued the footer away: it is unkeyed, so
//! it stops no attacker who can rewrite an object, and every mutation it catches is
//! also caught by a chunk's Poly1305 tag. The first half is true and the second is
//! false. The footer covers bytes **no chunk tag claims** — the header region, and
//! the footer itself — and a `dctl verify` whose job is to find bit rot does not get
//! to skip a region because the damage there would have been redundant to detect.
//! An existing test flipped the last byte of every object in a vault and expected
//! exit 21; against the footer-less version it got a clean bill of health for two
//! corrupt files. The check is folded, not argued about.
//!
//! ## Failure leaves nothing half-published
//!
//! [`Vault::get_file_to_path`](super::Vault::get_file_to_path) assembles into a
//! staging sibling of the destination and renames only after the final hash
//! comparison passes, so a tamper, a truncation or a disconnect mid-object
//! leaves **no** destination file rather than a partial one. A caller streaming
//! to a pipe cannot be given that guarantee — bytes written to a terminal cannot
//! be recalled — and [`Vault::stream_file_to`] says so rather than pretending
//! otherwise.

use std::path::Path;

use dctl_crypto::path;
use tokio::io::{AsyncWrite, AsyncWriteExt};

use super::Vault;
use super::put_stream::io_err;
use crate::constants::STREAM_WINDOW_CHUNKS;
use crate::error::{CoreError, Result};
use crate::range::RangeReader;
use crate::streamed::Streamed;

impl Vault {
    /// Stream the whole plaintext of `path` to `out`, at
    /// `O(STREAM_WINDOW_CHUNKS × chunk_size)` memory, returning the number of
    /// bytes written.
    ///
    /// The constant-memory twin of [`get_file`](Vault::get_file), making the
    /// identical integrity statement — every chunk authenticated before it is
    /// written, and the assembled plaintext checked against the object's own
    /// DEK-authenticated `content_blake3`. See the module documentation for why
    /// the footer is not part of that and why nothing is lost by it.
    ///
    /// **Bytes reach `out` before the whole-object check completes.** Each has
    /// been authenticated by its chunk's tag, but the final comparison cannot
    /// happen until the last byte has been hashed, so a caller writing somewhere
    /// irrevocable — a pipe, a socket, a terminal — may already have emitted a
    /// prefix when this returns [`CoreError::Integrity`]. That is unavoidable
    /// for a stream, and it is why
    /// [`get_file_to_path`](Vault::get_file_to_path) exists: writing to a file
    /// goes through a staging sibling and a rename, so a failure publishes
    /// nothing.
    ///
    /// # Errors
    /// [`CoreError::NotFound`] if the path resolves nowhere,
    /// [`CoreError::Crypto`] if any chunk fails authentication,
    /// [`CoreError::Integrity`] if the assembled plaintext does not match the
    /// hash the object records for it, and whatever the backend reported.
    #[tracing::instrument(skip(self, out), fields(backend = self.backend.name()))]
    pub async fn stream_file_to<W>(&self, path: &str, out: &mut W) -> Result<Streamed>
    where
        W: AsyncWrite + Unpin + Send + ?Sized,
    {
        let normalized = path::normalize(path)?;
        let reader = self.open_range_reader(&normalized).await?;
        self.stream_reader_to(&reader, &normalized, out).await
    }

    /// The window walk itself, over a reader the caller already opened.
    ///
    /// Split out because opening a reader costs a bounded header request and
    /// [`verify_file`](Vault::verify_file) needs the *same* reader twice — once
    /// to check the stored object's length against its geometry, once to stream
    /// it — and re-opening between the two would pay that request again and, far
    /// worse, would let the two halves of one verdict be taken over two
    /// different objects if the backend were rewritten in between.
    ///
    /// `normalized` is already-normalized and used only to name the file in an
    /// integrity error, since an operator cannot act on `o/3f9a…`.
    ///
    /// # Errors
    /// As [`stream_file_to`](Vault::stream_file_to).
    pub(crate) async fn stream_reader_to<W>(
        &self,
        reader: &RangeReader,
        normalized: &str,
        out: &mut W,
    ) -> Result<Streamed>
    where
        W: AsyncWrite + Unpin + Send + ?Sized,
    {
        let expected = reader.content_blake3().copied();

        let mut hasher = blake3::Hasher::new();
        // `None` for an object written without a footer (§3 makes it a flag), in
        // which case there is nothing to compare and the per-chunk tags are what
        // ran. Seeded with the object's header bytes, which the footer covers
        // before it reaches the payload.
        let mut footer = reader.footer_fold();
        let mut written: u64 = 0;
        let mut next = 0u64;

        // The window walk. `read_chunks` clamps to the object, so the final
        // window is short rather than an error, and an empty object performs no
        // iterations at all.
        while next < reader.chunk_count() {
            let chunks = match footer.as_mut() {
                Some(fold) => {
                    reader
                        .read_chunks_folding(next, STREAM_WINDOW_CHUNKS, fold)
                        .await?
                }
                None => reader.read_chunks(next, STREAM_WINDOW_CHUNKS).await?,
            };
            if chunks.is_empty() {
                // The reader agreed chunks remained and then produced none.
                // Continuing would spin against the backend forever and
                // returning `Ok` would report a short read as a complete one,
                // which is the misreport this project may not have.
                return Err(CoreError::Integrity(format!(
                    "{normalized}: object stopped after {written} of {} bytes",
                    reader.plaintext_len()
                )));
            }
            for chunk in chunks {
                hasher.update(&chunk.plaintext);
                out.write_all(&chunk.plaintext).await.map_err(io_err)?;
                written = written.saturating_add(chunk.plaintext.len() as u64);
                next = next.saturating_add(1);
                // `chunk.plaintext` drops here — wiped, and its memory is reused
                // by the next window rather than accumulated.
            }
        }

        // The head is authenticated, so its `plaintext_len` is a fact about the
        // object rather than a hint. A stream that produced a different number
        // of bytes was served something other than what it asked for.
        if written != reader.plaintext_len() {
            return Err(CoreError::Integrity(format!(
                "{normalized}: streamed {written} bytes, object declares {}",
                reader.plaintext_len()
            )));
        }

        // The whole-object statement. Absent only for a metadata schema this
        // build does not parse (§8), where the honest position is that the
        // per-chunk tags are what ran — the same position `get_file` takes.
        let plaintext_hash = *hasher.finalize().as_bytes();
        if let Some(expected) = expected {
            if plaintext_hash != expected {
                tracing::warn!(path = %normalized, "plaintext hash mismatch — integrity failure");
                return Err(CoreError::Integrity(normalized.to_string()));
            }
        }

        // The footer last, because it covers everything that came before it. A
        // fold that was started must be compared: a check that runs and is never
        // consulted reports success without having said anything.
        if let Some(fold) = footer {
            reader.confirm_footer(fold).await?;
        }

        out.flush().await.map_err(io_err)?;
        tracing::debug!(bytes = written, "streamed and integrity-verified");
        Ok(Streamed {
            bytes: written,
            plaintext_hash,
        })
    }

    /// Stream the whole plaintext of `logical_path` onto the local file `dest`,
    /// at constant memory and atomically.
    ///
    /// The publishing wrapper around [`stream_file_to`](Vault::stream_file_to):
    /// bytes are assembled under a staging sibling of `dest`, fsynced, and
    /// renamed onto `dest` only once every chunk has authenticated *and* the
    /// whole-plaintext hash has matched. Any failure removes the staging file
    /// and leaves `dest` untouched — absent if it was absent, and carrying its
    /// previous contents if it was not. There is no state in which `dest` holds
    /// a partial object.
    ///
    /// The staging file is a **sibling**, not a system temp file, and that is
    /// load-bearing twice over: `rename` is only atomic within one filesystem,
    /// and on the many Linux installations that mount `/tmp` as `tmpfs` a
    /// system temp would stage the whole object in RAM — silently undoing
    /// everything this path exists for.
    ///
    /// # Errors
    /// As [`stream_file_to`](Vault::stream_file_to), plus any I/O error from
    /// creating, writing, syncing or renaming the destination.
    #[tracing::instrument(skip(self), fields(backend = self.backend.name()))]
    pub async fn get_file_to_path(&self, logical_path: &str, dest: &Path) -> Result<Streamed> {
        if let Some(parent) = dest.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(io_err)?;
        }
        let staging = dctl_store::staging::staging_sibling(dest);

        let outcome = async {
            let file = tokio::fs::File::create(&staging).await.map_err(io_err)?;
            let mut writer =
                tokio::io::BufWriter::with_capacity(crate::constants::STREAM_BUF_LEN, file);
            let streamed = self.stream_file_to(logical_path, &mut writer).await?;
            // `sync_all` before the rename, so no name can point at bytes the
            // storage layer has not committed: a crash must never leave a
            // complete-looking file full of zeroes.
            let file = writer.into_inner();
            file.sync_all().await.map_err(io_err)?;
            Ok::<Streamed, CoreError>(streamed)
        }
        .await;

        let streamed = match outcome {
            Ok(streamed) => streamed,
            Err(error) => {
                let _ = tokio::fs::remove_file(&staging).await;
                return Err(error);
            }
        };
        if let Err(error) = tokio::fs::rename(&staging, dest).await {
            let _ = tokio::fs::remove_file(&staging).await;
            return Err(io_err(error));
        }
        tracing::info!(path = %logical_path, "file decrypted to destination");
        Ok(streamed)
    }
}
