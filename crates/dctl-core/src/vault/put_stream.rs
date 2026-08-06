//! `put_file_from_path`: sealing a file straight onto the wire, with no scratch
//! disk at all.
//!
//! Where [`Vault::put_file`](super::Vault::put_file) buffers the whole plaintext
//! (and seals it) in RAM, this path seals the source **into a bounded pipe** that
//! the backend drains, chunk by chunk, as fast as the link will take it. No stage
//! holds the whole file and no stage holds the whole object — and, since the
//! rewrite this module documents, no stage writes either of them to local disk.
//!
//! ## What used to be here, and what it cost
//!
//! The previous shape sealed the source to a temporary file, hashed that file,
//! and handed the path to the backend's
//! [`put_from_path`](dctl_store::Backend::put_from_path). Memory was bounded and
//! **disk was not**: every upload needed one object of free scratch space, and —
//! because a spool's page cache is charged to the same cgroup as the program —
//! a hard memory cap had to be sized for the writeback as well as for the
//! process. Measured, that was 491–504 MiB of *file* charge against a 512 MiB cap
//! at every object size, and on one 1 GiB copy to `sftp:` reclaim lost the race
//! and the kernel OOM-killed the run at 12.2 seconds. `docker run -m 512m` was
//! not a safe way to run DCTL, and the reason was a temporary file.
//!
//! The spool was never there for memory. It was there because a caller could not
//! *address* an object it had not produced: the destination key is
//! `o/<hex file_id>` and the `file_id` is generated inside the sealer, and a
//! multipart upload additionally has to know the object's exact length before its
//! first part. [`PlannedSeal`](dctl_crypto::object::PlannedSeal) answers both
//! before a payload byte exists, which is what let the file go.
//!
//! ## The memory contract, and every term in it
//!
//! The transfer's own working set:
//!
//! ```text
//! 2 × chunk_size                              the sealer: one scratch buffer and
//!                                             the ciphertext it produces from it
//! + WINDOW_LEN × (WINDOWS_IN_FLIGHT + 2)      the pipe (dctl_store::incoming)
//! + part_size × UPLOAD_PARTS_IN_FLIGHT        the object stores only
//! ```
//!
//! Every term is a named constant and **not one of them is a function of the
//! object's size**. There is no page-cache term because there is no file. At the
//! defaults that is 8 MiB on `local:` and `sftp:`, and 108 MiB on `b2:` — where
//! the part size is the whole of the difference and is what a remote's
//! `chunk_size` lowers.
//!
//! ## What a container must be sized for, which is **not** that number
//!
//! Quoting the figures above as the program's cost would be the same shape of
//! false claim this module exists to retire, so: a run that writes into a vault
//! **unlocks** it first, and unlocking is Argon2id at
//! [`DEFAULT_ARGON2_M_COST`](dctl_crypto::constants::DEFAULT_ARGON2_M_COST) —
//! 128 MiB, on purpose, because a password-derived key is worth exactly the
//! memory an attacker must spend to guess it. That allocation is one-shot and is
//! released before the first window is sealed, so the peak is a **maximum and
//! not a sum**:
//!
//! ```text
//! peak = max(Argon2id m_cost, the transfer terms above) + the runtime's overhead
//! ```
//!
//! and at every default the first term wins, on every backend. Measured on the
//! release binary under a 256 MiB cgroup cap, copy in and copy out, at 256 MiB,
//! 1 GiB and 4 GiB objects: **144 MiB of peak RSS on `local:` and `sftp:`, 147 MiB
//! on `b2:`, and 131 MiB of anonymous memory on all three — the same figures a
//! 1 MiB object produces.** That the b2 column does not sit 108 MiB higher is the
//! measurement that proves the max: the KDF's arena is gone by the time the first
//! part is bought.
//!
//! Two consequences worth stating plainly, because an operator sizing a container
//! will meet both. The flatness in object size is what this module bought. The
//! *height* is the KDF's, it was there before any of this, and it is why the
//! number to provision is in the region of 192 MiB rather than the 8 MiB the
//! transfer terms alone would suggest.
//!
//! ## The order, unchanged
//!
//! Object written and verified → the authoritative §5 name record → the durable
//! index commit. Success is reported only once the data is durably and correctly
//! stored, exactly as on the buffered path, and the *verification* now happens
//! inside the backend against a digest the sealer folded as it produced —
//! [`ObjectStream::agreed`](dctl_store::ObjectStream::agreed) states precisely
//! what that proves and what proves the rest.
//!
//! ## Two passes over the source, and why there is no third
//!
//! The format requires two: `enc_metadata` ships before the payload and carries
//! `content_blake3` of the whole plaintext, so the sealer hashes the input,
//! rewinds, and encrypts it. This module used to make a **third** pass to compute
//! the index row's plaintext digest — the same number the sealer had already
//! folded in pass one. It is handed back from the plan now, so a four-gigabyte
//! file is read twice rather than three times.

use std::path::Path;

use bytes::Bytes;
use dctl_crypto::object::{Metadata, PlannedSeal};
use dctl_crypto::path;
use dctl_index::Record;
use dctl_store::{ContentHash, HashAlgo, ObjectKey, SourceModified};
use zeroize::Zeroizing;

use super::{Modified, Vault, layout};
use crate::error::{CoreError, Result};
use crate::streamed::Streamed;

/// What phase one of the seal produced: the framing, and the open source handle
/// it was computed from.
///
/// The **same handle**, carried from one blocking task to the next rather than
/// the file being re-opened between them. Re-opening would widen the window in
/// which the source could change under the two passes — and a source that changed
/// between the hash and the encryption produces an object whose sealed
/// `content_blake3` does not describe its own payload, which nothing downstream
/// would notice until somebody verified it years later.
struct Planned<S> {
    plan: PlannedSeal,
    source: S,
}

impl Vault {
    /// Store the file at `source` under the logical `logical_path`, sealing it
    /// straight to the backend in bounded windows and writing nothing to local
    /// disk.
    ///
    /// Byte-for-byte equivalent to [`put_file`](Vault::put_file) for the same
    /// content: the object decodes identically, so a file stored here opens
    /// through the very same [`get_file`](Vault::get_file) path as a buffered put.
    ///
    /// `modified` is a required argument for the reason [`Modified`] gives, and it
    /// is **not** read from `source` even though this path opens the file:
    /// `source` is sometimes a spool of something that has no modification time of
    /// its own (a pipe captured by `dctl rcat`), and taking the temporary file's
    /// time would record the moment of the spool while looking exactly like a real
    /// answer.
    ///
    /// # Errors
    /// Whatever sealing, uploading or indexing reported. Nothing is committed on
    /// any of them: the object is not finished, the name record is not written,
    /// and the index row is not added.
    #[tracing::instrument(skip(self), fields(backend = self.backend.name()))]
    pub async fn put_file_from_path(
        &self,
        logical_path: &str,
        source: &Path,
        modified: Modified,
    ) -> Result<Streamed> {
        let source = source.to_path_buf();
        // Opened off the runtime: `open` and `metadata` both hit the filesystem,
        // and an async task that blocks on a slow disk stalls every other task
        // sharing its thread.
        let (file, plaintext_len) = tokio::task::spawn_blocking(move || -> Result<_> {
            let file = std::fs::File::open(&source).map_err(io_err)?;
            let len = file.metadata().map_err(io_err)?.len();
            Ok((file, len))
        })
        .await
        .map_err(|e| task_failed("opening the source", &e))??;

        self.put_file_from_source(logical_path, file, plaintext_len, modified)
            .await
    }

    /// Seal `source` under `logical_path`, streaming, without it ever being a
    /// file on disk in the clear.
    ///
    /// The generic half of [`put_file_from_path`](Vault::put_file_from_path),
    /// and the primitive a read-write mount needs: it accepts any seekable
    /// reader, so the bytes may come from a decrypting view over an encrypted
    /// spill rather than from plaintext somebody could read while the file is
    /// open.
    ///
    /// `plaintext_len` is passed rather than measured because a reader has no
    /// length of its own, and the caller — which created the spill — is the only
    /// party that knows it. It must be exact: it decides the frame layout, and a
    /// wrong value produces an object whose header disagrees with its contents.
    ///
    /// `modified` is a required argument for the reason [`Modified`] gives, and
    /// it is never inferred from the source.
    ///
    /// # Errors
    /// Whatever sealing, uploading or indexing reported. Nothing is committed on
    /// any of them: the object is not finished, the name record is not written,
    /// and the index row is not added.
    #[tracing::instrument(skip(self, source), fields(backend = self.backend.name()))]
    pub async fn put_file_from_source<S>(
        &self,
        logical_path: &str,
        source: S,
        plaintext_len: u64,
        modified: Modified,
    ) -> Result<Streamed>
    where
        S: std::io::Read + std::io::Seek + Send + 'static,
    {
        let path = path::normalize(logical_path)?;
        // Capture any object this path currently maps to, for post-commit overwrite GC.
        let previous = self.lookup_object_key(&path).await?;

        // Resolved once, here, so the object's own metadata and the index record
        // state the same time. `Modified::Now` reads the clock on resolution, and
        // resolving it twice would seal one instant and index another.
        let modified_unix = modified.resolve();

        // ── Phase one, off the runtime: hash the source and build the framing. ──
        // A transient owned copy of the root for the blocking task: `LockedSecret`
        // is not `Clone`, so it is copied into a `Zeroizing<[u8; 32]>` that wipes
        // when the task returns.
        let root_key = Zeroizing::new(*self.root()?);
        let chunk_size = self.chunk_size;
        let meta_path = path.clone();
        let mut file = source;
        let planned = tokio::task::spawn_blocking(move || -> Result<Planned<S>> {
            let plan = PlannedSeal::prepare(
                &root_key,
                &mut file,
                plaintext_len,
                &Metadata::new(&meta_path).with_mtime(modified_unix),
                chunk_size,
            )?;
            Ok(Planned { plan, source: file })
        })
        .await
        .map_err(|e| task_failed("streaming seal", &e))??;

        let Planned { plan, mut source } = planned;
        // Read off the plan before it is moved into the sealing task: the key, the
        // length and the two digests are everything the rest of this function
        // needs, and taking them here is what lets the plan (which holds the DEK)
        // travel to the thread that uses it and be wiped there.
        let file_id = plan.file_id();
        let object_key = format!("{}{}", layout::OBJECT_KEY_PREFIX, hex::encode(file_id));
        // The plan's length rather than the argument: `prepare` is what the
        // header will actually claim, and the two must be the same number.
        let plaintext_len = plan.plaintext_len();
        let plaintext_hash = plan.content_blake3();
        tracing::debug!(
            object = %object_key,
            plaintext_len,
            object_len = plan.object_len(),
            "sealed object planned (streamed, no spool)"
        );

        // ── Phase two: the sealer and the backend run at the same time, with the
        //    pipe's depth deciding how far ahead the sealer may get. ──
        let (mut writer, stream) = dctl_store::object_stream(plan.object_len(), HashAlgo::Blake3);
        let sealing = tokio::task::spawn_blocking(move || -> Result<()> {
            match plan.emit(&mut source, &mut writer) {
                Ok(()) => {
                    // The terminal message carries the digest of everything
                    // written, which is what the backend compares its own fold
                    // against before it commits anything.
                    writer.finish().map_err(io_err)?;
                    Ok(())
                }
                Err(e) => {
                    // Tell the consumer *why*, so the run reports the sealing
                    // failure rather than a stream that stopped early. Then return
                    // the original error, which is the one worth reporting if the
                    // backend has already given up for its own reasons.
                    writer.fail(e.to_string());
                    Err(e.into())
                }
            }
        });

        // No modification time on the provider's copy, for the reason `super::put`
        // states at length: the time is a fact about the plaintext, it is already
        // sealed inside the object's own metadata, and putting it in the bucket as
        // well would publish a per-file edit history in the clear.
        let stored = self
            .backend
            .put_stream(
                &ObjectKey::new(object_key.clone()),
                stream,
                SourceModified::unknown(),
            )
            .await;

        // Joined either way. A backend that failed has dropped the stream, which
        // closes the channel, which stops the sealer at its next window — so this
        // is a wait for a task that is already finishing rather than a hang. When
        // both went wrong the *sealer's* reason is the better one: it is upstream,
        // and the backend's complaint will be a consequence of it.
        let sealed = sealing
            .await
            .map_err(|e| task_failed("streaming seal", &e))?;
        sealed?;
        stored?;
        tracing::debug!(object = %object_key, "verified streaming write to backend complete");

        // Authoritative §5 name record: path → file_id (same as the buffered path).
        let (name_key, name_val) =
            self.name_keys
                .seal_record(&self.vault_id, &path, &file_id, 0)?;
        let name_expected = ContentHash::blake3(&name_val);
        self.backend
            .put(
                &ObjectKey::new(name_key),
                Bytes::from(name_val),
                &name_expected,
                SourceModified::unknown(),
            )
            .await?;

        // Commit the index record — this is what makes the file "stored".
        let record = Record {
            path: path.clone(),
            object_key: object_key.clone(),
            size: plaintext_len,
            modified_unix,
            content_hash: plaintext_hash.to_vec(),
        };
        self.index.put(&record)?;
        tracing::info!(object = %record.object_key, "file stored (streamed) and index committed");

        // Overwrite GC: the new mapping is durable, so delete the superseded object.
        self.gc_superseded_object(previous, &object_key).await;
        // The digest the index just committed, handed back rather than left to be
        // recomputed: see [`Streamed`] for why a second pass over the source would
        // be both slower and less truthful.
        Ok(Streamed {
            bytes: plaintext_len,
            plaintext_hash,
        })
    }
}

/// Report a `spawn_blocking` join failure as a backend error naming the stage.
fn task_failed(stage: &str, error: &tokio::task::JoinError) -> CoreError {
    CoreError::Store(dctl_store::StoreError::Backend(format!(
        "{stage} task failed: {error}"
    )))
}

/// Map a filesystem error into a [`CoreError`] without a dedicated I/O variant.
pub(super) fn io_err(e: std::io::Error) -> CoreError {
    CoreError::Store(dctl_store::StoreError::Io(e))
}
