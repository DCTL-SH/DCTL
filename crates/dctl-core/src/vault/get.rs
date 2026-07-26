//! `get_file` / `verify_file` and path→object resolution.
//!
//! Resolution ([`Vault::lookup_object_key`]) prefers the local index but falls back to
//! the backend's authoritative §5 name record, so a file is readable, verifiable, and
//! deletable on **any** device with only the password and the shared backend — no prior
//! local index required. Integrity is checked against the object's **own** DEK-
//! authenticated `content_blake3`, so it holds even with no local cache.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use dctl_crypto::object::{self, Metadata};
use dctl_crypto::path;
use dctl_store::{ContentHash, HashAlgo, Hasher, ObjectKey, StoreError};
use zeroize::Zeroizing;

use super::put_stream::io_err;
use super::{Vault, layout};
use crate::error::{CoreError, Result};

/// Working-buffer size for the streaming decrypt-to-disk copy.
const STREAM_BUF_LEN: usize = 128 * 1024;

/// Monotonic counter making the plaintext temp filename unique for concurrent readers.
static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

impl Vault {
    /// Resolve a normalized path to its backend object key, **without side effects**.
    ///
    /// Tries the local index, then the authoritative §5 name record (the cross-device
    /// path). `Ok(None)` means the path is present nowhere. Shared by read, verify,
    /// delete, and overwrite-GC so they agree on what "exists" means on any device.
    pub(super) async fn lookup_object_key(&self, nfc_path: &str) -> Result<Option<String>> {
        if let Some(record) = self.index.get(nfc_path)? {
            return Ok(Some(record.object_key));
        }
        let name_key = self.name_keys.record_key(nfc_path);
        let value = match self.backend.get(&ObjectKey::new(name_key.clone())).await {
            Ok(value) => value,
            Err(_) => return Ok(None),
        };
        match self
            .name_keys
            .open_record(&self.vault_id, &name_key, value.as_ref())
        {
            Ok(record) => Ok(Some(format!(
                "{}{}",
                layout::OBJECT_KEY_PREFIX,
                hex::encode(record.file_id)
            ))),
            Err(_) => Ok(None),
        }
    }

    /// Fetch and decrypt the file at `path`, verifying the plaintext against the object's
    /// own DEK-authenticated content hash. Returns the plaintext wiped-on-drop.
    ///
    /// Buffers the plaintext (its `Vec` return contract); for constant-memory reads of
    /// huge files use [`get_file_to_path`](Vault::get_file_to_path). `verify_file` is
    /// already constant-memory.
    #[tracing::instrument(skip(self), fields(backend = self.backend.name()))]
    pub async fn get_file(&self, path: &str) -> Result<Zeroizing<Vec<u8>>> {
        let path = path::normalize(path)?;
        let object_key = self
            .lookup_object_key(&path)
            .await?
            .ok_or_else(|| CoreError::NotFound(path.clone()))?;
        tracing::debug!(object = %object_key, "resolved object key");

        let object = self.backend.get(&ObjectKey::new(object_key)).await?;
        // The object self-describes its DEK + metadata; open under the vault root key.
        // `object::open` already verified every chunk tag and `meta.size == plaintext_len`.
        let opened = object::open(&self.root_key, &object)?;

        if let Some(meta) = &opened.metadata {
            let got = ContentHash::blake3(opened.plaintext.as_slice());
            if got.bytes[..] != meta.content_blake3[..] {
                tracing::warn!(%path, "plaintext hash mismatch — integrity failure");
                return Err(CoreError::Integrity(path.clone()));
            }
        }
        tracing::debug!(
            bytes = opened.plaintext.len(),
            "decrypted and integrity-verified"
        );
        Ok(opened.plaintext)
    }

    /// Fetch and decrypt the file at `logical_path` straight to the local file `dest`, at
    /// **`O(chunk_size)` memory end-to-end** — the constant-memory read that mirrors
    /// [`put_file_from_path`](Vault::put_file_from_path). Use this for huge media where
    /// [`get_file`](Vault::get_file)'s whole-plaintext `Vec` would blow up RAM.
    ///
    /// Pipeline: resolve `logical_path` → object key (local index, else the authoritative
    /// §5 name record, so it works cross-device with only the password) → stream the
    /// object to a temp file via [`get_to_path`](dctl_store::Backend::get_to_path) → open
    /// that temp with [`object::open_reader`], streaming plaintext into a temp sibling of
    /// `dest`, one chunk at a time. Memory is bounded by the chunk buffer plus the bounded
    /// object header; nothing ever holds the whole file. (On the `LocalFs` backend the
    /// object download is itself streamed; the remote backends still buffer that one stage
    /// pending their streaming-download follow-up, but the decrypt/verify/write stage is
    /// always `O(chunk_size)`.)
    ///
    /// **Integrity.** `open_reader` verifies every chunk's Poly1305 tag (and the footer);
    /// on top of that this folds a streaming BLAKE3 over the emitted plaintext and compares
    /// it to the object's own DEK-authenticated `content_blake3`, exactly as `get_file`
    /// does — a mismatch removes the temp and returns [`CoreError::Integrity`].
    ///
    /// **Atomicity.** Plaintext is written to a temp sibling of `dest`, fsynced, and only
    /// renamed onto `dest` once it fully decrypts and its hash matches — so a tamper,
    /// truncation, or I/O error leaves **no** `dest` file (and never a partial one).
    #[tracing::instrument(skip(self), fields(backend = self.backend.name()))]
    pub async fn get_file_to_path(&self, logical_path: &str, dest: &Path) -> Result<()> {
        let path = path::normalize(logical_path)?;
        let object_key = self
            .lookup_object_key(&path)
            .await?
            .ok_or_else(|| CoreError::NotFound(path.clone()))?;
        tracing::debug!(object = %object_key, "resolved object key");

        // Stream the ciphertext object to a temp file (constant memory on LocalFs).
        let obj_temp = tempfile::NamedTempFile::new().map_err(io_err)?;
        self.backend
            .get_to_path(&ObjectKey::new(object_key), obj_temp.path())
            .await?;

        // Decrypt the temp object → dest off the async runtime (blocking file I/O + CPU),
        // streaming with O(chunk_size) memory and an atomic write-then-rename onto `dest`.
        let root_key = self.root_key.clone();
        let dest = dest.to_path_buf();
        let err_path = path.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let out = decrypt_object_to_dest(&root_key, obj_temp.path(), &dest, &err_path);
            drop(obj_temp); // remove the temp object only after decrypt finished with it
            out
        })
        .await
        .map_err(|e| {
            CoreError::Store(StoreError::Backend(format!(
                "streaming read task failed: {e}"
            )))
        })??;
        tracing::info!(%path, "file decrypted (streamed) to destination");
        Ok(())
    }

    /// Verify the file at `path` end-to-end **without materializing its plaintext**:
    /// stream-decrypt to a sink so every chunk tag + footer is checked at O(chunk_size)
    /// plaintext memory (§9.1). A multi-GB object is verified without a multi-GB buffer.
    #[tracing::instrument(skip(self), fields(backend = self.backend.name()))]
    pub async fn verify_file(&self, path: &str) -> Result<()> {
        let path = path::normalize(path)?;
        let object_key = self
            .lookup_object_key(&path)
            .await?
            .ok_or_else(|| CoreError::NotFound(path.clone()))?;
        let object = self.backend.get(&ObjectKey::new(object_key)).await?;
        let mut sink = std::io::sink();
        object::open_stream(&self.root_key, &object, &mut sink)?;
        Ok(())
    }
}

/// Decrypt the temp object at `obj_path` under `root_key` straight to `dest`, atomically
/// and at constant memory. Streams plaintext into a temp sibling of `dest` (so the final
/// result is published by one rename), folding a BLAKE3 over the output to check it
/// against the object's own DEK-authenticated `content_blake3`. Any decrypt/integrity/I/O
/// failure removes the temp and leaves no `dest` file. `nfc_path` names the file only in
/// the [`CoreError::Integrity`] message.
fn decrypt_object_to_dest(
    root_key: &[u8; 32],
    obj_path: &Path,
    dest: &Path,
    nfc_path: &str,
) -> Result<()> {
    let mut obj = std::fs::File::open(obj_path).map_err(io_err)?;
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(io_err)?;
    }
    let dest_tmp = temp_sibling(dest);

    // Stream-decrypt object → dest_tmp, hashing the plaintext as it is written.
    let mut hasher = Hasher::new(HashAlgo::Blake3);
    let metadata = match stream_decrypt_to_tmp(root_key, &mut obj, &dest_tmp, &mut hasher) {
        Ok(md) => md,
        Err(e) => {
            let _ = std::fs::remove_file(&dest_tmp);
            return Err(e);
        }
    };

    // Integrity: the streamed plaintext hash must equal the object's own content hash.
    if let Some(md) = &metadata {
        let computed = hasher.finalize();
        if computed.bytes[..] != md.content_blake3[..] {
            let _ = std::fs::remove_file(&dest_tmp);
            tracing::warn!(path = %nfc_path, "plaintext hash mismatch — integrity failure");
            return Err(CoreError::Integrity(nfc_path.to_string()));
        }
    }

    // Publish atomically; nothing ever exposed a partial `dest`.
    if let Err(e) = std::fs::rename(&dest_tmp, dest) {
        let _ = std::fs::remove_file(&dest_tmp);
        return Err(io_err(e));
    }
    Ok(())
}

/// Open `obj` with [`object::open_reader`], writing plaintext to a fresh `dest_tmp` while
/// folding every emitted byte into `hasher`, then flush + fsync. Returns the object's
/// metadata. Kept separate from [`decrypt_object_to_dest`] so the `&mut hasher` borrow
/// ends here, leaving the caller free to `finalize` it.
fn stream_decrypt_to_tmp(
    root_key: &[u8; 32],
    obj: &mut std::fs::File,
    dest_tmp: &Path,
    hasher: &mut Hasher,
) -> Result<Option<Metadata>> {
    let file = std::fs::File::create(dest_tmp).map_err(io_err)?;
    let mut writer = HashingWriter {
        inner: std::io::BufWriter::with_capacity(STREAM_BUF_LEN, file),
        hasher,
    };
    let metadata = object::open_reader(root_key, obj, &mut writer)?;
    let file = writer
        .inner
        .into_inner()
        .map_err(|e| io_err(e.into_error()))?;
    file.sync_all().map_err(io_err)?;
    Ok(metadata)
}

/// A unique temp sibling of `dest` in the same directory, so the final publish is an
/// atomic same-filesystem rename.
fn temp_sibling(dest: &Path) -> PathBuf {
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let parent = dest
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    let name = dest
        .file_name()
        .map_or_else(|| "out".to_string(), |n| n.to_string_lossy().into_owned());
    parent.join(format!("{name}.dctl-tmp.{pid}.{seq}"))
}

/// A [`Write`] tee that folds every written byte into a [`Hasher`] before passing it to
/// the inner writer — lets the streaming decrypt compute the plaintext BLAKE3 in the same
/// pass it writes `dest`, with no extra buffer and no second read.
struct HashingWriter<'a, W: Write> {
    inner: W,
    hasher: &'a mut Hasher,
}

impl<W: Write> Write for HashingWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write_all(buf)?;
        self.hasher.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}
