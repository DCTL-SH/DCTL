//! `put_file_from_path`: the constant-memory streaming store for huge files.
//!
//! Where [`Vault::put_file`](super::Vault::put_file) buffers the whole plaintext (and
//! seals it) in RAM, this path seals the source **straight from disk to a temp object**
//! with [`object::seal_stream`] and hands that temp file to the backend's streaming
//! [`put_from_path`](dctl_store::Backend::put_from_path). No stage ever holds the whole
//! file or the whole object in memory, so peak memory is `O(chunk_size)` regardless of
//! file size — the fix for the ~2×-file-size RAM blow-up on huge video.
//!
//! The store order is identical to the buffered path — object written+verified → §5 name
//! record → durable index commit — so success is reported only once the data is durably
//! and correctly stored.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use bytes::Bytes;
use dctl_crypto::constants::OBJECT_HEAD_LEN;
use dctl_crypto::object::{self, Metadata};
use dctl_crypto::path;
use dctl_index::Record;
use dctl_store::{ContentHash, HashAlgo, Hasher, ObjectKey, SourceModified};
use zeroize::Zeroizing;

use super::{Modified, Vault, layout};
use crate::error::{CoreError, Result};

/// Working-buffer size for the vault's constant-memory hashing passes over the temp
/// object and the source plaintext.
const STREAM_BUF_LEN: usize = 128 * 1024;

/// The product of sealing a source file to a temp object: the temp file (kept alive so
/// it is not deleted before the backend reads it), plus everything the caller needs to
/// key, verify, and index the object without touching the file body again.
struct Sealed {
    temp: tempfile::NamedTempFile,
    file_id: [u8; 16],
    /// BLAKE3 of the sealed object bytes — the verified-write `expected` for the backend.
    object_hash: ContentHash,
    plaintext_len: u64,
    /// BLAKE3 of the source plaintext — what the index caches (parity with `put_file`).
    plaintext_hash: Vec<u8>,
}

impl Vault {
    /// Store the file at `source` under the logical `logical_path`, streaming with
    /// constant (`O(chunk_size)`) memory — never buffering the whole file or object.
    ///
    /// Byte-for-byte equivalent to [`put_file`](Vault::put_file) for the same content:
    /// the resulting object decodes identically (same DSF1 framing via
    /// [`object::seal_stream`]), so a file stored here opens through the very same
    /// [`get_file`](Vault::get_file) path as a buffered put. The strict order — object
    /// written and verified, then the authoritative §5 name record, then the durable
    /// index commit — means success is never reported unless the data is correctly stored.
    ///
    /// `modified` is a required argument for the reason [`Modified`] gives, and it is
    /// **not** read from `source` here even though this path opens the file: `source` is
    /// frequently a spool of something that has no modification time of its own (a pipe
    /// captured by `dctl rcat`), and taking the temporary file's time would record the
    /// moment of the spool while looking exactly like a real answer.
    #[tracing::instrument(skip(self), fields(backend = self.backend.name()))]
    pub async fn put_file_from_path(
        &self,
        logical_path: &str,
        source: &Path,
        modified: Modified,
    ) -> Result<()> {
        let path = path::normalize(logical_path)?;
        // Capture any object this path currently maps to, for post-commit overwrite GC.
        let previous = self.lookup_object_key(&path).await?;

        // Resolved once, here, so the object's own metadata and the index record
        // state the same time. `Modified::Now` reads the clock on resolution, and
        // resolving it twice would seal one instant and index another.
        let modified_unix = modified.resolve();

        // Seal the source straight to a temp object off the async runtime (heavy CPU +
        // blocking file I/O). Everything here is O(chunk_size)/O(buffer) memory.
        // A transient owned copy for the blocking sealer: `LockedSecret` is not `Clone`,
        // so the root is copied into a `Zeroizing<[u8; 32]>` that wipes when the task
        // returns. `seal_source_to_temp` still takes `&Zeroizing<[u8; 32]>`.
        let root_key = Zeroizing::new(*self.root()?);
        let chunk_size = self.chunk_size;
        let source = source.to_path_buf();
        let meta_path = path.clone();
        let sealed = tokio::task::spawn_blocking(move || -> Result<Sealed> {
            seal_source_to_temp(&root_key, &source, chunk_size, &meta_path, modified_unix)
        })
        .await
        .map_err(|e| {
            CoreError::Store(dctl_store::StoreError::Backend(format!(
                "streaming seal task failed: {e}"
            )))
        })??;

        let object_key = format!(
            "{}{}",
            layout::OBJECT_KEY_PREFIX,
            hex::encode(sealed.file_id)
        );
        tracing::debug!(object = %object_key, plaintext_len = sealed.plaintext_len, "sealed object (streamed)");

        // Verified streaming write of the content object: the backend copies the temp
        // file into place and confirms the on-disk bytes hash to `object_hash`.
        //
        // No modification time on the provider's copy, for the reason
        // `super::put` states at length: the time is a fact about the plaintext,
        // it is already sealed inside the object's own metadata, and putting it in
        // the bucket as well would publish a per-file edit history in the clear.
        self.backend
            .put_from_path(
                &ObjectKey::new(object_key.clone()),
                sealed.temp.path(),
                &sealed.object_hash,
                SourceModified::unknown(),
            )
            .await?;
        tracing::debug!(object = %object_key, "verified streaming write to backend complete");

        // Authoritative §5 name record: path → file_id (same as the buffered path).
        let (name_key, name_val) =
            self.name_keys
                .seal_record(&self.vault_id, &path, &sealed.file_id, 0)?;
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
            size: sealed.plaintext_len,
            modified_unix,
            content_hash: sealed.plaintext_hash,
        };
        self.index.put(&record)?;
        tracing::info!(object = %record.object_key, "file stored (streamed) and index committed");

        // Overwrite GC: the new mapping is durable, so delete the superseded object.
        self.gc_superseded_object(previous, &object_key).await;
        Ok(())
    }
}

/// Seal `source` into a fresh temp object under `root_key`, computing everything the
/// caller needs without ever holding the whole file/object in memory.
///
/// Three constant-memory passes over file data: [`object::seal_stream`] streams the
/// source into the temp object (itself `O(chunk_size)`), then the temp object is streamed
/// once to hash it (verified-write `expected`), then the source is streamed once to hash
/// the plaintext (index parity). Peak memory is a single working buffer plus the sealer's.
fn seal_source_to_temp(
    root_key: &Zeroizing<[u8; 32]>,
    source: &Path,
    chunk_size: u32,
    nfc_path: &str,
    modified_unix: Option<i64>,
) -> Result<Sealed> {
    let mut src = std::fs::File::open(source).map_err(io_err)?;
    let plaintext_len = src.metadata().map_err(io_err)?.len();

    // Seal source (Read + Seek) → temp object, constant memory.
    let mut temp = tempfile::NamedTempFile::new().map_err(io_err)?;
    {
        let mut writer = std::io::BufWriter::with_capacity(STREAM_BUF_LEN, temp.as_file_mut());
        object::seal_stream(
            root_key,
            &mut src,
            plaintext_len,
            &Metadata::new(nfc_path).with_mtime(modified_unix),
            chunk_size,
            &mut writer,
        )?;
        writer.flush().map_err(io_err)?;
    }

    // file_id = bytes [52..68] of the sealed object — a 68-byte head read from the temp.
    let f = temp.as_file_mut();
    f.seek(SeekFrom::Start(0)).map_err(io_err)?;
    let mut head = [0u8; OBJECT_HEAD_LEN];
    f.read_exact(&mut head).map_err(io_err)?;
    let mut file_id = [0u8; 16];
    file_id.copy_from_slice(&head[52..68]);

    // object_hash = BLAKE3 of the whole sealed object, streamed (constant memory).
    f.seek(SeekFrom::Start(0)).map_err(io_err)?;
    let object_hash = hash_reader(f)?;

    // plaintext_hash = BLAKE3 of the source plaintext, streamed (constant memory).
    src.seek(SeekFrom::Start(0)).map_err(io_err)?;
    let plaintext_hash = hash_reader(&mut src)?.bytes;

    Ok(Sealed {
        temp,
        file_id,
        object_hash,
        plaintext_len,
        plaintext_hash,
    })
}

/// Stream `r` through a BLAKE3 [`Hasher`] in fixed-size blocks — constant memory.
fn hash_reader<R: Read>(r: &mut R) -> Result<ContentHash> {
    let mut hasher = Hasher::new(HashAlgo::Blake3);
    let mut buf = vec![0u8; STREAM_BUF_LEN];
    loop {
        let n = r.read(&mut buf).map_err(io_err)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize())
}

/// Map a filesystem error into a [`CoreError`] without a dedicated I/O variant.
pub(super) fn io_err(e: std::io::Error) -> CoreError {
    CoreError::Store(dctl_store::StoreError::Io(e))
}
