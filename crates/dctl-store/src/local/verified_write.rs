//! Atomic, verified write: temp file → fsync → read-back verify → atomic rename.
//!
//! Nothing is ever published unless the bytes on disk match the expected hash, and
//! a failure at any step leaves no partial or committed object.

use std::path::{Path, PathBuf};

use bytes::Bytes;
use tokio::io::AsyncWriteExt;

use crate::checksum::{ContentHash, HashAlgo, Hasher};
use crate::error::{Result, StoreError};
use crate::model::{ObjectKey, PutOutcome};

use super::LocalFs;

/// Working-buffer size for the streaming (from-path) verified write. Bounds peak
/// memory to a constant, independent of the source file's size.
const STREAM_BUF_LEN: usize = 128 * 1024;

pub(super) async fn put(
    fs: &LocalFs,
    key: &ObjectKey,
    data: Bytes,
    expected: &ContentHash,
) -> Result<PutOutcome> {
    let dest = fs.resolve(key)?;

    // Guard: the in-hand bytes must match the caller's declared hash.
    let computed = ContentHash::compute(expected.algo, &data);
    if !computed.matches(expected) {
        return Err(StoreError::ChecksumMismatch {
            expected: expected.hex(),
            actual: computed.hex(),
        });
    }

    if let Some(parent) = dest.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let tmp = temp_path(&dest);

    // Write the temp file and flush it to stable storage.
    {
        let mut file = tokio::fs::File::create(&tmp).await?;
        file.write_all(&data).await?;
        file.sync_all().await?;
    }

    // Read back exactly what hit the disk and verify before committing.
    let on_disk = match tokio::fs::read(&tmp).await {
        Ok(bytes) => ContentHash::compute(expected.algo, &bytes),
        Err(e) => {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(e.into());
        }
    };
    if !on_disk.matches(expected) {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(StoreError::ChecksumMismatch {
            expected: expected.hex(),
            actual: on_disk.hex(),
        });
    }

    // Atomically publish, then fsync the directory so the rename is durable.
    tokio::fs::rename(&tmp, &dest).await?;
    if let Some(parent) = dest.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }

    Ok(PutOutcome {
        size: data.len() as u64,
        verified: on_disk,
    })
}

/// Streaming verified write: copy the file at `source` to a temp sibling of `dest`,
/// read it back to confirm the on-disk bytes hash to `expected`, then atomically rename.
///
/// Never holds the whole file in memory — the copy and the read-back both work in
/// `STREAM_BUF_LEN` blocks, so peak memory is constant regardless of file size. Exactly
/// like [`put`], nothing is committed unless the bytes durably on disk match `expected`;
/// any mismatch or I/O error removes the temp and leaves no partial object. The blocking
/// filesystem work runs on a blocking thread so it never stalls the async runtime.
pub(super) async fn put_from_path(
    fs: &LocalFs,
    key: &ObjectKey,
    source: &Path,
    expected: &ContentHash,
) -> Result<PutOutcome> {
    let dest = fs.resolve(key)?;
    let source = source.to_path_buf();
    let expected = expected.clone();
    tokio::task::spawn_blocking(move || put_from_path_blocking(&dest, &source, &expected))
        .await
        .map_err(|e| StoreError::Backend(format!("streaming verified write task failed: {e}")))?
}

/// The blocking body of [`put_from_path`]: stream-copy → sync → stream-verify → rename.
fn put_from_path_blocking(
    dest: &Path,
    source: &Path,
    expected: &ContentHash,
) -> Result<PutOutcome> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = temp_path(dest);

    // Stream source → temp (buffered, constant memory) and flush to stable storage.
    if let Err(e) = stream_copy_to_temp(source, &tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }

    // Read back exactly what hit the disk and hash it — still constant memory.
    let (on_disk, size) = match hash_file(&tmp, expected.algo) {
        Ok(v) => v,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(e.into());
        }
    };
    if !on_disk.matches(expected) {
        let _ = std::fs::remove_file(&tmp);
        return Err(StoreError::ChecksumMismatch {
            expected: expected.hex(),
            actual: on_disk.hex(),
        });
    }

    // Atomically publish, then fsync the directory so the rename is durable.
    std::fs::rename(&tmp, dest)?;
    if let Some(parent) = dest.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }

    Ok(PutOutcome {
        size,
        verified: on_disk,
    })
}

/// Buffered copy of `source` → `tmp`, flushed and fsynced. Constant memory.
fn stream_copy_to_temp(source: &Path, tmp: &Path) -> std::io::Result<()> {
    let mut reader =
        std::io::BufReader::with_capacity(STREAM_BUF_LEN, std::fs::File::open(source)?);
    let writer = std::io::BufWriter::with_capacity(STREAM_BUF_LEN, std::fs::File::create(tmp)?);
    let mut writer = writer;
    std::io::copy(&mut reader, &mut writer)?;
    let file = writer
        .into_inner()
        .map_err(std::io::IntoInnerError::into_error)?;
    file.sync_all()?;
    Ok(())
}

/// Stream `path` through a [`Hasher`], returning its digest and byte count. Constant memory.
fn hash_file(path: &Path, algo: HashAlgo) -> std::io::Result<(ContentHash, u64)> {
    use std::io::Read as _;
    let mut f = std::fs::File::open(path)?;
    let mut hasher = Hasher::new(algo);
    let mut buf = vec![0u8; STREAM_BUF_LEN];
    let mut total: u64 = 0;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    Ok((hasher.finalize(), total))
}

/// A unique sibling staging path in the destination directory.
///
/// The naming rule — and the reason it no longer embeds the destination's own
/// name — lives in [`crate::staging`], because a spelling the writer invents and
/// the listing walk half-remembers is what made real files invisible.
fn temp_path(dest: &Path) -> PathBuf {
    crate::staging::staging_sibling(dest)
}
