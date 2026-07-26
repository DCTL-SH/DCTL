//! Atomic, verified write: temp file → fsync → read-back verify → atomic rename.
//!
//! Nothing is ever published unless the bytes on disk match the expected hash, and
//! a failure at any step leaves no partial or committed object.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use tokio::io::AsyncWriteExt;

use crate::checksum::ContentHash;
use crate::error::{Result, StoreError};
use crate::model::{ObjectKey, PutOutcome};

use super::LocalFs;

/// Monotonic counter making temp filenames unique for concurrent writers.
static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

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

/// A unique sibling temp path in the destination directory (same filesystem, so
/// the final rename is atomic).
fn temp_path(dest: &Path) -> PathBuf {
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let parent = dest
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    let name = dest.file_name().map_or_else(
        || "object".to_string(),
        |n| n.to_string_lossy().into_owned(),
    );
    parent.join(format!("{name}.tmp.{pid}.{seq}"))
}
