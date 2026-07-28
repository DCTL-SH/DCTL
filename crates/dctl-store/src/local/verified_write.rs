//! Atomic, verified write: temp file → fsync → read-back verify → stamp → atomic
//! rename.
//!
//! Nothing is ever published unless the bytes on disk match the expected hash, and
//! a failure at any step leaves no partial or committed object.
//!
//! ## Where the modification time is set, and why it is there
//!
//! On the **staging file, after the read-back verification and before the
//! rename**. A rename carries the inode across, so the object appears at its
//! final name already stamped — there is no window in which a listing could see
//! it with the write time, and no second `open` by name that could stamp
//! whatever a later lookup of that name finds.
//!
//! Doing it afterwards would also have to reopen a file that another process may
//! by then have replaced, and a failure at that point would leave a committed
//! object carrying the wrong time — which is invisible until the next `sync`
//! re-transfers it and nothing on either stream says why.
//!
//! ## Why the read-back is not allowed to be the first thing that notices
//!
//! Every step below that can fail is asked what went wrong, in the order the
//! steps happen, and the read-back verification is *last*. That ordering is the
//! fix for `docs/HANDOVER.md` §16.1, where it was the other way round: the
//! `tokio::fs::File` write path swallowed an `ENOSPC` (see [`crate::durable`]),
//! the read-back found a file that was empty, and DCTL told the operator
//! **`checksum mismatch: expected … got …`** with a hint blaming the provider or
//! the network for corrupting data. It was a full disk on the machine they were
//! sitting at.
//!
//! A hash comparison is only capable of one sentence — "these bytes are not
//! those bytes" — so it must never be the thing that diagnoses an I/O failure.
//! It is the last resort, after the write has been asked directly and after the
//! length has been checked, and by then a differing hash really does mean what
//! it says.

use std::path::{Path, PathBuf};

use bytes::Bytes;
use tokio::io::AsyncWriteExt;

use crate::checksum::{ContentHash, HashAlgo, Hasher};
use crate::error::{Result, StoreError};
use crate::meter::Meter;
use crate::model::{ObjectKey, PutOutcome};
use crate::modified::SourceModified;

use super::LocalFs;

/// Working-buffer size for the streaming (from-path) verified write. Bounds peak
/// memory to a constant, independent of the source file's size.
const STREAM_BUF_LEN: usize = 128 * 1024;

/// Stamp `path` with the writer's modification time, if there is one to set.
///
/// A failure is a real failure rather than a shrug. The bytes are correct at this
/// point, so it is tempting to publish anyway — but an object that silently kept
/// the write time is compared against its source on the next run, found to
/// differ, and transferred again, forever, with nothing to explain it. Refusing
/// the commit leaves the staging file to be cleaned up and reports the reason.
fn stamp(path: &Path, modified: SourceModified) -> std::io::Result<()> {
    let Some(when) = modified.system_time() else {
        return Ok(());
    };
    std::fs::File::options()
        .write(true)
        .open(path)?
        .set_times(std::fs::FileTimes::new().set_modified(when))
}

/// Write `data` into the staging file and put it on stable storage.
///
/// The two steps after `write_all` are [`crate::durable::finish`], and the
/// reason they are a named call rather than a bare `sync_all` is the whole of
/// that module's documentation: a `tokio::fs::File` defers its write errors, and
/// `sync_all` on its own consumes one without returning it. This function used
/// to be three inline lines ending in `file.sync_all().await?`, and an `ENOSPC`
/// went straight through it.
async fn write_staging(tmp: &Path, data: &[u8]) -> std::io::Result<()> {
    let mut file = tokio::fs::File::create(tmp).await?;
    file.write_all(data).await?;
    crate::durable::finish(&mut file).await
}

pub(super) async fn put(
    fs: &LocalFs,
    key: &ObjectKey,
    data: Bytes,
    expected: &ContentHash,
    modified: SourceModified,
) -> Result<PutOutcome> {
    // Before anything else: the store this write was addressed to must still be
    // the store this backend opened. `create_dir_all` below will happily
    // re-create a root that was renamed away, and every stage after it —
    // including the read-back — then agrees with itself about a directory that
    // belongs to nobody. See `super::root`.
    fs.require_same_root()?;

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

    // Write the temp file and put it on stable storage, asking the write itself
    // what went wrong. The staging file is removed on the way out: a write that
    // ran out of space and left its half-written temp behind has taken the space
    // the retry needs, and a full disk stays full for reasons DCTL created.
    if let Err(e) = write_staging(&tmp, &data).await {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(e.into());
    }

    // Read back exactly what hit the disk and verify before committing.
    let bytes = match tokio::fs::read(&tmp).await {
        Ok(bytes) => bytes,
        Err(e) => {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(e.into());
        }
    };
    // Length before content. A file that is shorter than what was written is a
    // write that stopped, not a file that was altered, and the two have opposite
    // remedies — see the module docs.
    if bytes.len() != data.len() {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(StoreError::ShortWrite {
            expected: data.len() as u64,
            actual: bytes.len() as u64,
        });
    }
    let on_disk = ContentHash::compute(expected.algo, &bytes);
    if !on_disk.matches(expected) {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(StoreError::ChecksumMismatch {
            expected: expected.hex(),
            actual: on_disk.hex(),
        });
    }

    // The writer's time, onto the inode that is about to be published.
    {
        let staging = tmp.clone();
        let stamped = tokio::task::spawn_blocking(move || stamp(&staging, modified))
            .await
            .map_err(|e| StoreError::Backend(format!("stamping task failed: {e}")))?;
        if let Err(e) = stamped {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(e.into());
        }
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
    modified: SourceModified,
) -> Result<PutOutcome> {
    // The same guard as `put`, on the streaming path, for the same reason: a
    // large-file transfer is the one most likely to still be running when
    // somebody moves the disk.
    fs.require_same_root()?;

    let dest = fs.resolve(key)?;
    let source = source.to_path_buf();
    let expected = expected.clone();
    // The meter goes with the work, not with the call: the copy loop runs on a
    // blocking thread, and that is the thread whose windows have to be paced.
    let meter = fs.meter();
    tokio::task::spawn_blocking(move || {
        put_from_path_blocking(&dest, &source, &expected, modified, meter.as_ref())
    })
    .await
    .map_err(|e| StoreError::Backend(format!("streaming verified write task failed: {e}")))?
}

/// The blocking body of [`put_from_path`]: stream-copy → sync → stream-verify →
/// stamp → rename.
fn put_from_path_blocking(
    dest: &Path,
    source: &Path,
    expected: &ContentHash,
    modified: SourceModified,
    meter: &dyn Meter,
) -> Result<PutOutcome> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = temp_path(dest);

    // Stream source → temp (buffered, constant memory) and flush to stable storage.
    // `std::fs` is synchronous, so a failed write is returned by the call that
    // made it — there is no deferred error to surface here, unlike the buffered
    // `put` above.
    let written = match stream_copy_to_temp(source, &tmp, meter) {
        Ok(n) => n,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(e.into());
        }
    };

    // Read back exactly what hit the disk and hash it — still constant memory.
    let (on_disk, size) = match hash_file(&tmp, expected.algo) {
        Ok(v) => v,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(e.into());
        }
    };
    // Length before content, for the reason in the module docs: a short file is
    // a write that stopped, and calling that a checksum mismatch points the
    // operator at their data instead of at their disk.
    if size != written {
        let _ = std::fs::remove_file(&tmp);
        return Err(StoreError::ShortWrite {
            expected: written,
            actual: size,
        });
    }
    if !on_disk.matches(expected) {
        let _ = std::fs::remove_file(&tmp);
        return Err(StoreError::ChecksumMismatch {
            expected: expected.hex(),
            actual: on_disk.hex(),
        });
    }

    // The writer's time, onto the inode that is about to be published.
    if let Err(e) = stamp(&tmp, modified) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
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
///
/// Returns the number of bytes handed to the filesystem, so the caller can hold
/// the file that came back to that number rather than inferring a failure from
/// its hash.
///
/// Written as an explicit loop rather than `std::io::copy` for one reason: every
/// block is declared to `meter` as it lands, which is what makes `--bwlimit`
/// apply *within* one enormous object instead of only between files. `io::copy`
/// has no seam to declare from, and a copy that hands the whole file over in one
/// opaque call is precisely the shape this crate had to lose.
fn stream_copy_to_temp(source: &Path, tmp: &Path, meter: &dyn Meter) -> std::io::Result<u64> {
    use std::io::Read as _;
    use std::io::Write as _;

    let mut reader =
        std::io::BufReader::with_capacity(STREAM_BUF_LEN, std::fs::File::open(source)?);
    let mut writer = std::io::BufWriter::with_capacity(STREAM_BUF_LEN, std::fs::File::create(tmp)?);

    let mut buf = vec![0u8; STREAM_BUF_LEN];
    let mut written: u64 = 0;
    loop {
        let read = reader.read(&mut buf)?;
        if read == 0 {
            break;
        }
        writer.write_all(&buf[..read])?;
        written += read as u64;
        // After the block is written, never before: the charge is a measurement,
        // and the pause it produces belongs between this window and the next.
        crate::meter::charge_blocking(meter, read as u64);
    }

    let file = writer
        .into_inner()
        .map_err(std::io::IntoInnerError::into_error)?;
    file.sync_all()?;
    Ok(written)
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
