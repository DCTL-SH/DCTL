//! Full-object and byte-range reads, plus the streaming download to a file.

use std::io::SeekFrom;
use std::path::Path;

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use crate::error::{Result, StoreError};
use crate::meter::Meter;
use crate::model::{ByteRange, ObjectKey};

use super::LocalFs;

/// Working-buffer size for the streaming download copy. Bounds peak memory to a
/// constant, independent of the object's size.
const STREAM_BUF_LEN: usize = 128 * 1024;

pub(super) async fn get(fs: &LocalFs, key: &ObjectKey) -> Result<Bytes> {
    let path = fs.resolve(key)?;
    match tokio::fs::read(&path).await {
        Ok(bytes) => Ok(Bytes::from(bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(StoreError::NotFound(key.to_string()))
        }
        Err(e) => Err(e.into()),
    }
}

pub(super) async fn get_range(fs: &LocalFs, key: &ObjectKey, range: ByteRange) -> Result<Bytes> {
    let path = fs.resolve(key)?;
    let mut file = match tokio::fs::File::open(&path).await {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(StoreError::NotFound(key.to_string()));
        }
        Err(e) => return Err(e.into()),
    };

    let size = file.metadata().await?.len();
    if range.offset > size {
        return Err(StoreError::RangeOutOfBounds { size });
    }
    let available = size - range.offset;
    let to_read = range.length.map_or(available, |len| len.min(available));

    file.seek(SeekFrom::Start(range.offset)).await?;
    let mut buf = vec![0u8; to_read as usize];
    file.read_exact(&mut buf).await?;
    Ok(Bytes::from(buf))
}

/// Streaming download: copy the object file at `key` to `dest` with a fixed buffer, so
/// peak memory is constant regardless of object size (the `LocalFs` override of
/// [`Backend::get_to_path`](crate::backend::Backend::get_to_path)). The blocking
/// filesystem work runs on a blocking thread so it never stalls the async runtime.
pub(super) async fn get_to_path(fs: &LocalFs, key: &ObjectKey, dest: &Path) -> Result<()> {
    let src = fs.resolve(key)?;
    let key = key.to_string();
    let dest = dest.to_path_buf();
    let meter = fs.meter();
    tokio::task::spawn_blocking(move || copy_streaming(&src, &dest, &key, meter.as_ref()))
        .await
        .map_err(|e| StoreError::Backend(format!("streaming download task failed: {e}")))?
}

/// Buffered copy of `src` → `dest`, constant memory. A missing source maps to
/// [`StoreError::NotFound`], matching [`get`].
///
/// An explicit loop rather than `std::io::copy` so every block can be declared
/// to `meter` as it lands — see [`crate::meter`] for why one opaque call is the
/// shape a rate limit cannot be applied to.
fn copy_streaming(src: &Path, dest: &Path, key: &str, meter: &dyn Meter) -> Result<()> {
    use std::io::Read as _;
    use std::io::Write as _;

    let file = match std::fs::File::open(src) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(StoreError::NotFound(key.to_string()));
        }
        Err(e) => return Err(e.into()),
    };
    let mut reader = std::io::BufReader::with_capacity(STREAM_BUF_LEN, file);
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut writer =
        std::io::BufWriter::with_capacity(STREAM_BUF_LEN, std::fs::File::create(dest)?);

    let mut buf = vec![0u8; STREAM_BUF_LEN];
    loop {
        let read = reader.read(&mut buf)?;
        if read == 0 {
            break;
        }
        writer.write_all(&buf[..read])?;
        crate::meter::charge_blocking(meter, read as u64);
    }

    let file = writer
        .into_inner()
        .map_err(std::io::IntoInnerError::into_error)?;
    file.sync_all()?;
    Ok(())
}
