//! Full-object and byte-range reads.

use std::io::SeekFrom;

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use crate::error::{Result, StoreError};
use crate::model::{ByteRange, ObjectKey};

use super::LocalFs;

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
