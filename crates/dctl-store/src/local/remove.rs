//! Object deletion (idempotent).

use crate::error::Result;
use crate::model::ObjectKey;

use super::LocalFs;

pub(super) async fn delete(fs: &LocalFs, key: &ObjectKey) -> Result<()> {
    let path = fs.resolve(key)?;
    match tokio::fs::remove_file(&path).await {
        Ok(()) => Ok(()),
        // Deleting a missing object is a no-op success (idempotent).
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}
