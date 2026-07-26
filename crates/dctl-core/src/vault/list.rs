//! `list` / `delete_file`.

use dctl_crypto::path;
use dctl_index::Record;
use dctl_store::ObjectKey;

use crate::error::Result;

use super::Vault;

impl Vault {
    /// List records whose logical path starts with `prefix`, sorted by path.
    ///
    /// Enumerates the local index (constant-memory streaming under the hood); the
    /// returned `Vec` is materialized for caller convenience.
    pub fn list(&self, prefix: &str) -> Result<Vec<Record>> {
        let mut out = Vec::new();
        self.index.for_each(|record| {
            if record.path.starts_with(prefix) {
                out.push(record);
            }
            true
        })?;
        out.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(out)
    }

    /// Delete the file at `path`. Returns whether it existed. Removes the content
    /// object, then its §5 name record, then the index record.
    #[tracing::instrument(skip(self), fields(backend = self.backend.name()))]
    pub async fn delete_file(&self, path: &str) -> Result<bool> {
        let path = path::normalize(path)?;
        let Some(record) = self.index.get(&path)? else {
            tracing::debug!(%path, "delete: not present");
            return Ok(false);
        };
        self.backend
            .delete(&ObjectKey::new(record.object_key))
            .await?;
        // Remove the authoritative name record too, so a delete leaves nothing behind.
        let name_key = self.name_keys.record_key(&path);
        self.backend.delete(&ObjectKey::new(name_key)).await?;
        self.index.delete(&path)?;
        tracing::info!(%path, "deleted file, name record, and index record");
        Ok(true)
    }
}
