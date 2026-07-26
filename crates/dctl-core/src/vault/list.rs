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
    /// object, its §5 name record, and the index row — so a delete truly leaves nothing
    /// behind on the untrusted backend.
    ///
    /// Resolution goes through [`Vault::lookup_object_key`] (index → authoritative name
    /// record), so a delete works on a fresh/wiped device *before* any `rebuild_index`
    /// — symmetric with `get_file`. `Ok(false)` only when the path is present nowhere.
    #[tracing::instrument(skip(self), fields(backend = self.backend.name()))]
    pub async fn delete_file(&self, path: &str) -> Result<bool> {
        let path = path::normalize(path)?;
        let Some(object_key) = self.lookup_object_key(&path).await? else {
            tracing::debug!(%path, "delete: not present");
            return Ok(false);
        };
        self.backend.delete(&ObjectKey::new(object_key)).await?;
        let name_key = self.name_keys.record_key(&path);
        self.backend.delete(&ObjectKey::new(name_key)).await?;
        self.index.delete(&path)?;
        tracing::info!(%path, "deleted file, name record, and index record");
        Ok(true)
    }
}
