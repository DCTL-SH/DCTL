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

    /// The index record for exactly `path`, if the vault holds one.
    ///
    /// A keyed lookup, not a filtered [`Vault::list`], and the difference is not
    /// cosmetic in either direction:
    ///
    /// * **Cost.** `list` enumerates every row in the index and keeps the ones
    ///   whose path starts with the prefix. Asking it for one path once is fine;
    ///   asking it once per file — which is what a download of a large tree does
    ///   when it wants each object's recorded modification time — is a full index
    ///   scan per file.
    /// * **Correctness.** `list` matches by byte prefix, so `a.txt` also reports
    ///   `a.txt.bak`. Callers wanting one object have to filter afterwards, and a
    ///   caller that forgets reads the wrong record.
    ///
    /// The path is normalized first, so a caller may spell it however the user
    /// did and still find what [`put_file`](Vault::put_file) stored.
    ///
    /// Answers from the **local index only** — no provider request, no download,
    /// and therefore `Ok(None)` on a device that has not yet rebuilt its index,
    /// even for an object the backend holds. Callers needing the authoritative
    /// answer resolve through the §5 name records instead
    /// ([`Vault::get_file`](Vault::get_file) does).
    pub fn record(&self, path: &str) -> Result<Option<Record>> {
        let path = path::normalize(path)?;
        Ok(self.index.get(&path)?)
    }

    /// Delete the file at `path`. Returns whether it existed. Removes the content
    /// object, its §5 name record, and the index row — so a delete truly leaves nothing
    /// behind on the untrusted backend.
    ///
    /// Resolution goes through `Vault::lookup_object_key` (index → authoritative name
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
