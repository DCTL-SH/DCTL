//! `list` / `delete_file`.

use dctl_crypto::path;
use dctl_index::Record;
use dctl_store::ObjectKey;

use crate::error::Result;

use super::Vault;

impl Vault {
    /// List records whose logical path starts with `prefix`, sorted by path.
    ///
    /// Reads the **whole** index, which is the right cost for a question about
    /// a whole subtree — a recursive listing, a scrub, a size — and the wrong
    /// one for a question about a single directory. [`children`](Vault::children)
    /// is that one, and a `readdir` must use it: this function's cost does not
    /// fall when the prefix narrows, because the row key is a keyed hash and the
    /// rows cannot be sought or stopped early. Measured on 100,000 files, a
    /// prefix matching *nothing* cost 755 ms here, the same as one matching
    /// everything.
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

    /// The files sitting directly in `dir`, sorted by path.
    ///
    /// One indexed lookup on the directory's hash, so the work is the directory's
    /// own width rather than the vault's size. The sort is over what came back —
    /// bounded by the directory — not over the index.
    ///
    /// # Errors
    /// Whatever the index reported.
    pub fn children(&self, dir: &str) -> Result<Vec<Record>> {
        let mut out = Vec::new();
        self.index.children(dir, |record| {
            out.push(record);
            true
        })?;
        out.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(out)
    }

    /// The directories sitting directly in `dir`, sorted by path.
    ///
    /// A vault stores no directories, so each of these exists because something
    /// is under it — which means none of them can list empty.
    ///
    /// # Errors
    /// Whatever the index reported.
    pub fn child_dirs(&self, dir: &str) -> Result<Vec<String>> {
        let mut out = Vec::new();
        self.index.child_dirs(dir, |path| {
            out.push(path);
            true
        })?;
        out.sort();
        Ok(out)
    }

    /// Whether anything is stored under the directory `dir`.
    ///
    /// # Errors
    /// Whatever the index reported.
    pub fn has_dir(&self, dir: &str) -> Result<bool> {
        Ok(self.index.contains_dir(dir)?)
    }

    /// What the whole vault holds, in one row read rather than a full scan.
    ///
    /// # Errors
    /// Whatever the index reported.
    pub fn totals(&self) -> Result<dctl_index::Totals> {
        Ok(self.index.totals()?)
    }

    /// Every content-object key the backend actually holds, as one set.
    ///
    /// The reconciliation primitive behind honest destination listings: the
    /// index says what *should* be stored, and this says what *is*. A row
    /// whose `object_key` is absent here is a file the vault will lose on
    /// restore, whatever the index believes — the defect this was built for
    /// reported `Checks: 150/150, Errors: 0` over exactly that damage.
    ///
    /// Keys only, paged exactly as [`rebuild_index`](Vault::rebuild_index)
    /// pages name records — one LIST request per provider page, no GETs, no
    /// payload bytes. Memory is O(object keys), the same order as the
    /// materialised `Vec<Record>` [`Vault::list`] already carries; a streaming
    /// merge-join can replace the set later without changing any call site.
    ///
    /// # Errors
    /// Whatever the backend's listing reported.
    #[tracing::instrument(skip(self), fields(backend = self.backend.name()))]
    pub async fn stored_object_keys(&self) -> Result<std::collections::HashSet<String>> {
        let mut keys = std::collections::HashSet::new();
        let mut cursor: Option<String> = None;
        loop {
            let page = self
                .backend
                .list_page(super::layout::OBJECT_KEY_PREFIX, cursor)
                .await?;
            for item in &page.items {
                keys.insert(item.key.as_str().to_string());
            }
            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        Ok(keys)
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
