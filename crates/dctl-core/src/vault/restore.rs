//! Cross-device restore: rebuild the local index from the backend's authoritative
//! §5 name records.
//!
//! Everything a read needs lives in the shared backend — the wrapped root (envelope),
//! the path→object map (`n/*` name records), and self-describing objects (`o/*`) that
//! embed their own DEK + metadata. So a wiped or brand-new device can recover the whole
//! vault with only the password: `unlock`, then [`Vault::rebuild_index`], and every
//! path is listable and readable. No other local state is ever required.

use dctl_index::Record;

use super::{Vault, layout};
use crate::error::Result;

impl Vault {
    /// Rebuild the local index by enumerating and decrypting every `n/*` name record
    /// in the backend (§5). Returns the number of files indexed.
    ///
    /// Idempotent — existing rows are overwritten with the authoritative mapping. A
    /// name record that cannot be decrypted (e.g. belongs to a different vault under a
    /// shared bucket) is skipped with a warning rather than aborting the rebuild.
    ///
    /// **Size, content hash and modification time are left unset**, because a rebuild
    /// stays a cheap, list-only pass: they live in the object bodies, and fetching them
    /// would turn a reconciliation into a full read of the dataset. This comment used
    /// to claim they "populate on first read of each file"; they do not — `cat`,
    /// `hashsum` and a whole `scrub` all leave the row exactly as unmeasured as they
    /// found it, and only storing the file again records them. Nothing that *matters*
    /// depends on the row: every read measures the object itself. What does depend on
    /// it is a restore's timestamps, which fall back to the time of the restore. See
    /// `docs/RESTORE_DRILL.md`.
    #[tracing::instrument(skip(self), fields(backend = self.backend.name()))]
    pub async fn rebuild_index(&self) -> Result<u64> {
        let mut cursor: Option<String> = None;
        let mut count: u64 = 0;
        loop {
            let page = self
                .backend
                .list_page(layout::NAME_KEY_PREFIX, cursor)
                .await?;
            for item in &page.items {
                let name_key = item.key.as_str();
                let value = self.backend.get(&item.key).await?;
                let record = match self.name_keys.open_record(
                    &self.vault_id,
                    name_key,
                    value.as_ref(),
                ) {
                    Ok(record) => record,
                    Err(e) => {
                        tracing::warn!(key = name_key, error = %e, "skipping unreadable name record");
                        continue;
                    }
                };
                let object_key = format!(
                    "{}{}",
                    layout::OBJECT_KEY_PREFIX,
                    hex::encode(record.file_id)
                );
                self.index.put(&Record {
                    path: record.path,
                    object_key,
                    size: 0,
                    modified_unix: None,
                    content_hash: Vec::new(),
                })?;
                count += 1;
            }
            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        tracing::info!(count, "rebuilt index from backend name records");
        Ok(count)
    }
}
