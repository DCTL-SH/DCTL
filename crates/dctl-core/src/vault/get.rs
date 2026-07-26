//! `get_file` / `verify_file`: resolve → fetch → decrypt → self-describing integrity.
//!
//! Resolution prefers the local index but falls back to the backend's authoritative
//! §5 name record, so a file is readable on **any** device with only the password and
//! the shared backend — no prior local index required. Integrity is checked against
//! the object's **own** DEK-authenticated `content_blake3`, so it holds even when the
//! index carries no cached hash (e.g. right after a cross-device rebuild).

use dctl_crypto::{object, path};
use dctl_index::Record;
use dctl_store::{ContentHash, ObjectKey};
use zeroize::Zeroizing;

use super::{Vault, layout};
use crate::error::{CoreError, Result};

impl Vault {
    /// Resolve a normalized path to its backend object key.
    ///
    /// Tries the local index first; on a miss, reads the authoritative §5 name record
    /// from the backend — the cross-device path — and warms the index cache. A
    /// non-existent path (no name record) surfaces as [`CoreError::NotFound`].
    pub(super) async fn resolve_object_key(&self, nfc_path: &str) -> Result<String> {
        if let Some(record) = self.index.get(nfc_path)? {
            return Ok(record.object_key);
        }
        let name_key = self.name_keys.record_key(nfc_path);
        let value = self
            .backend
            .get(&ObjectKey::new(name_key.clone()))
            .await
            .map_err(|_| CoreError::NotFound(nfc_path.to_string()))?;
        let record = self
            .name_keys
            .open_record(&self.vault_id, &name_key, value.as_ref())
            .map_err(|_| CoreError::NotFound(nfc_path.to_string()))?;
        let object_key = format!(
            "{}{}",
            layout::OBJECT_KEY_PREFIX,
            hex::encode(record.file_id)
        );
        // Warm the local cache so `list` and later reads see it (size filled on read).
        let _ = self.index.put(&Record {
            path: nfc_path.to_string(),
            object_key: object_key.clone(),
            size: 0,
            modified_unix: None,
            content_hash: Vec::new(),
        });
        Ok(object_key)
    }

    /// Fetch and decrypt the file at `path`, verifying the plaintext against the
    /// object's own DEK-authenticated content hash. Returns the plaintext wiped-on-drop.
    #[tracing::instrument(skip(self), fields(backend = self.backend.name()))]
    pub async fn get_file(&self, path: &str) -> Result<Zeroizing<Vec<u8>>> {
        let path = path::normalize(path)?;
        let object_key = self.resolve_object_key(&path).await?;
        tracing::debug!(object = %object_key, "resolved object key");

        let object = self.backend.get(&ObjectKey::new(object_key)).await?;
        // The object self-describes its DEK + metadata; open under the vault root key.
        let opened = object::open(&self.root_key, &object)?;

        // Self-describing integrity: the object's metadata carries the plaintext hash,
        // DEK-authenticated, so this holds on any device with no index (object::open
        // already verified every chunk tag and meta.size == plaintext_len).
        if let Some(meta) = &opened.metadata {
            let got = ContentHash::blake3(opened.plaintext.as_slice());
            if got.bytes[..] != meta.content_blake3[..] {
                tracing::warn!(%path, "plaintext hash mismatch — integrity failure");
                return Err(CoreError::Integrity(path.clone()));
            }
        }
        tracing::debug!(
            bytes = opened.plaintext.len(),
            "decrypted and integrity-verified"
        );
        Ok(opened.plaintext)
    }

    /// Verify the integrity of the file at `path` without returning its contents.
    pub async fn verify_file(&self, path: &str) -> Result<()> {
        self.get_file(path).await.map(|_| ())
    }
}
