//! `get_file` / `verify_file` and path→object resolution.
//!
//! Resolution ([`Vault::lookup_object_key`]) prefers the local index but falls back to
//! the backend's authoritative §5 name record, so a file is readable, verifiable, and
//! deletable on **any** device with only the password and the shared backend — no prior
//! local index required. Integrity is checked against the object's **own** DEK-
//! authenticated `content_blake3`, so it holds even with no local cache.

use dctl_crypto::{object, path};
use dctl_store::{ContentHash, ObjectKey};
use zeroize::Zeroizing;

use super::{Vault, layout};
use crate::error::{CoreError, Result};

impl Vault {
    /// Resolve a normalized path to its backend object key, **without side effects**.
    ///
    /// Tries the local index, then the authoritative §5 name record (the cross-device
    /// path). `Ok(None)` means the path is present nowhere. Shared by read, verify,
    /// delete, and overwrite-GC so they agree on what "exists" means on any device.
    pub(super) async fn lookup_object_key(&self, nfc_path: &str) -> Result<Option<String>> {
        if let Some(record) = self.index.get(nfc_path)? {
            return Ok(Some(record.object_key));
        }
        let name_key = self.name_keys.record_key(nfc_path);
        let value = match self.backend.get(&ObjectKey::new(name_key.clone())).await {
            Ok(value) => value,
            Err(_) => return Ok(None),
        };
        match self
            .name_keys
            .open_record(&self.vault_id, &name_key, value.as_ref())
        {
            Ok(record) => Ok(Some(format!(
                "{}{}",
                layout::OBJECT_KEY_PREFIX,
                hex::encode(record.file_id)
            ))),
            Err(_) => Ok(None),
        }
    }

    /// Fetch and decrypt the file at `path`, verifying the plaintext against the object's
    /// own DEK-authenticated content hash. Returns the plaintext wiped-on-drop.
    ///
    /// Buffers the plaintext (its `Vec` return contract); for constant-memory reads of
    /// huge files use a streaming download (see task #17). `verify_file` is already
    /// constant-memory.
    #[tracing::instrument(skip(self), fields(backend = self.backend.name()))]
    pub async fn get_file(&self, path: &str) -> Result<Zeroizing<Vec<u8>>> {
        let path = path::normalize(path)?;
        let object_key = self
            .lookup_object_key(&path)
            .await?
            .ok_or_else(|| CoreError::NotFound(path.clone()))?;
        tracing::debug!(object = %object_key, "resolved object key");

        let object = self.backend.get(&ObjectKey::new(object_key)).await?;
        // The object self-describes its DEK + metadata; open under the vault root key.
        // `object::open` already verified every chunk tag and `meta.size == plaintext_len`.
        let opened = object::open(&self.root_key, &object)?;

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

    /// Verify the file at `path` end-to-end **without materializing its plaintext**:
    /// stream-decrypt to a sink so every chunk tag + footer is checked at O(chunk_size)
    /// plaintext memory (§9.1). A multi-GB object is verified without a multi-GB buffer.
    #[tracing::instrument(skip(self), fields(backend = self.backend.name()))]
    pub async fn verify_file(&self, path: &str) -> Result<()> {
        let path = path::normalize(path)?;
        let object_key = self
            .lookup_object_key(&path)
            .await?
            .ok_or_else(|| CoreError::NotFound(path.clone()))?;
        let object = self.backend.get(&ObjectKey::new(object_key)).await?;
        let mut sink = std::io::sink();
        object::open_stream(&self.root_key, &object, &mut sink)?;
        Ok(())
    }
}
