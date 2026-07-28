//! `put_file`: normalize → seal self-describing object → verified write → name
//! record → durable index commit.

use bytes::Bytes;
use dctl_crypto::object::{self, Metadata};
use dctl_crypto::path;
use dctl_index::Record;
use dctl_store::{ContentHash, ObjectKey, SourceModified};

use crate::error::{CoreError, Result};

use super::{Modified, Vault, layout};

impl Vault {
    /// Store `data` under the logical `path`, recorded as last modified at
    /// `modified`.
    ///
    /// Order matters: the object is sealed, written to the backend with a verified
    /// write, its authoritative name record is written, and only then is the index
    /// record committed — so success is never reported unless the data is durably
    /// and correctly stored.
    ///
    /// `modified` describes the **content**, not this call. See [`Modified`] for
    /// why it is a required argument: the index used to stamp the clock here, and
    /// a record that describes the write can never be compared against the source
    /// the write was made from.
    #[tracing::instrument(skip(self, data), fields(backend = self.backend.name(), bytes = data.len()))]
    pub async fn put_file(&self, path: &str, data: &[u8], modified: Modified) -> Result<()> {
        let path = path::normalize(path)?;
        // Capture any object this path currently maps to, so an overwrite can GC the old
        // ciphertext after the replacement is durable (never orphan a prior version).
        let previous = self.lookup_object_key(&path).await?;

        // Resolved once, here, so the object's own metadata and the index record
        // state the same time. `Modified::Now` reads the clock on resolution, and
        // resolving it twice would seal one instant and index another.
        let modified_unix = modified.resolve();

        // Seal into a self-describing DSF1 object (embeds its own root-wrapped DEK
        // + encrypted metadata). The backend key is the object's random file_id.
        // The modification time goes *into the object*, not only into the index:
        // the index is a cache, and a fact that lives only in a cache is a fact a
        // rebuilt machine has lost.
        let obj = object::seal(
            self.root()?,
            data,
            &Metadata::new(path.as_str()).with_mtime(modified_unix),
            self.chunk_size,
        )?;
        if obj.len() < 68 {
            return Err(CoreError::Integrity(
                "sealed object shorter than head".into(),
            ));
        }
        let mut file_id = [0u8; 16];
        file_id.copy_from_slice(&obj[52..68]);
        let object_key = format!("{}{}", layout::OBJECT_KEY_PREFIX, hex::encode(file_id));
        tracing::debug!(object = %object_key, object_bytes = obj.len(), "sealed object");

        // Verified write of the content object.
        //
        // `SourceModified::unknown()`, and that is a security decision rather than
        // an omission. A file's modification time is a fact about the *plaintext*,
        // and this vault's whole claim is that nothing about the plaintext — name,
        // size pattern or age — reaches the provider. The time is sealed inside
        // the object's own encrypted metadata a few lines above, where a rebuild
        // can recover it and the provider cannot read it; writing it into the
        // bucket's user metadata as well would hand over a per-file edit history
        // in the clear, for free, to buy nothing DCTL does not already have.
        let expected = ContentHash::blake3(&obj);
        self.backend
            .put(
                &ObjectKey::new(object_key.clone()),
                Bytes::from(obj),
                &expected,
                SourceModified::unknown(),
            )
            .await?;
        tracing::debug!(object = %object_key, "verified write to backend complete");

        // Authoritative §5 name record: path → file_id. A small AEAD blob; a plain
        // verified put is fine (the value is self-authenticating on read).
        let (name_key, name_val) =
            self.name_keys
                .seal_record(&self.vault_id, &path, &file_id, 0)?;
        let name_expected = ContentHash::blake3(&name_val);
        self.backend
            .put(
                &ObjectKey::new(name_key),
                Bytes::from(name_val),
                &name_expected,
                SourceModified::unknown(),
            )
            .await?;

        // Commit the index record (this is what makes the file "stored").
        let record = Record {
            path: path.clone(),
            object_key: object_key.clone(),
            size: data.len() as u64,
            modified_unix,
            content_hash: ContentHash::blake3(data).bytes,
        };
        self.index.put(&record)?;
        tracing::info!(object = %record.object_key, "file stored and index committed");

        // Overwrite GC: the new mapping is durable, so delete the superseded object.
        self.gc_superseded_object(previous, &object_key).await;
        Ok(())
    }

    /// Delete the content object a path previously mapped to, once its replacement is
    /// durably stored (object + name record + index all committed). **Delete-last**, so a
    /// crash or failure here only leaks storage — it can never lose the live object. A
    /// no-op when the path is new or the object id is unchanged. A private tool must not
    /// leave a superseded version's ciphertext on the untrusted backend indefinitely.
    pub(super) async fn gc_superseded_object(&self, previous: Option<String>, current: &str) {
        if let Some(old) = previous {
            if old != current {
                if let Err(e) = self.backend.delete(&ObjectKey::new(old)).await {
                    tracing::warn!(error = %e, "failed to delete superseded object (storage leak)");
                }
            }
        }
    }
}
