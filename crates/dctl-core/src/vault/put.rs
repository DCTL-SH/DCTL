//! `put_file`: normalize → seal self-describing object → verified write → name
//! record → durable index commit.

use bytes::Bytes;
use dctl_crypto::object::{self, Metadata};
use dctl_crypto::path;
use dctl_index::Record;
use dctl_store::{ContentHash, ObjectKey};

use crate::error::{CoreError, Result};

use super::{Vault, layout};

impl Vault {
    /// Store `data` under the logical `path`.
    ///
    /// Order matters: the object is sealed, written to the backend with a verified
    /// write, its authoritative name record is written, and only then is the index
    /// record committed — so success is never reported unless the data is durably
    /// and correctly stored.
    #[tracing::instrument(skip(self, data), fields(backend = self.backend.name(), bytes = data.len()))]
    pub async fn put_file(&self, path: &str, data: &[u8]) -> Result<()> {
        let path = path::normalize(path)?;

        // Seal into a self-describing DSF1 object (embeds its own root-wrapped DEK
        // + encrypted metadata). The backend key is the object's random file_id.
        let obj = object::seal(
            &self.root_key,
            data,
            &Metadata::new(path.as_str()),
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
        let expected = ContentHash::blake3(&obj);
        self.backend
            .put(
                &ObjectKey::new(object_key.clone()),
                Bytes::from(obj),
                &expected,
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
            )
            .await?;

        // Commit the index record (this is what makes the file "stored").
        let record = Record {
            path: path.clone(),
            object_key,
            size: data.len() as u64,
            modified_unix: now_unix(),
            content_hash: ContentHash::blake3(data).bytes,
        };
        self.index.put(&record)?;
        tracing::info!(object = %record.object_key, "file stored and index committed");
        Ok(())
    }
}

/// Current unix time in seconds, if the clock is available.
fn now_unix() -> Option<i64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs() as i64)
}
