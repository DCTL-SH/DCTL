//! §12 asymmetric sharing / write-only backup + the §12.3 public recipient registry.
//!
//! [`Vault::put_file_shared`] seals a `kem_id=1` object readable by an explicit recipient
//! set **plus the vault's own identity** (the §12.8 owner-inclusion MUST, so the owner can
//! always recover a write-only backup). [`Vault::publish_identity`] and
//! [`Vault::fetch_recipient`] are the `r/<hex key_id>` `DRR1` registry: a self-certifying
//! trust anchor for discovering the `DRK1` bytes of an already-pinned `key_id`.
//!
//! DEFERRED (additive, not needed for the core round-trip):
// TODO(task-16-followup): §12.6 `DGS1` grant sidecar at `g/<hex file_id>` (add/remove
// recipients without re-uploading the object) and imported/external (non-root-derived)
// keypairs (the `k/*` reserved store).

use bytes::Bytes;
use dctl_crypto::constants::{DRK1_LEN, KEY_ID_LEN};
use dctl_crypto::object::{self, Metadata};
use dctl_crypto::{kem, path};
use dctl_index::Record;
use dctl_store::{ContentHash, ObjectKey};

use super::put::now_unix;
use super::{Vault, layout};
use crate::error::{CoreError, Result};

/// `DRR1` public-registry container (§12.3): `magic(4) ‖ version(1) ‖ reserved(1) ‖
/// pubkey_len(u16 LE) ‖ DRK1(1222) ‖ label_len(u16 LE) ‖ label`.
const DRR1_MAGIC: [u8; 4] = *b"DRR1";
const DRR1_VERSION: u8 = 0x01;
/// Fixed prefix length before the `DRK1`: `magic(4)+version(1)+reserved(1)+pubkey_len(2)`.
const DRR1_PREFIX_LEN: usize = 8;

impl Vault {
    /// Store `data` under the logical `logical_path` as a `kem_id=1` object (§12) readable
    /// by every key in `recipients` **and always by this vault itself**.
    ///
    /// The effective recipient set is `recipients` with the vault's own root-derived
    /// identity prepended and the whole list **deduplicated by `key_id`** (§12.5). Owner
    /// inclusion is enforced unconditionally — a `kem_id=1` object has no symmetric
    /// fallback, so per §12.8 the owner MUST be a recipient or a write-only backup would be
    /// unrecoverable. Passing the owner explicitly (or a duplicate recipient) is harmless:
    /// it collapses to a single wrap.
    ///
    /// Same durability ordering as [`put_file`](Vault::put_file): seal → verified object
    /// write → authoritative §5 name record → durable index commit → overwrite-GC of any
    /// superseded object. Success is never reported unless the data is durably stored.
    #[tracing::instrument(skip(self, data, recipients), fields(backend = self.backend.name(), bytes = data.len(), recipients = recipients.len()))]
    pub async fn put_file_shared(
        &self,
        logical_path: &str,
        data: &[u8],
        recipients: &[kem::Drk1Public],
    ) -> Result<()> {
        let path = path::normalize(logical_path)?;
        // Capture any object this path currently maps to, so an overwrite can GC the old
        // ciphertext after the replacement is durable (never orphan a prior version).
        let previous = self.lookup_object_key(&path).await?;

        // Build the recipient set: owner ALWAYS first (§12.8), then each distinct
        // recipient, deduplicated by key_id so no identity is wrapped twice.
        let mut set: Vec<kem::Drk1Public> = Vec::with_capacity(recipients.len() + 1);
        let mut seen: Vec<[u8; KEY_ID_LEN]> = Vec::with_capacity(recipients.len() + 1);
        set.push(self.identity.public.clone());
        seen.push(self.identity_key_id);
        for r in recipients {
            let id = r.key_id();
            if !seen.iter().any(|s| s == &id) {
                seen.push(id);
                set.push(r.clone());
            }
        }
        tracing::debug!(unique_recipients = set.len(), "sealing hybrid object");

        // Seal into a self-describing DSF1 `kem_id=1` object. The backend key is the
        // object's random file_id (bytes [52..68] of the head), path-independent.
        let obj =
            object::seal_to_recipients(&set, data, &Metadata::new(path.as_str()), self.chunk_size)?;
        if obj.len() < 68 {
            return Err(CoreError::Integrity(
                "sealed object shorter than head".into(),
            ));
        }
        let mut file_id = [0u8; 16];
        file_id.copy_from_slice(&obj[52..68]);
        let object_key = format!("{}{}", layout::OBJECT_KEY_PREFIX, hex::encode(file_id));
        tracing::debug!(object = %object_key, object_bytes = obj.len(), "sealed shared object");

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

        // Authoritative §5 name record: path → file_id (identical to `put_file`).
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
            object_key: object_key.clone(),
            size: data.len() as u64,
            modified_unix: now_unix(),
            content_hash: ContentHash::blake3(data).bytes,
        };
        self.index.put(&record)?;
        tracing::info!(object = %record.object_key, "shared file stored and index committed");

        // Overwrite GC: the new mapping is durable, so delete the superseded object.
        self.gc_superseded_object(previous, &object_key).await;
        Ok(())
    }

    /// Publish this vault's **public** recipient identity to the §12.3 registry at backend
    /// key `r/<hex key_id>` as an unencrypted `DRR1` container (public-key material needs
    /// no confidentiality). No secrets ever leave the vault: only the `DRK1` public bytes
    /// are written. A writer that already trusts this `key_id` out-of-band can then fetch
    /// the `DRK1` to seal objects to this vault.
    #[tracing::instrument(skip(self), fields(backend = self.backend.name()))]
    pub async fn publish_identity(&self) -> Result<()> {
        let drk1 = self.identity.public.encode();
        let mut out = Vec::with_capacity(DRR1_PREFIX_LEN + DRK1_LEN + 2);
        out.extend_from_slice(&DRR1_MAGIC);
        out.push(DRR1_VERSION);
        out.push(0x00); // reserved
        out.extend_from_slice(&(DRK1_LEN as u16).to_le_bytes()); // pubkey_len = 1222
        out.extend_from_slice(&drk1);
        out.extend_from_slice(&0u16.to_le_bytes()); // label_len = 0 (no advisory label)

        let key = format!(
            "{}{}",
            layout::RECIP_KEY_PREFIX,
            hex::encode(self.identity_key_id)
        );
        let expected = ContentHash::blake3(&out);
        self.backend
            .put(&ObjectKey::new(key), Bytes::from(out), &expected)
            .await?;
        tracing::info!("published recipient identity to registry");
        Ok(())
    }

    /// Fetch a recipient's public `DRK1` from the §12.3 registry at `r/<hex key_id>`.
    ///
    /// Parses the `DRR1` container and, as the NORMATIVE trust anchor, **recomputes the
    /// `key_id` from the decoded `DRK1` and requires it to equal the requested `key_id`**
    /// before returning. This makes the registry self-certifying: a hostile backend cannot
    /// substitute a different pubkey under a pinned `key_id` (any advisory label is
    /// ignored — selection is by `key_id`, never by label). An absent key, a malformed
    /// container, or a `key_id` mismatch all surface as an error.
    #[tracing::instrument(skip(self), fields(backend = self.backend.name()))]
    pub async fn fetch_recipient(&self, key_id: &[u8; KEY_ID_LEN]) -> Result<kem::Drk1Public> {
        let key = format!("{}{}", layout::RECIP_KEY_PREFIX, hex::encode(key_id));
        // Absent key ⇒ the backend get errors ⇒ CoreError::Store (self-describing).
        let value = self.backend.get(&ObjectKey::new(key)).await?;
        let bytes = value.as_ref();

        if bytes.len() < DRR1_PREFIX_LEN {
            return Err(registry_err("DRR1 truncated"));
        }
        if bytes[0..4] != DRR1_MAGIC {
            return Err(registry_err("bad DRR1 magic"));
        }
        if bytes[4] != DRR1_VERSION {
            return Err(registry_err("unsupported DRR1 version"));
        }
        if bytes[5] != 0x00 {
            return Err(registry_err("non-zero DRR1 reserved"));
        }
        let pubkey_len = u16::from_le_bytes([bytes[6], bytes[7]]) as usize;
        if pubkey_len != DRK1_LEN {
            return Err(registry_err("unexpected DRR1 pubkey_len"));
        }
        if bytes.len() < DRR1_PREFIX_LEN + DRK1_LEN + 2 {
            return Err(registry_err("DRR1 truncated (pubkey/label)"));
        }
        let drk1 = &bytes[DRR1_PREFIX_LEN..DRR1_PREFIX_LEN + DRK1_LEN];
        let public = kem::Drk1Public::decode(drk1)?;

        // Trust anchor (§12.3): the recomputed key_id MUST match the requested one.
        if &public.key_id() != key_id {
            return Err(registry_err(
                "registry DRK1 key_id does not match the requested key_id",
            ));
        }
        Ok(public)
    }
}

/// A malformed or non-self-certifying `DRR1` registry entry — treated as an integrity
/// failure of the fetched object.
fn registry_err(msg: &str) -> CoreError {
    CoreError::Integrity(msg.to_string())
}
