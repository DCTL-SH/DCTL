//! §12 asymmetric sharing / write-only backup + the §12.3 public recipient registry.
//!
//! [`Vault::put_file_shared`] seals a `kem_id=1` object readable by an explicit recipient
//! set **plus the vault's own identity** (the §12.8 owner-inclusion MUST, so the owner can
//! always recover a write-only backup). [`Vault::publish_identity`] and
//! [`Vault::fetch_recipient`] are the `r/<hex key_id>` `DRR1` registry: a self-certifying
//! trust anchor for discovering the `DRK1` bytes of an already-pinned `key_id`.
//!
//! §12.6 grant sidecar: [`Vault::share_add_recipients`] and
//! [`Vault::share_remove_recipient`] edit the recipient set of an already-uploaded
//! `kem_id=1` object by rewriting a small `DGS1` object at `g/<hex file_id>` — never
//! re-uploading the (multi-GB) payload.
//!
//! DEFERRED (additive, not needed for the core round-trip):
// TODO(task-16-followup): imported/external (non-root-derived) keypairs (the `k/*`
// reserved store).

use bytes::Bytes;
use dctl_crypto::constants::{
    DRK1_LEN, FILE_ID_LEN, KEM_ID_HYBRID, KEY_ID_LEN, MAX_GRANT_COUNT, OBJECT_HEAD_LEN,
};
use dctl_crypto::object::{self, Metadata};
use dctl_crypto::{kem, path};
use dctl_index::Record;
use dctl_store::{ByteRange, ContentHash, ObjectKey, StoreError};

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

    /// Add `recipients` to the read set of the already-uploaded object at `logical_path` by
    /// writing (or extending) its §12.6 grant sidecar at `g/<file_id>` — WITHOUT
    /// re-uploading the object's (possibly multi-GB) payload.
    ///
    /// This vault must itself be able to recover the object's `KW` (as an inline recipient,
    /// or via an existing sidecar grant); it re-wraps that same `KW` to each new recipient
    /// as a §12.2 sub-record (fresh ephemeral + ML-KEM Encaps, bound to the exact object
    /// head, §12.1), appends the grants, bumps `grant_gen`, and verified-writes the sidecar.
    /// Recipients already present (inline or in the sidecar) and this vault's own identity
    /// are skipped (dedup by `key_id`). O(1) in the object size; a no-op if nothing is new.
    ///
    /// Guidance (§12.6): put durable recipients (owner, permanent backup key) INLINE at
    /// upload time — they cannot be removed without re-uploading — and put revocable
    /// recipients in the sidecar via this call.
    #[tracing::instrument(skip(self, recipients), fields(backend = self.backend.name(), recipients = recipients.len()))]
    pub async fn share_add_recipients(
        &self,
        logical_path: &str,
        recipients: &[kem::Drk1Public],
    ) -> Result<()> {
        let path = path::normalize(logical_path)?;
        let object_key = self
            .lookup_object_key(&path)
            .await?
            .ok_or_else(|| CoreError::NotFound(path.clone()))?;

        // Head + inline kem_wrap block (bounded range reads — never the whole payload).
        let (head_bytes, file_id, block) = self.fetch_head_and_block(&object_key).await?;

        // Read any existing sidecar (re-bound to THIS object) to extend it; else start fresh.
        let sidecar_key = ObjectKey::new(format!(
            "{}{}",
            layout::GRANT_KEY_PREFIX,
            hex::encode(file_id)
        ));
        let (mut grants, prev_gen) = match self.backend.get(&sidecar_key).await {
            Ok(b) => {
                let parsed = kem::sidecar::parse(b.as_ref(), &file_id, &head_bytes)?;
                (parsed.grants, parsed.grant_gen)
            }
            // Only a genuinely ABSENT sidecar (§12.6: "absent sidecar ⇒ not yet
            // extended") means "start fresh". Any other StoreError is transient
            // (B2/S3 map every non-404 to `Backend`/`Io`) and MUST propagate: if
            // swallowed here it would re-seal only the new recipients, roll
            // grant_gen back to 1, and verified-overwrite `g/<file_id>` — silently
            // revoking every previously-added sidecar recipient and violating §12.6
            // grant_gen monotonicity. A transient error aborts the share instead.
            Err(StoreError::NotFound(_)) => (Vec::new(), 0u64),
            Err(e) => return Err(e.into()),
        };

        // Recover KW: this vault must be an authorized reader (inline, else an existing grant).
        let kw = if let Some(kw) =
            kem::sidecar::recover_kw_from_block(&self.identity, &head_bytes, &block)?
        {
            kw
        } else if let Some(grant) = grants.iter().find(|g| g.key_id() == self.identity_key_id) {
            kem::sidecar::recover_kw_as_recipient(grant, &self.identity, &head_bytes)?
        } else {
            return Err(CoreError::Crypto(dctl_crypto::CryptoError::Format(
                "cannot share: this vault is not a recipient of the object".into(),
            )));
        };

        // Dedup set: inline recipients ∪ this vault's own identity ∪ existing sidecar grants.
        let mut present: Vec<[u8; KEY_ID_LEN]> = kem::sidecar::inline_key_ids(&block)?;
        present.push(self.identity_key_id);
        for g in &grants {
            present.push(g.key_id());
        }

        let mut added = 0usize;
        for r in recipients {
            let id = r.key_id();
            if present.iter().any(|p| p == &id) {
                continue; // already inline, already granted, or the owner itself
            }
            present.push(id);
            grants.push(kem::sidecar::seal_kw_to_recipient(&kw, r, &head_bytes)?);
            added += 1;
        }
        if added == 0 {
            tracing::debug!("share_add_recipients: nothing new to grant");
            return Ok(());
        }
        if grants.len() > MAX_GRANT_COUNT as usize {
            return Err(CoreError::Crypto(dctl_crypto::CryptoError::Format(
                "grant_count would exceed 4096".into(),
            )));
        }

        // Bump grant_gen (monotonic; higher wins on rewrite races) and verified-write.
        let grant_gen = prev_gen.checked_add(1).ok_or_else(|| {
            CoreError::Crypto(dctl_crypto::CryptoError::Format(
                "grant_gen overflow".into(),
            ))
        })?;
        let sidecar = kem::sidecar::serialize(&file_id, &head_bytes, grant_gen, &grants)?;
        let expected = ContentHash::blake3(&sidecar);
        self.backend
            .put(&sidecar_key, Bytes::from(sidecar), &expected)
            .await?;
        tracing::info!(added, grant_gen, "grant sidecar written");
        Ok(())
    }

    /// Remove the recipient `key_id` from the object's §12.6 grant sidecar, blocking its
    /// FUTURE `KW` recovery via the sidecar. Rewrites `g/<file_id>` omitting that grant and
    /// bumps `grant_gen`. Errors if the object has no sidecar or no grant for `key_id`.
    ///
    /// Caveats (§11/§12.6):
    /// - **Inline recipients cannot be removed this way.** A recipient wrapped inline at
    ///   upload time (owner, durable backup key) is part of the object body; dropping it
    ///   requires re-sealing under a fresh DEK (a full re-upload). This call only edits the
    ///   sidecar.
    /// - **Removal does not un-decrypt already-downloaded copies.** It blocks future access
    ///   via the sidecar but cannot revoke a copy an ex-recipient already fetched; true
    ///   revocation requires re-encrypting the payload under a fresh DEK.
    #[tracing::instrument(skip(self, key_id), fields(backend = self.backend.name()))]
    pub async fn share_remove_recipient(
        &self,
        logical_path: &str,
        key_id: &[u8; KEY_ID_LEN],
    ) -> Result<()> {
        let path = path::normalize(logical_path)?;
        let object_key = self
            .lookup_object_key(&path)
            .await?
            .ok_or_else(|| CoreError::NotFound(path.clone()))?;
        let (head_bytes, file_id, _block) = self.fetch_head_and_block(&object_key).await?;

        let sidecar_key = ObjectKey::new(format!(
            "{}{}",
            layout::GRANT_KEY_PREFIX,
            hex::encode(file_id)
        ));
        // A genuinely ABSENT sidecar ⇒ the grant is absent (nothing removable). Any
        // other StoreError is transient and MUST propagate rather than masquerade as
        // a permanent "no grant sidecar" — a 503 is not proof the grant is gone.
        let bytes = match self.backend.get(&sidecar_key).await {
            Ok(b) => b,
            Err(StoreError::NotFound(_)) => {
                return Err(CoreError::NotFound(format!("no grant sidecar for {path}")));
            }
            Err(e) => return Err(e.into()),
        };
        let parsed = kem::sidecar::parse(bytes.as_ref(), &file_id, &head_bytes)?;

        let mut grants = parsed.grants;
        let before = grants.len();
        grants.retain(|g| &g.key_id() != key_id);
        if grants.len() == before {
            return Err(CoreError::NotFound(format!(
                "no sidecar grant for the given key_id on {path}"
            )));
        }

        // Rewrite the sidecar omitting the grant, bumping grant_gen (§12.6). An empty
        // sidecar (G=0) with a higher grant_gen is intentionally kept rather than deleted,
        // so a replayed older sidecar cannot silently re-add the removed grant.
        let grant_gen = parsed.grant_gen.checked_add(1).ok_or_else(|| {
            CoreError::Crypto(dctl_crypto::CryptoError::Format(
                "grant_gen overflow".into(),
            ))
        })?;
        let sidecar = kem::sidecar::serialize(&file_id, &head_bytes, grant_gen, &grants)?;
        let expected = ContentHash::blake3(&sidecar);
        self.backend
            .put(&sidecar_key, Bytes::from(sidecar), &expected)
            .await?;
        tracing::info!(
            grant_gen,
            remaining = grants.len(),
            "grant removed from sidecar"
        );
        Ok(())
    }

    /// Fetch a `kem_id=1` object's fixed 68-byte head and its inline §12.2 `kem_wrap` block
    /// via BOUNDED range reads (never the payload), returning `(head_bytes, file_id, block)`.
    /// Rejects a non-hybrid object — only `kem_id=1` objects carry recipient grants.
    async fn fetch_head_and_block(
        &self,
        object_key: &str,
    ) -> Result<([u8; OBJECT_HEAD_LEN], [u8; FILE_ID_LEN], Vec<u8>)> {
        let key = ObjectKey::new(object_key.to_string());
        // Head (68) + kem_ct_len (2).
        let prefix = self
            .backend
            .get_range(&key, ByteRange::new(0, Some((OBJECT_HEAD_LEN + 2) as u64)))
            .await?;
        if prefix.len() < OBJECT_HEAD_LEN + 2 {
            return Err(CoreError::Integrity(
                "object truncated (head/kem_ct_len)".into(),
            ));
        }
        let head = object::parse_head(prefix.as_ref())?;
        if head.kem_id != KEM_ID_HYBRID {
            return Err(CoreError::Crypto(dctl_crypto::CryptoError::Format(
                "not a shared (kem_id=1) object — cannot add/remove recipients".into(),
            )));
        }
        let mut head_bytes = [0u8; OBJECT_HEAD_LEN];
        head_bytes.copy_from_slice(&prefix[0..OBJECT_HEAD_LEN]);
        let kem_ct_len =
            u16::from_le_bytes([prefix[OBJECT_HEAD_LEN], prefix[OBJECT_HEAD_LEN + 1]]) as usize;
        let block = self
            .backend
            .get_range(
                &key,
                ByteRange::new((OBJECT_HEAD_LEN + 2) as u64, Some(kem_ct_len as u64)),
            )
            .await?;
        if block.len() != kem_ct_len {
            return Err(CoreError::Integrity("object truncated (kem_wrap)".into()));
        }
        let mut file_id = [0u8; FILE_ID_LEN];
        file_id.copy_from_slice(&head_bytes[52..68]);
        Ok((head_bytes, file_id, block.to_vec()))
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
