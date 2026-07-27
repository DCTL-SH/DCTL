//! §13 imported-key store (`k/<hex key_id>`): hold external (non-root-derived) recipient
//! keypairs so the vault can also decrypt objects sealed to those identities.
//!
//! [`Vault::import_keypair`] generates a fresh external keypair and root-seals it as a
//! `DIK1`; [`Vault::import_keypair_material`] imports a caller-supplied keypair (e.g. one
//! shared out-of-band). Both do a **verified write** to `k/<hex key_id>`. On `unlock`,
//! [`Vault::load_imported_identities`] LISTs `k/*`, parses each `DIK1`, and returns the set
//! that joins the root-derived identity — skipping only content-invalid or absent entries
//! per the §8 one-way door, while a transient backend error propagates.

use bytes::Bytes;
use dctl_crypto::constants::KEY_ID_LEN;
use dctl_crypto::kem;
use dctl_store::{ContentHash, ObjectKey, StoreError};

use super::{Vault, layout};
use crate::error::Result;

impl Vault {
    /// Generate a fresh external recipient keypair, root-seal it as a §13 `DIK1`, and
    /// verified-write it to `k/<hex key_id>`. Returns the new identity's `key_id`.
    ///
    /// The in-memory identity set is refreshed on the next [`unlock`](Vault::unlock) (a
    /// `&self` method cannot mutate it); the sealed key is durable and root-restorable
    /// immediately. To seal objects to this identity a writer needs its public `DRK1`,
    /// obtainable by re-deriving from the same material or via the `r/*` registry.
    #[tracing::instrument(skip(self), fields(backend = self.backend.name()))]
    pub async fn import_keypair(&self) -> Result<[u8; KEY_ID_LEN]> {
        let keypair = kem::generate_external();
        self.import_keypair_material(&keypair).await
    }

    /// Import a caller-supplied external `keypair` into the §13 store: root-seal it as a
    /// `DIK1` and verified-write it to `k/<hex key_id>`. Returns its `key_id`. Idempotent by
    /// `key_id` — re-importing the same identity overwrites its (equally valid) container.
    #[tracing::instrument(skip(self, keypair), fields(backend = self.backend.name()))]
    pub async fn import_keypair_material(
        &self,
        keypair: &kem::RecipientKeypair,
    ) -> Result<[u8; KEY_ID_LEN]> {
        let key_id = keypair.key_id;
        let dik1 = kem::serialize_dik1(&self.root_key, keypair)?;
        let key = format!("{}{}", layout::IMPORTED_KEY_PREFIX, hex::encode(key_id));
        let expected = ContentHash::blake3(&dik1);
        self.backend
            .put(&ObjectKey::new(key), Bytes::from(dik1.to_vec()), &expected)
            .await?;
        tracing::info!(key_id = %hex::encode(key_id), "imported keypair sealed to k/*");
        Ok(key_id)
    }

    /// LIST `k/*`, parse each `DIK1` under the vault root, and return the valid imported
    /// identities (§13 load semantics). An entry is skipped — never fails the whole load —
    /// only for a CONTENT reason: it does not parse (unknown `version`/`hybrid_suite`, bad
    /// AEAD tag, failed self-consistency) or its recomputed `key_id` does not match the
    /// `k/<hex key_id>` path component (the §8 one-way door: a bad entry affects only itself).
    /// A TRANSIENT backend error (network/5xx/timeout) is NOT a content reason and PROPAGATES
    /// — otherwise the identity set would silently shrink on a blip (§13 keeps it a pure
    /// function of `{root, valid DIK1 objects}`).
    pub(super) async fn load_imported_identities(&self) -> Result<Vec<kem::RecipientKeypair>> {
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let page = self
                .backend
                .list_page(layout::IMPORTED_KEY_PREFIX, cursor)
                .await?;
            for item in &page.items {
                let key_str = item.key.as_str();
                let bytes = match self.backend.get(&item.key).await {
                    Ok(b) => b,
                    // TOCTOU: the entry was deleted between LIST and this GET → genuinely
                    // absent, skip it.
                    Err(StoreError::NotFound(_)) => {
                        tracing::debug!(key = key_str, "k/* entry vanished between list and get");
                        continue;
                    }
                    // Any OTHER StoreError is transient (B2/S3 map every non-404 to
                    // `Backend`/`Io`). Skipping it would silently DROP a legitimate imported
                    // identity, making the set depend on network luck instead of {root, valid
                    // DIK1s} (§13) — a retryable blip would surface later as a false, permanent
                    // "not a recipient" for a genuinely-owned object. Propagate and fail unlock.
                    Err(e) => return Err(e.into()),
                };
                match kem::parse_dik1(&self.root_key, bytes.as_ref()) {
                    Ok(keypair) => {
                        // §13: key_id MUST equal the "k/<hex key_id>" path component.
                        if key_matches_path(key_str, &keypair.key_id) {
                            out.push(keypair);
                        } else {
                            tracing::warn!(
                                key = key_str,
                                "skipping k/* entry: key_id != path component"
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!(key = key_str, error = %e, "skipping invalid DIK1 entry");
                    }
                }
            }
            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        tracing::info!(count = out.len(), "loaded imported identities from k/*");
        Ok(out)
    }
}

/// Whether the backend key `k/<hex>` names exactly this `key_id` (§13 path binding).
fn key_matches_path(key: &str, key_id: &[u8; KEY_ID_LEN]) -> bool {
    key.strip_prefix(layout::IMPORTED_KEY_PREFIX)
        .and_then(|hexpart| hex::decode(hexpart).ok())
        .is_some_and(|bytes| bytes == key_id[..])
}
