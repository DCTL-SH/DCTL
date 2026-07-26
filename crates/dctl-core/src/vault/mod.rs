//! The vault: unlock state + composed file operations.

mod get;
mod layout;
mod list;
mod put;
mod put_stream;
mod restore;

use std::path::Path;
use std::sync::Arc;

use bytes::Bytes;
use dctl_crypto::names::NameKeys;
use dctl_crypto::{constants, envelope, kdf, keys};
use dctl_index::Index;
use dctl_store::{Backend, ContentHash, ObjectKey};
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};

/// An unlocked vault over a storage backend.
pub struct Vault {
    backend: Arc<dyn Backend>,
    root_key: Zeroizing<[u8; 32]>,
    /// Name-layer sub-keys (§5) for the authoritative path→object records.
    name_keys: NameKeys,
    /// Vault id binding every envelope slot and name record to this vault.
    vault_id: [u8; constants::VAULT_ID_LEN],
    index: Index,
    chunk_size: u32,
}

impl Vault {
    /// Initialize a brand-new vault: generate a root key, wrap it in a single
    /// password slot of a `DKE1` envelope, and store that envelope in the backend.
    /// `index_path` is the local encrypted index database.
    pub async fn init(
        backend: Arc<dyn Backend>,
        index_path: &Path,
        password: &str,
    ) -> Result<Self> {
        let salt = kdf::generate_salt();
        let kek = kdf::derive_kek(password, None, &salt)?;
        let root_key = keys::generate_key();
        let vault_id = envelope::generate_vault_id();

        let slot = envelope::wrap_slot(
            &kek,
            &root_key,
            &vault_id,
            constants::SLOT_TYPE_PASSWORD,
            constants::KDF_ID_ARGON2ID,
            constants::DEFAULT_ARGON2_M_COST,
            constants::DEFAULT_ARGON2_T_COST,
            constants::DEFAULT_ARGON2_P_LANES,
            salt.to_vec(),
            Vec::new(),
        )?;
        let env = envelope::Envelope {
            vault_id,
            slots: vec![slot],
        };
        let bytes = envelope::serialize(&env)?;
        let expected = ContentHash::blake3(&bytes);
        backend
            .put(
                &ObjectKey::new(layout::ENVELOPE_OBJECT_KEY),
                Bytes::from(bytes),
                &expected,
            )
            .await?;
        tracing::info!(
            backend = backend.name(),
            "initialized vault (envelope written)"
        );

        Self::assemble(backend, &root_key, vault_id, index_path)
    }

    /// Unlock an existing vault by reading its envelope from the backend, then
    /// re-deriving the KEK for each password slot and unwrapping the root key. The
    /// first slot that unwraps wins; any failure surfaces as [`CoreError::Unlock`].
    pub async fn unlock(
        backend: Arc<dyn Backend>,
        index_path: &Path,
        password: &str,
    ) -> Result<Self> {
        let bytes = backend
            .get(&ObjectKey::new(layout::ENVELOPE_OBJECT_KEY))
            .await
            .map_err(|_| CoreError::Unlock)?;
        let env = envelope::parse(&bytes).map_err(|_| CoreError::Unlock)?;

        let mut recovered: Option<Zeroizing<[u8; 32]>> = None;
        for slot in &env.slots {
            // §8 skip rules: only attempt a slot this reader fully supports. An
            // unsupported slot_type/flags/wrap_algo/kdf_id is SKIPPED (try the others),
            // never a reason to reject the envelope — matching the frozen matrix and the
            // C reference decoder. (Crucially `flags` feeds the wrap AAD and the
            // commitment is flags-independent, so without this a future reserved-critical
            // flag slot would wrongly unlock here while conforming readers skip it.)
            if slot.slot_type != constants::SLOT_TYPE_PASSWORD
                || slot.flags != 0
                || slot.wrap_algo != constants::WRAP_ALGO_XCHACHA20_POLY1305
                || slot.kdf_id != constants::KDF_ID_ARGON2ID
            {
                continue;
            }
            // Re-derive the KEK from this slot's own stored KDF params + salt. A
            // corrupt/out-of-range param set fails validation → this slot is skipped.
            let Ok(kek) = kdf::derive_kek_with_params(
                password,
                None,
                &slot.salt,
                slot.m_cost,
                slot.t_cost,
                slot.p_lanes,
            ) else {
                continue;
            };
            if let Ok(root) = envelope::unwrap_slot(slot, &kek, &env.vault_id) {
                recovered = Some(root);
                break;
            }
        }
        let root_key = recovered.ok_or(CoreError::Unlock)?;
        tracing::info!(backend = backend.name(), "vault unlocked");

        Self::assemble(backend, &root_key, env.vault_id, index_path)
    }

    /// Common construction: derive sub-keys/name-keys and open the local index.
    fn assemble(
        backend: Arc<dyn Backend>,
        root_key: &[u8; 32],
        vault_id: [u8; constants::VAULT_ID_LEN],
        index_path: &Path,
    ) -> Result<Self> {
        let index_subkey = keys::derive_subkey(root_key, keys::INFO_INDEX)?;
        let index = Index::open(index_path, &index_subkey)?;
        let name_keys = NameKeys::derive(root_key)?;

        let mut root = Zeroizing::new([0u8; 32]);
        root.copy_from_slice(root_key);

        Ok(Self {
            backend,
            root_key: root,
            name_keys,
            vault_id,
            index,
            chunk_size: constants::DEFAULT_CHUNK_SIZE,
        })
    }
}
