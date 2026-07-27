//! The vault: unlock state + composed file operations.

mod get;
mod imported;
mod layout;
mod list;
mod put;
mod put_stream;
mod restore;
mod share;

use std::path::Path;
use std::sync::Arc;

use bytes::Bytes;
use dctl_crypto::names::NameKeys;
use dctl_crypto::{constants, envelope, kdf, kem, keys};
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
    /// The vault's own root-derived recipient identity (§12.4, `idx = 0`). It carries the
    /// private `(x_sk, dk)` needed to read `kem_id=1` objects sealed to this vault — the
    /// same trust level as `root_key`, which is already held here, and a pure
    /// deterministic function of it (no new persisted bytes).
    identity: kem::RecipientKeypair,
    /// Cached stable key-id of `identity` (§12.3) — the recipient-matching handle.
    identity_key_id: [u8; constants::KEY_ID_LEN],
    /// IMPORTED (non-root-derived) recipient keypairs loaded from the §13 `k/*` store on
    /// unlock. Together with the root-derived `identity` (§12.4, `idx=0`) these form the
    /// vault's **identity set**: an object sealed to ANY held identity opens (§12.5/§13).
    /// Each is offline-restorable from the vault root (its `DIK1` is root-sealed), so this
    /// set is a pure function of `{root, the k/* objects}` — no extra local secret state.
    imported: Vec<kem::RecipientKeypair>,
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

        let mut vault = Self::assemble(backend, &root_key, env.vault_id, index_path)?;
        // Load the §13 imported-key store into the identity set. An unreadable/unknown
        // entry is skipped (one-way door, §8) — it never fails the unlock.
        vault.imported = vault.load_imported_identities().await?;
        Ok(vault)
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

        // Root-derived recipient identity (§12.4). Deterministic in `root_key`, so every
        // device that unlocks the vault reproduces the same `key_id, x_pk, ek, dk`.
        let identity = kem::derive_recipient(root_key, constants::RECIP_IDX_DEFAULT)?;
        let identity_key_id = identity.key_id;

        let mut root = Zeroizing::new([0u8; 32]);
        root.copy_from_slice(root_key);

        Ok(Self {
            backend,
            root_key: root,
            name_keys,
            vault_id,
            index,
            chunk_size: constants::DEFAULT_CHUNK_SIZE,
            identity,
            identity_key_id,
            // Imported identities are loaded from the backend `k/*` store by `unlock`
            // (an async LIST/GET pass); a freshly `init`ed vault starts with none.
            imported: Vec::new(),
        })
    }

    /// Every recipient identity this vault holds (§12.5/§13): the root-derived `idx=0`
    /// identity **first**, then each valid imported `DIK1` in load order. The
    /// recipient-open paths try these in order and the first success wins.
    pub(super) fn all_identities(&self) -> impl Iterator<Item = &kem::RecipientKeypair> {
        std::iter::once(&self.identity).chain(self.imported.iter())
    }

    /// The stable key-ids of every identity in the vault's identity set (root-derived first,
    /// then each imported `DIK1`). Lets a host/test confirm which identities an unlocked
    /// vault holds (e.g. that an `import_keypair` survived a re-`unlock`).
    #[must_use]
    pub fn identity_key_ids(&self) -> Vec<[u8; constants::KEY_ID_LEN]> {
        self.all_identities().map(|k| k.key_id).collect()
    }

    /// The vault's own root-derived recipient **public** identity (§12.4). A writer seals
    /// `kem_id=1` objects to this `DRK1` so the owner can always recover them (§12.8); it
    /// is also what other vaults add to their recipient sets to share *to* this vault.
    #[must_use]
    pub fn identity(&self) -> &kem::Drk1Public {
        &self.identity.public
    }

    /// The stable 32-byte key-id of the vault's recipient identity (§12.3) — the
    /// self-certifying handle used to look this vault up in the `r/*` registry.
    #[must_use]
    pub fn identity_key_id(&self) -> [u8; constants::KEY_ID_LEN] {
        self.identity_key_id
    }
}
