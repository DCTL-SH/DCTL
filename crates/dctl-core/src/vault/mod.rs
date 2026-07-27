//! The vault: unlock state + composed file operations.
//!
//! The three things that can happen to a vault's *key material* each own a file,
//! because they are the operations where a mistake is unrecoverable rather than
//! merely wrong: [`init`] creates the root key and every way back to it,
//! [`unlock`] turns one offered secret into that root key again, and [`rekey`]
//! replaces one way in without disturbing the others. Everything else in this
//! directory operates on a vault that is already open.

mod get;
mod imported;
mod init;
mod layout;
mod list;
mod put;
mod put_stream;
mod rekey;
mod restore;
mod share;
mod unlock;

use std::sync::Arc;

use dctl_crypto::names::NameKeys;
use dctl_crypto::{constants, kem, keys};
use dctl_index::Index;
use dctl_store::Backend;

use crate::error::{CoreError, Result};

pub use init::NewVault;
pub use unlock::UnlockKey;

/// An unlocked vault over a storage backend.
pub struct Vault {
    backend: Arc<dyn Backend>,
    /// The vault root key: a session-long-lived raw-byte secret, held in an
    /// `mlock`-pinned [`LockedSecret`](dctl_secmem::LockedSecret) (out of swap /
    /// crash-dumps, zeroized on drop). Read only through [`Self::root`].
    root_key: dctl_secmem::LockedSecret,
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
    /// Common construction: derive sub-keys/name-keys and open the local index.
    fn assemble(
        backend: Arc<dyn Backend>,
        root_key: &[u8; 32],
        vault_id: [u8; constants::VAULT_ID_LEN],
        index_path: &std::path::Path,
    ) -> Result<Self> {
        // Best-effort process hardening, once at vault open: on Apple release builds this
        // installs `PT_DENY_ATTACH` so a forensic actor cannot attach a debugger to dump
        // live key memory. A no-op off Apple and in debug builds; its unit return is
        // intentionally ignored (never fatal — see `dctl-secmem`).
        dctl_secmem::apple_harden_crash_reporter();

        let index_subkey = keys::derive_subkey(root_key, keys::INFO_INDEX)?;
        let index = Index::open(index_path, &index_subkey)?;
        let name_keys = NameKeys::derive(root_key)?;

        // Root-derived recipient identity (§12.4). Deterministic in `root_key`, so every
        // device that unlocks the vault reproduces the same `key_id, x_pk, ek, dk`.
        let identity = kem::derive_recipient(root_key, constants::RECIP_IDX_DEFAULT)?;
        let identity_key_id = identity.key_id;

        Ok(Self {
            backend,
            root_key: dctl_secmem::LockedSecret::from_slice(root_key),
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

    /// The vault root key as a fixed array. The [`LockedSecret`](dctl_secmem::LockedSecret)
    /// buffer is always 32 bytes by construction (`assemble` copies a `[u8; 32]`), so the
    /// conversion cannot fail; it is written fallibly to obey the crate's no-unwrap/panic
    /// rule rather than because a length mismatch is reachable.
    fn root(&self) -> Result<&[u8; 32]> {
        self.root_key
            .as_slice()
            .try_into()
            .map_err(|_| CoreError::Integrity("root key length invariant".into()))
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
