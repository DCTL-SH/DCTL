//! Turning one offered secret back into the root key.
//!
//! The envelope is a list of slots, each of which wraps the same root key under
//! a different KEK (`docs/FORMAT.md` §2). Unlocking is therefore not "check the
//! password" but "find a slot this secret can open" — and the secret decides
//! which slots are even worth trying.
//!
//! That is what [`UnlockKey`] is for. A password is tried against `slot_type = 1`
//! slots and a recovery phrase against `slot_type = 2` slots, and neither is ever
//! tried against the other. The pairing is not an optimisation: without it the
//! two unlock paths would collapse into one path with two names, and a caller
//! that handed a password to the recovery route would be told the recovery route
//! works when it has never been exercised.
//!
//! ## Why the loop skips rather than rejects
//!
//! A slot whose `slot_type`, `flags`, `wrap_algo` or `kdf_id` this build does not
//! understand is **skipped**, and the reader tries the others (§8). Rejecting the
//! whole envelope instead would mean a vault that gained a device slot on a newer
//! DCTL could no longer be opened by an older one — the exact failure a
//! self-delimiting slot list exists to prevent. The same applies to a slot whose
//! stored Argon2id parameters fall outside the mandatory ceilings: it is skipped
//! without the KDF ever running, so one corrupt slot cannot deny access while a
//! good one is sitting beside it.

use std::path::Path;
use std::sync::Arc;

use dctl_crypto::{constants, envelope, kdf};
use dctl_store::{Backend, ObjectKey};
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};

use super::Vault;
use super::layout;

/// The secret a caller is offering in exchange for the root key.
///
/// Deliberately an enum at the API boundary rather than two `&str` parameters or
/// two similarly-named functions: the caller states *what kind of secret this
/// is*, and the slot loop below can then be exhaustive over the kinds. When
/// `docs/FORMAT.md` §2's reserved device (`0`) and Shamir (`3`) slot types are
/// implemented they become variants here, and every call site is recompiled
/// against the new set instead of silently continuing to mean "password".
#[derive(Clone, Copy)]
pub enum UnlockKey<'a> {
    /// Something the user knows. Opens `slot_type = 1` (password) slots.
    Password(&'a str),
    /// The BIP-39 phrase issued once by [`Vault::init`](super::Vault::init).
    /// Opens `slot_type = 2` (mnemonic) slots, with no password involved at all.
    RecoveryPhrase(&'a str),
}

// Never derive Debug: both variants hold a secret in the clear, and a `{:?}` on
// any struct that ever contains one is a plaintext key in a log file.

impl UnlockKey<'_> {
    /// The slot type this secret can open.
    const fn slot_type(self) -> u8 {
        match self {
            Self::Password(_) => constants::SLOT_TYPE_PASSWORD,
            Self::RecoveryPhrase(_) => constants::SLOT_TYPE_MNEMONIC,
        }
    }

    /// Re-derive this slot's KEK from the slot's **own** stored salt and cost
    /// parameters, or `None` if this secret cannot open a slot of that shape.
    ///
    /// Reading the parameters back out of the slot — rather than assuming
    /// today's defaults — is what lets the cost be raised in a future build
    /// without stranding vaults written by this one. Out-of-range parameters and
    /// an unparseable phrase both yield `None`, so the caller skips the slot
    /// rather than aborting: another slot may still open the vault.
    fn derive_kek(self, slot: &envelope::Slot) -> Option<Zeroizing<[u8; constants::KEY_LEN]>> {
        if slot.slot_type != self.slot_type() {
            return None;
        }
        let cost = kdf::Cost {
            m_cost: slot.m_cost,
            t_cost: slot.t_cost,
            p_lanes: slot.p_lanes,
        };
        match self {
            Self::Password(password) => kdf::derive_kek(password, None, &slot.salt, cost).ok(),
            Self::RecoveryPhrase(phrase) => {
                kdf::derive_kek_from_mnemonic(phrase, &slot.salt, cost).ok()
            }
        }
    }
}

impl Vault {
    /// Unlock an existing vault by reading its envelope from the backend, then
    /// re-deriving a KEK for each slot `key` can open and unwrapping the root
    /// key. The first slot that unwraps wins; any failure surfaces as
    /// [`CoreError::Unlock`].
    ///
    /// A [`UnlockKey::RecoveryPhrase`] opens the vault with **no password
    /// involved at any point** — that is the whole promise of the mnemonic slot
    /// (`PLAN.md` §13.2), and the reason this takes a secret *kind* rather than
    /// a string.
    ///
    /// # Errors
    /// [`CoreError::Unlock`] when the envelope is there and either unparseable
    /// or holding no slot this secret opens. One error for both, deliberately:
    /// telling an attacker with the envelope which of them happened would say
    /// whether a given password was close, and the operator's next step ("check
    /// the secret, then check the envelope") is the same either way.
    ///
    /// [`CoreError::NoVault`] when there is **no envelope object**, and the
    /// underlying [`CoreError::Store`] error when the store could not be read at
    /// all. Neither used to be distinguished, and folding them in was not
    /// caution — it was a wrong answer. A plain remote has no envelope by
    /// definition, so `dctl index rebuild` on one reported *"wrong password or
    /// corrupted envelope"* and advised restoring `system/envelope.bin` from a
    /// replica: a file that cannot be there, a password that was never involved,
    /// and an operator sent to look for both (`docs/HANDOVER.md` §16.2). A
    /// permission error or a dead connection produced the same sentence.
    ///
    /// The constant-answer property is untouched. It protects a password from
    /// being probed against an envelope that exists; these two answers are about
    /// whether the store has one and whether it can be read, which anyone who
    /// can reach the store can see without asking DCTL.
    pub async fn unlock(
        backend: Arc<dyn Backend>,
        index_path: &Path,
        key: UnlockKey<'_>,
    ) -> Result<Self> {
        let bytes = backend
            .get(&ObjectKey::new(layout::ENVELOPE_OBJECT_KEY))
            .await
            .map_err(|source| match source {
                dctl_store::StoreError::NotFound(_) => {
                    CoreError::NoVault(layout::ENVELOPE_OBJECT_KEY.to_string())
                }
                other => CoreError::Store(other),
            })?;
        let env = envelope::parse(&bytes).map_err(|_| CoreError::Unlock)?;

        let mut recovered: Option<Zeroizing<[u8; 32]>> = None;
        for slot in &env.slots {
            // §8 skip rules: only attempt a slot this reader fully supports. An
            // unsupported flags/wrap_algo/kdf_id is SKIPPED (try the others),
            // never a reason to reject the envelope — matching the frozen matrix
            // and the C reference decoder. (Crucially `flags` feeds the wrap AAD
            // and the commitment is flags-independent, so without this a future
            // reserved-critical flag slot would wrongly unlock here while
            // conforming readers skip it.) The `slot_type` half of the rule is
            // enforced by `UnlockKey::derive_kek`, which pairs each secret with
            // the one slot type it may open.
            if slot.flags != 0
                || slot.wrap_algo != constants::WRAP_ALGO_XCHACHA20_POLY1305
                || slot.kdf_id != constants::KDF_ID_ARGON2ID
            {
                continue;
            }
            let Some(kek) = key.derive_kek(slot) else {
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
}
