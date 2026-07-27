//! Replacing one way into a vault without disturbing the others.
//!
//! This is the operation that makes several unwrap paths worth having. The root
//! key never changes — it cannot, because every object's DEK is wrapped to it —
//! so changing a password means rewriting *one slot* of the envelope and leaving
//! every other slot's bytes exactly as they were.
//!
//! The alternative, and the mistake this file exists to make impossible, is to
//! re-create the envelope from the new password. That produces a vault with one
//! way in again, silently destroying the paper backup the owner is relying on;
//! nobody discovers it until the day the phrase is needed, which is the one day
//! it cannot be tested. `PLAN.md` §13.2 is explicit that the paths are
//! independent, and independence is a property of *this* function more than of
//! `init` — creating several paths is easy, keeping them is not.
//!
//! ## What "leaving the others alone" means precisely
//!
//! Non-password slots are carried through **byte-identical**, including slots of
//! a type this build does not understand. A device slot written by a newer DCTL
//! must survive a password change performed by an older one, because the
//! alternative is that routine maintenance on one machine locks another machine
//! out. The envelope is rewritten by a single verified `put` of one object, so a
//! failure leaves the previous envelope intact rather than a half-written one.

use bytes::Bytes;
use dctl_crypto::{constants, envelope, kdf};
use dctl_store::{ContentHash, ObjectKey};

use crate::error::{CoreError, Result};

use super::Vault;
use super::layout;

impl Vault {
    /// Replace the vault's password slot with one derived from `new_password`.
    ///
    /// The old password stops working immediately: every existing `slot_type = 1`
    /// slot is dropped and exactly one new one takes its place, so a change
    /// cannot leave the previous password quietly live beside the new one. Every
    /// other slot — the recovery-phrase slot above all — is untouched and still
    /// opens the vault afterwards.
    ///
    /// Requires an already-unlocked vault, which is the authorisation: holding a
    /// [`Vault`] means the root key was already recovered from *some* slot, so
    /// this is equally the "I recovered with my phrase, give me a working
    /// password again" path.
    ///
    /// # Errors
    /// * [`CoreError::Unlock`] if the envelope has gone missing or unparseable
    ///   between unlock and now — the same classification an unlock would give,
    ///   because it is the same fact about the same object.
    /// * A crypto failure from the KDF or the slot wrap, or a backend failure
    ///   from the verified write. In every case the stored envelope is the one
    ///   that was there before: the write is a single object `put` that either
    ///   verifies and lands or does not.
    pub async fn change_password(&self, new_password: &str) -> Result<()> {
        let key = ObjectKey::new(layout::ENVELOPE_OBJECT_KEY);
        let bytes = self
            .backend
            .get(&key)
            .await
            .map_err(|_| CoreError::Unlock)?;
        let stored = envelope::parse(&bytes).map_err(|_| CoreError::Unlock)?;

        // The vault id is folded into every slot's wrap AAD, so a rewrite that
        // used a fresh one would produce slots nothing could unwrap. Read it
        // back from the envelope rather than trusting the in-memory copy, and
        // refuse if they disagree: that combination means this handle and the
        // stored envelope are no longer the same vault.
        if stored.vault_id != self.vault_id {
            return Err(CoreError::Unlock);
        }

        // Today's shipped cost, not the one the old slot carried. A password
        // change writes a *new* slot, and a vault created years ago on a slower
        // machine should not hold this build's replacement down to that
        // machine's figure. Every other slot keeps its own, which is the whole
        // point of the parameters being per-slot.
        let cost = kdf::Cost::shipped();
        let salt = kdf::generate_salt();
        let kek = kdf::derive_kek(new_password, None, &salt, cost)?;
        let replacement = envelope::wrap_slot(
            &kek,
            self.root()?,
            &self.vault_id,
            constants::SLOT_TYPE_PASSWORD,
            constants::KDF_ID_ARGON2ID,
            cost.m_cost,
            cost.t_cost,
            cost.p_lanes,
            salt.to_vec(),
            Vec::new(),
        )?;

        // Position is preserved: the new slot sits where the first password slot
        // sat, and every other slot keeps its index. Nothing depends on slot
        // order, but an envelope that reshuffles itself on every password change
        // makes a byte-level diff useless for telling "one slot was replaced"
        // from "the whole thing was rewritten" — and that diff is exactly what a
        // reviewer of this code needs to look at.
        let mut replaced = false;
        let mut slots = Vec::with_capacity(stored.slots.len());
        for slot in stored.slots {
            if slot.slot_type != constants::SLOT_TYPE_PASSWORD {
                slots.push(slot);
            } else if !replaced {
                slots.push(replacement.clone());
                replaced = true;
            }
            // A second (or later) password slot is dropped: one password, one
            // slot, so that "change the password" cannot leave an old one live.
        }
        if !replaced {
            // A vault opened through its phrase alone may legitimately have no
            // password slot at all — this is how it gets one back.
            slots.push(replacement);
        }

        let rewritten = envelope::Envelope {
            vault_id: self.vault_id,
            slots,
        };
        let bytes = envelope::serialize(&rewritten)?;
        let expected = ContentHash::blake3(&bytes);
        self.backend
            .put(&key, Bytes::from(bytes), &expected)
            .await?;

        tracing::info!(
            backend = self.backend.name(),
            slots = rewritten.slots.len(),
            "password slot replaced (other slots untouched)"
        );
        Ok(())
    }
}
