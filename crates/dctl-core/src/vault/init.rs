//! Creating a vault, and every way back into it.
//!
//! A vault is one 32-byte root key that never changes. Everything a reader needs
//! — the index sub-key, the name keys, the recipient identity, every object's
//! wrapped DEK — is derived from it, so the root key *is* the dataset. The only
//! interesting question at creation time is therefore how many independent ways
//! out of the envelope that root key has.
//!
//! For a long time the answer here was **one**: a single password slot, and a
//! forgotten password meant permanent, total data loss with the ciphertext
//! sitting intact and unreadable on a provider that kept billing for it.
//! `PLAN.md` §13.2 calls key survival the #1 risk of a twenty-year tool and
//! promises several independent unwrap paths; `docs/FORMAT.md` §2 has carried
//! the multi-slot envelope that makes them possible since the format was frozen.
//! Nothing was missing except the second slot.
//!
//! So `init` writes **two**, and returns the recovery phrase to its caller:
//!
//! * a `slot_type = 1` **password** slot, `Argon2id(NFC(password), salt₁)`;
//! * a `slot_type = 2` **mnemonic** slot, `Argon2id(BIP39_seed(phrase), salt₂)`.
//!
//! Both wrap the same root key under different KEKs, with **independent random
//! salts**. Independent salts matter: a shared salt would tie the two KEKs to
//! one input and make the pair no stronger than the weaker half, which is
//! exactly the property the second slot exists to avoid.
//!
//! ## The phrase is returned, never stored
//!
//! [`NewVault::recovery_phrase`] is handed back once, wiped when the caller drops
//! it, and written nowhere DCTL can read. That is not an omission to be fixed
//! later — it is the property that makes the phrase worth having. A phrase the
//! tool could reprint is a phrase an attacker with the envelope could reprint,
//! and the envelope is on somebody else's disk by design. The consequence is
//! that whoever calls `init` is responsible for putting the phrase in front of a
//! human *before* it drops; a caller that ignores it has created a vault whose
//! second key nobody will ever know, which is why the field is on a
//! `#[must_use]` struct rather than an accessor somebody can forget to call.

use std::path::Path;
use std::sync::Arc;

use bytes::Bytes;
use dctl_crypto::{constants, envelope, kdf, keys};
use dctl_store::{Backend, ContentHash, ObjectKey};
use zeroize::Zeroizing;

use crate::error::Result;

use super::Vault;
use super::layout;

/// A freshly created vault and the recovery phrase that also opens it.
///
/// Returned as a struct rather than a bare [`Vault`] so that the phrase cannot
/// be produced and silently dropped: a caller has to name the field it wants,
/// and the compiler makes the other one visible while it does.
#[must_use = "the recovery phrase is issued once and stored nowhere; a caller \
              that drops it has created a vault whose second key nobody knows"]
pub struct NewVault {
    /// The unlocked vault, ready to use.
    pub vault: Vault,
    /// The BIP-39 recovery phrase for the mnemonic slot, wiped on drop.
    ///
    /// Show it to a human once. It is not recoverable from the vault, the
    /// envelope, or this process a moment later.
    pub recovery_phrase: Zeroizing<String>,
}

impl Vault {
    /// Initialize a brand-new vault: generate a root key, wrap it in **two**
    /// independent slots of a `DKE1` envelope — one for the password, one for a
    /// freshly generated BIP-39 recovery phrase — and store that envelope in the
    /// backend. `index_path` is the local encrypted index database.
    ///
    /// # Errors
    /// A KDF failure, a slot wrap failure, or a backend write that did not
    /// verify. Nothing partial is left behind: the envelope is a single object
    /// written by one verified `put`, so either both slots are on the store or
    /// neither is.
    pub async fn init(
        backend: Arc<dyn Backend>,
        index_path: &Path,
        password: &str,
    ) -> Result<NewVault> {
        let root_key = keys::generate_key();
        let vault_id = envelope::generate_vault_id();
        let recovery_phrase = kdf::generate_mnemonic()?;

        // Two salts, drawn independently. Reusing one would make both KEKs
        // functions of the same random value for no saving worth having.
        let password_salt = kdf::generate_salt();
        let phrase_salt = kdf::generate_salt();

        let password_kek = kdf::derive_kek(password, None, &password_salt)?;
        let phrase_kek = kdf::derive_kek_from_mnemonic(
            &recovery_phrase,
            &phrase_salt,
            constants::DEFAULT_ARGON2_M_COST,
            constants::DEFAULT_ARGON2_T_COST,
            constants::DEFAULT_ARGON2_P_LANES,
        )?;

        let slots = vec![
            wrap(
                &password_kek,
                &root_key,
                &vault_id,
                constants::SLOT_TYPE_PASSWORD,
                password_salt.to_vec(),
            )?,
            wrap(
                &phrase_kek,
                &root_key,
                &vault_id,
                constants::SLOT_TYPE_MNEMONIC,
                phrase_salt.to_vec(),
            )?,
        ];

        let env = envelope::Envelope { vault_id, slots };
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
            slots = env.slots.len(),
            "initialized vault (envelope written)"
        );

        let vault = Self::assemble(backend, &root_key, vault_id, index_path)?;
        Ok(NewVault {
            vault,
            recovery_phrase,
        })
    }
}

/// Wrap the root key into one Argon2id slot at the shipped cost parameters.
///
/// Both slots go through here so the recorded `m/t/p` can never differ between
/// them by accident — a mnemonic slot written at weaker parameters than the
/// password slot would quietly make the recovery path the cheapest thing to
/// attack, and nothing in the envelope would look wrong.
fn wrap(
    kek: &[u8; constants::KEY_LEN],
    root_key: &[u8; constants::KEY_LEN],
    vault_id: &[u8; constants::VAULT_ID_LEN],
    slot_type: u8,
    salt: Vec<u8>,
) -> Result<envelope::Slot> {
    Ok(envelope::wrap_slot(
        kek,
        root_key,
        vault_id,
        slot_type,
        constants::KDF_ID_ARGON2ID,
        constants::DEFAULT_ARGON2_M_COST,
        constants::DEFAULT_ARGON2_T_COST,
        constants::DEFAULT_ARGON2_P_LANES,
        salt,
        Vec::new(),
    )?)
}
