//! The two remotes that address one vault, written together or not at all.
//!
//! A vault has two views and needs both named:
//!
//! * **the sealed view** — `archive:` — through which everything is encrypted;
//! * **the object view** — `archive-store:` — the opaque ciphertext objects.
//!
//! The base gets a *name*, and that is the load-bearing decision. Because it is
//! named, an offsite replication job addressed at `archive-store:` copies
//! ciphertext provider-to-provider and needs **no vault password at all**: a
//! backup operator can satisfy 3-2-1 without ever holding decryption capability.
//! Separation of duties becomes a structural property of the configuration
//! rather than a rule somebody is trusted to follow. `PLAN.md` §13.3 requires
//! exactly this — replicating a vault's object tree with no re-encryption — and
//! it is unimplementable if the base has no name to type.
//!
//! ## Why the pair is a type
//!
//! Both `dctl init` and `dctl config import` produce it, and both have to obey
//! the same rule: **one save, both entries, or nothing.** A configuration naming
//! a vault whose base does not exist is worse than no configuration — it refuses
//! to load at all ([`ConfigError::UnknownBase`]), so the half-write does not
//! merely lose the store, it takes the vault's addressing with it and leaves an
//! operator with a file they must repair by hand before any command runs again.
//!
//! Atomicity itself belongs to [`super::save`], which stages and renames. What
//! this module guarantees is the step before: that the in-memory configuration
//! handed to it is *complete*, so a single save is all that is ever needed.
//! [`VaultPair::apply`] inserts both entries or returns an error having inserted
//! neither, and the caller saves once.

use super::error::{ConfigError, Result};
use super::model::{Config, RemoteDef, VaultDef};
use super::validate::validate_remote_name;

/// The sealed view and the object view of one vault, ready to be written.
///
/// Built by [`VaultPair::new`], which is where the names are checked and the
/// vault remote is derived from the store — so a caller cannot assemble a pair
/// whose vault points at a store it did not also bring.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultPair {
    /// Name of the sealed view: everything through it is encrypted.
    pub vault_name: String,
    /// Name of the object view: opaque ciphertext objects.
    pub store_name: String,
    /// The store remote's definition, carrying `require_vault`.
    pub store: RemoteDef,
    /// The vault remote's definition, wrapping [`VaultPair::store_name`].
    pub vault: RemoteDef,
}

impl VaultPair {
    /// Assemble the pair for a vault called `vault_name` over `store`.
    ///
    /// The store definition arrives already built from the base location, and
    /// this is where it is *marked*: [`crate::constants::CONFIG_KEY_REQUIRE_VAULT`] is set here
    /// rather than by each caller, so `init` and `import` cannot produce two
    /// different meanings of "the store remote DCTL created".
    ///
    /// `base_path` is the subdirectory of the store the vault occupies, and is
    /// carried through unchanged; `None` means the store's root, which is what
    /// every vault this build can create uses.
    ///
    /// # Errors
    /// Any rule [`validate_remote_name`] enforces, for either name — checked
    /// here so a name that cannot be typed is rejected before a vault is
    /// created rather than after — and [`ConfigError::DuplicateNameCase`] when
    /// the two names differ only in case, which would make one of them
    /// unreachable.
    pub fn new(
        vault_name: impl Into<String>,
        store_name: impl Into<String>,
        store: RemoteDef,
        base_path: Option<String>,
    ) -> Result<Self> {
        let vault_name = vault_name.into();
        let store_name = store_name.into();

        validate_remote_name(&vault_name)?;
        validate_remote_name(&store_name)?;

        // Caught here rather than by `validate` on save so the message arrives
        // before anything irreversible happens. Two names differing only in case
        // is always a typo, and one of the two views would be unaddressable on
        // any case-insensitive path a name travels.
        if vault_name.eq_ignore_ascii_case(&store_name) {
            return Err(ConfigError::DuplicateNameCase {
                first: vault_name,
                second: store_name,
            });
        }

        let store = mark_as_store(store);
        let vault = RemoteDef::Vault(VaultDef {
            base: store_name.clone(),
            base_path,
            // Left unset on purpose: a chunk size written today would freeze
            // a tuning decision a later release improves (`PLAN.md` §3).
            chunk_size: None,
            verify: None,
        });

        Ok(Self {
            vault_name,
            store_name,
            store,
            vault,
        })
    }

    /// Insert both entries into `config`, or neither.
    ///
    /// Collisions are checked for **both** names before either is inserted. The
    /// alternative — insert, discover, undo — is a rollback path that has to be
    /// right, and the way to make a rollback path right is not to need one.
    ///
    /// `force` replaces sections that already carry these names. It does not
    /// weaken any rule in [`super::validate`]: the caller still saves, and the
    /// save still refuses a configuration that would not load again.
    ///
    /// # Errors
    /// [`ConfigError::NameTaken`] for either name, when `force` is not set.
    pub fn apply(&self, config: &mut Config, force: bool) -> Result<()> {
        if !force {
            for name in [&self.vault_name, &self.store_name] {
                if config.contains(name) {
                    return Err(ConfigError::NameTaken { name: name.clone() });
                }
            }
        }

        // Store first, so that even a reader watching the in-memory value never
        // sees the vault without its base. The file only ever sees the finished
        // pair, but the ordering costs nothing and states the dependency.
        let _displaced_store = config.insert(self.store_name.clone(), self.store.clone());
        let _displaced_vault = config.insert(self.vault_name.clone(), self.vault.clone());
        Ok(())
    }
}

/// Set [`crate::constants::CONFIG_KEY_REQUIRE_VAULT`] on a store definition.
///
/// A `match` over every variant rather than a trait method with a default,
/// because "which providers can hold a vault's objects" is a question a new
/// provider must be made to answer: adding one that silently could not be marked
/// would produce a store remote the location rule never protects.
fn mark_as_store(store: RemoteDef) -> RemoteDef {
    match store {
        RemoteDef::Local(mut def) => {
            def.require_vault = true;
            RemoteDef::Local(def)
        }
        RemoteDef::B2(mut def) => {
            def.require_vault = true;
            RemoteDef::B2(def)
        }
        RemoteDef::S3(mut def) => {
            def.require_vault = true;
            RemoteDef::S3(def)
        }
        RemoteDef::R2(mut def) => {
            def.require_vault = true;
            RemoteDef::R2(def)
        }
        RemoteDef::Sftp(mut def) => {
            def.require_vault = true;
            RemoteDef::Sftp(def)
        }
        // Unreachable through `VaultPair::new`, whose callers build a store from
        // a location. Returned unchanged rather than panicking: a vault remote
        // has no location to declare, so there is nothing to mark, and
        // `validate` refuses the resulting chain on save anyway.
        vault @ RemoteDef::Vault(_) => vault,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::model::{B2Def, LocalDef};
    use crate::constants::MAX_REMOTE_NAME_LEN;
    use std::path::PathBuf;

    fn store() -> RemoteDef {
        RemoteDef::Local(LocalDef {
            path: PathBuf::from("/srv/vault"),
            verify: None,
            require_vault: false,
        })
    }

    fn pair() -> VaultPair {
        VaultPair::new("archive", "archive-store", store(), None).expect("a legal pair")
    }

    #[test]
    fn the_store_is_marked_and_the_vault_wraps_it() {
        let pair = pair();
        assert!(
            pair.store.require_vault(),
            "the store must declare its location vault-only, or the rule that \
             protects it never fires"
        );
        assert!(pair.vault.is_vault());
        assert_eq!(pair.vault.base(), Some("archive-store"));
        // The wrapper never claims a location of its own.
        assert!(!pair.vault.require_vault());
    }

    #[test]
    fn both_entries_land_in_one_configuration() {
        let mut config = Config::default();
        pair().apply(&mut config, false).expect("must apply");
        assert_eq!(config.len(), 2);
        assert!(config.contains("archive"));
        assert!(config.contains("archive-store"));
        // And the result is a configuration that would survive a save.
        assert!(super::super::validate::validate(&config).is_ok());
    }

    #[test]
    fn a_collision_on_either_name_inserts_nothing() {
        // The invariant the whole module exists for: never half a pair. A vault
        // written without its base makes the file refuse to load, so the failure
        // has to leave the configuration exactly as it was.
        for taken in ["archive", "archive-store"] {
            let mut config = Config::default();
            config.insert(
                taken,
                RemoteDef::B2(B2Def {
                    bucket: "unrelated".into(),
                    endpoint: None,
                    chunk_size: None,
                    verify: None,
                    require_vault: false,
                }),
            );
            let before = config.clone();

            let error = pair()
                .apply(&mut config, false)
                .expect_err("the taken name must be refused");
            assert!(
                matches!(error, ConfigError::NameTaken { ref name } if name == taken),
                "got {error}"
            );
            assert_eq!(config, before, "a refused apply must change nothing");
        }
    }

    #[test]
    fn force_replaces_both_sections() {
        let mut config = Config::default();
        config.insert("archive", store());
        pair().apply(&mut config, true).expect("must replace");
        assert_eq!(config.len(), 2);
        assert!(config.get("archive").is_some_and(RemoteDef::is_vault));
    }

    #[test]
    fn a_name_that_cannot_be_typed_is_refused_before_a_vault_is_created() {
        // Both names go through the same rules the file applies on load, and the
        // check happens here — before any envelope is written — because a vault
        // created and then found to be unaddressable is the expensive order.
        assert!(matches!(
            VaultPair::new("c", "c-store", store(), None),
            Err(ConfigError::NameTooShort { .. })
        ));
        assert!(matches!(
            VaultPair::new("archive", "b2", store(), None),
            Err(ConfigError::ReservedName { .. })
        ));
        // A derived store name that overruns the ceiling is caught here too,
        // which is what makes `--store-name` a real escape hatch rather than a
        // flag nobody discovers.
        let long = "a".repeat(MAX_REMOTE_NAME_LEN);
        assert!(matches!(
            VaultPair::new(long.clone(), format!("{long}-store"), store(), None),
            Err(ConfigError::NameTooLong { .. })
        ));
    }

    #[test]
    fn the_two_views_may_not_be_one_name() {
        // A vault whose base is itself is a cycle the loader refuses; catching
        // the case-folded near-miss here means the message names the real
        // mistake rather than describing a loop.
        assert!(matches!(
            VaultPair::new("archive", "Archive", store(), None),
            Err(ConfigError::DuplicateNameCase { .. })
        ));
        assert!(matches!(
            VaultPair::new("archive", "archive", store(), None),
            Err(ConfigError::DuplicateNameCase { .. })
        ));
    }

    #[test]
    fn a_subdirectory_is_carried_onto_the_vault_and_not_the_store() {
        // `base_path` says where inside the store the vault lives, so it belongs
        // to the wrapper. The store addresses the whole container.
        let pair = VaultPair::new("archive", "archive-store", store(), Some("vaults/a".into()))
            .expect("a legal pair");
        match pair.vault {
            RemoteDef::Vault(def) => assert_eq!(def.base_path.as_deref(), Some("vaults/a")),
            other => panic!("expected a vault remote, got {other:?}"),
        }
    }

    #[test]
    fn no_tuning_is_frozen_into_the_written_pair() {
        // A chunk size or verify policy written today would outlive the release
        // that chose it; both stay absent so the profile default keeps applying.
        match pair().vault {
            RemoteDef::Vault(def) => {
                assert!(def.chunk_size.is_none());
                assert!(def.verify.is_none());
            }
            other => panic!("expected a vault remote, got {other:?}"),
        }
    }
}
