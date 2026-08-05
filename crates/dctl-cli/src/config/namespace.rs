//! Which vault's namespace a destination belongs to, decided from the file.
//!
//! A vault has two names and they mean different things
//! ([the plan](https://doc.dctl.sh/project/plan) §13.3, and the shape
//! [`super::pair`] writes):
//!
//! * `archive:` — the **sealed view**. Everything through it is encrypted.
//! * `archive-store:` — the **object view**: the opaque ciphertext objects.
//!
//! This module answers one question about a destination — *does it belong to a
//! vault's object namespace?* — and answers it from the **configuration alone**.
//! Nothing here stats a file, opens a backend or looks at what a directory
//! currently contains.
//!
//! ## Why the configuration and not the destination's contents
//!
//! The rule this replaced walked the destination's ancestors looking for
//! `system/envelope.bin`. It stopped a real plaintext leak and it was the wrong
//! shape, because it made a command's encryption semantics a function of
//! filesystem state: the same `dctl copy` was refused today and permitted
//! tomorrow depending on whether somebody had run `dctl init` in between, and
//! permitted again the moment an envelope was moved. A tool that holds
//! irreplaceable data cannot have behaviour that changes underneath a runbook.
//!
//! So the rule is derived from what the operator *declared*. A location carries
//! [`RemoteDef::require_vault`] because a remote in the file says it holds a
//! vault's objects, and that declaration is what a refusal cites. The answer to
//! "will this command encrypt?" is then a property of the names typed and the
//! file on disk, both of which are reviewable before the command runs.
//!
//! ## What this deliberately does not do
//!
//! It never *promotes* a plain write into a sealed one. Recognising that a
//! destination belongs to `archive` and quietly encrypting for the user would be
//! exactly the inference the model forbids — the caller asked for one thing and
//! would get another, decided by state they did not name. The only outcomes are
//! "this is an ordinary place" and "this belongs to a vault, and here is the
//! remote that addresses it". Choosing between them stays with the operator.
//!
//! The flag is the discriminator rather than "is the base of some vault
//! remote", and that is deliberate too:
//! [the plan](https://doc.dctl.sh/project/plan) §14's worked example is a
//! vault over `b2prod` in which `b2prod:` remains usable as an ordinary remote,
//! and [`super::validate::vault_only_locations`] already draws the line in the
//! same place. Two definitions of "this location is a vault's" would sooner or
//! later disagree, and the disagreement would be visible as a refusal in one
//! command and a plaintext write in another.

use std::path::{Path, PathBuf};

use crate::platform::resolve::real_path;

use super::location::Location;
use super::model::{Config, RemoteDef};
use super::validate::vault_chain;

/// A destination that belongs to a vault's object namespace.
///
/// Owned rather than borrowed from the [`Config`] it was derived from, because
/// the caller that reports it has usually finished with the configuration by
/// then — a refusal outlives the file it was read from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultNamespace {
    subject: String,
    store: String,
    vault: Option<String>,
}

impl VaultNamespace {
    /// Whether the remote called `name` is a vault's object store.
    ///
    /// The `archive-store:` half of the addressing model. A write of foreign
    /// plaintext through it is refused; replicating the objects it already holds
    /// is a different operation that needs no key, which is the entire reason
    /// the base remote has a name at all.
    #[must_use]
    pub fn of_remote(config: &Config, name: &str) -> Option<Self> {
        if !config.get(name).is_some_and(RemoteDef::require_vault) {
            return None;
        }
        Some(Self {
            subject: name.to_string(),
            store: name.to_string(),
            vault: sealed_view(config, name),
        })
    }

    /// Whether a bare filesystem path lies in a configured store's location.
    ///
    /// Every spelling of the destination is compared against every spelling of
    /// every declared store — see [`spellings`] for which and why. The answer
    /// must be the same for `vault`, `./vault`, `/srv/vault`,
    /// `staging/../vault`, a symlink to it and any subdirectory of it, because
    /// an operator who reaches the same directory by a different route has not
    /// asked for different encryption behaviour.
    ///
    /// The refusal names the **store's root** rather than the full path the user
    /// happened to type: `'/srv/vault' is the object store for 'archive'` is what
    /// tells an operator what they hit, where `'/srv/vault/photos/2024/raw'` only
    /// tells them what they typed.
    #[must_use]
    pub fn of_path(config: &Config, path: &Path) -> Option<Self> {
        if path.as_os_str().is_empty() {
            return None;
        }

        let stores = vault_only_stores(config);
        if stores.is_empty() {
            // The overwhelming majority of configurations. Answering here costs
            // nothing and, more importantly, resolves no paths: a machine with
            // no vault at all must not pay a `stat` per destination.
            return None;
        }

        for ancestor in spellings(path) {
            let place = Location::of_path(&ancestor);
            if let Some(store) = stores.iter().find(|store| store.is(&place)) {
                return Some(Self {
                    subject: ancestor.display().to_string(),
                    store: store.name.to_string(),
                    vault: sealed_view(config, store.name),
                });
            }
        }
        None
    }
}

/// A configured store, in both the spelling the file uses and the place it
/// resolves to.
///
/// Two readings, because one is not enough.
///
/// [`Location`] is deliberately pure — it never touches a filesystem, so config
/// validation works on a machine that has never seen the paths it validates.
/// That purity is right for validation and wrong here: the destination arrives
/// as the user typed it, and `./srv` does not compare equal to the `/srv` the
/// file records. The claim then missed, the write path fell through to sniffing
/// the destination for an envelope, and the encryption decision became a
/// function of the destination's *contents* — the one thing the addressing model
/// forbids. Moving the same command between an absolute and a relative spelling
/// flipped it between refusing and writing plaintext.
struct Store<'a> {
    name: &'a str,
    /// Exactly as the configuration file spells it.
    spelled: Location,
    /// Where that spelling actually leads, for a local path. `None` for a
    /// bucket, which has one spelling and nothing to resolve.
    real: Option<Location>,
}

impl Store<'_> {
    /// Whether `place` is this store, under either reading.
    fn is(&self, place: &Location) -> bool {
        self.spelled == *place || self.real.as_ref() == Some(place)
    }
}

/// Every remote that declares itself a vault's object store, resolved once.
///
/// Resolved once per call rather than once per ancestor: a deep destination and
/// a handful of remotes would otherwise re-resolve the same configured paths a
/// dozen times, and the answer cannot change within one decision.
fn vault_only_stores(config: &Config) -> Vec<Store<'_>> {
    config
        .names()
        .filter_map(|name| {
            let remote = config.get(name)?;
            if !remote.require_vault() {
                return None;
            }
            Some(Store {
                name,
                spelled: Location::of(remote)?,
                real: configured_real(remote),
            })
        })
        .collect()
}

/// The resolved [`Location`] of a remote that names a local path.
///
/// Separate from [`Location::of`] so the pure, I/O-free version stays the one
/// config validation uses. Only the write-path check pays for the `stat`.
fn configured_real(remote: &RemoteDef) -> Option<Location> {
    let RemoteDef::Local(def) = remote else {
        // Only a filesystem path has spellings to reconcile. A bucket name is
        // already canonical: there is one spelling of `photos`.
        return None;
    };
    real_path(&def.path).map(|real| Location::of_path(&real))
}

/// Every place a destination could be claimed at: each ancestor of the spelling
/// typed, then each ancestor of the place it resolves to.
///
/// Ancestors are walked, and that is essential rather than thorough: checking
/// only the exact path meant naming any subdirectory defeated the rule entirely
/// — `/srv/vault` was refused while `/srv/vault/photos` was a plain write into
/// the middle of a vault's object tree. A rule one extra path component disables
/// is worse than none, because it reads as protection.
///
/// The typed spelling comes first so a refusal names something the operator
/// recognises from their own command line. The resolved spelling follows and is
/// what catches `./vault`, `staging/../vault`, a symlink, and a second mount
/// path for one directory — spellings under which the string comparison alone
/// silently permitted the write.
fn spellings(path: &Path) -> impl Iterator<Item = PathBuf> {
    let typed: Vec<PathBuf> = ancestors(path);

    // The resolved path is ALWAYS consulted, never filtered against the typed
    // one. It used to be skipped when `real == path`, and that comparison is
    // `Path`'s component-wise equality — which normalises away precisely `/`,
    // `//`, `/.` and a trailing separator. Those are exactly the spellings the
    // string identity used to miss, so the safety net was disabled for the only
    // cases that needed it: the two halves agreed only where neither was
    // required. Re-checking an identical resolved path costs one `stat` and
    // removes the whole class.
    let real = real_path(path);
    typed
        .into_iter()
        .chain(real.into_iter().flat_map(|real| ancestors(&real)))
}

/// A path's ancestors, deepest first, with the empty tail dropped.
///
/// The empty path is not an ancestor of anything for this purpose: a store
/// configured with no path at all would otherwise claim every destination on the
/// machine.
fn ancestors(path: &Path) -> Vec<PathBuf> {
    path.ancestors()
        .filter(|ancestor| !ancestor.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .collect()
}

impl VaultNamespace {
    /// What a message should name: the configured directory, or the remote.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// The remote that declared this location a vault's object store.
    #[must_use]
    pub fn store(&self) -> &str {
        &self.store
    }

    /// The sealed view to write through instead, when the file defines one.
    ///
    /// `None` is a hand-edited configuration: a store marked vault-only that no
    /// vault remote wraps. `dctl init` and `dctl config import` always write the
    /// pair together ([`super::pair`]), so the case cannot arise from a
    /// configuration DCTL produced — but a file a human can edit is a file a
    /// human can half-edit, and a refusal that invented a remote name would send
    /// them to type something that does not exist.
    #[must_use]
    pub fn vault(&self) -> Option<&str> {
        self.vault.as_deref()
    }
}

/// The vault remote whose chain reaches `store`, if the file defines one.
///
/// The whole chain is walked rather than only the direct `base`, because a vault
/// may sit over another vault: the remote worth naming is the one an operator
/// can actually type, which is the outermost wrapper, not the intermediate link.
/// File order breaks a tie between two wrappers over one store, so the answer is
/// a property of the configuration rather than of iteration order.
fn sealed_view(config: &Config, store: &str) -> Option<String> {
    config
        .names()
        .find(|name| {
            config.get(name).is_some_and(RemoteDef::is_vault)
                && vault_chain(config, name).is_ok_and(|chain| chain.contains(&store))
        })
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::model::{B2Def, LocalDef, VaultDef};
    use std::path::PathBuf;

    fn store_at(path: &str) -> RemoteDef {
        RemoteDef::Local(LocalDef {
            path: PathBuf::from(path),
            verify: None,
            require_vault: true,
        })
    }

    fn plain_at(path: &str) -> RemoteDef {
        RemoteDef::Local(LocalDef {
            path: PathBuf::from(path),
            verify: None,
            require_vault: false,
        })
    }

    fn bucket(name: &str, require_vault: bool) -> RemoteDef {
        RemoteDef::B2(B2Def {
            bucket: name.into(),
            endpoint: None,
            chunk_size: None,
            verify: None,
            require_vault,
        })
    }

    fn vault(base: &str) -> RemoteDef {
        RemoteDef::Vault(VaultDef {
            base: base.to_string(),
            base_path: None,
            chunk_size: None,
            verify: None,
        })
    }

    /// The pair `dctl init --name archive --base local:/srv/vault` writes.
    fn initialised() -> Config {
        let mut config = Config::default();
        config.insert("archive-store", store_at("/srv/vault"));
        config.insert("archive", vault("archive-store"));
        config
    }

    #[test]
    fn the_object_view_of_a_vault_is_recognised_by_name() {
        let config = initialised();
        let claimed = VaultNamespace::of_remote(&config, "archive-store").expect("a store remote");
        assert_eq!(claimed.store(), "archive-store");
        assert_eq!(claimed.vault(), Some("archive"));
        assert_eq!(claimed.subject(), "archive-store");
    }

    #[test]
    fn the_sealed_view_is_not_itself_an_object_store() {
        // Invariant I1: a write through `archive:` is sealed, so it must reach
        // the vault rather than be refused on the way.
        assert_eq!(VaultNamespace::of_remote(&initialised(), "archive"), None);
    }

    #[test]
    fn an_ordinary_remote_is_not_claimed() {
        let mut config = initialised();
        config.insert("scratch", plain_at("/srv/scratch"));
        assert_eq!(VaultNamespace::of_remote(&config, "scratch"), None);
        assert_eq!(VaultNamespace::of_remote(&config, "nosuchremote"), None);
    }

    #[test]
    fn a_configured_store_location_is_claimed_by_path() {
        // The rule this module exists for, and the property the filesystem check
        // could not have: nothing was created at `/srv/vault` here. The answer
        // comes from the file, so it is the same answer before and after the
        // objects land.
        let claimed = VaultNamespace::of_path(&initialised(), Path::new("/srv/vault"))
            .expect("the store's own directory");
        assert_eq!(claimed.vault(), Some("archive"));
        assert_eq!(claimed.subject(), "/srv/vault");
    }

    #[test]
    fn a_path_at_any_depth_inside_a_store_is_claimed() {
        // The bypass an exact-path rule leaves open: one extra component and the
        // write lands in the middle of a vault's object tree.
        let config = initialised();
        for typed in [
            "/srv/vault/photos",
            "/srv/vault/photos/2024",
            "/srv/vault/photos/2024/raw",
        ] {
            let claimed =
                VaultNamespace::of_path(&config, Path::new(typed)).expect("inside the store");
            assert_eq!(claimed.store(), "archive-store", "{typed}");
            // The configured root is what the operator needs to be told about.
            assert_eq!(claimed.subject(), "/srv/vault", "{typed}");
        }
    }

    #[test]
    fn a_sibling_of_a_store_is_an_ordinary_directory() {
        // The rule must not spread to directories that merely share a parent.
        let config = initialised();
        assert_eq!(
            VaultNamespace::of_path(&config, Path::new("/srv/other")),
            None
        );
        assert_eq!(
            VaultNamespace::of_path(&config, Path::new("/srv/vault-2")),
            None
        );
        // Nor to the parent of a store, which is an ordinary directory that
        // happens to contain one.
        assert_eq!(VaultNamespace::of_path(&config, Path::new("/srv")), None);
    }

    #[test]
    fn an_empty_path_claims_nothing() {
        // Directions with no local destination pass an empty root; it must not
        // resolve to the working directory or match a store with no path set.
        let mut config = initialised();
        config.insert("odd-store", store_at(""));
        assert_eq!(VaultNamespace::of_path(&config, Path::new("")), None);
    }

    #[test]
    fn a_configuration_with_no_store_claims_nothing() {
        // The overwhelming majority of configurations, which must cost nothing.
        let mut config = Config::default();
        config.insert("b2prod", bucket("photos", false));
        config.insert("vault", vault("b2prod"));
        assert_eq!(VaultNamespace::of_remote(&config, "b2prod"), None);
        assert_eq!(
            VaultNamespace::of_path(&config, Path::new("/srv/vault")),
            None
        );
    }

    #[test]
    fn a_bucket_store_is_claimed_by_name_and_never_by_a_path() {
        // A directory called `photos` is not the bucket called `photos`.
        let mut config = Config::default();
        config.insert("cold-store", bucket("photos", true));
        config.insert("cold", vault("cold-store"));

        assert!(VaultNamespace::of_remote(&config, "cold-store").is_some());
        assert_eq!(VaultNamespace::of_path(&config, Path::new("photos")), None);
        assert_eq!(VaultNamespace::of_path(&config, Path::new("/photos")), None);
    }

    #[test]
    fn a_store_nobody_wraps_is_still_a_store() {
        // Hand-edited: the flag without the pair. The location is still claimed,
        // and the refusal must not invent a vault remote to send the user to.
        let mut config = Config::default();
        config.insert("orphan-store", store_at("/srv/vault"));
        let claimed = VaultNamespace::of_path(&config, Path::new("/srv/vault")).expect("claimed");
        assert_eq!(claimed.store(), "orphan-store");
        assert_eq!(claimed.vault(), None);
    }

    #[test]
    fn the_outermost_wrapper_is_the_one_worth_typing() {
        // A vault over a vault: the operator can only address the outer one, and
        // a refusal naming the inner link would send them to type a remote that
        // seals into the wrong namespace.
        let mut config = Config::default();
        config.insert("deep-store", store_at("/srv/vault"));
        config.insert("inner", vault("deep-store"));
        config.insert("outer", vault("inner"));

        let claimed = VaultNamespace::of_path(&config, Path::new("/srv/vault")).expect("claimed");
        // Both wrappers reach the store; file order decides, and both are
        // typeable — what must never happen is naming the store itself.
        assert!(
            matches!(claimed.vault(), Some("inner" | "outer")),
            "got {:?}",
            claimed.vault()
        );
    }

    #[test]
    fn two_stores_at_one_place_do_not_confuse_the_answer() {
        // `validate` permits this: an operator renaming a store adds the new
        // section before removing the old one. Whichever is named, the claim
        // must be stable rather than depending on iteration order.
        let mut config = Config::default();
        config.insert("archive-store", store_at("/srv/vault"));
        config.insert("archive-store2", store_at("/srv/vault"));
        config.insert("archive", vault("archive-store"));

        let claimed = VaultNamespace::of_path(&config, Path::new("/srv/vault")).expect("claimed");
        assert_eq!(claimed.store(), "archive-store", "file order decides");
        assert_eq!(claimed.vault(), Some("archive"));
    }
}
