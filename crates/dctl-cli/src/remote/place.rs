//! What *kind of place* a named remote is, decided before anything is written.
//!
//! [`resolve`](super::resolve) answers "which remote is this, and is it fully
//! configured?". That is the right question for a read, because
//! [`crate::source`] can read every kind of place through one trait. It is not
//! enough for a write, because what a write *means* differs by place in ways no
//! backend hides:
//!
//! * a **sealed** vault has no directories and no settable modification time —
//!   both are properties of a key/value namespace, not of the provider under it;
//! * a **filesystem** has real directories and real timestamps, and the
//!   operating system is the thing that maintains them;
//! * an **object store** has neither: a bucket is a flat key space, and the
//!   provider stamps `Last-Modified` itself when it accepts the object.
//!
//! Three answers, not five, and deliberately not one per provider: b2, s3 and r2
//! differ in how bytes get there and in nothing a write-side command decides.
//!
//! ## What this module no longer decides
//!
//! It used to carry one shared refusal — "this build cannot put a plain object
//! in a bucket" — asked by `touch`, `rcat` and the transfer family alike. That
//! sentence was true of all three and is now true of none of them in the same
//! way, so keeping it shared would have meant one message describing three
//! different situations:
//!
//! * a **transfer** writes the object, through
//!   [`Backend::put`](dctl_store::Backend::put) and the verified-write contract
//!   that comes with it (see [`crate::remote::PlainRemote`]);
//! * **`touch`** is refused by something no release can change — a bucket has no
//!   settable modification time at all;
//! * **`rcat`** is refused by a missing branch in `dctl-cli`, which somebody can
//!   simply write.
//!
//! Each command therefore states its own gap, in its own words, next to the
//! `match` arm that produces it. What stays here is the classification, which is
//! the one thing all three genuinely share.
//!
//! ## Why this is a separate question from `source::open`'s
//!
//! [`crate::source::open`] makes the same sealed/plain split for reads, from the
//! same one-line rule — a configured remote whose definition
//! [`is_vault`](crate::config::RemoteDef::is_vault). That is not a duplicated
//! *rule*; it is the same public predicate asked by the other side of the tool,
//! and it has to be asked here because the read abstraction deliberately hands
//! back a `Box<dyn Source>` that a caller cannot interrogate. What would be a
//! duplicated rule — following the vault chain, choosing a backend, deciding a
//! prefix — is not repeated: that stays in [`resolve`](super::resolve) and
//! [`crate::session`], and this module calls them.
//!
//! ## Nothing here connects, and nothing here needs a credential
//!
//! Classification reads the configuration file and stops. That is what lets
//! `dctl mkdir archive:photos/2024` answer without a password on a machine whose
//! B2 keys are not exported: the honest answer for a vault is "there is nothing
//! to create", and paying for an unlock to say so would be a prompt in a
//! script's face for no result.

use std::path::PathBuf;

use crate::config::{self, Config, RemoteDef};
use crate::constants::{PLACE_FILESYSTEM, PLACE_OBJECT_STORE, PLACE_SEALED};
use crate::ctx::Ctx;
use crate::error::{CliError, Result};
use crate::exit::ExitCode;
use crate::remote::registry::Target;
use crate::remote::resolve;
use crate::remote::spec::RemoteSpec;

/// Where a logical path inside a named remote physically ends up.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Place {
    /// The sealed view of a configured vault remote: every write is encrypted,
    /// and the logical path is the vault's own namespace.
    Sealed,

    /// A directory tree on this machine, reached without any provider.
    Filesystem {
        /// The remote's root directory.
        root: PathBuf,
        /// The logical path *inside* that root, taken from the resolver rather
        /// than from the spec — for a configured local remote the two agree, and
        /// asking the resolver is what keeps them from drifting if a remote ever
        /// gains a prefix of its own.
        path: String,
    },

    /// A bucket: keys only, no directories, and no settable modification time.
    ObjectStore {
        /// The provider, for a message that names what was addressed.
        ///
        /// Kept even though nothing branches on it: the two commands that still
        /// refuse an object store quote it, and "b2" in a refusal is the
        /// difference between a reader checking their remote and checking their
        /// arguments.
        provider: &'static str,
    },
}

impl Place {
    /// Classify the remote named by `spec`, reading the configuration only.
    ///
    /// # Errors
    /// [`ExitCode::FatalError`](crate::exit::ExitCode::FatalError) for an
    /// unreadable configuration, an unknown remote, or one whose settings are
    /// incomplete — the same diagnoses [`resolve`](super::resolve) produces, so a
    /// typo is reported as a typo rather than as a missing feature.
    pub fn of(ctx: &Ctx, spec: &RemoteSpec) -> Result<Self> {
        let path = config::resolve_path(ctx.globals.config.as_deref());
        let configured = config::load_or_default(&path)?;
        Self::classify(&configured, spec)
    }

    /// The pure half, so the decision is testable against a config fixture
    /// without a filesystem, a credential or a password.
    fn classify(configured: &Config, spec: &RemoteSpec) -> Result<Self> {
        if let RemoteSpec::Named { remote, .. } = spec {
            if configured.get(remote).is_some_and(RemoteDef::is_vault) {
                return Ok(Self::Sealed);
            }
        }

        let resolved = resolve::resolve(spec, configured)?;
        match resolved.target() {
            Target::Local { root } => Ok(Self::Filesystem {
                root: root.clone(),
                path: resolved.path().to_string(),
            }),
            other => Ok(Self::ObjectStore {
                provider: other.provider_type(),
            }),
        }
    }

    /// Refuse a remote whose filesystem root is not there.
    ///
    /// ## The failure this closes
    ///
    /// `dctl-store`'s directory walk treats `ENOENT` on the root as the end of
    /// the walk — correct for a directory that vanished *during* one, wrong for
    /// a root that was never there. So every read of an unmounted volume came
    /// back as an ordinary empty answer:
    ///
    /// ```text
    /// $ dctl ls backups:            (nothing on either stream)      exit 0
    /// $ dctl size backups:          Total objects: 0                exit 0
    /// $ dctl about backups:         objects 0 / bytes 0 B           exit 0
    /// $ dctl purge backups:2019 --force
    ///                               OK removed: 0 object(s), 0 B    exit 0
    /// ```
    ///
    /// Every one of those is a **conclusion somebody acts on**. A retention job
    /// running `dctl purge archive:2019 --force && record_purged 2019` marks
    /// 2019 reclaimed while the data is untouched; a monitor running
    /// `dctl size backup:` sees zero and pages someone to say the backup was
    /// wiped. `crate::commands::about::usage` states the rule this enforces —
    /// *"a failure is never reported as a zero: 'the backup is empty' is a
    /// conclusion people act on"* — and it was that module, among others, that
    /// broke it.
    ///
    /// ## Both spellings of the same path
    ///
    /// The check is on [`Place`] rather than on [`RemoteSpec`], so
    /// `dctl ls /srv/backups` and `dctl ls backups:` give the same answer about
    /// the same directory. They did not: the earlier guard tested
    /// `RemoteSpec::Local` alone, which is one spelling out of two, and the
    /// named one is what an operator configures precisely because they intend to
    /// use it every day.
    ///
    /// ## The root, and not the prefix
    ///
    /// Only [`Place::Filesystem`] has a tree to check, and only its **root** is
    /// checked. A remote's path component is a scope inside it, and a scope that
    /// matches nothing on a *mounted* volume is a real answer — "there is
    /// nothing under 2019" — which must stay an answer rather than becoming an
    /// error. The dangerous case is fully covered by the root, because an
    /// unmounted volume is the whole remote being unreadable rather than one
    /// prefix inside it.
    ///
    /// A vault and an object store are not checked: neither has a filesystem
    /// root, and an empty listing from either is a real answer.
    ///
    /// `metadata` rather than `symlink_metadata`, matching every walker in the
    /// tree: the root is the one path the operator configured, and
    /// `/data -> /mnt/disk/data` is an ordinary layout.
    ///
    /// # Errors
    /// [`ExitCode::DirNotFound`] when the root is absent — the same code every
    /// transfer verb already gives the same path — and [`ExitCode::Usage`] when
    /// it is a file rather than a directory.
    pub fn require_readable_tree(&self) -> Result<()> {
        let Self::Filesystem { root, .. } = self else {
            return Ok(());
        };
        match std::fs::metadata(root) {
            Ok(metadata) if metadata.is_dir() => Ok(()),
            Ok(_) => Err(
                CliError::usage(format!("'{}' is not a directory", root.display())).with_hint(
                    "A listing walks a tree. Name the directory that holds this file, \
                     or use `dctl cat` to read the file itself.",
                ),
            ),
            Err(error) => Err(CliError::new(
                ExitCode::DirNotFound,
                format!("'{}' does not exist: {error}", root.display()),
            )
            .with_hint(
                "Nothing was read, so this is not an empty tree. Check the path, \
                 and check that the volume holding it is mounted.",
            )),
        }
    }

    /// The slug reported in the `Backend` row and in `--json`.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Sealed => PLACE_SEALED,
            Self::Filesystem { .. } => PLACE_FILESYSTEM,
            Self::ObjectStore { .. } => PLACE_OBJECT_STORE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{LocalDef, VaultDef};
    use crate::constants::{PROVIDER_B2, PROVIDER_LOCAL};
    use crate::exit::ExitCode;

    /// The pair `dctl init --name archive --base local:/srv/v` registers.
    fn initialised() -> Config {
        let mut config = Config::default();
        config.insert(
            "archive-store",
            RemoteDef::Local(LocalDef {
                path: PathBuf::from("/srv/v"),
                verify: None,
                require_vault: true,
            }),
        );
        config.insert(
            "archive",
            RemoteDef::Vault(VaultDef {
                base: "archive-store".into(),
                base_path: None,
                chunk_size: None,
                verify: None,
            }),
        );
        config
    }

    fn named(remote: &str, path: &str) -> RemoteSpec {
        RemoteSpec::Named {
            remote: remote.to_string(),
            path: path.to_string(),
        }
    }

    fn classify(config: &Config, remote: &str, path: &str) -> Result<Place> {
        Place::classify(config, &named(remote, path))
    }

    #[test]
    fn a_vault_remote_is_sealed_and_its_store_is_a_filesystem() {
        // Both halves of the `dctl init` pair, and they are not the same place:
        // one is a namespace of logical paths, the other a directory of objects.
        let config = initialised();
        assert_eq!(
            classify(&config, "archive", "photos").unwrap(),
            Place::Sealed
        );
        assert_eq!(
            classify(&config, "archive-store", "photos").unwrap(),
            Place::Filesystem {
                root: PathBuf::from("/srv/v"),
                path: "photos".into(),
            }
        );
    }

    #[test]
    fn a_provider_shorthand_is_an_object_store_and_keeps_its_prefix_separate() {
        // The bucket is the container and the rest is a prefix inside it. A
        // command that used the whole spec path as a key would address
        // `mybucket/photos` *inside* `mybucket`.
        let place = classify(&Config::default(), "b2", "mybucket/photos").unwrap();
        assert_eq!(
            place,
            Place::ObjectStore {
                provider: PROVIDER_B2
            }
        );
    }

    #[test]
    fn classifying_a_place_never_refuses_anything() {
        // This module answers "what kind of place is this" and stops. The shared
        // "no plain object write path" refusal that used to live here spoke for
        // three commands whose gaps have since diverged — a transfer writes the
        // object, `touch` never can, and `rcat` merely does not yet — so each
        // states its own, and every place classifies without an error.
        let config = initialised();
        for spec in [
            named("archive", "a"),
            named("archive-store", "a"),
            named("s3", "bucket/x"),
            named("b2", "mybucket/photos"),
        ] {
            assert!(
                Place::classify(&config, &spec).is_ok(),
                "classification must not refuse: {spec:?}"
            );
        }
    }

    #[test]
    fn an_unknown_remote_is_a_configuration_error_and_never_a_directory() {
        // Silently reinterpreting `vault:photos` as the relative directory
        // `vault` is how a backup lands in the working directory and exits 0.
        let error = classify(&Config::default(), "nosuchremote", "x")
            .expect_err("an unconfigured remote cannot be classified");
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.message().contains("nosuchremote"));
    }

    #[test]
    fn a_local_path_is_a_filesystem_with_no_configuration_at_all() {
        // The headless case: a bare path resolves without a config file, and the
        // whole path is the root because there is no remote to hang a prefix off.
        let place = Place::classify(
            &Config::default(),
            &RemoteSpec::Local(PathBuf::from("/srv/data")),
        )
        .unwrap();
        assert_eq!(
            place,
            Place::Filesystem {
                root: PathBuf::from("/srv/data"),
                path: String::new(),
            }
        );
    }

    #[test]
    fn the_slugs_are_distinct_and_match_the_provider_vocabulary() {
        // A `--json` consumer branches on these, and `vault`/`local` must be the
        // same words `about` and the config file already use.
        assert_eq!(Place::Sealed.label(), PLACE_SEALED);
        assert_eq!(PLACE_FILESYSTEM, PROVIDER_LOCAL);
        assert_ne!(Place::Sealed.label(), PLACE_OBJECT_STORE);
        assert_ne!(PLACE_FILESYSTEM, PLACE_OBJECT_STORE);
    }
}
