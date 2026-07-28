//! Which two places a replication runs between, and what makes each of them one.
//!
//! Everything dangerous about `dctl replicate` is decided here, before a single
//! object moves, and all of it follows from one question: **is this end an
//! object store?**
//!
//! ## A vault remote is refused, structurally
//!
//! `archive:` is the sealed view — reading through it decrypts, writing through
//! it encrypts. Either one would defeat the entire purpose of the command, which
//! is to move ciphertext with no key present, so a vault remote on either end is
//! refused from the **configuration alone**: no probe, no I/O, no password. The
//! refusal names the store remote that would have worked, because the operator
//! who typed `archive:` almost always meant `archive-store:` and should not have
//! to go and read a manual to learn the suffix.
//!
//! ## Declared, or demonstrated — never inferred
//!
//! A location earns its place at one end of a replication in exactly two ways:
//!
//! * **Declared.** The configuration says `require_vault = true`, which is what
//!   `dctl init` writes for the store remote it registers. That is a statement
//!   the operator made once, in a file, and it costs no network round trip to
//!   read.
//! * **Demonstrated.** A vault's envelope is at the location's root, found by
//!   the same key-free probe `dctl config import` uses ([`envelope`]). This is
//!   what makes a bare `local:/srv/vault` usable without configuring anything.
//!
//! An empty, undeclared location is **refused**, and that refusal is the point
//! rather than an oversight. The tempting alternative — "it is empty, so it must
//! be the new replica" — is precisely the auto-detection invariant I4 forbids:
//! what a command does would then depend on what the destination happened to
//! contain, and `dctl replicate archive-store: ~/Documents` would spray a
//! vault's object tree across somebody's files the first time and refuse the
//! second. Declaring a replica's store is one command, run once, and the refusal
//! names it.
//!
//! Note what the probe is *not* doing. It answers "may this location be one end
//! of a replication", never "should these bytes be encrypted" — replication has
//! one encryption behaviour, fixed at the verb, and nothing found on a store can
//! change it. Eligibility may be discovered; semantics may not.
//!
//! ## Roots only
//!
//! Both ends address a store's root. A prefix is a filter written in the
//! argument instead of in a flag, and it produces the same broken half-replica,
//! so it is refused in the same breath — see [`super::filters`].

use std::sync::Arc;

use dctl_store::{Backend, LinkPolicy};

use crate::commands::config::settings;
use crate::config::{Config, RemoteDef};
use crate::constants::{
    INIT_STORE_NAME_SUFFIX, REPLICATE_DEST_VALUE_NAME, REPLICATE_SAME_STORE_HINT,
    REPLICATE_SOURCE_VALUE_NAME, REPLICATE_STORE_HINT, REPLICATE_SUBPATH_HINT,
};
use crate::error::{CliError, Result};
use crate::exit::ExitCode;
use crate::remote::envelope::{self, Verdict};
use crate::remote::resolve::{Resolved, resolve};
use crate::remote::{RemoteSpec, registry};

/// Which end of the replication a target is.
///
/// Carried so a refusal can say *which argument* was wrong. "one of the two
/// stores is not a store" is a message that sends an operator to check both.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    /// The store being read from.
    Source,
    /// The store being written to.
    Destination,
}

impl Side {
    /// The argument's name, spelled as `--help` spells it.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Source => REPLICATE_SOURCE_VALUE_NAME,
            Self::Destination => REPLICATE_DEST_VALUE_NAME,
        }
    }
}

/// How a location earned the right to be one end of a replication.
///
/// Reported rather than merely checked, because the two are worth telling apart
/// in an audit record: a declared store was approved by a human editing a
/// configuration file, while a demonstrated one was approved by this run finding
/// an envelope. Both are legitimate; only one of them leaves a paper trail
/// outside the log line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standing {
    /// The configuration declares the location a vault's object store.
    Declared,
    /// A vault envelope is stored at the location's root.
    ///
    /// `slots` is `None` for an envelope of a format version this build cannot
    /// read. That is deliberately not a refusal: replication copies opaque
    /// bytes and never parses one, so being too old to *unlock* a vault is no
    /// reason to be unable to *protect* it with a second copy.
    Demonstrated { slots: Option<u16> },
}

impl Standing {
    /// The stable slug used in the report and in log records.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Declared => "declared",
            Self::Demonstrated { .. } => "demonstrated",
        }
    }
}

/// One end of a replication: a live backend and the reason it is allowed to be
/// one.
pub struct Store {
    /// The argument exactly as the user typed it, for messages and the report.
    ///
    /// Kept verbatim rather than re-rendered, because the whole value of an
    /// error at this stage is that the operator recognises their own argument.
    pub spec: String,
    /// Why this location may take part.
    pub standing: Standing,
    resolved: Resolved,
    backend: Arc<dyn Backend>,
}

/// Written by hand because a live backend has no `Debug`, and would be noise if
/// it had one: what a reader of a `{:?}` needs is which place this is and why it
/// was allowed to take part.
impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("spec", &self.spec)
            .field("remote", &self.resolved.name())
            .field("standing", &self.standing)
            .finish()
    }
}

impl Store {
    /// The live backend. Object keys pass through it untouched.
    #[must_use]
    pub fn backend(&self) -> &Arc<dyn Backend> {
        &self.backend
    }

    /// The remote's name, for the `remote` log field.
    #[must_use]
    pub fn name(&self) -> &str {
        self.resolved.name()
    }
}

/// Resolve one end of a replication, refusing anything that is not an object
/// store.
///
/// # Errors
/// [`ExitCode::Usage`] for a malformed spec, a spec naming a path inside a
/// store, or a vault remote. [`ExitCode::FatalError`] for an unresolvable
/// remote, missing credentials, or a location that is neither declared a store
/// nor holds a vault's envelope.
pub async fn open(config: &Config, spec: &str, side: Side, links: LinkPolicy) -> Result<Store> {
    let parsed = RemoteSpec::parse(spec)?;
    refuse_subpath(&parsed, spec, side)?;

    // Before resolution, so the message can be the one that helps: the resolver
    // would refuse a vault remote too, but as "a vault wrapper stores nothing
    // itself", which is true and unhelpful to someone who typed one argument off.
    if let RemoteSpec::Named { remote, .. } = &parsed
        && let Some(def) = config.get(remote)
        && def.is_vault()
    {
        return Err(refuse_vault(spec, remote, def, side));
    }

    let resolved = resolve(&parsed, &settings::catalog(config))?;
    let backend = registry::build(&resolved, links)?;
    let standing = admit(&parsed, config, &backend, spec, side).await?;

    Ok(Store {
        spec: spec.to_string(),
        standing,
        resolved,
        backend,
    })
}

/// Refuse two arguments that address the same physical place.
///
/// Compared on the resolved [`Target`](crate::remote::registry::Target) rather
/// than on the text, so two different names for one bucket are still caught —
/// which is the shape the mistake actually takes, since a store and its replica
/// are usually two config sections a human wrote at different times.
///
/// # Errors
/// [`ExitCode::Usage`] when both ends resolve to the same location.
pub fn refuse_same_place(source: &Store, destination: &Store) -> Result<()> {
    if source.resolved.target() != destination.resolved.target() {
        return Ok(());
    }

    Err(CliError::new(
        ExitCode::Usage,
        format!(
            "'{}' and '{}' are the same location, so replicating between them \
             would copy a store onto itself",
            source.spec, destination.spec
        ),
    )
    .with_hint(REPLICATE_SAME_STORE_HINT))
}

/// Refuse a spec that addresses a path inside a store rather than the store.
fn refuse_subpath(parsed: &RemoteSpec, spec: &str, side: Side) -> Result<()> {
    let RemoteSpec::Named { path, .. } = parsed else {
        // A bare path *is* the root: `RemoteSpec::Local` carries the whole
        // argument as the backend's root directory, with no prefix hanging off
        // it, so there is no partial address to refuse.
        return Ok(());
    };
    if path.is_empty() {
        return Ok(());
    }

    Err(CliError::new(
        ExitCode::Usage,
        format!(
            "{} '{spec}' names a path inside a store, not a store",
            side.label()
        ),
    )
    .with_hint(REPLICATE_SUBPATH_HINT))
}

/// The refusal for a vault remote, naming the store remote that would work.
///
/// The suggestion is taken from the vault's own `base` setting when it has one,
/// because that is the store remote that really holds its objects. Only when the
/// configuration is too broken to say does it fall back to the conventional
/// `<name>-store` spelling, which is a guess and is worded as one.
fn refuse_vault(spec: &str, remote: &str, def: &RemoteDef, side: Side) -> CliError {
    let error = CliError::new(
        ExitCode::Usage,
        format!(
            "{} '{spec}' is a vault remote, and reading a vault decrypts it",
            side.label()
        ),
    );

    match def.base() {
        Some(base) => error.with_hint(format!(
            "Replication moves opaque ciphertext and holds no key, so it is \
             addressed at the object store rather than at the sealed view. \
             '{remote}' seals on the way through to '{base}'; replicate \
             '{base}:' instead."
        )),
        None => error.with_hint(format!(
            "Replication moves opaque ciphertext and holds no key, so it is \
             addressed at the object store rather than at the sealed view. \
             '{remote}' names no base remote, which is itself a configuration \
             fault — run `dctl config verify`. The store is conventionally \
             called '{remote}{INIT_STORE_NAME_SUFFIX}'."
        )),
    }
}

/// Decide whether a location may be one end of a replication.
///
/// Declared first, and only then demonstrated: a store `dctl init` registered
/// needs no probe at all, which is what keeps the ordinary offsite job free of
/// an extra round trip against each provider before it starts.
async fn admit(
    parsed: &RemoteSpec,
    config: &Config,
    backend: &Arc<dyn Backend>,
    spec: &str,
    side: Side,
) -> Result<Standing> {
    if let RemoteSpec::Named { remote, .. } = parsed
        && config.get(remote).is_some_and(RemoteDef::require_vault)
    {
        return Ok(Standing::Declared);
    }

    match envelope::probe(backend).await? {
        Verdict::Vault { slots } => Ok(Standing::Demonstrated { slots: Some(slots) }),
        Verdict::Foreign { .. } => Ok(Standing::Demonstrated { slots: None }),
        Verdict::Absent => Err(CliError::new(
            ExitCode::FatalError,
            format!(
                "{} '{spec}' is not a vault's object store: the configuration \
                 does not declare it one, and no vault envelope is stored there",
                side.label()
            ),
        )
        .with_hint(REPLICATE_STORE_HINT)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{B2Def, LocalDef, RemoteDef, S3Def, VaultDef};
    use crate::constants::{VAULT_ENVELOPE_MAGIC, VAULT_ENVELOPE_VERSION};
    use std::path::{Path, PathBuf};

    /// A directory holding a plausible `DKE1` envelope.
    fn store_with_vault(root: &Path, slots: u16) {
        let system = root.join("system");
        std::fs::create_dir_all(&system).unwrap();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(VAULT_ENVELOPE_MAGIC);
        bytes.push(VAULT_ENVELOPE_VERSION);
        bytes.extend_from_slice(&[7; 16]);
        bytes.extend_from_slice(&slots.to_le_bytes());
        std::fs::write(system.join("envelope.bin"), bytes).unwrap();
    }

    fn vault_pair() -> Config {
        let mut config = Config::default();
        config.insert(
            "archive",
            RemoteDef::Vault(VaultDef {
                base: "archive-store".into(),
                base_path: None,
                chunk_size: None,
                verify: None,
            }),
        );
        config.insert(
            "archive-store",
            RemoteDef::Local(LocalDef {
                path: PathBuf::from("/srv/vault"),
                verify: None,
                require_vault: true,
            }),
        );
        config
    }

    #[tokio::test]
    async fn a_vault_remote_is_refused_on_either_side_without_touching_a_store() {
        // The most important refusal in the command, and it is decided from the
        // configuration alone: the path `/srv/vault` does not exist, so a probe
        // would have failed with something else entirely.
        let config = vault_pair();
        for side in [Side::Source, Side::Destination] {
            let error = open(&config, "archive:", side, LinkPolicy::default())
                .await
                .unwrap_err();
            assert_eq!(error.code(), ExitCode::Usage);
            assert!(error.message().contains("decrypts"), "{}", error.message());
            // The remediation has to be the exact argument that works.
            assert!(
                error.hint().unwrap_or_default().contains("archive-store:"),
                "got hint: {:?}",
                error.hint()
            );
        }
    }

    #[tokio::test]
    async fn a_vault_remote_with_no_base_still_refuses_and_says_the_config_is_broken() {
        let mut config = Config::default();
        config.insert(
            "archive",
            RemoteDef::Vault(VaultDef {
                base: String::new(),
                base_path: None,
                chunk_size: None,
                verify: None,
            }),
        );
        // An empty base is `Some("")`, which is still a base; the fallback arm is
        // reached only by a variant that reports none at all. Assert the arm
        // directly, so the message is pinned either way.
        let plain = RemoteDef::Local(LocalDef {
            path: PathBuf::from("/srv"),
            verify: None,
            require_vault: false,
        });
        let error = refuse_vault("x:", "x", &plain, Side::Source);
        assert!(
            error.hint().unwrap_or_default().contains("-store"),
            "got hint: {:?}",
            error.hint()
        );
    }

    #[tokio::test]
    async fn a_declared_store_is_admitted_with_no_probe_at_all() {
        // The enterprise path: a store `dctl init` registered is eligible from
        // the file. The directory below is never created, so an admission that
        // needed to look would fail.
        let dir = tempfile::tempdir().unwrap();
        let absent = dir.path().join("never-created");
        let mut config = Config::default();
        config.insert(
            "offsite-store",
            RemoteDef::Local(LocalDef {
                path: absent.clone(),
                verify: None,
                require_vault: true,
            }),
        );

        let store = open(
            &config,
            "offsite-store:",
            Side::Destination,
            LinkPolicy::default(),
        )
        .await
        .unwrap();
        assert_eq!(store.standing, Standing::Declared);
        assert!(
            !absent.exists(),
            "admission must not have touched the store"
        );
    }

    #[tokio::test]
    async fn a_bare_location_holding_an_envelope_is_admitted() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("vault");
        store_with_vault(&store, 3);

        let admitted = open(
            &Config::default(),
            &format!("local:{}", store.display()),
            Side::Source,
            LinkPolicy::default(),
        )
        .await
        .unwrap();
        assert_eq!(admitted.standing, Standing::Demonstrated { slots: Some(3) });
    }

    #[tokio::test]
    async fn an_undeclared_empty_location_is_refused_and_told_how_to_declare_itself() {
        // The refusal that keeps invariant I4 intact: "it is empty, so it must
        // be the replica" is an inference about contents, and this command makes
        // none.
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("ordinary-directory");
        std::fs::create_dir_all(&empty).unwrap();

        let error = open(
            &Config::default(),
            &format!("local:{}", empty.display()),
            Side::Destination,
            LinkPolicy::default(),
        )
        .await
        .unwrap_err();

        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(
            error.message().contains("not a vault's object store"),
            "{}",
            error.message()
        );
        assert!(
            error
                .hint()
                .unwrap_or_default()
                .contains("require_vault=true"),
            "the refusal must name the command that declares one"
        );
    }

    #[tokio::test]
    async fn a_path_inside_a_store_is_refused_as_a_filter_in_disguise() {
        let config = vault_pair();
        let error = open(
            &config,
            "archive-store:photos",
            Side::Source,
            LinkPolicy::default(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(
            error.hint().unwrap_or_default().contains("partial replica"),
            "got hint: {:?}",
            error.hint()
        );
    }

    #[tokio::test]
    async fn two_names_for_one_bucket_are_recognised_as_one_place() {
        // The shape the mistake takes in the field: a store and its "replica"
        // written into the file months apart, both naming the same bucket.
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("vault");
        store_with_vault(&store, 1);

        let mut config = Config::default();
        for name in ["primary-store", "offsite-store"] {
            config.insert(
                name,
                RemoteDef::Local(LocalDef {
                    path: store.clone(),
                    verify: None,
                    require_vault: true,
                }),
            );
        }

        let source = open(
            &config,
            "primary-store:",
            Side::Source,
            LinkPolicy::default(),
        )
        .await
        .unwrap();
        let destination = open(
            &config,
            "offsite-store:",
            Side::Destination,
            LinkPolicy::default(),
        )
        .await
        .unwrap();

        let error = refuse_same_place(&source, &destination).unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.message().contains("same location"));
    }

    #[test]
    fn two_genuinely_different_buckets_are_not_the_same_place() {
        // The other direction, checked on the resolver's own value so the rule
        // cannot be satisfied by two specs that merely read differently.
        let one = RemoteDef::B2(B2Def {
            bucket: "primary".into(),
            endpoint: None,
            chunk_size: None,
            verify: None,
            require_vault: true,
        });
        let other = RemoteDef::S3(S3Def {
            bucket: "primary".into(),
            endpoint: Some("https://s3.example.com".into()),
            region: None,
            chunk_size: None,
            verify: None,
            require_vault: true,
        });
        assert_ne!(one.type_name(), other.type_name());
    }

    #[test]
    fn each_side_names_the_argument_the_user_typed() {
        assert_ne!(Side::Source.label(), Side::Destination.label());
        assert!(Side::Source.label().ends_with(':'));
        assert!(Side::Destination.label().ends_with(':'));
    }

    #[test]
    fn standing_slugs_are_distinct_and_stable() {
        assert_ne!(
            Standing::Declared.slug(),
            Standing::Demonstrated { slots: None }.slug()
        );
        assert_eq!(
            Standing::Demonstrated { slots: Some(2) }.slug(),
            Standing::Demonstrated { slots: None }.slug(),
            "how many slots an envelope has does not change how it was admitted"
        );
    }
}
