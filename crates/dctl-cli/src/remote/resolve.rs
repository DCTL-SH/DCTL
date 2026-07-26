//! Resolving a parsed spec against the configured remotes.
//!
//! [`super::spec`] decides *whether* an argument names a remote; this decides
//! **which** remote that is and what it needs to connect. The two are separate
//! because they fail differently: a malformed spec is a usage error the user can
//! see in their own command line, while an unknown remote or a half-filled
//! config section is a configuration error whose fix is in a file somewhere else
//! (`PLAN.md` §7 — every failure carries the remediation that matches it).
//!
//! ## Resolution order
//!
//! 1. A **configured remote** of that name always wins. Naming a remote `s3`
//!    shadows the provider shorthand below, which is the right precedence: an
//!    explicit definition beats a convention.
//! 2. Otherwise, a name that *is* a provider type resolves as a **shorthand**
//!    for it — `b2:my-bucket`, `s3:my-bucket/prefix`. This keeps the pre-config
//!    behaviour of the CLI working: a headless job with nothing but exported
//!    credentials needs no config file at all (`PLAN.md` §14).
//! 3. Otherwise the remote is unknown, and that is a hard failure. It is never
//!    reinterpreted as a local path — by the time resolution runs, [`super::spec`]
//!    has already ruled that out, and quietly writing to a directory named
//!    `vault:photos` in the current working directory would be a data-loss bug
//!    wearing a convenience's clothes.
//!
//! In the shorthand form the first path component is the container: `b2:bucket`
//! addresses the bucket's root and `b2:bucket/photos/2024` addresses a prefix
//! inside it. A single-component shorthand therefore means exactly what it meant
//! before this module existed, and the multi-component form — which used to
//! produce a bucket named `bucket/photos` and a guaranteed 404 — now works.
//!
//! ## Why the config arrives through a trait
//!
//! [`RemoteCatalog`] is the whole interface to the configuration. Resolution
//! stays a pure function of (spec, catalog), so its tests are a `BTreeMap`
//! literal rather than a temporary directory and a TOML file, and the config
//! layer keeps sole ownership of parsing, precedence and file permissions.

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;

use crate::constants::{
    CONFIG_KEY_ACCOUNT, CONFIG_KEY_BASE, CONFIG_KEY_BUCKET, CONFIG_KEY_ENDPOINT, CONFIG_KEY_PATH,
    CONFIG_KEY_REGION, CONFIG_REMOTE_TYPE_KEY, PATH_SEPARATOR, PROVIDER_B2, PROVIDER_LOCAL,
    PROVIDER_R2, PROVIDER_S3, PROVIDER_VAULT, REMOTE_PROVIDER_TYPES,
};
use crate::error::{CliError, Result};

use super::registry::Target;
use super::spec::RemoteSpec;

/// One remote as the configuration file describes it.
///
/// A provider type plus its non-secret settings, deliberately untyped: the
/// config layer reads whatever keys a human wrote, and this module is where
/// those keys become a checked [`Target`]. Keeping the two apart means an
/// unknown key is diagnosed once, here, instead of being silently ignored by a
/// `serde` struct that had no field for it.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct RemoteEntry {
    /// The section's `type` key — one of [`REMOTE_PROVIDER_TYPES`].
    pub provider: String,
    /// Every other key in the section, as written.
    pub settings: BTreeMap<String, String>,
}

impl RemoteEntry {
    // The two builders below are `cfg(test)`. Nothing in a running command
    // assembles an entry: entries come *out* of a configuration file, through
    // whichever `RemoteCatalog` the command is holding, already spelled by a
    // human. A production caller building one by hand would be inventing a
    // configuration section that no file contains, which is how a remote comes
    // to resolve differently from the way it reads on disk. Tests need exactly
    // that, though — a map literal instead of a TOML fixture is what keeps
    // resolution testable without a filesystem.

    /// Start an entry for a provider type.
    #[cfg(test)]
    #[must_use]
    pub fn new(provider: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            settings: BTreeMap::new(),
        }
    }

    /// Add a setting, builder-style.
    #[cfg(test)]
    #[must_use]
    pub fn with_setting(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.settings.insert(key.into(), value.into());
        self
    }

    /// A setting's value, treating an empty one as absent.
    ///
    /// `endpoint = ""` in a TOML file is a key someone started filling in and
    /// did not finish. Honouring it would send a request to the empty string and
    /// surface as a parse error from deep inside an HTTP client; treating it as
    /// unset lets the environment fall-back and the "required setting missing"
    /// message do their jobs.
    #[must_use]
    pub fn setting(&self, key: &str) -> Option<&str> {
        self.settings
            .get(key)
            .map(String::as_str)
            .filter(|value| !value.is_empty())
    }
}

/// Shows the provider and which keys are set, never their values.
///
/// The config file holds no secrets by design, but a user is free to paste one
/// into it anyway, and a `Debug` derive would then put it in every `--dump
/// config` capture attached to a support ticket. Redaction is mandatory
/// (`PLAN.md` §7), so it is not left to the caller to remember.
impl fmt::Debug for RemoteEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteEntry")
            .field(CONFIG_REMOTE_TYPE_KEY, &self.provider)
            .field("settings", &self.settings.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// Anything that can answer "what is the remote called `name`?".
///
/// Implemented by the configuration, and by a plain map in tests. Lookup is by
/// exact name: the spec parser has already applied Unicode NFC to it, so an
/// implementation whose keys come from a file must normalise them the same way
/// or an accented remote name will be found on one platform and not another.
pub trait RemoteCatalog {
    /// The named remote's definition, or `None` if there is no such section.
    fn lookup(&self, name: &str) -> Option<RemoteEntry>;
}

/// Lets a `&Config` be passed wherever a catalog is expected, so callers do not
/// have to clone or deref by hand.
impl<C: RemoteCatalog + ?Sized> RemoteCatalog for &C {
    fn lookup(&self, name: &str) -> Option<RemoteEntry> {
        (**self).lookup(name)
    }
}

/// A map is a catalog. `BTreeMap` specifically, because the same ordering that
/// makes `dctl config list` deterministic makes a test's expectations stable.
impl RemoteCatalog for BTreeMap<String, RemoteEntry> {
    fn lookup(&self, name: &str) -> Option<RemoteEntry> {
        self.get(name).cloned()
    }
}

/// The empty catalog, for a run with no configuration file.
///
/// Spelled `()` so that `resolve(&spec, &())` reads as "resolve against
/// nothing". Only the provider shorthands resolve against it, which is exactly
/// the headless case: credentials in the environment, no config on disk.
impl RemoteCatalog for () {
    fn lookup(&self, _name: &str) -> Option<RemoteEntry> {
        None
    }
}

/// A spec with its provider decided and its settings checked.
///
/// Carries the remote's *name* alongside the target because every log record and
/// error message downstream needs it: `provider=b2` does not tell an operator
/// which of their three B2 remotes was involved, and `remote=archive` does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolved {
    name: String,
    target: Target,
    path: String,
}

impl Resolved {
    /// Assemble a resolved remote.
    ///
    /// Public so commands and their tests can construct one directly — driving
    /// a command against a temporary directory must not require a config file.
    #[must_use]
    pub fn new(name: impl Into<String>, target: Target, path: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            target,
            path: path.into(),
        }
    }

    /// The remote's name, for the `remote` log field and error messages.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// What to connect to. Consumed by [`super::registry::build`].
    #[must_use]
    pub const fn target(&self) -> &Target {
        &self.target
    }

    /// The logical path inside the remote; `""` addresses its root.
    ///
    /// For a local remote this is empty and the whole path lives in the target's
    /// root, because a filesystem backend is rooted at a directory rather than
    /// at a bucket that a prefix hangs off.
    ///
    /// `cfg(test)` for now, and the reason is worth knowing: both production
    /// routes through this module —
    /// [`build_backend`](super::registry::build_backend) for `dctl init`, and
    /// `crate::session::open` for the transfer family — resolve a spec and then
    /// **discard the path**, because all either one keeps is a backend. Every
    /// command therefore addresses a remote's root today. The accessor is how
    /// the resolver's own tests prove the path was split off correctly, and it
    /// is what a command will read the day one keeps its `Resolved`.
    #[cfg(test)]
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The provider type, as the config file spells it.
    ///
    /// Test-only: production reads it off the [`Target`] directly, at the one
    /// place that logs it. Kept here because the resolver's tests assert *which
    /// provider a spec resolved to*, which is the whole output of resolution and
    /// cannot be checked through a backend without credentials.
    #[cfg(test)]
    #[must_use]
    pub const fn provider_type(&self) -> &'static str {
        self.target.provider_type()
    }
}

/// Resolve a parsed spec against the configured remotes.
pub fn resolve<C: RemoteCatalog + ?Sized>(spec: &RemoteSpec, catalog: &C) -> Result<Resolved> {
    match spec {
        // A filesystem path needs no configuration and no credentials: the root
        // is the path itself, and the logical path inside it is empty.
        RemoteSpec::Local(root) => Ok(Resolved::new(
            PROVIDER_LOCAL,
            Target::Local { root: root.clone() },
            String::new(),
        )),

        RemoteSpec::Named { remote, path } => match catalog.lookup(remote) {
            Some(entry) => Ok(Resolved::new(
                remote,
                target_from_entry(remote, &entry)?,
                path.clone(),
            )),
            None => shorthand(remote, path),
        },
    }
}

/// Build a target from a configured remote's settings, checking that each
/// provider got the ones it cannot work without.
fn target_from_entry(name: &str, entry: &RemoteEntry) -> Result<Target> {
    match entry.provider.as_str() {
        PROVIDER_LOCAL => Ok(Target::Local {
            root: PathBuf::from(required(name, entry, CONFIG_KEY_PATH)?),
        }),

        PROVIDER_B2 => Ok(Target::B2 {
            bucket: required(name, entry, CONFIG_KEY_BUCKET)?.to_string(),
        }),

        PROVIDER_S3 => Ok(Target::S3 {
            bucket: required(name, entry, CONFIG_KEY_BUCKET)?.to_string(),
            endpoint: entry.setting(CONFIG_KEY_ENDPOINT).map(str::to_string),
            region: entry.setting(CONFIG_KEY_REGION).map(str::to_string),
        }),

        PROVIDER_R2 => Ok(Target::R2 {
            bucket: required(name, entry, CONFIG_KEY_BUCKET)?.to_string(),
            account: entry.setting(CONFIG_KEY_ACCOUNT).map(str::to_string),
        }),

        // A legal `type` that is deliberately not a provider. Diagnosed on its
        // own rather than falling into "unknown type", which would be untrue and
        // would send the user looking for a typo they did not make: a vault
        // remote stores nothing itself, it encrypts on the way through to the
        // remote it wraps (`PLAN.md` §14).
        PROVIDER_VAULT => Err(CliError::fatal(format!(
            "remote '{name}' is a {PROVIDER_VAULT} wrapper, which stores nothing itself"
        ))
        .with_hint(match entry.setting(CONFIG_KEY_BASE) {
            Some(base) => format!(
                "It wraps '{base}'. Encryption is applied above the backend, so \
                 the registry builds '{base}' and never '{name}' directly."
            ),
            None => format!(
                "A vault remote needs a '{CONFIG_KEY_BASE}' setting naming the \
                 remote it wraps; encryption is applied above that backend."
            ),
        })),

        other => Err(CliError::fatal(format!(
            "remote '{name}' has unknown {CONFIG_REMOTE_TYPE_KEY} '{other}'"
        ))
        .with_hint(format!(
            "Supported types are {}. Run `dctl config providers` for what each one is.",
            provider_list()
        ))),
    }
}

/// Resolve a name that is not in the config but is a provider type.
///
/// The container — bucket — is the first component of the path, and everything
/// after it is a prefix inside that container.
fn shorthand(name: &str, path: &str) -> Result<Resolved> {
    // Reachable only if a spec was built by hand, since `local:` is turned into
    // a plain path by the parser. Handled anyway, and identically: the whole
    // remainder is the root directory.
    if name == PROVIDER_LOCAL {
        return Ok(Resolved::new(
            name,
            Target::Local {
                root: PathBuf::from(path),
            },
            String::new(),
        ));
    }

    let (container, prefix) = path.split_once(PATH_SEPARATOR).unwrap_or((path, ""));

    let target = match name {
        PROVIDER_B2 => Target::B2 {
            bucket: bucket(name, container)?,
        },
        PROVIDER_S3 => Target::S3 {
            bucket: bucket(name, container)?,
            endpoint: None,
            region: None,
        },
        PROVIDER_R2 => Target::R2 {
            bucket: bucket(name, container)?,
            account: None,
        },
        other => {
            return Err(
                CliError::fatal(format!("unknown remote '{other}'")).with_hint(format!(
                    "Run `dctl config list` to see configured remotes, or address a \
                     provider directly as one of {}.",
                    provider_list()
                )),
            );
        }
    };

    Ok(Resolved::new(name, target, prefix))
}

/// The bucket named by a shorthand spec, refusing the empty one.
///
/// `b2:` on its own says "some bucket" and means nothing; failing here is far
/// better than sending an unauthenticated request to a bucket named `""`.
fn bucket(name: &str, container: &str) -> Result<String> {
    if container.is_empty() {
        return Err(
            CliError::fatal(format!("'{name}' needs a bucket name")).with_hint(format!(
                "Write it as '{name}:BUCKET' or '{name}:BUCKET/prefix', or define a \
                 named remote with `dctl config`."
            )),
        );
    }
    Ok(container.to_string())
}

/// A setting a provider cannot work without.
fn required<'a>(name: &str, entry: &'a RemoteEntry, key: &str) -> Result<&'a str> {
    entry.setting(key).ok_or_else(|| {
        CliError::fatal(format!(
            "remote '{name}' ({}) has no '{key}' setting",
            entry.provider
        ))
        .with_hint(format!("Set it with `dctl config set {name} {key}=VALUE`."))
    })
}

/// The advertised provider types, for a hint. Derived from the table rather than
/// written out, so a new provider appears in every message that lists them.
fn provider_list() -> String {
    REMOTE_PROVIDER_TYPES
        .iter()
        .map(|(name, _)| *name)
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exit::ExitCode;

    fn catalog(entries: &[(&str, RemoteEntry)]) -> BTreeMap<String, RemoteEntry> {
        entries
            .iter()
            .map(|(name, entry)| ((*name).to_string(), entry.clone()))
            .collect()
    }

    fn resolve_str<C: RemoteCatalog + ?Sized>(input: &str, catalog: &C) -> Result<Resolved> {
        resolve(&RemoteSpec::parse(input)?, catalog)
    }

    #[test]
    fn a_local_path_resolves_with_no_config_and_no_credentials() {
        let resolved = resolve_str("/srv/data", &()).unwrap();
        assert_eq!(resolved.provider_type(), PROVIDER_LOCAL);
        assert_eq!(
            resolved.target(),
            &Target::Local {
                root: PathBuf::from("/srv/data")
            }
        );
        // The whole path is the root; nothing hangs off it as a prefix.
        assert!(resolved.path().is_empty());
    }

    #[test]
    fn a_drive_letter_path_never_becomes_a_remote_lookup() {
        // The end-to-end version of the module's reason for existing: even with
        // a remote genuinely called `C` in the config, `C:\Users\me` is a path.
        let config = catalog(&[(
            "C",
            RemoteEntry::new(PROVIDER_B2).with_setting(CONFIG_KEY_BUCKET, "wrong"),
        )]);
        let resolved = resolve_str(r"C:\Users\me", &config).unwrap();
        assert_eq!(resolved.provider_type(), PROVIDER_LOCAL);
        assert_eq!(
            resolved.target(),
            &Target::Local {
                root: PathBuf::from(r"C:\Users\me")
            }
        );
    }

    #[test]
    fn a_configured_remote_supplies_its_settings() {
        let config = catalog(&[(
            "archive",
            RemoteEntry::new(PROVIDER_B2).with_setting(CONFIG_KEY_BUCKET, "cold-storage"),
        )]);
        let resolved = resolve_str("archive:photos/2024", &config).unwrap();
        assert_eq!(resolved.name(), "archive");
        assert_eq!(
            resolved.target(),
            &Target::B2 {
                bucket: "cold-storage".into()
            }
        );
        assert_eq!(resolved.path(), "photos/2024");
    }

    #[test]
    fn a_local_remote_roots_logical_paths_at_its_directory() {
        let config = catalog(&[(
            "scratch",
            RemoteEntry::new(PROVIDER_LOCAL).with_setting(CONFIG_KEY_PATH, "/mnt/scratch"),
        )]);
        let resolved = resolve_str("scratch:photos/a.jpg", &config).unwrap();
        assert_eq!(
            resolved.target(),
            &Target::Local {
                root: PathBuf::from("/mnt/scratch")
            }
        );
        // Unlike a bare path, the logical path survives: it is addressed inside
        // the remote rather than being part of the root.
        assert_eq!(resolved.path(), "photos/a.jpg");
    }

    #[test]
    fn optional_settings_are_carried_through_and_empty_ones_are_not() {
        let config = catalog(&[(
            "minio",
            RemoteEntry::new(PROVIDER_S3)
                .with_setting(CONFIG_KEY_BUCKET, "media")
                .with_setting(CONFIG_KEY_ENDPOINT, "https://minio.internal")
                .with_setting(CONFIG_KEY_REGION, ""),
        )]);
        let resolved = resolve_str("minio:", &config).unwrap();
        assert_eq!(
            resolved.target(),
            &Target::S3 {
                bucket: "media".into(),
                endpoint: Some("https://minio.internal".into()),
                // A half-typed key must not become an empty signing region: the
                // environment fall-back has to stay reachable.
                region: None,
            }
        );
    }

    #[test]
    fn a_configured_remote_shadows_the_provider_shorthand() {
        // An explicit definition beats a convention, so someone who names a
        // remote `s3` gets their remote and not the shorthand.
        let config = catalog(&[(
            PROVIDER_S3,
            RemoteEntry::new(PROVIDER_B2).with_setting(CONFIG_KEY_BUCKET, "actually-b2"),
        )]);
        let resolved = resolve_str("s3:anything", &config).unwrap();
        assert_eq!(
            resolved.target(),
            &Target::B2 {
                bucket: "actually-b2".into()
            }
        );
        assert_eq!(resolved.path(), "anything");
    }

    #[test]
    fn the_shorthand_keeps_working_with_no_config_at_all() {
        // The headless case from PLAN.md §14: exported credentials, no file.
        let resolved = resolve_str("b2:my-bucket", &()).unwrap();
        assert_eq!(
            resolved.target(),
            &Target::B2 {
                bucket: "my-bucket".into()
            }
        );
        assert!(resolved.path().is_empty());
    }

    #[test]
    fn the_shorthand_splits_the_bucket_from_the_prefix() {
        // The single-component form means what it always meant; the longer form
        // used to produce a bucket named `my-bucket/photos` and a certain 404.
        let resolved = resolve_str("s3:my-bucket/photos/2024", &()).unwrap();
        assert_eq!(
            resolved.target(),
            &Target::S3 {
                bucket: "my-bucket".into(),
                endpoint: None,
                region: None,
            }
        );
        assert_eq!(resolved.path(), "photos/2024");
    }

    #[test]
    fn every_provider_shorthand_resolves() {
        assert_eq!(
            resolve_str("b2:bucket", &()).unwrap().provider_type(),
            PROVIDER_B2
        );
        assert_eq!(
            resolve_str("s3:bucket", &()).unwrap().provider_type(),
            PROVIDER_S3
        );
        assert_eq!(
            resolve_str("r2:bucket", &()).unwrap().provider_type(),
            PROVIDER_R2
        );
        // `local:` is turned into a path by the parser, one step earlier.
        assert_eq!(
            resolve_str("local:/srv/data", &()).unwrap().provider_type(),
            PROVIDER_LOCAL
        );
    }

    #[test]
    fn a_bucketless_shorthand_is_refused() {
        let error = resolve_str("b2:", &()).unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.hint().is_some_and(|hint| hint.contains("BUCKET")));
    }

    #[test]
    fn an_unknown_remote_fails_instead_of_becoming_a_directory() {
        // The dangerous alternative: silently treating `vault:photos` as a
        // relative directory would write a backup into the working directory and
        // report success.
        let error = resolve_str("vault:photos", &()).unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.message().contains("vault"));
        assert!(
            error
                .hint()
                .is_some_and(|hint| hint.contains("config list"))
        );
    }

    #[test]
    fn a_remote_missing_a_required_setting_says_which_one() {
        let config = catalog(&[("archive", RemoteEntry::new(PROVIDER_B2))]);
        let error = resolve_str("archive:x", &config).unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.message().contains(CONFIG_KEY_BUCKET));
        assert!(error.hint().is_some_and(|hint| hint.contains("archive")));
    }

    #[test]
    fn an_empty_required_setting_counts_as_missing() {
        let config = catalog(&[(
            "archive",
            RemoteEntry::new(PROVIDER_B2).with_setting(CONFIG_KEY_BUCKET, ""),
        )]);
        assert!(resolve_str("archive:x", &config).is_err());
    }

    #[test]
    fn a_remote_of_an_unknown_type_lists_the_supported_ones() {
        let config = catalog(&[("future", RemoteEntry::new("gdrive"))]);
        let error = resolve_str("future:x", &config).unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.message().contains("gdrive"));
        assert!(error.hint().is_some_and(|hint| hint.contains(PROVIDER_B2)));
    }

    #[test]
    fn a_vault_remote_is_diagnosed_as_a_wrapper_not_as_a_typo() {
        // `vault` is a legal type the config accepts, so "unknown type" would be
        // a lie that sends the user hunting for a spelling mistake.
        let config = catalog(&[(
            "vault",
            RemoteEntry::new(PROVIDER_VAULT).with_setting(CONFIG_KEY_BASE, "b2prod"),
        )]);
        let error = resolve_str("vault:photos", &config).unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(!error.message().contains("unknown"));
        // The hint has to name the remote that does hold the bytes.
        assert!(error.hint().is_some_and(|hint| hint.contains("b2prod")));
    }

    #[test]
    fn a_vault_remote_with_no_base_says_which_setting_is_missing() {
        let config = catalog(&[("vault", RemoteEntry::new(PROVIDER_VAULT))]);
        let error = resolve_str("vault:", &config).unwrap_err();
        assert!(
            error
                .hint()
                .is_some_and(|hint| hint.contains(CONFIG_KEY_BASE))
        );
    }

    #[test]
    fn the_debug_rendering_shows_keys_but_never_values() {
        // A user who pastes a secret into the config file must not have it
        // echoed into a `--dump config` capture.
        let entry = RemoteEntry::new(PROVIDER_S3)
            .with_setting(CONFIG_KEY_BUCKET, "media")
            .with_setting("secret_key", "AKIAsupersecretvalue");
        let rendered = format!("{entry:?}");
        assert!(rendered.contains(CONFIG_KEY_BUCKET), "keys must be visible");
        assert!(!rendered.contains("AKIAsupersecretvalue"), "a value leaked");
        assert!(!rendered.contains("media"), "a value leaked");
    }

    #[test]
    fn a_reference_to_a_catalog_is_a_catalog() {
        // Lets a command pass `&ctx.config` without cloning or dereferencing.
        let config = catalog(&[(
            "archive",
            RemoteEntry::new(PROVIDER_B2).with_setting(CONFIG_KEY_BUCKET, "cold"),
        )]);
        let by_reference: &BTreeMap<String, RemoteEntry> = &config;
        assert_eq!(
            resolve_str("archive:", &by_reference).unwrap().name(),
            "archive"
        );
    }
}
