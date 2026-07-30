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
    CONFIG_KEY_ACCOUNT, CONFIG_KEY_BASE, CONFIG_KEY_BUCKET, CONFIG_KEY_CHUNK_SIZE,
    CONFIG_KEY_ENDPOINT, CONFIG_KEY_HOST, CONFIG_KEY_PATH, CONFIG_KEY_REGION,
    CONFIG_REMOTE_TYPE_KEY, PATH_SEPARATOR, PROVIDER_B2, PROVIDER_LOCAL, PROVIDER_R2, PROVIDER_S3,
    PROVIDER_SFTP, PROVIDER_VAULT, REMOTE_PROVIDER_TYPES,
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
    /// For a **bare local path** this is empty and the whole path lives in the
    /// target's root, because a filesystem backend is rooted at a directory
    /// rather than at a bucket that a prefix hangs off. For a *named* remote it
    /// is the path inside it, and for a provider shorthand it is what remains
    /// after the bucket: `b2:mybucket/photos` resolves to the bucket `mybucket`
    /// and the path `photos`, so a caller that used the spec's own path as a key
    /// would address `mybucket/photos` *inside* `mybucket`.
    ///
    /// That last sentence is why this is no longer test-only.
    /// [`build_backend`](super::registry::build_backend) and
    /// `crate::session::open` still discard it — all either keeps is a backend,
    /// which is the gap `commands::transfer::engine` documents — but
    /// [`super::place`] keeps its `Resolved` precisely so a write lands under the
    /// prefix the user named rather than at the remote's root.
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
            chunk_size: chunk_size(name, entry)?,
        }),

        PROVIDER_S3 => Ok(Target::S3 {
            bucket: required(name, entry, CONFIG_KEY_BUCKET)?.to_string(),
            endpoint: entry.setting(CONFIG_KEY_ENDPOINT).map(str::to_string),
            region: entry.setting(CONFIG_KEY_REGION).map(str::to_string),
            chunk_size: chunk_size(name, entry)?,
        }),

        PROVIDER_R2 => Ok(Target::R2 {
            bucket: required(name, entry, CONFIG_KEY_BUCKET)?.to_string(),
            account: entry.setting(CONFIG_KEY_ACCOUNT).map(str::to_string),
            chunk_size: chunk_size(name, entry)?,
        }),

        // Both are required and neither has an environment fall-back: an sftp
        // remote holds no credential, and a host or base left unset is a broken
        // remote, not one the environment can complete.
        //
        // The base is re-read through the one rule rather than taken as written,
        // so a configuration carrying the old ambiguous spelling — `base=store`,
        // which meant `$HOME/store` here and `/store` through the shorthand — is
        // diagnosed on the way in instead of silently addressing one of the two.
        // The message names the one-character fix.
        PROVIDER_SFTP => Ok(Target::Sftp {
            host: required(name, entry, CONFIG_KEY_HOST)?.to_string(),
            base: crate::remote::sftp_base::from_setting(required(name, entry, CONFIG_KEY_BASE)?)?,
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

    // An sftp shorthand is `sftp:host/base-dir`: the first component is the ssh
    // destination and the *entire* remainder is the base directory, so nothing is
    // left over as a logical path. Unlike a bucket shorthand, it cannot split a
    // prefix off the end — there is no way to tell where the base directory stops
    // and a path inside it begins — so a path within an sftp remote is addressed
    // through a named remote (`dctl config create NAME sftp host=… base=…`), where
    // the two are separate settings and unambiguous. This is the form
    // `dctl init --base sftp:host/dir` and a headless `DCTL_REMOTE` use.
    //
    // The split is [`crate::remote::sftp_base`]'s, not a second copy of it: this
    // path and `dctl init`'s used to be two implementations of "where does the
    // host stop", and they disagreed about whether the separating slash belonged
    // to the base — which is exactly how one string came to name two directories.
    if name == PROVIDER_SFTP {
        let (host, base) = crate::remote::sftp_base::from_spec(&format!("{name}:{path}"), path)?;
        return Ok(Resolved::new(
            name,
            Target::Sftp { host, base },
            String::new(),
        ));
    }

    let (container, prefix) = path.split_once(PATH_SEPARATOR).unwrap_or((path, ""));

    let target = match name {
        PROVIDER_B2 => Target::B2 {
            bucket: bucket(name, container)?,
            chunk_size: None,
        },
        PROVIDER_S3 => Target::S3 {
            bucket: bucket(name, container)?,
            endpoint: None,
            region: None,
            chunk_size: None,
        },
        PROVIDER_R2 => Target::R2 {
            bucket: bucket(name, container)?,
            account: None,
            chunk_size: None,
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
///
/// The hint names `config update`, which is the verb that exists. It said
/// `config set` until the check in [`crate::cli`] read it back against the
/// parser: nothing has ever answered to `set`, so the one instruction given to
/// somebody whose remote will not resolve was itself unrunnable.
fn required<'a>(name: &str, entry: &'a RemoteEntry, key: &str) -> Result<&'a str> {
    entry.setting(key).ok_or_else(|| {
        CliError::fatal(format!(
            "remote '{name}' ({}) has no '{key}' setting",
            entry.provider
        ))
        .with_hint(format!(
            "Set it with `dctl config update {name} {key}=VALUE`."
        ))
    })
}

/// The `chunk_size` setting, if a remote declares one.
///
/// Returns a *refusal* for a value that is not a positive whole number of bytes,
/// rather than falling back to the default. This setting was inert until this
/// pass — declared in the file, documented in `config providers`, and read by
/// nothing — so the one thing it must not now do is accept a mistyped value and
/// quietly use a different one. `chunk_size = "8MB"` is a fault in the file, and
/// a fault in the file is worth a message naming the key.
///
/// # Errors
/// [`crate::exit::ExitCode::FatalError`] naming the remote and the value.
fn chunk_size(name: &str, entry: &RemoteEntry) -> Result<Option<u64>> {
    let Some(written) = entry.setting(CONFIG_KEY_CHUNK_SIZE) else {
        return Ok(None);
    };
    match written.trim().parse::<u64>() {
        Ok(0) | Err(_) => Err(CliError::fatal(format!(
            "remote '{name}' has {CONFIG_KEY_CHUNK_SIZE} = '{written}', which is not a \
             positive number of bytes"
        ))
        .with_hint(format!(
            "Write it as plain bytes, for example \
             `dctl config update {name} {CONFIG_KEY_CHUNK_SIZE}=8388608` for 8 MiB. \
             The provider's own minimum and maximum still apply and the value is \
             clamped into them."
        ))),
        Ok(size) => Ok(Some(size)),
    }
}

/// The logical prefix `spec` addresses **inside the store that holds its bytes**.
///
/// ## The defect this closes
///
/// A provider shorthand carries two things in one path: `b2:DCTL001/photos` names
/// the *bucket* `DCTL001` and the *prefix* `photos` inside it. [`resolve`] splits
/// them — that is what [`Resolved::path`] is — but every read-side verb took its
/// prefix from the spec instead, so `dctl ls b2:DCTL001` enumerated keys under
/// `DCTL001/` **inside the bucket `DCTL001`** and found nothing. The consequence
/// is not a cosmetic empty listing: a `sync` to `b2:DCTL001` reads an empty
/// destination on every run and re-uploads the whole dataset, forever
/// (`HANDOVER.md` §11.3 item 6).
///
/// One function rather than a rule each verb applies, because there were nine
/// call sites and they all applied the same wrong one. [`crate::source::open`]
/// now hands this back beside the source, so a caller cannot reach for
/// `spec.path()` — the value it would have to use is not in its hand.
///
/// ## Why a vault answers differently, and why that is not an exception
///
/// A vault remote resolves to no [`Target`] at all: it stores nothing, and
/// [`crate::session::open`] follows the chain to the object store beneath it. Its
/// path is a logical path in the **vault's own namespace**, which no bucket split
/// applies to — `archive:photos` addresses `photos` in the vault, whatever the
/// bucket underneath is called. So the answer is the spec's path, and it is the
/// same rule stated once: *the prefix is the one that addresses inside whatever
/// this read will actually enumerate*.
///
/// # Errors
/// Whatever [`resolve`] reported — an unknown remote, a missing required setting,
/// a malformed `chunk_size`. A read that cannot say where it would look must not
/// guess, because guessing produces an empty listing and an empty listing is a
/// conclusion people act on.
pub fn logical_prefix<C: RemoteCatalog + ?Sized>(spec: &RemoteSpec, catalog: &C) -> Result<String> {
    match spec {
        // A bare path is its own root; there is nothing left over to scope by.
        RemoteSpec::Local(_) => Ok(String::new()),
        RemoteSpec::Named { remote, path } => {
            if catalog
                .lookup(remote)
                .is_some_and(|entry| entry.provider == PROVIDER_VAULT)
            {
                return Ok(path.clone());
            }
            Ok(resolve(spec, catalog)?.path().to_string())
        }
    }
}

/// The address of the *thing that gets opened*, as distinct from the scope
/// inside it.
///
/// `b2:DCTL001/photos` opens the bucket `DCTL001` and scopes a read to `photos`;
/// the container is `b2:DCTL001`. For every other spec shape resolution consumes
/// nothing from the path, so the container is the remote itself and the whole
/// path is the scope.
///
/// Derived from `prefix` rather than computed a second way, because two
/// independent answers to "how much of this path was the container" is precisely
/// how the bucket came to be counted twice. `prefix` is a suffix of the spec's
/// path by construction on both branches of [`logical_prefix`]; a value that is
/// not is treated as consuming nothing, which over-shares a cache entry rather
/// than addressing the wrong bucket.
///
/// The one caller that needs it is `dctl cat`, which opens each argument's remote
/// once per *container*: two arguments in one vault must not unlock it twice, and
/// two arguments in two buckets of one provider must not share a client.
#[must_use]
pub fn container(spec: &RemoteSpec, prefix: &str) -> String {
    match spec {
        RemoteSpec::Local(path) => path.display().to_string(),
        RemoteSpec::Named { remote, path } => {
            let consumed = path
                .strip_suffix(prefix)
                .unwrap_or_default()
                .trim_end_matches(PATH_SEPARATOR);
            format!("{remote}{}{consumed}", crate::constants::REMOTE_SEPARATOR)
        }
    }
}

/// The `chunk_size` of a **vault** remote — the setting that reaches the sealer.
///
/// A vault remote resolves to no [`Target`] of its own: it stores nothing, and
/// [`crate::session::open`] follows its chain to the object store underneath and
/// builds *that*. So the vault's own settings have no `Target` field to travel in,
/// and this is the seam where the one that matters is picked up instead.
///
/// It goes through the same [`chunk_size`] parser every other provider's does, so
/// a mistyped value on a vault is refused with the same message rather than
/// quietly defaulted — which is the failure mode a newly-wired setting must not
/// have, because it is indistinguishable from the inert behaviour it replaced.
///
/// [`None`] for anything that is not a configured vault remote: a bare path, a
/// provider shorthand, or a named remote that is an object store. Those have no
/// sealer to configure.
///
/// # Errors
/// [`crate::exit::ExitCode::FatalError`] for a value that is not a positive whole
/// number of bytes, naming the remote and the value.
pub fn vault_chunk_size<C: RemoteCatalog + ?Sized>(
    spec: &RemoteSpec,
    catalog: &C,
) -> Result<Option<u64>> {
    let RemoteSpec::Named { remote, .. } = spec else {
        return Ok(None);
    };
    let Some(entry) = catalog.lookup(remote) else {
        return Ok(None);
    };
    if entry.provider != PROVIDER_VAULT {
        return Ok(None);
    }
    chunk_size(remote, &entry)
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

    /// Providers whose `chunk_size` setting reaches the backend that stores the
    /// bytes, and providers whose does not.
    ///
    /// `chunk_size` is declared on four provider definitions in
    /// [`crate::config::model`] and was read by **nothing**: an operator could
    /// write `chunk_size = 8388608`, see it in `dctl config show`, and have every
    /// upload cut at the compiled-in default anyway. That is the §13 defect —
    /// a setting that parses, is documented, and reaches nothing — on the
    /// configuration surface rather than the flag surface, where the standing
    /// guard does not look.
    ///
    /// Two are wired here. Two are not, and the point of this table is that they
    /// are *declared* not to be rather than silently so: adding a provider that
    /// carries the setting without carrying it through fails
    /// [`chunk_size_is_either_carried_to_the_backend_or_listed_as_inert`], which
    /// says which list to add it to and what that costs.
    const CHUNK_SIZE_HONOURED: &[&str] = &[PROVIDER_S3, PROVIDER_R2, PROVIDER_B2];

    /// The provider whose `chunk_size` reaches the *sealer* rather than a
    /// `Target`, and therefore cannot be checked by the loop above.
    ///
    /// A vault remote resolves to no target of its own — it stores nothing, and
    /// the chain is followed to the object store beneath it — so its setting
    /// travels through [`vault_chunk_size`] instead, and is asserted by
    /// [`a_vaults_chunk_size_is_read_from_its_own_remote`] and, at the far end,
    /// by `dctl_core`'s own `clamp_chunk_size`.
    const CHUNK_SIZE_VIA_THE_SEALER: &[&str] = &[crate::constants::PROVIDER_VAULT];

    /// `chunk_size` on these providers is accepted by the parser and reaches
    /// nothing.
    ///
    /// One remains, and naming it is the whole point of this table: **sftp**.
    /// Its streaming transfer window is the compiled-in `CHUNK_LEN` in
    /// `dctl_store::sftp`, which the setting does not reach. It costs less than
    /// the two that have been wired — an sftp write's peak is one window of the
    /// streaming pipe now, not one of these chunks — so it is declared inert
    /// rather than half-wired, and it is on the pre-production list in
    /// `HANDOVER.md` §11.3 rather than quietly left for somebody to measure.
    ///
    /// B2 left this list in §25 and the vault left it in §27. Both had to: on B2
    /// the part size *is* an upload's peak memory, and on a vault the chunk size
    /// is two terms of it.
    const CHUNK_SIZE_INERT: &[&str] = &[crate::constants::PROVIDER_SFTP];

    #[test]
    fn chunk_size_is_either_carried_to_the_backend_or_listed_as_inert() {
        for provider in CHUNK_SIZE_HONOURED {
            let entry = RemoteEntry::new(*provider)
                .with_setting(CONFIG_KEY_BUCKET, "b")
                .with_setting(CONFIG_KEY_ACCOUNT, "acct")
                .with_setting(CONFIG_KEY_CHUNK_SIZE, "8388608");
            let target = target_from_entry("r", &entry).expect("the remote resolves");
            let carried = match target {
                Target::S3 { chunk_size, .. }
                | Target::R2 { chunk_size, .. }
                | Target::B2 { chunk_size, .. } => chunk_size,
                other => panic!("'{provider}' resolved to {other:?}"),
            };
            assert_eq!(
                carried,
                Some(8_388_608),
                "'{provider}' claims to honour chunk_size and drops it"
            );
        }

        // The rest are named, so nobody has to rediscover where a setting goes by
        // measuring an upload.
        for provider in CHUNK_SIZE_INERT.iter().chain(CHUNK_SIZE_VIA_THE_SEALER) {
            assert!(
                !CHUNK_SIZE_HONOURED.contains(provider),
                "'{provider}' is in two lists"
            );
        }
        for provider in CHUNK_SIZE_INERT {
            assert!(
                !CHUNK_SIZE_VIA_THE_SEALER.contains(provider),
                "'{provider}' is in two lists"
            );
        }
        // **Five**, not four. This count was wrong: `SftpDef` declares
        // `chunk_size` exactly as the other four do, and it was in neither list,
        // so the one guard meant to stop a setting being silently inert had
        // itself lost one. `RemoteDef::chunk_size` is the fold that decides, and
        // it has five arms that answer with a value.
        assert_eq!(
            CHUNK_SIZE_HONOURED.len() + CHUNK_SIZE_VIA_THE_SEALER.len() + CHUNK_SIZE_INERT.len(),
            5,
            "five provider definitions declare chunk_size; every one has to be in \
             exactly one of these lists"
        );
    }

    /// The resolver's end of a vault's `chunk_size` journey.
    ///
    /// Half of §11.3 item 8, and the half that is checked here because the middle
    /// is where this project has lost a setting before (§21.7). The other end —
    /// that the number reaches the sealer and is clamped into the format's
    /// envelope — is `dctl_core::vault::chunking`, and `session::open` is the one
    /// line between them.
    #[test]
    fn a_vaults_chunk_size_is_read_from_its_own_remote() {
        let configured = catalog(&[
            (
                "archive",
                RemoteEntry::new(crate::constants::PROVIDER_VAULT)
                    .with_setting(CONFIG_KEY_BASE, "archive-store")
                    .with_setting(CONFIG_KEY_CHUNK_SIZE, "262144"),
            ),
            (
                "archive-store",
                RemoteEntry::new(PROVIDER_B2).with_setting(CONFIG_KEY_BUCKET, "b"),
            ),
        ]);

        let spec = RemoteSpec::parse("archive:photos").expect("a well-formed spec");
        assert_eq!(
            vault_chunk_size(&spec, &configured).expect("the setting parses"),
            Some(262_144),
            "a vault's chunk_size must reach the sealer, or an operator's \
             configuration is decoration"
        );

        // The object store underneath is not a vault, so it has no sealer to
        // configure and answers nothing — its own chunk_size travels in its
        // `Target`, which is what the loop above checks.
        let base = RemoteSpec::parse("archive-store:").expect("a well-formed spec");
        assert_eq!(vault_chunk_size(&base, &configured).expect("parses"), None);

        // A vault that pins nothing takes the default, and says so by answering
        // `None` rather than by inventing a number here.
        let unpinned = catalog(&[(
            "plainvault",
            RemoteEntry::new(crate::constants::PROVIDER_VAULT).with_setting(CONFIG_KEY_BASE, "b2x"),
        )]);
        let spec = RemoteSpec::parse("plainvault:").expect("a well-formed spec");
        assert_eq!(vault_chunk_size(&spec, &unpinned).expect("parses"), None);
    }

    #[test]
    fn a_mistyped_vault_chunk_size_is_refused_by_the_same_parser_as_every_other() {
        // The one thing a newly-wired setting must not do is accept a value it
        // cannot use and fall back to the default, which looks exactly like the
        // inert behaviour it replaced. A vault goes through the same function, so
        // it cannot acquire a second, kinder dialect.
        let configured = catalog(&[(
            "archive",
            RemoteEntry::new(crate::constants::PROVIDER_VAULT)
                .with_setting(CONFIG_KEY_BASE, "b2x")
                .with_setting(CONFIG_KEY_CHUNK_SIZE, "256KiB"),
        )]);
        let spec = RemoteSpec::parse("archive:").expect("a well-formed spec");
        let error = vault_chunk_size(&spec, &configured).expect_err("a mistyped size is refused");
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(
            error.message().contains("chunk_size"),
            "{}",
            error.message()
        );
        assert!(error.message().contains("archive"), "{}", error.message());
    }

    #[test]
    fn a_mistyped_chunk_size_is_refused_rather_than_quietly_defaulted() {
        // The one thing a newly-wired setting must not do is accept a value it
        // cannot use and fall back to the default, which would look exactly like
        // the inert behaviour it replaced.
        for written in ["8MB", "0", "-1", "eight"] {
            let entry = RemoteEntry::new(PROVIDER_S3)
                .with_setting(CONFIG_KEY_BUCKET, "b")
                .with_setting(CONFIG_KEY_CHUNK_SIZE, written);
            let error = target_from_entry("r", &entry)
                .expect_err(&format!("'{written}' must be refused, not defaulted"));
            assert!(
                error.message().contains(CONFIG_KEY_CHUNK_SIZE),
                "the message must name the key: {}",
                error.message()
            );
            assert!(error.hint().is_some(), "'{written}' failed without advice");
        }
        // A value the provider will clamp is still accepted here: clamping is
        // the backend's business and happens with the number in hand, so a
        // refusal at this layer would forbid a setting that works.
        let small = RemoteEntry::new(PROVIDER_S3)
            .with_setting(CONFIG_KEY_BUCKET, "b")
            .with_setting(CONFIG_KEY_CHUNK_SIZE, "1024");
        assert!(target_from_entry("r", &small).is_ok());

        // An empty value is *unset*, not malformed — the same rule
        // `endpoint = ""` follows, so a half-typed key keeps the default rather
        // than failing the remote.
        let blank = RemoteEntry::new(PROVIDER_S3)
            .with_setting(CONFIG_KEY_BUCKET, "b")
            .with_setting(CONFIG_KEY_CHUNK_SIZE, "");
        assert!(matches!(
            target_from_entry("r", &blank).expect("an empty setting is unset"),
            Target::S3 {
                chunk_size: None,
                ..
            }
        ));
    }

    #[test]
    fn a_read_is_scoped_by_the_resolvers_prefix_and_never_by_the_specs_path() {
        // `HANDOVER.md` §11.3 item 6. The shorthand's first component is the
        // *bucket*; a read that used the spec's path as its prefix looked for
        // keys under `DCTL001/` inside the bucket `DCTL001` and found none. The
        // cost is not an empty listing — it is a scheduled `sync` that reads an
        // empty destination every night and re-uploads the whole dataset.
        for (written, expected) in [
            ("b2:DCTL001", ""),
            ("b2:DCTL001/photos", "photos"),
            ("b2:DCTL001/photos/2024", "photos/2024"),
            ("s3:media", ""),
            ("s3:media/raw", "raw"),
            ("r2:cold", ""),
            ("r2:cold/2019", "2019"),
        ] {
            let spec = RemoteSpec::parse(written).expect("a well-formed spec");
            assert_eq!(
                logical_prefix(&spec, &()).expect("a shorthand resolves"),
                expected,
                "'{written}' is enumerated at the wrong prefix"
            );
        }
    }

    #[test]
    fn a_named_remote_and_a_bare_path_keep_the_prefixes_they_always_had() {
        // The other half of the property, and the reason it is stated as one
        // function rather than a special case for buckets: a named remote's path
        // *is* the prefix inside it, and a bare path has no prefix at all
        // because the whole path became the root. Getting either of these wrong
        // while fixing the shorthand would move every existing listing.
        let configured = catalog(&[
            (
                "store",
                RemoteEntry::new(PROVIDER_LOCAL).with_setting(CONFIG_KEY_PATH, "/srv/v"),
            ),
            (
                "cold",
                RemoteEntry::new(PROVIDER_B2).with_setting(CONFIG_KEY_BUCKET, "bucket"),
            ),
        ]);

        for (written, expected) in [
            ("store:", ""),
            ("store:photos", "photos"),
            ("store:photos/2024", "photos/2024"),
            // A *named* b2 remote carries its bucket in a setting, so the whole
            // path is the prefix — the exact opposite of the shorthand, which is
            // why this cannot be a rule about the provider.
            ("cold:", ""),
            ("cold:photos", "photos"),
        ] {
            let spec = RemoteSpec::parse(written).expect("a well-formed spec");
            assert_eq!(
                logical_prefix(&spec, &configured).expect("a configured remote resolves"),
                expected,
                "'{written}'"
            );
        }

        let bare = RemoteSpec::parse("/srv/photos").expect("a well-formed spec");
        assert_eq!(
            logical_prefix(&bare, &configured).expect("a path resolves"),
            ""
        );
    }

    #[test]
    fn a_vaults_prefix_is_its_own_namespace_and_not_a_bucket_split() {
        // A vault resolves to no target: it stores nothing, and the chain is
        // followed to the store beneath it. `archive:photos` therefore addresses
        // `photos` in the vault's own namespace whatever the bucket underneath
        // is called — and asking `resolve` would fail outright, because a vault
        // wrapper is not a place bytes go.
        let configured = catalog(&[
            (
                "archive",
                RemoteEntry::new(PROVIDER_VAULT).with_setting(CONFIG_KEY_BASE, "archive-store"),
            ),
            (
                "archive-store",
                RemoteEntry::new(PROVIDER_B2).with_setting(CONFIG_KEY_BUCKET, "cold"),
            ),
        ]);
        for (written, expected) in [
            ("archive:", ""),
            ("archive:photos", "photos"),
            ("archive:photos/2024", "photos/2024"),
        ] {
            let spec = RemoteSpec::parse(written).expect("a well-formed spec");
            assert_eq!(
                logical_prefix(&spec, &configured).expect("a vault answers"),
                expected,
                "'{written}'"
            );
        }
    }

    #[test]
    fn a_prefix_cannot_be_produced_for_a_remote_that_does_not_resolve() {
        // Never `Ok("")`. An empty prefix on an unresolvable remote would list
        // the whole of some other store, or nothing at all and exit 0 — and
        // "the backup is empty" is a conclusion people act on.
        let error = logical_prefix(
            &RemoteSpec::parse("nosuchremote:photos").expect("a well-formed spec"),
            &(),
        )
        .expect_err("an unknown remote has no prefix");
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.message().contains("nosuchremote"));
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
    fn a_drive_letter_path_is_resolved_the_way_its_platform_means_it() {
        // The end-to-end version of `super::spec`'s reason for existing, and now
        // of its one platform-dependent rule. Both halves are asserted, on
        // whichever machine runs the test, because a rule only one platform ever
        // exercises is a rule only one platform is protected by.
        //
        // On Windows: a path, whatever the config says.
        let windows = RemoteSpec::classify(r"C:\Users\me", true).unwrap();
        let resolved = resolve(&windows, &()).unwrap();
        assert_eq!(resolved.provider_type(), PROVIDER_LOCAL);
        assert_eq!(
            resolved.target(),
            &Target::Local {
                root: PathBuf::from(r"C:\Users\me")
            }
        );

        // Elsewhere: a reference to a remote called `C`, which resolves to
        // nothing and *fails by name*. It cannot become a directory literally
        // called `C:\Users\me` — that behaviour is what made
        // `dctl copy /srv/data r:` write into `./r:` and exit 0.
        let posix = RemoteSpec::classify(r"C:\Users\me", false).unwrap();
        let error = resolve(&posix, &()).unwrap_err();
        assert!(error.message().contains('C'), "{}", error.message());
    }

    #[test]
    fn a_one_character_remote_is_declarable_and_resolves_off_windows() {
        // Corrected this pass. `config::validate` used to refuse the name, so
        // the shape below was unreachable and the platform split was defended by
        // a rule rclone does not have. It is reachable now: off Windows `C:` is
        // the remote `C`, and a config may declare it, exactly as rclone's may.
        let config = catalog(&[(
            "C",
            RemoteEntry::new(PROVIDER_B2).with_setting(CONFIG_KEY_BUCKET, "wrong"),
        )]);
        assert!(crate::config::validate_remote_name("C").is_ok());
        let posix = RemoteSpec::classify(r"C:\Users\me", false).unwrap();
        assert_eq!(
            resolve(&posix, &config).unwrap().provider_type(),
            PROVIDER_B2
        );

        // On a platform with drives the same argument is a path and never
        // reaches the catalog at all, which is what makes declaring the name
        // safe there: `config create` refuses to mint it in the first place.
        let windows = RemoteSpec::classify(r"C:\Users\me", true).unwrap();
        assert_eq!(
            windows.local_path(),
            Some(std::path::Path::new(r"C:\Users\me"))
        );
        assert!(crate::config::drive_letter_conflict("C", true));
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
                bucket: "cold-storage".into(),
                chunk_size: None,
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
                chunk_size: None,
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
                bucket: "actually-b2".into(),
                chunk_size: None,
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
                bucket: "my-bucket".into(),
                chunk_size: None,
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
                chunk_size: None,
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
