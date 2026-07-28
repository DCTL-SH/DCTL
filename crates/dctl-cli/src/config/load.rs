//! Finding and reading `config.toml`.
//!
//! Two questions, answered separately because they fail differently.
//!
//! **Which file?** `--config` beats `DCTL_CONFIG` beats the platform config
//! directory. That order is not arbitrary: the flag is the most specific
//! statement of intent available (it applies to this one invocation), the
//! environment variable is the next (it applies to this shell or this
//! container), and the platform default is the fallback that makes DCTL work
//! with no configuration at all. `PLAN.md` §14 requires all three, because a
//! server running DCTL headless configures it by environment and a CI job
//! configures it by flag.
//!
//! **Is it usable?** A file the user *named* and got wrong is an error; a
//! *default* path that does not exist is a fresh installation and yields an
//! empty configuration. Anything that does exist is parsed, audited for
//! credential-shaped keys, and validated before a caller ever sees it — so no
//! other module has to defend itself against a cycle or a dangling base.
//!
//! Reading the file also *warns* — never fails — when it is readable by anyone
//! but its owner (`PLAN.md` §14). The file holds no secrets, so exposure is not
//! a breach; it holds buckets, endpoints, regions and account ids, which is free
//! reconnaissance, and that is worth a line on stderr rather than a refusal to
//! run.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::constants::ENV_CONFIG;
use crate::logging::fields;

use super::error::{ConfigError, Result};
use super::model::Config;
use super::validate;

/// Decide which configuration file this invocation uses.
///
/// `explicit` is `--config` as parsed. The environment variable is consulted
/// only when the flag is absent, and an *empty* value is treated as unset — an
/// exported-but-blank `DCTL_CONFIG` is a shell accident, and honouring it would
/// silently point DCTL at the current directory.
#[must_use]
pub fn resolve_path(explicit: Option<&Path>) -> PathBuf {
    resolve_from(
        explicit,
        std::env::var_os(dctl_meta::env_var(ENV_CONFIG)),
        dctl_meta::paths::config_file,
    )
}

/// The precedence rule behind [`resolve_path`], with its inputs supplied.
///
/// Split out because the process environment cannot be mutated in a test:
/// `std::env::set_var` is `unsafe` in edition 2024, and this crate is
/// `#![forbid(unsafe_code)]`. Passing the environment in keeps the rule itself
/// — which is the part that can be got wrong — directly testable.
fn resolve_from(
    explicit: Option<&Path>,
    from_env: Option<OsString>,
    default: impl FnOnce() -> PathBuf,
) -> PathBuf {
    if let Some(path) = explicit {
        return path.to_path_buf();
    }
    if let Some(value) = from_env.filter(|value| !value.is_empty()) {
        return PathBuf::from(value);
    }
    default()
}

/// A configuration path that is guaranteed not to exist, for tests.
///
/// Every command that decides *where a write may land* now reads the
/// configuration, and a test that let that resolve to the platform default
/// would be reading the developer's own `config.toml`: it would pass on one
/// machine and fail on the next, which is the one thing a test may not do. So
/// the test contexts pass `--config` pointing here, and
/// [`load_or_default`] answers with the empty configuration a fresh
/// installation has.
///
/// Resolved once per process and deleted on first use, so the guarantee in the
/// first line is one this function actually keeps rather than one it assumes.
#[cfg(test)]
#[must_use]
pub fn absent_path() -> PathBuf {
    use std::sync::OnceLock;
    static PATH: OnceLock<PathBuf> = OnceLock::new();

    PATH.get_or_init(|| {
        let path = std::env::temp_dir().join(format!(
            "{}-absent-config-{}.toml",
            dctl_meta::BINARY_NAME,
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        path
    })
    .clone()
}

/// Read and validate the configuration at `path`.
///
/// Fails with [`ConfigError::Missing`] when the file is not there. Use
/// [`load_or_default`] for a path the user did not name, where absence means
/// "not configured yet" rather than "wrong path".
///
/// # Errors
/// [`ConfigError::Missing`] when the file is absent, [`ConfigError::Read`] when
/// it cannot be read, and anything [`parse`] produces.
pub fn load(path: &Path) -> Result<Config> {
    let text = read_to_string(path)?;
    warn_if_exposed(path);
    parse(&text, path)
}

/// Read the configuration at `path`, treating absence as an empty one.
///
/// The right call for the *default* location: `PLAN.md` §14 requires DCTL to run
/// fully headless from flags and environment variables, so a machine that never
/// runs `dctl config` must not be told it is misconfigured.
///
/// Only `NotFound` is forgiven. A file that exists but cannot be read — wrong
/// owner, bad permissions, an I/O error — is still an error, because silently
/// continuing with an empty configuration there would send a transfer to the
/// wrong place.
///
/// # Errors
/// Anything [`load`] produces except [`ConfigError::Missing`], which is
/// answered with an empty configuration.
pub fn load_or_default(path: &Path) -> Result<Config> {
    match read_to_string(path) {
        Ok(text) => {
            warn_if_exposed(path);
            parse(&text, path)
        }
        Err(ConfigError::Missing(_)) => Ok(Config::default()),
        Err(other) => Err(other),
    }
}

/// Turn the text of a configuration file into a validated [`Config`].
///
/// Parsed once into a raw document, audited, then deserialised. The audit has to
/// come first: `deny_unknown_fields` would reject a pasted-in credential too,
/// but as "unknown field `secret_key`", which reads like a typo instead of like
/// the security event it is (`PLAN.md` §14).
///
/// `path` is carried only so that a failure can say which file it was talking
/// about; nothing is read from disk here, which is what makes this the entry
/// point the tests drive.
///
/// # Errors
/// [`ConfigError::Parse`] for malformed TOML or a shape the model does not
/// describe, [`ConfigError::SecretInConfig`] for a credential-shaped key, and
/// any rule [`validate`](super::validate::validate) enforces.
pub fn parse(text: &str, path: &Path) -> Result<Config> {
    let document: toml::Table = toml::from_str(text).map_err(|source| ConfigError::Parse {
        path: path.to_path_buf(),
        source,
    })?;

    validate::reject_secret_keys(&document)?;

    let config: Config =
        toml::Value::Table(document)
            .try_into()
            .map_err(|source| ConfigError::Parse {
                path: path.to_path_buf(),
                source,
            })?;

    validate::validate(&config)?;
    Ok(config)
}

/// Read the configuration at `path` **without** applying the graph rules.
///
/// The one door into the model that skips [`validate`](super::validate::validate),
/// and it exists for exactly one caller: `dctl config verify`, whose entire
/// purpose is to *report* the problems that [`load`] refuses to open the file
/// over. A diagnostic that cannot open a broken file diagnoses nothing — an
/// operator whose config has a dangling base would get the same one-line refusal
/// from `verify` as from every other command, and would still have no list of
/// what else is wrong.
///
/// What it does **not** skip is the part that protects the user rather than the
/// tool: the file must still be well-formed TOML matching the model, and a
/// credential-shaped key is still refused (`PLAN.md` §14). Reporting on a file
/// while ignoring a secret sitting in it would be the wrong kind of lenient.
///
/// Nothing that *acts* on a configuration may call this. The value it returns
/// has not been proven consistent, so the invariant every other module relies on
/// — that a [`Config`] in hand contains no cycle and no dangling base — does not
/// hold for it. It is named for what it is so that a call site claiming
/// otherwise reads as the mistake it would be.
///
/// # Errors
/// [`ConfigError::Missing`] when the file is absent, [`ConfigError::Read`] when
/// it cannot be read, [`ConfigError::Parse`] for malformed TOML, and
/// [`ConfigError::SecretInConfig`] for a credential-shaped key.
pub fn load_for_diagnosis(path: &Path) -> Result<Config> {
    let text = read_to_string(path)?;
    warn_if_exposed(path);
    parse_unvalidated(&text, path)
}

/// The parse half of [`load_for_diagnosis`], without the filesystem.
///
/// Split out for the same reason [`parse`] is: the rules that can be got wrong
/// are the ones worth driving directly from a test.
///
/// # Errors
/// As [`load_for_diagnosis`], minus the filesystem failures.
fn parse_unvalidated(text: &str, path: &Path) -> Result<Config> {
    let document: toml::Table = toml::from_str(text).map_err(|source| ConfigError::Parse {
        path: path.to_path_buf(),
        source,
    })?;

    validate::reject_secret_keys(&document)?;

    toml::Value::Table(document)
        .try_into()
        .map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })
}

/// Read a file, mapping "not there" onto its own error.
fn read_to_string(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            ConfigError::Missing(path.to_path_buf())
        } else {
            ConfigError::Read {
                path: path.to_path_buf(),
                source,
            }
        }
    })
}

/// Permission bits that let somebody other than the owner read the file.
///
/// Returns `None` when the file is owner-only, unreadable, or absent — the
/// caller is warning about a file it has just read, so "cannot tell" and "fine"
/// deserve the same silence.
///
/// On Windows this always returns `None`. Access there is an ACL rather than a
/// mode, the equivalent audit is a walk of the discretionary ACL, and reporting
/// a made-up answer would be worse than reporting none: the file inherits the
/// user profile directory's ACL, which is already owner-only on a default
/// installation.
#[cfg(unix)]
#[must_use]
pub fn exposed_permission_bits(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;

    use crate::constants::CONFIG_FILE_EXPOSED_MODE_MASK;

    let mode = std::fs::metadata(path).ok()?.permissions().mode();
    let exposed = mode & CONFIG_FILE_EXPOSED_MODE_MASK;
    (exposed != 0).then_some(exposed)
}

/// See the Unix definition.
#[cfg(not(unix))]
#[must_use]
pub fn exposed_permission_bits(_path: &Path) -> Option<u32> {
    None
}

/// Warn — never fail — when the configuration is readable beyond its owner.
///
/// `PLAN.md` §14 asks for exactly this shape. Refusing to run would be wrong:
/// the file holds no credentials, so a loose mode is a disclosure of buckets and
/// endpoints rather than of access, and a tool that refuses to start over it
/// would teach people to `chmod 777` and move on. Saying so once, with the fix
/// in the message, is the proportionate response.
fn warn_if_exposed(path: &Path) {
    if let Some(bits) = exposed_permission_bits(path) {
        let recommended = recommended_mode();
        tracing::warn!(
            { fields::PATH } = %path.display(),
            "configuration is accessible beyond its owner (mode bits {bits:03o}); \
             it names buckets, endpoints and regions. Fix with: chmod {recommended} {}",
            path.display()
        );
    }
}

/// The mode [`warn_if_exposed`] tells the user to set, as `chmod` spells it.
#[cfg(unix)]
fn recommended_mode() -> String {
    format!("{:03o}", crate::constants::CONFIG_FILE_MODE)
}

/// See the Unix definition. Unreachable on Windows, where nothing is ever
/// reported as exposed, but defined so the warning path compiles everywhere.
#[cfg(not(unix))]
fn recommended_mode() -> String {
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::model::RemoteDef;
    use crate::constants::PROVIDER_B2;

    const VALID: &str = "[remotes.b2prod]\ntype = \"b2\"\nbucket = \"photos\"\n\
                         \n[remotes.vault]\ntype = \"vault\"\nbase = \"b2prod\"\n";

    fn any_path() -> PathBuf {
        PathBuf::from("config.toml")
    }

    #[test]
    fn an_explicit_flag_beats_everything() {
        let chosen = resolve_from(
            Some(Path::new("/flag.toml")),
            Some(OsString::from("/env.toml")),
            || PathBuf::from("/default.toml"),
        );
        assert_eq!(chosen, PathBuf::from("/flag.toml"));
    }

    #[test]
    fn the_environment_beats_the_platform_default() {
        let chosen = resolve_from(None, Some(OsString::from("/env.toml")), || {
            PathBuf::from("/default.toml")
        });
        assert_eq!(chosen, PathBuf::from("/env.toml"));
    }

    #[test]
    fn the_platform_default_is_the_fallback() {
        let chosen = resolve_from(None, None, || PathBuf::from("/default.toml"));
        assert_eq!(chosen, PathBuf::from("/default.toml"));
    }

    #[test]
    fn an_empty_environment_variable_is_treated_as_unset() {
        // An exported-but-blank DCTL_CONFIG is a shell accident. Honouring it
        // would resolve the config to "", which is the current directory.
        let chosen = resolve_from(None, Some(OsString::new()), || {
            PathBuf::from("/default.toml")
        });
        assert_eq!(chosen, PathBuf::from("/default.toml"));
    }

    #[test]
    fn the_real_resolver_ends_up_somewhere_named_after_the_product() {
        // Not asserting an exact path — it differs per platform and per user —
        // but the fallback must at least be a file and not a directory.
        let path = resolve_path(None);
        assert!(path.file_name().is_some(), "got: {}", path.display());
    }

    #[test]
    fn a_valid_file_parses_into_remotes() {
        let config = parse(VALID, &any_path()).expect("must parse");
        assert_eq!(config.len(), 2);
        assert_eq!(
            config.get("b2prod").map(RemoteDef::type_name),
            Some(PROVIDER_B2)
        );
    }

    #[test]
    fn an_empty_file_is_a_valid_empty_configuration() {
        assert!(parse("", &any_path()).expect("must parse").is_empty());
        assert!(
            parse("# nothing but a comment\n", &any_path())
                .expect("must parse")
                .is_empty()
        );
    }

    #[test]
    fn malformed_toml_reports_the_file_it_came_from() {
        let error =
            parse("[remotes.b2prod\n", Path::new("/etc/dctl.toml")).expect_err("must not parse");
        assert!(matches!(error, ConfigError::Parse { .. }));
        assert!(error.to_string().contains("/etc/dctl.toml"), "{error}");
    }

    #[test]
    fn a_credential_in_the_file_is_refused_by_name() {
        // The §14 prohibition, enforced on the way in. The message must name the
        // key rather than saying "unknown field".
        let error = parse(
            "[remotes.b2prod]\ntype = \"b2\"\nbucket = \"x\"\napp_key = \"K00…\"\n",
            &any_path(),
        )
        .expect_err("must be refused");
        match error {
            ConfigError::SecretInConfig { ref key } => {
                assert_eq!(key, "remotes.b2prod.app_key");
            }
            other => panic!("expected a refused credential, got {other}"),
        }
    }

    #[test]
    fn an_invalid_remote_graph_is_caught_on_load() {
        // Loading is one of the two moments validation runs, so nothing that
        // reads the config afterwards has to consider a cycle.
        let error = parse(
            "[remotes.vault]\ntype = \"vault\"\nbase = \"inner\"\n\
             [remotes.inner]\ntype = \"vault\"\nbase = \"vault\"\n",
            &any_path(),
        )
        .expect_err("must be refused");
        assert!(matches!(error, ConfigError::VaultCycle { .. }), "{error}");
    }

    #[test]
    fn an_illegal_remote_name_is_caught_on_load() {
        let error = parse(
            "[remotes.\"my remote\"]\ntype = \"local\"\npath = \"/srv\"\n",
            &any_path(),
        )
        .expect_err("must be refused");
        assert!(matches!(error, ConfigError::NameCharset { .. }), "{error}");
    }

    #[test]
    fn a_one_character_remote_name_loads_on_every_platform() {
        // The portability half of the rclone-parity fix: a config written on a
        // machine without drive letters must open on one that has them, or a
        // name rclone allows becomes a file DCTL refuses to read at all.
        let config = parse(
            "[remotes.c]\ntype = \"local\"\npath = \"/srv\"\n",
            &any_path(),
        )
        .expect("a one-character section must load");
        assert!(config.get("c").is_some());
    }

    #[test]
    fn the_diagnostic_door_opens_a_file_the_strict_one_refuses() {
        // The reason `load_for_diagnosis` exists: `dctl config verify` has to be
        // able to *read* a config with a dangling base in order to report it.
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "[remotes.archive]\ntype = \"vault\"\nbase = \"gone\"\n",
        )
        .expect("write");

        assert!(matches!(load(&path), Err(ConfigError::UnknownBase { .. })));

        let loaded = load_for_diagnosis(&path).expect("the diagnostic door must open it");
        assert_eq!(loaded.len(), 1);
        assert_eq!(
            loaded.get("archive").and_then(RemoteDef::base),
            Some("gone")
        );
    }

    #[test]
    fn the_diagnostic_door_still_refuses_a_credential_and_a_malformed_file() {
        // Leniency is only ever about the *graph*. A secret in the file is not a
        // finding to report politely; it is a key to rotate (PLAN.md §14).
        let error = parse_unvalidated(
            "[remotes.b2prod]\ntype = \"b2\"\nbucket = \"x\"\napp_key = \"K00…\"\n",
            &any_path(),
        )
        .expect_err("must be refused");
        assert!(
            matches!(error, ConfigError::SecretInConfig { .. }),
            "{error}"
        );

        assert!(matches!(
            parse_unvalidated("[remotes.b2prod\n", &any_path()),
            Err(ConfigError::Parse { .. })
        ));
        // A section the model has no shape for is still not a remote.
        assert!(parse_unvalidated("[remotes.x]\ntype = \"dropbox\"\n", &any_path()).is_err());
    }

    #[test]
    fn a_missing_named_file_is_an_error_and_a_missing_default_is_not() {
        let dir = tempfile::tempdir().expect("temp dir");
        let absent = dir.path().join("nope.toml");

        assert!(matches!(load(&absent), Err(ConfigError::Missing(_))));
        assert!(
            load_or_default(&absent)
                .expect("a missing default is a fresh installation")
                .is_empty()
        );
    }

    #[test]
    fn a_file_on_disk_round_trips_through_load() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        std::fs::write(&path, VALID).expect("write");

        let loaded = load(&path).expect("must load");
        assert_eq!(loaded.len(), 2);
        assert_eq!(
            load_or_default(&path).expect("must load").len(),
            loaded.len()
        );
    }

    #[cfg(unix)]
    #[test]
    fn an_exposed_file_is_detected_but_still_loads() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        std::fs::write(&path, VALID).expect("write");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        assert_eq!(
            exposed_permission_bits(&path),
            Some(0o044),
            "group and world read must be reported"
        );
        // The warning is a warning: the configuration still loads.
        assert!(load(&path).is_ok());

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        assert_eq!(exposed_permission_bits(&path), None);

        // Write-only exposure counts too: a group-writable config can be
        // replaced wholesale, which is worse than being read.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o620)).expect("chmod");
        assert_eq!(exposed_permission_bits(&path), Some(0o020));
    }

    #[test]
    fn a_file_that_is_not_there_is_never_reported_as_exposed() {
        let dir = tempfile::tempdir().expect("temp dir");
        assert_eq!(exposed_permission_bits(&dir.path().join("absent")), None);
    }
}
