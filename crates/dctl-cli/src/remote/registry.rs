//! Turning a resolved remote into a live [`Backend`].
//!
//! This is the one place in the CLI that knows which provider implementation
//! exists, and the one place that reads a credential. Everything above it deals
//! in [`Target`] — a provider plus the settings that provider needs — so adding
//! sftp or Google Drive later is a new variant plus a new arm here, and touches
//! no command (`PLAN.md` §16.1: extensibility through traits, not branches).
//!
//! ## Why [`Target`] is an enum and not a settings map
//!
//! The map form is how the config file stores a remote, and it is the wrong
//! shape to build from: `settings["bucket"]` compiles whether or not the
//! provider has a bucket, so a provider added six months from now can silently
//! ship without a required setting until someone runs it against real data. As
//! an enum, every arm's requirements are checked when the resolver builds it
//! (see [`super::resolve`]) and the match below is exhaustive — a new provider
//! that nobody wired up is a compile error, not a runtime surprise.
//!
//! ## Credentials come from the environment, never the config file
//!
//! `PLAN.md` §14 is explicit about the mistake being avoided: rclone stores
//! provider secrets in `rclone.conf`, merely "obscured" with reversible
//! obfuscation, so anyone who reads the file recovers them. DCTL's config file
//! holds only the non-secret half of a remote — bucket, endpoint, region,
//! account — and every secret arrives through the environment (later, the OS
//! keychain). Nothing here can read a key out of a config value, because no
//! code path exists that would.
//!
//! A missing credential is reported by **variable name only**. The value is
//! never echoed, never logged, and never included in an error — not even when
//! it is present but malformed, which is exactly the moment a naive tool prints
//! the secret to the terminal to be helpful.

use std::env::VarError;
use std::path::PathBuf;
use std::sync::Arc;

use dctl_store::b2::{B2Backend, B2Credentials};
use dctl_store::{Backend, LocalFs, R2Backend, S3Backend, S3Config, SftpBackend, SftpConfig};

use crate::constants::{
    ENV_B2_APP_KEY, ENV_B2_KEY_ID, ENV_R2_ACCESS_KEY, ENV_R2_ACCOUNT_ID, ENV_R2_SECRET_KEY,
    ENV_S3_ACCESS_KEY, ENV_S3_ENDPOINT, ENV_S3_REGION, ENV_S3_SECRET_KEY, PROVIDER_B2,
    PROVIDER_LOCAL, PROVIDER_R2, PROVIDER_S3, PROVIDER_SFTP,
};
use crate::error::{CliError, Result};
use crate::logging::fields;

use super::resolve::Resolved;
use super::spec::RemoteSpec;

/// A provider together with everything non-secret it needs to connect.
///
/// Produced by [`super::resolve::resolve`] from a spec plus the config, and
/// consumed only by [`build`]. The optional fields are settings the config file
/// *may* pin; when it does not, [`build`] falls back to the provider's
/// environment variable, which is what makes a zero-config `s3:bucket` work the
/// same way it did before named remotes existed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    /// A directory on this machine's filesystem, used as the root that logical
    /// paths resolve beneath.
    Local {
        /// Root directory. Kept as a [`PathBuf`] rather than a `String` so a
        /// path the operating system accepts but UTF-8 does not still works.
        root: PathBuf,
    },

    /// A Backblaze B2 bucket over B2's native API.
    B2 {
        /// Bucket name.
        bucket: String,
    },

    /// Amazon S3, or any S3-compatible endpoint.
    S3 {
        /// Bucket name.
        bucket: String,
        /// Endpoint URL; falls back to the environment when unset, because
        /// every non-AWS deployment needs its own and there is no default that
        /// is safe to guess.
        endpoint: Option<String>,
        /// SigV4 signing region; falls back to the environment when unset.
        region: Option<String>,
    },

    /// A Cloudflare R2 bucket.
    R2 {
        /// Bucket name.
        bucket: String,
        /// Cloudflare account id, from which R2's endpoint is derived; falls
        /// back to the environment when unset.
        account: Option<String>,
    },

    /// An SSH host reached over SFTP, driven by the system `ssh`.
    ///
    /// Neither field falls back to the environment: unlike the cloud providers,
    /// an sftp remote holds no credential to look up. The user, port, identity
    /// and any `ProxyCommand` come from `~/.ssh/config`, resolved by `ssh` from
    /// [`host`](Target::Sftp::host) alone, so the config file carries the whole
    /// of what DCTL needs and there is nothing secret to keep out of it.
    Sftp {
        /// SSH destination: a `~/.ssh/config` `Host` alias or `user@host[:port]`.
        host: String,
        /// Remote base directory objects live under.
        base: String,
    },
}

impl Target {
    /// The provider type name this target builds — the same spelling a config
    /// section's `type` key carries, so logs, `dctl config list` and the config
    /// file all say the same word for the same thing.
    #[must_use]
    pub const fn provider_type(&self) -> &'static str {
        match self {
            Self::Local { .. } => PROVIDER_LOCAL,
            Self::B2 { .. } => PROVIDER_B2,
            Self::S3 { .. } => PROVIDER_S3,
            Self::R2 { .. } => PROVIDER_R2,
            Self::Sftp { .. } => PROVIDER_SFTP,
        }
    }
}

/// Build a live backend for a resolved remote.
///
/// Constructing a backend is deliberately separate from resolving one: the
/// resolver is pure and can be tested against a config fixture, while this
/// reads the environment and opens connections. Commands that only need to
/// *name* a remote — `--dry-run`, error messages, completion — never reach here
/// and therefore never demand credentials for a run that will not connect.
pub fn build(resolved: &Resolved) -> Result<Arc<dyn Backend>> {
    let target = resolved.target();

    tracing::debug!(
        { fields::REMOTE } = resolved.name(),
        provider = target.provider_type(),
        "building backend"
    );

    match target {
        Target::Local { root } => Ok(Arc::new(LocalFs::new(root.clone()))),

        Target::B2 { bucket } => {
            let key_id = env_required(ENV_B2_KEY_ID)?;
            let app_key = env_required(ENV_B2_APP_KEY)?;
            Ok(Arc::new(B2Backend::new(
                B2Credentials::new(key_id, app_key),
                bucket.clone(),
            )?))
        }

        Target::S3 {
            bucket,
            endpoint,
            region,
        } => {
            let endpoint = setting_or_env(endpoint.as_deref(), ENV_S3_ENDPOINT)?;
            let region = setting_or_env(region.as_deref(), ENV_S3_REGION)?;
            let access_key = env_required(ENV_S3_ACCESS_KEY)?;
            let secret_key = env_required(ENV_S3_SECRET_KEY)?;
            let config = S3Config::new(endpoint, region, bucket.clone(), access_key, secret_key);
            Ok(Arc::new(S3Backend::new(config)?))
        }

        Target::R2 { bucket, account } => {
            let account = setting_or_env(account.as_deref(), ENV_R2_ACCOUNT_ID)?;
            let access_key = env_required(ENV_R2_ACCESS_KEY)?;
            let secret_key = env_required(ENV_R2_SECRET_KEY)?;
            Ok(Arc::new(R2Backend::new(
                &account,
                bucket.clone(),
                access_key,
                secret_key,
            )?))
        }

        // No credential is read: `ssh` authenticates the transport from the
        // user's own config, which is the whole reason a cloudflared-proxied host
        // works. This is also the one arm that opens a connection to build, so it
        // is the one that bridges to the async `connect` — see [`connect_sftp`].
        Target::Sftp { host, base } => connect_sftp(host, base),
    }
}

/// Open an [`SftpBackend`], bridging its async [`SftpBackend::connect`] to the
/// synchronous [`build`] path.
///
/// The other providers construct without any I/O — they defer every request to
/// first use — so their constructors are synchronous and fit [`build`] directly.
/// SFTP cannot: it opens a multiplexed `ssh` session up front (that is what makes
/// every later operation reuse one connection), so `connect` is `async`. [`build`]
/// stays synchronous because it is reached from synchronous command paths too
/// (`session::prepare`, `source::plain::open`), and turning it `async` would
/// cascade through all of them and their tests for the sake of one provider.
///
/// The whole CLI runs inside the multi-threaded runtime built in `main`, so
/// [`tokio::task::block_in_place`] lets this worker thread block on the connect
/// without starving the scheduler, and [`tokio::runtime::Handle::block_on`] drives
/// it on that same long-lived runtime — which the returned session must stay on
/// for the backend's lifetime. [`Handle::try_current`](tokio::runtime::Handle::try_current)
/// is used rather than `current` so the "not on a runtime" case is a typed error
/// rather than a panic, keeping this lib code panic-free.
fn connect_sftp(host: &str, base: &str) -> Result<Arc<dyn Backend>> {
    let handle = tokio::runtime::Handle::try_current().map_err(|_| {
        CliError::fatal("the sftp backend must be built inside the async runtime").with_hint(
            "This is an internal error. Please report the command that produced it.",
        )
    })?;
    let config = SftpConfig::new(host, base);
    let backend =
        tokio::task::block_in_place(|| handle.block_on(SftpBackend::connect(config)))?;
    Ok(Arc::new(backend))
}

/// Build a backend for a spec typed on the command line, without a config file.
///
/// The three steps in one call — parse, resolve against the empty catalog,
/// build — for the commands that run before a configuration is necessarily
/// readable (`dctl init` creating the first vault) and for headless jobs that
/// carry everything in the environment (`PLAN.md` §14).
///
/// Two limits are worth knowing before reaching for it, because both are silent:
/// a **named** remote cannot resolve here — only the `local:`, `b2:`, `s3:` and
/// `r2:` shorthands do — and the path portion of the spec is discarded, since
/// only a backend comes back. Anything addressing a prefix inside a remote, or
/// a remote the user defined, must go through
/// [`resolve`](super::resolve::resolve) and keep the [`Resolved`] it returns.
///
/// The argument is a **spec as the user typed it**, and the distinction is not
/// cosmetic: this function parses it, and a remote's bare name parses as a
/// relative directory, because it carries no colon for
/// [`RemoteSpec::parse`] to split on. Handing it `"b2"` where `"b2:mybucket"`
/// was meant therefore builds a filesystem backend rooted at `./b2` and reports
/// no error at all. A caller that already holds a [`RemoteSpec`] must resolve
/// that value directly rather than reconstructing text for this entry point.
pub fn build_backend(spec: &str) -> Result<Arc<dyn Backend>> {
    let parsed = RemoteSpec::parse(spec)?;
    let resolved = super::resolve::resolve(&parsed, &())?;
    build(&resolved)
}

/// Take a setting the config pinned, or fall back to its environment variable.
///
/// The precedence is config-then-environment for the *non-secret* settings only.
/// It exists so a named remote can pin its endpoint permanently while a bare
/// `s3:bucket` — no config at all — still works from exported variables, which
/// is how the CLI behaved before named remotes and how CI jobs are written.
fn setting_or_env(configured: Option<&str>, setting: &str) -> Result<String> {
    match configured {
        Some(value) => Ok(value.to_string()),
        None => env_required(setting),
    }
}

/// Read a required setting from the environment, named `DCTL_<SETTING>`.
fn env_required(setting: &str) -> Result<String> {
    let variable = dctl_meta::env_var(setting);
    let value = std::env::var(&variable);
    classify(&variable, value)
}

/// Turn the outcome of an environment read into a value or a typed failure.
///
/// Split from [`env_required`] so every branch is testable without mutating the
/// process environment — which, under Rust 2024, is an `unsafe` operation this
/// crate forbids outright.
///
/// All three failures are fatal (exit 7) rather than temporary: no amount of
/// retrying invents a credential, and reporting one as transient would have a
/// scheduled job silently back off for an hour instead of failing loudly.
fn classify(variable: &str, value: std::result::Result<String, VarError>) -> Result<String> {
    match value {
        // An exported-but-empty variable is the classic broken-CI shape — a
        // secret that failed to interpolate. Treated as absent, because sending
        // an empty key to a provider produces an opaque 403 instead.
        Ok(value) if value.is_empty() => Err(missing(variable, "is set but empty")),
        Ok(value) => Ok(value),
        Err(VarError::NotPresent) => Err(missing(variable, "is not set")),
        // Deliberately does not quote the value: it is a credential, and the
        // bytes that broke UTF-8 would be printed to a terminal or a log.
        Err(VarError::NotUnicode(_)) => Err(missing(variable, "is not valid UTF-8")),
    }
}

/// Build the failure for an unusable credential variable.
///
/// One constructor so every provider words it identically, and so the value can
/// never leak into a message by a copy-paste that forgot to leave it out.
fn missing(variable: &str, problem: &str) -> CliError {
    CliError::fatal(format!("{variable} {problem}")).with_hint(format!(
        "Provider credentials are read from the environment, never from the \
         config file. Export {variable} before running."
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exit::ExitCode;

    fn local_target() -> Target {
        Target::Local {
            root: PathBuf::from("/srv/data"),
        }
    }

    #[test]
    fn a_local_target_builds_without_any_credential() {
        // The only provider that must work on a machine with no environment set
        // up at all — `dctl copy a b` between two directories.
        let resolved = Resolved::new(PROVIDER_LOCAL, local_target(), String::new());
        let backend = build(&resolved).unwrap();
        assert_eq!(backend.name(), PROVIDER_LOCAL);
    }

    #[test]
    fn every_target_reports_the_provider_type_the_config_spells() {
        // The registry, the config file and the log field must agree on the
        // word, or an operator greps for `provider=s3` and finds nothing.
        assert_eq!(local_target().provider_type(), PROVIDER_LOCAL);
        assert_eq!(
            Target::B2 { bucket: "b".into() }.provider_type(),
            PROVIDER_B2
        );
        assert_eq!(
            Target::S3 {
                bucket: "b".into(),
                endpoint: None,
                region: None,
            }
            .provider_type(),
            PROVIDER_S3
        );
        assert_eq!(
            Target::R2 {
                bucket: "b".into(),
                account: None,
            }
            .provider_type(),
            PROVIDER_R2
        );
        assert_eq!(
            Target::Sftp {
                host: "lsx-001".into(),
                base: "store".into(),
            }
            .provider_type(),
            PROVIDER_SFTP
        );
    }

    #[test]
    fn a_missing_credential_is_fatal_and_names_the_variable() {
        // Fatal, not temporary: retrying never invents a key, and a scheduled
        // job must fail now rather than back off for an hour first.
        let error = classify("DCTL_B2_APP_KEY", Err(VarError::NotPresent)).unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.message().contains("DCTL_B2_APP_KEY"));
        assert!(
            error
                .hint()
                .is_some_and(|hint| hint.contains("environment"))
        );
    }

    #[test]
    fn an_exported_but_empty_credential_is_treated_as_missing() {
        // `export KEY=$UNSET_VAR` in a CI script. Passing the empty string on to
        // the provider buys an opaque 403 instead of an actionable message.
        let error = classify("DCTL_S3_SECRET_KEY", Ok(String::new())).unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.message().contains("empty"));
    }

    #[test]
    fn a_credential_value_never_appears_in_any_message() {
        // The property that matters most here: a secret must not reach a
        // terminal, a log, or a support ticket by way of an error message.
        let secret = "AKIAsupersecretvalue";
        for outcome in [
            Err(VarError::NotUnicode(secret.into())),
            Ok(String::new()),
            Err(VarError::NotPresent),
        ] {
            let Err(error) = classify("DCTL_S3_ACCESS_KEY", outcome) else {
                continue;
            };
            let rendered = format!("{error}");
            assert!(
                !rendered.contains(secret),
                "a secret leaked into '{rendered}'"
            );
        }
    }

    #[test]
    fn a_present_credential_is_returned_verbatim() {
        // Whitespace and padding are meaningful in a signing key; trimming one
        // would produce signature failures that look like a clock problem.
        assert_eq!(
            classify("DCTL_S3_ACCESS_KEY", Ok(" padded ".into())).unwrap(),
            " padded "
        );
    }

    #[test]
    fn the_config_free_entry_point_still_builds_a_local_backend() {
        // What `dctl init` uses: a vault has to be creatable on a machine whose
        // config file does not exist yet.
        let backend = build_backend("/srv/data").unwrap();
        assert_eq!(backend.name(), PROVIDER_LOCAL);
        assert_eq!(
            build_backend("local:/srv/data").unwrap().name(),
            PROVIDER_LOCAL
        );
    }

    #[test]
    fn the_config_free_entry_point_refuses_a_named_remote() {
        // It has no catalog to look one up in, so failing is the only honest
        // answer; silently treating `vault:` as a directory would create the
        // vault in the working directory and report success.
        assert!(build_backend("vault:photos").is_err());
    }

    #[test]
    fn a_pinned_setting_wins_over_the_environment() {
        // A named remote's endpoint is part of its identity: it must not change
        // because an unrelated variable happens to be exported in this shell.
        assert_eq!(
            setting_or_env(Some("https://minio.internal"), ENV_S3_ENDPOINT).unwrap(),
            "https://minio.internal"
        );
    }
}
