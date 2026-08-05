//! Turning a resolved remote into a live [`Backend`].
//!
//! This is the one place in the CLI that knows which provider implementation
//! exists, and the one place that reads a credential. Everything above it deals
//! in [`Target`] — a provider plus the settings that provider needs — so adding
//! sftp or Google Drive later is a new variant plus a new arm here, and touches
//! no command ([the plan](https://doc.dctl.sh/project/plan) §16.1:
//! extensibility through traits, not branches).
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
//! [The plan](https://doc.dctl.sh/project/plan) §14 is explicit about the
//! mistake being avoided: rclone stores provider secrets in `rclone.conf`,
//! merely "obscured" with reversible obfuscation, so anyone who reads the file
//! recovers them. DCTL's config file holds only the non-secret half of a remote
//! — bucket, endpoint, region, account — and every secret arrives through the
//! environment (later, the OS keychain). Nothing here can read a key out of a
//! config value, because no code path exists that would.
//!
//! A missing credential is reported by **variable name only**. The value is
//! never echoed, never logged, and never included in an error — not even when
//! it is present but malformed, which is exactly the moment a naive tool prints
//! the secret to the terminal to be helpful.

use std::env::VarError;
use std::path::PathBuf;
use std::sync::Arc;

use dctl_store::b2::{B2Backend, B2Credentials};
use dctl_store::{
    Backend, Deadlines, LinkPolicy, LocalFs, R2Backend, S3Backend, S3Config, SftpBackend,
    SftpConfig,
};

use crate::constants::{
    ENV_B2_APP_KEY, ENV_B2_KEY_ID, ENV_R2_ACCESS_KEY, ENV_R2_ACCOUNT_ID, ENV_R2_SECRET_KEY,
    ENV_S3_ACCESS_KEY, ENV_S3_ENDPOINT, ENV_S3_REGION, ENV_S3_SECRET_KEY, PROVIDER_B2,
    PROVIDER_LOCAL, PROVIDER_R2, PROVIDER_S3, PROVIDER_SFTP,
};
use crate::error::{CliError, Result};
use crate::logging::fields;
use crate::remote::vars::{ProcessVars, Vars};

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
        /// Override for B2's authorization endpoint.
        ///
        /// `None` takes B2's published one, which is what every real
        /// installation wants. It exists for a private deployment and for a
        /// test double, and it was declared on `B2Def` and read by nothing —
        /// an operator could point a `b2` remote at their own gateway, see the
        /// setting in `dctl config show`, and have every request go to
        /// Backblaze regardless.
        ///
        /// Unlike the S3 endpoint there is no environment fall-back, and the
        /// asymmetry is deliberate: an S3 remote is *unusable* without one, so
        /// a headless job needs a way to supply it with no config file, while a
        /// B2 remote works perfectly with none.
        endpoint: Option<String>,
        /// Large-file part size in bytes, from the remote's `chunk_size`.
        ///
        /// `None` takes the client's default. Also the size above which an
        /// upload stops being one request, and — because a part is the one
        /// buffer an upload holds — the whole of what that upload costs in
        /// memory. No environment fall-back, for the reason the S3 variant's
        /// own `chunk_size` gives: it is a tuning choice rather than a piece of
        /// addressing.
        chunk_size: Option<u64>,
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
        /// Multipart part size in bytes, from the remote's `chunk_size`.
        ///
        /// `None` takes the client's default. No environment fall-back: unlike
        /// the endpoint and the region this is a tuning choice rather than a
        /// piece of addressing, and a machine-wide variable that silently
        /// changed how every bucket was cut would be a strange thing to have.
        chunk_size: Option<u64>,
    },

    /// A Cloudflare R2 bucket.
    R2 {
        /// Bucket name.
        bucket: String,
        /// Cloudflare account id, from which R2's endpoint is derived; falls
        /// back to the environment when unset.
        account: Option<String>,
        /// Explicit endpoint URL, overriding the one derived from
        /// [`account`](Target::R2::account).
        ///
        /// Declared on `R2Def` and read by nothing until this pass: a remote
        /// naming a jurisdiction-specific endpoint went to the derived
        /// `https://<account>.r2.cloudflarestorage.com` anyway.
        ///
        /// When it is set the account id is no longer needed — it exists only to
        /// build the hostname — so a remote may carry either, which is what
        /// [`super::resolve::target_from_entry`] enforces rather than demanding
        /// an account nobody's endpoint uses.
        endpoint: Option<String>,
        /// Multipart part size in bytes, from the remote's `chunk_size`.
        chunk_size: Option<u64>,
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
        /// Transfer window in bytes, from the remote's `chunk_size`.
        ///
        /// `None` takes the backend's compiled-in window. Unlike the object
        /// stores this is not a *part* size — SFTP has no multipart API and
        /// declares no content length — it is the size of the one buffer a
        /// streaming read or write holds, so it is what an sftp transfer costs
        /// in memory and the knob a small container needs.
        ///
        /// The last of the inert settings: it was declared on `SftpDef`,
        /// printed by `dctl config show`, and reached nothing.
        chunk_size: Option<u64>,
    },
}

impl Target {
    /// How the *container* this target writes into is named to an operator.
    ///
    /// Not the remote's configured alias and not [`Target::provider_type`]: this
    /// is what a refusal prints when the store moves out from under a run, and
    /// its reader needs to know which directory or which bucket to go and look
    /// at. The alias would send them to the config file instead. See
    /// [`dctl_store::guard`].
    #[must_use]
    pub fn container(&self) -> String {
        match self {
            Self::Local { root } => root.display().to_string(),
            Self::B2 { bucket, .. } => format!("{PROVIDER_B2}:{bucket}"),
            Self::S3 { bucket, .. } => format!("{PROVIDER_S3}:{bucket}"),
            Self::R2 { bucket, .. } => format!("{PROVIDER_R2}:{bucket}"),
            Self::Sftp { host, base, .. } => format!("{PROVIDER_SFTP}:{host}:{base}"),
        }
    }

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
///
/// `links` is the run's `--links` policy. It is a parameter rather than
/// something the backend reads for itself because it belongs to the
/// *invocation*: a config file describes a place, and what to do about the
/// symbolic links found there is a decision the operator makes at the command
/// line. Only the two backends that walk a real filesystem can use it; passing
/// it to the object stores would be offering a dial that does nothing, which is
/// the class of defect this project has already had to fix: a setting that
/// parses, prints under `dctl config show`, and reaches no code at all.
///
/// `deadlines` is the run's `--timeout`, `--contimeout` and `--max-duration`. It
/// is a parameter for the same reason `links` and `meter` are: it belongs to the
/// invocation rather than to the place, and a backend that read it for itself
/// would be a backend that could disagree with the rest of the run about how
/// long to wait.
///
/// The first two reach every provider that has something to wait for, and
/// `local:` is the one arm that takes neither — see `dctl_store::deadline`,
/// which says why a user-space deadline cannot help a wedged filesystem and
/// would only be a report rather than a remedy. The third reaches **every** arm
/// including `local:`, because it is installed on the retry layer below, which
/// every provider shares.
pub fn build(
    resolved: &Resolved,
    links: LinkPolicy,
    meter: Arc<dyn dctl_store::Meter>,
    deadlines: Deadlines,
) -> Result<Arc<dyn Backend>> {
    let target = resolved.target();

    tracing::debug!(
        { fields::REMOTE } = resolved.name(),
        provider = target.provider_type(),
        "building backend"
    );

    let built = assemble(&ProcessVars, target, links, deadlines.clone())?;
    // Metered, then made to try again. The order matters and is not arbitrary: a
    // retried request really did cross the link on every attempt, so the meter
    // has to sit *underneath* the retry layer and be charged once per attempt.
    // Wrapping the other way round would let a run that is retrying sprint past
    // its `--bwlimit`, which is the opposite of what a limiter is for.
    // The store guard is outermost, and that order matters most. Its probe has
    // to be retried like any other request — a `HEAD` on a bucket that answers
    // `503` must not be read as "the bucket is gone" and refuse every later
    // write — but a *refusal* it issues must never be retried, because a store
    // that has been replaced will still be replaced five seconds later. This
    // order gets both: the probe travels through the retrying backend
    // underneath, and `StoreError::RootChanged` is classified permanent
    // (`dctl_store::retry::observed`) so nothing above tries again.
    // The run's own deadline goes to the retry layer as well as to the
    // backends, because this is where `--timeout` is multiplied: six attempts
    // per request, several distinct requests per copy. A retry layer that did
    // not know when the run had to be over is the whole of a measured defect: a
    // 160 MiB upload with `--timeout 30 --retries 1` had still not ended 943.6 s
    // after the cut, because every layer honoured its own clock and none of them
    // honoured the run's.
    //
    // The stall counter goes with it, and it is the *same cell* the backend
    // underneath was given — `Deadlines` clones the handle, never the count.
    // That is the whole of the stall bound: the second factor above, "several
    // distinct requests per copy", stops multiplying only if every layer that
    // retries counts into one place.
    let backend =
        dctl_store::Retrying::wrap(built.metered(meter), deadlines.run, deadlines.stall.clone());
    Ok(dctl_store::Guarded::wrap(backend, target.container()))
}

/// Construct the provider's own backend for `target`, reading credentials from
/// `vars`.
///
/// **Split out of [`build`] so a test can reach these arms at all.** What each
/// arm does is take the fields a resolved `Target` carries and hand them to a
/// constructor, and the fields include every per-remote setting that survived
/// the configuration file and the resolver — `chunk_size`, `endpoint`,
/// `region`, `account`. Each is one argument in one call, each is the last step
/// of a journey `config::reach` proves the first three quarters of, and dropping
/// one is invisible: the setting still parses, still round-trips through
/// `config show`, and still reaches the `Target`. That defect is on record for
/// the meter — written into one arm of this match and silently omitted from
/// four — and it was measured again on B2's `chunk_size`: dropped at this call
/// and `cargo test --workspace` stayed entirely green.
///
/// The environment is a parameter because it was the reason there was no way in.
/// Four of the five arms demand a credential, `std::env::set_var` is `unsafe`
/// under Rust 2024, and a test that mutated the process environment would be
/// changing another test's answer. See [`crate::remote::vars`].
///
/// # Errors
/// A missing or unusable credential (exit 7), an `sftp` session that would not
/// open, or an `s3`/`r2` configuration a client refuses.
fn assemble(
    vars: &dyn Vars,
    target: &Target,
    links: LinkPolicy,
    deadlines: Deadlines,
) -> Result<Built> {
    Ok(match target {
        Target::Local { root } => Built::Local(LocalFs::new(root.clone()).with_links(links)),

        Target::B2 {
            bucket,
            endpoint,
            chunk_size,
        } => {
            let key_id = env_required(vars, ENV_B2_KEY_ID)?;
            let app_key = env_required(vars, ENV_B2_APP_KEY)?;
            Built::B2(b2_backend(
                key_id,
                app_key,
                bucket,
                endpoint.as_deref(),
                *chunk_size,
                deadlines,
            )?)
        }

        Target::S3 {
            bucket,
            endpoint,
            region,
            chunk_size,
        } => {
            let endpoint = setting_or_env(vars, endpoint.as_deref(), ENV_S3_ENDPOINT)?;
            let region = setting_or_env(vars, region.as_deref(), ENV_S3_REGION)?;
            let access_key = env_required(vars, ENV_S3_ACCESS_KEY)?;
            let secret_key = env_required(vars, ENV_S3_SECRET_KEY)?;
            let config = S3Config::new(endpoint, region, bucket.clone(), access_key, secret_key)
                .with_part_size(*chunk_size);
            Built::S3(S3Backend::new(config, deadlines)?)
        }

        Target::R2 {
            bucket,
            account,
            endpoint,
            chunk_size,
        } => {
            let access_key = env_required(vars, ENV_R2_ACCESS_KEY)?;
            let secret_key = env_required(vars, ENV_R2_SECRET_KEY)?;
            // An explicit endpoint replaces the derived one, and with it the
            // reason the account id is needed at all — so it is only demanded
            // when it is the thing that builds the hostname. Asking for both
            // would make a jurisdiction-specific endpoint impossible to
            // configure without inventing an account id nobody uses.
            let config = match endpoint {
                Some(endpoint) => {
                    R2Backend::config_at(endpoint.clone(), bucket.clone(), access_key, secret_key)
                }
                None => {
                    let account = setting_or_env(vars, account.as_deref(), ENV_R2_ACCOUNT_ID)?;
                    R2Backend::config(&account, bucket.clone(), access_key, secret_key)
                }
            }
            .with_part_size(*chunk_size);
            Built::R2(R2Backend::from_config(config, deadlines)?)
        }

        // No credential is read: `ssh` authenticates the transport from the
        // user's own config, which is the whole reason a cloudflared-proxied host
        // works. This is also the one arm that opens a connection to build, so it
        // is the one that bridges to the async `connect` — see [`connect_sftp`].
        Target::Sftp {
            host,
            base,
            chunk_size,
        } => Built::Sftp(connect_sftp(host, base, *chunk_size, links, deadlines)?),
    })
}

/// A backend that has been constructed but not yet told who is watching it.
///
/// This type exists for one reason and it is worth stating, because the type
/// itself does nothing: **installing the meter is a step every provider needs
/// and no provider's constructor performs**, and while it was written into each
/// arm of the match above, four of the five arms silently dropped it. `local:`
/// was paced and B2, S3, R2 and SFTP were not — so `--bwlimit` was inert on
/// every cloud provider this tool exists to talk to, with nothing to indicate
/// it. That is precisely the failure `dctl_store::meter` warns about in its own
/// documentation, made one layer higher up.
///
/// Splitting the two halves apart means the construction match cannot mention
/// the meter at all, and [`Built::metered`] is one small match whose only job is
/// to install it. A provider added later must add a variant here, and the
/// compiler will not accept the variant without an arm — so the new backend
/// cannot be unpaced by omission. It can still be unpaced *deliberately*, which
/// is a different thing and has to be written down.
enum Built {
    Local(LocalFs),
    B2(B2Backend),
    S3(S3Backend),
    R2(R2Backend),
    Sftp(SftpBackend),
}

impl Built {
    /// Install `meter` and hand back the finished backend.
    ///
    /// Exhaustive by construction: there is no `_ =>`, deliberately, because a
    /// wildcard here would let a provider added later fall through unpaced and
    /// compile perfectly.
    fn metered(self, meter: Arc<dyn dctl_store::Meter>) -> Arc<dyn Backend> {
        match self {
            Self::Local(backend) => Arc::new(backend.with_meter(meter)),
            Self::B2(backend) => Arc::new(backend.with_meter(meter)),
            Self::S3(backend) => Arc::new(backend.with_meter(meter)),
            Self::R2(backend) => Arc::new(backend.with_meter(meter)),
            Self::Sftp(backend) => Arc::new(backend.with_meter(meter)),
        }
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
fn connect_sftp(
    host: &str,
    base: &str,
    chunk_size: Option<u64>,
    links: LinkPolicy,
    deadlines: Deadlines,
) -> Result<SftpBackend> {
    let handle = tokio::runtime::Handle::try_current().map_err(|_| {
        CliError::fatal("the sftp backend must be built inside the async runtime")
            .with_hint("This is an internal error. Please report the command that produced it.")
    })?;
    let config = SftpConfig::new(host, base)
        .with_links(links)
        .with_chunk_size(chunk_size);
    Ok(tokio::task::block_in_place(|| {
        handle.block_on(SftpBackend::connect(config, deadlines))
    })?)
}

/// Build a backend for a spec typed on the command line, without a config file.
///
/// The three steps in one call — parse, resolve against the empty catalog,
/// build — for the commands that run before a configuration is necessarily
/// readable (`dctl init` creating the first vault) and for headless jobs that
/// carry everything in the environment
/// ([the plan](https://doc.dctl.sh/project/plan) §14).
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
pub fn build_backend(
    spec: &str,
    links: LinkPolicy,
    deadlines: Deadlines,
) -> Result<Arc<dyn Backend>> {
    let parsed = RemoteSpec::parse(spec)?;
    let resolved = super::resolve::resolve(&parsed, &())?;
    build(&resolved, links, dctl_store::unmetered(), deadlines)
}

/// Take a setting the config pinned, or fall back to its environment variable.
///
/// The precedence is config-then-environment for the *non-secret* settings only.
/// It exists so a named remote can pin its endpoint permanently while a bare
/// `s3:bucket` — no config at all — still works from exported variables, which
/// is how the CLI behaved before named remotes and how CI jobs are written.
fn setting_or_env(vars: &dyn Vars, configured: Option<&str>, setting: &str) -> Result<String> {
    match configured {
        Some(value) => Ok(value.to_string()),
        None => env_required(vars, setting),
    }
}

/// Read a required setting from the environment, named `DCTL_<SETTING>`.
fn env_required(vars: &dyn Vars, setting: &str) -> Result<String> {
    let variable = dctl_meta::env_var(setting);
    let value = vars.get(&variable);
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

/// Assemble the B2 backend from a resolved target's parts.
///
/// Split out from [`build`] so the journey a `chunk_size` makes — configuration
/// file, resolver, `Target`, backend — can be tested at its last step without
/// exporting a credential into the test process. The resolver's half is covered
/// in [`super::resolve`]; this is the half where a setting that was carried all
/// the way here can still be dropped on the floor — a defect this project has
/// already measured: the meter was installed in one arm of this very match and
/// silently omitted from four.
///
/// On B2 the part size is the whole of an upload's peak memory, so dropping it
/// would not be a lost tuning hint — it would be an operator's container limit
/// silently ignored.
fn b2_backend(
    key_id: String,
    app_key: String,
    bucket: &str,
    endpoint: Option<&str>,
    chunk_size: Option<u64>,
    deadlines: Deadlines,
) -> Result<B2Backend> {
    let backend = B2Backend::new(B2Credentials::new(key_id, app_key), bucket, deadlines)?
        .with_part_size(chunk_size);
    // Applied only when the remote names one, so the published endpoint stays
    // the single source of B2's address for every installation that has not
    // deliberately moved it.
    Ok(match endpoint {
        Some(endpoint) => backend.with_authorize_url(endpoint),
        None => backend,
    })
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
        let backend = build(
            &resolved,
            LinkPolicy::default(),
            dctl_store::unmetered(),
            Deadlines::default(),
        )
        .unwrap();
        assert_eq!(backend.name(), PROVIDER_LOCAL);
    }

    /// Everything four of the five arms demand, and nothing a real deployment
    /// would recognise. Values are placeholders on purpose: nothing here
    /// authorizes, and a credential-shaped literal in a test file is how a real
    /// one eventually gets committed beside it.
    fn credentials() -> crate::remote::vars::FixedVars {
        crate::remote::vars::FixedVars::of(&[
            ("DCTL_B2_KEY_ID", "key-id"),
            ("DCTL_B2_APP_KEY", "app-key"),
            ("DCTL_S3_ACCESS_KEY", "access"),
            ("DCTL_S3_SECRET_KEY", "secret"),
            ("DCTL_R2_ACCESS_KEY", "access"),
            ("DCTL_R2_SECRET_KEY", "secret"),
        ])
    }

    #[test]
    fn every_object_stores_chunk_size_reaches_the_arm_that_builds_it() {
        // **The last step of the journey, and the one nothing could turn red.**
        // `config::reach` proves a `chunk_size` survives the configuration file
        // and the resolver; `a_b2_remotes_chunk_size_reaches_the_backend_that_
        // cuts_the_parts` below proves the *helper* keeps it. What was between
        // them was the line in each arm of `assemble` that passes the resolved
        // `Target`'s field to the constructor — and dropping it on the B2 arm
        // left `cargo test --workspace` entirely green.
        //
        // Three arms, because the setting has three copies of the same one-line
        // wiring and a test covering one leaves the other two deletable — which
        // is the meter's own history: it was written into one arm of this very
        // match and omitted from four.
        //
        // What it costs is not a lost tuning hint. On every one of these the
        // part size **is** the upload's peak working set, so a dropped
        // `chunk_size` is an operator's container memory limit silently ignored
        // and an OOM kill at the first large object.
        let asked = 8 * 1024 * 1024;
        let vars = credentials();

        let b2 = assemble(
            &vars,
            &Target::B2 {
                bucket: "bucket".into(),
                endpoint: None,
                chunk_size: Some(asked),
            },
            LinkPolicy::default(),
            Deadlines::default(),
        )
        .unwrap_or_else(|_| panic!("a b2 target builds from a key pair"));
        let Built::B2(b2) = b2 else {
            panic!("a b2 target must build the b2 backend");
        };
        assert_eq!(
            b2.upload_peak_bytes(),
            asked,
            "b2: a configured chunk_size that stops here is a memory ceiling \
             that parses and does nothing"
        );

        let s3 = assemble(
            &vars,
            &Target::S3 {
                bucket: "bucket".into(),
                endpoint: Some("https://s3.example.invalid".into()),
                region: Some("us-east-1".into()),
                chunk_size: Some(asked),
            },
            LinkPolicy::default(),
            Deadlines::default(),
        )
        .unwrap_or_else(|_| panic!("an s3 target builds"));
        let Built::S3(s3) = s3 else {
            panic!("an s3 target must build the s3 backend");
        };
        assert_eq!(s3.part_size(), asked, "s3");

        let r2 = assemble(
            &vars,
            &Target::R2 {
                bucket: "bucket".into(),
                account: Some("account".into()),
                endpoint: None,
                chunk_size: Some(asked),
            },
            LinkPolicy::default(),
            Deadlines::default(),
        )
        .unwrap_or_else(|_| panic!("an r2 target builds"));
        let Built::R2(r2) = r2 else {
            panic!("an r2 target must build the r2 backend");
        };
        assert_eq!(r2.part_size(), asked, "r2");
    }

    #[test]
    fn a_target_that_configured_no_chunk_size_gets_the_compiled_default() {
        // The control that makes the test above mean something. Without it an
        // arm that ignored its argument and happened to default to 8 MiB would
        // pass, and so would one that returned the number it was asked for from
        // a constant. These are the shipped defaults, and they are not equal to
        // each other or to `asked`.
        let vars = credentials();
        let Ok(Built::B2(b2)) = assemble(
            &vars,
            &Target::B2 {
                bucket: "bucket".into(),
                endpoint: None,
                chunk_size: None,
            },
            LinkPolicy::default(),
            Deadlines::default(),
        ) else {
            panic!("a b2 target builds without a chunk_size");
        };
        assert_eq!(b2.upload_peak_bytes(), 100 * 1024 * 1024);

        let Ok(Built::S3(s3)) = assemble(
            &vars,
            &Target::S3 {
                bucket: "bucket".into(),
                endpoint: Some("https://s3.example.invalid".into()),
                region: Some("us-east-1".into()),
                chunk_size: None,
            },
            LinkPolicy::default(),
            Deadlines::default(),
        ) else {
            panic!("an s3 target builds without a chunk_size");
        };
        assert_eq!(s3.part_size(), 100 * 1024 * 1024);
    }

    /// The refusal `assemble` produced, or a panic naming what it built instead.
    ///
    /// `Built` holds live backends and does not implement `Debug` — deriving it
    /// would put a credential-bearing client's fields one `{:?}` away from a log
    /// — so `expect_err` is not available and this says the same thing without
    /// it.
    fn refusal(built: Result<Built>) -> CliError {
        match built {
            Ok(_) => panic!("a target that cannot be addressed must not build"),
            Err(error) => error,
        }
    }

    #[test]
    fn an_endpoint_that_is_configured_nowhere_is_named_rather_than_guessed_at() {
        // The other settings with a far end in this match. An `endpoint` dropped
        // on the `s3` arm sends every request to AWS instead of the operator's
        // MinIO, with a credential that will not authorize there — so the arm
        // that has neither a pinned setting nor an exported variable has to say
        // which variable is missing.
        let error = refusal(assemble(
            &credentials(),
            &Target::S3 {
                bucket: "bucket".into(),
                endpoint: None,
                region: None,
                chunk_size: None,
            },
            LinkPolicy::default(),
            Deadlines::default(),
        ));
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.message().contains("DCTL_S3_ENDPOINT"), "{error:?}");
    }

    #[test]
    fn a_missing_credential_is_named_rather_than_guessed_at() {
        // And the arm's other half: a credential that is not there is a fatal,
        // named refusal — not a client that fails opaquely at the first request.
        let error = refusal(assemble(
            &crate::remote::vars::FixedVars::of(&[]),
            &Target::B2 {
                bucket: "bucket".into(),
                endpoint: None,
                chunk_size: None,
            },
            LinkPolicy::default(),
            Deadlines::default(),
        ));
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.message().contains("DCTL_B2_KEY_ID"), "{error:?}");
    }

    #[test]
    fn a_b2_remotes_chunk_size_reaches_the_backend_that_cuts_the_parts() {
        // The setting's last step. `resolve` proves it survives the config file;
        // this proves the arm of `build` that receives it does not drop it — and
        // the number it must not drop is the upload's peak memory, which is what
        // `upload_peak_bytes` reports.
        let asked = 8 * 1024 * 1024;
        let backend = b2_backend(
            "k".into(),
            "a".into(),
            "bucket",
            None,
            Some(asked),
            Deadlines::default(),
        )
        .expect("a b2 backend builds from a key pair");
        assert_eq!(
            backend.upload_peak_bytes(),
            asked,
            "a configured chunk_size must reach the backend, or an operator's \
             memory ceiling is a setting that parses and does nothing"
        );

        // And with nothing configured, the compiled default — not zero, and not
        // whatever B2 advertises when the run authorizes.
        let default = b2_backend(
            "k".into(),
            "a".into(),
            "bucket",
            None,
            None,
            Deadlines::default(),
        )
        .expect("a b2 backend builds without a chunk_size");
        assert_eq!(default.upload_peak_bytes(), 100 * 1024 * 1024);
    }

    #[test]
    fn a_b2_remotes_endpoint_reaches_the_client_that_authorizes() {
        // The far end of `endpoint` on b2. `config::reach` proves the value
        // survives the resolver; this proves the arm of `build` that receives it
        // does not drop it — which is the half this project has been caught
        // losing before.
        //
        // The consequence of dropping it is not cosmetic: an operator running a
        // private B2 gateway, or a test pointing at a double, silently talks to
        // Backblaze with their real credentials.
        let backend = b2_backend(
            "k".into(),
            "a".into(),
            "bucket",
            Some("https://b2.internal/b2api/v2/b2_authorize_account"),
            None,
            Deadlines::default(),
        )
        .expect("a b2 backend builds with an endpoint");
        assert_eq!(
            backend.authorize_url(),
            "https://b2.internal/b2api/v2/b2_authorize_account"
        );

        // And with nothing configured, B2's published endpoint — never the empty
        // string, which would fail as a URL parse error three layers down.
        let default = b2_backend(
            "k".into(),
            "a".into(),
            "bucket",
            None,
            None,
            Deadlines::default(),
        )
        .expect("a b2 backend builds without an endpoint");
        assert!(
            default.authorize_url().contains("backblazeb2.com"),
            "an unset endpoint must leave B2's own: {}",
            default.authorize_url()
        );
    }

    #[test]
    fn an_r2_remotes_endpoint_replaces_the_one_derived_from_its_account() {
        // The far end of `endpoint` on r2, and the rule that comes with it: an
        // explicit endpoint makes the account id unnecessary, because deriving
        // the hostname is the only thing R2 uses it for. Demanding both would
        // make a jurisdiction-specific endpoint unconfigurable without inventing
        // an account nobody's URL contains.
        let named = R2Backend::config_at("https://eu.r2.example", "bucket", "ak", "sk");
        assert_eq!(named.endpoint, "https://eu.r2.example");
        // R2's fixed signing region survives, which is the reason `config_at`
        // exists rather than callers reaching for `S3Config::new`: signing for
        // anything else fails with `SignatureDoesNotMatch`.
        let derived = R2Backend::config("acct", "bucket", "ak", "sk");
        assert_eq!(named.region, derived.region);
        assert_ne!(named.endpoint, derived.endpoint);
    }

    #[test]
    fn every_target_reports_the_provider_type_the_config_spells() {
        // The registry, the config file and the log field must agree on the
        // word, or an operator greps for `provider=s3` and finds nothing.
        assert_eq!(local_target().provider_type(), PROVIDER_LOCAL);
        assert_eq!(
            Target::B2 {
                bucket: "b".into(),
                endpoint: None,
                chunk_size: None,
            }
            .provider_type(),
            PROVIDER_B2
        );
        assert_eq!(
            Target::S3 {
                bucket: "b".into(),
                endpoint: None,
                region: None,
                chunk_size: None,
            }
            .provider_type(),
            PROVIDER_S3
        );
        assert_eq!(
            Target::R2 {
                bucket: "b".into(),
                account: None,
                endpoint: None,
                chunk_size: None,
            }
            .provider_type(),
            PROVIDER_R2
        );
        assert_eq!(
            Target::Sftp {
                host: "backup.example.com".into(),
                base: "store".into(),
                chunk_size: None,
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
        let backend =
            build_backend("/srv/data", LinkPolicy::default(), Deadlines::default()).unwrap();
        assert_eq!(backend.name(), PROVIDER_LOCAL);
        assert_eq!(
            build_backend(
                "local:/srv/data",
                LinkPolicy::default(),
                Deadlines::default()
            )
            .unwrap()
            .name(),
            PROVIDER_LOCAL
        );
    }

    #[test]
    fn the_config_free_entry_point_refuses_a_named_remote() {
        // It has no catalog to look one up in, so failing is the only honest
        // answer; silently treating `vault:` as a directory would create the
        // vault in the working directory and report success.
        assert!(
            build_backend("vault:photos", LinkPolicy::default(), Deadlines::default()).is_err()
        );
    }

    #[test]
    fn a_pinned_setting_wins_over_the_environment() {
        // A named remote's endpoint is part of its identity: it must not change
        // because an unrelated variable happens to be exported in this shell.
        // Asserted against an environment that *does* export the variable, so
        // the precedence is what is measured rather than the variable's absence.
        let vars = crate::remote::vars::FixedVars::of(&[(
            "DCTL_S3_ENDPOINT",
            "https://aws.example.invalid",
        )]);
        assert_eq!(
            setting_or_env(&vars, Some("https://minio.internal"), ENV_S3_ENDPOINT).unwrap(),
            "https://minio.internal"
        );
        // …and with nothing pinned, the exported one is what is used.
        assert_eq!(
            setting_or_env(&vars, None, ENV_S3_ENDPOINT).unwrap(),
            "https://aws.example.invalid"
        );
    }
}
