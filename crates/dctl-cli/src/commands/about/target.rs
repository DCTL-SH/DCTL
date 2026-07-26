//! From what the user typed to the provider that would actually store bytes.
//!
//! `dctl about` needs one thing before it can say anything useful: which
//! provider is on the other end. That is not always the type of the remote the
//! user named. A vault remote stores nothing itself — it wraps another remote
//! and encrypts on the way through (`PLAN.md` §14) — so `vault:` may be a
//! `vault` whose bytes land in `b2`, and a capability report that answered
//! "vault" would be answering the wrong question.
//!
//! ## Three ways a name resolves, in order
//!
//! 1. A **filesystem path** — `./photos`, `/srv/data`, `C:\data`, `local:/srv` —
//!    is the local provider. Decided by [`RemoteSpec`], on every platform
//!    identically, so a drive letter is never mistaken for a remote called `C`.
//! 2. A **configured remote** wins next, and its vault chain is followed to the
//!    remote that stores bytes. The chain is walked by
//!    [`crate::config::vault_chain`], which is also what detects a cycle or a
//!    dangling base — so a broken config is diagnosed here rather than producing
//!    a confident answer about the wrong provider.
//! 3. A **provider shorthand** — `b2:bucket`, `s3:bucket/prefix` — resolves to
//!    that provider with no config at all, which is the headless case
//!    `PLAN.md` §14 requires to keep working.
//!
//! Anything else is an unknown remote and a hard failure. It is never quietly
//! reinterpreted as a directory: reporting on the wrong thing is worse than
//! reporting on nothing.
//!
//! ## Nothing here touches the network
//!
//! Resolution reads the config file and stops. No credential is looked up, no
//! backend is built, no request is made — which is what lets
//! `dctl about --capabilities` answer on a machine with no keys exported.

use crate::config;
use crate::constants::{
    ABOUT_TARGET_HINT, INLINE_LIST_SEPARATOR, PROVIDER_LOCAL, REMOTE_PROVIDER_TYPES,
};
use crate::ctx::Ctx;
use crate::error::{CliError, Result};
use crate::remote::RemoteSpec;

/// A remote, resolved as far as it can be without connecting to it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Described {
    /// The remote as the user wrote it, normalised through [`RemoteSpec`].
    pub remote: String,
    /// The named remote's own provider type — `vault` for a vault remote.
    pub provider: &'static str,
    /// The provider that actually holds bytes: the far end of the vault chain,
    /// and the one whose capabilities are reported.
    pub storage_provider: &'static str,
    /// Whether anything in the chain encrypts on the way through.
    pub encrypted: bool,
    /// The remote names walked, nearest first. Empty for a filesystem path,
    /// which is not a named remote at all.
    pub chain: Vec<String>,
}

impl Described {
    /// Resolve the positional argument, falling back to `--remote`.
    ///
    /// # Errors
    /// [`ExitCode::Usage`](crate::exit::ExitCode::Usage) when there is nothing
    /// to describe or the spec is malformed;
    /// [`ExitCode::FatalError`](crate::exit::ExitCode::FatalError) when the
    /// remote is unknown, or when the configuration file is unreadable or
    /// internally inconsistent.
    pub fn resolve(ctx: &Ctx, argument: Option<&str>) -> Result<Self> {
        let spec = argument
            .or(ctx.globals.remote.as_deref())
            .map(str::trim)
            .filter(|spec| !spec.is_empty())
            .ok_or_else(|| {
                CliError::usage("no remote given and no default remote configured")
                    .with_hint(ABOUT_TARGET_HINT)
            })?;

        let parsed = RemoteSpec::parse(spec)?;
        // Rendered from the parsed spec rather than echoed back, so the report
        // shows how the argument was *understood*: `C:\data` comes back as a
        // path, and `vault:./a//b` comes back canonicalised.
        let display = parsed.to_string();

        match parsed {
            // A path needs no configuration, no credentials and no lookup.
            RemoteSpec::Local(_) => Ok(Self {
                remote: display,
                provider: PROVIDER_LOCAL,
                storage_provider: PROVIDER_LOCAL,
                encrypted: false,
                chain: Vec::new(),
            }),

            RemoteSpec::Named { remote, .. } => Self::named(ctx, &remote, display),
        }
    }

    /// Resolve a name that is not a filesystem path.
    fn named(ctx: &Ctx, remote: &str, display: String) -> Result<Self> {
        let path = config::resolve_path(ctx.globals.config.as_deref());
        let configured = config::load_or_default(&path)?;

        if configured.contains(remote) {
            // Walking the chain is what turns `vault:` into "a vault remote whose
            // bytes land in b2", and what surfaces a cycle or a dangling base as
            // a configuration error rather than as a confident wrong answer.
            let chain = config::vault_chain(&configured, remote)?;

            let provider = configured
                .get(remote)
                .map_or(PROVIDER_LOCAL, |def| def.type_name());
            let storage_provider = chain
                .last()
                .and_then(|name| configured.get(name))
                .map_or(provider, |def| def.type_name());
            let encrypted = chain
                .iter()
                .filter_map(|name| configured.get(name))
                .any(|def| def.is_vault());

            return Ok(Self {
                remote: display,
                provider,
                storage_provider,
                encrypted,
                chain: chain.into_iter().map(str::to_string).collect(),
            });
        }

        if let Some(provider) = shorthand(remote) {
            return Ok(Self {
                remote: display,
                provider,
                storage_provider: provider,
                encrypted: false,
                chain: vec![remote.to_string()],
            });
        }

        Err(
            CliError::fatal(format!("unknown remote '{remote}'")).with_hint(format!(
                "Run `dctl config list` to see configured remotes, or address a \
                 provider directly as one of {}.",
                provider_list()
            )),
        )
    }
}

/// The provider a bare provider name stands for, if it is one.
///
/// `local` is accepted even though [`RemoteSpec`] turns `local:` into a path one
/// step earlier, because a config-free `--remote local` should still describe
/// the filesystem rather than fail.
fn shorthand(name: &str) -> Option<&'static str> {
    REMOTE_PROVIDER_TYPES
        .iter()
        .find(|(provider, _)| *provider == name)
        .map(|&(provider, _)| provider)
}

/// The advertised provider types, for a hint. Derived from the table rather than
/// written out, so a new provider appears in every message that lists them.
fn provider_list() -> String {
    REMOTE_PROVIDER_TYPES
        .iter()
        .map(|&(name, _)| name)
        .collect::<Vec<_>>()
        .join(INLINE_LIST_SEPARATOR)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::GlobalArgs;
    use crate::constants::{PROVIDER_B2, PROVIDER_S3, PROVIDER_VAULT};
    use crate::exit::ExitCode;
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn ctx(args: &[&str]) -> Ctx {
        let parsed = Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied()));
        Ctx::new(parsed.globals)
    }

    /// A context pointed at a config file written for this test.
    ///
    /// Always `--config`, never the platform default: a test that read the
    /// developer's real configuration would pass or fail depending on whose
    /// machine it ran on, which is the one thing a test may not do.
    ///
    /// The directory is returned alongside the context because dropping it
    /// deletes the fixture, and the file has to outlive the call under test.
    fn ctx_with_config(body: &str) -> (tempfile::TempDir, Ctx) {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("config.toml");
        std::fs::write(&path, body).expect("the fixture is writable");
        let ctx = ctx(&["--config", &path.to_string_lossy()]);
        (dir, ctx)
    }

    /// A context whose configuration file does not exist.
    ///
    /// The fresh installation `PLAN.md` §14 requires to keep working:
    /// `load_or_default` answers an absent file with an empty configuration, so
    /// only the provider shorthands resolve.
    fn ctx_without_config() -> (tempfile::TempDir, Ctx) {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("absent.toml");
        let ctx = ctx(&["--config", &path.to_string_lossy()]);
        (dir, ctx)
    }

    /// The same, with extra global flags appended.
    fn ctx_without_config_plus(extra: &[&str]) -> (tempfile::TempDir, Ctx) {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir
            .path()
            .join("absent.toml")
            .to_string_lossy()
            .into_owned();
        let mut flags = vec!["--config".to_string(), path];
        flags.extend(extra.iter().map(|flag| (*flag).to_string()));
        let borrowed: Vec<&str> = flags.iter().map(String::as_str).collect();
        (dir, ctx(&borrowed))
    }

    #[test]
    fn a_filesystem_path_resolves_with_no_config_at_all() {
        let (_dir, ctx) = ctx_without_config();
        for spec in ["/srv/data", "./photos", r"C:\Users\me", "local:/srv/data"] {
            let described = Described::resolve(&ctx, Some(spec)).unwrap();
            assert_eq!(described.provider, PROVIDER_LOCAL, "{spec}");
            assert_eq!(described.storage_provider, PROVIDER_LOCAL, "{spec}");
            assert!(!described.encrypted);
            assert!(described.chain.is_empty(), "a path is not a named remote");
        }
    }

    #[test]
    fn a_drive_letter_is_never_looked_up_as_a_remote() {
        // The sharpest edge in the CLI, exercised end to end: even with a remote
        // genuinely called `C`, a drive path stays a path.
        let (_dir, ctx) = ctx_with_config("[remotes.C]\ntype = \"b2\"\nbucket = \"wrong\"\n");
        let described = Described::resolve(&ctx, Some(r"C:\Users\me")).unwrap();
        assert_eq!(described.provider, PROVIDER_LOCAL);
    }

    #[test]
    fn a_provider_shorthand_resolves_without_a_config_file() {
        // The headless case: credentials in the environment, no file on disk.
        let (_dir, ctx) = ctx_without_config();
        let described = Described::resolve(&ctx, Some("b2:my-bucket")).unwrap();
        assert_eq!(described.provider, PROVIDER_B2);
        assert_eq!(described.storage_provider, PROVIDER_B2);
        assert_eq!(described.chain, vec!["b2".to_string()]);
        assert!(!described.encrypted);
    }

    #[test]
    fn a_configured_remote_reports_its_own_provider() {
        let (_dir, ctx) = ctx_with_config("[remotes.archive]\ntype = \"s3\"\nbucket = \"cold\"\n");
        let described = Described::resolve(&ctx, Some("archive:photos")).unwrap();
        assert_eq!(described.provider, PROVIDER_S3);
        assert_eq!(described.storage_provider, PROVIDER_S3);
        assert!(!described.encrypted);
        assert_eq!(described.chain, vec!["archive".to_string()]);
    }

    #[test]
    fn a_vault_remote_reports_the_provider_that_actually_stores_the_bytes() {
        // The reason this module exists: answering "vault" would describe the
        // wrapper's capabilities, and the wrapper stores nothing.
        let (_dir, ctx) = ctx_with_config(
            "[remotes.b2prod]\ntype = \"b2\"\nbucket = \"photos\"\n\
             \n[remotes.vault]\ntype = \"vault\"\nbase = \"b2prod\"\n",
        );
        let described = Described::resolve(&ctx, Some("vault:2024")).unwrap();
        assert_eq!(described.provider, PROVIDER_VAULT);
        assert_eq!(described.storage_provider, PROVIDER_B2);
        assert!(described.encrypted);
        assert_eq!(
            described.chain,
            vec!["vault".to_string(), "b2prod".to_string()]
        );
    }

    #[test]
    fn a_remote_may_not_shadow_a_provider_shorthand() {
        // Shadowing is refused rather than resolved, and the refusal happens
        // when the config is read — not when a transfer is halfway done.
        //
        // The alternative (an explicit definition silently beating the
        // convention) would make `s3:bucket` mean different things depending on
        // whether a config file happens to define an `s3` remote. The same
        // script would then send data to different providers on two machines,
        // with nothing on screen to say so. That is precisely the class of
        // ambiguity a tool holding irreplaceable data must not have, so the
        // name is rejected at the point it is introduced.
        let (_dir, ctx) =
            ctx_with_config("[remotes.s3]\ntype = \"b2\"\nbucket = \"actually-b2\"\n");
        let error = Described::resolve(&ctx, Some("s3:anything")).unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(
            error.message().contains("provider type"),
            "the message must name the collision: {}",
            error.message()
        );
        assert!(
            error.hint().is_some(),
            "a refusal must say how to fix it: pick another name"
        );
    }

    #[test]
    fn a_drive_letter_outranks_even_a_provider_collision_check() {
        // `C` is not a provider shorthand, so the drive-letter rule is what
        // decides here — and it decides before any config lookup happens.
        let (_dir, ctx) = ctx_without_config();
        let described = Described::resolve(&ctx, Some(r"C:\data")).unwrap();
        assert_eq!(described.provider, PROVIDER_LOCAL);
    }

    #[test]
    fn an_unknown_remote_is_a_hard_failure_and_never_a_directory() {
        // Quietly describing a directory called `vault:photos` would answer a
        // question the user never asked.
        let (_dir, ctx) = ctx_without_config();
        let error = Described::resolve(&ctx, Some("vault:photos")).unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.message().contains("vault"));
        assert!(
            error
                .hint()
                .is_some_and(|hint| hint.contains("config list"))
        );
    }

    #[test]
    fn a_broken_vault_chain_is_reported_rather_than_answered() {
        // A dangling base means the config is wrong; describing `vault` as if it
        // resolved would hide that.
        let (_dir, ctx) =
            ctx_with_config("[remotes.vault]\ntype = \"vault\"\nbase = \"missing\"\n");
        let error = Described::resolve(&ctx, Some("vault:")).unwrap_err();
        assert_ne!(error.code(), ExitCode::Success);
    }

    #[test]
    fn the_default_remote_is_used_when_no_argument_is_given() {
        let (_dir, with_flag) = ctx_without_config_plus(&["--remote", "b2:bucket"]);
        assert_eq!(
            Described::resolve(&with_flag, None).unwrap().provider,
            PROVIDER_B2
        );
        // The argument wins over the flag when both are present: a user who
        // names a remote on the command line means that one.
        assert_eq!(
            Described::resolve(&with_flag, Some("/srv/data"))
                .unwrap()
                .provider,
            PROVIDER_LOCAL
        );
    }

    #[test]
    fn no_remote_anywhere_is_a_usage_error_with_a_way_out() {
        let (_dir, ctx) = ctx_without_config();
        let error = Described::resolve(&ctx, None).unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.hint().is_some_and(|hint| hint.contains("--remote")));
    }

    #[test]
    fn a_blank_argument_is_treated_as_absent_rather_than_as_a_remote() {
        // `dctl about ""` and `dctl about` must fail the same way.
        let (_dir, ctx) = ctx_without_config();
        for argument in [Some(""), Some("   "), None] {
            let error = Described::resolve(&ctx, argument).unwrap_err();
            assert_eq!(error.code(), ExitCode::Usage, "{argument:?}");
        }
    }

    #[test]
    fn the_shorthand_table_is_the_provider_table() {
        for (provider, _) in REMOTE_PROVIDER_TYPES {
            assert_eq!(shorthand(provider), Some(*provider));
        }
        assert_eq!(shorthand("gdrive"), None);
        // A vault remote is not a place to put bytes, so it is not a shorthand.
        assert_eq!(shorthand(PROVIDER_VAULT), None);
    }
}
