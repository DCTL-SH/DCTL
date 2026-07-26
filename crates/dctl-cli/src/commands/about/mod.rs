//! `dctl about` — what is on the other end of a remote.
//!
//! rclone's `about` answers three questions at once: how much is stored, how
//! much the account is allowed, and what the backend can do. DCTL splits them,
//! because in this build only the third has an honest answer.
//!
//! ## Usage and quota are not implemented, and say so
//!
//! `dctl_store::Backend` has no usage or quota call — there is no method to
//! invoke, on any provider — so `dctl about REMOTE` cannot report either. It
//! returns [`CliError::unimplemented`] with a real exit code rather than
//! printing zeroes, an empty table, or a cheerful "0 B used": a number nobody
//! measured is worse than no number, because it gets believed and then gets used
//! to decide whether a backup will fit. That is `PLAN.md` §6's core promise
//! applied to a read.
//!
//! The refusal is not a special case bolted on: `usage_reporting` and
//! `quota_reporting` are rows in the capability matrix like any other, both
//! unsupported by every provider, and a test in [`capabilities`] fails the
//! moment a backend gains either — which is the reminder to delete the gate
//! below.
//!
//! ## What does work, and needs nothing
//!
//! `dctl about --capabilities REMOTE` reports which provider is really behind
//! the name and what its backend can do. It reads the config file and stops:
//! no credential, no network request, no vault, no password — see
//! [`crate::cli::Command::requires_vault`]. That makes it usable as a
//! configuration check on a machine where nothing has been set up yet, which is
//! exactly when someone wants to know whether `vault:` points where they think.
//!
//! A vault remote is followed to the remote that actually stores bytes, so the
//! answer describes the provider that will hold the data rather than the wrapper
//! that will not. See [`target`] for the resolution rules.

mod capabilities;
mod report;
mod target;

use clap::Args;

use crate::constants::{ABOUT_USAGE_FEATURE, ABOUT_USAGE_HINT};
use crate::ctx::Ctx;
use crate::error::{CliError, Result};

use report::AboutReport;
use target::Described;

/// Arguments for `dctl about`.
///
/// `--json` is *not* declared here: it is a global flag on
/// [`crate::cli::GlobalArgs`] and reaches this command through
/// `ctx.out.format()` like every other. Redeclaring it would shadow the global
/// and give the same word two meanings.
#[derive(Args, Debug)]
pub struct AboutArgs {
    /// Remote to describe, as REMOTE or REMOTE:PATH. Defaults to --remote.
    #[arg(value_name = "REMOTE")]
    pub remote: Option<String>,

    /// Report what the remote's backend can do, and stop.
    ///
    /// Answered from this binary's own backends, so it needs no credentials and
    /// makes no request. Without it the command reports usage and quota, which
    /// no provider in this build can supply.
    #[arg(long)]
    pub capabilities: bool,
}

/// Describe a remote.
///
/// # Errors
/// * [`ExitCode::Usage`](crate::exit::ExitCode::Usage) when no remote was given
///   and no default is configured, or when the spec is malformed.
/// * [`ExitCode::FatalError`](crate::exit::ExitCode::FatalError) when the remote
///   is unknown, when the configuration is unreadable or inconsistent, and —
///   without `--capabilities` — for the usage and quota report itself.
///
/// The remote is resolved **before** the unimplemented gate, deliberately: a
/// user who typed a remote that does not exist should be told about their typo,
/// not about a missing engine.
///
/// `--dry-run` changes nothing. The command only reads, so there is no mutation
/// to withhold and a `[dry-run] would describe` line would be noise.
pub async fn run(ctx: &Ctx, args: &AboutArgs) -> Result<()> {
    let described = Described::resolve(ctx, args.remote.as_deref())?;

    if args.capabilities {
        return AboutReport::new(&described).emit(ctx);
    }

    Err(CliError::unimplemented(ABOUT_USAGE_FEATURE).with_hint(ABOUT_USAGE_HINT))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Cli, GlobalArgs};
    use crate::exit::ExitCode;
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    /// A context whose configuration file does not exist, so a test never reads
    /// the developer's real remotes.
    fn ctx(extra: &[&str]) -> (tempfile::TempDir, Ctx) {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir
            .path()
            .join("absent.toml")
            .to_string_lossy()
            .into_owned();
        let mut flags = vec!["--config".to_string(), path];
        flags.extend(extra.iter().map(|flag| (*flag).to_string()));

        let parsed =
            Harness::parse_from(std::iter::once("dctl".to_string()).chain(flags.iter().cloned()));
        (dir, Ctx::new(parsed.globals))
    }

    fn args(remote: Option<&str>, capabilities: bool) -> AboutArgs {
        AboutArgs {
            remote: remote.map(str::to_string),
            capabilities,
        }
    }

    #[test]
    fn the_remote_is_optional_and_the_flag_is_long_only() {
        assert!(Cli::try_parse_from(["dctl", "about"]).is_ok());
        assert!(Cli::try_parse_from(["dctl", "about", "b2:bucket"]).is_ok());
        assert!(Cli::try_parse_from(["dctl", "about", "b2:bucket", "--capabilities"]).is_ok());
        // A second positional would hide a typo in `dctl about a b`.
        assert!(Cli::try_parse_from(["dctl", "about", "a:", "b:"]).is_err());
    }

    #[test]
    fn about_never_needs_a_vault() {
        // It reads the config file and nothing else, so it must not prompt for
        // a password — asserted here because this module documents the claim.
        let cli = Cli::try_parse_from(["dctl", "about", "b2:bucket"]).unwrap();
        assert!(!cli.command.requires_vault());
        assert!(!cli.command.is_destructive());
    }

    #[test]
    fn global_flags_are_not_redeclared_on_this_command() {
        // `--json` belongs to GlobalArgs; a local copy would shadow it.
        let cli = Cli::try_parse_from(["dctl", "about", "b2:bucket", "--json"]).unwrap();
        assert!(cli.globals.json);
    }

    #[tokio::test]
    async fn usage_and_quota_fail_loudly_rather_than_reporting_zero() {
        // The rule the whole crate is built on: no answer is better than an
        // invented one, and a wrong "0 B used" decides whether a backup runs.
        let (_dir, ctx) = ctx(&[]);
        let error = run(&ctx, &args(Some("b2:bucket"), false))
            .await
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert_ne!(error.code(), ExitCode::Success);
        assert!(
            error
                .hint()
                .is_some_and(|hint| hint.contains("--capabilities"))
        );
    }

    #[tokio::test]
    async fn the_capability_report_succeeds_with_no_credentials_and_no_network() {
        // No provider credentials are exported in the test environment, which is
        // the point: this must answer without any.
        let (_dir, ctx) = ctx(&[]);
        for remote in ["b2:bucket", "s3:bucket/prefix", "/srv/data", "./photos"] {
            assert!(
                run(&ctx, &args(Some(remote), true)).await.is_ok(),
                "{remote} failed"
            );
        }
    }

    #[tokio::test]
    async fn an_unknown_remote_is_diagnosed_before_the_unimplemented_gate() {
        // Validation order matters: a user with a typo should be told about the
        // typo, not about a missing engine.
        let (_dir, ctx) = ctx(&[]);
        let error = run(&ctx, &args(Some("vault:photos"), false))
            .await
            .unwrap_err();
        assert!(
            error.message().contains("vault"),
            "the typo was hidden behind the engine gate: {}",
            error.message()
        );
    }

    #[tokio::test]
    async fn a_missing_remote_is_a_usage_error_in_both_modes() {
        let (_dir, ctx) = ctx(&[]);
        for capabilities in [true, false] {
            let error = run(&ctx, &args(None, capabilities)).await.unwrap_err();
            assert_eq!(error.code(), ExitCode::Usage, "capabilities={capabilities}");
        }
    }

    #[tokio::test]
    async fn every_output_format_is_supported() {
        for format in ["text", "json", "json-lines"] {
            let (_dir, ctx) = ctx(&["--format", format]);
            assert!(
                run(&ctx, &args(Some("b2:bucket"), true)).await.is_ok(),
                "{format} failed"
            );
            // The refusal must classify identically in every format, rather than
            // a machine consumer receiving a silent success.
            let error = run(&ctx, &args(Some("b2:bucket"), false))
                .await
                .unwrap_err();
            assert_eq!(error.code(), ExitCode::FatalError, "{format}");
        }
    }

    #[tokio::test]
    async fn dry_run_changes_nothing_about_a_read_only_command() {
        let (_dir, plain) = ctx(&[]);
        let (_dry_dir, dry) = ctx(&["--dry-run"]);
        assert_eq!(
            run(&plain, &args(Some("b2:bucket"), true)).await.is_ok(),
            run(&dry, &args(Some("b2:bucket"), true)).await.is_ok(),
        );
        assert_eq!(
            run(&plain, &args(Some("b2:bucket"), false))
                .await
                .err()
                .map(|e| e.code()),
            run(&dry, &args(Some("b2:bucket"), false))
                .await
                .err()
                .map(|e| e.code()),
        );
    }
}
