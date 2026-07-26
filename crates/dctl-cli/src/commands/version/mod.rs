//! `dctl version` — which build this is, and what produced it.
//!
//! The command with the strictest operational requirement in the whole CLI: it
//! must work **with no configuration, no network, no index and no vault**. It is
//! the first thing someone runs when the tool is misbehaving, and a diagnostic
//! that needs the thing being diagnosed is not a diagnostic. Nothing in this
//! module opens a file, resolves a remote, reads an environment variable at run
//! time, or asks for a password; every value it prints was decided when the
//! binary was compiled (see [`build_info`]).
//!
//! That is also why `Command::requires_vault` excludes it — see
//! [`crate::cli::Command::requires_vault`] — and why [`report::VersionReport`]
//! is built by an infallible constructor rather than a `Result`.
//!
//! ## What it prints
//!
//! Version, executable name, commit, compiler, target triple, cargo profile,
//! operating system, architecture, enabled features, and whether debug
//! assertions are on. Facts that could not be established are shown as absent
//! rather than guessed — see the [`build_info`] module docs for why a wrong
//! commit hash is worse than a missing one.
//!
//! ## `--check` is not implemented, and says so
//!
//! Asking whether a newer release exists needs a release feed to ask, and DCTL
//! has none in this build. Rather than printing "you are up to date" — a claim
//! about work that never happened, which `PLAN.md` §6 forbids outright — the
//! flag returns [`CliError::unimplemented`] and a real exit code.
//!
//! The build report is still printed first, and deliberately so: `--check` is
//! typed by someone whose machine is already misbehaving, and swallowing the one
//! part of the command that does work would leave them with nothing. The
//! non-zero exit says precisely what did not happen, and the hint says it in
//! words.

mod build_info;
mod report;

use clap::Args;

use crate::constants::{VERSION_UPDATE_CHECK_FEATURE, VERSION_UPDATE_CHECK_HINT};
use crate::ctx::Ctx;
use crate::error::{CliError, Result};

use report::VersionReport;

/// Arguments for `dctl version`.
///
/// No positional arguments, and no flags beyond `--check`: everything else this
/// command could be asked to vary — the output format, colour, quiet — already
/// lives on [`crate::cli::GlobalArgs`].
#[derive(Args, Debug)]
pub struct VersionArgs {
    /// Also check whether a newer release is available.
    #[arg(long)]
    pub check: bool,
}

/// Print build information, and optionally look for an update.
///
/// # Errors
/// Only two ways to fail, and neither depends on the machine's configuration:
/// a stdout write that is not a broken pipe, and
/// [`ExitCode::FatalError`](crate::exit::ExitCode::FatalError) from `--check`,
/// which no build can yet satisfy.
///
/// `--dry-run` changes nothing here. The command mutates nothing, so there is
/// nothing for a dry run to withhold, and a `[dry-run] would print the version`
/// line would be noise rather than safety.
pub async fn run(ctx: &Ctx, args: &VersionArgs) -> Result<()> {
    VersionReport::current().emit(ctx)?;

    if args.check {
        return Err(CliError::unimplemented(VERSION_UPDATE_CHECK_FEATURE)
            .with_hint(VERSION_UPDATE_CHECK_HINT));
    }

    Ok(())
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

    fn ctx(args: &[&str]) -> Ctx {
        let parsed = Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied()));
        Ctx::new(parsed.globals)
    }

    const fn args(check: bool) -> VersionArgs {
        VersionArgs { check }
    }

    #[test]
    fn the_command_parses_with_and_without_the_check_flag() {
        let cli = Cli::try_parse_from(["dctl", "version"]).unwrap();
        assert_eq!(cli.command.name(), "version");

        let checked = Cli::try_parse_from(["dctl", "version", "--check"]).unwrap();
        match checked.command {
            crate::cli::Command::Version(args) => assert!(args.check),
            other => panic!("parsed as {other:?}"),
        }
    }

    #[test]
    fn version_takes_no_positional_arguments() {
        // Silently ignoring one would hide `dctl version vault:` — a user who
        // meant `dctl about vault:`.
        assert!(Cli::try_parse_from(["dctl", "version", "vault:"]).is_err());
    }

    #[test]
    fn version_never_needs_a_vault() {
        // Enforced in the command tree, asserted here because this module is
        // where the requirement is documented.
        let cli = Cli::try_parse_from(["dctl", "version"]).unwrap();
        assert!(!cli.command.requires_vault());
    }

    #[tokio::test]
    async fn it_succeeds_with_no_config_no_index_and_no_password() {
        // The operational contract: this is what someone runs when everything
        // else is broken, so every one of these must still return Ok.
        for flags in [
            vec![],
            vec!["--config", "/nonexistent/dctl/config.toml"],
            vec!["--index", "/nonexistent/dctl/vault.redb"],
            vec!["--no-ask-password"],
            vec!["--remote", "definitely-not-a-remote:"],
            vec!["--quiet"],
        ] {
            let ctx = ctx(&flags);
            assert!(run(&ctx, &args(false)).await.is_ok(), "{flags:?} failed");
        }
    }

    #[tokio::test]
    async fn every_output_format_is_supported() {
        for format in ["text", "json", "json-lines"] {
            let ctx = ctx(&["--format", format]);
            assert!(run(&ctx, &args(false)).await.is_ok(), "{format} failed");
        }
        assert!(run(&ctx(&["--json"]), &args(false)).await.is_ok());
    }

    #[tokio::test]
    async fn dry_run_changes_nothing_about_a_read_only_command() {
        // No mutation to withhold, so the outcome must be identical.
        let plain = run(&ctx(&[]), &args(false)).await;
        let dry = run(&ctx(&["--dry-run"]), &args(false)).await;
        assert_eq!(plain.is_ok(), dry.is_ok());
    }

    #[tokio::test]
    async fn the_update_check_fails_loudly_rather_than_claiming_to_be_current() {
        // The rule this whole crate is built around: no success message for
        // work that did not happen.
        let error = run(&ctx(&[]), &args(true)).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert_ne!(error.code(), ExitCode::Success);
        assert!(
            error.message().contains("--check"),
            "the message must name the flag that failed: {}",
            error.message()
        );
        assert!(
            error.hint().is_some_and(|hint| hint.contains("printed")),
            "the hint must say the report above is real"
        );
    }

    #[tokio::test]
    async fn the_update_check_fails_in_every_format() {
        // A JSON consumer must get the same classification as a human, not a
        // silent success because the report serialised fine.
        for format in ["text", "json", "json-lines"] {
            let ctx = ctx(&["--format", format]);
            let error = run(&ctx, &args(true)).await.unwrap_err();
            assert_eq!(error.code(), ExitCode::FatalError, "{format}");
        }
    }
}
