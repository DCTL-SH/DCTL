//! `dctl about` — what is on the other end of a remote.
//!
//! rclone's `about` answers three questions at once: how much is stored, how
//! much the account is allowed, and what the backend can do. DCTL answers each
//! of them as well as it honestly can, which is not equally well:
//!
//! | Question | Answer here | How |
//! |---|---|---|
//! | How much is stored? | exact | measured, by enumerating the remote ([`usage`]) |
//! | What is the allowance? | **not reported**, with the reason | there is no call to make |
//! | What can the backend do? | exact | a fact about this binary ([`capabilities`]) |
//!
//! ## Stored is measured, not asked for
//!
//! For a **vault** the walk is the local encrypted index, so the object count
//! and the total *plaintext* size are exact and cost no provider request. For a
//! **plain** remote — a local directory, a bucket, or a vault's own object store
//! — it is that remote's listing, so the figure is the objects as stored. The
//! basis travels with the number, because a plaintext total and a stored total
//! are both true, are not equal, and get reconciled against invoices.
//!
//! Measuring a vault means unlocking it, so `dctl about archive:` asks for a
//! password. `dctl about archive-store:` does not, and reports the ciphertext
//! side of the same data — which is the separation `dctl init`'s two remotes
//! exist for.
//!
//! ## The allowance is not reported, and the report says exactly why
//!
//! Two independent reasons, both stated in
//! [`ABOUT_LIMITS_NOTE`](crate::constants::ABOUT_LIMITS_NOTE) and carried in
//! `--json` beside the two `null`s they explain: `dctl_store::Backend` exposes
//! no usage or quota call on any provider, and a local filesystem's own free
//! space needs a `statvfs` this crate cannot make under
//! `#![forbid(unsafe_code)]`. A number nobody measured is worse than no number,
//! because it gets believed and then gets used to decide whether a backup will
//! fit — `PLAN.md` §6's promise applied to a read.
//!
//! This is not a special case bolted on: `usage_reporting` and `quota_reporting`
//! are rows in the capability matrix like any other, both unsupported by every
//! provider, and a test in [`capabilities`] fails the moment a backend gains
//! either — which is the reminder to come back here.
//!
//! ## `--capabilities` still needs nothing at all
//!
//! It reports which provider is really behind the name and what its backend can
//! do, reading the config file and stopping: no credential, no network request,
//! no vault, no password, no listing. That makes it usable as a configuration
//! check on a machine where nothing has been set up yet, which is exactly when
//! someone wants to know whether `vault:` points where they think.
//!
//! A vault remote is followed to the remote that actually stores bytes, so the
//! answer describes the provider that will hold the data rather than the wrapper
//! that will not. See [`target`] for the resolution rules.

mod capabilities;
mod report;
mod target;
mod usage;

use clap::Args;

use crate::ctx::Ctx;
use crate::error::Result;

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
    /// Answered from this binary's own backends, so it needs no credentials, no
    /// password and no request. Without it the command additionally measures how
    /// much the remote holds, which costs one listing pass — and, for a vault, an
    /// unlock.
    #[arg(long)]
    pub capabilities: bool,
}

/// Describe a remote.
///
/// # Errors
/// * [`ExitCode::Usage`](crate::exit::ExitCode::Usage) when no remote was given
///   and no default is configured, or when the spec is malformed.
/// * [`ExitCode::FatalError`](crate::exit::ExitCode::FatalError) when the remote
///   is unknown, or when the configuration is unreadable or inconsistent.
/// * [`ExitCode::VaultLocked`](crate::exit::ExitCode::VaultLocked) when a sealed
///   remote will not unlock for the usage measurement.
/// * Whatever the provider reported while listing. A failure is never reported
///   as a zero: "the backup is empty" is a conclusion people act on.
///
/// The remote is resolved **before** anything is measured, deliberately: a user
/// who typed a remote that does not exist should be told about their typo rather
/// than about a listing that failed.
///
/// `--dry-run` changes nothing. The command only reads, so there is no mutation
/// to withhold and a `[dry-run] would describe` line would be noise.
pub async fn run(ctx: &Ctx, args: &AboutArgs) -> Result<()> {
    let described = Described::resolve(ctx, args.remote.as_deref())?;

    // `--capabilities` measures nothing on purpose. It is the mode that answers
    // offline, and enumerating would cost a credential, a password and a listing
    // to produce a figure the caller did not ask for.
    let usage = if args.capabilities {
        None
    } else {
        Some(usage::measure(ctx, &described.spec).await?)
    };

    AboutReport::new(&described, usage).emit(ctx)
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
    fn about_reads_and_never_destroys() {
        // The half of the old claim that still holds in every mode. The other
        // half — "never needs a vault" — stopped being true when the usage
        // report started measuring a sealed remote, and `Command::requires_vault`
        // was corrected rather than left as a documented hope.
        let cli = Cli::try_parse_from(["dctl", "about", "b2:bucket"]).unwrap();
        assert!(!cli.command.is_destructive());
        assert!(cli.command.requires_vault());
    }

    #[tokio::test]
    async fn the_capability_mode_still_answers_without_a_password() {
        // The promise `--capabilities` exists to keep: a configuration check on
        // a machine where nothing has been set up. `--no-ask-password` turns any
        // unlock attempt into VaultLocked, so success here proves none happened.
        let (_dir, ctx) = ctx(&["--no-ask-password"]);
        assert!(run(&ctx, &args(Some("b2:bucket"), true)).await.is_ok());
    }

    #[test]
    fn global_flags_are_not_redeclared_on_this_command() {
        // `--json` belongs to GlobalArgs; a local copy would shadow it.
        let cli = Cli::try_parse_from(["dctl", "about", "b2:bucket", "--json"]).unwrap();
        assert!(cli.globals.json);
    }

    #[tokio::test]
    async fn a_local_directory_is_measured_end_to_end() {
        // The command's own claim, against real bytes rather than a fixture:
        // two files go in, and the report counts both.
        let root = tempfile::tempdir().expect("a temporary directory");
        std::fs::write(root.path().join("a.bin"), vec![0u8; 1024]).expect("a file");
        std::fs::write(root.path().join("b.bin"), b"twelve bytes").expect("a file");

        let (_dir, ctx) = ctx(&["--quiet"]);
        let described =
            Described::resolve(&ctx, Some(&root.path().to_string_lossy())).expect("a path");
        let usage = usage::measure(&ctx, &described.spec)
            .await
            .expect("a directory can be measured");

        assert_eq!(usage.objects, 2);
        assert_eq!(usage.bytes, Some(1024 + 12));
        assert!(
            run(&ctx, &args(Some(&root.path().to_string_lossy()), false))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn a_remote_that_cannot_be_reached_fails_rather_than_reporting_zero() {
        // The rule the whole crate is built on: no answer is better than an
        // invented one, and a wrong "0 B used" decides whether a backup runs.
        // No B2 credentials are exported here, so the listing cannot happen.
        let (_dir, ctx) = ctx(&[]);
        let error = run(&ctx, &args(Some("b2:bucket"), false))
            .await
            .expect_err("an unreachable bucket cannot be measured");
        assert_ne!(error.code(), ExitCode::Success);
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
    async fn an_unknown_remote_is_diagnosed_before_anything_is_measured() {
        // Validation order matters: a user with a typo should be told about the
        // typo, not about a listing that failed.
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
            // And a remote that cannot be reached fails identically in every
            // format, rather than a machine consumer receiving a silent success.
            let error = run(&ctx, &args(Some("b2:bucket"), false))
                .await
                .expect_err("an unreachable bucket cannot be measured");
            assert_ne!(error.code(), ExitCode::Success, "{format}");
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
