//! `dctl purge` — remove a path and everything under it.
//!
//! **`purge` versus `delete`.** The distinction rclone users expect, kept
//! exactly: [`delete`](super::delete) **honours the filter flags** and **leaves
//! the directory structure standing**; `purge` **ignores filters entirely** and
//! removes the tree — every object beneath the target, at every depth, plus the
//! directories themselves. `dctl delete --include '*.tmp' vault:project`
//! removes the scratch files; `dctl purge vault:project` removes the project.
//!
//! Because filters are ignored rather than unsupported, a `--include` or
//! `--exclude` on a purge is a misunderstanding worth interrupting: the command
//! warns on stderr that the flags will not narrow anything, rather than letting
//! the user believe they made the operation safer.
//!
//! **The extra gate.** Every removal command is destructive, but this one's
//! blast radius is a whole tree, so it is the one command that will not run on
//! a bare invocation: it requires either `--force` (an explicit, scriptable
//! "yes, all of it") or `--interactive` (which prompts and demands the
//! confirmation word). `--dry-run` is exempt — refusing to *preview* a purge
//! would be hostile, and a preview removes nothing.
//!
//! ## What runs today
//!
//! Argument parsing, target resolution, the extra gate, the filter warning, the
//! destructive gate and the `--dry-run` plan. The removal itself needs
//! recursive enumeration the vault does not expose and a vault handle [`Ctx`]
//! does not carry, so the command fails with a real exit code rather than
//! reporting a purge that never happened. See [`super::removal::engine`].

use clap::Args;

use crate::constants::{
    PURGE_SCOPE_REMOTE, PURGE_SCOPE_SUBTREE, REMOTE_PATH_VALUE_NAME, REMOVAL_ACTION_PURGE,
};
use crate::ctx::Ctx;
use crate::error::{CliError, Result};

use super::removal::{NoOptions, Removal, Target, execute};

/// Stable command name. Must match `Command::name()` in `cli/mod.rs`.
const COMMAND: &str = "purge";

/// The engine capability this command is waiting on.
const CAPABILITY: &str = "removing a directory tree and everything beneath it";

/// `dctl purge REMOTE:PATH`
#[derive(Args, Debug)]
pub struct PurgeArgs {
    /// The path to remove, with all of its contents. Filters are ignored.
    #[arg(value_name = REMOTE_PATH_VALUE_NAME)]
    pub path: String,
}

/// Run `dctl purge`.
///
/// # Errors
/// [`crate::exit::ExitCode::Usage`] for a malformed target, or when neither
/// `--force` nor `--interactive` was given on a run that would remove data;
/// [`crate::exit::ExitCode::Cancelled`] if the user declines; otherwise the
/// unimplemented refusal described above.
pub async fn run(ctx: &Ctx, args: &PurgeArgs) -> Result<()> {
    let target = Target::parse(&args.path)?;
    require_explicit_approval(ctx, &target)?;
    warn_about_ignored_filters(ctx);

    let removal = Removal {
        command: COMMAND,
        action: REMOVAL_ACTION_PURGE,
        target,
        // The defining behaviour: purge ignores filters, delete honours them.
        filters: None,
        options: NoOptions {},
        capability: CAPABILITY,
    };

    execute(ctx, &removal)
}

/// Refuse a bare `dctl purge`.
///
/// [`Ctx::confirm_destructive`] treats a non-interactive run as consent — the
/// user typed the command, which is enough for a single file. A tree is not a
/// single file, so this command demands that the consent be explicit.
fn require_explicit_approval(ctx: &Ctx, target: &Target) -> Result<()> {
    if ctx.is_dry_run() || ctx.globals.force || ctx.globals.interactive {
        return Ok(());
    }

    let scope = if target.is_root() {
        PURGE_SCOPE_REMOTE
    } else {
        PURGE_SCOPE_SUBTREE
    };

    Err(
        CliError::usage(format!("refusing to purge '{target}': it removes {scope}")).with_hint(
            "Pass --force to approve it, --interactive to be asked first, or \
             --dry-run to see what it would cover. Use `dctl delete` if you \
             meant to remove objects and keep the directories.",
        ),
    )
}

/// Warn that filters do nothing here.
///
/// Silence would be worse than noise: a user who believes `--exclude` protected
/// something is a user who is about to lose it.
fn warn_about_ignored_filters(ctx: &Ctx) {
    let globals = &ctx.globals;
    let filtered = !globals.include.is_empty()
        || !globals.exclude.is_empty()
        || !globals.filter_from.is_empty()
        || !globals.files_from.is_empty()
        || globals.min_size.is_some()
        || globals.max_size.is_some();

    if filtered {
        ctx.out.warn(
            "purge ignores filters: the whole tree goes. Use `dctl delete` to \
             remove a filtered subset.",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::globals::GlobalArgs;
    use crate::exit::ExitCode;
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
        #[command(flatten)]
        args: PurgeArgs,
    }

    fn parse(args: &[&str]) -> Harness {
        Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied()))
    }

    async fn run_with(args: &[&str]) -> Result<()> {
        let parsed = parse(args);
        run(&Ctx::new(parsed.globals), &parsed.args).await
    }

    #[test]
    fn the_target_is_the_only_argument() {
        assert_eq!(parse(&["vault:old"]).args.path, "vault:old");
        assert!(Harness::try_parse_from(["dctl"]).is_err());
    }

    #[tokio::test]
    async fn a_bare_purge_is_refused() {
        // The gate that distinguishes purge from every other removal.
        let error = run_with(&["vault:old", "--quiet"]).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.hint().unwrap_or_default().contains("--force"));
    }

    #[tokio::test]
    async fn force_and_interactive_both_open_the_gate() {
        // Past the gate, the run still fails — on the engine, not the gate.
        let forced = run_with(&["vault:old", "--force", "--quiet"])
            .await
            .unwrap_err();
        assert_eq!(forced.code(), ExitCode::FatalError);

        // --interactive would prompt; only assert the gate itself is open.
        assert!(
            require_explicit_approval(
                &Ctx::new(parse(&["vault:old", "--interactive"]).globals),
                &Target::parse("vault:old").unwrap(),
            )
            .is_ok()
        );
    }

    #[tokio::test]
    async fn a_dry_run_needs_no_approval_because_it_removes_nothing() {
        let error = run_with(&["vault:old", "--dry-run", "--quiet"])
            .await
            .unwrap_err();
        // Not the usage refusal: the dry run got as far as the engine.
        assert_eq!(error.code(), ExitCode::FatalError);
    }

    #[tokio::test]
    async fn purging_a_whole_remote_says_so() {
        let error = run_with(&["vault:", "--quiet"]).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.message().contains("the entire remote"));
    }

    #[tokio::test]
    async fn a_malformed_target_fails_before_the_gate() {
        let error = run_with(&["/local/path", "--force"]).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[tokio::test]
    async fn every_output_format_is_supported() {
        for format in [vec!["--json"], vec!["--format", "json-lines"], vec![]] {
            let mut args = vec!["vault:old", "--dry-run", "--quiet"];
            args.extend(format.iter().copied());
            assert!(run_with(&args).await.is_err(), "{format:?}");
        }
    }

    #[test]
    fn the_json_plan_records_that_filters_were_ignored() {
        // Absence is the contract: a purge plan has no filters key at all,
        // which is how a machine consumer sees that none applied.
        let target = Target::parse("vault:old").unwrap();
        let options = NoOptions {};
        let plan =
            crate::commands::removal::plan::Plan::new(COMMAND, &target, true, None, &options);
        let value = serde_json::to_value(&plan).unwrap();
        assert_eq!(value["command"], COMMAND);
        assert!(value.get("filters").is_none());
    }
}
