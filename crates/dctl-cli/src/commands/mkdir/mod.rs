//! `dctl mkdir` — create a directory.
//!
//! ## What a directory is here
//!
//! Object stores have no directories. `photos/2024/a.jpg` is a single flat key
//! that happens to contain slashes, and a "directory" is nothing more than a
//! shared prefix among keys — which means a directory containing no objects does
//! not exist at all, and cannot be listed, entered or synced.
//!
//! `mkdir` closes that gap the way every object-store tool does: it writes a
//! zero-byte **marker object** at `<dir>/.dctl-dir`
//! ([`DIRECTORY_MARKER_NAME`](crate::constants::DIRECTORY_MARKER_NAME)). The
//! marker gives the prefix at least one key, so the directory survives a
//! listing, a `sync` and a restore. Listing commands hide markers and `rmdir`
//! treats a directory holding nothing else as empty, so the illusion stays
//! consistent from every angle.
//!
//! On a backend that *does* have directories — a local filesystem, SFTP — the
//! engine will create a real directory instead and skip the marker. That choice
//! belongs to the backend, not to this command, which is why the plan describes
//! the marker rather than promising it.
//!
//! ## Engine reality (`PLAN.md` §6, §11)
//!
//! Parsing, canonicalisation, the `--parents` chain, the marker naming, the
//! `--dry-run` report and the JSON shape are all complete and tested here.
//! Writing the object is not: `dctl-core::Vault` exposes `put_file`, but the
//! command context does not yet carry an unlocked vault, so there is nothing to
//! call it on. Rather than print a success message for a write that never
//! happened — the one thing `PLAN.md` §6 forbids — a real run emits its plan and
//! then fails with [`CliError::unimplemented`], which is an error with a real
//! exit code. A `--dry-run` succeeds, because a dry run promises a report and
//! delivers exactly that.

pub mod chain;

use clap::Args;
use serde::Serialize;

use crate::commands::directory::{self, Plan, PlanOptions, Row, Target};
use crate::constants::{
    DIRECTORY_ACTION_MKDIR, DIRECTORY_ENGINE_HINT, DIRECTORY_LABEL_DIRECTORY,
    DIRECTORY_LABEL_MARKER, DIRECTORY_LABEL_PARENTS,
};
use crate::ctx::Ctx;
use crate::error::{CliError, Result};
use crate::logging::fields;

use chain::PlannedDirectory;

/// Stable command name. Matches `Command::name()` in `cli/mod.rs`, because it is
/// the `command` field of the JSON plan and the `op` field of every log record
/// the command emits — two places a script may branch on.
const VERB: &str = "mkdir";

/// What this command calls the thing it addresses, in its diagnostics.
const NOUN: &str = "directory";

/// Arguments for `dctl mkdir`.
///
/// Global flags — `--dry-run`, `--json`, `--format`, `--quiet` — are not
/// repeated here: they live in [`crate::cli::GlobalArgs`] and reach the command
/// through [`Ctx`].
#[derive(Args, Debug)]
pub struct MkdirArgs {
    /// Directory to create, as REMOTE:PATH.
    #[arg(value_name = "REMOTE:PATH")]
    pub target: String,

    /// Create missing parent directories as well.
    ///
    /// Mirrors `mkdir -p`: `vault:a/b/c` creates `a`, then `a/b`, then `a/b/c`.
    #[arg(short, long)]
    pub parents: bool,
}

/// The `mkdir`-specific half of the plan.
///
/// Carries the resolved chain rather than just the flag, so `--dry-run --json`
/// shows every object that would be written instead of leaving the reader to
/// re-derive it.
#[derive(Debug, Serialize)]
struct Options {
    parents: bool,
    directories: Vec<PlannedDirectory>,
}

impl PlanOptions for Options {
    fn rows(&self) -> Vec<Row> {
        let mut rows = vec![(DIRECTORY_LABEL_PARENTS, directory::yes_no(self.parents))];
        for planned in &self.directories {
            rows.push((DIRECTORY_LABEL_DIRECTORY, planned.path.clone()));
        }
        // One marker row, for the directory the user actually named: the
        // ancestors' markers follow the same rule and repeating them would bury
        // the target under its own scaffolding.
        if let Some(last) = self.directories.last() {
            rows.push((DIRECTORY_LABEL_MARKER, last.marker.clone()));
        }
        rows
    }
}

/// Create a directory.
///
/// # Errors
/// [`crate::exit::ExitCode::Usage`] for an unparseable target, and
/// [`crate::exit::ExitCode::FatalError`] from
/// [`CliError::unimplemented`] when a real run reaches the engine boundary
/// described in the module docs.
pub async fn run(ctx: &Ctx, args: &MkdirArgs) -> Result<()> {
    let target = Target::parse(&args.target, NOUN)?;
    let options = Options {
        parents: args.parents,
        directories: chain::build(&target, args.parents),
    };

    tracing::debug!(
        { fields::REMOTE } = target.remote.as_str(),
        { fields::PATH } = target.path.as_str(),
        parents = args.parents,
        directories = options.directories.len(),
        "planned mkdir"
    );

    let plan = Plan::new(VERB, &target, ctx.is_dry_run(), &options);
    directory::emit(ctx, &plan)?;

    if ctx.is_dry_run() {
        ctx.dry_run_notice(DIRECTORY_ACTION_MKDIR, &target.to_string());
        return Ok(());
    }

    Err(CliError::unimplemented(directory::command_name(VERB)).with_hint(DIRECTORY_ENGINE_HINT))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::directory::testing::ctx;
    use crate::exit::ExitCode;
    use clap::Parser;

    /// Minimal parser that exposes `MkdirArgs` on its own.
    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        args: MkdirArgs,
    }

    fn parse(argv: &[&str]) -> MkdirArgs {
        Harness::parse_from(std::iter::once("dctl").chain(argv.iter().copied())).args
    }

    #[test]
    fn the_target_is_positional_and_required() {
        let args = parse(&["vault:photos/2024"]);
        assert_eq!(args.target, "vault:photos/2024");
        assert!(!args.parents);
        assert!(Harness::try_parse_from(["dctl"]).is_err());
    }

    #[test]
    fn parents_has_the_short_form_muscle_memory_expects() {
        assert!(parse(&["vault:a", "-p"]).parents);
        assert!(parse(&["vault:a", "--parents"]).parents);
    }

    #[tokio::test]
    async fn a_dry_run_reports_and_succeeds() {
        // A dry run promises a report and no writes. It performs no work, so
        // reporting the plan and exiting 0 claims nothing that did not happen.
        let ctx = ctx(&["--dry-run"]);
        let args = parse(&["vault:photos/2024", "--parents"]);
        assert!(run(&ctx, &args).await.is_ok());
    }

    #[tokio::test]
    async fn a_real_run_fails_loudly_rather_than_claiming_success() {
        // The core promise of PLAN.md §6: work that did not happen is never
        // reported as done. The engine cannot write the marker yet, so the
        // command must exit non-zero.
        let ctx = ctx(&[]);
        let error = run(&ctx, &parse(&["vault:photos"])).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert_ne!(error.code(), ExitCode::Success);
        assert!(error.message().contains("mkdir"));
        assert!(error.hint().is_some(), "a refusal must say what is missing");
    }

    #[tokio::test]
    async fn every_format_runs_the_same_command() {
        for format in [
            vec!["--dry-run"],
            vec!["--dry-run", "--json"],
            vec!["--dry-run", "--format", "json-lines"],
        ] {
            let ctx = ctx(&format);
            assert!(
                run(&ctx, &parse(&["vault:a/b", "-p"])).await.is_ok(),
                "failed for {format:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_bad_target_is_a_usage_error_not_an_engine_error() {
        // Classification matters: a typo must not look like a missing feature.
        let ctx = ctx(&[]);
        for spec in ["", "/tmp/x", "vault:", "vault:../escape"] {
            let error = run(&ctx, &parse(&[spec])).await.unwrap_err();
            assert_eq!(error.code(), ExitCode::Usage, "accepted '{spec}'");
        }
    }

    #[test]
    fn the_plan_lists_every_directory_and_the_target_marker() {
        let target = Target::parse("vault:a/b", NOUN).unwrap();
        let options = Options {
            parents: true,
            directories: chain::build(&target, true),
        };
        let rows = options.rows();
        assert_eq!(rows[0].0, DIRECTORY_LABEL_PARENTS);
        assert_eq!(rows[1], (DIRECTORY_LABEL_DIRECTORY, "a".to_string()));
        assert_eq!(rows[2], (DIRECTORY_LABEL_DIRECTORY, "a/b".to_string()));
        assert_eq!(rows[3].0, DIRECTORY_LABEL_MARKER);
        assert!(rows[3].1.starts_with("a/b/"));
    }

    #[test]
    fn the_json_plan_names_the_command_and_every_marker() {
        let target = Target::parse("vault:a/b", NOUN).unwrap();
        let options = Options {
            parents: true,
            directories: chain::build(&target, true),
        };
        let plan = Plan::new(VERB, &target, true, &options);
        let value = serde_json::to_value(&plan).unwrap();

        assert_eq!(value["command"], VERB);
        assert_eq!(value["options"]["parents"], true);
        assert_eq!(value["options"]["directories"][0]["path"], "a");
        assert_eq!(value["options"]["directories"][1]["path"], "a/b");
        // Nothing in the document may suggest the write happened.
        assert!(value.get("created").is_none());
    }
}
