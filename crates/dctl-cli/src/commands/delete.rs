//! `dctl delete` — remove objects under a path, honouring filters.
//!
//! **`delete` versus `purge`.** This is the distinction rclone users rely on,
//! and DCTL keeps it exactly: `delete` **honours the filter flags** and
//! **leaves the directory structure standing**, while
//! [`purge`](super::purge) **ignores filters** and removes the whole tree. So
//! `dctl delete --include '*.tmp' vault:project` removes the scratch files and
//! nothing else, and the directories they lived in survive; `dctl purge
//! vault:project` removes the project. Choosing the wrong one of those is the
//! most expensive mistake this command family allows, so both doc comments say
//! it and both `--help` texts repeat it.
//!
//! `--rmdirs` is the deliberate exception to "leaves the structure standing":
//! after a filtered delete has emptied a directory, an empty directory is
//! usually litter rather than information, so the flag sweeps them — but only
//! the ones the delete itself emptied, and never the target root.
//!
//! ## What runs today
//!
//! Argument parsing, target resolution, filter validation, the destructive
//! gate and the `--dry-run` plan all run now. The removal itself does not:
//! [`super::removal::engine`] explains why — the vault exposes no filtered
//! listing and [`Ctx`] carries no vault handle — and the command fails with a
//! real exit code rather than reporting a deletion that never happened.

use clap::Args;

use crate::constants::{REMOTE_PATH_VALUE_NAME, REMOVAL_ACTION_DELETE, REMOVAL_LABEL_EMPTY_DIRS};
use crate::ctx::Ctx;
use crate::error::Result;
use serde::Serialize;

use super::removal::{Filters, PlanOptions, Removal, Row, Target, execute, yes_no};

/// Stable command name. Must match `Command::name()` in `cli/mod.rs`, because
/// it is what appears in the audit record for the operation.
const COMMAND: &str = "delete";

/// The engine capability this command is waiting on, in the user's vocabulary.
const CAPABILITY: &str = "listing a vault so the filters can select what to remove";

/// `dctl delete REMOTE:PATH`
#[derive(Args, Debug)]
pub struct DeleteArgs {
    /// Objects to delete, written REMOTE:PATH. Filters apply.
    #[arg(value_name = REMOTE_PATH_VALUE_NAME)]
    pub path: String,

    /// Also remove directories left empty by the deletion.
    #[arg(long)]
    pub rmdirs: bool,
}

/// The `delete`-specific half of the plan.
#[derive(Debug, Serialize)]
struct DeleteOptions {
    rmdirs: bool,
}

impl PlanOptions for DeleteOptions {
    fn rows(&self) -> Vec<Row> {
        vec![(REMOVAL_LABEL_EMPTY_DIRS, yes_no(self.rmdirs))]
    }
}

/// Run `dctl delete`.
///
/// # Errors
/// Usage errors for a malformed target or filter; [`crate::exit::ExitCode::Cancelled`]
/// if the user declines; otherwise the unimplemented refusal described above.
pub async fn run(ctx: &Ctx, args: &DeleteArgs) -> Result<()> {
    let removal = Removal {
        command: COMMAND,
        action: REMOVAL_ACTION_DELETE,
        target: Target::parse(&args.path)?,
        // The defining behaviour: delete narrows by filter, purge does not.
        filters: Some(Filters::resolve(&ctx.globals)?),
        options: DeleteOptions {
            rmdirs: args.rmdirs,
        },
        capability: CAPABILITY,
    };

    execute(ctx, &removal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::globals::GlobalArgs;
    use crate::exit::ExitCode;
    use crate::output::Format;
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
        #[command(flatten)]
        args: DeleteArgs,
    }

    fn parse(args: &[&str]) -> Harness {
        Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied()))
    }

    async fn run_with(args: &[&str]) -> Result<()> {
        let parsed = parse(args);
        run(&Ctx::new(parsed.globals), &parsed.args).await
    }

    #[test]
    fn the_target_is_positional_and_rmdirs_is_a_flag() {
        let parsed = parse(&["vault:photos"]);
        assert_eq!(parsed.args.path, "vault:photos");
        assert!(!parsed.args.rmdirs);
        assert!(parse(&["vault:photos", "--rmdirs"]).args.rmdirs);
    }

    #[test]
    fn a_target_is_required() {
        assert!(Harness::try_parse_from(["dctl"]).is_err());
    }

    #[tokio::test]
    async fn a_malformed_target_fails_before_the_destructive_gate() {
        let error = run_with(&["/local/path", "--force"]).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[tokio::test]
    async fn a_malformed_filter_fails_before_the_destructive_gate() {
        let error = run_with(&["vault:photos", "--max-size", "banana", "--force"])
            .await
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[tokio::test]
    async fn a_dry_run_never_reports_a_deletion() {
        // Nothing was listed, so nothing may be claimed: the run ends in an
        // error, not a silent, misleading success.
        let error = run_with(&["vault:photos", "--dry-run", "--quiet"])
            .await
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
    }

    #[tokio::test]
    async fn a_real_run_never_reports_a_deletion_either() {
        let error = run_with(&["vault:photos", "--force", "--quiet"])
            .await
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.hint().is_some(), "a refusal must explain itself");
    }

    #[tokio::test]
    async fn every_output_format_is_supported() {
        for format in [vec!["--json"], vec!["--format", "json-lines"], vec![]] {
            let mut args = vec!["vault:photos", "--dry-run", "--quiet"];
            args.extend(format.iter().copied());
            assert!(run_with(&args).await.is_err(), "{format:?}");
        }
    }

    #[test]
    fn the_json_plan_carries_the_filters_and_the_rmdirs_flag() {
        let parsed = parse(&["vault:photos", "--rmdirs", "--include", "*.tmp"]);
        let target = Target::parse(&parsed.args.path).unwrap();
        let filters = Filters::resolve(&parsed.globals).unwrap();
        let options = DeleteOptions {
            rmdirs: parsed.args.rmdirs,
        };
        let plan = crate::commands::removal::plan::Plan::new(
            COMMAND,
            &target,
            true,
            Some(&filters),
            &options,
        );

        let encoded = Format::Json.encode(&plan).unwrap();
        let value: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        assert_eq!(value["command"], COMMAND);
        assert_eq!(value["filters"]["include"][0], "*.tmp");
        assert_eq!(value["options"]["rmdirs"], true);
    }
}
