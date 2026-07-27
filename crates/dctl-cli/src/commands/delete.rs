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
//! ## What a directory means here
//!
//! An object store has no directories, so `--rmdirs` sweeps the zero-byte
//! markers `dctl mkdir` writes — and only the ones *this* deletion emptied. A
//! directory that was already empty before the run is somebody's deliberate
//! `mkdir` and survives; a directory that existed only because a file sat in it
//! has already ceased to exist by the time the file is gone, and is not counted
//! as a removal because none happened. See [`super::removal::dirs`].

use clap::Args;

use crate::constants::{REMOTE_PATH_VALUE_NAME, REMOVAL_ACTION_DELETE, REMOVAL_LABEL_EMPTY_DIRS};
use crate::ctx::Ctx;
use crate::error::Result;
use serde::Serialize;

use super::removal::{Filters, Operation, PlanOptions, Removal, Row, Target, execute, yes_no};

/// Stable command name. Must match `Command::name()` in `cli/mod.rs`, because
/// it is what appears in the audit record for the operation.
const COMMAND: &str = "delete";

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
/// Usage errors for a malformed target or filter;
/// [`crate::exit::ExitCode::Cancelled`] if the user declines; whatever opening
/// the remote reported. Individual objects that could not be removed are
/// reported and counted rather than returned, so the run finishes and the
/// process exits [`crate::exit::ExitCode::PartialFailure`].
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
        operation: Operation::Delete {
            rmdirs: args.rmdirs,
        },
    };

    execute(ctx, &removal).await
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
    async fn an_unknown_remote_is_refused_rather_than_read_as_a_directory() {
        // S6 in the removal direction: a bare name has no colon, so anything
        // that re-parses one turns `vault:` into the *directory* `vault` — and
        // deleting from a folder nobody named would exit 0 having removed the
        // wrong files, or nothing at all.
        let error = run_with(&["vault:photos", "--force", "--quiet", "--no-ask-password"])
            .await
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.message().contains("vault"), "{}", error.message());
    }

    #[tokio::test]
    async fn a_dry_run_reaches_the_engine_rather_than_being_cancelled() {
        // The regression this guards: `confirm_destructive` declines a dry run,
        // and a flow that read that as a refusal made `--dry-run` exit 25.
        let error = run_with(&["vault:photos", "--dry-run", "--quiet", "--no-ask-password"])
            .await
            .unwrap_err();
        assert_ne!(error.code(), ExitCode::Cancelled);
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
