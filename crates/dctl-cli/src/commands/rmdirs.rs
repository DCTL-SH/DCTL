//! `dctl rmdirs` — sweep the empty directories under a path.
//!
//! The plural of [`rmdir`](super::rmdir), and it keeps that command's promise:
//! it removes containers, never contents. A directory that still holds an
//! object is left standing — which is what makes the sweep safe to run on a
//! whole vault after a filtered [`delete`](super::delete) has left empty shells
//! behind. Where `rmdir` errors on a non-empty directory because the user named
//! that one directory, `rmdirs` simply skips it: the user named a region, not a
//! victim.
//!
//! The sweep is depth-first by necessity. Removing `a/b` can be what makes `a`
//! empty, so a single pass that visited parents first would leave half the
//! litter behind and report success.
//!
//! `--leave-root` keeps the target directory itself even when the sweep empties
//! it. That is the flag a scheduled job wants: the tree it writes into should
//! still exist tomorrow morning, and re-creating a directory that a cleanup
//! removed overnight is a race nobody needs.
//!
//! ## What it can and cannot sweep
//!
//! A directory with no objects in it is not stored anywhere, so the only empty
//! directories that *exist* to be removed are the ones somebody declared with
//! `dctl mkdir` — the sweep removes their markers. A directory that existed only
//! because a file sat in it has already ceased to exist by the time the file is
//! gone, and is not counted as a removal, because none happened. Inventing one
//! so the numbers looked like a filesystem's is exactly the misreport `PLAN.md`
//! §6 forbids. See [`super::removal::dirs`].

use clap::Args;

use crate::constants::{
    REMOTE_PATH_VALUE_NAME, REMOVAL_ACTION_REMOVE_EMPTY_DIRS, REMOVAL_LABEL_LEAVE_ROOT,
};
use crate::ctx::Ctx;
use crate::error::Result;
use serde::Serialize;

use super::removal::{Operation, PlanOptions, Removal, Row, Target, execute, yes_no};

/// Stable command name. Must match `Command::name()` in `cli/mod.rs`.
const COMMAND: &str = "rmdirs";

/// `dctl rmdirs REMOTE:PATH`
#[derive(Args, Debug)]
pub struct RmdirsArgs {
    /// The path to sweep, written REMOTE:PATH.
    #[arg(value_name = REMOTE_PATH_VALUE_NAME)]
    pub path: String,

    /// Keep the target directory itself, even if the sweep empties it.
    #[arg(long)]
    pub leave_root: bool,
}

/// The `rmdirs`-specific half of the plan.
#[derive(Debug, Serialize)]
struct RmdirsOptions {
    leave_root: bool,
}

impl PlanOptions for RmdirsOptions {
    fn rows(&self) -> Vec<Row> {
        vec![(REMOVAL_LABEL_LEAVE_ROOT, yes_no(self.leave_root))]
    }
}

/// Run `dctl rmdirs`.
///
/// # Errors
/// [`crate::exit::ExitCode::Usage`] for a malformed target;
/// [`crate::exit::ExitCode::Cancelled`] if the user declines; whatever opening
/// the remote reported. A directory that could not be removed is reported and
/// counted rather than returned, so the sweep finishes and the process exits
/// [`crate::exit::ExitCode::PartialFailure`].
pub async fn run(ctx: &Ctx, args: &RmdirsArgs) -> Result<()> {
    let target = Target::parse(&args.path)?;

    // A bare `REMOTE:` sweeps the whole vault, which is legitimate — nothing
    // holding an object is touched — so the root is allowed here even though
    // `rmdir` refuses it. `--leave-root` then has nothing to protect, because
    // the root is the vault itself and was never a candidate.
    let removal = Removal {
        command: COMMAND,
        action: REMOVAL_ACTION_REMOVE_EMPTY_DIRS,
        target,
        // A filter selects objects; this command removes empty containers.
        filters: None,
        options: RmdirsOptions {
            leave_root: args.leave_root,
        },
        operation: Operation::Rmdirs {
            leave_root: args.leave_root,
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
        args: RmdirsArgs,
    }

    fn parse(args: &[&str]) -> Harness {
        Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied()))
    }

    async fn run_with(args: &[&str]) -> Result<()> {
        let parsed = parse(args);
        run(&Ctx::new(parsed.globals), &parsed.args).await
    }

    #[test]
    fn the_path_is_positional_and_leave_root_is_a_flag() {
        let parsed = parse(&["vault:photos"]);
        assert_eq!(parsed.args.path, "vault:photos");
        assert!(!parsed.args.leave_root);
        assert!(parse(&["vault:photos", "--leave-root"]).args.leave_root);
        assert!(Harness::try_parse_from(["dctl"]).is_err());
    }

    #[tokio::test]
    async fn the_whole_vault_may_be_swept() {
        // Unlike `rmdir`, the root is a legal region: nothing that holds an
        // object is touched, so there is no blast radius to guard. The run
        // reaches the store and fails there rather than on a usage rule.
        let error = run_with(&["vault:", "--dry-run", "--quiet", "--no-ask-password"])
            .await
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.message().contains("vault"), "{}", error.message());
    }

    #[tokio::test]
    async fn a_malformed_target_is_refused() {
        let error = run_with(&["vault", "--force"]).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[tokio::test]
    async fn a_dry_run_reaches_the_engine_rather_than_being_cancelled() {
        let error = run_with(&["vault:photos", "--dry-run", "--quiet", "--no-ask-password"])
            .await
            .unwrap_err();
        assert_ne!(error.code(), ExitCode::Cancelled);
    }

    #[test]
    fn the_json_plan_carries_the_leave_root_flag() {
        let target = Target::parse("vault:photos").unwrap();
        let options = RmdirsOptions { leave_root: true };
        let plan =
            crate::commands::removal::plan::Plan::new(COMMAND, &target, true, None, &options);

        let encoded = Format::JsonLines.encode(&plan).unwrap();
        assert!(!encoded.contains('\n'), "one record, one line");
        let value: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        assert_eq!(value["command"], COMMAND);
        assert_eq!(value["options"]["leave_root"], true);
    }
}
