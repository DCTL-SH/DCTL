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
//! ## What runs today
//!
//! Argument parsing, target resolution, the destructive gate and the
//! `--dry-run` plan. The sweep needs recursive directory enumeration, which the
//! vault does not expose — and [`Ctx`] carries no vault handle to ask — so the
//! command fails with a real exit code rather than reporting removals that
//! never happened. See [`super::removal::engine`].

use clap::Args;

use crate::constants::{
    REMOTE_PATH_VALUE_NAME, REMOVAL_ACTION_REMOVE_EMPTY_DIRS, REMOVAL_LABEL_LEAVE_ROOT,
};
use crate::ctx::Ctx;
use crate::error::Result;
use serde::Serialize;

use super::removal::{PlanOptions, Removal, Row, Target, execute, yes_no};

/// Stable command name. Must match `Command::name()` in `cli/mod.rs`.
const COMMAND: &str = "rmdirs";

/// The engine capability this command is waiting on.
const CAPABILITY: &str = "walking a vault's directories to find the empty ones";

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
/// [`crate::exit::ExitCode::Cancelled`] if the user declines; otherwise the
/// unimplemented refusal described above.
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
        // object is touched, so there is no blast radius to guard.
        let error = run_with(&["vault:", "--dry-run", "--quiet"])
            .await
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
    }

    #[tokio::test]
    async fn a_malformed_target_is_refused() {
        let error = run_with(&["vault", "--force"]).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[tokio::test]
    async fn a_dry_run_never_reports_a_sweep() {
        let error = run_with(&["vault:photos", "--dry-run", "--quiet"])
            .await
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
    }

    #[tokio::test]
    async fn a_real_run_never_reports_a_sweep_either() {
        let error = run_with(&["vault:photos", "--force", "--quiet"])
            .await
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
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
