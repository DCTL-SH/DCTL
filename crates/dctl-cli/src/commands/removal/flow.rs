//! The order in which every removal does the same four things.
//!
//! 1. Ask [`Ctx::confirm_destructive`] for permission. Under `--dry-run` that
//!    call declines and emits the `[dry-run] would …` notice on stderr; under
//!    `--interactive` it prompts; otherwise the user accepted the risk by
//!    typing the command.
//! 2. Under `--dry-run`, print the plan — the dry run's data, on stdout, in
//!    whichever format was asked for.
//! 3. If the user declined, stop with [`ExitCode::Cancelled`](crate::exit::ExitCode::Cancelled).
//! 4. Otherwise hand off to the engine.
//!
//! Sharing the sequence is not tidiness. Steps 1 and 3 are the safety contract
//! (`PLAN.md` §6), and six copies of a safety contract is six chances for one
//! of them to be subtly wrong — a `delete` that forgot to honour `--dry-run`
//! would destroy data on a run whose entire purpose was to destroy nothing.

use crate::ctx::Ctx;
use crate::error::Result;

use super::filters::Filters;
use super::plan::{Plan, PlanOptions};
use super::target::Target;
use super::{engine, plan};

/// One removal, fully resolved and ready to be gated and executed.
pub struct Removal<O: PlanOptions> {
    /// Stable command name, matching `Command::name()` in `cli/mod.rs`.
    pub command: &'static str,
    /// Verb used in the confirmation prompt and the dry-run notice.
    pub action: &'static str,
    pub target: Target,
    /// `None` for the commands that document themselves as ignoring filters.
    pub filters: Option<Filters>,
    pub options: O,
    /// The engine capability this removal needs, in the user's vocabulary.
    pub capability: &'static str,
}

/// Run the shared sequence.
///
/// # Errors
/// - [`ExitCode::Cancelled`](crate::exit::ExitCode::Cancelled) when the user
///   declines an interactive confirmation.
/// - [`ExitCode::Usage`](crate::exit::ExitCode::Usage) when `--interactive`
///   was asked for but there is no terminal to ask on.
/// - [`ExitCode::FatalError`](crate::exit::ExitCode::FatalError) from
///   [`engine::unavailable`] while the engine cannot perform the removal —
///   including on a dry run, which cannot list what would go without the same
///   listing the removal itself needs.
pub fn execute<O: PlanOptions>(ctx: &Ctx, removal: &Removal<O>) -> Result<()> {
    let target = removal.target.to_string();
    let approved = ctx.confirm_destructive(removal.action, &target)?;

    if ctx.is_dry_run() {
        let plan = Plan::new(
            removal.command,
            &removal.target,
            true,
            removal.filters.as_ref(),
            &removal.options,
        );
        plan::emit(ctx, &plan)?;
        // A dry run that printed a plan and exited 0 would be read as "these
        // are the objects that would go" — a claim about a listing that was
        // never performed. The plan says what was *requested*; the error says
        // the enumeration is not available.
        return Err(engine::unavailable(removal.command, removal.capability));
    }

    if !approved {
        return Err(engine::declined(removal.action, &target));
    }

    Err(engine::unavailable(removal.command, removal.capability))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::globals::GlobalArgs;
    use crate::exit::ExitCode;
    use crate::output::Out;
    use clap::Parser;

    use super::plan::NoOptions;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn ctx(args: &[&str]) -> Ctx {
        Ctx::new(Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied())).globals)
    }

    fn removal() -> Removal<NoOptions> {
        Removal {
            command: "delete",
            action: "delete",
            target: Target::parse("vault:photos").unwrap(),
            filters: None,
            options: NoOptions {},
            capability: "removing objects from a vault",
        }
    }

    #[test]
    fn a_dry_run_reports_the_plan_and_still_fails() {
        // Both halves matter: the plan is printed, and the exit code refuses
        // to imply that a listing was produced.
        let error = execute(&ctx(&["--dry-run", "--quiet"]), &removal()).unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
    }

    #[test]
    fn a_dry_run_works_in_every_output_format() {
        for args in [
            vec!["--dry-run", "--quiet"],
            vec!["--dry-run", "--json", "--quiet"],
            vec!["--dry-run", "--format", "json-lines", "--quiet"],
        ] {
            assert!(execute(&ctx(&args), &removal()).is_err(), "{args:?}");
        }
    }

    #[test]
    fn a_real_run_never_reports_success() {
        // The one thing PLAN.md §6 forbids: claiming work that did not happen.
        let error = execute(&ctx(&["--force", "--quiet"]), &removal()).unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.hint().is_some());
    }

    #[test]
    fn interactive_without_a_terminal_is_a_usage_error() {
        // An unattended job that asked for confirmation must fail loudly
        // rather than hang or assume consent. Skipped when the test run does
        // have a terminal, because a test must never block reading stdin.
        if Out::stderr_is_terminal() {
            return;
        }
        let error = execute(&ctx(&["--interactive", "--quiet"]), &removal()).unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }
}
