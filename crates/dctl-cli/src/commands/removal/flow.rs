//! The order in which every removal does the same four things.
//!
//! 1. **Compile the filters.** A malformed `--include`, an unparseable
//!    `--max-size` or a rule file this build cannot honour is a mistake in the
//!    command line, and a mistake in a `delete`'s command line is exactly the
//!    kind that removes far more than intended. Failing here costs a second;
//!    failing after the confirmation costs the user's trust in the prompt, and
//!    failing after the first object is gone costs a restore.
//! 2. **Ask [`Ctx::confirm_destructive`] for permission.** Under `--dry-run`
//!    that call declines and emits the `[dry-run] would …` notice on stderr;
//!    under `--interactive` it prompts; otherwise the user accepted the risk by
//!    typing the command.
//! 3. **Stop if the user declined**, with
//!    [`ExitCode::Cancelled`](crate::exit::ExitCode::Cancelled) — a code of its
//!    own, so a script can tell "you said no" from "it went wrong".
//! 4. **Hand off to the engine**, which opens the store, resolves the exact set
//!    and removes it.
//!
//! Sharing the sequence is not tidiness. Steps 1 to 3 are the safety contract
//! ([the plan](https://doc.dctl.sh/project/plan) §6), and six copies of a safety
//! contract is six chances for one of them to be subtly wrong — a `delete` that
//! forgot to honour `--dry-run` would destroy data on a run whose entire purpose
//! was to destroy nothing.
//!
//! ## The gate is ahead of the unlock, deliberately
//!
//! Nothing is opened, listed or unlocked until consent exists. Declining a
//! `purge` therefore costs no password prompt and touches no provider — and,
//! more importantly, there is no code path on which a store is opened for
//! writing before the user has been asked.
//!
//! ## A dry run is not a declined run
//!
//! `confirm_destructive` answers `false` for both, because both mean "do not
//! change anything". They are not the same outcome: a dry run is a successful
//! rehearsal that must go on to *list* what it would have removed, and a
//! declined run stops. Conflating them is how `--dry-run` ends up printing
//! nothing and exiting non-zero, which is what it used to do.

use crate::commands::listing::Filter;
use crate::ctx::Ctx;
use crate::error::Result;

use super::engine;
use super::filters::Filters;
use super::operation::Operation;
use super::plan::PlanOptions;
use super::target::Target;

/// One removal, fully resolved and ready to be gated and executed.
pub struct Removal<O: PlanOptions> {
    /// Stable command name, matching `Command::name()` in `cli/mod.rs`.
    pub command: &'static str,
    /// Verb used in the confirmation prompt and the dry-run notice.
    pub action: &'static str,
    pub target: Target,
    /// The filter set as the *plan* describes it. `None` for the commands that
    /// document themselves as ignoring filters, which is what makes the absence
    /// of a `filters` key in their JSON a statement rather than an omission.
    pub filters: Option<Filters>,
    pub options: O,
    /// What this command actually removes.
    pub operation: Operation,
}

/// Run the shared sequence.
///
/// # Errors
/// - [`ExitCode::Usage`](crate::exit::ExitCode::Usage) for an unusable filter,
///   or when `--interactive` was asked for but there is no terminal to ask on.
/// - [`ExitCode::Cancelled`](crate::exit::ExitCode::Cancelled) when the user
///   declines an interactive confirmation.
/// - Whatever [`engine::run`] reported for a run that could not begin.
pub async fn execute<O: PlanOptions>(ctx: &Ctx, removal: &Removal<O>) -> Result<()> {
    // Step 1, before consent is even requested. A pattern that does not compile
    // is not a question anybody should be asked to confirm.
    let filter = match removal.filters {
        Some(_) => Filter::from_globals(&ctx.globals)?,
        // The verbs that ignore filters get a matcher that matches everything,
        // and never consult it. Building one unconditionally would mean a
        // `purge --include '*.jpg'` failing on a malformed pattern it was
        // documented to ignore.
        None => Filter::default(),
    };

    let target = removal.target.to_string();
    let approved = ctx.confirm_destructive(removal.action, &target)?;

    // A dry run always declines, and that is not a refusal — see the module
    // documentation. The engine then reports what it *would* have removed and
    // removes nothing, because the branch that mutates is inside
    // [`super::remove`] and is guarded by the same flag.
    if !approved && !ctx.is_dry_run() {
        return Err(engine::declined(removal.action, &target));
    }

    engine::run(ctx, removal, &filter).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::globals::GlobalArgs;
    use crate::exit::ExitCode;
    use crate::output::Out;
    use clap::Parser;

    use super::super::plan::NoOptions;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn ctx(args: &[&str]) -> Ctx {
        Ctx::new(Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied())).globals)
    }

    /// A removal aimed at a remote no configuration defines, so the run reaches
    /// the gate and then fails on the store rather than on anything earlier.
    fn removal() -> Removal<NoOptions> {
        Removal {
            command: "delete",
            action: "delete",
            target: Target::parse("nosuchremote:photos").expect("a well-formed target"),
            filters: Some(Filters::default()),
            options: NoOptions {},
            operation: Operation::Delete { rmdirs: false },
        }
    }

    #[tokio::test]
    async fn an_unusable_filter_fails_before_the_gate() {
        // The ordering that matters: the pattern is rejected before anybody is
        // asked to confirm a deletion, and before any store is opened.
        let error = execute(&ctx(&["--include", "[abc", "--quiet"]), &removal())
            .await
            .expect_err("a malformed pattern must be refused");
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.message().contains("--include"), "{}", error.message());
    }

    #[tokio::test]
    async fn a_rule_file_is_refused_rather_than_silently_dropped() {
        // A `--filter-from` that were ignored would make a `delete` remove
        // everything the rules were written to protect.
        let error = execute(&ctx(&["--filter-from", "rules.txt", "--quiet"]), &removal())
            .await
            .expect_err("a rule file must be refused");
        assert_ne!(error.code(), ExitCode::Success);
        assert!(error.hint().is_some());
    }

    #[tokio::test]
    async fn a_command_that_ignores_filters_is_not_stopped_by_a_bad_pattern() {
        // `purge` documents itself as ignoring filters, so a pattern it will
        // never consult must not be compiled on its behalf.
        let purge = Removal {
            command: "purge",
            action: "purge",
            filters: None,
            operation: Operation::Purge,
            ..removal()
        };
        let error = execute(&ctx(&["--include", "[abc", "--force", "--quiet"]), &purge)
            .await
            .expect_err("the unknown remote still fails");
        // Past the filter, past the gate, and failing on the store instead.
        assert_ne!(error.code(), ExitCode::Usage, "{}", error.message());
    }

    #[tokio::test]
    async fn a_declined_confirmation_stops_before_the_store_is_opened() {
        // `--interactive` with no terminal is refused by the gate itself, which
        // is the unattended case: a job that asked to be asked must fail loudly
        // rather than hang or assume consent. Skipped when the suite does have a
        // terminal, because a test must never block reading stdin.
        if Out::stderr_is_terminal() {
            return;
        }
        let error = execute(&ctx(&["--interactive", "--quiet"]), &removal())
            .await
            .expect_err("there is no terminal to confirm on");
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[tokio::test]
    async fn a_dry_run_is_not_treated_as_a_refusal() {
        // `confirm_destructive` answers `false` for a dry run, and a flow that
        // read that as "the user said no" would make `--dry-run` exit 25 and
        // print nothing.
        let error = execute(&ctx(&["--dry-run", "--quiet"]), &removal())
            .await
            .expect_err("the unknown remote fails");
        assert_ne!(
            error.code(),
            ExitCode::Cancelled,
            "a dry run must reach the engine, not be cancelled"
        );
    }
}
