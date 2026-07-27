//! `--immutable` for the transfer family: an overwrite becomes a refusal.
//!
//! The flag's contract (`docs/GLOBAL_FLAGS.md`) is one sentence — *refuse to
//! modify or delete anything that already exists; only additions are allowed* —
//! and it is what makes a write-once archival job expressible at all. Without it
//! honoured here, `dctl copy ./src ./archive --immutable` replaced whatever
//! `./archive` already held and exited 0, which is worse than not offering the
//! flag: the operator believed a guarantee that was never enforced.
//!
//! ## Why this is decided at plan time
//!
//! The check reads a [`Plan`], not a filesystem, and runs before any byte moves.
//! That is what makes the refusal *verifiable in advance*: `--dry-run` reports
//! exactly the same failure a real run would, so an archival job can be proven
//! safe before it is scheduled rather than discovered unsafe by the first file
//! it ruins. Deciding at write time would also refuse — but only after some
//! earlier files had already been overwritten, leaving the destination in a
//! state neither the plan nor the flag described.
//!
//! It also means the answer comes from the *same* diff the report prints. A
//! second, independent notion of "would this overwrite?" evaluated during the
//! walk is how a plan and its execution come to disagree.
//!
//! ## What is refused, and what is not
//!
//! [`Op::Update`] and [`Op::Delete`] are the two ops that touch something the
//! destination already holds — see [`Op::replaces_existing`]. A destination that
//! does not exist yet is an addition, not an overwrite, and still copies; that
//! is the whole point of "only additions are allowed".
//!
//! The flag governs the **destination**. It does not protect a `move`'s source,
//! whose removal is what the verb means — reading it that way would make
//! `move --immutable` a contradiction rather than a safeguard, and `copy` is
//! already the verb that leaves a source alone.
//!
//! ## Why the exit code is 7 and not 1 or 6
//!
//! [`ExitCode::FatalError`] — the run cannot continue, and nothing was written.
//! The alternatives both say something false to a script:
//!
//! * **1 (`usage`)** would claim the command line was wrong. It was not: the
//!   flags are coherent and the paths parse. The conflict is with the *state of
//!   the destination*, which is only knowable after listing it, and `usage` is
//!   reserved for what could have been caught before any I/O happened.
//! * **6 (`partial_failure`)** means the run finished with some files failed —
//!   it implies other files succeeded. Here nothing was attempted at all, and a
//!   scheduler reading 6 would resume or reconcile a transfer that never began.
//!
//! 7 is also what `restore` already returns for its own `--immutable` gate, so
//! "immutable refused" is one number across the product rather than one per
//! command. (`rcat` returns 1 for the same condition; that number is published
//! and cannot be changed now, but it is a single named object and a check made
//! before any listing, which is the case `usage` fits least badly.)

use crate::cli::GlobalArgs;
use crate::constants::{
    IMMUTABLE_NO_TRAVERSE_CONFLICT, IMMUTABLE_NO_TRAVERSE_HINT, IMMUTABLE_REFUSAL_HINT,
    IMMUTABLE_REFUSAL_SAMPLE,
};
use crate::error::{CliError, Result};
use crate::exit::ExitCode;

use super::options::TraversalFlags;
use super::plan::{Plan, PlanEntry};

/// Refuse a plan that would replace or remove anything at the destination.
///
/// A no-op unless `--immutable` was given, so every transfer command can call it
/// unconditionally and none of them can forget to.
///
/// # Errors
/// [`ExitCode::FatalError`] naming the offending paths — see the module docs for
/// why that code and not `usage` or `partial_failure`.
pub fn ensure_nothing_is_replaced(globals: &GlobalArgs, plan: &Plan) -> Result<()> {
    if !globals.immutable {
        return Ok(());
    }

    let refused: Vec<&PlanEntry> = plan
        .entries
        .iter()
        .filter(|entry| entry.action.replaces_existing())
        .collect();

    if refused.is_empty() {
        return Ok(());
    }

    Err(CliError::new(
        ExitCode::FatalError,
        format!(
            "--immutable, but {} existing destination object(s) would be replaced or removed: {}",
            refused.len(),
            describe(&refused),
        ),
    )
    .with_hint(IMMUTABLE_REFUSAL_HINT))
}

/// Refuse `--immutable` together with `--no-traverse`.
///
/// Checked before either side is enumerated, because the answer needs no I/O and
/// because failing after a full listing wastes the walk. See
/// [`IMMUTABLE_NO_TRAVERSE_CONFLICT`] for why the pair cannot be honoured: with
/// the destination never listed, every entry is planned as a first-time copy and
/// the overwrite this flag forbids is invisible to the planner.
///
/// # Errors
/// [`ExitCode::Usage`] — unlike the refusal above, this one *is* decidable from
/// the command line alone, and it is the same answer
/// `touch --no-create --immutable` already gives to the same shape of
/// contradiction.
pub fn ensure_traversal_can_enforce_it(
    globals: &GlobalArgs,
    traversal: &TraversalFlags,
) -> Result<()> {
    if globals.immutable && traversal.no_traverse {
        return Err(
            CliError::usage(IMMUTABLE_NO_TRAVERSE_CONFLICT).with_hint(IMMUTABLE_NO_TRAVERSE_HINT)
        );
    }
    Ok(())
}

/// Render the refused entries: `update a.txt, delete stale.txt, and 7 more`.
///
/// Each path is prefixed with the plan's own action slug rather than prose, so
/// the refusal and the `--dry-run` table use one vocabulary — an operator can
/// grep the plan for the word the error just quoted. The list is bounded by
/// [`IMMUTABLE_REFUSAL_SAMPLE`]; the count in the surrounding sentence is always
/// exact, so nothing is hidden, only elided.
fn describe(refused: &[&PlanEntry]) -> String {
    let mut rendered: Vec<String> = refused
        .iter()
        .take(IMMUTABLE_REFUSAL_SAMPLE)
        .map(|entry| format!("{} {}", entry.action.slug(), entry.dest))
        .collect();

    let elided = refused.len().saturating_sub(IMMUTABLE_REFUSAL_SAMPLE);
    if elided > 0 {
        rendered.push(format!("and {elided} more"));
    }
    rendered.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::transfer::compare::ComparePolicy;
    use crate::commands::transfer::entry::Entry;
    use crate::commands::transfer::plan::{Op, Policy};
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn globals(args: &[&str]) -> GlobalArgs {
        Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied())).globals
    }

    fn plan_of(entries: &[(Op, &str)]) -> Plan {
        Plan {
            entries: entries
                .iter()
                .map(|(action, path)| PlanEntry {
                    action: *action,
                    source: (*path).to_string(),
                    dest: (*path).to_string(),
                    size: Some(1),
                    reason: "test",
                })
                .collect(),
        }
    }

    #[test]
    fn without_the_flag_nothing_is_refused() {
        let plan = plan_of(&[(Op::Update, "a.txt"), (Op::Delete, "b.txt")]);
        assert!(ensure_nothing_is_replaced(&globals(&[]), &plan).is_ok());
    }

    #[test]
    fn an_update_is_refused_and_the_path_is_named() {
        // The S4 defect in one assertion: an existing destination object being
        // replaced has to stop the run, and the operator has to be told which
        // file did it or the message is unactionable.
        let plan = plan_of(&[(Op::Copy, "new.txt"), (Op::Update, "photos/a.jpg")]);
        let error = ensure_nothing_is_replaced(&globals(&["--immutable"]), &plan).unwrap_err();

        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(
            error.message().contains("photos/a.jpg"),
            "{}",
            error.message()
        );
        assert!(error.message().contains("update"), "{}", error.message());
        assert!(
            error
                .hint()
                .is_some_and(|hint| hint.contains("--immutable"))
        );
    }

    #[test]
    fn a_sync_deletion_is_refused_too() {
        // "Refuse to modify **or delete** anything that already exists": a sync
        // that removes a destination extra is destroying something that exists,
        // which is exactly what a write-once archive must not permit.
        let plan = plan_of(&[(Op::Delete, "stale.txt")]);
        let error = ensure_nothing_is_replaced(&globals(&["--immutable"]), &plan).unwrap_err();
        assert!(error.message().contains("stale.txt"), "{}", error.message());
        assert!(error.message().contains("delete"), "{}", error.message());
    }

    #[test]
    fn additions_alone_are_always_allowed() {
        // The other half of the contract. A destination that does not exist yet
        // is not an overwrite, so a write-once job must still be able to add.
        let plan = plan_of(&[
            (Op::Copy, "new.txt"),
            (Op::CreateDir, "empty"),
            (Op::Skip, "same.txt"),
        ]);
        assert!(ensure_nothing_is_replaced(&globals(&["--immutable"]), &plan).is_ok());
    }

    #[test]
    fn a_computed_plan_is_read_the_same_way_a_hand_built_one_is() {
        // Guards against the check drifting from the real diff: this plan comes
        // out of `Plan::compute`, not out of the test's own idea of one.
        let source = [Entry::file("changed.txt", 20), Entry::file("new.txt", 5)];
        let dest = [Entry::file("changed.txt", 21), Entry::file("extra.txt", 3)];
        let plan = Plan::compute(
            &source,
            &dest,
            &Policy::syncing(ComparePolicy {
                size_only: true,
                ..ComparePolicy::default()
            }),
        )
        .unwrap();

        let error = ensure_nothing_is_replaced(&globals(&["--immutable"]), &plan).unwrap_err();
        assert!(
            error.message().contains("changed.txt"),
            "{}",
            error.message()
        );
        assert!(error.message().contains("extra.txt"), "{}", error.message());
        assert!(
            !error.message().contains("new.txt"),
            "an addition must not appear in the refusal: {}",
            error.message()
        );
    }

    #[test]
    fn a_huge_refusal_is_elided_but_its_count_stays_exact() {
        // A sync of a million changed files must not print a million paths on
        // its way out, and must not misreport how many it refused either.
        let paths: Vec<String> = (0..IMMUTABLE_REFUSAL_SAMPLE + 7)
            .map(|index| format!("file-{index}.bin"))
            .collect();
        let entries: Vec<(Op, &str)> = paths
            .iter()
            .map(|path| (Op::Update, path.as_str()))
            .collect();
        let plan = plan_of(&entries);

        let error = ensure_nothing_is_replaced(&globals(&["--immutable"]), &plan).unwrap_err();
        let message = error.message();
        assert!(
            message.contains(&format!("{} existing", IMMUTABLE_REFUSAL_SAMPLE + 7)),
            "{message}"
        );
        assert!(message.contains("and 7 more"), "{message}");
        assert!(
            !message.contains(&format!("file-{}.bin", IMMUTABLE_REFUSAL_SAMPLE + 6)),
            "the tail must be elided: {message}"
        );
    }

    #[test]
    fn no_traverse_cannot_pretend_to_honour_immutable() {
        // Without a destination listing every entry is planned as a first-time
        // copy, so the check above would pass while overwriting freely. Refusing
        // the pair is the only way the flag keeps meaning what it says.
        let untraversed = TraversalFlags { no_traverse: true };
        let error =
            ensure_traversal_can_enforce_it(&globals(&["--immutable"]), &untraversed).unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(
            error
                .hint()
                .is_some_and(|hint| hint.contains("--no-traverse"))
        );

        // Either flag on its own is perfectly ordinary.
        assert!(ensure_traversal_can_enforce_it(&globals(&[]), &untraversed).is_ok());
        assert!(
            ensure_traversal_can_enforce_it(&globals(&["--immutable"]), &TraversalFlags::default())
                .is_ok()
        );
    }
}
