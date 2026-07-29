//! The removal engine: open the store, resolve the set, remove it, report it.
//!
//! One function performs every removal in the binary, and the six commands are
//! six ways of filling in an [`Operation`]. That is not a refactoring
//! preference. The steps below are, in order, the places a destructive command
//! can be wrong — the wrong store, the wrong set, the wrong order, the wrong
//! claim about what happened — and six copies of them would be six chances for
//! one copy to be subtly wrong in the one direction that cannot be undone.
//!
//! ```text
//!   Target ──▶ medium ──▶ selection ──▶ remove ──▶ report
//!               │           │            │           │
//!               │           │            │           └─ one record per object,
//!               │           │            │              written as it happens
//!               │           │            └─ ordered, serial, partial-failure
//!               │           │               tolerant
//!               │           └─ complete before anything is deleted
//!               └─ sealed vault or plain store, decided once
//! ```
//!
//! ## What runs before this, and why it is not here
//!
//! The destructive gate and the confirmation live in [`super::flow`], ahead of
//! everything above — including the vault unlock, so that declining a `purge`
//! never costs a password prompt. By the time this module runs, consent has been
//! established and the only remaining questions are factual.
//!
//! ## The exit code
//!
//! This function returns `Ok(())` for a run that finished, whatever happened to
//! the individual objects, and the process's exit status is then derived from
//! the counters in [`Ctx::outcome`](crate::ctx::Ctx::outcome): any recorded error
//! downgrades the result to
//! [`ExitCode::PartialFailure`](crate::exit::ExitCode::PartialFailure).
//! `PLAN.md` §7 forbids rolling a partial failure into a success, and deriving
//! the status from the counters rather than from the return value is what makes
//! that structural instead of remembered.
//!
//! An `Err` from here means the run did not get as far as removing anything: an
//! unresolvable remote, a locked vault, a `deletefile` naming a directory, a
//! `rmdir` on a directory that is not empty.

use crate::commands::listing::Filter;
use crate::ctx::Ctx;
use crate::error::{CliError, Result};
use crate::exit::ExitCode;
use crate::remote::{Place, RemoteSpec};

use super::flow::Removal;
use super::medium::Medium;
use super::operation::Operation;
use super::plan::{Plan, PlanOptions};
use super::report::Report;
use super::selection::{self, Selection};
use super::{reclaim, remove};

/// Refuse a target whose filesystem root is not there.
///
/// One implementation, on [`Place`], shared with the listing family and `about`
/// — see [`Place::require_readable_tree`] for the full account of the failure.
///
/// A removal target is always `REMOTE:PATH` (a local path is rejected at parse
/// time), so there is no bare-path arm here. A remote that will not classify is
/// left to [`Medium::open`], which gives a better diagnosis of the same typo.
fn require_readable_tree(ctx: &Ctx, target: &super::target::Target) -> Result<()> {
    let spec = RemoteSpec::Named {
        remote: target.remote.clone(),
        path: target.path.clone(),
    };
    match Place::of(ctx, &spec) {
        Ok(place) => place.require_readable_tree(),
        Err(_) => Ok(()),
    }
}

/// Perform one removal, from an opened store to a closed report.
///
/// # Errors
/// Whatever opening the store or resolving the selection reported. A failure to
/// remove an individual object is *not* one of these — it is recorded, counted
/// and reported, and the run continues.
pub async fn run<O: PlanOptions>(ctx: &Ctx, removal: &Removal<O>, filter: &Filter) -> Result<()> {
    // Before the store is opened, and before a single object is selected.
    //
    // A removal over an unmounted volume used to enumerate nothing, remove
    // nothing, and report `OK removed: 0 object(s), 0 B` at exit 0 — which is
    // the same output as a genuinely empty tree. The scenario is a retention job
    // running `dctl purge archive:2019 --force && record_purged 2019`: the
    // archive volume did not mount, the command reports success, 2019 is marked
    // reclaimed, and the data is still there. Of the six verbs this is worst for
    // `purge`, because `purge` is the one a script trusts to have destroyed
    // something.
    require_readable_tree(ctx, &removal.target)?;

    let medium = Medium::open(ctx, &removal.target).await?;
    let selection = selection::select(&medium, &removal.target, &removal.operation, filter).await?;

    let mut report = Report::new(ctx);
    // The request opens the document, in every format, so a report can always be
    // read back against what was asked for.
    report.plan(&Plan::new(
        removal.command,
        &removal.target,
        ctx.is_dry_run(),
        removal.filters.as_ref(),
        &removal.options,
    ))?;

    // The command's own name and the remote it addressed reach the loop because
    // both are fields of every audit record it appends: `op` says which of the
    // six verbs ran, and a log in which `purge` recorded itself as `delete`
    // would understate the blast radius of the thing that happened.
    remove::run(
        ctx,
        removal.command,
        &removal.target.remote,
        &medium,
        &selection.items,
        &mut report,
    )
    .await?;

    if let Operation::Cleanup {
        classes,
        min_age,
        named,
    } = &removal.operation
    {
        reclaim::sweep(
            ctx,
            removal.command,
            &medium,
            &removal.target,
            &reclaim::Request {
                classes,
                min_age: *min_age,
                named: *named,
            },
            &mut report,
        )
        .await?;
    }

    note_empty(ctx, removal, &selection, &report);
    report.finish()
}

/// Say why a removal touched nothing, when the reason is worth saying.
///
/// "There was nothing here" and "nothing survived your filters" send a user to
/// two different places — the first to their memory, the second to their command
/// line — and a removal that could not tell them apart would be the family's
/// least trustworthy corner. Always a note on stderr and never data: a JSON
/// consumer already has the counters.
fn note_empty<O: PlanOptions>(
    ctx: &Ctx,
    removal: &Removal<O>,
    selection: &Selection,
    report: &Report<'_>,
) {
    let totals = report.totals();
    if totals.removed + totals.would_remove + totals.absent + totals.failed > 0 {
        return;
    }
    // Debris that was found and deliberately held is not nothing found. Saying
    // "no reclaimable debris found" over a staging file the sweep had just
    // decided was too young is the false all-clear this family exists not to
    // print, one branch below the listing that used to produce it.
    if totals.held > 0 {
        return;
    }

    let target = &removal.target;
    if removal.operation.is_cleanup() {
        ctx.out
            .info(format!("no reclaimable debris found in '{target}'"));
    } else if selection.considered == 0 {
        ctx.out.info(format!("nothing is stored under '{target}'"));
    } else if removal.operation.removes_user_data() {
        ctx.out.info(format!(
            "no objects under '{target}' matched ({} considered)",
            selection.considered
        ));
    } else {
        ctx.out
            .info(format!("no empty directories under '{target}'"));
    }
}

/// The error a removal returns when the user declines the confirmation.
///
/// Not a success and not a failure of the command: the operation was cancelled,
/// which has its own exit code so a script can tell "you said no" apart from "it
/// went wrong".
#[must_use]
pub fn declined(action: &str, target: &str) -> CliError {
    CliError::new(
        ExitCode::Cancelled,
        format!("cancelled: '{action}' on '{target}' was not confirmed"),
    )
    .with_hint(format!(
        "Type '{}' at the prompt to confirm, or pass --force to approve \
         destructive actions without being asked.",
        crate::constants::DESTRUCTIVE_CONFIRMATION
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_declined_confirmation_is_cancelled_not_failed() {
        // A script has to be able to tell "you said no" from "it went wrong",
        // and both from "it worked".
        let error = declined("purge", "vault:old");
        assert_eq!(error.code(), ExitCode::Cancelled);
        assert_ne!(error.code(), ExitCode::Success);
        assert!(error.message().contains("vault:old"));
        assert!(
            error
                .hint()
                .unwrap_or_default()
                .contains(crate::constants::DESTRUCTIVE_CONFIRMATION)
        );
    }
}
