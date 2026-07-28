//! Telling an operator what a walk did about the symbolic links it met.
//!
//! One implementation, read by every family that walks a tree: the transfer
//! verbs, the six listing verbs and `backup`. The policy itself and the counting
//! live one layer down in [`dctl_store::links`]; what is here is the wording and
//! the level, and it is here rather than in each command for the reason the
//! filter engine is: three copies of "say something about the links" is how one
//! family comes to say it and another comes to say nothing, which is the state
//! this whole change exists to end.
//!
//! # What is a warning and what is a note
//!
//! **Passed over is a warning**, always shown short of `--quiet`. Those are
//! files the operator asked for and did not get, and finding that out from a
//! restore is far too late — the exact failure `HANDOVER.md` §11.2 recorded.
//!
//! **Followed is a note**, shown at `-v`. The operator asked for it and got it;
//! a `WARNING` on requested behaviour is how people learn to skim past
//! warnings, and the run that most needs to be heard is the one that skipped.
//!
//! **Broken is a warning and an error.** A link a run was told to follow, that
//! leads nowhere, is a path that was named and not stored, so it raises the
//! run's error count and its exit code. rclone treats it identically —
//! `fs.Errorf` plus `accounting.Stats(ctx).Error(...)` at
//! `backend/local/local.go:741`, which fails the sync — and the alternative is
//! a `copy` that reports success over files it could not read.
//!
//! Every name is a note, never a warning: a tree with forty thousand links must
//! not produce forty thousand lines on a terminal that has already been told
//! the count.

use dctl_store::LinkReport;

use crate::constants::{LINKS_BROKEN_HINT, LINKS_SKIPPED_HINT};
use crate::ctx::Ctx;

/// Report one walk's findings about symbolic links.
///
/// Silent when the walk met none, which is the ordinary tree and must stay
/// wordless — a line about links on every run is a line nobody reads on the run
/// that has them.
pub fn report(ctx: &Ctx, links: &LinkReport) {
    if links.is_empty() {
        return;
    }

    if links.skipped() > 0 {
        ctx.out.warn(format!(
            "skipped {} symbolic link(s). {LINKS_SKIPPED_HINT}",
            links.skipped()
        ));
    }

    if links.broken() > 0 {
        ctx.out.warn(format!(
            "{} symbolic link(s) point at nothing and were not stored. {LINKS_BROKEN_HINT}",
            links.broken()
        ));
        // One error per link, not one for the batch: the run's error count is
        // "how many things went wrong", and a hundred dangling links in a
        // nightly backup is a different situation from one.
        for _ in 0..links.broken() {
            ctx.stats.error();
        }
    }

    if links.followed() > 0 {
        ctx.out
            .info(format!("followed {} symbolic link(s)", links.followed()));
    }

    for note in links.notes() {
        ctx.out
            .info(format!("  {}: {}", note.path, note.verdict.reason()));
    }
    if links.unnamed() > 0 {
        ctx.out
            .info(format!("  … and {} more, not named", links.unnamed()));
    }
}

/// Whether a report describes anything a run must not stay quiet about.
///
/// Separate from [`report`] because two callers need to *decide* before they
/// print — the transfer family folds this into its own omissions warning — and
/// a caller that re-derived the condition would eventually derive a different
/// one.
#[must_use]
pub fn needs_saying(links: &LinkReport) -> bool {
    links.skipped() > 0 || links.broken() > 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::GlobalArgs;
    use clap::Parser;
    use dctl_store::LinkVerdict;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn ctx(args: &[&str]) -> Ctx {
        Ctx::new(Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied())).globals)
    }

    #[test]
    fn a_walk_that_met_no_links_says_nothing_and_counts_nothing() {
        let ctx = ctx(&[]);
        report(&ctx, &LinkReport::default());
        assert_eq!(ctx.stats.snapshot().errors, 0);
        assert!(!needs_saying(&LinkReport::default()));
    }

    #[test]
    fn a_skipped_link_is_worth_saying_and_is_not_an_error() {
        // The default path. A stray link in a home directory must not fail a
        // backup; it must not be invisible either.
        let mut links = LinkReport::default();
        links.observe("data", LinkVerdict::NotFollowed);

        let ctx = ctx(&[]);
        report(&ctx, &links);
        assert!(needs_saying(&links));
        assert_eq!(ctx.stats.snapshot().errors, 0);
    }

    #[test]
    fn a_broken_link_raises_the_runs_error_count_once_each() {
        // Only reachable under a policy that follows: nothing looked behind a
        // skipped link, so nothing can call it broken.
        let mut links = LinkReport::default();
        links.observe("stale", LinkVerdict::Broken);
        links.observe("older", LinkVerdict::Broken);

        let ctx = ctx(&[]);
        report(&ctx, &links);
        assert_eq!(ctx.stats.snapshot().errors, 2);
    }

    #[test]
    fn a_followed_link_is_not_an_error_and_is_not_a_warning() {
        let mut links = LinkReport::default();
        links.observe("data", LinkVerdict::Followed);

        let ctx = ctx(&[]);
        report(&ctx, &links);
        assert!(
            !needs_saying(&links),
            "the operator asked for this and got it"
        );
        assert_eq!(ctx.stats.snapshot().errors, 0);
    }
}
