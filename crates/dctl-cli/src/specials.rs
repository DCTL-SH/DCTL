//! Telling an operator what a walk did about the fifos, sockets and device
//! nodes it met.
//!
//! One implementation, read by every family that walks a tree: the transfer
//! verbs, the six listing verbs and `backup`. The classification and the
//! counting live one layer down in [`dctl_store::specials`]; what is here is the
//! wording and the level. Beside [`crate::links`] and deliberately shaped the
//! same way, because it is the same promise made about a different entry — and
//! because three copies of "say something about what was passed over" is how one
//! family comes to say it and another comes to say nothing.
//!
//! # Why it is a warning and never an error
//!
//! **A warning**, shown short of `--quiet`, because the operator asked for a
//! tree and did not get all of it, and finding that out from a restore is far
//! too late. **Never an error**, because there is nothing there to lose: a fifo
//! has no bytes, a socket has no bytes, a device node's contents are not the
//! device. rclone settles it identically — it logs the entry as one it cannot
//! transfer and counts no error against the run, so a `/var` full of sockets
//! does not fail a sync. A broken *symlink* is an error and this is not, and the
//! difference is exactly that a broken link names a path that was supposed to
//! have bytes behind it.
//!
//! Every name is a note, never a warning: a walk over `/dev` must not produce
//! four hundred lines on a terminal that has already been told the count.

use dctl_store::SpecialReport;

use crate::constants::SPECIALS_SKIPPED_HINT;
use crate::ctx::Ctx;

/// Report one walk's findings about special files.
///
/// Silent when the walk met none, which is the ordinary tree and must stay
/// wordless — a line about fifos on every run is a line nobody reads on the run
/// that has one.
pub fn report(ctx: &Ctx, specials: &SpecialReport) {
    if specials.is_empty() {
        return;
    }

    ctx.out.warn(format!(
        "skipped {} special file(s). {SPECIALS_SKIPPED_HINT}",
        specials.skipped()
    ));

    for note in specials.notes() {
        ctx.out
            .info(format!("  {}: {}", note.path, note.kind.reason()));
    }
    if specials.unnamed() > 0 {
        ctx.out
            .info(format!("  … and {} more, not named", specials.unnamed()));
    }
}

/// Which special file this metadata describes.
///
/// The one place in the binary that turns a [`std::fs::Metadata`] into a kind,
/// so the transfer family's walk and `backup`'s scan cannot come to disagree
/// about what a socket is. The rule itself is
/// [`SpecialKind::from_posix_mode`](dctl_store::SpecialKind::from_posix_mode),
/// shared with the two storage backends that walk a tree of their own — four
/// walks, one classification.
///
/// [`SpecialKind::Unknown`] on a platform with no POSIX mode, and for the entry
/// that turns out to be a regular file after all: both walks reach this only
/// after excluding files, directories and links, so that answer means the entry
/// changed underneath the walk and nothing can now say what it was.
#[must_use]
pub fn kind_of(metadata: &std::fs::Metadata) -> dctl_store::SpecialKind {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        dctl_store::SpecialKind::from_posix_mode(metadata.mode())
            .unwrap_or(dctl_store::SpecialKind::Unknown)
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        dctl_store::SpecialKind::Unknown
    }
}

/// Whether a report describes anything a run must not stay quiet about.
///
/// Separate from [`report`] for the reason [`crate::links::needs_saying`] is:
/// the transfer family folds this into its own omissions warning and has to
/// *decide* before it prints, and a caller that re-derived the condition would
/// eventually derive a different one.
#[must_use]
pub const fn needs_saying(specials: &SpecialReport) -> bool {
    !specials.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::GlobalArgs;
    use clap::Parser;
    use dctl_store::SpecialKind;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn ctx(args: &[&str]) -> Ctx {
        Ctx::new(Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied())).globals)
    }

    #[test]
    fn a_walk_that_met_none_says_nothing_and_counts_nothing() {
        let ctx = ctx(&[]);
        report(&ctx, &SpecialReport::default());
        assert_eq!(ctx.stats.snapshot().errors, 0);
        assert!(!needs_saying(&SpecialReport::default()));
    }

    #[test]
    fn a_skipped_special_file_is_worth_saying_and_is_not_an_error() {
        // A socket in `/var/run` must not fail a nightly backup; it must not be
        // invisible either. rclone logs it and counts no error, and the whole of
        // this fix is the logging half DCTL left out.
        let mut specials = SpecialReport::default();
        specials.observe("run/docker.sock", SpecialKind::Socket);

        let ctx = ctx(&[]);
        report(&ctx, &specials);
        assert!(needs_saying(&specials));
        assert_eq!(ctx.stats.snapshot().errors, 0);
    }

    #[test]
    fn every_kind_reaches_the_report_without_raising_the_error_count() {
        let mut specials = SpecialReport::default();
        specials.observe("pipe", SpecialKind::Fifo);
        specials.observe("sock", SpecialKind::Socket);
        specials.observe("dev/null", SpecialKind::CharDevice);
        specials.observe("dev/sda", SpecialKind::BlockDevice);
        specials.observe("mystery", SpecialKind::Unknown);

        let ctx = ctx(&["-v"]);
        report(&ctx, &specials);
        assert_eq!(specials.skipped(), 5);
        assert_eq!(ctx.stats.snapshot().errors, 0);
    }
}
