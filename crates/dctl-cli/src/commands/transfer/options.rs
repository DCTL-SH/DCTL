//! Per-command flags shared by the transfer family.
//!
//! These are the rclone-compatible dials that are *not* global: they change what
//! one transfer does, not how the whole process behaves, so putting them on
//! [`crate::cli::GlobalArgs`] would offer them to `ls` and `version` too.
//!
//! They are grouped into three flattened structs rather than one, because the
//! groups are not universally applicable and clap must reflect that. A flag that
//! parses but is then ignored is a defect: `dctl sync --no-traverse` has no
//! meaningful behaviour — a sync must list the destination in order to find the
//! extras it deletes — so `sync` does not offer the flag at all and the parser
//! rejects it, instead of accepting it and quietly doing something else.

use clap::Args;

use crate::error::{CliError, Result};

/// Flags that change how source and destination are compared.
///
/// Offered by every verb in the family: all five have to decide, per file,
/// whether the destination already holds the right bytes.
#[derive(Args, Clone, Debug, Default)]
pub struct CompareFlags {
    /// Skip files that already exist at the destination, without comparing them.
    #[arg(long)]
    pub ignore_existing: bool,

    /// Skip files where the destination is newer than the source.
    #[arg(long)]
    pub update: bool,
}

/// Flags that change how the destination is enumerated.
///
/// Not offered by `sync`; see the module docs.
#[derive(Args, Clone, Debug, Default)]
pub struct TraversalFlags {
    /// Do not list the destination; assume every source file is missing there.
    ///
    /// Faster on a destination with far more files than the source, at the cost
    /// of re-transferring anything already present.
    #[arg(long)]
    pub no_traverse: bool,
}

/// When `sync` removes the files that exist only at the destination.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DeleteMode {
    /// Delete everything first, then transfer.
    ///
    /// The only mode that guarantees the destination never needs room for the
    /// old and new copies at once — and the only one where a mid-run failure can
    /// leave the destination holding neither.
    Before,
    /// Delete and transfer interleaved, in path order. The default.
    #[default]
    During,
    /// Transfer everything first, delete afterwards.
    ///
    /// The safest ordering, and the one to reach for when the destination is the
    /// only copy: nothing is removed until every replacement is durably
    /// committed, so an interrupted run leaves a superset rather than a gap.
    After,
}

/// The three mutually exclusive `--delete-*` flags.
///
/// Modelled as three booleans rather than one `--delete=MODE` value because that
/// is rclone's spelling and therefore what existing scripts contain. clap
/// enforces the exclusivity, so [`DeleteFlags::mode`] can never see two of them
/// set — but it is still written to fail rather than pick a winner, because a
/// silently-resolved contradiction about *when data is deleted* is not a
/// contradiction worth resolving quietly.
#[derive(Args, Clone, Debug, Default)]
pub struct DeleteFlags {
    /// Delete destination files before transferring.
    #[arg(long, conflicts_with_all = ["delete_during", "delete_after"])]
    pub delete_before: bool,

    /// Delete destination files during the transfer. The default.
    #[arg(long, conflicts_with_all = ["delete_before", "delete_after"])]
    pub delete_during: bool,

    /// Delete destination files after transferring everything.
    #[arg(long, conflicts_with_all = ["delete_before", "delete_during"])]
    pub delete_after: bool,
}

impl DeleteFlags {
    /// The requested mode, or the default when none was given.
    ///
    /// # Errors
    /// Returns a usage error if more than one flag is somehow set. clap already
    /// rejects that at parse time; this arm exists so a future refactor that
    /// loosens the parser cannot turn a contradiction into a silent choice.
    pub fn mode(&self) -> Result<DeleteMode> {
        match (self.delete_before, self.delete_during, self.delete_after) {
            (true, false, false) => Ok(DeleteMode::Before),
            (false, true, false) => Ok(DeleteMode::During),
            (false, false, true) => Ok(DeleteMode::After),
            (false, false, false) => Ok(DeleteMode::default()),
            _ => Err(CliError::usage(
                "--delete-before, --delete-during and --delete-after are mutually exclusive",
            )
            .with_hint("Pick one; the default is --delete-during.")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        compare: CompareFlags,
        #[command(flatten)]
        traversal: TraversalFlags,
        #[command(flatten)]
        delete: DeleteFlags,
    }

    fn parse(args: &[&str]) -> Harness {
        Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied()))
    }

    #[test]
    fn every_flag_defaults_to_off() {
        let parsed = parse(&[]);
        assert!(!parsed.compare.ignore_existing);
        assert!(!parsed.compare.update);
        assert!(!parsed.traversal.no_traverse);
        assert_eq!(parsed.delete.mode().unwrap(), DeleteMode::During);
    }

    #[test]
    fn the_rclone_spellings_parse() {
        let parsed = parse(&["--ignore-existing", "--update", "--no-traverse"]);
        assert!(parsed.compare.ignore_existing);
        assert!(parsed.compare.update);
        assert!(parsed.traversal.no_traverse);
    }

    #[test]
    fn each_delete_mode_is_selectable() {
        assert_eq!(
            parse(&["--delete-before"]).delete.mode().unwrap(),
            DeleteMode::Before
        );
        assert_eq!(
            parse(&["--delete-during"]).delete.mode().unwrap(),
            DeleteMode::During
        );
        assert_eq!(
            parse(&["--delete-after"]).delete.mode().unwrap(),
            DeleteMode::After
        );
    }

    #[test]
    fn delete_modes_are_mutually_exclusive_at_parse_time() {
        // Two answers to "when is data deleted?" is not a question to resolve by
        // precedence.
        assert!(Harness::try_parse_from(["dctl", "--delete-before", "--delete-after"]).is_err());
        assert!(Harness::try_parse_from(["dctl", "--delete-during", "--delete-before"]).is_err());
    }

    #[test]
    fn a_contradiction_that_slipped_past_the_parser_is_still_refused() {
        let flags = DeleteFlags {
            delete_before: true,
            delete_during: true,
            delete_after: false,
        };
        let error = flags.mode().unwrap_err();
        assert_eq!(error.code(), crate::exit::ExitCode::Usage);
    }
}
