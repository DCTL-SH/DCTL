//! The one decision every transfer command repeats per file: does this need to
//! move?
//!
//! Getting it wrong is expensive in both directions. A false "differs" re-uploads
//! a dataset that was already correct; a false "identical" leaves stale bytes at
//! the destination that `sync` will then happily keep forever. So the rules are
//! written once, here, as a pure function of two entries and a policy — no I/O,
//! no globals, no clock — and every command routes through it.
//!
//! The default comparison is **size plus modification time**, matching rclone,
//! because it costs one metadata round trip. `--checksum` upgrades it to a
//! content comparison and `--size-only` downgrades it to size alone; both are
//! the user's explicit trade of certainty against cost, and both are honoured
//! exactly rather than approximated.

use std::time::Duration;

use crate::cli::GlobalArgs;
use crate::constants::{
    DEFAULT_MODIFY_WINDOW_SECS, PATTERN_FILTER_HINT, PLAN_REASON_CHECKSUM,
    PLAN_REASON_DESTINATION_NEWER, PLAN_REASON_EXISTS, PLAN_REASON_IDENTICAL, PLAN_REASON_MISSING,
    PLAN_REASON_MODIFIED, PLAN_REASON_SIZE,
};
use crate::error::{CliError, Result};

use super::entry::Entry;
use super::options::CompareFlags;

/// What to do with one source file.
///
/// Carries the reason as a stable slug so the plan, the JSON output and the
/// verbose log all quote the same answer to "why is this being re-uploaded?".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Nothing at the destination — a first-time transfer.
    Copy(&'static str),
    /// Something at the destination, but it differs.
    Update(&'static str),
    /// Nothing to do.
    Skip(&'static str),
}

impl Action {
    /// The stable slug explaining this decision.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Copy(reason) | Self::Update(reason) | Self::Skip(reason) => reason,
        }
    }
}

/// How two sides are compared.
#[derive(Clone, Copy, Debug)]
pub struct ComparePolicy {
    /// Compare content hashes rather than size and time (`--checksum`).
    pub checksum: bool,
    /// Compare size only, ignoring time (`--size-only`).
    pub size_only: bool,
    /// Never touch anything already at the destination (`--ignore-existing`).
    pub ignore_existing: bool,
    /// Never overwrite something newer at the destination (`--update`).
    pub update: bool,
    /// Tolerance applied to every timestamp comparison.
    pub modify_window: Duration,
}

impl Default for ComparePolicy {
    fn default() -> Self {
        Self {
            checksum: false,
            size_only: false,
            ignore_existing: false,
            update: false,
            modify_window: Duration::from_secs(DEFAULT_MODIFY_WINDOW_SECS),
        }
    }
}

impl ComparePolicy {
    /// Fold the global comparison flags and a command's own flags together.
    ///
    /// Both halves arrive here rather than being read at the call sites, so
    /// `--checksum` (global) and `--ignore-existing` (per-command) can never be
    /// honoured by one command and forgotten by another.
    #[must_use]
    pub fn resolve(globals: &GlobalArgs, flags: &CompareFlags) -> Self {
        Self {
            checksum: globals.checksum,
            size_only: globals.size_only,
            ignore_existing: flags.ignore_existing,
            update: flags.update,
            modify_window: Duration::from_secs(DEFAULT_MODIFY_WINDOW_SECS),
        }
    }
}

/// Decide what to do with `source`, given what (if anything) is at the
/// destination.
///
/// The order of the rules is the contract:
///
/// 1. Nothing at the destination ⇒ copy. Nothing else can override that; a flag
///    that skipped a missing file would silently lose data.
/// 2. `--ignore-existing` ⇒ skip, without comparing. The flag's whole purpose is
///    to avoid the comparison's cost.
/// 3. `--update` ⇒ skip anything newer at the destination.
/// 4. The configured comparison decides.
///
/// # Errors
/// Returns an *unimplemented* error when `--checksum` was requested and either
/// side cannot supply a hash. Falling back to a size-and-time comparison would
/// be worse than failing: the user asked for content equality, and a weaker
/// answer dressed up as the one they asked for is exactly the misreporting
/// `PLAN.md` §6 forbids.
pub fn decide(source: &Entry, dest: Option<&Entry>, policy: &ComparePolicy) -> Result<Action> {
    let Some(dest) = dest else {
        return Ok(Action::Copy(PLAN_REASON_MISSING));
    };

    if policy.ignore_existing {
        return Ok(Action::Skip(PLAN_REASON_EXISTS));
    }

    if policy.update && dest.is_newer_than(source, policy.modify_window) {
        return Ok(Action::Skip(PLAN_REASON_DESTINATION_NEWER));
    }

    if policy.checksum {
        let (Some(ours), Some(theirs)) = (source.hash.as_deref(), dest.hash.as_deref()) else {
            return Err(CliError::unimplemented("--checksum comparison").with_hint(
                "Hashes for both sides come from the index and the provider, \
                     which the command context cannot reach yet. Compare by size \
                     and modification time instead, or add --size-only.",
            ));
        };
        return Ok(if ours == theirs {
            Action::Skip(PLAN_REASON_IDENTICAL)
        } else {
            Action::Update(PLAN_REASON_CHECKSUM)
        });
    }

    if source.size != dest.size {
        return Ok(Action::Update(PLAN_REASON_SIZE));
    }

    if policy.size_only {
        return Ok(Action::Skip(PLAN_REASON_IDENTICAL));
    }

    if source.modified_matches(dest, policy.modify_window) {
        Ok(Action::Skip(PLAN_REASON_IDENTICAL))
    } else {
        Ok(Action::Update(PLAN_REASON_MODIFIED))
    }
}

/// Refuse to run when a pattern filter was requested.
///
/// DCTL does not yet evaluate `--include`/`--exclude`/`--filter-from`/
/// `--files-from`, and the honest response is to stop. Consider what the
/// alternative does: `dctl sync src dst --exclude 'archive/**'` with the rule
/// ignored does not merely copy too much — it sees every excluded destination
/// file as an extra and **deletes** it. A filter that is quietly dropped is a
/// data-loss bug wearing a convenience feature's clothes.
///
/// The size and depth filters are evaluated for real; see [`super::listing`].
///
/// # Errors
/// Returns an unimplemented error naming the flags that were set.
pub fn ensure_filters_are_supported(globals: &GlobalArgs) -> Result<()> {
    let requested = !globals.include.is_empty()
        || !globals.exclude.is_empty()
        || !globals.filter_from.is_empty()
        || !globals.files_from.is_empty();

    if requested {
        return Err(
            CliError::unimplemented(crate::constants::PATTERN_FILTER_FEATURE)
                .with_hint(PATTERN_FILTER_HINT),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exit::ExitCode;
    use std::time::{Duration, SystemTime};

    fn at(seconds: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
    }

    fn policy() -> ComparePolicy {
        ComparePolicy::default()
    }

    /// An entry whose content hash is already known — what the index and the
    /// provider supply once the engine can ask them.
    fn hashed(path: &str, size: u64, hash: &str) -> Entry {
        Entry {
            hash: Some(hash.to_string()),
            ..Entry::file(path, size)
        }
    }

    #[test]
    fn a_missing_destination_is_always_a_copy() {
        let source = Entry::file("a", 10);
        assert_eq!(
            decide(&source, None, &policy()).unwrap(),
            Action::Copy(PLAN_REASON_MISSING)
        );
    }

    #[test]
    fn ignore_existing_never_overrides_a_missing_destination() {
        // The dangerous misreading of the flag: it must skip files that exist,
        // not files that were asked for.
        let source = Entry::file("a", 10);
        let policy = ComparePolicy {
            ignore_existing: true,
            ..policy()
        };
        assert_eq!(
            decide(&source, None, &policy).unwrap(),
            Action::Copy(PLAN_REASON_MISSING)
        );
    }

    #[test]
    fn ignore_existing_skips_without_comparing() {
        let source = Entry::file("a", 10).with_modified(at(2000));
        let dest = Entry::file("a", 99).with_modified(at(1000));
        let policy = ComparePolicy {
            ignore_existing: true,
            ..policy()
        };
        assert_eq!(
            decide(&source, Some(&dest), &policy).unwrap(),
            Action::Skip(PLAN_REASON_EXISTS)
        );
    }

    #[test]
    fn update_protects_a_newer_destination() {
        let source = Entry::file("a", 10).with_modified(at(1000));
        let dest = Entry::file("a", 10).with_modified(at(5000));
        let policy = ComparePolicy {
            update: true,
            ..policy()
        };
        assert_eq!(
            decide(&source, Some(&dest), &policy).unwrap(),
            Action::Skip(PLAN_REASON_DESTINATION_NEWER)
        );
    }

    #[test]
    fn update_still_transfers_an_older_destination() {
        let source = Entry::file("a", 10).with_modified(at(5000));
        let dest = Entry::file("a", 10).with_modified(at(1000));
        let policy = ComparePolicy {
            update: true,
            ..policy()
        };
        assert_eq!(
            decide(&source, Some(&dest), &policy).unwrap(),
            Action::Update(PLAN_REASON_MODIFIED)
        );
    }

    #[test]
    fn size_differences_always_win() {
        let source = Entry::file("a", 10).with_modified(at(1000));
        let dest = Entry::file("a", 11).with_modified(at(1000));
        assert_eq!(
            decide(&source, Some(&dest), &policy()).unwrap(),
            Action::Update(PLAN_REASON_SIZE)
        );
    }

    #[test]
    fn matching_size_and_time_is_identical() {
        let source = Entry::file("a", 10).with_modified(at(1000));
        let dest = Entry::file("a", 10).with_modified(at(1001));
        assert_eq!(
            decide(&source, Some(&dest), &policy()).unwrap(),
            Action::Skip(PLAN_REASON_IDENTICAL)
        );
    }

    #[test]
    fn size_only_ignores_the_clock() {
        // The point of the flag: a destination that cannot report timestamps
        // must not look modified on every run.
        let source = Entry::file("a", 10).with_modified(at(1000));
        let dest = Entry::file("a", 10);
        let policy = ComparePolicy {
            size_only: true,
            ..policy()
        };
        assert_eq!(
            decide(&source, Some(&dest), &policy).unwrap(),
            Action::Skip(PLAN_REASON_IDENTICAL)
        );
    }

    #[test]
    fn an_unknown_timestamp_is_treated_as_modified_not_identical() {
        // Safe direction: re-transferring costs bandwidth, skipping costs data.
        let source = Entry::file("a", 10).with_modified(at(1000));
        let dest = Entry::file("a", 10);
        assert_eq!(
            decide(&source, Some(&dest), &policy()).unwrap(),
            Action::Update(PLAN_REASON_MODIFIED)
        );
    }

    #[test]
    fn checksum_comparison_uses_hashes_when_both_sides_have_them() {
        let policy = ComparePolicy {
            checksum: true,
            ..policy()
        };
        let source = hashed("a", 10, "aa");
        let same = hashed("a", 999, "aa");
        let different = hashed("a", 10, "bb");

        // Content equality outranks the size difference: that is what the flag
        // was asked for.
        assert_eq!(
            decide(&source, Some(&same), &policy).unwrap(),
            Action::Skip(PLAN_REASON_IDENTICAL)
        );
        assert_eq!(
            decide(&source, Some(&different), &policy).unwrap(),
            Action::Update(PLAN_REASON_CHECKSUM)
        );
    }

    #[test]
    fn checksum_comparison_fails_loudly_when_a_hash_is_missing() {
        // Never silently downgrade to size-and-time: the user asked for content
        // equality, and answering a different question would be misreporting.
        let policy = ComparePolicy {
            checksum: true,
            ..policy()
        };
        let source = Entry::file("a", 10);
        let dest = Entry::file("a", 10);
        let error = decide(&source, Some(&dest), &policy).unwrap_err();
        assert_ne!(error.code(), ExitCode::Success);
        assert!(error.hint().is_some());
    }

    #[test]
    fn pattern_filters_are_refused_rather_than_ignored() {
        use clap::Parser;

        #[derive(Parser, Debug)]
        struct Harness {
            #[command(flatten)]
            globals: GlobalArgs,
        }
        let parse = |args: &[&str]| {
            Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied())).globals
        };

        assert!(ensure_filters_are_supported(&parse(&[])).is_ok());
        // Silently dropping this rule would make `sync` delete everything under
        // `archive/` at the destination.
        let error = ensure_filters_are_supported(&parse(&["--exclude", "archive/**"])).unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.hint().is_some_and(|hint| hint.contains("sync")));

        assert!(ensure_filters_are_supported(&parse(&["--include", "*.jpg"])).is_err());
        assert!(ensure_filters_are_supported(&parse(&["--files-from", "list.txt"])).is_err());
    }

    #[test]
    fn size_and_depth_filters_are_not_refused() {
        use clap::Parser;

        #[derive(Parser, Debug)]
        struct Harness {
            #[command(flatten)]
            globals: GlobalArgs,
        }
        let globals = Harness::parse_from(["dctl", "--min-size", "1M", "--max-depth", "2"]).globals;
        // These are evaluated for real by the listing walk, so they must pass.
        assert!(ensure_filters_are_supported(&globals).is_ok());
    }
}
