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
//!
//! ## Where the hashes `--checksum` compares come from
//!
//! Not from here. This file is a pure function and never reads a byte; the two
//! hashes arrive on the entries, put there by [`super::listing`] when — and only
//! when — the flag asked for them. A vault side carries the plaintext BLAKE3 it
//! recorded at write time, and a local side is read and hashed. Both spell the
//! digest the same way ([`super::checksum`]), so the comparison below is a
//! string equality and not a negotiation.
//!
//! One case genuinely cannot answer, and it is refused rather than downgraded: a
//! **plain object store** knows the provider's checksum of whatever bytes it
//! happens to be holding, which is a different claim from "the BLAKE3 of the
//! plaintext that was stored". Comparing the two would produce a confident wrong
//! answer, and answering the size-and-time question instead while the user asked
//! for content equality is exactly the misreport `PLAN.md` §6 forbids.
//!
//! ## There is no fourth comparison, and there used to be
//!
//! A destination that stamps its own write time cannot be compared by
//! modification time at all — not badly, but *at all*: the number it reports is
//! true and describes something else. Every vault destination was in that state,
//! because `dctl_core::Vault::put_file` took no source timestamp, and it made
//! `copy` re-upload every file forever while `check` called a tree it had just
//! written entirely different (defect D5).
//!
//! The answer, for a while, was a fourth mode nobody could ask for: against a
//! vault the default silently became a content comparison, which the index could
//! answer for free on its side and which cost a **full read of the other side**
//! — very nearly the price of the transfer it existed to avoid, paid on every
//! run of every nightly backup.
//!
//! The cause is fixed rather than compensated for. A vault index row now carries
//! the source's modification time ([`dctl_core::Modified`]) and a downloaded file
//! is stamped with the one its record holds, so a sealed side answers the
//! ordinary question like any other side and the substitution — along with the
//! module that decided it and the warning that announced it — is gone.
//!
//! What that costs, stated plainly because it is a real trade: the default no
//! longer notices an edit that changes neither the size nor the modification
//! time. `--checksum` does, and is the flag to reach for when a source is
//! rewritten by something that preserves timestamps.

use std::time::Duration;

use crate::cli::GlobalArgs;
use crate::constants::{
    CHECKSUM_UNAVAILABLE_HINT, DEFAULT_MODIFY_WINDOW_SECS, PLAN_REASON_CHECKSUM,
    PLAN_REASON_DESTINATION_NEWER, PLAN_REASON_EXISTS, PLAN_REASON_IDENTICAL, PLAN_REASON_MISSING,
    PLAN_REASON_MODIFIED, PLAN_REASON_SIZE, PLAN_REASON_SIZE_UNRECORDED,
};
use crate::error::{CliError, Result};
use crate::exit::ExitCode;

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
            return Err(CliError::new(
                ExitCode::FatalError,
                format!("--checksum: no content hash for '{}'", source.path),
            )
            .with_hint(CHECKSUM_UNAVAILABLE_HINT));
        };
        return Ok(if ours == theirs {
            Action::Skip(PLAN_REASON_IDENTICAL)
        } else {
            Action::Update(PLAN_REASON_CHECKSUM)
        });
    }

    // `zip` rather than `!=` on the two options. Two absent sizes are two
    // unknowns and must not compare equal: a vault whose index was rebuilt
    // reports no size for any object, and `Option::eq` would call every one of
    // them "the same size" as the local file it is being compared against —
    // which under `--size-only` is a skip, and a backup that skipped every file
    // is the worst outcome this comparison can produce. An unknown on either
    // side means the sizes were never comparable, so the file is sent.
    match source.size.zip(dest.size) {
        Some((ours, theirs)) if ours != theirs => return Ok(Action::Update(PLAN_REASON_SIZE)),
        Some(_) => {}
        None => return Ok(Action::Update(PLAN_REASON_SIZE_UNRECORDED)),
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
        // The one side that genuinely cannot answer is a plain object store,
        // whose provider checksum is not the plaintext BLAKE3 a vault records.
        let policy = ComparePolicy {
            checksum: true,
            ..policy()
        };
        let source = Entry::file("a", 10);
        let dest = Entry::file("a", 10);
        let error = decide(&source, Some(&dest), &policy).unwrap_err();
        assert_ne!(error.code(), ExitCode::Success);
        // The refusal names the file, so an operator knows which side to look at.
        assert!(error.message().contains('a'), "{}", error.message());
        assert!(error.hint().is_some());
    }

    #[test]
    fn a_matching_time_is_a_skip_however_far_from_the_clock_it_is() {
        // Where the substituted content comparison used to live, and the case it
        // was invented for: a source last edited a day before the copy of it was
        // made. Both sides now carry the *source's* time, so the ordinary rule
        // answers it — and this is the assertion that fails first if a
        // destination ever goes back to stamping its own write time.
        let source = Entry::file("a", 10).with_modified(at(1_000));
        let dest = Entry::file("a", 10).with_modified(at(1_000));
        assert_eq!(
            decide(&source, Some(&dest), &policy()).unwrap(),
            Action::Skip(PLAN_REASON_IDENTICAL)
        );

        // …and the destination that *did* stamp its own write time is still
        // caught, rather than being waved through by whatever replaced the
        // substitution.
        let write_stamped = Entry::file("a", 10).with_modified(at(87_400));
        assert_eq!(
            decide(&source, Some(&write_stamped), &policy()).unwrap(),
            Action::Update(PLAN_REASON_MODIFIED)
        );
    }

    #[test]
    fn a_same_size_edit_that_kept_its_timestamp_is_the_documented_cost() {
        // Stated as a test rather than left to be discovered. The default is size
        // and modification time, so an edit that changes neither is invisible to
        // it — the same trade rclone and rsync make, and the reason `--checksum`
        // exists. Pinning it here means a reader of this file learns the limit
        // from the suite instead of from a restore.
        let source = hashed("a", 10, "aa").with_modified(at(1_000));
        let dest = hashed("a", 10, "bb").with_modified(at(1_000));
        assert_eq!(
            decide(&source, Some(&dest), &policy()).unwrap(),
            Action::Skip(PLAN_REASON_IDENTICAL),
        );
        assert_eq!(
            decide(
                &source,
                Some(&dest),
                &ComparePolicy {
                    checksum: true,
                    ..policy()
                }
            )
            .unwrap(),
            Action::Update(PLAN_REASON_CHECKSUM),
            "--checksum is the answer to the case the default cannot see"
        );
    }

    #[test]
    fn a_checksum_refusal_survives_one_side_having_an_answer() {
        // Half an answer is not an answer: a vault side knowing its hash while
        // the other side does not still cannot establish content equality.
        let policy = ComparePolicy {
            checksum: true,
            ..policy()
        };
        assert!(decide(&hashed("a", 10, "aa"), Some(&Entry::file("a", 10)), &policy).is_err());
        assert!(decide(&Entry::file("a", 10), Some(&hashed("a", 10, "aa")), &policy).is_err());
    }
}
