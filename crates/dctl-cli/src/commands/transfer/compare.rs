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
//! ## When the default comparison is answered by content instead
//!
//! A destination that stamps its own write time cannot be compared by
//! modification time at all — not badly, but *at all*: the number it reports is
//! true and describes something else. That is the state of a sealed vault today,
//! because `dctl_core::Vault::put_file` takes no source timestamp, and it made
//! `copy` re-upload every file forever while `check` called a tree it had just
//! written entirely different (defect D5).
//!
//! [`ComparePolicy::content_for_time`] is how that arrives here. It is set by
//! [`crate::fidelity`] — never by a flag — and it swaps the timestamp question
//! for the content question the vault can actually answer. The difference from
//! `--checksum` is deliberate and is in the missing-hash arm: `--checksum` is a
//! request, so a side that cannot answer it is a refusal, while this is a
//! compensation nobody asked for, so a side that cannot answer it means the file
//! is transferred. Sending a file that did not need sending costs bandwidth;
//! refusing a plain `copy` because one index row predates content hashing would
//! stop a backup dead.

use std::time::Duration;

use crate::cli::GlobalArgs;
use crate::constants::{
    CHECKSUM_UNAVAILABLE_HINT, DEFAULT_MODIFY_WINDOW_SECS, PLAN_REASON_CHECKSUM,
    PLAN_REASON_CONTENT_UNRECORDED, PLAN_REASON_DESTINATION_NEWER, PLAN_REASON_EXISTS,
    PLAN_REASON_IDENTICAL, PLAN_REASON_MISSING, PLAN_REASON_MODIFIED, PLAN_REASON_SIZE,
    PLAN_REASON_SIZE_UNRECORDED,
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
    /// Answer the default comparison by content, because a side of this transfer
    /// stamps its own write time and so has no source timestamp to compare.
    ///
    /// **Not a flag, and it must never become one.** It is decided per transfer
    /// by [`crate::fidelity`] from the configuration, and it exists only because
    /// `dctl_core::Vault::put_file` records `now_unix()` rather than the source's
    /// modification time. The day the core takes that parameter, this field and
    /// everything that sets it are deleted together — see the module docs.
    ///
    /// Has no effect under `--size-only` or `--checksum`: both are explicit
    /// instructions, and neither depends on a timestamp.
    pub content_for_time: bool,
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
            content_for_time: false,
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
            // Off here on purpose: nothing on the command line selects it, and
            // the caller that knows which places this transfer touches turns it
            // on through [`ComparePolicy::comparing_content_for_time`].
            content_for_time: false,
            modify_window: Duration::from_secs(DEFAULT_MODIFY_WINDOW_SECS),
        }
    }

    /// Answer the default comparison by content rather than by modification
    /// time.
    ///
    /// A builder rather than a parameter on [`ComparePolicy::resolve`], because
    /// the two decisions come from different places and must not be confused: the
    /// flags come from the user, and this comes from what the transfer's two ends
    /// turn out to be.
    #[must_use]
    pub const fn comparing_content_for_time(mut self, yes: bool) -> Self {
        self.content_for_time = yes;
        self
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

    if policy.content_for_time {
        return Ok(match (source.hash.as_deref(), dest.hash.as_deref()) {
            (Some(ours), Some(theirs)) if ours == theirs => Action::Skip(PLAN_REASON_IDENTICAL),
            (Some(_), Some(_)) => Action::Update(PLAN_REASON_CHECKSUM),
            // Nobody asked for this comparison, so a side that cannot supply a
            // hash may not stop the run. The file is sent, which is the safe
            // direction and is also self-healing: the write records the hash the
            // next run will compare against.
            _ => Action::Update(PLAN_REASON_CONTENT_UNRECORDED),
        });
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

    /// The default comparison against a side that stamps its own write time.
    fn substituted() -> ComparePolicy {
        policy().comparing_content_for_time(true)
    }

    #[test]
    fn a_write_stamped_destination_is_compared_by_content_not_by_time() {
        // Defect D5 in one assertion. The two timestamps are a day apart —
        // because one of them is when the vault was written and the other is
        // when the file was last edited — and the contents are identical. Under
        // the old rule this was `modified` on every run, forever.
        let source = hashed("a", 10, "aa").with_modified(at(1_000));
        let dest = hashed("a", 10, "aa").with_modified(at(87_400));
        assert_eq!(
            decide(&source, Some(&dest), &substituted()).unwrap(),
            Action::Skip(PLAN_REASON_IDENTICAL)
        );
    }

    #[test]
    fn identical_times_do_not_excuse_different_contents() {
        // The dangerous direction. A same-size, same-time edit is exactly what
        // the substituted comparison has to keep catching, or the fix would have
        // traded a useless re-upload for a missed one.
        let source = hashed("a", 10, "aa").with_modified(at(1_000));
        let dest = hashed("a", 10, "bb").with_modified(at(1_000));
        assert_eq!(
            decide(&source, Some(&dest), &substituted()).unwrap(),
            Action::Update(PLAN_REASON_CHECKSUM)
        );
    }

    #[test]
    fn a_size_difference_still_answers_before_any_hash_is_consulted() {
        // Cheap and unanswerable-by-anything-else: different sizes cannot be the
        // same contents, so there is nothing for a hash to add.
        let source = hashed("a", 10, "aa");
        let dest = hashed("a", 11, "aa");
        assert_eq!(
            decide(&source, Some(&dest), &substituted()).unwrap(),
            Action::Update(PLAN_REASON_SIZE)
        );
    }

    #[test]
    fn a_missing_hash_transfers_the_file_rather_than_stopping_the_run() {
        // The difference from `--checksum`, and the reason the two are separate
        // fields. Nobody asked for this comparison, so an index row with no
        // recorded content hash — what `rebuild_index` writes — must not turn a
        // plain `copy` into a fatal error.
        let source = hashed("a", 10, "aa");
        let dest = Entry::file("a", 10);
        assert_eq!(
            decide(&source, Some(&dest), &substituted()).unwrap(),
            Action::Update(PLAN_REASON_CONTENT_UNRECORDED)
        );
        // …and the reason says which of the two happened. `modified` would send
        // an operator looking at clocks that were never compared.
        assert_ne!(
            decide(&source, Some(&dest), &substituted())
                .unwrap()
                .reason(),
            PLAN_REASON_MODIFIED
        );
    }

    #[test]
    fn the_substitution_never_overrides_a_flag_the_user_set() {
        // `--size-only` is a request for the cheapest comparison there is, and
        // upgrading it would spend a full read of the source on a question the
        // user declined to ask. `--checksum` already asks this one, so it keeps
        // its own strict missing-hash refusal rather than the lenient arm.
        let source = hashed("a", 10, "aa");
        let same_size = hashed("a", 10, "bb");
        assert_eq!(
            decide(
                &source,
                Some(&same_size),
                &ComparePolicy {
                    size_only: true,
                    ..substituted()
                }
            )
            .unwrap(),
            Action::Skip(PLAN_REASON_IDENTICAL)
        );

        let unhashed = Entry::file("a", 10);
        assert!(
            decide(
                &source,
                Some(&unhashed),
                &ComparePolicy {
                    checksum: true,
                    ..substituted()
                }
            )
            .is_err(),
            "an explicit --checksum still refuses what it cannot answer"
        );
    }

    #[test]
    fn ignore_existing_and_update_still_outrank_the_substitution() {
        // The rule order in this function is the contract; a new comparison
        // slotted in at the wrong height would silently change what two flags
        // mean.
        let source = hashed("a", 10, "aa").with_modified(at(1_000));
        let dest = hashed("a", 10, "bb").with_modified(at(9_000));
        assert_eq!(
            decide(
                &source,
                Some(&dest),
                &ComparePolicy {
                    ignore_existing: true,
                    ..substituted()
                }
            )
            .unwrap(),
            Action::Skip(PLAN_REASON_EXISTS)
        );
        assert_eq!(
            decide(
                &source,
                Some(&dest),
                &ComparePolicy {
                    update: true,
                    ..substituted()
                }
            )
            .unwrap(),
            Action::Skip(PLAN_REASON_DESTINATION_NEWER)
        );
    }

    #[test]
    fn the_substitution_is_off_unless_something_turns_it_on() {
        // It is not a flag and has no command-line spelling, so the only way it
        // can reach a policy is the builder — which is what keeps an ordinary
        // filesystem transfer from paying for a hash it does not need.
        use clap::Parser as _;

        #[derive(clap::Parser, Debug)]
        struct Harness {
            #[command(flatten)]
            globals: GlobalArgs,
        }

        assert!(!ComparePolicy::default().content_for_time);
        let globals = Harness::parse_from(["dctl"]).globals;
        assert!(!ComparePolicy::resolve(&globals, &CompareFlags::default()).content_for_time);
        assert!(policy().comparing_content_for_time(true).content_for_time);
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
