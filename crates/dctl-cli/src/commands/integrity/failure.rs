//! What a single object's integrity check concluded, and how a run that found
//! damage ends.
//!
//! The important rule this file exists to enforce is
//! [the plan](https://doc.dctl.sh/project/plan) §6's read-path guarantee: *an
//! integrity failure is loud, never served as data*. A corrupt object must
//! therefore always end the process with [`ExitCode::IntegrityFailure`] and a
//! message that says, in words, that the bytes were not handed over — never
//! with the generic bucket, and never with a wording that leaves room for
//! "maybe some of it came through".
//!
//! Four verdicts rather than pass/fail, because the operator's next action is
//! different for each one, and a report that collapsed them would tell them to
//! do the wrong thing:
//!
//! | verdict      | what happened                                | what to do            |
//! |--------------|----------------------------------------------|-----------------------|
//! | `ok`         | decrypted and matched its recorded hash       | nothing               |
//! | `corrupt`    | authentication failed — real damage           | restore from a copy   |
//! | `missing`    | indexed, but absent at the provider           | rebuild/reconcile     |
//! | `unreadable` | the provider never answered                   | retry                 |

// One item below has no caller outside this module's tests: `is_corruption`, the
// narrow "was this real damage" question a future repair path needs. It is kept
// with the test that pins it because the distinction it draws — an outage is not
// bit rot — is the one this whole file exists to preserve.
#![allow(dead_code)]

use crate::constants::{
    INTEGRITY_FAILURE_HINT, INTEGRITY_NOT_SERVED_NOTICE, INTEGRITY_NOTHING_VERIFIED,
    VERDICT_CORRUPT, VERDICT_MISSING, VERDICT_OK, VERDICT_UNREADABLE, VERDICT_UNVERIFIABLE,
};
use crate::error::CliError;
use crate::exit::ExitCode;

/// The conclusion for one object.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Verdict {
    /// The object read back without complaint.
    ///
    /// **What that proves depends on the source, and this verdict does not say
    /// which.** Over a vault it means decrypted, authenticated, and matched the
    /// hash recorded in the index — which is what this doc comment used to claim
    /// unconditionally, and it was false for half the remotes that produce the
    /// verdict. Over a plain object store, which records no hash of its own, it
    /// means the object was still there and every byte of it came back; a
    /// provider that returned different bytes would produce this same `Ok`.
    ///
    /// The distinction is carried beside the verdict rather than folded into it,
    /// by the report's `assurance` field
    /// ([`Assurance`](crate::source::Assurance)), because `verify` and `scrub`
    /// share this vocabulary and a fifth variant would fork it — and because a
    /// per-object word cannot state a property of the whole source. A consumer
    /// reading `Ok` without reading `assurance` is reading half a sentence.
    #[default]
    Ok,
    /// AEAD authentication or the plaintext hash comparison failed. The bytes
    /// exist but are not the bytes that were stored.
    Corrupt,
    /// The index has a record, but the provider has no object for it.
    Missing,
    /// The provider could not serve the object at all — an outage, a permission
    /// change, or a network path that stayed broken past the retry budget.
    Unreadable,
    /// Every byte came back and nothing recorded anywhere could say whether they
    /// are the bytes that were written.
    ///
    /// The fifth verdict, and the one this vocabulary was missing. It is a fact
    /// about **this object**, which is why it belongs here beside the others and
    /// not in [`Assurance`](crate::source::Assurance): a backend that records
    /// digests can still hold an object it has none for — a B2 large file
    /// carries `contentSha1: "none"` and only the uploader can have recorded a
    /// whole-file digest beside it — and the run has to say which objects those
    /// were rather than averaging them into a source-level sentence.
    ///
    /// Reported as `ok` before this existed. That is the defect: `ok` is the
    /// word an operator reads as *checked*.
    Unverifiable,
}

impl Verdict {
    /// The stable slug used in `--json` output and log records.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Ok => VERDICT_OK,
            Self::Corrupt => VERDICT_CORRUPT,
            Self::Missing => VERDICT_MISSING,
            Self::Unreadable => VERDICT_UNREADABLE,
            Self::Unverifiable => VERDICT_UNVERIFIABLE,
        }
    }

    /// Whether this verdict means the object did not verify.
    #[must_use]
    pub const fn is_failure(self) -> bool {
        !matches!(self, Self::Ok)
    }

    /// Whether stored bytes failed authentication.
    ///
    /// Narrower than [`Verdict::is_failure`] on purpose: an object the provider
    /// could not serve is a *availability* problem, and calling it corruption
    /// would send someone hunting for damage that is not there.
    #[must_use]
    pub const fn is_corruption(self) -> bool {
        matches!(self, Self::Corrupt)
    }

    /// Rank used to reduce many verdicts to the one that decides the exit code.
    ///
    /// Corruption outranks everything because it is the only verdict that means
    /// data is gone rather than merely out of reach; a missing object outranks an
    /// unreadable one because a retry can fix the latter and nothing fixes the
    /// former.
    #[must_use]
    pub const fn severity(self) -> u8 {
        match self {
            Self::Ok => 0,
            // Lowest of the four failures: nothing here is evidence that
            // anything is wrong with the data, only that the question was not
            // answered. Any verdict that *did* look at the bytes outranks it.
            Self::Unverifiable => 1,
            Self::Unreadable => 2,
            Self::Missing => 3,
            Self::Corrupt => 4,
        }
    }

    /// The worse of two verdicts.
    #[must_use]
    pub const fn worse(self, other: Self) -> Self {
        if other.severity() > self.severity() {
            other
        } else {
            self
        }
    }

    /// The exit code this verdict implies when it is the worst one in a run.
    #[must_use]
    pub const fn exit_code(self) -> ExitCode {
        match self {
            Self::Ok => ExitCode::Success,
            // The whole reason code 21 exists
            // ([the plan](https://doc.dctl.sh/project/plan) §7).
            Self::Corrupt => ExitCode::IntegrityFailure,
            Self::Missing => ExitCode::FileNotFound,
            Self::Unreadable => ExitCode::TemporaryError,
            Self::Unverifiable => ExitCode::VerificationNotPossible,
        }
    }
}

impl serde::Serialize for Verdict {
    /// Serialised as its slug, so the JSON a consumer matches on and the word a
    /// human reads in the table are the same string by construction.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.slug())
    }
}

/// The error that ends a run in which objects failed to verify.
///
/// Returns `None` for a clean run, so a caller can write
/// `if let Some(error) = failure(..) { return Err(error) }` without deciding for
/// itself what "clean" means.
///
/// The corruption message carries [`INTEGRITY_NOT_SERVED_NOTICE`] verbatim. That
/// sentence is the product's promise: DCTL refused to hand over bytes it could
/// not authenticate, and the person reading the line must not be left wondering
/// whether a partial, silently-wrong file landed somewhere.
#[must_use]
pub fn failure(worst: Verdict, failed: u64, examined: u64) -> Option<CliError> {
    if !worst.is_failure() || failed == 0 {
        return None;
    }

    let scope = format!("{failed} of {examined}");
    let message = match worst {
        Verdict::Ok => return None,
        Verdict::Corrupt => {
            format!("{scope} objects failed integrity verification — {INTEGRITY_NOT_SERVED_NOTICE}")
        }
        Verdict::Missing => {
            format!("{scope} objects are recorded in the index but absent from the remote")
        }
        Verdict::Unreadable => format!("{scope} objects could not be read from the remote"),
        Verdict::Unverifiable => format!(
            "{scope} objects came back whole and could not be checked — nothing recorded \
             anywhere says whether their bytes are the bytes that were written"
        ),
    };

    Some(CliError::new(worst.exit_code(), message).with_hint(hint_for(worst)))
}

/// The error that ends a run which examined nothing at all.
///
/// Not a failure — nothing broke, and the operator asked for a check of a place
/// with nothing in it — but not a pass either.
/// [`ExitCode::NoFilesTransferred`] (9) is already published as "succeeded, but
/// the run did no work", which is exactly the claim: this run proved nothing.
///
/// It lives here because `verify` and `scrub` must not answer the question
/// differently. They did: a `scrub` over a mistyped prefix exited 9 and said so,
/// while a `verify` over the same prefix exited 0 and — at the default verbosity
/// — printed nothing on either stream, because its notice was an
/// [`Out::info`](crate::output::Out::info). A cron entry calling the second could
/// verify nothing every night and stay green for years, and the first anybody
/// would hear of it is a restore.
///
/// `cause` is the verb's own: which of the several routes to zero coverage this
/// run took decides what the operator should do next, and only the verb knows.
#[must_use]
pub fn nothing_examined(cause: &str, hint: &'static str) -> CliError {
    CliError::new(
        ExitCode::NoFilesTransferred,
        format!("{INTEGRITY_NOTHING_VERIFIED}: {cause}"),
    )
    .with_hint(hint)
}

/// The error for a named target that resolved to nothing at all.
///
/// A different claim from [`nothing_examined`], and a different exit code:
/// `verify store:gone.bin` names ONE object, and an empty walk under that
/// exact name proves the object is not there — which is
/// [`ExitCode::FileNotFound`] (4), the published "file not found" every other
/// verb already uses for a named absence. Folding it into exit 9 told a cron
/// job "the run did no work" about a run that discovered a loss.
///
/// Deliberately not worded as "in the index but absent from the remote": that
/// sentence is false on a plain remote, and false for a name that was never
/// indexed. What an empty walk proves is exactly this and no more.
#[must_use]
pub fn named_target_missing(target: &str, hint: &'static str) -> CliError {
    CliError::new(
        ExitCode::FileNotFound,
        format!("'{target}' was not found: the remote holds no object with this name"),
    )
    .with_hint(hint)
}

/// The error for a single object that failed authentication.
///
/// Used on the read path, where there is no run-level tally to summarise: `cat`,
/// `hashsum` and a one-object `verify` all fail the same way and must say the
/// same thing.
#[must_use]
pub fn object_failure(path: &str, verdict: Verdict) -> CliError {
    let message = match verdict {
        Verdict::Ok => format!("'{path}' verified"),
        Verdict::Corrupt => {
            format!("'{path}' failed integrity verification — {INTEGRITY_NOT_SERVED_NOTICE}")
        }
        Verdict::Missing => format!("'{path}' is in the index but absent from the remote"),
        Verdict::Unreadable => format!("'{path}' could not be read from the remote"),
        Verdict::Unverifiable => format!(
            "'{path}' came back whole and could not be checked — nothing recorded anywhere \
             says whether its bytes are the bytes that were written"
        ),
    };
    CliError::new(verdict.exit_code(), message).with_hint(hint_for(verdict))
}

/// Which finding a failed read-back represents.
///
/// Three outcomes rather than one, because the operator's next action differs
/// for each and a report that collapsed them would send them to the wrong place:
/// corruption means restore from another copy, a missing object means the index
/// and the provider disagree, and an unreadable one may need nothing but a
/// retry.
///
/// It lives here rather than in any one command because `verify`, `scrub` and
/// `hashsum` all ask the same question of the same errors, and three copies of
/// this `match` would drift one commit at a time — with the first divergence
/// being some command reporting an outage as corruption and sending an operator
/// hunting for damage that is not there.
#[must_use]
pub fn classify(error: &CliError) -> Verdict {
    match error.code() {
        // The bytes came back and were not the bytes that were stored. This is
        // the only verdict that means data is gone rather than out of reach.
        ExitCode::IntegrityFailure | ExitCode::ChecksumMismatch => Verdict::Corrupt,
        ExitCode::FileNotFound => Verdict::Missing,
        // The read succeeded and the question went unanswered. Kept apart from
        // `Unreadable` because a retry fixes that one and cannot fix this one.
        ExitCode::VerificationNotPossible => Verdict::Unverifiable,
        // Everything else — an outage, a permission change, a network path that
        // stayed broken past the retry budget — is an availability problem.
        _ => Verdict::Unreadable,
    }
}

/// The remediation hint that fits a verdict.
fn hint_for(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Ok | Verdict::Corrupt => INTEGRITY_FAILURE_HINT,
        Verdict::Missing => {
            "The index is a rebuildable cache: `dctl index rebuild` rescans object \
             headers and reconciles it with what the provider actually holds."
        }
        Verdict::Unreadable => {
            // Not "retries were exhausted". `ExitCode::LinkSilent` reaches this
            // verdict through `classify`'s wildcard and its retries were
            // emphatically **not** exhausted — the run stopped early, because a
            // link answering nothing cannot be persuaded by asking again. A
            // hint that described the wrong work would be the same class of
            // false report the retry hint itself was written to remove.
            "The object could not be read. Check connectivity and provider \
             status, then run the command again — nothing about the stored data \
             has changed."
        }
        Verdict::Unverifiable => {
            "Nothing is known to be wrong with these objects and nothing is known to be \
             right. Store them in a vault (`dctl init`), or re-upload them through a \
             path that records a whole-object digest, if they have to be provable."
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_verdict_has_a_distinct_slug() {
        let verdicts = [
            Verdict::Ok,
            Verdict::Corrupt,
            Verdict::Missing,
            Verdict::Unreadable,
            Verdict::Unverifiable,
        ];
        for (index, verdict) in verdicts.iter().enumerate() {
            assert!(!verdict.slug().is_empty());
            for other in &verdicts[index + 1..] {
                assert_ne!(verdict.slug(), other.slug());
            }
        }
    }

    #[test]
    fn corruption_exits_twenty_one_and_nothing_else_does() {
        // The contract scripts branch on: only a failed authentication is 21.
        assert_eq!(Verdict::Corrupt.exit_code(), ExitCode::IntegrityFailure);
        assert_eq!(Verdict::Corrupt.exit_code().as_i32(), 21);
        assert_eq!(Verdict::Missing.exit_code(), ExitCode::FileNotFound);
        assert_eq!(Verdict::Unreadable.exit_code(), ExitCode::TemporaryError);
        assert_eq!(Verdict::Ok.exit_code(), ExitCode::Success);
        assert_eq!(
            Verdict::Unverifiable.exit_code(),
            ExitCode::VerificationNotPossible
        );
        assert_eq!(Verdict::Unverifiable.exit_code().as_i32(), 27);
    }

    #[test]
    fn an_object_that_could_not_be_checked_is_a_failure_and_is_not_corruption() {
        // Both halves matter. `ok` is what it used to be, and `corrupt` is the
        // over-correction: one claims a check that never happened, the other
        // claims damage that has not been shown.
        assert!(Verdict::Unverifiable.is_failure());
        assert!(!Verdict::Unverifiable.is_corruption());
        assert_ne!(Verdict::Unverifiable.exit_code(), ExitCode::Success);
        assert_ne!(
            Verdict::Unverifiable.exit_code(),
            ExitCode::IntegrityFailure
        );
    }

    #[test]
    fn anything_that_looked_at_the_bytes_outranks_a_check_that_could_not_be_made() {
        // A run holding one corrupt object and nine unverifiable ones exits on
        // the corruption; the reverse would bury the only finding that means
        // data is gone.
        assert_eq!(
            Verdict::Unverifiable.worse(Verdict::Corrupt),
            Verdict::Corrupt
        );
        assert_eq!(
            Verdict::Unverifiable.worse(Verdict::Missing),
            Verdict::Missing
        );
        assert_eq!(
            Verdict::Unverifiable.worse(Verdict::Unreadable),
            Verdict::Unreadable
        );
        assert_eq!(
            Verdict::Ok.worse(Verdict::Unverifiable),
            Verdict::Unverifiable
        );
    }

    #[test]
    fn a_run_of_unverifiable_objects_does_not_claim_they_are_damaged() {
        let error = failure(Verdict::Unverifiable, 4, 4).expect("a failure is produced");
        assert_eq!(error.code(), ExitCode::VerificationNotPossible);
        assert!(error.message().contains("4 of 4"));
        assert!(
            !error.message().contains("NOT served"),
            "nothing was withheld and nothing was found bad: {}",
            error.message()
        );
        assert!(error.hint().is_some());
    }

    #[test]
    fn corruption_outranks_every_other_verdict() {
        assert_eq!(
            Verdict::Unreadable.worse(Verdict::Corrupt),
            Verdict::Corrupt
        );
        assert_eq!(Verdict::Corrupt.worse(Verdict::Missing), Verdict::Corrupt);
        assert_eq!(
            Verdict::Missing.worse(Verdict::Unreadable),
            Verdict::Missing
        );
        assert_eq!(Verdict::Ok.worse(Verdict::Ok), Verdict::Ok);
        // Reduction over a whole run must reach the same answer either way round.
        assert_eq!(
            Verdict::Missing.worse(Verdict::Corrupt),
            Verdict::Corrupt.worse(Verdict::Missing)
        );
    }

    #[test]
    fn a_clean_run_produces_no_error() {
        assert!(failure(Verdict::Ok, 0, 100).is_none());
        // A worst-verdict that is a failure but with nothing counted is still a
        // clean run — the tally, not the enum, decides.
        assert!(failure(Verdict::Corrupt, 0, 100).is_none());
    }

    #[test]
    fn a_corrupt_run_says_the_data_was_not_served() {
        let error = failure(Verdict::Corrupt, 3, 120).expect("damage must produce an error");
        assert_eq!(error.code(), ExitCode::IntegrityFailure);
        assert!(error.message().contains("3 of 120"));
        assert!(
            error.message().contains(INTEGRITY_NOT_SERVED_NOTICE),
            "got: {}",
            error.message()
        );
        assert!(error.hint().is_some());
    }

    #[test]
    fn availability_problems_are_not_reported_as_corruption() {
        // An outage must not send someone hunting for bit rot.
        let error = failure(Verdict::Unreadable, 2, 10).unwrap();
        assert_eq!(error.code(), ExitCode::TemporaryError);
        assert!(!error.message().contains(INTEGRITY_NOT_SERVED_NOTICE));
        assert!(!Verdict::Unreadable.is_corruption());
        assert!(Verdict::Unreadable.is_failure());
    }

    #[test]
    fn a_single_corrupt_object_fails_the_same_way_as_a_run() {
        let error = object_failure("photos/a.jpg", Verdict::Corrupt);
        assert_eq!(error.code(), ExitCode::IntegrityFailure);
        assert!(error.message().contains("photos/a.jpg"));
        assert!(error.message().contains(INTEGRITY_NOT_SERVED_NOTICE));
    }

    #[test]
    fn a_failed_read_is_classified_by_what_it_means_for_the_data() {
        assert_eq!(
            classify(&CliError::new(ExitCode::IntegrityFailure, "x")),
            Verdict::Corrupt
        );
        assert_eq!(
            classify(&CliError::new(ExitCode::ChecksumMismatch, "x")),
            Verdict::Corrupt
        );
        assert_eq!(
            classify(&CliError::new(ExitCode::FileNotFound, "x")),
            Verdict::Missing
        );
        // An outage is availability, not damage.
        assert_eq!(
            classify(&CliError::new(ExitCode::TemporaryError, "x")),
            Verdict::Unreadable
        );
        assert_eq!(
            classify(&CliError::new(ExitCode::Uncategorised, "x")),
            Verdict::Unreadable
        );
    }

    #[test]
    fn verdicts_serialise_as_their_slugs() {
        let json = serde_json::to_string(&Verdict::Corrupt).unwrap();
        assert_eq!(json, format!("\"{VERDICT_CORRUPT}\""));
    }
}
