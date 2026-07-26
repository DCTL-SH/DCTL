//! What a single object's integrity check concluded, and how a run that found
//! damage ends.
//!
//! The important rule this file exists to enforce is `PLAN.md` §6's read-path
//! guarantee: *an integrity failure is loud, never served as data*. A corrupt
//! object must therefore always end the process with
//! [`ExitCode::IntegrityFailure`] and a message that says, in words, that the
//! bytes were not handed over — never with the generic bucket, and never with a
//! wording that leaves room for "maybe some of it came through".
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

// Some of what follows is not reachable from this build's `run` body: the engine
// has no entry point yet for the step that would call it (see the command's
// module documentation). It is written and unit-tested now, with the tests that
// pin its contract, rather than left until the engine lands — a machine-readable
// output format that first appears on the day it is needed is a format nobody
// reviewed.
#![allow(dead_code)]

use crate::constants::{
    INTEGRITY_FAILURE_HINT, INTEGRITY_NOT_SERVED_NOTICE, VERDICT_CORRUPT, VERDICT_MISSING,
    VERDICT_OK, VERDICT_UNREADABLE,
};
use crate::error::CliError;
use crate::exit::ExitCode;

/// The conclusion for one object.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Verdict {
    /// Decrypted, authenticated, and matched the hash recorded in the index.
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
            Self::Unreadable => 1,
            Self::Missing => 2,
            Self::Corrupt => 3,
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
            // The whole reason code 21 exists (`PLAN.md` §7).
            Self::Corrupt => ExitCode::IntegrityFailure,
            Self::Missing => ExitCode::FileNotFound,
            Self::Unreadable => ExitCode::TemporaryError,
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
    };

    Some(CliError::new(worst.exit_code(), message).with_hint(hint_for(worst)))
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
    };
    CliError::new(verdict.exit_code(), message).with_hint(hint_for(verdict))
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
            "Retries were exhausted. Check connectivity and provider status, then \
             run the command again — nothing about the stored data has changed."
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
    fn verdicts_serialise_as_their_slugs() {
        let json = serde_json::to_string(&Verdict::Corrupt).unwrap();
        assert_eq!(json, format!("\"{VERDICT_CORRUPT}\""));
    }
}
