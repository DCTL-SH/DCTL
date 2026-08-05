//! When the run stops asking a link that never answers.
//!
//! # The defect this closes
//!
//! *`--timeout` does not bound a run.* The flag itself is exact — a black-holed
//! request fails at **30 s** under `--timeout 30`, to the second — and it bounds
//! *one attempt*, which is rclone's meaning of the same flag: an IO idle
//! timeout. What was missing is that nothing bounded the number of attempts a
//! **run** could spend discovering the same silence.
//!
//! [`super::run`] answered the operator's *need* and left this arithmetic where
//! it was, stating in `--help` that the cost of a dead link is *"a product this
//! flag does not know"*. That sentence was true, and the reason it was true is
//! the defect: the product is
//!
//! ```text
//!   --timeout  ×  attempts per request  ×  DISTINCT REQUESTS  ×  --retries
//! ```
//!
//! and the third factor is unbounded. A copy makes as many requests as it makes
//! — one `b2_authorize_account`, one `b2_list_buckets`, one
//! `b2_start_large_file`, one `b2_upload_part` per part, one
//! `b2_cancel_large_file` — and *each* of them runs a full six-attempt schedule
//! against a link that has already proved silent. That is why the same command,
//! against the same fault, measured **46.3 s**, **136.6 s** and **288.7 s** on
//! three runs: the answer depended on which request the cut happened to land on
//! and how many were left to make.
//!
//! # What this bounds, and what it deliberately does not
//!
//! One number, counted **for the whole run** rather than per request:
//! consecutive attempts that got **no answer at all**. Reset by anything that
//! answers — a success, a status, a protocol reply, an errno. Consulted before
//! an attempt is begun.
//!
//! The limit is [`UNANSWERED_ATTEMPT_LIMIT`], which is
//! **not smaller than the longest single schedule any layer runs** — a
//! compile-time assertion in [`super::constants`] holds that, and it is the
//! property that makes this change safe. One operation's own retries are
//! therefore never cut short: the first request to meet a dead link spends its
//! whole schedule exactly as before, and it is the *second* request that is
//! refused. Nothing that works today can fail because of this, because six
//! consecutive attempts that got nothing back is a dead link by any reading.
//!
//! What is removed is precisely the `DISTINCT REQUESTS` factor, and with it the
//! reason the product could not be stated. The whole-run cost of a link that
//! never answers becomes
//!
//! ```text
//!   --timeout  ×  attempts
//! ```
//!
//! two numbers an operator can see, which `--timeout`'s `--help` now states.
//!
//! # It is not a wall clock, and that distinction is the whole design
//!
//! [`super::run`] is the wall clock and stays the flag that bounds a *healthy
//! but slow* run. This counts attempts, not seconds, so a transfer that is
//! moving cannot reach it however long it runs — every frame that moves resets
//! the count through the same [`Activity`](super::Activity) the watchdog reads.
//! Making `--timeout` a stopwatch would destroy a 4 GiB restore over a slow
//! uplink at minute five while reporting a network fault that did not happen,
//! which is a worse defect than the one being fixed, and is why that reading
//! was refused.
//!
//! # `--timeout 0` is unbounded, and it has to be
//!
//! Zero means *wait as long as it takes*, which is rclone's meaning too. An
//! operator who has said they will wait forever for a quiet link has also said
//! they want it asked again, so a run with no idle deadline has no stall limit
//! either. [`RunStall::unbounded`] is how that is spelled, out loud, rather
//! than by a limit nobody notices is absent.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use super::constants::UNANSWERED_ATTEMPT_LIMIT;

/// The run stopped asking, because a whole schedule of attempts got nothing
/// back.
///
/// Its own type rather than a formatted string, for the reason
/// [`super::watch::Expired`] and [`super::run::Exceeded`] both give: the call
/// site knows which backend it is, and a message assembled here could only be
/// matched on later by searching its words.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stalled {
    /// Consecutive attempts that got no answer — the operator's own arithmetic,
    /// so the report multiplies out to a number they can check.
    pub attempts: u32,
    /// The `--timeout` those attempts were each bounded by.
    pub idle: Duration,
}

impl Stalled {
    /// The error an operator reads.
    ///
    /// [`crate::error::StoreError::Stalled`], which
    /// [`crate::retry::observed`] classifies as terminal — the same treatment
    /// [`super::run::Exceeded`] gets and for the same reason. Handing it back as
    /// a `Transport` would put "worth another attempt" on the one conclusion
    /// this type exists to reach, and every layer above would spend the schedule
    /// that had just been declared spent.
    ///
    /// No backend is named, unlike [`super::watch::Expired::into_store_error`]
    /// beside it: this count is the run's and spans every request it made, to
    /// either end of a copy, so naming one remote would be a claim the counter
    /// does not hold. See the variant's own documentation.
    #[must_use]
    pub fn into_store_error(self) -> crate::error::StoreError {
        crate::error::StoreError::Stalled {
            attempts: self.attempts,
            idle: self.idle,
        }
    }
}

/// The run's count of consecutive attempts that got no answer.
#[derive(Debug)]
struct Stall {
    /// `--timeout`, carried for the report so it quotes the operator's number.
    idle: Duration,
    /// How many in a row is too many.
    limit: u32,
    /// The live count.
    ///
    /// [`Ordering::Relaxed`], for the reason [`super::activity`] gives about the
    /// clock beside it: no other memory's visibility is being ordered by this
    /// value, and the only reader asks "have we reached the limit?" about a
    /// number that changes at most once per network attempt. The cost of a
    /// stale read is at most one further attempt, and this build's executor is
    /// sequential (`--transfers 1`) so there is at most one attempt in flight
    /// to be stale about.
    unanswered: AtomicU32,
}

/// How many attempts in a row this run will let go unanswered, or nothing at
/// all.
///
/// `Clone` rather than `Copy` — unlike [`super::run::RunDeadline`] beside it —
/// because this one is *state* and not an instant: every layer that counts must
/// count into the same cell, which is the entire difference between bounding a
/// run and bounding a request. It is the reason [`super::Deadlines`] is `Clone`.
#[derive(Clone, Debug, Default)]
pub struct RunStall(Option<Arc<Stall>>);

impl RunStall {
    /// A run nothing stops asking — what `--timeout 0` means, and what every
    /// caller that has no idle deadline to derive a limit from gets.
    #[must_use]
    pub const fn unbounded() -> Self {
        Self(None)
    }

    /// The limit a run with this `--timeout` gets.
    ///
    /// [`None`] — `--timeout 0` — is unbounded, deliberately: see the module
    /// documentation.
    #[must_use]
    pub fn from_idle(idle: Option<Duration>) -> Self {
        match idle {
            None => Self::unbounded(),
            Some(idle) => Self(Some(Arc::new(Stall {
                idle,
                limit: UNANSWERED_ATTEMPT_LIMIT,
                unanswered: AtomicU32::new(0),
            }))),
        }
    }

    /// Record that an attempt got an answer — any answer.
    ///
    /// A success, a status, a protocol reply, an errno: all of them prove the
    /// far end is there, which is the only question this counter asks. Called
    /// on every outcome that is not silence, so the count means *consecutive*
    /// and never *cumulative* — a run that fails one request in ten and
    /// completes the rest must never accumulate its way into giving up.
    pub fn answered(&self) {
        if let Some(stall) = &self.0 {
            stall.unanswered.store(0, Ordering::Relaxed);
        }
    }

    /// Record that an attempt got nothing back, and return the new count.
    pub fn unanswered(&self) -> u32 {
        self.0.as_ref().map_or(0, |stall| {
            stall
                .unanswered
                .fetch_add(1, Ordering::Relaxed)
                .saturating_add(1)
        })
    }

    /// Whether this run has stopped asking, and what to report if it has.
    #[must_use]
    pub fn exhausted(&self) -> Option<Stalled> {
        let stall = self.0.as_ref()?;
        let attempts = stall.unanswered.load(Ordering::Relaxed);
        (attempts >= stall.limit).then_some(Stalled {
            attempts,
            idle: stall.idle,
        })
    }

    /// Whether anything bounds this run's asking at all.
    ///
    /// Read by the tests that have to prove the *unbounded* direction really is
    /// unbounded, rather than proving it by not observing a limit in a test too
    /// short to reach one.
    #[must_use]
    pub const fn is_bounded(&self) -> bool {
        self.0.is_some()
    }

    /// The limit, for the tests and for the report that states the product.
    #[must_use]
    pub fn limit(&self) -> Option<u32> {
        self.0.as_ref().map(|stall| stall.limit)
    }

    /// The live count, for the tests that must see it move rather than infer it.
    #[must_use]
    pub fn count(&self) -> u32 {
        self.0
            .as_ref()
            .map_or(0, |stall| stall.unanswered.load(Ordering::Relaxed))
    }
}

/// Two stalls are equal when they were **configured** the same, not when they
/// have counted the same.
///
/// [`super::Deadlines`] derives `PartialEq` and its tests compare two of them to
/// assert what a pair of flags produced. The live count is state the run writes
/// during the run; folding it into identity would make those assertions depend
/// on how much work had happened, which is not what any of them are about.
impl PartialEq for RunStall {
    fn eq(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (None, None) => true,
            (Some(a), Some(b)) => a.idle == b.idle && a.limit == b.limit,
            _ => false,
        }
    }
}

impl Eq for RunStall {}

#[cfg(test)]
mod tests {
    use super::*;

    const IDLE: Duration = Duration::from_secs(30);

    fn bounded() -> RunStall {
        RunStall::from_idle(Some(IDLE))
    }

    #[test]
    fn a_fresh_run_has_not_stalled() {
        let stall = bounded();
        assert!(stall.is_bounded());
        assert_eq!(stall.count(), 0);
        assert_eq!(stall.exhausted(), None);
    }

    #[test]
    fn the_limit_is_reached_only_at_the_limit() {
        // The property that makes this change safe: one operation's own
        // schedule is never cut short, because the limit is not smaller than
        // the longest schedule any layer runs. The attempt *below* the limit
        // must still be allowed.
        let stall = bounded();
        for _ in 1..UNANSWERED_ATTEMPT_LIMIT {
            stall.unanswered();
            assert_eq!(
                stall.exhausted(),
                None,
                "an operation's own schedule was cut short at {} of {UNANSWERED_ATTEMPT_LIMIT}",
                stall.count()
            );
        }
        stall.unanswered();
        assert_eq!(
            stall.exhausted(),
            Some(Stalled {
                attempts: UNANSWERED_ATTEMPT_LIMIT,
                idle: IDLE,
            })
        );
    }

    #[test]
    fn any_answer_at_all_puts_the_whole_count_back() {
        // "Consecutive", not "cumulative". A run that fails one request in ten
        // and completes the rest must never accumulate its way into giving up,
        // which is the false-failure this counter would otherwise introduce.
        let stall = bounded();
        for _ in 0..(UNANSWERED_ATTEMPT_LIMIT * 4) {
            for _ in 1..UNANSWERED_ATTEMPT_LIMIT {
                stall.unanswered();
            }
            stall.answered();
            assert_eq!(stall.count(), 0);
            assert_eq!(stall.exhausted(), None);
        }
    }

    #[test]
    fn a_run_with_no_idle_deadline_is_never_stopped() {
        // `--timeout 0` is "wait as long as it takes", and an operator who said
        // that has also said they want it asked again.
        let stall = RunStall::from_idle(None);
        assert!(!stall.is_bounded());
        assert_eq!(stall.limit(), None);
        for _ in 0..(UNANSWERED_ATTEMPT_LIMIT * 10) {
            stall.unanswered();
            assert_eq!(stall.exhausted(), None);
        }
        assert_eq!(stall.count(), 0);
    }

    #[test]
    fn the_count_is_shared_by_every_holder_of_the_handle() {
        // The whole point, and the reason this type is `Clone` and not `Copy`:
        // the two retry layers count into the same cell. If they did not, B2's
        // inner schedule and the outer decorator would each have their own six,
        // which is the arithmetic being removed rather than a bound on it.
        let first = bounded();
        let second = first.clone();
        for _ in 0..UNANSWERED_ATTEMPT_LIMIT {
            second.unanswered();
        }
        assert!(
            first.exhausted().is_some(),
            "the count did not reach the other handle"
        );
        first.answered();
        assert_eq!(
            second.count(),
            0,
            "the reset did not reach the other handle"
        );
    }

    #[test]
    fn the_report_quotes_the_operators_own_number() {
        // The report is the whole product of a bound. An operator reading "gave
        // up" learns nothing they can act on; one reading their own
        // `--timeout 30` back, multiplied by the attempts it was spent on, knows
        // exactly which dial to move.
        let stalled = Stalled {
            attempts: UNANSWERED_ATTEMPT_LIMIT,
            idle: IDLE,
        };
        let rendered = stalled.into_store_error().to_string();
        assert!(rendered.contains("--timeout 30s"), "{rendered}");
        assert!(
            rendered.contains(&UNANSWERED_ATTEMPT_LIMIT.to_string()),
            "{rendered}"
        );
    }

    #[test]
    fn identity_is_the_configuration_and_not_the_counting() {
        // `Deadlines` derives `PartialEq` and its tests compare two of them to
        // assert what a pair of flags produced. A count folded into identity
        // would make those assertions depend on how much work had happened.
        let first = bounded();
        let second = bounded();
        assert_eq!(first, second);
        first.unanswered();
        assert_eq!(first, second, "the live count is state, not identity");
        assert_ne!(first, RunStall::unbounded());
        assert_eq!(RunStall::unbounded(), RunStall::unbounded());
        assert_ne!(first, RunStall::from_idle(Some(IDLE * 2)));
    }
}
