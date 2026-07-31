//! `--max-duration`: the one deadline that is about the **run**.
//!
//! # The entry this closes
//!
//! `HANDOVER.md` §11.2, and it is the entry that says a flag did not bound what
//! it claimed to bound. `--timeout` is exact — a black-holed B2 request fails at
//! **30 s** under `--timeout 30`, to the second — and it bounds *one attempt*,
//! which is rclone's meaning of the same flag (`fs/config.go:122`,
//! `Help: "IO idle timeout"`). What it does not do is end the run. Measured in
//! §32.9: a 160 MiB upload with `--timeout 30 --retries 1` had **not ended
//! 943.6 s after the route was cut**, and an `sftp` copy had not ended after
//! 601 s, because `--timeout` × six attempts × several distinct requests ×
//! `--retries` is a product an operator cannot compute and no flag stated.
//!
//! An operator sizing a backup window needs one number that means *be finished
//! by then*. This module is that number.
//!
//! # It is emphatically not `--timeout` with a different name
//!
//! [`super::watch`] exists to keep the two apart and the distinction is the
//! whole design. An **inactivity** deadline follows the last byte, so a 4 GiB
//! restore over a slow link runs for hours and never approaches it; a
//! **duration** deadline is a wall clock and would destroy exactly that
//! transfer. Making `--timeout` behave like this type would be a worse defect
//! than the one being fixed, which is why they are two flags, two types and two
//! numbers.
//!
//! # What happens when it fires
//!
//! The run stops — hard. rclone's `--max-duration` defaults to
//! `--cutoff-mode hard` and implements it by giving the transfer context a
//! deadline (`fs/sync/sync.go:203-205`, `context.WithDeadline`), which cancels
//! whatever is in flight. DCTL does the same thing in the Rust idiom: the
//! future is dropped, which is what cancels it, at three depths that each cover
//! what the ones below cannot —
//!
//! | depth | what it stops | why the depth below is not enough |
//! |---|---|---|
//! | [`RunDeadline::guard`] around a request | the in-flight request | a request that never answers is never *observed* to be late by anything above it |
//! | [`crate::retry::driver`] | the next attempt, and the backoff before it | a cancelled request classifies as transient, and six attempts of it is the §32.9 arithmetic |
//! | the process's own `select!` | everything, including work no future owns | a blocking read, a `spawn_blocking`, an `ssh` child |
//!
//! Nothing is left half-written by the cut. A verified write does not commit
//! unless the stored bytes match, so an abandoned object was never an object;
//! what a cut transfer leaves is staging debris or an unfinished multipart
//! upload, and `dctl cleanup` reclaims both.

use std::future::Future;
use std::time::{Duration, Instant};

/// How much of the run's own deadline is left.
///
/// Three states rather than an `Option<Duration>`, because the two answers that
/// an `Option` would collapse are the two that must never be confused: *there
/// is no deadline* and *the deadline has passed*. A `None` meaning either one is
/// how a bound becomes a no-op — read as "unlimited" at the call site that
/// should have stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Left {
    /// No `--max-duration` was set. The run is bounded by nothing.
    Unbounded,
    /// This much of the operator's window remains.
    Remaining(Duration),
    /// The window is over.
    Spent,
}

/// The run reached the deadline the operator set for it.
///
/// Its own type rather than a formatted string, for the reason
/// [`super::watch::Expired`] gives: the call site knows what it was doing and a
/// message assembled here could only be matched on later by searching its words.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Exceeded {
    /// The window the operator asked for, so the report quotes their number
    /// rather than one DCTL chose.
    pub limit: Duration,
}

impl Exceeded {
    /// The error an operator reads.
    #[must_use]
    pub fn into_store_error(self) -> crate::error::StoreError {
        crate::error::StoreError::RunDeadline { limit: self.limit }
    }
}

impl std::fmt::Display for Exceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Names the flag and the number, because the operator's next question is
        // which dial to move — the same rule `super::watch::Expired` follows.
        write!(
            f,
            "the run reached its own deadline (--max-duration {}s)",
            self.limit.as_secs()
        )
    }
}

/// When a bounded run has to be over, and the number that said so.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Bound {
    /// What the operator typed, kept for the message.
    limit: Duration,
    /// The instant the run must not outlive.
    ends_at: Instant,
}

/// The instant this run must be finished by, or nothing at all.
///
/// `Copy` and passed by value, like [`super::Deadlines`] which carries it: a
/// backend that needs it holds its own, and nothing can move a live run's
/// deadline out from under the layer that is enforcing it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct RunDeadline(Option<Bound>);

impl RunDeadline {
    /// A run nothing bounds — what an absent `--max-duration` means, and what
    /// rclone's absent `--max-duration` means too (`fs/config.go:361`,
    /// `Default: time.Duration(0)`).
    #[must_use]
    pub const fn unbounded() -> Self {
        Self(None)
    }

    /// A run of at most `limit`, starting now.
    ///
    /// Read once, at the top of the process, and carried down — never
    /// recomputed. A deadline re-derived per file would be a deadline each file
    /// got in full, which is the shape of the defect this module exists to
    /// remove.
    ///
    /// A `limit` so large that the monotonic clock cannot express the end of it
    /// is treated as no deadline at all. That is the honest reading: a bound
    /// beyond the representable future is not a bound, and the alternative —
    /// saturating to some instant — would end a run at a moment nobody asked
    /// for.
    #[must_use]
    pub fn starting_now(limit: Option<Duration>) -> Self {
        Self::starting_at(Instant::now(), limit)
    }

    /// The same, from an explicit start.
    ///
    /// For the tests that must place a deadline in the past without sleeping
    /// through it, and for a caller that captured the start before this type
    /// existed in its call chain.
    #[must_use]
    pub fn starting_at(start: Instant, limit: Option<Duration>) -> Self {
        match limit {
            None => Self::unbounded(),
            Some(limit) => Self(
                start
                    .checked_add(limit)
                    .map(|ends_at| Bound { limit, ends_at }),
            ),
        }
    }

    /// The window the operator asked for, when they asked for one.
    #[must_use]
    pub const fn limit(&self) -> Option<Duration> {
        match self.0 {
            Some(bound) => Some(bound.limit),
            None => None,
        }
    }

    /// Whether this run is bounded at all.
    #[must_use]
    pub const fn is_bounded(&self) -> bool {
        self.0.is_some()
    }

    /// How much of the window is left, read from the clock now.
    #[must_use]
    pub fn left(&self) -> Left {
        self.left_at(Instant::now())
    }

    /// The same, at an explicit reading of the clock.
    ///
    /// For the same reason [`starting_at`](Self::starting_at) exists, and for
    /// one more. The `remaining.is_zero()` arm below is reachable **only** when
    /// two reads of a monotonic clock return the identical instant, which on a
    /// nanosecond-resolution clock is a coincidence no test can arrange — so
    /// deleting that arm left `cargo test --workspace` entirely green, which is
    /// how it was found (`HANDOVER.md` §35.5). An argument that the arm cannot
    /// fire would have been wrong: it can, on a coarse clock, and this is the
    /// half of the run's deadline that decides whether an attempt is made.
    #[must_use]
    pub fn left_at(&self, now: Instant) -> Left {
        match self.0 {
            None => Left::Unbounded,
            Some(bound) => match bound.ends_at.checked_duration_since(now) {
                // `checked_duration_since` is `None` once the instant is behind
                // us, and zero is reported as `Spent` rather than as
                // `Remaining(0)`: a caller handed a wait of zero would arm a
                // timer that fires immediately, which is a slower way of saying
                // the same thing and one more place for the two to disagree.
                None => Left::Spent,
                Some(remaining) if remaining.is_zero() => Left::Spent,
                Some(remaining) => Left::Remaining(remaining),
            },
        }
    }

    /// The instant this run's window closes, when it has one.
    ///
    /// Only [`left_at`](Self::left_at)'s tests need it: it is the one reading of
    /// the clock at which the zero arm fires.
    #[cfg(test)]
    const fn ends_at(&self) -> Option<Instant> {
        match self.0 {
            Some(bound) => Some(bound.ends_at),
            None => None,
        }
    }

    /// Whether the window is over.
    #[must_use]
    pub fn is_spent(&self) -> bool {
        matches!(self.left(), Left::Spent)
    }

    /// The failure to report when the window is over, and nothing while it is
    /// not.
    ///
    /// Returned rather than constructed at each call site so the number an
    /// operator reads is the number they set, everywhere, and so a caller cannot
    /// report a deadline that has not been reached.
    #[must_use]
    pub fn exceeded(&self) -> Option<Exceeded> {
        match (self.0, self.left()) {
            (Some(bound), Left::Spent) => Some(Exceeded { limit: bound.limit }),
            _ => None,
        }
    }

    /// `patience`, shortened to what is left of the run.
    ///
    /// The arithmetic that stops a wait outliving the window it is inside.
    /// `dctl_store::retry` sleeps between attempts, and a backoff of two minutes
    /// begun with thirty seconds left is two minutes of a run that was supposed
    /// to be over — the §32.9 shape in miniature. [`None`] means *no wait at
    /// all is bounded*, which happens only when the caller had no patience of
    /// its own and the run has no deadline either.
    #[must_use]
    pub fn shorten(&self, patience: Option<Duration>) -> Option<Duration> {
        match (patience, self.left()) {
            (_, Left::Spent) => Some(Duration::ZERO),
            (None, Left::Unbounded) => None,
            (Some(wait), Left::Unbounded) => Some(wait),
            (None, Left::Remaining(left)) => Some(left),
            (Some(wait), Left::Remaining(left)) => Some(wait.min(left)),
        }
    }

    /// Run `op`, abandoning it if the run's window closes first.
    ///
    /// # Cancellation
    ///
    /// On [`Exceeded`] the operation's future is **dropped**, which is how a
    /// Rust future is cancelled and is the whole point: the socket read that
    /// will never complete stops being awaited, the connection carrying it is
    /// dropped with it, and the run can end. It is the same act
    /// [`super::watch::IdleWatch::guard`] performs for `--timeout`, and it
    /// carries the same caveat — the far end has not forgotten the request, so a
    /// multiplexed session that has had a request cancelled under it must be
    /// discarded rather than reused.
    ///
    /// # The operation is always polled at least once
    ///
    /// Even when the deadline has already passed. `super::watch` records what
    /// happened the first time that rule was missing: a watch that had gone
    /// quiet before `guard` was called failed the operation *without polling it
    /// once*, and then reported that it had moved nothing — about work that had
    /// never started. An operation that is already complete must not be failed
    /// by a clock.
    ///
    /// # Errors
    ///
    /// [`Exceeded`] and nothing else. `op`'s own failures are returned as `op`
    /// produced them.
    pub async fn guard<F>(&self, op: F) -> Result<F::Output, Exceeded>
    where
        F: Future,
    {
        let Some(bound) = self.0 else {
            // Not "a very long sleep": an unbounded run gets no timer, no
            // wakeups and no arithmetic that could one day overflow into one.
            return Ok(op.await);
        };

        tokio::pin!(op);
        loop {
            // Read straight off the bound rather than through `left`, so the
            // arm for an unbounded run — which `bound` has already excluded —
            // does not have to be written as an unreachable case.
            let wait = match bound.ends_at.checked_duration_since(Instant::now()) {
                Some(remaining) if !remaining.is_zero() => remaining,
                // Zero, so the biased arm below still gets to poll the
                // operation before the deadline is allowed to decide.
                _ => Duration::ZERO,
            };

            tokio::select! {
                // Biased so the operation is polled first. Without it an
                // operation that completed in the same wakeup as the deadline
                // would be failed half the time by a coin toss — a flake that
                // appears only under load, which is the worst place to find one.
                biased;

                out = &mut op => return Ok(out),
                () = tokio::time::sleep(wait) => {
                    if wait.is_zero() {
                        // Polled, still not ready, and the window really is
                        // over. The only path to `Exceeded`, and reached only
                        // after the operation has had its turn.
                        return Err(Exceeded { limit: bound.limit });
                    }
                    // The clock reached the deadline. Round again so the branch
                    // above is the one that reports it, which keeps the "polled
                    // at least once at zero" rule in exactly one place.
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Short enough that the suite spends no real time on it, long enough that a
    /// loaded scheduler is not what decides the outcome.
    const WINDOW: Duration = Duration::from_millis(400);

    #[tokio::test]
    async fn an_unbounded_run_never_fires() {
        let deadline = RunDeadline::unbounded();
        assert!(!deadline.is_bounded());
        assert_eq!(deadline.left(), Left::Unbounded);
        assert_eq!(deadline.exceeded(), None);
        // Would expire immediately under any bounded deadline in this file.
        let out = deadline
            .guard(async {
                tokio::time::sleep(WINDOW).await;
                "arrived"
            })
            .await;
        assert_eq!(out, Ok("arrived"));
    }

    #[test]
    fn a_window_that_has_passed_is_spent_and_names_the_operators_number() {
        let deadline = RunDeadline::starting_at(Instant::now() - WINDOW * 2, Some(WINDOW));
        assert_eq!(deadline.left(), Left::Spent);
        assert!(deadline.is_spent());
        assert_eq!(deadline.exceeded(), Some(Exceeded { limit: WINDOW }));
    }

    #[test]
    fn a_window_with_nothing_left_is_spent_rather_than_open_with_zero() {
        // The arm two reads of a monotonic clock will not produce on this
        // machine, and the one that decides whether the next attempt is made.
        // `Left::Remaining(0)` reads as *open* to every caller: `is_spent` is
        // false, `exceeded` yields nothing, and `retry::driver` makes another
        // request for a run whose window has closed — which is §32.9's shape,
        // the run that continued 943.6 s past the cut.
        //
        // `shorten` is the other half and would go the same way: a backoff
        // shortened to `Some(0)` under `Spent` becomes `Some(wait.min(0))`, the
        // same number, only by accident rather than by rule.
        let deadline = RunDeadline::starting_now(Some(WINDOW));
        let ends_at = deadline.ends_at().expect("a bounded run has an end");
        assert_eq!(deadline.left_at(ends_at), Left::Spent);
        assert_eq!(
            deadline.left_at(ends_at - Duration::from_nanos(1)),
            Left::Remaining(Duration::from_nanos(1))
        );
        assert_eq!(deadline.left_at(ends_at + WINDOW), Left::Spent);
    }

    #[test]
    fn a_window_still_open_reports_what_is_left() {
        let deadline = RunDeadline::starting_now(Some(WINDOW));
        match deadline.left() {
            Left::Remaining(left) => assert!(left <= WINDOW && left > Duration::ZERO),
            other => panic!("a fresh window must have time left: {other:?}"),
        }
        assert!(!deadline.is_spent());
        assert_eq!(deadline.exceeded(), None);
    }

    #[tokio::test]
    async fn an_operation_that_never_answers_is_abandoned_at_the_deadline() {
        // The §32.9 shape: connected, silent, and without this it runs until
        // something else gives up.
        let deadline = RunDeadline::starting_now(Some(WINDOW));
        let started = Instant::now();
        let out = deadline
            .guard(async { std::future::pending::<()>().await })
            .await;
        assert_eq!(out, Err(Exceeded { limit: WINDOW }));
        assert!(
            started.elapsed() < WINDOW * 4,
            "it must end at the deadline, not merely eventually: {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn an_operation_that_has_already_finished_is_never_failed_by_the_clock() {
        // The rule `super::watch` learned the hard way: a deadline in the past
        // must not fail work that is already done, or the report describes a
        // stall that never happened.
        let deadline = RunDeadline::starting_at(Instant::now() - WINDOW * 2, Some(WINDOW));
        assert!(deadline.is_spent());
        assert_eq!(deadline.guard(async { 7 }).await, Ok(7));
    }

    #[test]
    fn a_wait_is_shortened_to_what_is_left_and_never_lengthened() {
        let open = RunDeadline::starting_now(Some(WINDOW));
        // A patience longer than the window is cut down to it…
        let shortened = open.shorten(Some(WINDOW * 10)).expect("a bounded run");
        assert!(shortened <= WINDOW);
        // …and one shorter than the window is left alone.
        assert_eq!(
            open.shorten(Some(Duration::from_millis(1))),
            Some(Duration::from_millis(1))
        );
        // An unbounded run does not shorten anything.
        let none = RunDeadline::unbounded();
        assert_eq!(none.shorten(Some(WINDOW)), Some(WINDOW));
        assert_eq!(none.shorten(None), None);
        // A spent window admits no wait at all.
        let spent = RunDeadline::starting_at(Instant::now() - WINDOW * 2, Some(WINDOW));
        assert_eq!(spent.shorten(Some(WINDOW)), Some(Duration::ZERO));
        assert_eq!(spent.shorten(None), Some(Duration::ZERO));
    }

    #[test]
    fn a_window_beyond_the_representable_future_is_no_window_at_all() {
        // Saturating would end the run at an instant nobody asked for; the
        // honest answer is that a bound nothing can express is not a bound.
        let absurd = RunDeadline::starting_now(Some(Duration::MAX));
        assert!(!absurd.is_bounded());
        assert_eq!(absurd.left(), Left::Unbounded);
    }

    #[test]
    fn the_failure_names_the_flag_and_the_number_the_operator_set() {
        let rendered = Exceeded {
            limit: Duration::from_secs(30),
        }
        .to_string();
        assert!(rendered.contains("--max-duration 30s"), "{rendered}");
    }
}
