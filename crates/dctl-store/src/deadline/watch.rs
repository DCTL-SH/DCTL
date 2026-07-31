//! The watchdog: give up on an operation that has stopped moving bytes.
//!
//! # The distinction this module exists to keep
//!
//! `--timeout` is an **inactivity** deadline, not a deadline on the operation.
//! rclone is explicit about it in the flag's own help — `"IO idle timeout"`,
//! `fs/config.go:122` — and implements it by re-arming a socket deadline after
//! every successful read and write that moved a byte
//! (`fs/fshttp/dialer.go:101-127`). Getting that backwards is not a small error:
//! a 4 GiB restore over a domestic uplink takes hours, and a five-minute
//! *operation* deadline would destroy it at minute five, every time, while
//! reporting a network fault that did not happen.
//!
//! So the shape here is a loop rather than a `tokio::time::timeout`:
//!
//! ```text
//!   sleep until (last progress + idle)
//!       │
//!       ├── the operation finished first  ──▶  its result, untouched
//!       │
//!       └── the sleep finished first
//!               │
//!               ├── something moved while we slept ──▶ sleep again, from there
//!               └── nothing moved                  ──▶ Expired
//! ```
//!
//! The re-check after waking is the whole mechanism. It is what makes the
//! deadline follow the last byte instead of the first.
//!
//! # What counts as progress
//!
//! Whatever touches the [`Activity`] this watch holds. For an HTTP request body
//! that is hyper taking the next frame ([`super::http`]); for a response it is a
//! chunk arriving; for SFTP it is a protocol operation completing. Each of those
//! is documented where it is written, including how closely it tracks the wire —
//! because "a byte moved" is a claim, and a claim in this project carries its
//! own evidence.
//!
//! # The other deadline this watch also has to honour
//!
//! `--max-duration` ([`super::run`]) is a wall clock on the whole run, and it
//! ends every operation in flight when it fires. It is enforced *here* as well
//! as at the two layers above because this is the only layer that holds the
//! request's own future: nothing above can cancel a read that never returns, it
//! can only stop waiting for the layer that is waiting for it.
//!
//! The two are kept apart in the report, not merged into "timed out". They send
//! an operator to opposite places — one says the link went quiet, the other says
//! the window you gave me is over — and only one of them is worth another
//! attempt.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use super::activity::Activity;
use super::run::RunDeadline;

/// An operation this run stopped waiting for, and which of the two deadlines
/// decided it.
///
/// Its own type rather than a formatted string, for the reason
/// [`crate::retry::observed`] gives about every other classification in this
/// crate: the call site that turns this into a [`StoreError`](crate::StoreError)
/// knows which backend it is and what it was doing, and a message assembled here
/// could only be matched on later by searching its words.
///
/// An enum rather than one struct with a flag, because the two are not degrees
/// of the same thing. One is *transient by definition* — a link that went quiet
/// may not be quiet on another connection — and the other is *terminal by
/// definition*: no number of attempts gives back a window that has closed.
/// Retrying the second is the §32.9 defect written down.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expired {
    /// `--timeout`: nothing moved for as long as the operator was willing to
    /// wait.
    Idle {
        /// The operator's own `--timeout`, so the report quotes the number they
        /// set rather than one DCTL chose.
        idle: Duration,
    },
    /// `--max-duration`: the run's window closed while this operation was still
    /// in flight.
    Run {
        /// The operator's own `--max-duration`.
        limit: Duration,
    },
}

impl Expired {
    /// The error an operator reads, attributed to the backend that stopped.
    ///
    /// The two variants map to two different [`StoreError`](crate::StoreError)s
    /// and that is the whole reason the enum exists.
    ///
    /// [`Expired::Idle`] becomes
    /// [`StoreError::Transport`](crate::StoreError::Transport), deliberately not
    /// a variant of its own: "nothing answered" is exactly what a timeout
    /// observed, it is what that variant already means, and it is what
    /// [`crate::retry::observed`] already classifies as worth another attempt. A
    /// stall on one connection is the textbook case for trying again on another
    /// — which is what makes the re-dial in [`crate::sftp`] the other half of
    /// that feature rather than a separate one.
    ///
    /// [`Expired::Run`] becomes
    /// [`StoreError::RunDeadline`](crate::StoreError::RunDeadline), which
    /// [`crate::retry::observed`] classifies as terminal. Handing it back as a
    /// `Transport` would be worse than not having the flag: every layer above
    /// would read "worth another attempt" and spend the schedule the deadline
    /// had just ended.
    #[must_use]
    pub fn into_store_error(self, backend: &'static str) -> crate::error::StoreError {
        match self {
            Self::Idle { .. } => crate::error::StoreError::Transport {
                backend,
                detail: self.to_string(),
            },
            Self::Run { limit } => crate::error::StoreError::RunDeadline { limit },
        }
    }

    /// Whether it was the run's own window that closed, rather than the link
    /// going quiet.
    #[must_use]
    pub const fn is_run_deadline(&self) -> bool {
        matches!(self, Self::Run { .. })
    }
}

impl std::fmt::Display for Expired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Names the flag, because the operator's next question is what to change.
        match self {
            Self::Idle { idle } => write!(
                f,
                "no data moved for {:?} (--timeout {}s)",
                idle,
                idle.as_secs()
            ),
            Self::Run { limit } => write!(f, "{}", super::run::Exceeded { limit: *limit }),
        }
    }
}

/// One operation's inactivity deadline, and the clock it is measured against.
///
/// Created per operation rather than per backend: two requests in flight on one
/// backend are two independent claims about whether *that request* is moving,
/// and a shared clock would let a healthy download hold a dead upload open
/// indefinitely.
#[derive(Clone, Debug)]
pub struct IdleWatch {
    /// How long with no progress is too long. [`None`] disables the deadline
    /// entirely — see [`super::constants::DISABLED_SECONDS`] — and is what an
    /// operator who asked for `--timeout 0` gets.
    idle: Option<Duration>,
    /// When the whole run has to be over — `--max-duration`.
    ///
    /// Shared with every other watch this run makes rather than per operation,
    /// which is the difference between it and [`IdleWatch::idle`]: an
    /// inactivity deadline is a fresh claim about each request, and a run's
    /// window is one instant the whole invocation is inside.
    run: RunDeadline,
    /// When this operation last moved bytes.
    activity: Arc<Activity>,
}

impl IdleWatch {
    /// A watch that gives up after `idle` without progress, when the run's own
    /// window closes, or never if neither is set.
    #[must_use]
    pub fn new(idle: Option<Duration>, run: RunDeadline) -> Self {
        Self {
            idle,
            run,
            activity: Activity::started(),
        }
    }

    /// The run's own deadline, as this watch received it.
    ///
    /// Read by the tests that have to prove one instant reached every watch
    /// rather than each watch inventing its own — the property the whole
    /// feature rests on, and one that cannot be observed from the outside any
    /// other way.
    #[must_use]
    pub const fn run_deadline(&self) -> RunDeadline {
        self.run
    }

    /// The clock, for whatever is going to carry the bytes.
    ///
    /// Handed out rather than written through this type, because the writer is
    /// usually somewhere this value is not: a request body owned by hyper, or a
    /// closure inside a read loop.
    #[must_use]
    pub fn activity(&self) -> Arc<Activity> {
        Arc::clone(&self.activity)
    }

    /// Record progress on this operation.
    pub fn touch(&self) {
        self.activity.touch();
    }

    /// Whether this watch will ever fire, on either deadline.
    ///
    /// Read by the tests that have to prove the *disabled* direction actually
    /// disables something, rather than proving it by not observing a timeout in
    /// a test too short to produce one.
    ///
    /// It answers for both deadlines and not only `--timeout`, because
    /// `--timeout 0 --max-duration 4h` is a pair an operator has a real reason
    /// to write — wait as long as it takes for a quiet link, but be finished by
    /// six — and a watch that called itself disarmed there would be one nothing
    /// could prove was armed.
    #[must_use]
    pub const fn is_armed(&self) -> bool {
        self.idle.is_some() || self.run.is_bounded()
    }

    /// How long this watch may sleep before one of its two deadlines is due,
    /// and which one that would be.
    ///
    /// [`None`] when neither deadline is set. A wait of zero means the deadline
    /// it names has already arrived — which is not the same as *fire now*; see
    /// [`IdleWatch::guard`], where an operation is polled once regardless.
    ///
    /// The nearer of the two wins, and it is recomputed every time round the
    /// loop rather than decided once: the idle half moves forward with every
    /// byte that arrives while the run's half does not, so which of them is
    /// nearer changes during a healthy transfer and has to be re-asked.
    fn due(&self) -> Option<(Duration, Expired)> {
        // `checked_sub` returning `None` means the clock is already past the
        // idle deadline. That is **not** a reason to return yet: this used to
        // be an early `return Err(Expired)` above the `select!`, so a watch that
        // had gone quiet before `guard` was called failed the operation
        // *without polling it once* — and then reported that it "moved nothing",
        // about work that had never started. The window is real wherever a watch
        // outlives the call that made it, which is by design:
        // `streaming::stream_to_file` takes a watch still running from the
        // request that produced its response, and every `--timeout` an operator
        // lowers narrows the gap further. It was found by two tests in this file
        // failing under a full `cargo test --workspace` on a loaded machine,
        // where the gap was nothing but scheduler latency.
        let idle = self.idle.map(|idle| {
            (
                idle.checked_sub(self.activity.quiet_for())
                    .unwrap_or(Duration::ZERO),
                Expired::Idle { idle },
            )
        });
        let run = self.run.limit().map(|limit| {
            (
                match self.run.left() {
                    super::run::Left::Remaining(left) => left,
                    // Unbounded cannot happen under a `Some(limit)`; spent is a
                    // wait of zero, for the same reason the idle half uses one.
                    _ => Duration::ZERO,
                },
                Expired::Run { limit },
            )
        });

        match (idle, run) {
            (None, None) => None,
            (Some(only), None) | (None, Some(only)) => Some(only),
            (Some(idle), Some(run)) => Some(if idle.0 <= run.0 { idle } else { run }),
        }
    }

    /// Run `op`, failing with [`Expired`] if nothing touches the clock for the
    /// configured span, or if the run's own window closes first.
    ///
    /// # Cancellation
    ///
    /// On [`Expired`] the operation's future is **dropped**, which is how a Rust
    /// future is cancelled and which is the point: the socket read that will
    /// never complete stops being awaited. What it is *not* is a promise that
    /// the far end forgot the request. For HTTP that does not matter — the
    /// connection is dropped with the future and a retry opens another. For
    /// SFTP it matters a great deal, because a cancelled request leaves a reply
    /// nobody will read on a multiplexed session, and that is exactly why
    /// [`crate::sftp`] discards the connection when this fires rather than
    /// reusing it. A timeout that silently left a poisoned session in the pool
    /// would turn one slow request into every later request failing.
    ///
    /// Both deadlines cancel the same way, and the difference is only in what is
    /// reported and what the layers above then do with it — try again, or stop.
    ///
    /// # Errors
    ///
    /// [`Expired`] and nothing else. `op`'s own failures are returned as `op`
    /// produced them, unwrapped and unclassified, because this layer has no
    /// opinion about them.
    pub async fn guard<F>(&self, op: F) -> Result<F::Output, Expired>
    where
        F: Future,
    {
        if self.due().is_none() {
            // Not merely "a very long sleep": an operator who asked for no
            // deadline gets no timer, no wakeups and no arithmetic that could
            // one day overflow into one.
            return Ok(op.await);
        }

        let op = op;
        tokio::pin!(op);

        loop {
            // A wait of zero, so the `biased` arm below still gets to run the
            // operation first. A ready operation wins even at a deadline already
            // passed, which is the whole of the correction recorded in `due`.
            let Some((wait, expired)) = self.due() else {
                // Unreachable from the check above — neither deadline can appear
                // or vanish mid-operation — and written as a return rather than
                // an unwrap because the alternative would be a fabricated
                // `Expired`, which is a report about a deadline nobody set.
                return Ok((&mut op).await);
            };

            tokio::select! {
                // Biased so the operation is polled first. Without it, an
                // operation that completed in the same wakeup as the deadline
                // would be failed half the time by a coin toss — a flake that
                // would appear only under load, which is the worst place to
                // find one.
                biased;

                out = &mut op => return Ok(out),
                () = tokio::time::sleep(wait) => {
                    if wait.is_zero() {
                        // Polled, still not ready, and the patience really is
                        // spent. This is the only path to `Expired`, and it is
                        // reached only after the operation has had its turn.
                        return Err(expired);
                    }
                    // The deadline elapsed. Whether that is a stall depends on
                    // what happened *while* we slept, which is why the loop goes
                    // round rather than failing here: a transfer that moved a
                    // frame two seconds ago has its full patience back. The
                    // run's own deadline never comes back, so the next round
                    // computes a wait of zero for it and the branch above fires.
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shorter than any real deadline, and sized so that a loaded test machine
    /// does not decide the outcome.
    ///
    /// That second half was already claimed at 200 ms, and it was measured
    /// false: under a full
    /// `cargo test --workspace` on a box already running a 6 GB transfer,
    /// `an_operation_that_finishes_is_untouched` and
    /// `a_slow_transfer_that_keeps_moving_never_expires` both failed on
    /// scheduler latency alone. The first of those turned out to be a real
    /// defect and is fixed (`an_operation_is_always_given_one_chance_to_run`);
    /// the second is genuinely a race against the clock, so the budget is what
    /// protects it, and the tests that step the clock now do so in eighths of
    /// this rather than halves — eight times the headroom per gap, and a shorter
    /// run than 200 ms bought.
    const IDLE: Duration = Duration::from_millis(400);

    /// One step of a transfer that is still moving: small enough against
    /// [`IDLE`] that a stalled scheduler, not a stalled transfer, cannot be what
    /// the assertion measures.
    const STEP: Duration = Duration::from_millis(IDLE.as_millis() as u64 / 8);

    #[tokio::test]
    async fn an_operation_that_finishes_is_untouched() {
        let watch = IdleWatch::new(Some(IDLE), RunDeadline::unbounded());
        let out = watch.guard(async { 7 }).await;
        assert_eq!(out, Ok(7));
    }

    #[tokio::test]
    async fn an_operation_is_always_given_one_chance_to_run() {
        // Found by the gate flaking under load, which is the only way this was
        // ever going to surface. `guard` reads the clock and returns `Expired`
        // *before* the `select!`, so a watch that was already quiet for longer
        // than the deadline fails the operation without polling it once — and
        // then reports that it "moved nothing", about work that never started.
        //
        // The window is real wherever a watch outlives the call that made it:
        // `streaming::stream_to_file` takes a watch "still running from the
        // request that produced `resp`", and every `--timeout` an operator
        // lowers narrows the gap further. Under a full `cargo test --workspace`
        // on a loaded machine the gap was scheduler latency alone, and two tests
        // in this file failed for it.
        let watch = IdleWatch::new(Some(IDLE), RunDeadline::unbounded());
        // Quiet for longer than the deadline before the operation is even
        // handed over — the shape of a caller that did some work in between.
        tokio::time::sleep(IDLE * 2).await;

        let out = watch.guard(async { 7 }).await;
        assert_eq!(
            out,
            Ok(7),
            "an operation that completes immediately was reported as a stall \
             without ever being polled"
        );
    }

    #[tokio::test]
    async fn an_operation_that_moves_nothing_expires() {
        let watch = IdleWatch::new(Some(IDLE), RunDeadline::unbounded());
        let out = guarded(&watch, async {
            // The black hole: connected, and silent forever.
            std::future::pending::<()>().await;
        })
        .await;
        assert_eq!(out, Err(Expired::Idle { idle: IDLE }));
    }

    #[tokio::test]
    async fn a_slow_transfer_that_keeps_moving_never_expires() {
        // The direction that matters more, and the one a stopwatch would fail.
        // This operation runs for five times the deadline and must not be
        // touched, because it is moving the whole way — which is precisely a
        // large object over a slow link.
        let watch = IdleWatch::new(Some(IDLE), RunDeadline::unbounded());
        let activity = watch.activity();
        let out = watch
            .guard(async {
                for _ in 0..10 {
                    tokio::time::sleep(STEP).await;
                    activity.touch();
                }
                "arrived"
            })
            .await;
        assert_eq!(out, Ok("arrived"));
    }

    #[tokio::test]
    async fn a_transfer_that_stops_moving_expires_even_though_it_started_well() {
        // Progress, then silence. A deadline anchored to the start of the
        // operation would have fired during the healthy part; one anchored to
        // the last byte fires here and only here.
        let watch = IdleWatch::new(Some(IDLE), RunDeadline::unbounded());
        let activity = watch.activity();
        let started = std::time::Instant::now();
        let out = watch
            .guard(async {
                // Sixteen steps, not four: the moving half has to outlast IDLE
                // for the assertion below to mean anything, and a STEP is an
                // eighth of it. The count follows the constant rather than the
                // constant following the count.
                for _ in 0..16 {
                    tokio::time::sleep(STEP).await;
                    activity.touch();
                }
                std::future::pending::<()>().await;
            })
            .await;
        assert_eq!(out, Err(Expired::Idle { idle: IDLE }));
        assert!(
            started.elapsed() >= IDLE * 2,
            "it must have survived the moving half rather than failing at the start"
        );
    }

    #[tokio::test]
    async fn a_disabled_watch_never_fires() {
        let watch = IdleWatch::new(None, RunDeadline::unbounded());
        assert!(!watch.is_armed());
        // Would expire immediately under any armed watch: nothing ever touches
        // the clock, and the operation outlives every deadline this file uses.
        let out = watch
            .guard(async {
                tokio::time::sleep(IDLE * 4).await;
                "arrived"
            })
            .await;
        assert_eq!(out, Ok("arrived"));
    }

    #[tokio::test]
    async fn the_failure_names_the_flag_and_the_number_the_operator_set() {
        // The report is the whole product of a timeout. An operator reading
        // "timed out" learns nothing they can act on; one reading their own
        // `--timeout 30` back knows exactly which dial to move.
        let expired = Expired::Idle {
            idle: Duration::from_secs(30),
        };
        let rendered = expired.to_string();
        assert!(rendered.contains("--timeout 30s"), "{rendered}");
    }

    // ── the run's own deadline ───────────────────────────────────────────
    //
    // §32.9: `--timeout 30` fired at exactly 30 s and the run carried on for
    // 943.6 s. Every test below is about the second half of that sentence.

    /// A run window short enough to fire inside a test, and — deliberately —
    /// much shorter than [`IDLE`], so a watch that stopped on the *idle*
    /// deadline could not be mistaken for one that stopped on the run's.
    const WINDOW: Duration = Duration::from_millis(IDLE.as_millis() as u64 / 4);

    fn bounded_run() -> RunDeadline {
        RunDeadline::starting_now(Some(WINDOW))
    }

    /// Long enough that only a watch which never fires at all can reach it, and
    /// short enough that reaching it is a failed test rather than a stalled
    /// suite.
    ///
    /// **A test that hangs when the defect is present is a test nobody can
    /// watch go red**, and this file needs the bound for a reason its siblings
    /// do not: `guard` is asked to hold a future that never completes, so a
    /// watch with no armed deadline waits forever by construction rather than
    /// by accident. This was found the way such things are always found — by
    /// reinstating the defect and watching the gate stop instead of fail, at
    /// 36 of 56 binaries, which the harness reported INCOMPLETE rather than as
    /// a verdict.
    const NEVER_FIRED: Duration = Duration::from_millis(IDLE.as_millis() as u64 * 8);

    /// `watch.guard(op)`, bounded so that "the deadline never fired" is a
    /// failure with a message instead of a suite that stops.
    async fn guarded<F>(watch: &IdleWatch, op: F) -> Result<F::Output, Expired>
    where
        F: Future,
    {
        match tokio::time::timeout(NEVER_FIRED, watch.guard(op)).await {
            Ok(outcome) => outcome,
            Err(_) => panic!(
                "neither deadline fired within {NEVER_FIRED:?}: the watch is \
                 not armed at all"
            ),
        }
    }

    #[tokio::test]
    async fn a_request_in_flight_is_abandoned_when_the_runs_window_closes() {
        // The §32.9 shape at the layer that owns the request: connected, silent,
        // and — before this — waited on until something else gave up.
        let watch = IdleWatch::new(Some(IDLE), bounded_run());
        let started = std::time::Instant::now();
        let out = guarded(&watch, async { std::future::pending::<()>().await }).await;
        assert_eq!(out, Err(Expired::Run { limit: WINDOW }));
        assert!(
            started.elapsed() < IDLE,
            "the run's window is the nearer deadline and must be the one that \
             fires: {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn the_runs_window_ends_an_operation_a_disabled_timeout_would_not() {
        // `--timeout 0 --max-duration W`. Before the run's deadline existed this
        // watch carried no timer at all, so the operation below would have run
        // for as long as TCP allowed.
        let watch = IdleWatch::new(None, bounded_run());
        assert!(watch.is_armed());
        let out = guarded(&watch, async { std::future::pending::<()>().await }).await;
        assert_eq!(out, Err(Expired::Run { limit: WINDOW }));
    }

    #[tokio::test]
    async fn a_transfer_that_is_moving_perfectly_well_is_still_ended_by_the_window() {
        // The difference between the two deadlines, stated as a test. This
        // operation touches the clock throughout, so `--timeout` would never
        // fire however long it ran — and that is correct, and it is why
        // `--timeout` cannot be the flag that bounds a backup window.
        let watch = IdleWatch::new(Some(IDLE), bounded_run());
        let activity = watch.activity();
        let out = watch
            .guard(async {
                // Sixteen touches an eighth of a STEP apart: never quiet for
                // anything like `--timeout`, and in total four times the run's
                // window. The counts follow the two constants rather than the
                // constants following the counts.
                for _ in 0..16 {
                    tokio::time::sleep(STEP / 2).await;
                    activity.touch();
                }
                "arrived"
            })
            .await;
        assert_eq!(out, Err(Expired::Run { limit: WINDOW }));
    }

    #[tokio::test]
    async fn an_operation_that_finishes_inside_the_window_is_untouched() {
        // The direction that matters more. A `--max-duration` that killed work
        // it had time for would be worse than no flag at all.
        let watch = IdleWatch::new(Some(IDLE), RunDeadline::starting_now(Some(IDLE * 8)));
        let out = watch
            .guard(async {
                tokio::time::sleep(STEP).await;
                "arrived"
            })
            .await;
        assert_eq!(out, Ok("arrived"));
    }

    #[tokio::test]
    async fn a_window_already_closed_still_lets_a_finished_operation_through() {
        // The same rule `an_operation_is_always_given_one_chance_to_run` states
        // for the idle deadline, against the other one. A watch outlives the
        // call that made it — `streaming::stream_to_file` is handed one — so a
        // response already in hand must not be failed by a clock.
        let watch = IdleWatch::new(
            Some(IDLE),
            RunDeadline::starting_at(std::time::Instant::now() - WINDOW * 4, Some(WINDOW)),
        );
        assert_eq!(watch.guard(async { 7 }).await, Ok(7));
    }

    #[test]
    fn the_two_deadlines_become_two_different_errors() {
        // The classification is the whole reason the enum exists: one is worth
        // another attempt and the other is the run being over. A `--max-duration`
        // that arrived as a transport failure would be retried six times by the
        // layer above, which is the defect with a new name.
        let stalled = Expired::Idle { idle: WINDOW }.into_store_error("b2");
        assert!(matches!(
            stalled,
            crate::error::StoreError::Transport { .. }
        ));
        assert!(!Expired::Idle { idle: WINDOW }.is_run_deadline());

        let over = Expired::Run { limit: WINDOW }.into_store_error("b2");
        assert!(matches!(over, crate::error::StoreError::RunDeadline { .. }));
        assert!(Expired::Run { limit: WINDOW }.is_run_deadline());
        assert!(over.to_string().contains("--max-duration"), "{over}");
    }
}
