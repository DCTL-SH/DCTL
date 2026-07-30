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

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use super::activity::Activity;

/// An operation that moved nothing for as long as the operator was willing to
/// wait.
///
/// Its own type rather than a formatted string, for the reason
/// [`crate::retry::observed`] gives about every other classification in this
/// crate: the call site that turns this into a [`StoreError`](crate::StoreError)
/// knows which backend it is and what it was doing, and a message assembled here
/// could only be matched on later by searching its words.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Expired {
    /// The deadline that was exceeded — the operator's own `--timeout`, so the
    /// report can quote the number they set rather than a number DCTL chose.
    pub idle: Duration,
}

impl Expired {
    /// The error an operator reads, attributed to the backend that stalled.
    ///
    /// [`StoreError::Transport`](crate::StoreError::Transport) and deliberately
    /// not a new variant: "nothing answered" is exactly what a timeout observed,
    /// it is what that variant already means, and it is what
    /// [`crate::retry::observed`] already classifies as worth another attempt.
    /// A stall on one connection is the textbook case for trying again on
    /// another — which is what makes the re-dial in [`crate::sftp`] the other
    /// half of this feature rather than a separate one.
    #[must_use]
    pub fn into_store_error(self, backend: &'static str) -> crate::error::StoreError {
        crate::error::StoreError::Transport {
            backend,
            detail: self.to_string(),
        }
    }
}

impl std::fmt::Display for Expired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Names the flag, because the operator's next question is what to change.
        write!(
            f,
            "no data moved for {:?} (--timeout {}s)",
            self.idle,
            self.idle.as_secs()
        )
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
    /// When this operation last moved bytes.
    activity: Arc<Activity>,
}

impl IdleWatch {
    /// A watch that gives up after `idle` without progress, or never if `idle`
    /// is [`None`].
    #[must_use]
    pub fn new(idle: Option<Duration>) -> Self {
        Self {
            idle,
            activity: Activity::started(),
        }
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

    /// Whether this watch will ever fire.
    ///
    /// Read by the tests that have to prove the *disabled* direction actually
    /// disables something, rather than proving it by not observing a timeout in
    /// a test too short to produce one.
    #[must_use]
    pub const fn is_armed(&self) -> bool {
        self.idle.is_some()
    }

    /// Run `op`, failing with [`Expired`] if nothing touches the clock for the
    /// configured span.
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
    /// # Errors
    ///
    /// [`Expired`] and nothing else. `op`'s own failures are returned as `op`
    /// produced them, unwrapped and unclassified, because this layer has no
    /// opinion about them.
    pub async fn guard<F>(&self, op: F) -> Result<F::Output, Expired>
    where
        F: Future,
    {
        let Some(idle) = self.idle else {
            // Not merely "a very long sleep": an operator who asked for no
            // deadline gets no timer, no wakeups and no arithmetic that could
            // one day overflow into one.
            return Ok(op.await);
        };

        let op = op;
        tokio::pin!(op);

        loop {
            let quiet = self.activity.quiet_for();
            // `None` means the clock is already past the deadline. That is
            // **not** a reason to return yet: this used to be an early `return
            // Err(Expired)` above the `select!`, so a watch that had gone quiet
            // before `guard` was called failed the operation *without polling it
            // once* — and then reported that it "moved nothing", about work that
            // had never started. An operation that completes immediately was
            // failed by it. The window is real wherever a watch outlives the
            // call that made it, which is by design: `streaming::stream_to_file`
            // takes a watch still running from the request that produced its
            // response, and every `--timeout` an operator lowers narrows the gap
            // further. It was found by two tests in this file failing under a
            // full `cargo test --workspace` on a loaded machine, where the gap
            // was nothing but scheduler latency.
            let remaining = idle.checked_sub(quiet);
            // Zero, so the `biased` arm below still gets to run the operation
            // first. A ready operation wins even at a deadline already passed,
            // which is the whole of the correction.
            let wait = remaining.unwrap_or(Duration::ZERO);

            tokio::select! {
                // Biased so the operation is polled first. Without it, an
                // operation that completed in the same wakeup as the deadline
                // would be failed half the time by a coin toss — a flake that
                // would appear only under load, which is the worst place to
                // find one.
                biased;

                out = &mut op => return Ok(out),
                () = tokio::time::sleep(wait) => {
                    if remaining.is_none() {
                        // Polled, still not ready, and the patience really is
                        // spent. This is the only path to `Expired`, and it is
                        // reached only after the operation has had its turn.
                        return Err(Expired { idle });
                    }
                    // The deadline elapsed. Whether that is a stall depends on
                    // what happened *while* we slept, which is why the loop goes
                    // round rather than failing here: a transfer that moved a
                    // frame two seconds ago has its full patience back.
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
        let watch = IdleWatch::new(Some(IDLE));
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
        let watch = IdleWatch::new(Some(IDLE));
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
        let watch = IdleWatch::new(Some(IDLE));
        let out = watch
            .guard(async {
                // The black hole: connected, and silent forever.
                std::future::pending::<()>().await;
            })
            .await;
        assert_eq!(out, Err(Expired { idle: IDLE }));
    }

    #[tokio::test]
    async fn a_slow_transfer_that_keeps_moving_never_expires() {
        // The direction that matters more, and the one a stopwatch would fail.
        // This operation runs for five times the deadline and must not be
        // touched, because it is moving the whole way — which is precisely a
        // large object over a slow link.
        let watch = IdleWatch::new(Some(IDLE));
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
        let watch = IdleWatch::new(Some(IDLE));
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
        assert_eq!(out, Err(Expired { idle: IDLE }));
        assert!(
            started.elapsed() >= IDLE * 2,
            "it must have survived the moving half rather than failing at the start"
        );
    }

    #[tokio::test]
    async fn a_disabled_watch_never_fires() {
        let watch = IdleWatch::new(None);
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
        let expired = Expired {
            idle: Duration::from_secs(30),
        };
        let rendered = expired.to_string();
        assert!(rendered.contains("--timeout 30s"), "{rendered}");
    }
}
