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
            let Some(remaining) = idle.checked_sub(quiet) else {
                return Err(Expired { idle });
            };

            tokio::select! {
                // Biased so the operation is polled first. Without it, an
                // operation that completed in the same wakeup as the deadline
                // would be failed half the time by a coin toss — a flake that
                // would appear only under load, which is the worst place to
                // find one.
                biased;

                out = &mut op => return Ok(out),
                () = tokio::time::sleep(remaining) => {
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

    /// Shorter than any real deadline, long enough that a loaded test machine
    /// does not decide the outcome.
    const IDLE: Duration = Duration::from_millis(200);

    #[tokio::test]
    async fn an_operation_that_finishes_is_untouched() {
        let watch = IdleWatch::new(Some(IDLE));
        let out = watch.guard(async { 7 }).await;
        assert_eq!(out, Ok(7));
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
                    tokio::time::sleep(IDLE / 2).await;
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
                for _ in 0..4 {
                    tokio::time::sleep(IDLE / 2).await;
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
