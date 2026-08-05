//! How long to wait — for a link to answer, and for one that has gone quiet.
//!
//! # The defect this closes
//!
//! **An operator could not choose how long to wait for a dead network.** The
//! retry half of the requirement was already done and a black-holed route
//! already terminated — exit 5 after 200 s, with an honest attempt count. What
//! was missing was that **200 s was nobody's choice**. `--timeout` and
//! `--contimeout` were refused and no HTTP client carried a deadline, so an
//! operator whose backup window was thirty seconds and one whose link recovers
//! after ten minutes got the same number, and neither of them had asked for it.
//!
//! A backup window is a number somebody else chooses. This module is where that
//! number lives.
//!
//! # Three numbers, three different failures
//!
//! * [`Deadlines::connect`] — `--contimeout`. How long to spend *reaching* a
//!   host. Nothing is at risk while a connection is being established, so this
//!   is the impatient one.
//! * [`Deadlines::idle`] — `--timeout`. How long a transfer may move **no
//!   bytes**. Not how long it may take: see [`watch`], which is written around
//!   that distinction, and `constants::DEFAULT_IDLE`, which explains why getting
//!   it backwards would destroy exactly the transfers worth protecting.
//! * [`Deadlines::run`] — `--max-duration`. When the **run** has to be over.
//!   The only one of the three that is a wall clock, and the only one that
//!   bounds a whole invocation; see [`run`].
//!
//! The first two take rclone's defaults and rclone's meaning of zero, because a
//! script being migrated should not discover that the same flag means a
//! different length of patience. The third takes rclone's default too — none.
//!
//! **Neither of the first two bounds a run, and saying so is the point.** Each
//! bounds *one attempt*; a run makes several distinct requests and retries each
//! of them on a schedule, and `--retries` repeats the file on top of that. The
//! product was measured: a black-holed B2 upload under `--timeout 30 --retries
//! 1` had not ended **943.6 s** after the cut. The remedy is not to make an
//! inactivity deadline behave like a stopwatch — that would destroy every large
//! transfer it was protecting — but to have a flag that is a stopwatch, and to
//! have the retry layer consult it. That is [`run`].
//!
//! # How each backend is reached
//!
//! | | `--contimeout` | `--timeout` | `--max-duration` |
//! |---|---|---|---|
//! | `b2`, `s3`, `r2` | `reqwest`'s `connect_timeout`, which covers the TCP connect and the TLS handshake | [`IdleWatch`] around every request, fed by [`http`]: a frame taken by the connection, or a chunk arriving | the same [`IdleWatch`], which ends at whichever of the two deadlines is nearer, and [`crate::retry::driver`] between attempts |
//! | `sftp` | `ssh -o ConnectTimeout` **and** [`RunDeadline::guard`] around the whole dial, because `ConnectTimeout` bounds the TCP connect and not the handshake behind it | [`IdleWatch`] around every protocol operation, fed by each one that completes | as above, plus the dial |
//! | `local` | — | — | [`crate::retry::driver`] between attempts |
//!
//! `local:` gets neither of the first two, and that is a statement rather than
//! an omission. There is no connection to establish, and there is no deadline a
//! user-space timer can impose on the case that would want one: a wedged NFS
//! mount blocks in uninterruptible sleep inside the kernel, where dropping the
//! future does not stop the thread, and a timeout that returned while the read
//! carried on would be a report rather than a remedy.
//! `crate::retry::policy::local` is what covers the failures a local filesystem
//! does produce. `--max-duration` reaches it anyway, because the retry loop is
//! shared and because the process's own deadline is above every backend.
//!
//! # The grain, stated honestly
//!
//! rclone re-arms a deadline on the socket itself, so its resolution is one
//! `read`/`write` syscall. DCTL's is coarser and by a different amount per
//! backend, because the seams it owns are different — [`http`] says exactly how
//! close the HTTP one gets and why the socket is out of reach, and
//! `crate::sftp` says the same for a protocol operation. Neither is guessed at:
//! the difference only matters on a link so slow that one frame or one chunk
//! takes longer than the whole deadline, and that bound is written down where
//! the number that decides it lives.

pub mod activity;
pub mod constants;
pub mod http;
pub mod run;
pub mod stall;
pub mod watch;

use std::time::Duration;

pub use activity::Activity;
pub use http::Answered;
pub use run::{Exceeded, Left, RunDeadline};
pub use stall::{RunStall, Stalled};
pub use watch::{Expired, IdleWatch};

/// How long this run is willing to wait, on every backend that can wait.
///
/// `Clone` and no longer `Copy`, and the loss is deliberate rather than
/// incidental. Three of the four fields are lengths of patience or an instant,
/// which copy perfectly well; [`Deadlines::stall`] is **state the whole run
/// shares**, and a copy of it would be exactly the defect it exists to close —
/// every layer counting its own attempts is how `--timeout × attempts` became
/// `--timeout × attempts × distinct requests`. Cloning a `Deadlines` clones the
/// handle and not the cell, so a backend that needs its own copy still counts
/// into the run's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Deadlines {
    /// `--contimeout`. [`None`] means "as long as it takes".
    pub connect: Option<Duration>,
    /// `--timeout`. [`None`] means "as long as it takes".
    pub idle: Option<Duration>,
    /// `--max-duration`. When the **run** has to be over, as distinct from how
    /// long any one part of it may be quiet.
    ///
    /// Carried here rather than threaded separately because this structure
    /// already reaches every backend that can wait, and a run-level bound that
    /// only some of them received would be a bound only some of the run
    /// respected — which is the shape of the defect it exists to close. See
    /// [`run`] for what the three depths of enforcement are and why each of
    /// them is needed.
    pub run: RunDeadline,
    /// How many attempts in a row may get **no answer at all** before the run
    /// stops asking — derived from [`Deadlines::idle`], because it is that
    /// number the operator set and that number the report quotes.
    ///
    /// Here for the same reason [`Deadlines::run`] is: this structure already
    /// reaches every backend that can wait, and a run-level bound only some of
    /// them received would be a bound only some of the run respected. It is
    /// also why this type is `Clone` and not `Copy` — see [`stall`] for the
    /// whole argument, and for why counting per request instead of per run is
    /// the arithmetic that came out at 46.3 s, 136.6 s and 288.7 s on three
    /// runs of one command against one fault.
    pub stall: RunStall,
}

impl Default for Deadlines {
    /// What a run that names neither flag gets: rclone's two defaults.
    ///
    /// A default rather than "no deadline at all", and the change is deliberate.
    /// Before this module a `dctl copy` into a black hole was bounded only by
    /// the operating system's TCP behaviour multiplied by the retry schedule,
    /// which is a number no operator can predict and no scheduler can plan
    /// around. Five minutes of silence and sixty seconds to connect are the
    /// numbers rclone has shipped for a decade against these same providers.
    fn default() -> Self {
        Self {
            connect: Some(constants::DEFAULT_CONNECT),
            idle: Some(constants::DEFAULT_IDLE),
            // Unbounded, and that is rclone's default too: its `--max-duration`
            // is zero, meaning no bound at all. A run-length bound nobody asked
            // for would kill a first sync of a large dataset at whatever number
            // this file happened to pick, and no number picked here could be
            // right for both a nightly incremental and a ten-terabyte seed.
            run: RunDeadline::unbounded(),
            // Derived from `idle` above rather than stated again, so the two can
            // never disagree about what `--timeout 0` meant.
            stall: RunStall::from_idle(Some(constants::DEFAULT_IDLE)),
        }
    }
}

impl Deadlines {
    /// Deadlines built from the two flag values, in seconds.
    ///
    /// Zero disables, matching rclone (`constants::DISABLED_SECONDS`), so an
    /// operator who means "never give up" has a way to say it that is not a very
    /// large number they will one day be wrong about.
    ///
    /// The run's own deadline is **not** a parameter here, and the asymmetry is
    /// deliberate: these two are lengths of patience, fixed for the whole run
    /// and meaningful before it starts, while `--max-duration` is an *instant*
    /// that only exists once the run has begun. Folding a reading of the clock
    /// into a `const fn` would mean the deadline was set wherever this happened
    /// to be called. [`Deadlines::within`] is where it is attached, once.
    /// Not `const`, and the reason is [`Deadlines::stall`]: a shared counter is
    /// an allocation, and an allocation cannot happen in a `const`. That is the
    /// right way round — a `const Deadlines` would be a *copy* of the run's
    /// counter per constant, which is precisely the per-request counting this
    /// field exists to replace.
    #[must_use]
    pub fn from_seconds(connect: u64, idle: u64) -> Self {
        let idle = seconds(idle);
        Self {
            connect: seconds(connect),
            idle,
            run: RunDeadline::unbounded(),
            stall: RunStall::from_idle(idle),
        }
    }

    /// The same deadlines, inside a run that has to be over at `run`.
    ///
    /// Applied once, at the top of the process, so every backend the run opens
    /// shares one instant. A deadline attached per backend would give each
    /// destination its own window, and a copy between two of them would get two.
    #[must_use]
    pub fn within(self, run: RunDeadline) -> Self {
        Self { run, ..self }
    }

    /// Neither deadline armed, and no bound on the run.
    ///
    /// For the tests and internal readers that must observe what one attempt
    /// does without a clock in the way — the same reason
    /// [`crate::retry::RetryPolicy::none`] exists.
    #[must_use]
    pub fn none() -> Self {
        Self {
            connect: None,
            idle: None,
            run: RunDeadline::unbounded(),
            stall: RunStall::unbounded(),
        }
    }

    /// A fresh watch for one operation.
    ///
    /// Per operation, never per backend: two requests in flight are two separate
    /// claims about whether *that request* is moving, and one clock between them
    /// would let a healthy download hold a dead upload open.
    ///
    /// The run's deadline goes with it, and is the one part that is **not** per
    /// operation: every watch this method hands out ends at the same instant,
    /// because that instant is a property of the run. A watch that carried a
    /// fresh copy of the window would give every request the whole of it, which
    /// is the arithmetic behind the 943.6 s overrun.
    #[must_use]
    pub fn watch(&self) -> IdleWatch {
        IdleWatch::new(self.idle, self.run)
    }
}

/// `Some(d)` for a positive number of seconds, [`None`] for zero.
const fn seconds(value: u64) -> Option<Duration> {
    if value == constants::DISABLED_SECONDS {
        None
    } else {
        Some(Duration::from_secs(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shipped_defaults_are_rclones() {
        // If either of these is ever changed, the sentence in the module
        // documentation that claims parity with rclone stops being true and has
        // to change with it.
        let deadlines = Deadlines::default();
        assert_eq!(deadlines.connect, Some(Duration::from_secs(60)));
        assert_eq!(deadlines.idle, Some(Duration::from_secs(5 * 60)));
        // And a run nothing asked to be bounded is not bounded — rclone's
        // `--max-duration` default is zero, and a number invented here would
        // end somebody's first sync at it.
        assert!(!deadlines.run.is_bounded());
    }

    #[test]
    fn zero_means_never_give_up_on_either_flag() {
        assert_eq!(Deadlines::from_seconds(0, 0), Deadlines::none());
        assert_eq!(
            Deadlines::from_seconds(0, 30),
            Deadlines {
                connect: None,
                idle: Some(Duration::from_secs(30)),
                run: RunDeadline::unbounded(),
                stall: RunStall::from_idle(Some(Duration::from_secs(30))),
            }
        );
        assert_eq!(
            Deadlines::from_seconds(30, 0),
            Deadlines {
                connect: Some(Duration::from_secs(30)),
                idle: None,
                run: RunDeadline::unbounded(),
                stall: RunStall::unbounded(),
            }
        );
    }

    #[test]
    fn a_watch_carries_the_idle_deadline_and_not_the_connect_one() {
        // The two are separate failures and mixing them would give a transfer
        // the connect timeout's much shorter patience.
        let deadlines = Deadlines::from_seconds(1, 600);
        assert!(deadlines.watch().is_armed());
        assert!(!Deadlines::from_seconds(600, 0).watch().is_armed());
    }

    #[test]
    fn the_run_deadline_is_attached_once_and_reaches_every_watch() {
        // The property the whole feature rests on: one instant, shared. A watch
        // that got a fresh window per operation would give the run's bound to
        // each request separately, which is exactly the arithmetic behind the
        // 943.6 s overrun — `--timeout` per attempt, multiplied by every
        // attempt and every distinct request.
        let window = Duration::from_secs(30);
        let deadlines =
            Deadlines::from_seconds(60, 300).within(RunDeadline::starting_now(Some(window)));
        assert_eq!(deadlines.run.limit(), Some(window));
        let first = deadlines.watch();
        let second = deadlines.watch();
        assert_eq!(first.run_deadline(), second.run_deadline());
        assert_eq!(first.run_deadline(), deadlines.run);
        // …and the two lengths of patience are untouched by it.
        assert_eq!(deadlines.connect, Some(Duration::from_secs(60)));
        assert_eq!(deadlines.idle, Some(Duration::from_secs(300)));
    }

    #[test]
    fn a_run_deadline_arms_a_watch_that_the_timeout_flag_alone_would_not() {
        // `--timeout 0 --max-duration 30`: an operator who will wait forever for
        // a quiet link but needs the job finished by a fixed hour. Before
        // `--max-duration` existed that pair had no way to be expressed, and a
        // watch built from `--timeout 0` alone carries no timer at all.
        let deadlines = Deadlines::from_seconds(0, 0)
            .within(RunDeadline::starting_now(Some(Duration::from_secs(30))));
        assert!(
            deadlines.watch().is_armed(),
            "a bounded run must arm the watch even with --timeout 0"
        );
    }

    #[test]
    fn every_copy_of_a_deadlines_counts_into_one_cell() {
        // The plumbing property the whole bound rests on, and the one nothing
        // else in the workspace can see. `Deadlines` reaches five backends and
        // two retry layers, and it gets there by being cloned — into
        // `Retrying::wrap`, into `B2Backend::new`, through `within` at the top
        // of the process. If any of those hops minted a *fresh* counter, each
        // layer would have its own six and the run's bound would be six times
        // however many layers there are, which is the arithmetic of the 46.3 s,
        // 136.6 s and 288.7 s runs wearing a different hat.
        let deadlines = Deadlines::from_seconds(60, 30);
        let handed_to_a_backend = deadlines.clone();
        let inside_a_bounded_run = deadlines
            .clone()
            .within(RunDeadline::starting_now(Some(Duration::from_secs(600))));

        for _ in 0..constants::UNANSWERED_ATTEMPT_LIMIT {
            handed_to_a_backend.stall.unanswered();
        }
        assert!(
            deadlines.stall.exhausted().is_some(),
            "a clone counted somewhere the original cannot see"
        );
        assert!(
            inside_a_bounded_run.stall.exhausted().is_some(),
            "`within` minted a fresh counter and gave the run a second budget"
        );

        inside_a_bounded_run.stall.answered();
        assert_eq!(
            deadlines.stall.count(),
            0,
            "an answer observed by one holder did not reach the others"
        );
    }

    #[test]
    fn a_run_that_will_wait_forever_has_nothing_counting_against_it() {
        // `--timeout 0`. The control for the test above: if the counter were
        // armed unconditionally, every arm of it would pass for the wrong
        // reason and an operator who asked to wait forever would not.
        assert!(!Deadlines::from_seconds(60, 0).stall.is_bounded());
        assert!(!Deadlines::none().stall.is_bounded());
        assert!(Deadlines::from_seconds(60, 30).stall.is_bounded());
        assert!(
            Deadlines::default().stall.is_bounded(),
            "a run that names neither flag still gets the default --timeout, so \
             it is bounded by the product of it"
        );
    }

    #[test]
    fn each_operation_gets_its_own_clock() {
        // Two watches from one `Deadlines` must not share progress: a stalled
        // upload that was kept alive by a healthy download is a transfer that
        // never terminates.
        let deadlines = Deadlines::default();
        let first = deadlines.watch();
        let second = deadlines.watch();
        std::thread::sleep(Duration::from_millis(30));
        first.touch();
        assert!(first.activity().quiet_for() < second.activity().quiet_for());
    }
}
