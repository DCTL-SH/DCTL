//! How long to wait — for a link to answer, and for one that has gone quiet.
//!
//! # The entry this closes
//!
//! `HANDOVER.md` §11.2: *"Let an operator choose how long to wait for a dead
//! network."* The retry half of that item was already done and a black-holed
//! route already terminated — exit 5 after 200 s, with an honest attempt count.
//! What was missing was that **200 s was nobody's choice**. `--timeout` and
//! `--contimeout` were refused and no HTTP client carried a deadline, so an
//! operator whose backup window was thirty seconds and one whose link recovers
//! after ten minutes got the same number, and neither of them had asked for it.
//!
//! A backup window is a number somebody else chooses. This module is where that
//! number lives.
//!
//! # Two numbers, two different failures
//!
//! * [`Deadlines::connect`] — `--contimeout`. How long to spend *reaching* a
//!   host. Nothing is at risk while a connection is being established, so this
//!   is the impatient one.
//! * [`Deadlines::idle`] — `--timeout`. How long a transfer may move **no
//!   bytes**. Not how long it may take: see [`watch`], which is written around
//!   that distinction, and `constants::DEFAULT_IDLE`, which explains why getting
//!   it backwards would destroy exactly the transfers worth protecting.
//!
//! Both take rclone's defaults and rclone's meaning of zero
//! (`fs/config.go:115-123`), because a script being migrated should not discover
//! that the same flag means a different length of patience.
//!
//! # How each backend is reached
//!
//! | | `--contimeout` | `--timeout` |
//! |---|---|---|
//! | `b2`, `s3`, `r2` | `reqwest`'s `connect_timeout`, which covers the TCP connect and the TLS handshake | [`IdleWatch`] around every request, fed by [`http`]: a frame taken by the connection, or a chunk arriving |
//! | `sftp` | `ssh -o ConnectTimeout`, so the whole `ProxyCommand`/handshake chain is bounded | [`IdleWatch`] around every protocol operation, fed by each one that completes |
//! | `local` | — | — |
//!
//! `local:` gets neither, and that is a statement rather than an omission. There
//! is no connection to establish, and there is no deadline a user-space timer
//! can impose on the case that would want one: a wedged NFS mount blocks in
//! uninterruptible sleep inside the kernel, where dropping the future does not
//! stop the thread, and a timeout that returned while the read carried on would
//! be a report rather than a remedy. `crate::retry::policy::local` is what
//! covers the failures a local filesystem does produce.
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
pub mod watch;

use std::time::Duration;

pub use activity::Activity;
pub use http::Answered;
pub use watch::{Expired, IdleWatch};

/// How long this run is willing to wait, on every backend that can wait.
///
/// Passed by value and `Copy`, so a backend that needs it holds its own and
/// nothing can mutate a live connection's patience out from under it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Deadlines {
    /// `--contimeout`. [`None`] means "as long as it takes".
    pub connect: Option<Duration>,
    /// `--timeout`. [`None`] means "as long as it takes".
    pub idle: Option<Duration>,
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
        }
    }
}

impl Deadlines {
    /// Deadlines built from the two flag values, in seconds.
    ///
    /// Zero disables, matching rclone (`constants::DISABLED_SECONDS`), so an
    /// operator who means "never give up" has a way to say it that is not a very
    /// large number they will one day be wrong about.
    #[must_use]
    pub const fn from_seconds(connect: u64, idle: u64) -> Self {
        Self {
            connect: seconds(connect),
            idle: seconds(idle),
        }
    }

    /// Neither deadline armed.
    ///
    /// For the tests and internal readers that must observe what one attempt
    /// does without a clock in the way — the same reason
    /// [`crate::retry::RetryPolicy::none`] exists.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            connect: None,
            idle: None,
        }
    }

    /// A fresh watch for one operation.
    ///
    /// Per operation, never per backend: two requests in flight are two separate
    /// claims about whether *that request* is moving, and one clock between them
    /// would let a healthy download hold a dead upload open.
    #[must_use]
    pub fn watch(&self) -> IdleWatch {
        IdleWatch::new(self.idle)
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
        // Quoted from `fs/config.go:115-123`. If either of these is ever
        // changed, the sentence in the module documentation that claims parity
        // with rclone stops being true and has to change with it.
        let deadlines = Deadlines::default();
        assert_eq!(deadlines.connect, Some(Duration::from_secs(60)));
        assert_eq!(deadlines.idle, Some(Duration::from_secs(5 * 60)));
    }

    #[test]
    fn zero_means_never_give_up_on_either_flag() {
        assert_eq!(Deadlines::from_seconds(0, 0), Deadlines::none());
        assert_eq!(
            Deadlines::from_seconds(0, 30),
            Deadlines {
                connect: None,
                idle: Some(Duration::from_secs(30))
            }
        );
        assert_eq!(
            Deadlines::from_seconds(30, 0),
            Deadlines {
                connect: Some(Duration::from_secs(30)),
                idle: None
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
