//! The thing that makes [`Mode::Plain`] actually emit anything.
//!
//! A terminal run redraws its bars from `indicatif`'s own thread, so nothing in
//! this crate has to decide *when* to paint. A redirected run has no such
//! thread: [`Mode::Plain`] describes periodic single-line status records, and
//! without something on a clock to produce them a `dctl copy … >> backup.log`
//! writes the summary at the end and not one byte before it. For a job that
//! moves a terabyte overnight that is the difference between "it is 40% through
//! and moving at 90 MB/s" and total silence until it either finishes or does
//! not.
//!
//! Deliberately its own file, and deliberately not a method on [`Progress`]:
//! everything else in the display is synchronous and callable from a test with
//! no runtime, whereas this owns a spawned task and a cancellation rule. Mixing
//! the two would make the whole display require an executor to exercise.
//!
//! ## Cancellation is a drop, not a call
//!
//! [`spawn`] returns a guard that aborts the task when it goes out of scope.
//! A `JoinHandle` dropped on its own leaves the task running, and a status line
//! printed after the end-of-run summary — or worse, interleaved into a failure
//! message — reads as though the run were still going. Tying the lifetime to a
//! value the compiler tracks means no error path can forget to stop it.

use std::sync::Arc;
use std::time::Duration;

use super::Progress;
use super::mode::Mode;
use crate::constants;
use crate::output::stats::Stats;

/// A running status-line task, stopped when this is dropped.
///
/// Deliberately holds no methods: there is exactly one thing a caller does with
/// it, which is keep it alive for as long as the command runs.
pub struct Ticker {
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for Ticker {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// Which shape the periodic record takes.
///
/// Two shapes because `--stats-one-line` has to *do* something. It used to be
/// accepted and ignored — the ticker only ever emitted the condensed line, so
/// asking for one line was asking for what you already had, and the flag was
/// indistinguishable from its absence in every run. rclone's arrangement is the
/// one restored here: a block by default, condensed on request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Style {
    /// The full report, mid-run: every row the end-of-run summary would show.
    Block,
    /// One line, for a log that will be read with `grep`.
    OneLine,
}

impl Style {
    /// The shape `--stats-one-line` selects.
    #[must_use]
    pub const fn resolve(one_line: bool) -> Self {
        if one_line { Self::OneLine } else { Self::Block }
    }
}

/// How often this run emits a status record, or [`None`] for never.
///
/// The second of the two things `--progress` measurably does, and the one that
/// applies to the environment the flag exists for. A redirected run reports every
/// [`DEFAULT_STATS_INTERVAL_SECS`] — a minute, which is right for an unattended
/// nightly job and useless to somebody watching. `-P` says *watch this*, so it
/// selects [`PROGRESS_STATS_INTERVAL_SECS`]. Measured on a three-minute copy that
/// is three records against a hundred and eighty.
///
/// Three rules, in order:
///
/// 1. `--stats 0` is the documented off switch and wins outright, `-P` or not. It
///    is a direct instruction about this exact output, and a flag that overrode
///    it would leave no way to say "keep the bars, drop the log spam".
/// 2. `--progress` asks for the live cadence.
/// 3. Whichever of the two is *shorter* is used, so forcing progress can never
///    produce fewer records than not forcing it — the property that stopped `-P`
///    being actively harmful, kept as an invariant rather than a coincidence.
///
/// rclone's arrangement, near enough: `-P` there also selects a sub-second
/// interval and defers to an explicitly given `--stats`. It differs in honouring
/// an explicit `--stats 0`, which rclone ignores.
#[must_use]
pub fn interval(force_progress: bool, stats_secs: u64) -> Option<Duration> {
    if stats_secs == 0 {
        return None;
    }
    let seconds = if force_progress {
        stats_secs.min(constants::PROGRESS_STATS_INTERVAL_SECS)
    } else {
        stats_secs
    };
    Some(Duration::from_secs(seconds))
}

/// Start emitting a status record every `interval`, if this run wants one.
///
/// Returns `None` — and spawns nothing — unless both conditions hold:
///
/// * the display is in [`Mode::Plain`]. Bars already show live progress, and
///   [`Quiet`](Mode::Quiet) was an explicit request for silence.
/// * `interval` is `Some`; see [`interval`] for when it is not.
///
/// A `None` return is a normal outcome, not a failure: most runs are watched on
/// a terminal.
#[must_use]
pub fn spawn(
    progress: &Arc<Progress>,
    stats: &Arc<Stats>,
    interval: Option<Duration>,
    style: Style,
) -> Option<Ticker> {
    let interval = interval?;
    if progress.mode() != Mode::Plain {
        return None;
    }

    let progress = Arc::clone(progress);
    let stats = Arc::clone(stats);

    Some(Ticker {
        handle: tokio::spawn(async move {
            loop {
                // Sleep first. A record emitted at t=0 would report an empty
                // snapshot of a run that has not started moving bytes yet,
                // which is noise at best and misleading at worst.
                tokio::time::sleep(interval).await;
                let snapshot = stats.snapshot();
                match style {
                    Style::OneLine => progress.println(progress.one_line(&snapshot)),
                    // Printed line by line rather than as one joined string, so
                    // the bars-suspending `println` gets each record the way it
                    // gets every other line and cannot interleave a bar into the
                    // middle of a block.
                    Style::Block => {
                        for line in progress.block(&snapshot) {
                            progress.println(line);
                        }
                    }
                }
            }
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{DEFAULT_STATS_INTERVAL_SECS, PROGRESS_STATS_INTERVAL_SECS};
    use crate::output::Units;

    fn plain() -> Arc<Progress> {
        Arc::new(Progress::new(
            Mode::Plain,
            Units::Binary,
            false,
            Stats::shared(),
        ))
    }

    #[tokio::test]
    async fn a_plain_run_gets_a_ticker() {
        let stats = Stats::shared();
        assert!(spawn(&plain(), &stats, interval(false, 1), Style::Block).is_some());
    }

    #[tokio::test]
    async fn zero_disables_the_line_without_disabling_progress() {
        // `--stats 0` is the documented off switch; it must not be confused
        // with `--quiet`, which turns the whole display off.
        let stats = Stats::shared();
        assert!(spawn(&plain(), &stats, interval(false, 0), Style::Block).is_none());
    }

    #[tokio::test]
    async fn modes_that_render_their_own_progress_get_no_ticker() {
        // Bars redraw continuously and Quiet asked for nothing; a periodic line
        // in either would be output the user did not ask for.
        let stats = Stats::shared();
        for mode in [Mode::Bars, Mode::Quiet] {
            let progress = Arc::new(Progress::new(mode, Units::Binary, false, Stats::shared()));
            assert!(
                spawn(&progress, &stats, interval(false, 1), Style::Block).is_none(),
                "{mode:?}"
            );
        }
    }

    /// The second of the two things `-P` measurably does.
    ///
    /// A redirected three-minute copy without it writes three status records and
    /// with it writes a hundred and eighty. Before this, the flag produced the
    /// same output in every environment — a "guarantee" nobody could observe,
    /// which is what HANDOVER §11.2 called out.
    #[test]
    fn forcing_progress_selects_the_live_cadence() {
        let ordinary = interval(false, DEFAULT_STATS_INTERVAL_SECS).expect("a default cadence");
        let live = interval(true, DEFAULT_STATS_INTERVAL_SECS).expect("a live cadence");
        assert_eq!(ordinary, Duration::from_secs(DEFAULT_STATS_INTERVAL_SECS));
        assert_eq!(live, Duration::from_secs(PROGRESS_STATS_INTERVAL_SECS));
        assert!(
            live < ordinary,
            "the flag has to produce more records, not the same number: {live:?} vs {ordinary:?}"
        );
    }

    #[test]
    fn an_explicit_stats_interval_shorter_than_the_live_one_is_kept() {
        // The rule is "whichever is shorter", so a user asking for something
        // faster than `-P`'s own cadence is not slowed down by adding it.
        assert_eq!(interval(true, 0), None, "the off switch still wins");
        assert_eq!(interval(false, 5), Some(Duration::from_secs(5)));
        assert_eq!(
            interval(true, 5),
            Some(Duration::from_secs(PROGRESS_STATS_INTERVAL_SECS))
        );
    }

    #[test]
    fn forcing_progress_never_produces_fewer_records() {
        // The invariant behind the harm that was fixed last pass, kept as a
        // property rather than a promise: for every `--stats` a user can type,
        // adding `-P` may only shorten the interval.
        for stats_secs in [0, 1, 2, 5, 60, 3600, u64::MAX] {
            match (interval(false, stats_secs), interval(true, stats_secs)) {
                (None, forced) => assert_eq!(
                    forced, None,
                    "--stats 0 is an instruction, not a default ({stats_secs})"
                ),
                (Some(unforced), Some(forced)) => assert!(
                    forced <= unforced,
                    "-P produced a longer interval at --stats {stats_secs}: \
                     {forced:?} > {unforced:?}"
                ),
                (Some(_), None) => panic!("-P silenced --stats {stats_secs}"),
            }
        }
    }

    #[test]
    fn the_two_styles_really_are_two_shapes() {
        // The check that `--stats-one-line` is not the flag it used to be. When
        // the ticker only knew one shape, this assertion had nothing to compare
        // and the flag could not be distinguished from its absence.
        assert_eq!(Style::resolve(false), Style::Block);
        assert_eq!(Style::resolve(true), Style::OneLine);

        let stats = Stats::shared();
        stats.set_total_bytes(1000);
        stats.add_bytes(500);
        let progress = plain();
        let snapshot = stats.snapshot();

        let block = progress.block(&snapshot);
        let one_line = progress.one_line(&snapshot);
        assert!(
            block.len() > 1,
            "the default record must be a block, got {block:?}"
        );
        assert!(!one_line.contains('\n'), "got: {one_line}");
        // …and the block must carry what the condensed line cannot: the errors
        // row is the reason somebody reads a status record at all.
        assert!(
            block.iter().any(|line| line.contains("Errors")),
            "got {block:?}"
        );
    }

    #[tokio::test]
    async fn dropping_the_guard_stops_the_task() {
        let stats = Stats::shared();
        let ticker =
            spawn(&plain(), &stats, interval(false, 1), Style::Block).expect("plain runs tick");
        let handle = ticker.handle.abort_handle();
        drop(ticker);
        // A line printed after the run ended would read as though it were
        // still going, so the abort is part of the contract, not a courtesy.
        assert!(
            handle.is_finished() || {
                tokio::task::yield_now().await;
                handle.is_finished()
            }
        );
    }
}
