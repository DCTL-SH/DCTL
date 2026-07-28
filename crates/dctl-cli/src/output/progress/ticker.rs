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

/// Start emitting a status record every `interval_secs`, if this run wants one.
///
/// Returns `None` — and spawns nothing — unless both conditions hold:
///
/// * the display is in [`Mode::Plain`]. Bars already show live progress, and
///   [`Quiet`](Mode::Quiet) was an explicit request for silence.
/// * `interval_secs` is non-zero. `--stats 0` is the documented way to turn the
///   record off without turning off progress altogether.
///
/// A `None` return is a normal outcome, not a failure: most runs are watched on
/// a terminal.
#[must_use]
pub fn spawn(
    progress: &Arc<Progress>,
    stats: &Arc<Stats>,
    interval_secs: u64,
    style: Style,
) -> Option<Ticker> {
    if progress.mode() != Mode::Plain || interval_secs == 0 {
        return None;
    }

    let progress = Arc::clone(progress);
    let stats = Arc::clone(stats);
    let interval = Duration::from_secs(interval_secs);

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
        assert!(spawn(&plain(), &stats, 1, Style::Block).is_some());
    }

    #[tokio::test]
    async fn zero_disables_the_line_without_disabling_progress() {
        // `--stats 0` is the documented off switch; it must not be confused
        // with `--quiet`, which turns the whole display off.
        let stats = Stats::shared();
        assert!(spawn(&plain(), &stats, 0, Style::Block).is_none());
    }

    #[tokio::test]
    async fn modes_that_render_their_own_progress_get_no_ticker() {
        // Bars redraw continuously and Quiet asked for nothing; a periodic line
        // in either would be output the user did not ask for.
        let stats = Stats::shared();
        for mode in [Mode::Bars, Mode::Quiet] {
            let progress = Arc::new(Progress::new(mode, Units::Binary, false, Stats::shared()));
            assert!(
                spawn(&progress, &stats, 1, Style::Block).is_none(),
                "{mode:?}"
            );
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
        let ticker = spawn(&plain(), &stats, 1, Style::Block).expect("plain runs tick");
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
