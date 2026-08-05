//! Real-time progress rendering.
//!
//! Three rendering modes, chosen automatically and overridable ([`Mode`]):
//!
//! * **Bars** — a live aggregate bar plus one bar per in-flight file, redrawn
//!   [`PROGRESS_REDRAW_HZ`] times a second. Used when stderr is a terminal.
//! * **Plain** — periodic single-line status records, no ANSI, no cursor
//!   movement. Used when output is piped or redirected to a log file, where
//!   bars would produce megabytes of escape-sequence noise.
//! * **Quiet** — nothing at all (`--quiet`, or `--json` where the machine
//!   consumer wants a clean stream).
//!
//! **Everything here writes to stderr.** `dctl cat`, `dctl lsjson` and friends
//! stream real data on stdout, so a progress bar on stdout would corrupt a pipe.
//! That separation is what makes `dctl cat vault:film.mkv | ffplay -` work while
//! still showing progress on the terminal.
//!
//! The module splits along the four decisions the display makes, so each can be
//! reasoned about and tested without a terminal:
//!
//! | file | decision |
//! |------|----------|
//! | [`mode`] | whether to draw at all, and how |
//! | [`charset`] | which glyphs the terminal can survive |
//! | [`style`] | how a row is laid out |
//! | [`truncate`] | how a long path is fitted into its column |
//! | [`ticker`] | when a run with no bars emits its status line |
//!
//! What is left here is the display itself: the bar registry, the handles that
//! let concurrent transfer tasks each update their own row, and the plain-text
//! status line.

mod charset;
mod mode;
mod style;
pub mod ticker;
mod truncate;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget};

use self::charset::Charset;
use self::style::{aggregate_style, file_style};
use super::size::{self, Units};
use super::stats::{Snapshot, Stage, Stats};
use crate::constants::{
    FILE_LABEL_WIDTH, PERCENT_FIELD_WIDTH, PROGRESS_REDRAW_HZ, PROGRESS_TICK_INTERVAL_MS,
    UNKNOWN_VALUE,
};

pub use mode::Mode;
pub use truncate::truncate_middle;

/// The live progress display.
///
/// One instance per run, shared by every transfer task. All interior mutability
/// is deliberate: the transfer pipeline holds `&Progress` from many tasks at
/// once and must never have to serialise on the renderer.
pub struct Progress {
    mode: Mode,
    units: Units,
    /// Resolved once at construction. Re-detecting per file would re-read the
    /// environment on a hot path and, worse, could hand different rows different
    /// glyph sets — including ignoring `--ascii` on every bar but the first.
    charset: Charset,
    multi: MultiProgress,
    aggregate: ProgressBar,
    /// Per-file bars, keyed by an opaque handle so a task can update only its
    /// own row without holding a lock on the whole display.
    files: Mutex<HashMap<u64, ProgressBar>>,
    next_handle: AtomicU64,
    stats: Arc<Stats>,
}

impl Progress {
    /// Build a display in the given mode.
    ///
    /// `force_ascii` is the user's override for glyph detection; see
    /// [`charset`]. The [`Stats`] handle is shared with the transfer pipeline,
    /// so the bars and the final summary can never disagree — they are two
    /// renderings of one set of counters.
    pub fn new(mode: Mode, units: Units, force_ascii: bool, stats: Arc<Stats>) -> Self {
        let charset = Charset::detect(force_ascii);

        let multi = MultiProgress::with_draw_target(if mode.draws_bars() {
            ProgressDrawTarget::stderr_with_hz(PROGRESS_REDRAW_HZ)
        } else {
            // Plain and Quiet both suppress bar drawing; Plain emits its own
            // periodic lines instead.
            ProgressDrawTarget::hidden()
        });

        let aggregate = multi.add(ProgressBar::new(0));
        aggregate.set_style(aggregate_style(&charset));
        if mode.draws_bars() {
            // Without a steady tick the spinner only advances when bytes arrive,
            // so a stalled transfer would look identical to a finished one.
            aggregate.enable_steady_tick(Duration::from_millis(PROGRESS_TICK_INTERVAL_MS));
        }

        Self {
            mode,
            units,
            charset,
            multi,
            aggregate,
            files: Mutex::new(HashMap::new()),
            next_handle: AtomicU64::new(0),
            stats,
        }
    }

    /// A display that renders nothing.
    ///
    /// Test-only. A real `--quiet` run reaches [`Mode::Quiet`] through
    /// [`Mode::resolve`] like every other run, so the mode is decided in exactly
    /// one place; this is the shorthand for the tests that need a display which
    /// counts but does not draw. It still updates [`Stats`], so those tests
    /// assert on the same numbers a loud run would report.
    #[cfg(test)]
    #[must_use]
    pub fn hidden(stats: Arc<Stats>) -> Self {
        Self::new(Mode::Quiet, Units::Binary, false, stats)
    }

    /// The rendering mode chosen at construction. Fixed for the life of the run.
    #[must_use]
    pub const fn mode(&self) -> Mode {
        self.mode
    }

    /// Set (or revise) the totals shown by the aggregate bar.
    ///
    /// Safe to call repeatedly: a streaming walk discovers work as it goes, so
    /// the total legitimately grows mid-run.
    pub fn set_totals(&self, total_bytes: u64, total_files: u64) {
        self.stats.set_total_bytes(total_bytes);
        self.stats.set_total_files(total_files);
        self.aggregate.set_length(total_bytes);
    }

    /// Begin tracking one file. Returns a handle used to update or finish it.
    ///
    /// Rows are only created when bars are actually drawn; in [`Mode::Plain`]
    /// and [`Mode::Quiet`] the handle is still issued and still valid, so
    /// callers need no mode-specific branches.
    pub fn start_file(&self, name: &str, size: u64) -> FileHandle {
        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);

        if self.mode.draws_bars() {
            let bar = self.multi.add(ProgressBar::new(size));
            bar.set_style(file_style(&self.charset));
            bar.set_prefix(truncate_middle(name, FILE_LABEL_WIDTH));
            bar.set_message(Stage::Reading.label());
            if let Ok(mut files) = self.files.lock() {
                files.insert(handle, bar);
            }
        }

        FileHandle { id: handle }
    }

    /// Record progress on a file, and on the aggregate.
    pub fn advance(&self, handle: &FileHandle, bytes: u64) {
        self.stats.add_bytes(bytes);
        self.aggregate.inc(bytes);
        if let Ok(files) = self.files.lock() {
            if let Some(bar) = files.get(&handle.id) {
                bar.inc(bytes);
            }
        }
    }

    /// Move a file to a new pipeline stage.
    ///
    /// This is the row that makes DCTL's guarantee visible: a file sitting at
    /// `verify` has been uploaded but is not yet provably durable, and a file
    /// at `commit` is being written into the index — the step that actually
    /// makes it count as stored ([the plan](https://doc.dctl.sh/project/plan)
    /// §6 step 6).
    pub fn set_stage(&self, handle: &FileHandle, stage: Stage) {
        if let Ok(files) = self.files.lock() {
            if let Some(bar) = files.get(&handle.id) {
                bar.set_message(stage.label());
            }
        }
    }

    /// Finish a file, removing its row.
    ///
    /// Takes the handle by value: a row is retired exactly once, and a second
    /// call would otherwise clear a row that a later file had been given.
    pub fn finish_file(&self, handle: FileHandle) {
        if let Ok(mut files) = self.files.lock() {
            if let Some(bar) = files.remove(&handle.id) {
                bar.finish_and_clear();
                self.multi.remove(&bar);
            }
        }
    }

    /// Print a line without tearing the bars.
    ///
    /// `indicatif` clears the bar region, writes the line, and redraws — so
    /// per-file log output interleaves cleanly with live bars.
    pub fn println(&self, line: impl AsRef<str>) {
        match self.mode {
            Mode::Quiet => {}
            Mode::Bars => {
                let _ = self.multi.println(line.as_ref());
            }
            Mode::Plain => eprintln!("{}", line.as_ref()),
        }
    }

    /// Run a closure with the bars temporarily cleared — for a password prompt
    /// or an interactive confirmation, which must not be overdrawn.
    pub fn suspend<F: FnOnce() -> T, T>(&self, f: F) -> T {
        if self.mode.draws_bars() {
            self.multi.suspend(f)
        } else {
            f()
        }
    }

    /// The periodic status record, as `--stats-one-line` asked for it.
    ///
    /// The condensed form. Fixed-width fields throughout, because this line is
    /// written repeatedly into a log that a human or a script later reads top to
    /// bottom; columns that shift as the numbers grow make it unreadable either
    /// way.
    ///
    /// This used to be the *only* form, which is what made `--stats-one-line`
    /// indistinguishable from its absence: the flag asked for something it
    /// already had. [`Progress::block`] is now the default and this is what the
    /// flag selects, which is also rclone's arrangement.
    #[must_use]
    pub fn one_line(&self, snapshot: &Snapshot) -> String {
        let pct = snapshot.percent().map_or_else(
            || format!("{UNKNOWN_VALUE:>width$} ", width = PERCENT_FIELD_WIDTH),
            |p| format!("{p:>width$.0}%", width = PERCENT_FIELD_WIDTH),
        );
        format!(
            "{pct} | {} / {} | {} | ETA {} | {}/{} files | {} errors",
            size::bytes(snapshot.bytes_transferred, self.units),
            size::bytes(snapshot.bytes_total, self.units),
            size::rate(snapshot.average_rate, self.units),
            size::eta(snapshot.bytes_remaining(), snapshot.average_rate),
            snapshot.files_done,
            snapshot.files_total,
            snapshot.errors,
        )
    }

    /// The periodic status record in its default, multi-line form.
    ///
    /// The same rows as the end-of-run summary, in the same order, carrying the
    /// same numbers — because it *is* the summary, taken mid-run. A watcher
    /// reading a log at 3 a.m. should not have to learn a second format to find
    /// out how many errors there have been, and the condensed line cannot carry
    /// every row without becoming unreadable.
    ///
    /// Rendered in this run's units, so a status record and the report that
    /// follows it never disagree about whether a gigabyte is 10^9 or 2^30.
    #[must_use]
    pub fn block(&self, snapshot: &Snapshot) -> Vec<String> {
        crate::output::summary::lines(snapshot, self.units)
    }

    /// Tear down the bars. Call before printing a summary or an error.
    ///
    /// Clears every row, not just the aggregate: a leftover per-file bar would
    /// be redrawn over the summary that follows it.
    pub fn finish(&self) {
        if let Ok(mut files) = self.files.lock() {
            for (_, bar) in files.drain() {
                bar.finish_and_clear();
            }
        }
        self.aggregate.finish_and_clear();
    }
}

/// Opaque per-file handle. Not `Clone` — exactly one owner finishes each file.
///
/// The identifier is meaningless outside the [`Progress`] that issued it, which
/// is the point: a transfer task can update its own row from another thread
/// without being handed a reference to the bar registry.
#[derive(Debug)]
pub struct FileHandle {
    id: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hidden_progress_renders_nothing_and_never_panics() {
        let stats = Stats::shared();
        let progress = Progress::hidden(stats.clone());
        assert_eq!(progress.mode(), Mode::Quiet);

        progress.set_totals(1000, 2);
        let handle = progress.start_file("a.txt", 500);
        progress.advance(&handle, 250);
        progress.set_stage(&handle, Stage::Verifying);
        progress.finish_file(handle);
        progress.println("ignored");
        progress.finish();

        assert_eq!(stats.snapshot().bytes_transferred, 250);
    }

    #[test]
    fn advancing_updates_shared_stats() {
        let stats = Stats::shared();
        let progress = Progress::hidden(stats.clone());
        let a = progress.start_file("a", 100);
        let b = progress.start_file("b", 100);
        progress.advance(&a, 60);
        progress.advance(&b, 40);
        assert_eq!(stats.snapshot().bytes_transferred, 100);
    }

    #[test]
    fn one_line_status_is_stable_and_parseable() {
        let stats = Stats::shared();
        stats.set_total_bytes(1000);
        stats.set_total_files(2);
        stats.add_bytes(500);
        stats.file_done();

        let progress = Progress::hidden(stats.clone());
        let line = progress.one_line(&stats.snapshot());
        assert!(line.contains("50%"), "got: {line}");
        assert!(line.contains("1/2 files"), "got: {line}");
        assert!(line.contains("0 errors"), "got: {line}");
    }

    #[test]
    fn suspend_runs_the_closure_in_every_mode() {
        let progress = Progress::hidden(Stats::shared());
        assert_eq!(progress.suspend(|| 42), 42);
    }

    #[test]
    fn an_unknown_percentage_keeps_the_column_width() {
        // With no total there is no percentage, but the placeholder must occupy
        // the same space or every line in the log shifts sideways.
        let stats = Stats::shared();
        let progress = Progress::hidden(stats.clone());
        let unknown = progress.one_line(&stats.snapshot());
        assert!(unknown.starts_with(&format!(
            "{UNKNOWN_VALUE:>width$} ",
            width = PERCENT_FIELD_WIDTH
        )));

        stats.set_total_bytes(1000);
        stats.add_bytes(1000);
        let known = progress.one_line(&stats.snapshot());
        let unknown_prefix = unknown.split('|').next().unwrap_or_default().len();
        let known_prefix = known.split('|').next().unwrap_or_default().len();
        assert_eq!(unknown_prefix, known_prefix, "\n{unknown}\n{known}");
    }

    #[test]
    fn handles_are_unique_per_file() {
        // Two files sharing an id would make one row shadow the other, and
        // finishing one would clear both.
        let progress = Progress::hidden(Stats::shared());
        let first = progress.start_file("a", 1);
        let second = progress.start_file("b", 1);
        assert_ne!(first.id, second.id);
    }

    #[test]
    fn a_hidden_display_still_issues_usable_handles() {
        // Callers must not need a mode-specific branch: every operation on a
        // handle has to be a no-op rather than an error when nothing is drawn.
        let progress = Progress::hidden(Stats::shared());
        let handle = progress.start_file("never-drawn", 10);
        progress.set_stage(&handle, Stage::Committing);
        progress.advance(&handle, 10);
        progress.finish_file(handle);
        progress.finish();
    }

    #[test]
    fn forcing_ascii_is_remembered_for_the_whole_run() {
        // The latent bug this guards against: re-detecting the charset per file
        // would drop `--ascii` on every row but the aggregate.
        let progress = Progress::new(Mode::Quiet, Units::Binary, true, Stats::shared());
        assert_eq!(progress.charset, Charset::ASCII);
    }

    #[test]
    fn totals_may_grow_mid_run() {
        // A streaming walk discovers work as it goes; revising the total must
        // not disturb what has already been counted.
        let stats = Stats::shared();
        let progress = Progress::hidden(stats.clone());
        progress.set_totals(100, 1);
        progress.set_totals(500, 3);
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.bytes_total, 500);
        assert_eq!(snapshot.files_total, 3);
    }
}
