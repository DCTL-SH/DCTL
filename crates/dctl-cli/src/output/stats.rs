//! Live transfer counters shared across all worker tasks.
//!
//! Every number the progress display and the final summary show comes from here.
//! The counters are plain atomics behind an [`Arc`], so the transfer pipeline
//! updates them from many tasks at once without locking, and the renderer reads
//! a consistent-enough snapshot ~10×/second without ever blocking a transfer.
//!
//! The rows are deliberately DCTL-specific. A generic copier reports "bytes
//! moved"; DCTL's contract ([the plan](https://doc.dctl.sh/project/plan) §6) is
//! that bytes are *encrypted*, then *verified against the provider's checksum*,
//! then *committed to the index*, so the display separates those stages.
//! "Transferred" going up while "Verified" lags is meaningful information — it
//! means data is in flight but not yet provably durable.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Which stage of the verified-write pipeline a file is currently in.
///
/// Mirrors the numbered steps of [the plan](https://doc.dctl.sh/project/plan)
/// §6 so the display and the spec use the same vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    /// Step 1 — streaming the source and hashing the plaintext.
    Reading,
    /// Step 2 — sealing into chunked AEAD.
    Encrypting,
    /// Step 3 — staging the upload.
    Uploading,
    /// Step 4 — comparing the provider's stored checksum with ours.
    Verifying,
    /// Step 6 — the durable index commit that makes the file count as stored.
    Committing,
    /// Steps 7–8 — done and recorded in the audit log.
    Done,
}

impl Stage {
    /// Short label for the progress line.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Reading => "read",
            Self::Encrypting => "encrypt",
            Self::Uploading => "upload",
            Self::Verifying => "verify",
            Self::Committing => "commit",
            Self::Done => "done",
        }
    }
}

/// Shared, thread-safe counters for one command invocation.
#[derive(Debug)]
pub struct Stats {
    started: Instant,

    // Byte counters.
    bytes_transferred: AtomicU64,
    bytes_total: AtomicU64,
    bytes_verified: AtomicU64,

    // File counters.
    files_done: AtomicU64,
    files_total: AtomicU64,
    files_skipped: AtomicU64,
    files_deleted: AtomicU64,

    // Health counters.
    checks_done: AtomicU64,
    checks_total: AtomicU64,
    errors: AtomicU64,
    retries: AtomicU64,
    checksum_mismatches: AtomicU64,
}

impl Default for Stats {
    fn default() -> Self {
        Self::new()
    }
}

impl Stats {
    #[must_use]
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
            bytes_transferred: AtomicU64::new(0),
            bytes_total: AtomicU64::new(0),
            bytes_verified: AtomicU64::new(0),
            files_done: AtomicU64::new(0),
            files_total: AtomicU64::new(0),
            files_skipped: AtomicU64::new(0),
            files_deleted: AtomicU64::new(0),
            checks_done: AtomicU64::new(0),
            checks_total: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            retries: AtomicU64::new(0),
            checksum_mismatches: AtomicU64::new(0),
        }
    }

    /// A new shared handle.
    #[must_use]
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::new())
    }

    // ── mutation (called from worker tasks) ──────────────────────────────

    pub fn add_bytes(&self, n: u64) {
        self.bytes_transferred.fetch_add(n, Ordering::Relaxed);
    }

    pub fn add_verified_bytes(&self, n: u64) {
        self.bytes_verified.fetch_add(n, Ordering::Relaxed);
    }

    pub fn set_total_bytes(&self, n: u64) {
        self.bytes_total.store(n, Ordering::Relaxed);
    }

    pub fn add_total_bytes(&self, n: u64) {
        self.bytes_total.fetch_add(n, Ordering::Relaxed);
    }

    pub fn file_done(&self) {
        self.files_done.fetch_add(1, Ordering::Relaxed);
    }

    pub fn file_skipped(&self) {
        self.files_skipped.fetch_add(1, Ordering::Relaxed);
    }

    pub fn file_deleted(&self) {
        self.files_deleted.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_total_files(&self, n: u64) {
        self.files_total.store(n, Ordering::Relaxed);
    }

    pub fn add_total_files(&self, n: u64) {
        self.files_total.fetch_add(n, Ordering::Relaxed);
    }

    pub fn check_done(&self) {
        self.checks_done.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_total_checks(&self, n: u64) {
        self.checks_total.store(n, Ordering::Relaxed);
    }

    pub fn error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Count one retry of a whole file.
    ///
    /// Uncalled: `--retries` and `--low-level-retries` parse, and nothing loops
    /// on them yet. Kept because the *report* already has a Retries row wired to
    /// this counter, so the first retry loop has one place to record itself and
    /// one field name to log it under ([`crate::logging::fields::ATTEMPT`]). A
    /// retry loop that invented its own counter would move a number the summary
    /// does not read.
    #[allow(dead_code)]
    pub fn retry(&self) {
        self.retries.fetch_add(1, Ordering::Relaxed);
    }

    pub fn checksum_mismatch(&self) {
        self.checksum_mismatches.fetch_add(1, Ordering::Relaxed);
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    // ── observation (called from the renderer) ───────────────────────────

    /// Take a consistent-enough snapshot for rendering.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        let elapsed = self.started.elapsed().as_secs_f64();
        let transferred = self.bytes_transferred.load(Ordering::Relaxed);
        Snapshot {
            elapsed_secs: elapsed,
            bytes_transferred: transferred,
            bytes_total: self.bytes_total.load(Ordering::Relaxed),
            bytes_verified: self.bytes_verified.load(Ordering::Relaxed),
            files_done: self.files_done.load(Ordering::Relaxed),
            files_total: self.files_total.load(Ordering::Relaxed),
            files_skipped: self.files_skipped.load(Ordering::Relaxed),
            files_deleted: self.files_deleted.load(Ordering::Relaxed),
            checks_done: self.checks_done.load(Ordering::Relaxed),
            checks_total: self.checks_total.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            retries: self.retries.load(Ordering::Relaxed),
            checksum_mismatches: self.checksum_mismatches.load(Ordering::Relaxed),
            // Average rate over the whole run. The live bar shows a smoothed
            // instantaneous rate instead; this one is for the final summary,
            // where the average is the honest number.
            average_rate: if elapsed > 0.0 {
                transferred as f64 / elapsed
            } else {
                0.0
            },
        }
    }

    // No `had_errors` / `transferred_nothing` here on purpose. The exit code is
    // decided in one place, [`crate::ctx::Ctx::outcome`], and it decides from a
    // [`Snapshot`] — one consistent read of every counter — rather than from a
    // series of live loads that can disagree with each other and with the
    // summary printed beside them. A second, live way to ask "did anything
    // fail?" is a second answer waiting to be given.
}

/// An immutable view of the counters at one instant.
#[derive(Clone, Copy, Debug)]
pub struct Snapshot {
    pub elapsed_secs: f64,
    pub bytes_transferred: u64,
    pub bytes_total: u64,
    pub bytes_verified: u64,
    pub files_done: u64,
    pub files_total: u64,
    pub files_skipped: u64,
    pub files_deleted: u64,
    pub checks_done: u64,
    pub checks_total: u64,
    pub errors: u64,
    pub retries: u64,
    pub checksum_mismatches: u64,
    pub average_rate: f64,
}

impl Snapshot {
    /// Whether the run **landed** nothing: no byte moved or verified, no file
    /// done or deleted, no error, retry or mismatch recorded.
    ///
    /// The planning-side counters — `bytes_total`, `files_total`,
    /// `files_skipped`, `checks_done`, `checks_total` — are deliberately not
    /// consulted. They are set by the planner before a single byte moves:
    /// announcements of what was *considered*, not a record of what
    /// *happened*. A `moveto` between two remotes lists its source, accounts
    /// its skips, and only then reaches the refusal in `Engine::connect` — and
    /// under the old every-counter predicate that pre-execution accounting was
    /// enough to print `Checks: 1 / 1` and `Errors: 0` in a table directly
    /// above the refusal telling the reader nothing was done. A refusal is the
    /// whole report; what earns a summary above an error is work that landed.
    ///
    /// It exists so the failure path can suppress the summary. A run that
    /// refused used to print a full statistics block *above* its own error —
    ///
    /// ```text
    ///  Transferred: 0 B / 0 B, -
    ///        Files: 0 / 0
    ///       Errors: 0
    ///      Elapsed: 0s
    /// error: SOURCE-STORE: 'pl:' is not a vault's object store …
    /// ```
    ///
    /// — where `Errors: 0` is not merely noise but a direct contradiction of the
    /// line beneath it, printed first and in a table. On a *successful* run the
    /// same zeroes are a positive statement ("this ran and did nothing"), which
    /// is why the rule is about failure and not about emptiness.
    #[must_use]
    pub const fn nothing_landed(&self) -> bool {
        self.bytes_transferred == 0
            && self.bytes_verified == 0
            && self.files_done == 0
            && self.files_deleted == 0
            && self.errors == 0
            && self.retries == 0
            && self.checksum_mismatches == 0
    }

    /// Completion as a percentage of total bytes, or `None` when the total is
    /// not yet known (a streaming walk has not finished counting).
    #[must_use]
    pub fn percent(&self) -> Option<f64> {
        if self.bytes_total == 0 {
            return None;
        }
        Some((self.bytes_transferred as f64 / self.bytes_total as f64) * 100.0)
    }

    /// Bytes still to move, saturating so a mid-walk total revision cannot
    /// underflow into a nonsense ETA.
    #[must_use]
    pub const fn bytes_remaining(&self) -> u64 {
        self.bytes_total.saturating_sub(self.bytes_transferred)
    }
}

#[cfg(test)]
mod tests {
    use super::{Stage, Stats};

    #[test]
    fn landed_work_defeats_suppression_and_planning_accounting_does_not() {
        // What decides whether a failing run prints a summary above its own
        // error. The two halves are the whole rule: work that LANDED — a byte
        // moved or verified, a file done or deleted, an error, a retry, a
        // mismatch — has a record the error message does not carry, and earns
        // the summary. Accounting the planner did before execution — totals,
        // skips, checks — is an announcement of intent, and a refusal must not
        // be crowned with a table of intentions.
        assert!(Stats::new().snapshot().nothing_landed());

        /// One counter, named, and the call that moves it.
        type Touch = (&'static str, fn(&Stats));

        let landed: [Touch; 6] = [
            ("bytes", |s| s.add_bytes(1)),
            ("verified bytes", |s| s.add_verified_bytes(1)),
            ("a file", Stats::file_done),
            ("a delete", Stats::file_deleted),
            ("a retry", Stats::retry),
            ("an error", Stats::error),
        ];
        for (what, touch) in landed {
            let stats = Stats::new();
            touch(&stats);
            assert!(
                !stats.snapshot().nothing_landed(),
                "a run that recorded {what} landed something and must report it"
            );
        }

        let planning: [Touch; 5] = [
            ("total bytes", |s| s.set_total_bytes(1)),
            ("total files", |s| s.set_total_files(1)),
            ("a skip", Stats::file_skipped),
            ("a check", Stats::check_done),
            ("total checks", |s| s.set_total_checks(1)),
        ];
        for (what, touch) in planning {
            let stats = Stats::new();
            touch(&stats);
            assert!(
                stats.snapshot().nothing_landed(),
                "planning-side accounting ({what}) must not earn a summary \
                 above a refusal — the moveto counter-block defect"
            );
        }
    }

    #[test]
    fn counters_accumulate() {
        let stats = Stats::new();
        stats.set_total_files(3);
        stats.set_total_bytes(3000);
        stats.add_bytes(1000);
        stats.file_done();

        let snap = stats.snapshot();
        assert_eq!(snap.bytes_transferred, 1000);
        assert_eq!(snap.bytes_total, 3000);
        assert_eq!(snap.files_done, 1);
        assert_eq!(snap.files_total, 3);
        assert!((snap.percent().unwrap() - 33.333).abs() < 0.01);
    }

    #[test]
    fn percent_is_unknown_before_the_total_is_counted() {
        let stats = Stats::new();
        stats.add_bytes(500);
        assert_eq!(stats.snapshot().percent(), None);
    }

    #[test]
    fn remaining_saturates_when_the_total_is_revised_down() {
        let stats = Stats::new();
        stats.set_total_bytes(100);
        stats.add_bytes(500);
        // A streaming walk can revise the total; this must not underflow.
        assert_eq!(stats.snapshot().bytes_remaining(), 0);
    }

    #[test]
    fn a_checksum_mismatch_also_counts_as_an_error() {
        let stats = Stats::new();
        stats.checksum_mismatch();
        let snap = stats.snapshot();
        assert_eq!(snap.checksum_mismatches, 1);
        assert_eq!(snap.errors, 1, "a mismatch must never be silently absorbed");
    }

    #[test]
    fn a_clean_run_reports_no_errors() {
        let stats = Stats::new();
        stats.file_done();
        let snap = stats.snapshot();
        assert_eq!(snap.errors, 0);
        assert_eq!(snap.files_done, 1);
    }

    #[test]
    fn stage_labels_are_stable() {
        assert_eq!(Stage::Verifying.label(), "verify");
        assert_eq!(Stage::Committing.label(), "commit");
    }
}
