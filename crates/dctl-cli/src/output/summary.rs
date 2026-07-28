//! The end-of-run report.
//!
//! This is the last thing a user reads after a transfer, so which rows exist —
//! and which are hidden — is domain logic, not formatting trivia:
//!
//! * *Transferred* and *Verified* are separate rows. Bytes that have been
//!   uploaded but not yet checksum-confirmed are **not yet durable**, and
//!   collapsing the two into one number is exactly the misreporting the
//!   verified-write contract (`PLAN.md` §6) exists to prevent.
//! * *Errors* is always shown, including as `0`, because a missing row could be
//!   read as "nothing failed" when it really meant "nobody rendered it".
//! * The optional rows — *Verified*, *Checks*, *Skipped*, *Deleted*, *Retries*,
//!   *Mismatches* — appear only when their counter moved. A run that skipped and
//!   deleted nothing should not have to prove it with two zero rows; noise here
//!   trains people to stop reading the report.
//! * A checksum mismatch is always rendered in the error style, even though it
//!   is also counted under *Errors*. It is the one failure that means the
//!   destination gave us back bytes we did not send, and it must be impossible
//!   to skim past.
//!
//! Row selection ([`rows`]) is deliberately separated from painting
//! ([`render`]): the selection rules are the part worth testing, and they are
//! testable only if choosing a row does not require a terminal.

use anstream::eprintln as astyle_eprintln;

use crate::constants::{
    SUMMARY_LABEL_CHECKS, SUMMARY_LABEL_DELETED, SUMMARY_LABEL_ELAPSED, SUMMARY_LABEL_ERRORS,
    SUMMARY_LABEL_FILES, SUMMARY_LABEL_MISMATCHES, SUMMARY_LABEL_RETRIES, SUMMARY_LABEL_SKIPPED,
    SUMMARY_LABEL_TRANSFERRED, SUMMARY_LABEL_VERIFIED, SUMMARY_LABEL_WIDTH, SUMMARY_MISMATCH_NOTE,
    SUMMARY_PERCENT_DECIMALS, SUMMARY_SKIPPED_NOTE, SUMMARY_VERIFIED_NOTE,
};

use super::color::Palette;
use super::sink::Out;
use super::size::{self, Units};
use super::stats::Snapshot;

/// How much attention a row's value demands.
///
/// Carried on the row itself rather than re-derived from the label at paint
/// time: a string comparison against `"Errors"` would silently stop alarming the
/// moment someone reworded the label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Emphasis {
    /// An ordinary figure.
    Normal,
    /// A figure that reports damage — painted in the error style so it cannot be
    /// skimmed past.
    Alarm,
}

/// One label/value pair of the report.
#[derive(Debug)]
pub struct Row {
    /// Left-hand label, right-aligned into [`SUMMARY_LABEL_WIDTH`] columns.
    pub label: &'static str,
    /// Pre-formatted value, already in the caller's chosen units.
    pub value: String,
    /// Whether the value is bad news.
    pub emphasis: Emphasis,
}

impl Row {
    /// An ordinary row.
    fn normal(label: &'static str, value: impl Into<String>) -> Self {
        Self {
            label,
            value: value.into(),
            emphasis: Emphasis::Normal,
        }
    }

    /// A row reporting damage.
    fn alarm(label: &'static str, value: impl Into<String>) -> Self {
        Self {
            label,
            value: value.into(),
            emphasis: Emphasis::Alarm,
        }
    }
}

/// Build the rows for a snapshot, in display order.
///
/// Pure: no terminal, no styling, no I/O — so the selection rules above can be
/// asserted directly. `units` decides whether sizes read as the operating
/// system reports them (binary) or as the provider bills them (decimal).
#[must_use]
pub fn rows(snapshot: &Snapshot, units: Units) -> Vec<Row> {
    let mut rows = Vec::new();

    // Omitted, rather than faked, while a streaming walk is still counting the
    // work: "0%" of an unknown total would be a lie. Carries its own separator
    // so the row reads correctly with or without it.
    let percent = snapshot.percent().map_or_else(String::new, |percent| {
        format!(", {percent:.SUMMARY_PERCENT_DECIMALS$}%")
    });
    let transferred = size::bytes(snapshot.bytes_transferred, units);
    let total = size::bytes(snapshot.bytes_total, units);
    let rate = size::rate(snapshot.average_rate, units);
    rows.push(Row::normal(
        SUMMARY_LABEL_TRANSFERRED,
        format!("{transferred} / {total}{percent}, {rate}"),
    ));

    if snapshot.bytes_verified > 0 {
        rows.push(Row::normal(
            SUMMARY_LABEL_VERIFIED,
            format!(
                "{} {SUMMARY_VERIFIED_NOTE}",
                size::bytes(snapshot.bytes_verified, units)
            ),
        ));
    }

    rows.push(Row::normal(
        SUMMARY_LABEL_FILES,
        format!(
            "{} / {}",
            size::count(snapshot.files_done),
            size::count(snapshot.files_total)
        ),
    ));

    if snapshot.checks_total > 0 {
        rows.push(Row::normal(
            SUMMARY_LABEL_CHECKS,
            format!(
                "{} / {}",
                size::count(snapshot.checks_done),
                size::count(snapshot.checks_total)
            ),
        ));
    }
    if snapshot.files_skipped > 0 {
        rows.push(Row::normal(
            SUMMARY_LABEL_SKIPPED,
            format!(
                "{} {SUMMARY_SKIPPED_NOTE}",
                size::count(snapshot.files_skipped)
            ),
        ));
    }
    if snapshot.files_deleted > 0 {
        rows.push(Row::normal(
            SUMMARY_LABEL_DELETED,
            size::count(snapshot.files_deleted),
        ));
    }
    if snapshot.retries > 0 {
        rows.push(Row::normal(
            SUMMARY_LABEL_RETRIES,
            size::count(snapshot.retries),
        ));
    }
    if snapshot.checksum_mismatches > 0 {
        rows.push(Row::alarm(
            SUMMARY_LABEL_MISMATCHES,
            format!(
                "{} {SUMMARY_MISMATCH_NOTE}",
                size::count(snapshot.checksum_mismatches)
            ),
        ));
    }

    // Always present, in both directions: a zero here is a positive statement
    // that nothing failed.
    let errors = size::count(snapshot.errors);
    rows.push(if snapshot.errors > 0 {
        Row::alarm(SUMMARY_LABEL_ERRORS, errors)
    } else {
        Row::normal(SUMMARY_LABEL_ERRORS, errors)
    });

    rows.push(Row::normal(
        SUMMARY_LABEL_ELAPSED,
        // `as` saturates on overflow and elapsed time is never negative, so the
        // cast cannot wrap into a nonsense duration.
        size::duration(snapshot.elapsed_secs.round() as u64),
    ));

    rows
}

/// The report as plain, unstyled lines.
///
/// The periodic status record `--stats` emits, which is the same report as the
/// end-of-run one and is deliberately built from the same [`rows`]. Two
/// renderers over one row list rather than two independent formatters: a
/// periodic line that disagreed with the summary it precedes would make a reader
/// distrust both, and the disagreement would arrive the first time a row was
/// added to one of them.
///
/// Unstyled because this is written into a log a machine or a human reads later,
/// where escape sequences are noise. The end-of-run [`render`] keeps its colour;
/// it is read on a terminal, once.
#[must_use]
pub fn lines(snapshot: &Snapshot, units: Units) -> Vec<String> {
    rows(snapshot, units)
        .iter()
        .map(|row| format!("{:>SUMMARY_LABEL_WIDTH$}: {}", row.label, row.value))
        .collect()
}

/// Paint one row into a finished line.
///
/// Split out of [`render`] so the styling decision is inspectable without a
/// terminal: an alarmed row must carry the error style, and a plain sink must
/// carry no escape sequences at all.
fn render_row(row: &Row, palette: &Palette) -> String {
    let dim = palette.dim();
    let value = match row.emphasis {
        Emphasis::Normal => {
            let bold = palette.header();
            format!("{bold}{}{bold:#}", row.value)
        }
        Emphasis::Alarm => {
            let error = palette.error();
            format!("{error}{}{error:#}", row.value)
        }
    };
    let label = row.label;
    format!("{dim}{label:>SUMMARY_LABEL_WIDTH$}:{dim:#} {value}")
}

/// Write the report to **stderr**.
///
/// Stderr, not stdout, so `dctl lsjson vault: | jq` and `dctl cat … | ffplay -`
/// stay clean while the report is printed. Suppressed entirely under `--quiet`,
/// and under a JSON format where the machine-readable result already carries
/// every one of these numbers — printing them twice, in two shapes, is how the
/// two copies start to disagree.
pub fn render(out: &Out, snapshot: &Snapshot) {
    if out.is_quiet() || out.is_json() {
        return;
    }

    let palette = out.palette();
    astyle_eprintln!();
    for row in rows(snapshot, out.units()) {
        astyle_eprintln!("{}", render_row(&row, palette));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::{ColorChoice, Format, Stats};

    /// Find a row by label, if it was rendered at all.
    fn find<'a>(rows: &'a [Row], label: &str) -> Option<&'a Row> {
        rows.iter().find(|row| row.label == label)
    }

    fn labels(rows: &[Row]) -> Vec<&'static str> {
        rows.iter().map(|row| row.label).collect()
    }

    /// A run that moved two files cleanly and did nothing else.
    fn clean_run() -> Snapshot {
        let stats = Stats::new();
        stats.set_total_bytes(2048);
        stats.set_total_files(2);
        stats.add_bytes(2048);
        stats.file_done();
        stats.file_done();
        stats.snapshot()
    }

    #[test]
    fn a_clean_run_shows_only_the_always_on_rows() {
        let rows = rows(&clean_run(), Units::Binary);
        assert_eq!(
            labels(&rows),
            vec![
                SUMMARY_LABEL_TRANSFERRED,
                SUMMARY_LABEL_FILES,
                SUMMARY_LABEL_ERRORS,
                SUMMARY_LABEL_ELAPSED,
            ],
            "zero-valued optional rows are noise and must be omitted"
        );
    }

    #[test]
    fn optional_rows_appear_exactly_when_their_counter_moves() {
        for label in [
            SUMMARY_LABEL_SKIPPED,
            SUMMARY_LABEL_DELETED,
            SUMMARY_LABEL_RETRIES,
            SUMMARY_LABEL_CHECKS,
            SUMMARY_LABEL_VERIFIED,
            SUMMARY_LABEL_MISMATCHES,
        ] {
            assert!(
                find(&rows(&clean_run(), Units::Binary), label).is_none(),
                "'{label}' must be hidden while its counter is zero"
            );
        }

        let stats = Stats::new();
        stats.file_skipped();
        stats.file_deleted();
        stats.retry();
        stats.set_total_checks(3);
        stats.check_done();
        stats.add_verified_bytes(1024);
        stats.checksum_mismatch();
        let rows = rows(&stats.snapshot(), Units::Binary);

        for label in [
            SUMMARY_LABEL_SKIPPED,
            SUMMARY_LABEL_DELETED,
            SUMMARY_LABEL_RETRIES,
            SUMMARY_LABEL_CHECKS,
            SUMMARY_LABEL_VERIFIED,
            SUMMARY_LABEL_MISMATCHES,
        ] {
            assert!(
                find(&rows, label).is_some(),
                "'{label}' must appear once its counter is non-zero"
            );
        }
    }

    #[test]
    fn skipped_and_deleted_report_the_real_counts() {
        let stats = Stats::new();
        for _ in 0..1200 {
            stats.file_skipped();
        }
        stats.file_deleted();
        let rows = rows(&stats.snapshot(), Units::Binary);

        let skipped = find(&rows, SUMMARY_LABEL_SKIPPED).unwrap();
        // Thousands separators and the qualifier that says a skip is a proof of
        // sameness, not an omission.
        assert_eq!(skipped.value, format!("1,200 {SUMMARY_SKIPPED_NOTE}"));
        assert_eq!(find(&rows, SUMMARY_LABEL_DELETED).unwrap().value, "1");
    }

    #[test]
    fn transferred_and_verified_stay_separate_numbers() {
        // The core of PLAN.md §6: uploaded is not the same as durable, so the
        // report must never merge them.
        let stats = Stats::new();
        stats.set_total_bytes(4096);
        stats.add_bytes(4096);
        stats.add_verified_bytes(1024);
        let rows = rows(&stats.snapshot(), Units::Binary);

        let transferred = find(&rows, SUMMARY_LABEL_TRANSFERRED).unwrap();
        let verified = find(&rows, SUMMARY_LABEL_VERIFIED).unwrap();
        assert!(
            transferred.value.starts_with("4.00 KiB"),
            "got: {}",
            transferred.value
        );
        assert_eq!(verified.value, format!("1.00 KiB {SUMMARY_VERIFIED_NOTE}"));
    }

    #[test]
    fn a_checksum_mismatch_is_always_alarmed() {
        let stats = Stats::new();
        stats.checksum_mismatch();
        let rows = rows(&stats.snapshot(), Units::Binary);
        let mismatch = find(&rows, SUMMARY_LABEL_MISMATCHES).unwrap();

        assert_eq!(mismatch.emphasis, Emphasis::Alarm);
        // And it says what a mismatch actually means for the user's data.
        assert!(mismatch.value.contains(SUMMARY_MISMATCH_NOTE));
    }

    #[test]
    fn the_error_row_alarms_only_when_something_failed() {
        let clean = rows(&clean_run(), Units::Binary);
        let errors = find(&clean, SUMMARY_LABEL_ERRORS).unwrap();
        assert_eq!(errors.emphasis, Emphasis::Normal);
        assert_eq!(errors.value, "0", "a zero must still be stated out loud");

        let stats = Stats::new();
        stats.error();
        let failed = rows(&stats.snapshot(), Units::Binary);
        assert_eq!(
            find(&failed, SUMMARY_LABEL_ERRORS).unwrap().emphasis,
            Emphasis::Alarm
        );
    }

    /// The transferred row's value, which is where the percentage and the units
    /// both show up.
    fn transferred_value(snapshot: &Snapshot, units: Units) -> String {
        find(&rows(snapshot, units), SUMMARY_LABEL_TRANSFERRED)
            .map(|row| row.value.clone())
            .unwrap_or_default()
    }

    #[test]
    fn percent_is_omitted_until_the_total_is_known() {
        let counting = Stats::new();
        counting.add_bytes(500);
        let mid_walk = transferred_value(&counting.snapshot(), Units::Binary);
        assert!(
            !mid_walk.contains('%'),
            "a percentage of an unknown total would be invented: {mid_walk}"
        );

        let finished = transferred_value(&clean_run(), Units::Binary);
        assert!(finished.contains("100%"), "got: {finished}");
    }

    #[test]
    fn units_follow_the_caller_not_the_counters() {
        let stats = Stats::new();
        stats.set_total_bytes(1000);
        stats.add_bytes(1000);
        let snapshot = stats.snapshot();
        // The same counters, read as the OS reports them and as a provider
        // bills them.
        let binary = transferred_value(&snapshot, Units::Binary);
        let decimal = transferred_value(&snapshot, Units::Decimal);
        assert!(binary.contains("1000 B"), "got: {binary}");
        assert!(decimal.contains("1.00 kB"), "got: {decimal}");
    }

    #[test]
    fn an_alarmed_row_carries_the_error_style() {
        let palette = Palette::new(true);
        let alarmed = render_row(&Row::alarm(SUMMARY_LABEL_MISMATCHES, "1"), &palette);
        let normal = render_row(&Row::normal(SUMMARY_LABEL_FILES, "1"), &palette);

        let error_style = format!("{}", palette.error());
        assert!(!error_style.is_empty(), "the test needs a styled palette");
        assert!(alarmed.contains(&error_style), "got: {alarmed:?}");
        assert!(!normal.contains(&error_style), "got: {normal:?}");
    }

    #[test]
    fn a_plain_palette_emits_no_escape_sequences() {
        // Redirected to a file or a CI log, the report must stay plain text.
        let plain = Palette::plain();
        for row in rows(&clean_run(), Units::Binary) {
            let line = render_row(&row, &plain);
            assert!(!line.contains('\u{1b}'), "got: {line:?}");
        }
    }

    #[test]
    fn labels_are_right_aligned_into_a_fixed_column() {
        // Values must start in the same column on every row, or the report stops
        // being readable as a table.
        let plain = Palette::plain();
        let lines: Vec<String> = rows(&clean_run(), Units::Binary)
            .iter()
            .map(|row| render_row(row, &plain))
            .collect();
        for line in &lines {
            assert_eq!(line.find(':'), Some(SUMMARY_LABEL_WIDTH), "got: {line:?}");
        }
    }

    #[test]
    fn rendering_is_suppressed_for_quiet_and_json_sinks() {
        // Smoke test: no configuration may panic, and the machine formats stay
        // clean because the JSON result already carries these numbers.
        let snapshot = clean_run();
        let quiet = Out::new(Format::Text, ColorChoice::Never, Units::Binary, true, 0);
        let json = Out::new(Format::Json, ColorChoice::Never, Units::Binary, false, 0);
        quiet.summary(&snapshot);
        json.summary(&snapshot);
        Out::plain().summary(&snapshot);
    }
}
