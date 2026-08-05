//! Bar templates: the layout of the aggregate row and of a per-file row.
//!
//! Two rules govern everything here.
//!
//! **A template failure must never be fatal.** `ProgressStyle::with_template`
//! returns an error for a malformed template, and the library forbids panics
//! ([the plan](https://doc.dctl.sh/project/plan) §16.5), so a mistake falls
//! back to indicatif's default bar. A transfer that is otherwise going fine
//! must not be killed by a formatting typo. The templates are still checked by
//! tests, so the fallback is a safety net rather than a licence to ship a
//! broken layout.
//!
//! **Column widths come from [`crate::constants`].** Every width in a template
//! is interpolated, never typed into the string, because the aggregate and
//! per-file rows have to stay aligned with each other and with the summary.

use indicatif::ProgressStyle;

use super::charset::Charset;
use crate::constants::{
    AGGREGATE_BAR_WIDTH, FILE_BAR_WIDTH, FILE_BYTES_COLUMN_WIDTH, FILE_LABEL_WIDTH,
    PERCENT_FIELD_WIDTH,
};

/// Layout of the aggregate bar: spinner, label, bar, percentage, bytes moved out
/// of bytes total, current rate, ETA, and a trailing free-form message.
///
/// Kept separate from [`aggregate_style`] so the template can be parsed in a
/// test without building a whole `ProgressStyle`, which is what makes the
/// fallback path testable at all.
fn aggregate_template() -> String {
    format!(
        "{{spinner:.green}} {{prefix:.bold}} [{{bar:{AGGREGATE_BAR_WIDTH}.cyan/blue}}] \
         {{percent:>{PERCENT_FIELD_WIDTH}}}% {{binary_bytes}}/{{binary_total_bytes}} \
         @ {{binary_bytes_per_sec}} ETA {{eta}} {{wide_msg}}"
    )
}

/// Layout of a per-file bar. Indented under the aggregate, with the filename in
/// a fixed-width column so the bars of concurrent transfers line up vertically,
/// and a trailing `{msg}` carrying the pipeline stage.
fn file_template() -> String {
    format!(
        "  {{prefix:<{FILE_LABEL_WIDTH}}} [{{bar:{FILE_BAR_WIDTH}.cyan/blue}}] \
         {{percent:>{PERCENT_FIELD_WIDTH}}}% \
         {{binary_bytes:>{FILE_BYTES_COLUMN_WIDTH}}}/\
         {{binary_total_bytes:<{FILE_BYTES_COLUMN_WIDTH}}} {{msg:.dim}}"
    )
}

/// Style for the aggregate bar.
///
/// Falls back to indicatif's default bar if the template ever fails to parse, so
/// a formatting mistake degrades the display instead of killing a transfer.
pub(super) fn aggregate_style(charset: &Charset) -> ProgressStyle {
    build(&aggregate_template(), charset)
}

/// Style for a per-file bar.
///
/// The trailing `{msg}` is the row that makes DCTL's guarantee visible: it
/// carries the verified-write stage (`read` → `encrypt` → `upload` → `verify` →
/// `commit`) from [the plan](https://doc.dctl.sh/project/plan) §6, so a user
/// can see that an uploaded file is not yet a committed one.
pub(super) fn file_style(charset: &Charset) -> ProgressStyle {
    build(&file_template(), charset)
}

/// Parse a template and dress it in the chosen glyphs.
///
/// The fallback lives here, in one place, so both bars degrade identically
/// rather than one silently keeping its glyphs while the other loses them.
fn build(template: &str, charset: &Charset) -> ProgressStyle {
    ProgressStyle::with_template(template)
        .unwrap_or_else(|_| ProgressStyle::default_bar())
        .progress_chars(charset.progress_chars)
        .tick_strings(charset.tick_strings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_templates_actually_parse() {
        // The real regression guard: a typo would otherwise be invisible, since
        // the fallback silently replaces the layout with indicatif's default.
        assert!(
            ProgressStyle::with_template(&aggregate_template()).is_ok(),
            "aggregate template must parse: {}",
            aggregate_template()
        );
        assert!(
            ProgressStyle::with_template(&file_template()).is_ok(),
            "file template must parse: {}",
            file_template()
        );
    }

    #[test]
    fn templates_use_the_configured_widths() {
        // Widths must come from constants; a literal typed into the string would
        // drift the moment the constant changed.
        let aggregate = aggregate_template();
        assert!(aggregate.contains(&format!("bar:{AGGREGATE_BAR_WIDTH}")));
        assert!(aggregate.contains(&format!("percent:>{PERCENT_FIELD_WIDTH}")));

        let file = file_template();
        assert!(file.contains(&format!("bar:{FILE_BAR_WIDTH}")));
        assert!(file.contains(&format!("prefix:<{FILE_LABEL_WIDTH}")));
        assert!(file.contains(&format!("percent:>{PERCENT_FIELD_WIDTH}")));
        assert!(file.contains(&format!("binary_bytes:>{FILE_BYTES_COLUMN_WIDTH}")));
    }

    #[test]
    fn the_aggregate_reports_rate_and_eta() {
        // These two fields are the reason the aggregate bar exists: without them
        // it says less than the final summary already does.
        let template = aggregate_template();
        assert!(template.contains("binary_bytes_per_sec"));
        assert!(template.contains("eta"));
    }

    #[test]
    fn a_file_row_carries_its_pipeline_stage() {
        // `{msg}` is where the verified-write stage is rendered
        // ([the plan](https://doc.dctl.sh/project/plan) §6);
        // dropping it would hide the difference between uploaded and committed.
        assert!(file_template().contains("{msg"));
    }

    #[test]
    fn styles_build_with_either_glyph_set() {
        // Smoke test across both charsets: neither may panic, and a bad template
        // must still yield a usable style.
        for charset in [Charset::ASCII, Charset::UNICODE] {
            let _ = aggregate_style(&charset);
            let _ = file_style(&charset);
        }
    }

    #[test]
    fn a_broken_template_degrades_instead_of_failing() {
        // `{nonsense` is unclosed and cannot parse; `build` must still hand back
        // a style rather than propagating an error into a running transfer.
        let _ = build("{unterminated", &Charset::ASCII);
    }
}
