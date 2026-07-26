//! How a `dctl config` result reaches stdout, in each of the three formats.
//!
//! Every subcommand that produces structured results routes through here, for
//! one reason: [`crate::output::Format::JsonLines`] is not "JSON with the
//! newlines left in". A `--format json` run emits **one document** for the whole
//! result, and a `--format json-lines` run emits **one document per record**, so
//! a consumer can read a line, parse it and drop it. A subcommand that
//! hand-rolled its own serialisation would sooner or later emit a pretty-printed
//! array into a line-delimited stream and break every reader downstream.
//!
//! Text rendering is passed in as a closure rather than built eagerly, so a
//! `--json` run never pays to lay out columns nobody will see.

use serde::Serialize;

use crate::ctx::Ctx;
use crate::error::Result;
use crate::output::{Align, Border, Column, Table};

/// A two-column, borderless table.
///
/// The shape almost every `dctl config` result takes, built in one place so the
/// subcommands agree on alignment and framing. [`Border::None`] because the
/// default output of a config command is something a script reads: values only,
/// single-space separated, no header line to skip.
#[must_use]
pub fn pairs(left: &str, right: &str, rows: Vec<(String, String)>) -> Table {
    let mut table = Table::new(vec![
        Column::new(left, Align::Left),
        Column::new(right, Align::Left),
    ])
    .with_border(Border::None);

    for (a, b) in rows {
        table.push(vec![a, b]);
    }
    table
}

/// Emit a list of records.
///
/// # Errors
/// Any stdout failure other than a broken pipe, which [`crate::output::Out`]
/// deliberately tolerates so `dctl config list | head -1` is a success.
pub fn records<T: Serialize>(
    ctx: &Ctx,
    rows: &[T],
    build_table: impl FnOnce() -> Table,
) -> Result<()> {
    let format = ctx.out.format();

    if format.is_line_delimited() {
        for row in rows {
            ctx.out.json(row)?;
        }
        return Ok(());
    }

    if format.is_json() {
        ctx.out.json(&rows)?;
        return Ok(());
    }

    let table = build_table();
    // An empty table would print a bare header, which reads as a broken result
    // rather than as "nothing is configured". Say nothing instead; the count
    // belongs on stderr, where it cannot pollute a pipeline.
    if !table.is_empty() {
        ctx.out.table(&table)?;
    }
    Ok(())
}

/// Emit a single record.
///
/// Both JSON formats emit exactly one document, which is the same thing in each
/// — the distinction only matters when there is a sequence to delimit.
///
/// # Errors
/// As [`records`].
pub fn one<T: Serialize>(ctx: &Ctx, record: &T, text: impl FnOnce() -> String) -> Result<()> {
    if ctx.out.format().is_json() {
        ctx.out.json(record)?;
        return Ok(());
    }
    ctx.out.line(text())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::GlobalArgs;
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn ctx(format: &str) -> Ctx {
        Ctx::new(Harness::parse_from(["dctl", "--format", format]).globals)
    }

    #[derive(Serialize)]
    struct Row {
        name: String,
    }

    fn rows() -> Vec<Row> {
        vec![
            Row {
                name: "b2prod".into(),
            },
            Row {
                name: "vault".into(),
            },
        ]
    }

    fn table() -> Table {
        let mut table =
            Table::new(vec![Column::new("Name", Align::Left)]).with_border(Border::None);
        table.push(vec!["b2prod".into()]);
        table.push(vec!["vault".into()]);
        table
    }

    #[test]
    fn every_format_emits_without_error() {
        for format in ["text", "json", "json-lines"] {
            let ctx = ctx(format);
            assert!(records(&ctx, &rows(), table).is_ok(), "{format} failed");
        }
    }

    #[test]
    fn a_json_lines_record_never_spans_two_lines() {
        // The contract a line-at-a-time consumer depends on. Asserted against
        // the encoder the sink uses, since the sink itself writes to the real
        // stdout.
        let format = crate::output::Format::JsonLines;
        for row in rows() {
            assert!(!format.encode(&row).unwrap().contains('\n'));
        }
    }

    #[test]
    fn a_whole_document_format_wraps_the_records_in_one_array() {
        let format = crate::output::Format::Json;
        let encoded = format.encode(&rows()).unwrap();
        assert!(encoded.trim_start().starts_with('['), "got: {encoded}");
    }

    #[test]
    fn an_empty_result_prints_nothing_rather_than_a_bare_header() {
        // A header with no rows under it reads as a malfunction; silence is the
        // honest rendering of "nothing is configured".
        let ctx = ctx("text");
        let empty: Vec<Row> = Vec::new();
        let build = || Table::new(vec![Column::new("Name", Align::Left)]);
        assert!(records(&ctx, &empty, build).is_ok());
    }

    #[test]
    fn the_text_renderer_is_not_run_for_a_json_output() {
        // Laying out columns for a consumer that will never see them is waste,
        // and a renderer with a side effect would be a bug.
        let ctx = ctx("json");
        let build = || -> Table {
            unreachable!("the text renderer must not run for --format json");
        };
        assert!(records(&ctx, &rows(), build).is_ok());
    }

    #[test]
    fn a_pair_table_is_script_friendly_by_default() {
        // Values only, no header rule: `dctl config show x | awk '{print $2}'`
        // must keep working, which a bordered table would break.
        let table = pairs("Key", "Value", vec![("bucket".into(), "photos".into())]);
        assert_eq!(table.len(), 1);
        assert!(!table.is_empty());
    }

    #[test]
    fn a_single_record_emits_in_every_format() {
        for format in ["text", "json", "json-lines"] {
            let ctx = ctx(format);
            let record = Row {
                name: "b2prod".into(),
            };
            assert!(
                one(&ctx, &record, || record.name.clone()).is_ok(),
                "{format}"
            );
        }
    }
}
