//! What a removal *would* do, rendered in every output format.
//!
//! A plan is not a result. It carries no counters and never claims that
//! anything was removed — [the plan](https://doc.dctl.sh/project/plan) §6
//! forbids reporting work that did not happen, and a document containing
//! `"files_deleted": 0` beside an operation
//! that never ran would be exactly that lie. The JSON shape is deliberately
//! limited to the *request*: which command, which target, which filters, which
//! options, and a `status` that says the run got as far as planning.
//!
//! Rendering lives here rather than in each command because all six removals
//! answer the same question in the same shape, and a user who has read one
//! `--dry-run` has read them all. Text gets an aligned two-column table; JSON
//! gets one document; JSON Lines gets that document on a single line, because a
//! plan is one record and the newline is the record separator.

use serde::Serialize;

use crate::constants::{
    REMOVAL_BOOL_NO, REMOVAL_BOOL_YES, REMOVAL_COLUMN_FIELD, REMOVAL_COLUMN_VALUE,
    REMOVAL_LABEL_COMMAND, REMOVAL_LABEL_MODE, REMOVAL_LABEL_TARGET, REMOVAL_MODE_DRY_RUN,
    REMOVAL_MODE_EXECUTE, REMOVAL_STATUS_PLANNED,
};
use crate::ctx::Ctx;
use crate::error::Result;
use crate::output::{Align, Column, Format, Table, Units};

use super::filters::Filters;
use super::target::Target;

/// One label/value pair in the text rendering of a plan.
pub type Row = (&'static str, String);

/// Per-command options that a plan can display and serialise.
///
/// Implemented by each command's own options struct rather than modelled as a
/// bag of strings, so `--rmdirs` is a `bool` in the JSON and a row in the table
/// without either spelling being written twice.
pub trait PlanOptions: Serialize {
    /// Label/value rows for the text rendering, in display order.
    fn rows(&self) -> Vec<Row>;
}

/// A command with no options of its own.
///
/// Serialises as an empty object so the `options` key is always present and a
/// consumer never has to branch on its absence.
#[derive(Debug, Default, Serialize)]
pub struct NoOptions {}

impl PlanOptions for NoOptions {
    fn rows(&self) -> Vec<Row> {
        Vec::new()
    }
}

/// The resolved request for one removal.
#[derive(Debug, Serialize)]
pub struct Plan<'a, O: PlanOptions> {
    /// Stable command name, matching `Command::name()` in `cli/mod.rs`.
    pub command: &'static str,
    pub target: &'a Target,
    /// Whether this run was forbidden from changing anything.
    pub dry_run: bool,
    /// Absent for the commands that document themselves as ignoring filters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filters: Option<&'a Filters>,
    pub options: &'a O,
    /// How far the run got. Never "done": a plan is not an outcome.
    pub status: &'static str,
}

impl<'a, O: PlanOptions> Plan<'a, O> {
    /// Assemble a plan. `status` is fixed rather than a parameter — this type
    /// exists only to describe an operation that has not run.
    #[must_use]
    pub fn new(
        command: &'static str,
        target: &'a Target,
        dry_run: bool,
        filters: Option<&'a Filters>,
        options: &'a O,
    ) -> Self {
        Self {
            command,
            target,
            dry_run,
            filters,
            options,
            status: REMOVAL_STATUS_PLANNED,
        }
    }

    /// Every row of the text rendering, in display order.
    #[must_use]
    fn rows(&self, units: Units) -> Vec<Row> {
        let mut rows = vec![
            (REMOVAL_LABEL_COMMAND, self.command.to_string()),
            (REMOVAL_LABEL_TARGET, self.target.to_string()),
            (
                REMOVAL_LABEL_MODE,
                if self.dry_run {
                    REMOVAL_MODE_DRY_RUN
                } else {
                    REMOVAL_MODE_EXECUTE
                }
                .to_string(),
            ),
        ];
        if let Some(filters) = self.filters {
            rows.extend(filters.rows(units));
        }
        rows.extend(self.options.rows());
        rows
    }
}

/// Write a plan to stdout in the format the run asked for.
///
/// Stdout, not stderr: under `--dry-run` the plan *is* the command's data, and
/// `dctl delete --dry-run --json vault:x | jq` has to work.
///
/// # Errors
/// Propagates a stdout write failure. A closed pipe is not one — the sink
/// already treats that as success.
pub fn emit<O: PlanOptions>(ctx: &Ctx, plan: &Plan<'_, O>) -> Result<()> {
    match ctx.out.format() {
        Format::Text => {
            let mut table = Table::new(vec![
                Column::new(REMOVAL_COLUMN_FIELD, Align::Left),
                Column::new(REMOVAL_COLUMN_VALUE, Align::Left),
            ]);
            for (label, value) in plan.rows(ctx.out.units()) {
                table.push(vec![label.to_string(), value]);
            }
            ctx.out.table(&table)?;
        }
        Format::Json | Format::JsonLines => ctx.out.json(plan)?,
    }
    Ok(())
}

/// Render a flag for the text plan.
///
/// Shares its vocabulary with the destructive confirmation prompt, so "yes"
/// means the same thing everywhere the user reads it.
#[must_use]
pub fn yes_no(value: bool) -> String {
    if value {
        REMOVAL_BOOL_YES
    } else {
        REMOVAL_BOOL_NO
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::globals::GlobalArgs;
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn ctx(args: &[&str]) -> Ctx {
        Ctx::new(Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied())).globals)
    }

    fn filters(args: &[&str]) -> Filters {
        Filters::resolve(
            &Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied())).globals,
        )
        .unwrap()
    }

    #[derive(Debug, Serialize)]
    struct TestOptions {
        rmdirs: bool,
    }

    impl PlanOptions for TestOptions {
        fn rows(&self) -> Vec<Row> {
            vec![("Empty directories", yes_no(self.rmdirs))]
        }
    }

    #[test]
    fn a_plan_reports_the_request_and_never_a_result() {
        let target = Target::parse("vault:photos").unwrap();
        let options = TestOptions { rmdirs: true };
        let plan = Plan::new("delete", &target, true, None, &options);
        let value = serde_json::to_value(&plan).unwrap();

        assert_eq!(value["command"], "delete");
        assert_eq!(value["target"]["path"], "photos");
        assert_eq!(value["dry_run"], true);
        assert_eq!(value["options"]["rmdirs"], true);
        assert_eq!(value["status"], REMOVAL_STATUS_PLANNED);
        // The load-bearing absence: no counter may imply completed work.
        assert!(value.get("files_deleted").is_none());
        assert!(value.get("deleted").is_none());
    }

    #[test]
    fn absent_filters_are_omitted_entirely() {
        let target = Target::parse("vault:").unwrap();
        let plan = Plan::new("purge", &target, false, None, &NoOptions {});
        let value = serde_json::to_value(&plan).unwrap();
        assert!(value.get("filters").is_none());
        assert_eq!(value["options"], serde_json::json!({}));
    }

    #[test]
    fn present_filters_are_carried_into_the_document() {
        let target = Target::parse("vault:photos").unwrap();
        let filters = filters(&["--include", "*.jpg"]);
        let plan = Plan::new("delete", &target, false, Some(&filters), &NoOptions {});
        let value = serde_json::to_value(&plan).unwrap();
        assert_eq!(value["filters"]["include"][0], "*.jpg");
    }

    #[test]
    fn the_text_rows_lead_with_command_target_and_mode() {
        let target = Target::parse("vault:photos").unwrap();
        let filters = filters(&["--include", "*.jpg"]);
        let options = TestOptions { rmdirs: false };
        let plan = Plan::new("delete", &target, true, Some(&filters), &options);
        let rows = plan.rows(Units::Binary);

        assert_eq!(rows[0], (REMOVAL_LABEL_COMMAND, "delete".to_string()));
        assert_eq!(rows[1], (REMOVAL_LABEL_TARGET, "vault:photos".to_string()));
        assert_eq!(rows[2].1, REMOVAL_MODE_DRY_RUN);
        // Filters come before the command's own options.
        assert_eq!(rows[3].0, crate::constants::REMOVAL_LABEL_INCLUDE);
        assert_eq!(rows.last().unwrap().1, REMOVAL_BOOL_NO);
    }

    #[test]
    fn a_real_run_is_labelled_as_one() {
        let target = Target::parse("vault:photos").unwrap();
        let plan = Plan::new("delete", &target, false, None, &NoOptions {});
        assert_eq!(plan.rows(Units::Binary)[2].1, REMOVAL_MODE_EXECUTE);
    }

    #[test]
    fn every_format_renders_without_error() {
        let target = Target::parse("vault:photos").unwrap();
        let plan = Plan::new("delete", &target, true, None, &NoOptions {});
        for args in [
            vec!["--quiet"],
            vec!["--json", "--quiet"],
            vec!["--format", "json-lines", "--quiet"],
        ] {
            assert!(emit(&ctx(&args), &plan).is_ok(), "failed for {args:?}");
        }
    }

    #[test]
    fn json_lines_keeps_a_plan_on_one_line() {
        // The newline is the record separator; a pretty-printed plan would
        // break a line-at-a-time consumer.
        let target = Target::parse("vault:photos").unwrap();
        let plan = Plan::new("delete", &target, true, None, &NoOptions {});
        let encoded = Format::JsonLines.encode(&plan).unwrap();
        assert!(!encoded.contains('\n'), "got: {encoded}");
    }

    #[test]
    fn flags_render_with_the_prompt_vocabulary() {
        assert_eq!(yes_no(true), crate::constants::DESTRUCTIVE_CONFIRMATION);
        assert_ne!(yes_no(false), yes_no(true));
    }
}
