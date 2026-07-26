//! What a `mkdir` or `touch` *would* write, rendered in every output format.
//!
//! A plan is not a result. It carries no counters and never claims that anything
//! was created — `PLAN.md` §6 forbids reporting work that did not happen, and a
//! document containing `"created": true` beside an operation that never ran
//! would be exactly that lie. The JSON shape is therefore limited to the
//! *request*: which command, which target, which options, and a `status` that
//! says the run got as far as planning.
//!
//! Rendering lives here rather than in each command because both verbs answer
//! the same question in the same shape, and a user who has read one `--dry-run`
//! has read them both. Text gets an aligned label/value table; JSON gets one
//! document; JSON Lines gets that document on a single line, because a plan is
//! one record and the newline is the record separator.
//!
//! The plan goes to **stdout** even though it is not file content: under
//! `--dry-run` it is the only thing the command produces, and
//! `dctl mkdir --dry-run --json vault:a | jq` has to work. Everything
//! conversational — the `[dry-run]` notice, the engine refusal — goes to stderr,
//! as [`crate::output`] requires.

use serde::Serialize;

use crate::constants::{
    DIRECTORY_BOOL_NO, DIRECTORY_BOOL_YES, DIRECTORY_COLUMN_FIELD, DIRECTORY_COLUMN_VALUE,
    DIRECTORY_LABEL_COMMAND, DIRECTORY_LABEL_MODE, DIRECTORY_LABEL_TARGET, DIRECTORY_MODE_DRY_RUN,
    DIRECTORY_MODE_EXECUTE, DIRECTORY_STATUS_PLANNED,
};
use crate::ctx::Ctx;
use crate::error::Result;
use crate::output::{Align, Column, Format, Table};

use super::target::Target;

/// One label/value pair in the text rendering of a plan.
pub type Row = (&'static str, String);

/// The per-command half of a plan.
///
/// Implemented by each command's own options struct rather than modelled as a
/// bag of strings, so `--parents` is a `bool` in the JSON and a row in the table
/// without either spelling being written twice.
pub trait PlanOptions: Serialize {
    /// Label/value rows for the text rendering, in display order.
    fn rows(&self) -> Vec<Row>;
}

/// The resolved request for one directory-family operation.
#[derive(Debug, Serialize)]
pub struct Plan<'a, O: PlanOptions> {
    /// Stable command name, matching `Command::name()` in `cli/mod.rs`.
    pub command: &'static str,
    pub target: &'a Target,
    /// Whether this run was forbidden from changing anything.
    pub dry_run: bool,
    pub options: &'a O,
    /// How far the run got. Never "created": a plan is not an outcome.
    pub status: &'static str,
}

impl<'a, O: PlanOptions> Plan<'a, O> {
    /// Assemble a plan. `status` is fixed rather than a parameter — this type
    /// exists only to describe an operation that has not run.
    #[must_use]
    pub fn new(command: &'static str, target: &'a Target, dry_run: bool, options: &'a O) -> Self {
        Self {
            command,
            target,
            dry_run,
            options,
            status: DIRECTORY_STATUS_PLANNED,
        }
    }

    /// Every row of the text rendering, in display order.
    ///
    /// Command, target and mode first, always in that order: they are the three
    /// facts that decide whether the rest of the table is worth reading.
    #[must_use]
    fn rows(&self) -> Vec<Row> {
        let mut rows = vec![
            (DIRECTORY_LABEL_COMMAND, self.command.to_string()),
            (DIRECTORY_LABEL_TARGET, self.target.to_string()),
            (DIRECTORY_LABEL_MODE, self.mode().to_string()),
        ];
        rows.extend(self.options.rows());
        rows
    }

    /// How this run is labelled in the `Mode` row.
    #[must_use]
    const fn mode(&self) -> &'static str {
        if self.dry_run {
            DIRECTORY_MODE_DRY_RUN
        } else {
            DIRECTORY_MODE_EXECUTE
        }
    }
}

/// Write a plan to stdout in the format the run asked for.
///
/// # Errors
/// Propagates a stdout write failure. A closed pipe is not one — the sink
/// already treats that as success.
pub fn emit<O: PlanOptions>(ctx: &Ctx, plan: &Plan<'_, O>) -> Result<()> {
    match ctx.out.format() {
        Format::Text => {
            let mut table = Table::new(vec![
                Column::new(DIRECTORY_COLUMN_FIELD, Align::Left),
                Column::new(DIRECTORY_COLUMN_VALUE, Align::Left),
            ]);
            for (label, value) in plan.rows() {
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
        DIRECTORY_BOOL_YES
    } else {
        DIRECTORY_BOOL_NO
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::directory::testing::ctx;
    use crate::constants::DIRECTORY_LABEL_PARENTS;

    #[derive(Debug, Serialize)]
    struct TestOptions {
        parents: bool,
    }

    impl PlanOptions for TestOptions {
        fn rows(&self) -> Vec<Row> {
            vec![(DIRECTORY_LABEL_PARENTS, yes_no(self.parents))]
        }
    }

    fn target() -> Target {
        Target::parse("vault:photos/2024", "directory").unwrap()
    }

    #[test]
    fn a_plan_reports_the_request_and_never_a_result() {
        let target = target();
        let options = TestOptions { parents: true };
        let plan = Plan::new("mkdir", &target, true, &options);
        let value = serde_json::to_value(&plan).unwrap();

        assert_eq!(value["command"], "mkdir");
        assert_eq!(value["target"]["remote"], "vault");
        assert_eq!(value["target"]["path"], "photos/2024");
        assert_eq!(value["dry_run"], true);
        assert_eq!(value["options"]["parents"], true);
        assert_eq!(value["status"], DIRECTORY_STATUS_PLANNED);
        // The load-bearing absence: no field may imply completed work.
        assert!(value.get("created").is_none());
        assert!(value.get("directories_created").is_none());
    }

    #[test]
    fn the_text_rows_lead_with_command_target_and_mode() {
        let target = target();
        let options = TestOptions { parents: false };
        let plan = Plan::new("mkdir", &target, true, &options);
        let rows = plan.rows();

        assert_eq!(rows[0], (DIRECTORY_LABEL_COMMAND, "mkdir".to_string()));
        assert_eq!(
            rows[1],
            (DIRECTORY_LABEL_TARGET, "vault:photos/2024".to_string())
        );
        assert_eq!(rows[2].1, DIRECTORY_MODE_DRY_RUN);
        // The command's own rows come after the three shared ones.
        assert_eq!(rows[3], (DIRECTORY_LABEL_PARENTS, DIRECTORY_BOOL_NO.into()));
    }

    #[test]
    fn a_real_run_is_labelled_as_one() {
        let target = target();
        let options = TestOptions { parents: false };
        let plan = Plan::new("mkdir", &target, false, &options);
        assert_eq!(plan.rows()[2].1, DIRECTORY_MODE_EXECUTE);
    }

    #[test]
    fn every_format_renders_without_error() {
        let target = target();
        let options = TestOptions { parents: true };
        let plan = Plan::new("mkdir", &target, true, &options);
        for args in [
            vec![],
            vec!["--json"],
            vec!["--format", "json-lines"],
            vec!["--format", "text"],
        ] {
            assert!(emit(&ctx(&args), &plan).is_ok(), "failed for {args:?}");
        }
    }

    #[test]
    fn json_lines_keeps_a_plan_on_one_line() {
        // The newline is the record separator; a pretty-printed plan would break
        // a line-at-a-time consumer.
        let target = target();
        let options = TestOptions { parents: true };
        let plan = Plan::new("mkdir", &target, true, &options);
        let encoded = Format::JsonLines.encode(&plan).unwrap();
        assert!(!encoded.contains('\n'), "got: {encoded}");
    }

    #[test]
    fn flags_render_with_the_prompt_vocabulary() {
        assert_eq!(yes_no(true), crate::constants::DESTRUCTIVE_CONFIRMATION);
        assert_ne!(yes_no(false), yes_no(true));
    }
}
