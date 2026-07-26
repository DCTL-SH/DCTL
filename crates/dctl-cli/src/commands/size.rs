//! `dctl size` — how many objects, and how many bytes.
//!
//! The cheapest question in the family and the one most often asked from a
//! script: two numbers, over the same scope every other listing verb uses, so
//! `dctl size --include "*.raw"` and `dctl ls --include "*.raw" | wc -l` agree by
//! construction.
//!
//! ## Two renderings of the same number
//!
//! The text report prints the rounded human figure *and* the exact byte count:
//!
//! ```text
//! Total objects: 1,234
//! Total size: 1.44 GiB (1546188226 bytes)
//! ```
//!
//! Both, because they answer different questions. `1.44 GiB` is what a person
//! reads; `1546188226` is what gets subtracted from a quota, and a rounded
//! figure quietly loses up to five per cent of it. The JSON shape carries only
//! the exact values — a machine has no use for a rounded one and every use for a
//! stable one.
//!
//! ## Memory
//!
//! Two `u64`s, whatever the vault holds. This is the command that proves the
//! streaming pipeline is real: counting ten million objects must not need ten
//! million anything (`PLAN.md` §16.2).
//!
//! ## Not implemented yet
//!
//! The read itself: see [`listing::source::open`].

use clap::Args;
use serde::Serialize;

use crate::constants::{
    SIZE_REPORT_EXACT_UNIT, SIZE_REPORT_LABEL_BYTES, SIZE_REPORT_LABEL_OBJECTS,
};
use crate::ctx::Ctx;
use crate::error::Result;
use crate::output::Units;
use crate::output::size::{bytes, count};

use super::listing::{self, Filter, Target};

/// Arguments for `dctl size`.
#[derive(Args, Debug)]
pub struct SizeArgs {
    /// Remote and path to measure, as REMOTE:PATH. Defaults to --remote.
    #[arg(value_name = "REMOTE:PATH")]
    pub path: Option<String>,
}

/// The totals, as a machine reads them.
///
/// Field names are rclone's `size --json` shape, lower case, so a script that
/// already reads `.count` and `.bytes` keeps working. Both are exact: rounding
/// belongs in the text rendering and nowhere else.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Totals {
    /// Objects in scope.
    pub count: u64,
    /// Sum of their plaintext sizes, in bytes.
    pub bytes: u64,
}

/// Measure everything under the given path.
///
/// # Errors
/// A malformed spec or filter is a usage error; an unreachable index is fatal.
pub async fn run(ctx: &Ctx, args: &SizeArgs) -> Result<()> {
    let target = Target::parse(args.path.as_deref(), ctx.globals.remote.as_deref())?;
    let filter = Filter::from_globals(&ctx.globals)?;
    let mut stream = listing::open(ctx, &target, filter).await?;

    let mut totals = Totals { count: 0, bytes: 0 };
    stream.try_for_each(|entry| {
        totals.count = totals.count.saturating_add(1);
        // Saturating rather than wrapping: a vault whose total overflows u64 is
        // not something DCTL will meet, and reporting u64::MAX would at least be
        // visibly wrong where a wrapped value would look plausible.
        totals.bytes = totals.bytes.saturating_add(entry.size());
        Ok(())
    })?;

    if ctx.out.is_json() {
        ctx.out.json(&totals)?;
    } else {
        for line in report(&totals, ctx.out.units()) {
            ctx.out.line(line)?;
        }
    }

    Ok(())
}

/// The two text lines of the report.
///
/// Returned rather than printed so the exact wording is testable without a
/// terminal — this is the output people paste into capacity spreadsheets.
fn report(totals: &Totals, units: Units) -> [String; 2] {
    [
        format!("{SIZE_REPORT_LABEL_OBJECTS} {}", count(totals.count)),
        format!(
            "{SIZE_REPORT_LABEL_BYTES} {} ({} {SIZE_REPORT_EXACT_UNIT})",
            bytes(totals.bytes, units),
            totals.bytes
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Cli;
    use crate::commands::listing::tests_support::ctx;
    use crate::exit::ExitCode;
    use clap::Parser;
    use serde_json::json;

    #[test]
    fn the_command_parses_with_and_without_a_path() {
        assert!(Cli::try_parse_from(["dctl", "size"]).is_ok());
        let cli = Cli::try_parse_from(["dctl", "size", "vault:photos"]).unwrap();
        assert_eq!(cli.command.name(), "size");
    }

    #[test]
    fn the_report_carries_the_rounded_and_the_exact_figure() {
        let report = report(
            &Totals {
                count: 1_234,
                bytes: 1_546_188_226,
            },
            Units::Binary,
        );
        assert_eq!(report[0], "Total objects: 1,234");
        assert_eq!(report[1], "Total size: 1.44 GiB (1546188226 bytes)");
    }

    #[test]
    fn the_exact_figure_is_never_rounded_or_separated() {
        // It is there to be pasted into arithmetic, so no thousands separators
        // and no unit ladder.
        let report = report(
            &Totals {
                count: 0,
                bytes: 1_000_000,
            },
            Units::Decimal,
        );
        assert!(report[1].contains("(1000000 bytes)"), "{}", report[1]);
    }

    #[test]
    fn the_unit_convention_reaches_the_rounded_figure() {
        let totals = Totals {
            count: 1,
            bytes: 1_000_000_000_000,
        };
        assert!(report(&totals, Units::Binary)[1].contains("931.3 GiB"));
        assert!(report(&totals, Units::Decimal)[1].contains("1.00 TB"));
    }

    #[test]
    fn an_empty_vault_reports_zeroes_rather_than_nothing() {
        // "Zero objects" is an answer; silence is not.
        let report = report(&Totals { count: 0, bytes: 0 }, Units::Binary);
        assert_eq!(report[0], "Total objects: 0");
        assert!(report[1].starts_with("Total size: 0 B"));
    }

    #[test]
    fn the_json_shape_is_exact_and_stable() {
        let value = serde_json::to_value(Totals {
            count: 7,
            bytes: 1_546_188_226,
        })
        .unwrap();
        assert_eq!(value, json!({ "count": 7, "bytes": 1_546_188_226u64 }));
    }

    #[tokio::test]
    async fn an_unreachable_index_is_an_error_not_a_zero() {
        // A reported zero would be indistinguishable from an empty vault, and
        // "the backup is empty" is a conclusion people act on.
        for flags in [vec![], vec!["--json"], vec!["--format", "json-lines"]] {
            let ctx = ctx(&flags);
            let error = run(
                &ctx,
                &SizeArgs {
                    path: Some("vault:".into()),
                },
            )
            .await
            .unwrap_err();
            assert_eq!(error.code(), ExitCode::FatalError, "{flags:?}");
        }
    }

    #[tokio::test]
    async fn filters_are_validated_before_the_engine_is_reached() {
        let ctx = ctx(&["--min-size", "not-a-size"]);
        let error = run(
            &ctx,
            &SizeArgs {
                path: Some("vault:".into()),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[tokio::test]
    async fn a_missing_target_is_a_usage_error() {
        let error = run(&ctx(&[]), &SizeArgs { path: None }).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }
}
