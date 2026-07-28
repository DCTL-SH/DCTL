//! `dctl lsl` — objects with size, modification time and path.
//!
//! [`ls`](super::ls) with a time column. The same objects, the same order, the
//! same filters; the only difference is one field, which is why the two share
//! everything except the line they print.
//!
//! ## The time column is RFC 3339, in UTC
//!
//! rclone prints `2017-05-31 16:24:29.000000000`, a local-time rendering with
//! nanoseconds it did not measure. DCTL prints `2017-05-31T16:24:29Z`, which is
//! shorter, sorts correctly as plain text, parses with every date library
//! without a format string, and — the reason that matters most — does not change
//! when the same vault is listed from a different timezone. See
//! [`listing::time`] for why UTC is not negotiable.
//!
//! An object whose index record carries no modification time prints a
//! placeholder padded to the same width, rather than the epoch. `1970-01-01` is
//! a claim; the placeholder is the truth.
//!
//! ## Where the objects come from
//!
//! [`listing::source::open`] — one call that reaches a sealed vault, a plain
//! object store or a local directory through [`crate::source`], so this command
//! never learns which it was given.

use clap::Args;

use crate::ctx::Ctx;
use crate::error::Result;
use crate::output::Units;

use super::listing::emit::Emitter;
use super::listing::render::{modtime_column, row, size_column};
use super::listing::{self, Entry, Filter, JsonEntry, Target};

/// Arguments for `dctl lsl`.
#[derive(Args, Debug)]
pub struct LslArgs {
    /// Remote and path to list, as REMOTE:PATH. Defaults to --remote.
    #[arg(value_name = "REMOTE:PATH")]
    pub path: Option<String>,
}

/// List every object under the given path, with modification times.
///
/// # Errors
/// A malformed spec or filter is a usage error; an unreachable index is fatal.
pub async fn run(ctx: &Ctx, args: &LslArgs) -> Result<()> {
    let target = Target::parse(args.path.as_deref(), ctx.globals.remote.as_deref())?;
    let filter = Filter::from_globals(&ctx.globals)?;
    let mut stream = listing::open(ctx, &target, filter).await?;

    if ctx.out.is_json() {
        // The listing family speaks one JSON vocabulary. `lsl` differs from `ls`
        // in what a *person* sees; giving a machine consumer a second shape to
        // learn would be a cost with no benefit, since `ModTime` is already
        // there.
        let mut emitter = Emitter::new(&ctx.out);
        stream
            .try_for_each(|entry| emitter.push(&JsonEntry::new(entry)))
            .await?;
        emitter.finish()?;
    } else {
        let units = ctx.out.units();
        stream
            .try_for_each(|entry| {
                ctx.out.line(line(entry, units))?;
                Ok(())
            })
            .await?;
    }

    listing::report_links(ctx, &stream);
    listing::report_empty(ctx, &stream, &target);
    Ok(())
}

/// One text line: size, modification time, then the path.
fn line(entry: &Entry, units: Units) -> String {
    row(&[
        &size_column(entry.size(), units),
        &modtime_column(entry.modified_unix()),
        entry.relative(),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Cli;
    use crate::commands::listing::tests_support::{ctx, listed};
    use crate::constants::{
        LISTING_MODTIME_COLUMN_WIDTH, LISTING_SIZE_COLUMN_WIDTH, UNKNOWN_VALUE,
    };
    use crate::exit::ExitCode;
    use clap::Parser;

    fn at(path: &str, size: u64, modified: Option<i64>) -> Entry {
        Entry::from_source(listed(path, size, modified), "")
    }

    #[test]
    fn the_command_parses_with_and_without_a_path() {
        assert!(Cli::try_parse_from(["dctl", "lsl"]).is_ok());
        let cli = Cli::try_parse_from(["dctl", "lsl", "vault:photos"]).unwrap();
        assert_eq!(cli.command.name(), "lsl");
    }

    #[test]
    fn a_line_carries_size_time_and_path_in_that_order() {
        let rendered = line(&at("2024/a.jpg", 1024, Some(1_704_067_200)), Units::Binary);
        assert_eq!(rendered, "  1.00 KiB 2024-01-01T00:00:00Z 2024/a.jpg");
    }

    #[test]
    fn an_unknown_time_keeps_the_columns_aligned() {
        let known = line(&at("a", 1, Some(0)), Units::Binary);
        let unknown = line(&at("a", 1, None), Units::Binary);
        assert_eq!(known.chars().count(), unknown.chars().count());
        assert!(unknown.contains(UNKNOWN_VALUE));
        // Never the epoch: "unknown" and "1970" are different claims.
        assert!(!unknown.contains("1970"));
    }

    /// The time column, taken by position rather than by splitting: the layout
    /// itself is what these tests are about.
    fn time_column(rendered: &str) -> String {
        let start = LISTING_SIZE_COLUMN_WIDTH + 1;
        let end = start + LISTING_MODTIME_COLUMN_WIDTH;
        rendered
            .get(start..end)
            .expect("the time column sits at a fixed offset")
            .to_string()
    }

    #[test]
    fn the_time_column_never_changes_width_or_position() {
        // A run spanning several centuries still aligns, which is what makes
        // `cut -c` and `sort -k` over an `lsl` listing meaningful.
        for seconds in [0, 1_704_067_200, 4_102_444_800, -2_203_891_200] {
            let rendered = line(&at("a", 1, Some(seconds)), Units::Binary);
            let column = time_column(&rendered);
            assert_eq!(
                column.chars().count(),
                LISTING_MODTIME_COLUMN_WIDTH,
                "{seconds}"
            );
            assert!(column.ends_with('Z'), "{seconds}: {column:?}");
        }
    }

    #[test]
    fn the_rendering_is_lexicographically_sortable_by_time() {
        // The property RFC 3339 buys and rclone's local-time format does not.
        let early = time_column(&line(&at("z.txt", 1, Some(0)), Units::Binary));
        let late = time_column(&line(&at("a.txt", 1, Some(1_704_067_200)), Units::Binary));
        assert!(early < late, "{early:?} should sort before {late:?}");
    }

    #[tokio::test]
    async fn an_unreachable_index_is_an_error_in_every_format() {
        for flags in [vec![], vec!["--json"], vec!["--format", "json-lines"]] {
            let ctx = ctx(&flags);
            let error = run(
                &ctx,
                &LslArgs {
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
        let ctx = ctx(&["--max-size", "banana"]);
        let error = run(
            &ctx,
            &LslArgs {
                path: Some("vault:".into()),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }
}
