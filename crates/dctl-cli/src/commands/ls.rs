//! `dctl ls` — objects with their sizes.
//!
//! The listing everything else is compared against: one line per object,
//! recursive by default, paths relative to the spec that was given. rclone's
//! semantics exactly, because `rclone ls remote:path | wc -l` is in a lot of
//! people's scripts.
//!
//! ## Sizes are human, exact figures are in the JSON
//!
//! The size column is rendered through [`crate::output::size`], so it follows
//! `--units` and reads as `1.44 GiB` rather than `1546188226`. That costs
//! `awk '{print $1}'` its numeric field, and buys a listing a person can scan —
//! which is what the text format is *for*. Anything arithmetic belongs in
//! `--json`, where `Size` is an exact integer and always will be.
//!
//! ## Where the objects come from
//!
//! [`listing::source::open`] — one call that reaches a sealed vault, a plain
//! object store or a local directory through [`crate::source`], so this command
//! never learns which it was given. When that call fails, so does the command,
//! with a real exit code rather than an empty listing: "the vault has no
//! objects" and "DCTL could not look" must never be the same output
//! ([the plan](https://doc.dctl.sh/project/plan) §6).

use clap::Args;

use crate::ctx::Ctx;
use crate::error::Result;
use crate::output::Units;
use crate::output::color::Palette;
use crate::output::paint;

use super::listing::emit::Emitter;
use super::listing::render::{row, size_column};
use super::listing::{self, Entry, Filter, JsonEntry, Target};

/// Arguments for `dctl ls`.
#[derive(Args, Debug)]
pub struct LsArgs {
    /// Remote and path to list, as REMOTE:PATH. Defaults to --remote.
    #[arg(value_name = "REMOTE:PATH")]
    pub path: Option<String>,
}

/// List every object under the given path.
///
/// # Errors
/// A malformed spec or filter is a usage error; an unreachable index is fatal.
/// Nothing here mutates, so `--dry-run` changes neither the output nor the
/// exit code — a read-only command that printed "[dry-run] would list" would be
/// noise, not safety.
pub async fn run(ctx: &Ctx, args: &LsArgs) -> Result<()> {
    let target = Target::parse(args.path.as_deref(), ctx.globals.remote.as_deref())?;
    let filter = Filter::from_globals(&ctx.globals)?;
    let mut stream = listing::open(ctx, &target, filter).await?;

    if ctx.out.is_json() {
        let mut emitter = Emitter::new(&ctx.out);
        stream
            .try_for_each(|entry| emitter.push(&JsonEntry::new(entry)))
            .await?;
        emitter.finish()?;
    } else {
        let units = ctx.out.units();
        stream
            .try_for_each(|entry| {
                ctx.out.line(line(entry, units, ctx.out.palette()))?;
                Ok(())
            })
            .await?;
    }

    listing::report_omissions(ctx, &stream);
    listing::report_empty(ctx, &stream, &target);
    Ok(())
}

/// One text line: the size column, then the path.
///
/// Painted *after* the columns are measured, never before: an escape sequence
/// costs bytes and no width, so styling a value and then padding it produces a
/// column that is right in a `String` and ragged on a terminal. See
/// [`crate::output::paint`].
fn line(entry: &Entry, units: Units, palette: &Palette) -> String {
    row(&[
        &paint::number(palette, &size_column(entry.size(), units)),
        &paint::path(palette, entry.relative()),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Cli;
    use crate::commands::listing::tests_support::{ctx, entry};
    use crate::constants::LISTING_SIZE_COLUMN_WIDTH;
    use crate::exit::ExitCode;
    use clap::Parser;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(std::iter::once("dctl").chain(args.iter().copied()))
            .expect("arguments should parse")
    }

    #[test]
    fn the_path_argument_is_optional() {
        let Cli { command, .. } = parse(&["ls"]);
        assert_eq!(command.name(), "ls");
        assert!(Cli::try_parse_from(["dctl", "ls", "vault:photos"]).is_ok());
    }

    #[test]
    fn a_second_positional_is_a_usage_error() {
        // `ls` takes one path. Silently ignoring a second would hide a typo in
        // `dctl ls vault:a vault:b`.
        assert!(Cli::try_parse_from(["dctl", "ls", "vault:a", "vault:b"]).is_err());
    }

    #[test]
    fn global_filters_are_accepted_without_being_redeclared() {
        // They live on GlobalArgs; a command that declared its own would shadow
        // them and diverge.
        let cli = parse(&["ls", "vault:", "--include", "*.jpg", "--max-depth", "2"]);
        assert_eq!(cli.globals.include, vec!["*.jpg"]);
        assert_eq!(cli.globals.max_depth, 2);
    }

    #[test]
    fn a_line_is_the_size_column_then_the_relative_path() {
        let rendered = line(
            &entry("photos", "photos/2024/a.jpg", 1024),
            Units::Binary,
            &Palette::plain(),
        );
        assert_eq!(rendered, "  1.00 KiB 2024/a.jpg");
        // The path column is last and unpadded, so `awk '{print $NF}'` works.
        assert!(rendered.ends_with("2024/a.jpg"));
    }

    #[test]
    fn the_size_column_holds_its_width_across_magnitudes() {
        for size in [0, 1, 1023, 1024, 1 << 30, u64::MAX] {
            let rendered = line(&entry("", "a", size), Units::Binary, &Palette::plain());
            let column = rendered.rsplit_once(' ').map(|(head, _)| head.to_string());
            assert_eq!(
                column.as_deref().map(|c| c.chars().count()),
                Some(LISTING_SIZE_COLUMN_WIDTH),
                "size {size} rendered as {rendered:?}"
            );
        }
    }

    #[test]
    fn the_unit_convention_reaches_the_line() {
        assert!(line(&entry("", "a", 1000), Units::Decimal, &Palette::plain()).contains("kB"));
        assert!(line(&entry("", "a", 1024), Units::Binary, &Palette::plain()).contains("KiB"));
    }

    #[tokio::test]
    async fn a_listing_with_no_target_is_a_usage_error() {
        let ctx = ctx(&[]);
        let error = run(&ctx, &LsArgs { path: None }).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[tokio::test]
    async fn a_bad_pattern_fails_before_the_engine_is_reached() {
        // Validation order matters: a user with a typo in `--include` should be
        // told about the typo, not about a missing engine.
        let ctx = ctx(&["--include", "[unclosed"]);
        let error = run(
            &ctx,
            &LsArgs {
                path: Some("vault:".into()),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.message().contains("--include"));
    }

    #[tokio::test]
    async fn an_unreachable_index_is_an_error_not_an_empty_listing() {
        let ctx = ctx(&[]);
        let error = run(
            &ctx,
            &LsArgs {
                path: Some("vault:photos".into()),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
    }

    #[tokio::test]
    async fn dry_run_does_not_change_a_read_only_command() {
        // `ls` mutates nothing, so `--dry-run` must not suppress its output or
        // its errors — it has nothing to suppress.
        let plain = run(
            &ctx(&[]),
            &LsArgs {
                path: Some("vault:".into()),
            },
        )
        .await;
        let dry = run(
            &ctx(&["--dry-run"]),
            &LsArgs {
                path: Some("vault:".into()),
            },
        )
        .await;
        assert_eq!(
            plain.err().map(|e| e.code()),
            dry.err().map(|e| e.code()),
            "--dry-run changed a read-only command"
        );
    }

    #[tokio::test]
    async fn every_output_format_is_accepted() {
        // Text, JSON and JSON Lines must all reach the same failure, not a
        // "format not supported" one.
        for flags in [vec![], vec!["--json"], vec!["--format", "json-lines"]] {
            let ctx = ctx(&flags);
            let error = run(
                &ctx,
                &LsArgs {
                    path: Some("vault:".into()),
                },
            )
            .await
            .unwrap_err();
            assert_eq!(error.code(), ExitCode::FatalError, "{flags:?}");
        }
    }
}
