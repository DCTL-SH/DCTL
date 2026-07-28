//! `dctl lsd` — directories only.
//!
//! The command that answers "what is in here" before you decide where to look.
//! One level by default ([`LSD_DEFAULT_DEPTH`]), because a recursive directory
//! listing of a real vault is not something anyone reads; `--recursive` removes
//! the limit and `--max-depth` sets it to anything in between.
//!
//! ## Directories do not exist
//!
//! An object store has no directories, so every row here is inferred from the
//! paths of the objects beneath it — see [`listing::dirs`]
//! for how, and for why that can be done in one streaming pass. Two consequences
//! are worth stating because they surprise people:
//!
//! * A directory containing no objects does not appear, because nothing implies
//!   it. There is no such thing as an empty directory in a vault.
//! * A directory's size and object count are **recursive totals**. `photos`
//!   reports every byte under it, including those in `photos/2024`, which is
//!   what the question means when a human asks it.
//!
//! rclone prints `-1` in both columns here, having never computed them. DCTL
//! computes them, because it costs one addition per object on a pass it was
//! making anyway, and because a size column that always reads `-1` is a column
//! of nothing.
//!
//! ## Depth is applied to directories, not to objects
//!
//! `--max-depth 1` means "report the top level", not "ignore anything below it".
//! The aggregator still counts every object at every depth — otherwise a
//! top-level directory whose files all live two levels down would report as
//! empty — and only the *reporting* is truncated.
//!
//! ## Where the objects come from
//!
//! [`listing::source::open`] — one call that reaches a sealed vault, a plain
//! object store or a local directory through [`crate::source`], so this command
//! never learns which it was given.

use clap::Args;

use crate::constants::{LSD_DEFAULT_DEPTH, MAX_DEPTH_UNLIMITED};
use crate::ctx::Ctx;
use crate::error::Result;
use crate::output::Units;

use super::listing::dirs::{Aggregator, Directory};
use super::listing::emit::Emitter;
use super::listing::render::{count_column, directory_path, row, size_column};
use super::listing::{self, Filter, JsonEntry, Target};

/// Arguments for `dctl lsd`.
#[derive(Args, Debug)]
pub struct LsdArgs {
    /// Remote and path to list, as REMOTE:PATH. Defaults to --remote.
    #[arg(value_name = "REMOTE:PATH")]
    pub path: Option<String>,

    /// Show directories at every depth, not just the top level.
    #[arg(short = 'R', long)]
    pub recursive: bool,
}

/// List the directories under the given path.
///
/// # Errors
/// A malformed spec or filter is a usage error; an unreachable index is fatal.
pub async fn run(ctx: &Ctx, args: &LsdArgs) -> Result<()> {
    let target = Target::parse(args.path.as_deref(), ctx.globals.remote.as_deref())?;
    let depth = directory_depth(ctx.globals.max_depth, args.recursive);

    // The object filter must not carry the depth limit: `lsd` needs to see deep
    // objects in order to know that the shallow directory exists at all.
    let filter = Filter::from_globals(&ctx.globals)?.with_depth_limit(None);
    let mut stream = listing::open(ctx, &target, filter).await?;

    let mut aggregator = Aggregator::new(target.prefix(), depth);
    let units = ctx.out.units();
    let mut shown = 0u64;

    if ctx.out.is_json() {
        let mut emitter = Emitter::new(&ctx.out);
        {
            let mut emit = |dir: &Directory| -> Result<()> {
                shown += 1;
                emitter.push(&JsonEntry::new(&dir.to_entry()))
            };
            stream
                .try_for_each(|entry| aggregator.push(entry, &mut emit))
                .await?;
            aggregator.finish(&mut emit)?;
        }
        emitter.finish()?;
    } else {
        let mut emit = |dir: &Directory| -> Result<()> {
            shown += 1;
            ctx.out.line(line(dir, units))?;
            Ok(())
        };
        stream
            .try_for_each(|entry| aggregator.push(entry, &mut emit))
            .await?;
        aggregator.finish(&mut emit)?;
    }

    listing::report_links(ctx, &stream);
    if shown == 0 {
        report_empty(ctx, &stream, &target);
    }
    Ok(())
}

/// The depth at which directories stop being reported.
///
/// An explicit `--max-depth` wins; otherwise `--recursive` means unlimited and
/// the default is [`LSD_DEFAULT_DEPTH`]. The one ambiguity — a user who spells
/// out `--max-depth -1` is indistinguishable from one who passed nothing — is
/// harmless, because both then get the same answer as `--recursive`.
fn directory_depth(max_depth: i32, recursive: bool) -> Option<usize> {
    let effective = if max_depth != MAX_DEPTH_UNLIMITED {
        max_depth
    } else if recursive {
        MAX_DEPTH_UNLIMITED
    } else {
        LSD_DEFAULT_DEPTH
    };

    if effective <= MAX_DEPTH_UNLIMITED {
        None
    } else {
        usize::try_from(effective).ok()
    }
}

/// One text line: total size, object count, then the directory path.
fn line(dir: &Directory, units: Units) -> String {
    let as_entry = dir.to_entry();
    row(&[
        &size_column(dir.bytes(), units),
        &count_column(dir.objects()),
        &directory_path(as_entry.relative()),
    ])
}

/// Note on stderr that no directories were found, distinguishing the reasons.
fn report_empty(ctx: &Ctx, stream: &listing::Stream, target: &Target) {
    if stream.matched() > 0 {
        // Objects were found but none of them implied a directory: everything
        // sits at the top level. Saying "empty" here would be wrong.
        ctx.out.info(format!(
            "no directories under '{}'; {} objects are at the top level",
            target.display(),
            stream.matched()
        ));
    } else {
        listing::report_empty(ctx, stream, target);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Cli;
    use crate::commands::listing::tests_support::{ctx, entry};
    use crate::exit::ExitCode;
    use clap::Parser;

    /// The rows `lsd` would print for a sorted set of objects.
    fn rows(root: &str, depth: Option<usize>, paths: &[(&str, u64)]) -> Vec<String> {
        let mut lines = Vec::new();
        let mut aggregator = Aggregator::new(root, depth);
        {
            let mut emit = |dir: &Directory| -> Result<()> {
                lines.push(line(dir, Units::Binary));
                Ok(())
            };
            for (path, size) in paths {
                aggregator
                    .push(&entry(root, path, *size), &mut emit)
                    .expect("collecting cannot fail");
            }
            aggregator
                .finish(&mut emit)
                .expect("collecting cannot fail");
        }
        lines
    }

    #[test]
    fn recursive_has_a_short_flag_and_a_long_one() {
        for spelling in ["-R", "--recursive"] {
            let cli = Cli::try_parse_from(["dctl", "lsd", "vault:", spelling]).unwrap();
            assert_eq!(cli.command.name(), "lsd");
        }
        assert!(Cli::try_parse_from(["dctl", "lsd"]).is_ok());
    }

    #[test]
    fn the_default_depth_comes_from_the_constant() {
        assert_eq!(
            directory_depth(MAX_DEPTH_UNLIMITED, false),
            usize::try_from(LSD_DEFAULT_DEPTH).ok()
        );
    }

    #[test]
    fn recursive_removes_the_depth_limit() {
        assert_eq!(directory_depth(MAX_DEPTH_UNLIMITED, true), None);
    }

    #[test]
    fn an_explicit_max_depth_beats_both_defaults() {
        assert_eq!(directory_depth(3, false), Some(3));
        // Even against --recursive: the user named a number, so honour it.
        assert_eq!(directory_depth(3, true), Some(3));
    }

    #[test]
    fn only_the_top_level_is_shown_by_default() {
        let rows = rows(
            "",
            directory_depth(MAX_DEPTH_UNLIMITED, false),
            &[
                ("docs/a.txt", 10),
                ("photos/2024/a.jpg", 1024),
                ("photos/b.jpg", 1024),
            ],
        );
        assert_eq!(rows.len(), 2);
        assert!(rows[0].ends_with("docs/"));
        assert!(rows[1].ends_with("photos/"));
    }

    #[test]
    fn recursion_shows_every_level_parents_first() {
        let rows = rows(
            "",
            None,
            &[("photos/2024/a.jpg", 1024), ("photos/2025/b.jpg", 2048)],
        );
        let paths: Vec<&str> = rows
            .iter()
            .filter_map(|row| row.rsplit(' ').next())
            .collect();
        assert_eq!(paths, vec!["photos/", "photos/2024/", "photos/2025/"]);
    }

    #[test]
    fn a_row_carries_the_recursive_totals() {
        let rows = rows(
            "",
            Some(1),
            &[("photos/2024/a.jpg", 1024), ("photos/b.jpg", 1024)],
        );
        // 2 KiB across 2 objects, both counted at the top level even though one
        // of them lives a level down.
        assert_eq!(rows, vec!["  2.00 KiB         2 photos/"]);
    }

    #[test]
    fn paths_are_relative_to_the_listing_root() {
        let rows = rows("photos", Some(1), &[("photos/2024/a.jpg", 1)]);
        assert!(
            rows.first().is_some_and(|row| row.ends_with("2024/")),
            "{rows:?}"
        );
    }

    #[test]
    fn objects_at_the_top_level_imply_no_directory() {
        assert!(rows("", Some(1), &[("a.txt", 1), ("b.txt", 2)]).is_empty());
    }

    #[tokio::test]
    async fn an_unreachable_index_is_an_error_in_every_format() {
        for flags in [vec![], vec!["--json"], vec!["--format", "json-lines"]] {
            let ctx = ctx(&flags);
            let error = run(
                &ctx,
                &LsdArgs {
                    path: Some("vault:".into()),
                    recursive: false,
                },
            )
            .await
            .unwrap_err();
            assert_eq!(error.code(), ExitCode::FatalError, "{flags:?}");
        }
    }

    #[tokio::test]
    async fn a_missing_target_is_a_usage_error() {
        let error = run(
            &ctx(&[]),
            &LsdArgs {
                path: None,
                recursive: true,
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }
}
