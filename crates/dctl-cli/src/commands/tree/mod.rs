//! `dctl tree` — the object namespace, drawn.
//!
//! The listing you read when you are trying to understand a vault rather than
//! process it. Same scope rules as every other listing verb — same filters, same
//! ordering, same relative paths — rendered as nesting instead of as rows.
//!
//! ```text
//! vault:photos
//! ├── 2024/
//! │   ├── a.jpg
//! │   └── b.jpg
//! └── 2025/
//!     └── c.jpg
//! ```
//!
//! ## Two dials of its own
//!
//! * `--dirs-only` drops the objects and leaves the shape, which is the form
//!   that stays readable on a real dataset.
//! * `--level` bounds the depth. It composes with the global `--max-depth`
//!   rather than overriding it: whichever is tighter wins, so a user who has set
//!   a depth for a whole script does not have it silently widened here.
//!
//! ## Memory, and why this verb is the exception
//!
//! A tree cannot be drawn in one streaming pass — see
//! [`node`] for the reason, which is a property of the picture rather than of
//! the code. Everything else in the family streams; this holds a bounded
//! skeleton and says so.
//!
//! ## JSON is the flat stream, not a nested document
//!
//! Under `--json` or `--format json-lines`, `tree` emits the same
//! [`JsonEntry`] records the rest of the family
//! emits, in the same order. A nested JSON document would have to be assembled
//! whole before its first byte could be written — the one thing [the plan](https://doc.dctl.sh/project/plan) §16.2
//! rules out — and the hierarchy is already in the `Path` field, losslessly. A
//! consumer that wants a tree can build one; a consumer that wants records
//! should not have to walk one.
//!
//! ## Where the objects come from
//!
//! [`listing::source::open`] — one call that reaches a sealed vault, a plain
//! object store or a local directory through [`crate::source`], so this command
//! never learns which it was given.

pub mod glyphs;
pub mod node;

use clap::Args;

use crate::constants::{
    MAX_DEPTH_UNLIMITED, TREE_ROOT_LABEL, TREE_SUMMARY_DIRECTORIES, TREE_SUMMARY_FILES,
};
use crate::ctx::Ctx;
use crate::error::Result;
use crate::output::size::{bytes_or_unknown, count};

use self::glyphs::Glyphs;
use self::node::Tree;

use super::listing::emit::Emitter;
use super::listing::{self, Filter, JsonEntry, Target};

/// Arguments for `dctl tree`.
#[derive(Args, Debug)]
pub struct TreeArgs {
    /// Remote and path to draw, as REMOTE:PATH. Defaults to --remote.
    #[arg(value_name = "REMOTE:PATH")]
    pub path: Option<String>,

    /// Show directories only, omitting the objects inside them.
    #[arg(short = 'd', long)]
    pub dirs_only: bool,

    /// Descend at most this many levels; -1 for unlimited.
    #[arg(
        short = 'L',
        long,
        value_name = "N",
        default_value_t = MAX_DEPTH_UNLIMITED,
        allow_negative_numbers = true
    )]
    pub level: i32,
}

/// Draw the object tree under the given path.
///
/// # Errors
/// A malformed spec or filter is a usage error; an unreachable index is fatal.
pub async fn run(ctx: &Ctx, args: &TreeArgs) -> Result<()> {
    let target = Target::parse(args.path.as_deref(), ctx.globals.remote.as_deref())?;
    let depth = tighter(depth_of(args.level), depth_of(ctx.globals.max_depth));

    // The object filter carries no depth limit: the tree applies it while
    // building, so that a directory at the boundary is still drawn even though
    // everything inside it has been pruned.
    let filter = Filter::from_globals(&ctx.globals)?.with_depth_limit(None);
    let mut stream = listing::open(ctx, &target, filter).await?;

    if ctx.out.is_json() {
        let mut emitter = Emitter::new(&ctx.out);
        stream
            .try_for_each(|entry| emitter.push(&JsonEntry::new(entry)))
            .await?;
        emitter.finish()?;
        listing::report_omissions(ctx, &stream);
        listing::report_empty(ctx, &stream, &target);
        return Ok(());
    }

    let mut tree = Tree::new(root_label(&target), depth);
    stream
        .try_for_each(|entry| {
            tree.insert(entry.relative(), entry.size());
            Ok(())
        })
        .await?;

    let mut emit = |line: &str| -> Result<()> {
        ctx.out.line(line)?;
        Ok(())
    };
    let counts = tree.render(
        Glyphs::resolve(ctx.globals.ascii),
        args.dirs_only,
        ctx.out.palette(),
        &mut emit,
    )?;

    // A footer on stderr, not stdout: the drawing is the data, and a trailing
    // sentence appended to it would break `dctl tree | grep`. The byte total is
    // the whole subtree's, including anything `--level` pruned from the picture —
    // the drawing was truncated, the vault was not.
    ctx.out.info(format!(
        "{} {TREE_SUMMARY_DIRECTORIES}, {} {TREE_SUMMARY_FILES}, {}",
        count(counts.directories),
        count(counts.files),
        bytes_or_unknown(tree.total_bytes(), ctx.out.units())
    ));

    listing::report_omissions(ctx, &stream);
    if tree.is_empty() {
        listing::report_empty(ctx, &stream, &target);
    }
    Ok(())
}

/// The label printed above the first branch.
///
/// The spec the user typed, so a tree pasted into a ticket says which vault and
/// which subtree it came from. A bare vault root has nothing to name, and falls
/// back to [`TREE_ROOT_LABEL`].
fn root_label(target: &Target) -> String {
    let display = target.display();
    if display.is_empty() {
        TREE_ROOT_LABEL.to_string()
    } else {
        display
    }
}

/// Turn a depth flag into a limit, treating the sentinel as unlimited.
fn depth_of(value: i32) -> Option<usize> {
    if value <= MAX_DEPTH_UNLIMITED {
        None
    } else {
        usize::try_from(value).ok()
    }
}

/// The tighter of two limits, where `None` means unlimited.
fn tighter(left: Option<usize>, right: Option<usize>) -> Option<usize> {
    match (left, right) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (limit, None) | (None, limit) => limit,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Cli, Command};
    use crate::commands::listing::tests_support::ctx;
    use crate::exit::ExitCode;
    use clap::Parser;

    fn args(argv: &[&str]) -> TreeArgs {
        let cli = Cli::try_parse_from(std::iter::once("dctl").chain(argv.iter().copied()))
            .expect("arguments should parse");
        match cli.command {
            Command::Tree(args) => args,
            other => panic!("expected tree, got {}", other.name()),
        }
    }

    #[test]
    fn the_dials_have_short_and_long_spellings() {
        let short = args(&["tree", "vault:", "-d", "-L", "2"]);
        assert!(short.dirs_only);
        assert_eq!(short.level, 2);

        let long = args(&["tree", "vault:", "--dirs-only", "--level", "2"]);
        assert!(long.dirs_only);
        assert_eq!(long.level, 2);
    }

    #[test]
    fn the_level_defaults_to_unlimited_and_accepts_the_sentinel() {
        assert_eq!(args(&["tree"]).level, MAX_DEPTH_UNLIMITED);
        // `-L -1` must parse as a number, not as an unknown flag.
        assert_eq!(
            args(&["tree", "vault:", "-L", "-1"]).level,
            MAX_DEPTH_UNLIMITED
        );
    }

    #[test]
    fn the_tighter_of_the_two_depth_limits_wins() {
        // A depth already set for a whole script must not be silently widened.
        assert_eq!(tighter(Some(2), Some(5)), Some(2));
        assert_eq!(tighter(Some(5), Some(2)), Some(2));
        assert_eq!(tighter(None, Some(3)), Some(3));
        assert_eq!(tighter(Some(3), None), Some(3));
        assert_eq!(tighter(None, None), None);
    }

    #[test]
    fn the_unlimited_sentinel_becomes_no_limit() {
        assert_eq!(depth_of(MAX_DEPTH_UNLIMITED), None);
        assert_eq!(depth_of(-9), None);
        assert_eq!(depth_of(0), Some(0));
        assert_eq!(depth_of(4), Some(4));
    }

    #[test]
    fn the_root_label_names_the_subtree_that_was_drawn() {
        let target = Target::parse(Some("vault:photos/2024"), None).unwrap();
        assert_eq!(root_label(&target), "vault:photos/2024");
    }

    #[test]
    fn a_target_with_nothing_to_name_falls_back_to_the_placeholder() {
        let target = Target::Local(std::path::PathBuf::new());
        assert_eq!(root_label(&target), TREE_ROOT_LABEL);
    }

    #[test]
    fn the_glyph_set_follows_the_ascii_flag_and_nothing_else() {
        // Not the terminal, not the pipe: the drawing is data and must be
        // reproducible. See `glyphs` for the argument.
        assert_eq!(
            Glyphs::resolve(ctx(&["--ascii"]).globals.ascii),
            Glyphs::ASCII
        );
        assert_eq!(Glyphs::resolve(ctx(&[]).globals.ascii), Glyphs::UNICODE);
    }

    #[tokio::test]
    async fn an_unreachable_index_is_an_error_in_every_format() {
        for flags in [vec![], vec!["--json"], vec!["--format", "json-lines"]] {
            let ctx = ctx(&flags);
            let error = run(
                &ctx,
                &TreeArgs {
                    path: Some("vault:".into()),
                    dirs_only: false,
                    level: MAX_DEPTH_UNLIMITED,
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
            &TreeArgs {
                path: None,
                dirs_only: true,
                level: 1,
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[tokio::test]
    async fn a_bad_filter_fails_before_the_engine_is_reached() {
        let ctx = ctx(&["--exclude", "[unclosed"]);
        let error = run(
            &ctx,
            &TreeArgs {
                path: Some("vault:".into()),
                dirs_only: false,
                level: MAX_DEPTH_UNLIMITED,
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }
}
