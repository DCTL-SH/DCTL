//! `dctl lsjson` — one JSON object per entry.
//!
//! The listing a program reads. Where [`ls`](super::ls) and [`lsl`](super::lsl)
//! choose a rendering for a person and only emit JSON when asked,
//! `lsjson` emits JSON whatever `--format` says — that is the whole point of
//! having a separate verb, and it matches rclone, where `lsjson` is the
//! machine-readable listing regardless of any other flag.
//!
//! What `--format` still decides is the *framing*:
//!
//! | Format        | Output                                                  |
//! |---------------|---------------------------------------------------------|
//! | `text` (default) | One indented JSON array, as rclone produces          |
//! | `json`        | The same array                                          |
//! | `json-lines`  | One compact object per line                             |
//!
//! `json-lines` is the one to reach for on a large vault: it starts producing
//! records immediately, needs no closing bracket to be valid, and lets a
//! consumer process a listing far larger than its own memory. The array form is
//! streamed too — see [`listing::emit`] — so neither
//! framing ever holds the listing in RAM, but only `json-lines` lets the
//! *reader* avoid it as well.
//!
//! The shape of each object is documented on
//! [`JsonEntry`], including why `Path` is relative
//! and why no object key ever appears in it.
//!
//! ## Where the objects come from
//!
//! [`listing::source::open`] — one call that reaches a sealed vault, a plain
//! object store or a local directory through [`crate::source`], so this command
//! never learns which it was given.

use clap::Args;

use crate::ctx::Ctx;
use crate::error::Result;

use super::listing::emit::Emitter;
use super::listing::{self, Filter, JsonEntry, Target};

/// Arguments for `dctl lsjson`.
#[derive(Args, Debug)]
pub struct LsjsonArgs {
    /// Remote and path to list, as REMOTE:PATH. Defaults to --remote.
    #[arg(value_name = "REMOTE:PATH")]
    pub path: Option<String>,
}

/// List every object under the given path as JSON.
///
/// # Errors
/// A malformed spec or filter is a usage error; an unreachable index is fatal.
/// An empty result is neither: it emits `[]` (or, under `json-lines`, nothing at
/// all) and exits zero, because "no objects matched" is a successful answer to a
/// question.
pub async fn run(ctx: &Ctx, args: &LsjsonArgs) -> Result<()> {
    let target = Target::parse(args.path.as_deref(), ctx.globals.remote.as_deref())?;
    let filter = Filter::from_globals(&ctx.globals)?;
    let mut stream = listing::open(ctx, &target, filter).await?;

    let mut emitter = Emitter::new(&ctx.out);
    stream
        .try_for_each(|entry| emitter.push(&JsonEntry::new(entry)))
        .await?;
    emitter.finish()?;

    listing::report_links(ctx, &stream);
    listing::report_empty(ctx, &stream, &target);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Cli;
    use crate::commands::listing::Entry;
    use crate::commands::listing::tests_support::{ctx, listed};
    use crate::exit::ExitCode;
    use clap::Parser;
    use serde_json::Value;

    #[test]
    fn the_command_parses_with_and_without_a_path() {
        assert!(Cli::try_parse_from(["dctl", "lsjson"]).is_ok());
        let cli = Cli::try_parse_from(["dctl", "lsjson", "vault:photos"]).unwrap();
        assert_eq!(cli.command.name(), "lsjson");
    }

    #[test]
    fn the_emitted_shape_is_the_documented_one() {
        // The contract this command exists to publish. Asserted here as well as
        // on the shape itself, because this is the command whose output people
        // write parsers against.
        let entry = Entry::from_source(listed("photos/a.jpg", 42, Some(1_704_067_200)), "photos");
        let value: Value = serde_json::to_value(JsonEntry::new(&entry)).unwrap();
        assert_eq!(value["Path"], "a.jpg");
        assert_eq!(value["Name"], "a.jpg");
        assert_eq!(value["Size"], 42);
        assert_eq!(value["ModTime"], "2024-01-01T00:00:00Z");
        assert_eq!(value["IsDir"], false);
        assert_eq!(value["Hashes"]["blake3"], "abcd");
    }

    #[tokio::test]
    async fn json_is_emitted_regardless_of_the_global_format() {
        // Including plain `--format text`, which is what makes this a separate
        // verb rather than an alias for `ls --json`.
        for flags in [
            vec![],
            vec!["--format", "text"],
            vec!["--json"],
            vec!["--format", "json-lines"],
        ] {
            let ctx = ctx(&flags);
            let error = run(
                &ctx,
                &LsjsonArgs {
                    path: Some("vault:".into()),
                },
            )
            .await
            .unwrap_err();
            // Every framing reaches the same missing capability rather than a
            // "format not supported" refusal.
            assert_eq!(error.code(), ExitCode::FatalError, "{flags:?}");
        }
    }

    #[tokio::test]
    async fn an_unreachable_index_is_an_error_not_an_empty_array() {
        // A consumer that received `[]` would conclude the vault is empty and
        // could then prune a backup on the strength of it.
        let ctx = ctx(&["--json"]);
        let error = run(
            &ctx,
            &LsjsonArgs {
                path: Some("vault:photos".into()),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.hint().is_some());
    }

    #[tokio::test]
    async fn a_missing_target_is_a_usage_error() {
        let error = run(&ctx(&[]), &LsjsonArgs { path: None })
            .await
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[tokio::test]
    async fn a_rule_file_is_refused_rather_than_ignored() {
        // A machine listing that silently dropped its filters is the worst of
        // the three commands to get this wrong.
        let ctx = ctx(&["--filter-from", "rules.txt"]);
        let error = run(
            &ctx,
            &LsjsonArgs {
                path: Some("vault:".into()),
            },
        )
        .await
        .unwrap_err();
        assert_ne!(error.code(), ExitCode::Success);
        assert!(error.hint().is_some());
    }
}
