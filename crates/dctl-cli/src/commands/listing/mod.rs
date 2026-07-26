//! Shared machinery behind the six listing verbs.
//!
//! `ls`, `lsd`, `lsl`, `lsjson`, `tree` and `size` differ only in how they
//! *render* — the work of deciding which objects are in scope is identical for
//! all six, and doing it once here is what keeps the six commands honest about
//! agreeing with each other. A `--exclude` that hid a file from `ls` but not
//! from `size` would make the two commands disagree about the same vault, and a
//! user would have no way to tell which one was lying.
//!
//! This is not a subcommand. It carries no `Args` and no `run`; it is declared
//! beside the commands because it is theirs, in the same way
//! [`super::integrity`] belongs to the verification verbs.
//!
//! ## The pipeline
//!
//! ```text
//!   REMOTE:PATH ──▶ target ──▶ source ──▶ stream ──▶ (renderer)
//!                              │           │
//!                              │           └─ filter: globs, sizes, depth
//!                              └─ pages of Entry, one page in RAM at a time
//! ```
//!
//! [`target`] turns what the user typed into a remote plus a logical prefix,
//! [`source`] opens a paged view of the objects beneath it, [`filter`] decides
//! which of them are in scope, and [`stream`] joins the two so a renderer sees
//! one `Entry` at a time and never a `Vec` of all of them.
//!
//! ## Why paging, when the index hands back a `Vec` today
//!
//! `PLAN.md` §16.2 forbids ever holding the full file list in RAM, and
//! [`Vault::list`](dctl_core::Vault::list) currently violates that by
//! materialising every record before returning. That buffer is the core's and
//! lives in [`crate::source::vault`], which says so plainly and names what
//! removing it takes. The boundary is drawn at [`source::Pages`] anyway: the
//! renderers are written against a page cursor they cannot see the end of, so
//! the day the index exposes a range scan the change is confined to one `impl`
//! and no command is rewritten. Structuring it the other way round — renderers
//! over a slice, "we'll stream it later" — is how a tool ends up unable to list
//! its own dataset.
//!
//! ## Where the objects come from
//!
//! Nothing here opens a vault or builds a backend. [`source::open`] hands the
//! target to [`crate::source::open`], which is the binary's single answer to
//! "what does this spec address" — a sealed vault, a plain object store, or a
//! directory on this machine. The six verbs cannot tell which they got, and
//! therefore cannot be the place where the three drift apart.
//!
//! ## Order is a contract
//!
//! Every source yields entries in ascending lexicographic order of logical
//! path, which is what a B-tree range scan produces for free. Three of the
//! renderers depend on it: [`dirs`] can close a directory the moment the path
//! leaves it, [`super::tree`] can nest without a second pass, and `size` needs
//! no ordering at all but gets determinism from it. A source that returned
//! records in arbitrary order would not fail loudly — it would silently produce
//! a wrong tree — so the requirement is stated on the trait and tested there.

pub mod dirs;
pub mod emit;
pub mod entry;
pub mod filter;
pub mod glob;
pub mod json;
pub mod render;
pub mod source;
pub mod stream;
pub mod target;
pub mod time;

pub use entry::Entry;
pub use filter::Filter;
pub use json::JsonEntry;
pub use stream::Stream;
pub use target::Target;

use crate::ctx::Ctx;
use crate::error::Result;

/// Open the filtered entry stream a listing command reads from.
///
/// The one call every listing verb makes, so that the order of operations —
/// resolve the target, build the filter, open the source, join them — cannot
/// drift between commands.
///
/// # Errors
/// Propagates a malformed target or an unusable filter, plus whatever opening
/// the source reported — see [`source::open`].
pub async fn open(ctx: &Ctx, target: &Target, filter: Filter) -> Result<Stream> {
    Ok(Stream::new(source::open(ctx, target).await?, filter))
}

/// Say on stderr why a listing came back empty, when the reason is the filters.
///
/// Only ever a note, never data: `dctl ls | wc -l` must still see zero lines,
/// and a JSON consumer must still receive `[]` and nothing else. The distinction
/// is worth making because "the directory is empty" sends a user looking for
/// missing files, while "your `--include` matched nothing" sends them to their
/// own command line — and a listing family that could not tell the two apart
/// would be the tool's least trustworthy corner.
pub fn report_empty(ctx: &Ctx, stream: &Stream, target: &Target) {
    if stream.matched() > 0 {
        return;
    }

    if stream.filter().is_restricting() && stream.seen() > 0 {
        ctx.out.info(format!(
            "no objects matched the active filters ({} considered under '{}')",
            stream.seen(),
            target.display()
        ));
    } else {
        ctx.out
            .info(format!("no objects under '{}'", target.display()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exit::ExitCode;

    #[tokio::test]
    async fn opening_a_stream_fails_loudly_rather_than_returning_an_empty_one() {
        // The whole point of `PLAN.md` §6: a listing that cannot reach its
        // source must not render as "the vault is empty".
        let ctx = crate::commands::listing::tests_support::ctx(&["--no-ask-password"]);
        let target = Target::parse(Some("nosuchremote:"), None).unwrap();
        let error = open(&ctx, &target, Filter::from_globals(&ctx.globals).unwrap())
            .await
            .err()
            .expect("an unconfigured remote cannot be listed");
        assert_ne!(error.code(), ExitCode::Success);
    }

    #[tokio::test]
    async fn a_real_directory_streams_through_the_filter() {
        // The other half of the same promise: when the source *is* reachable,
        // the pipeline end to end produces rows rather than a refusal.
        let root = tempfile::TempDir::new().unwrap();
        std::fs::write(root.path().join("a.jpg"), b"1").unwrap();
        std::fs::write(root.path().join("b.txt"), b"22").unwrap();

        let ctx = crate::commands::listing::tests_support::ctx(&["--include", "*.jpg"]);
        let target = Target::parse(Some(&root.path().to_string_lossy()), None).unwrap();
        let mut stream = open(&ctx, &target, Filter::from_globals(&ctx.globals).unwrap())
            .await
            .expect("a directory lists");

        let mut seen = Vec::new();
        stream
            .try_for_each(|entry| {
                seen.push(entry.path().to_string());
                Ok(())
            })
            .await
            .expect("the listing completes");
        assert_eq!(seen, vec!["a.jpg"]);
        assert_eq!(stream.seen(), 2, "both files were considered");
    }
}

/// Helpers shared by the tests of this module and its children.
///
/// Building a [`Ctx`] takes a full parse of the global flags, and every module
/// under here needs one; duplicating the harness eleven times would guarantee
/// eleven subtly different ones.
#[cfg(test)]
pub mod tests_support {
    use clap::Parser;

    use crate::cli::globals::GlobalArgs;
    use crate::ctx::Ctx;
    use crate::source;

    use super::entry::Entry;
    use super::source::Pager;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    /// A context built from the given global flags, as if typed on the command
    /// line.
    pub fn ctx(args: &[&str]) -> Ctx {
        let parsed = Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied()));
        Ctx::new(parsed.globals)
    }

    /// One entry with a plausible shape, as a source would have reported it.
    ///
    /// Carries a content hash, because the sealed source does and the renderers
    /// that show a checksum column are the ones being tested.
    pub fn listed(path: &str, size: u64, modified: Option<i64>) -> source::Entry {
        source::Entry::new(path, size)
            .with_modified(modified)
            .with_content_hash(vec![0xab, 0xcd])
    }

    /// A single entry rooted at `root`.
    pub fn entry(root: &str, path: &str, size: u64) -> Entry {
        Entry::from_source(listed(path, size, Some(0)), root)
    }

    /// A pager over the given paths, in the order a sorted index would yield
    /// them.
    pub fn pager(root: &str, paths: &[(&str, u64)]) -> Pager {
        let entries = paths
            .iter()
            .map(|(path, size)| listed(path, *size, Some(0)))
            .collect();
        Pager::new(entries, root)
    }
}
