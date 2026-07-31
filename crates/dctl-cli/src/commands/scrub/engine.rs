//! The walk itself: select, re-read, record.
//!
//! The loop is deliberately small, because everything interesting about a scrub
//! has already been decided by the time it starts — [`Plan`] knows which objects
//! are in the sample and when the error budget runs out, [`Report`] knows how a
//! verdict becomes a grade, and [`Source::verify`] knows what "intact" means for
//! the remote in hand. What is left here is the part that must not be got wrong:
//! every object is either read or *counted as skipped*, and nothing is quietly
//! passed over.
//!
//! ## Why every object is either scanned or skipped
//!
//! A scrub's output is a claim about coverage as much as about health.
//! `healthy` after reading a tenth of a vault is a statement about that tenth,
//! and the only thing standing between that and a dangerous overstatement is
//! that the other nine tenths were *counted*. So there is no path through this
//! loop that neither reads an object nor calls [`Report::skip`], and a filter
//! that removes an object removes it from the dataset's definition entirely
//! rather than silently shrinking the denominator — which is why the filtered
//! case is documented on the command rather than folded into the skip count.
//!
//! ## Memory
//!
//! One [`Entry`](crate::source::Entry) at a time from the cursor, and
//! [`Source::verify`] never materialises an object. A scrub of a vault holding
//! multi-gigabyte videos therefore costs a chunk, not a video — which is the
//! only reason the command is runnable on the datasets it is meant for.
//!
//! ## Failures are findings, not exits
//!
//! A corrupt or unreachable object does not abort the walk. The most valuable
//! thing a scrub reports is *how widespread* the damage is, and returning at the
//! first bad object would hide every other one — `--max-errors` exists precisely
//! so that stopping early is a decision the operator makes explicitly, and the
//! report records that it happened.

use crate::commands::integrity::failure::{Verdict, classify};
use crate::commands::listing::{self, Filter};
use crate::ctx::Ctx;
use crate::error::Result;
use crate::source::Source;
use crate::source::open::Opened;

use super::plan::Plan;
use super::report::{Record, Report};

/// Re-read everything `plan` selects under `prefix`, recording what was found.
///
/// # Errors
/// Only a failure of the *listing* — an index or provider that could not be
/// enumerated. A failure to read one object is a verdict on that object and
/// never an error here, because a run that stopped at the first damaged file
/// would answer a much less useful question than the one that was asked.
/// Takes an [`Opened`] rather than a source and a prefix for the reason
/// [`super::super::verify::engine::verify`] gives: the two were separate
/// parameters, `scrub` passed the spec's path instead of the resolver's prefix,
/// and nothing in the workspace could turn that red.
pub async fn scrub(
    ctx: &Ctx,
    opened: &Opened,
    filter: &Filter,
    plan: &Plan,
    report: &mut Report,
) -> Result<()> {
    let source = opened.source();
    let prefix = opened.prefix();
    let mut entries = opened.enumerate().await?;
    let mut errors = 0;

    while let Some(entry) = entries.next().await? {
        // Building the listing view costs a clone, so it is skipped entirely
        // when no filter is in force — which is every run that does not ask for
        // one, including every scheduled full scrub.
        if filter.is_restricting()
            && !filter.matches(&listing::Entry::from_source(entry.clone(), prefix))
        {
            continue;
        }

        if !plan.selects(&entry.path) {
            report.skip();
            continue;
        }

        let verdict = examine(ctx, source, &entry.path).await;
        if verdict.is_failure() {
            errors += 1;
        }
        report.push(Record::new(entry.path, verdict, entry.size));

        // Checked after the object is recorded, so the object that exhausted the
        // budget is in the report rather than being the one nobody hears about.
        if plan.budget_exhausted(errors) {
            report.stopped_early();
            break;
        }
    }

    Ok(())
}

/// Read one object back and classify what happened.
///
/// The message is written to stderr as it is found rather than being carried
/// into the report, for two reasons: a scrub of a badly damaged remote produces
/// findings for hours and an operator wants them as they happen, and the report
/// has no field for a provider's own wording — [`Record`] carries a verdict,
/// which is the part a machine consumer can act on.
///
/// The error-to-verdict rule is [`classify`], which lives in the integrity
/// family rather than here because `verify` and `hashsum` ask the same question
/// of the same errors and three copies of it would drift.
async fn examine(ctx: &Ctx, source: &dyn Source, path: &str) -> Verdict {
    match source.verify(path).await {
        Ok(()) => Verdict::Ok,
        Err(error) => {
            let verdict = classify(&error);
            ctx.out
                .warn(format!("{}: {}", verdict.slug(), error.message()));
            verdict
        }
    }
}

#[cfg(test)]
mod tests {

    /// Pair a source with the prefix a read of it is scoped by, the way
    /// `crate::source::open` does for a real run.
    ///
    /// The engines take the two together rather than as separate parameters,
    /// because as separate parameters the call site passed the wrong prefix and
    /// nothing in the workspace could turn that red — see the function's own
    /// documentation.
    fn opened(source: impl Source + 'static, prefix: &str) -> Opened {
        Opened::for_test(Box::new(source), prefix)
    }
    use super::*;
    use crate::cli::GlobalArgs;
    use crate::constants::{SCRUB_FULL_SAMPLE_PERCENT, SCRUB_MAX_ERRORS_UNLIMITED};
    use crate::source::Assurance;
    use crate::source::plain::PlainSource;
    use crate::source::vault::VaultSource;
    use clap::Parser;
    use dctl_store::{Backend, LocalFs};
    use std::sync::Arc;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn ctx(args: &[&str]) -> Ctx {
        Ctx::new(Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied())).globals)
    }

    /// A real directory behind a real backend — the same one a `local:` remote
    /// builds, so the read-back path under test is the production one.
    fn store(files: &[(&str, &[u8])]) -> (tempfile::TempDir, PlainSource) {
        let root = tempfile::TempDir::new().expect("a temporary directory");
        for (relative, bytes) in files {
            let path = root.path().join(relative);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("the parent directory is created");
            }
            std::fs::write(&path, bytes).expect("the fixture file is written");
        }
        let backend: Arc<dyn Backend> = Arc::new(LocalFs::new(root.path()));
        (root, PlainSource::new(backend))
    }

    fn report() -> Report {
        Report::new("store:", "strict", Assurance::ReadBack, 100, 0, false)
    }

    fn full_plan() -> Plan {
        Plan::new(
            SCRUB_FULL_SAMPLE_PERCENT,
            SCRUB_MAX_ERRORS_UNLIMITED,
            false,
            0,
        )
        .expect("the default plan is valid")
    }

    #[tokio::test]
    async fn every_object_is_read_back_and_counted() {
        let (_root, source) = store(&[("a.txt", b"1"), ("sub/b.txt", b"22")]);
        let mut report = report();
        scrub(
            &ctx(&[]),
            &opened(source, ""),
            &Filter::default(),
            &full_plan(),
            &mut report,
        )
        .await
        .expect("the listing succeeds");

        assert_eq!(report.coverage.scanned, 2);
        assert_eq!(report.coverage.healthy, 2);
        assert_eq!(report.coverage.bytes, Some(3));
        assert_eq!(report.coverage.skipped, 0);
        assert!(report.outcome().is_none());
    }

    #[tokio::test]
    async fn objects_the_sample_passes_over_are_counted_rather_than_forgotten() {
        // The property that stops "healthy" over a 10% sample being read as a
        // claim about the whole dataset.
        let files: Vec<(String, Vec<u8>)> = (0..200)
            .map(|n| (format!("f{n:03}.bin"), b"x".to_vec()))
            .collect();
        let borrowed: Vec<(&str, &[u8])> = files
            .iter()
            .map(|(name, bytes)| (name.as_str(), bytes.as_slice()))
            .collect();
        let (_root, source) = store(&borrowed);

        let plan = Plan::new(10, SCRUB_MAX_ERRORS_UNLIMITED, false, 4_242).unwrap();
        let mut report = report();
        scrub(
            &ctx(&[]),
            &opened(source, ""),
            &Filter::default(),
            &plan,
            &mut report,
        )
        .await
        .unwrap();

        assert_eq!(report.coverage.scanned + report.coverage.skipped, 200);
        assert!(report.coverage.skipped > 0, "a 10% sample must skip most");
        assert!(report.coverage.scanned > 0, "and must still read some");
    }

    #[tokio::test]
    async fn a_prefix_scopes_the_scrub_to_whole_components() {
        let (_root, source) = store(&[
            ("photos/a.jpg", b"a"),
            ("photos-backup/b.jpg", b"b"),
            ("other/c.jpg", b"c"),
        ]);
        let mut report = report();
        scrub(
            &ctx(&[]),
            &opened(source, "photos"),
            &Filter::default(),
            &full_plan(),
            &mut report,
        )
        .await
        .unwrap();
        assert_eq!(report.coverage.scanned, 1);
    }

    /// A real sealed vault over temporary directories, with `files` written
    /// through the ordinary verified-write path.
    ///
    /// Returned with the store directory, so a test can reach past DCTL and
    /// damage the bytes a provider is holding — which is the only way to prove
    /// this command detects what it exists to detect.
    async fn sealed(
        files: &[(&str, &[u8])],
    ) -> (tempfile::TempDir, tempfile::TempDir, VaultSource) {
        use dctl_core::Vault;

        let store = tempfile::TempDir::new().expect("a temporary store");
        let index = tempfile::TempDir::new().expect("a temporary index");
        let index_path = index.path().join("index.redb");
        let backend: Arc<dyn Backend> = Arc::new(LocalFs::new(store.path()));

        let vault = Vault::init(backend, &index_path, "pw")
            .await
            .expect("a fresh vault initialises")
            .vault;
        for (path, bytes) in files {
            vault
                .put_file(path, bytes, dctl_core::Modified::Now)
                .await
                .expect("a verified write");
        }

        let session = crate::session::Session {
            vault,
            remote: "archive:".to_string(),
            index: index_path,
        };
        (store, index, VaultSource::new(session))
    }

    /// Overwrite every sealed object in `store` with garbage of the same length.
    ///
    /// Deliberately not a subtle single-bit flip: the point of the test is that
    /// damage is *detected*, and a whole-object overwrite is damage no
    /// authenticated format can miss, so the test cannot pass or fail on where a
    /// byte happened to land inside a header.
    fn damage_objects(store: &std::path::Path) -> usize {
        let mut damaged = 0;
        // Sealed objects live under the layout's object prefix; the envelope and
        // name records live elsewhere and must be left alone, or the vault would
        // fail to open rather than reporting a damaged object.
        let objects = store.join("o");
        for entry in std::fs::read_dir(&objects).expect("the object directory exists") {
            let path = entry.expect("a directory entry").path();
            if !path.is_file() {
                continue;
            }
            let length = std::fs::metadata(&path)
                .expect("the object is readable")
                .len();
            std::fs::write(&path, vec![0xA5; length as usize]).expect("the object is overwritten");
            damaged += 1;
        }
        damaged
    }

    #[tokio::test]
    async fn damaged_objects_are_found_named_and_fail_the_run() {
        // The whole reason the command exists: rot is discovered here, not on
        // restore day.
        let (store, _index, source) = sealed(&[("a.txt", b"one"), ("b.txt", b"two")]).await;
        assert_eq!(damage_objects(store.path()), 2);

        let mut report = Report::new(
            "archive:",
            "strict",
            Assurance::Authenticated,
            100,
            0,
            false,
        );
        scrub(
            &ctx(&[]),
            &opened(source, ""),
            &Filter::default(),
            &full_plan(),
            &mut report,
        )
        .await
        .expect("the listing still succeeds — the index is intact");

        assert_eq!(report.coverage.scanned, 2);
        assert_eq!(report.coverage.damaged, 2);
        assert_eq!(report.coverage.healthy, 0);
        assert_eq!(report.findings.len(), 2, "every damaged object is named");

        let error = report.outcome().expect("unrepaired damage must fail");
        assert_eq!(error.code(), crate::exit::ExitCode::IntegrityFailure);
        assert_eq!(error.code().as_i32(), 21);
    }

    #[tokio::test]
    async fn an_intact_vault_reads_back_clean() {
        let (_store, _index, source) = sealed(&[("a.txt", b"one"), ("sub/b.txt", b"two")]).await;
        let mut report = Report::new(
            "archive:",
            "strict",
            Assurance::Authenticated,
            100,
            0,
            false,
        );
        scrub(
            &ctx(&[]),
            &opened(source, ""),
            &Filter::default(),
            &full_plan(),
            &mut report,
        )
        .await
        .unwrap();

        assert_eq!(report.coverage.healthy, 2);
        assert_eq!(report.coverage.damaged, 0);
        assert!(report.outcome().is_none());
        assert!(report.findings.is_empty());
    }

    #[tokio::test]
    async fn a_bounded_budget_stops_early_and_the_report_admits_it() {
        // A run that ended early covered less than it was asked to, and a
        // consumer reading only the JSON has to be able to tell — otherwise the
        // damage count reads as the full extent of the damage.
        let (store, _index, source) =
            sealed(&[("a.txt", b"1"), ("b.txt", b"2"), ("c.txt", b"3")]).await;
        damage_objects(store.path());

        let plan = Plan::new(SCRUB_FULL_SAMPLE_PERCENT, 1, false, 0).unwrap();
        assert!(plan.is_bounded());

        let mut report = Report::new(
            "archive:",
            "strict",
            Assurance::Authenticated,
            100,
            0,
            false,
        );
        scrub(
            &ctx(&[]),
            &opened(source, ""),
            &Filter::default(),
            &plan,
            &mut report,
        )
        .await
        .unwrap();

        assert!(report.stopped_early, "the budget was reached");
        assert_eq!(report.coverage.damaged, 1);
        assert_eq!(
            report.coverage.scanned, 1,
            "the object that exhausted the budget is still recorded"
        );
    }

    #[tokio::test]
    async fn an_unlimited_budget_never_stops_early() {
        let (_root, source) = store(&[("a.txt", b"1"), ("b.txt", b"2"), ("c.txt", b"3")]);
        let plan = full_plan();
        assert!(
            !plan.is_bounded(),
            "0 means unlimited, not a budget of zero"
        );

        let mut report = report();
        scrub(
            &ctx(&[]),
            &opened(source, ""),
            &Filter::default(),
            &plan,
            &mut report,
        )
        .await
        .unwrap();
        assert!(!report.stopped_early);
        assert_eq!(report.coverage.scanned, 3);
    }

    #[tokio::test]
    async fn filters_narrow_what_is_read() {
        let (_root, source) = store(&[("a.jpg", b"1"), ("b.txt", b"22")]);
        let context = ctx(&["--include", "*.jpg"]);
        let filter = Filter::from_globals(&context.globals).expect("the pattern compiles");
        let mut report = report();
        scrub(
            &context,
            &opened(source, ""),
            &filter,
            &full_plan(),
            &mut report,
        )
        .await
        .unwrap();
        assert_eq!(report.coverage.scanned, 1);
    }
}
