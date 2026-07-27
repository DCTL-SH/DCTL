//! The walk: select, prove, record.
//!
//! Almost all of the interesting decisions have already been made by the time
//! this loop starts. [`Source::verify`] knows what "intact" means for the remote
//! in hand, [`Report`] knows how verdicts become an exit code, and
//! [`failure::classify`] knows what a failed read means for the data. What is
//! left here is the part that must not be got wrong: every object the filter
//! admits is examined and recorded, and a run that stopped early admits it.
//!
//! ## Why the default keeps going
//!
//! The most useful thing a verify run can tell an operator is *how much* is
//! damaged. One corrupt object out of 40,000 is a restore of one file; 12,000 is
//! a lost dataset and a different afternoon. Returning at the first failure
//! answers neither question, so failures are findings here rather than exits,
//! and the run's outcome is computed from the tally at the end.
//!
//! `--fail-fast` opts out, and the report records that it stopped
//! ([`Report::stopped_early`]) — otherwise the summary would read as the full
//! extent of the damage when it is only the first of it.
//!
//! ## Memory
//!
//! One [`Entry`](crate::source::Entry) at a time from the cursor, and
//! [`Source::verify`] never materialises an object: a vault stream-decrypts into
//! a sink at O(chunk). A `verify` of a vault full of multi-gigabyte videos
//! therefore costs a chunk, not a video.

use crate::commands::integrity::failure::{Verdict, classify};
use crate::commands::listing::{self, Filter};
use crate::ctx::Ctx;
use crate::error::Result;
use crate::source::Source;

use super::report::{Record, Report};

/// Verify everything under `prefix` that `filter` admits, recording what was
/// found.
///
/// `fail_fast` stops at the first object that does not verify.
///
/// # Errors
/// Only a failure of the *listing* — an index or provider that could not be
/// enumerated. A failure to verify one object is a verdict on that object and
/// never an error here; see the module documentation.
pub async fn verify(
    ctx: &Ctx,
    source: &dyn Source,
    prefix: &str,
    filter: &Filter,
    fail_fast: bool,
    report: &mut Report,
) -> Result<()> {
    let mut entries = source.enumerate(prefix).await?;

    while let Some(entry) = entries.next().await? {
        // Building the listing view costs a clone, so it is skipped entirely
        // when no filter is in force.
        if filter.is_restricting()
            && !filter.matches(&listing::Entry::from_source(entry.clone(), prefix))
        {
            continue;
        }

        let (verdict, detail) = examine(ctx, source, &entry.path).await;
        let mut record = Record::new(&entry.path, verdict, entry.size);
        if let Some(detail) = detail {
            record = record.with_detail(detail);
        }
        report.push(record);

        // Checked after the object is recorded, so the object that ended the run
        // is in the report rather than being the one nobody hears about.
        if fail_fast && verdict.is_failure() {
            report.stopped_early();
            break;
        }
    }

    Ok(())
}

/// Prove one object, and classify what happened if it could not be proved.
///
/// The provider's own wording is carried into the record as its `detail` rather
/// than only written to stderr, because a `--json` consumer that redirected
/// stdout must still be able to see *why* an object failed. That is the
/// difference between this and `scrub`, whose findings arrive over hours and are
/// wanted as they happen; a `verify` is a single question with a single answer
/// document.
async fn examine(ctx: &Ctx, source: &dyn Source, path: &str) -> (Verdict, Option<String>) {
    match source.verify(path).await {
        Ok(()) => (Verdict::Ok, None),
        Err(error) => {
            let verdict = classify(&error);
            ctx.out
                .warn(format!("{}: {}", verdict.slug(), error.message()));
            (verdict, Some(error.message().to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::GlobalArgs;
    use crate::exit::ExitCode;
    use crate::session::Session;
    use crate::source::plain::PlainSource;
    use crate::source::vault::VaultSource;
    use clap::Parser;
    use dctl_core::Vault;
    use dctl_store::{Backend, LocalFs};
    use std::sync::Arc;
    use tempfile::TempDir;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn ctx(args: &[&str]) -> Ctx {
        Ctx::new(Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied())).globals)
    }

    fn report() -> Report {
        Report::new("archive:", "strict")
    }

    /// A real directory behind a real backend.
    fn store(files: &[(&str, &[u8])]) -> (TempDir, PlainSource) {
        let root = TempDir::new().expect("a temporary directory");
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

    /// A real sealed vault, with `files` written through the ordinary verified
    /// write. The store directory comes back so a test can reach past DCTL and
    /// damage the bytes a provider is holding.
    async fn sealed(files: &[(&str, &[u8])]) -> (TempDir, TempDir, VaultSource) {
        let store = TempDir::new().expect("a temporary store");
        let index = TempDir::new().expect("a temporary index");
        let index_path = index.path().join("index.redb");
        let backend: Arc<dyn Backend> = Arc::new(LocalFs::new(store.path()));

        let vault = Vault::init(backend, &index_path, "pw")
            .await
            .expect("a fresh vault initialises")
            .vault;
        for (path, bytes) in files {
            vault.put_file(path, bytes).await.expect("a verified write");
        }

        let session = Session {
            vault,
            remote: "archive:".to_string(),
            index: index_path,
        };
        (store, index, VaultSource::new(session))
    }

    /// Flip a single byte in every sealed object.
    ///
    /// Deliberately one byte rather than a whole-object overwrite: the claim
    /// under test is that *any* alteration is caught, and an AEAD that only
    /// noticed wholesale replacement would be no use against bit rot, which is
    /// exactly a single flipped byte.
    fn flip_a_byte(store: &std::path::Path) -> usize {
        let mut damaged = 0;
        let objects = store.join("o");
        for entry in std::fs::read_dir(&objects).expect("the object directory exists") {
            let path = entry.expect("a directory entry").path();
            if !path.is_file() {
                continue;
            }
            let mut bytes = std::fs::read(&path).expect("the object is readable");
            // The last byte is inside the footer or the final chunk's tag on
            // every object large enough to have one, and is present on every
            // object at all — which a fixed offset near the front would not be.
            if let Some(last) = bytes.last_mut() {
                *last ^= 0xFF;
                std::fs::write(&path, &bytes).expect("the object is rewritten");
                damaged += 1;
            }
        }
        damaged
    }

    #[tokio::test]
    async fn an_intact_vault_verifies_clean_and_the_run_succeeds() {
        let (_store, _index, source) = sealed(&[("a.txt", b"one"), ("sub/b.txt", b"two")]).await;
        let mut report = report();
        verify(
            &ctx(&[]),
            &source,
            "",
            &Filter::default(),
            false,
            &mut report,
        )
        .await
        .expect("the listing succeeds");

        assert_eq!(report.summary.examined, 2);
        assert_eq!(report.summary.verified, 2);
        assert_eq!(report.summary.failed, 0);
        assert_eq!(report.summary.bytes, Some(6));
        assert!(report.outcome().is_none());
        assert!(!report.stopped_early);
    }

    #[tokio::test]
    async fn a_single_flipped_byte_fails_the_run_with_exit_twenty_one() {
        // The whole reason the command exists.
        let (store, _index, source) = sealed(&[("a.txt", b"one"), ("b.txt", b"two")]).await;
        assert_eq!(flip_a_byte(store.path()), 2);

        let mut report = report();
        verify(
            &ctx(&[]),
            &source,
            "",
            &Filter::default(),
            false,
            &mut report,
        )
        .await
        .expect("the listing still succeeds — the index is intact");

        assert_eq!(report.summary.examined, 2);
        assert_eq!(report.summary.failed, 2, "the default reports how much");
        assert_eq!(report.worst(), Verdict::Corrupt);

        let error = report.outcome().expect("damage must fail the run");
        assert_eq!(error.code(), ExitCode::IntegrityFailure);
        assert_eq!(error.code().as_i32(), 21);
        assert!(
            error.message().contains("NOT served"),
            "the message must say the data was not returned: {}",
            error.message()
        );
        assert!(error.message().contains("2 of 2"));
    }

    #[tokio::test]
    async fn the_default_measures_the_whole_extent_of_the_damage() {
        // One corrupt object out of four is a restore of one file; four out of
        // four is a lost dataset. Stopping at the first would answer neither.
        let (store, _index, source) = sealed(&[
            ("a.txt", b"1"),
            ("b.txt", b"2"),
            ("c.txt", b"3"),
            ("d.txt", b"4"),
        ])
        .await;
        flip_a_byte(store.path());

        let mut report = report();
        verify(
            &ctx(&[]),
            &source,
            "",
            &Filter::default(),
            false,
            &mut report,
        )
        .await
        .unwrap();
        assert_eq!(report.summary.examined, 4);
        assert_eq!(report.summary.failed, 4);
        assert!(!report.stopped_early);
    }

    #[tokio::test]
    async fn fail_fast_stops_at_the_first_and_the_report_admits_it() {
        // A consumer reading only the JSON has to be able to tell, or the count
        // reads as the full extent of the damage.
        let (store, _index, source) =
            sealed(&[("a.txt", b"1"), ("b.txt", b"2"), ("c.txt", b"3")]).await;
        flip_a_byte(store.path());

        let mut report = report();
        verify(
            &ctx(&[]),
            &source,
            "",
            &Filter::default(),
            true,
            &mut report,
        )
        .await
        .unwrap();

        assert!(report.stopped_early, "the run ended at the first failure");
        assert_eq!(report.summary.examined, 1);
        assert_eq!(report.summary.failed, 1);
        assert_eq!(report.outcome().unwrap().code(), ExitCode::IntegrityFailure);
    }

    #[tokio::test]
    async fn fail_fast_does_not_stop_on_a_clean_object() {
        // Only a *failure* ends the run; a clean one that happened to be first
        // must not truncate the listing.
        let (_store, _index, source) = sealed(&[("a.txt", b"1"), ("b.txt", b"2")]).await;
        let mut report = report();
        verify(
            &ctx(&[]),
            &source,
            "",
            &Filter::default(),
            true,
            &mut report,
        )
        .await
        .unwrap();
        assert_eq!(report.summary.examined, 2);
        assert!(!report.stopped_early);
    }

    #[tokio::test]
    async fn a_failed_object_carries_the_reason_into_the_report() {
        // On stdout, not only on stderr: a `--json` consumer that redirected
        // stdout must still be able to see why an object failed.
        let (store, _index, source) = sealed(&[("a.txt", b"one")]).await;
        flip_a_byte(store.path());

        let mut report = report();
        verify(
            &ctx(&[]),
            &source,
            "",
            &Filter::default(),
            false,
            &mut report,
        )
        .await
        .unwrap();
        let detail = report.objects[0]
            .detail
            .as_deref()
            .expect("a failure must say why");
        assert!(!detail.is_empty());
    }

    #[tokio::test]
    async fn a_plain_remote_verifies_by_reading_every_byte_back() {
        // A weaker claim than a vault's, and the report says so through the
        // source's assurance rather than through this count — but the walk still
        // has to happen, because a replica quietly losing objects is exactly
        // what it catches.
        let (_root, source) = store(&[("a.txt", b"1"), ("sub/b.txt", b"22")]);
        let mut report = Report::new("store:", "strict");
        verify(
            &ctx(&[]),
            &source,
            "",
            &Filter::default(),
            false,
            &mut report,
        )
        .await
        .unwrap();
        assert_eq!(report.summary.verified, 2);
        assert!(report.outcome().is_none());
    }

    #[tokio::test]
    async fn a_prefix_scopes_the_run_to_whole_components() {
        let (_root, source) = store(&[
            ("photos/a.jpg", b"a"),
            ("photos-backup/b.jpg", b"b"),
            ("other/c.jpg", b"c"),
        ]);
        let mut report = Report::new("store:photos", "strict");
        verify(
            &ctx(&[]),
            &source,
            "photos",
            &Filter::default(),
            false,
            &mut report,
        )
        .await
        .unwrap();
        assert_eq!(report.summary.examined, 1);
    }

    #[tokio::test]
    async fn filters_narrow_what_is_verified() {
        let (_root, source) = store(&[("a.jpg", b"1"), ("b.txt", b"22")]);
        let context = ctx(&["--include", "*.jpg"]);
        let filter = Filter::from_globals(&context.globals).expect("the pattern compiles");
        let mut report = Report::new("store:", "strict");
        verify(&context, &source, "", &filter, false, &mut report)
            .await
            .unwrap();
        assert_eq!(report.summary.examined, 1);
    }

    #[tokio::test]
    async fn an_object_the_provider_lost_is_missing_rather_than_corrupt() {
        // Different verdict, different exit code, different next action: this
        // one is a reconciliation problem, and reporting it as corruption would
        // send someone hunting for damage that is not there.
        let (store, _index, source) = sealed(&[("a.txt", b"one")]).await;
        for entry in std::fs::read_dir(store.path().join("o")).unwrap() {
            let path = entry.unwrap().path();
            if path.is_file() {
                std::fs::remove_file(&path).unwrap();
            }
        }

        let mut report = report();
        verify(
            &ctx(&[]),
            &source,
            "",
            &Filter::default(),
            false,
            &mut report,
        )
        .await
        .unwrap();
        assert_eq!(report.worst(), Verdict::Missing);
        assert_eq!(report.outcome().unwrap().code(), ExitCode::FileNotFound);
    }
}
