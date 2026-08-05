//! The loop that actually removes things, and the order it removes them in.
//!
//! # The order, and what a crash at each point leaves behind
//!
//! Two orderings matter, at two different levels, and only one of them is this
//! crate's to choose. Both are written out here because "which order?" is the
//! question an operator asks after a machine dies half-way through a `purge`,
//! and the answer must be findable in the source rather than reconstructed from
//! a damaged vault.
//!
//! ## 1. The order across the selection — chosen here
//!
//! **Objects first, in ascending path order; directory markers last, deepest
//! first.** [`super::selection`] produces the list in exactly that shape and this
//! loop preserves it, one object at a time, never in parallel.
//!
//! Every intermediate state is therefore the same shape: *fewer objects, the
//! structure they lived in still declared*. Concretely, an interruption can
//! never leave:
//!
//! * a directory whose marker is gone while files are still stored inside it —
//!   the marker is removed after everything under it, so an undeclared directory
//!   is always an empty one;
//! * a parent directory removed while a child is still declared beneath it —
//!   markers go deepest first, so the tree is dismantled from the leaves.
//!
//! Serial rather than concurrent, deliberately. Concurrency would buy latency on
//! a large `purge` and would cost the ordering above, because two in-flight
//! deletes have no order at all; and the loop is bounded by round trips to one
//! provider, which is the thing `--transfers` exists to parallelise on the write
//! side and where a delete storm is most likely to be rate-limited.
//!
//! ## 2. The order within one object — `dctl-core`'s, not this crate's
//!
//! A sealed removal is one call to [`Vault::delete_file`](dctl_core::Vault::delete_file),
//! and that call performs three deletions in this order:
//!
//! 1. the **content object** (`o/…`) — the ciphertext;
//! 2. the **§5 name record** (`n/…`) — the authoritative, backend-resident
//!    path → object map that makes a vault restorable on a bare machine;
//! 3. the **index row** — the local encrypted cache of that map.
//!
//! A crash leaves, respectively:
//!
//! | crash after | backend state | index state | what a user sees | repair |
//! |-------------|---------------|-------------|------------------|--------|
//! | 1 | name record present, object gone | row present | the file is listed but cannot be read | re-run the removal |
//! | 2 | nothing | row present | the file is listed but cannot be read | re-run the removal, or `dctl index rebuild` |
//! | 3 | nothing | nothing | the file is gone | — |
//!
//! **This is not the order this file would have chosen**, and saying so is more
//! useful than implying otherwise. The state after step 1 is a dangling index
//! entry — a listed file whose bytes are gone — and the ideal order is the
//! reverse: index row, then name record, then object, so that an interruption
//! leaves a *content object nobody refers to*, which is exactly the debris
//! `dctl cleanup --class orphans` reclaims. That reversal is not available from
//! here: the three steps are one call into `dctl-core`, whose `Index` and
//! `Backend` handles are private to that crate, and reimplementing them in the
//! CLI would mean a second copy of the vault's storage layout. So the mitigation
//! is the one this layer *can* make, and it is real:
//!
//! * **Nothing is reported as removed until the index row is gone.**
//!   `delete_file` returns `true` only after step 3 has committed, and only that
//!   `true` produces a `removed` record. So the report can never claim a file is
//!   gone while a listing would still show it — which is the promise
//!   [the plan](https://doc.dctl.sh/project/plan) §6 actually makes.
//! * **Removal is idempotent, and re-running converges.** From the state after
//!   step 1 or 2, running the same command again resolves the path (through the
//!   index, or through the name record on a fresh machine), deletes a content
//!   object that is already gone — `Backend::delete` is documented idempotent —
//!   and completes the remaining steps. The vault reaches the clean state and
//!   the report says `removed`, truthfully, the second time.
//! * **The window is one backend round trip wide** and closes with no data loss
//!   in either direction: the file's bytes are gone in every crash state after
//!   step 1, so no re-run can resurrect data that was already destroyed, and no
//!   crash state loses data that the run was not asked to destroy.
//!
//! The day `dctl-core` exposes the three steps separately — or reverses them
//! itself — this loop does not change, because it already reports from the
//! confirmation rather than from the attempt.

use crate::audit::record::Entry as AuditEntry;
use crate::ctx::Ctx;
use crate::error::Result;
use crate::exit::ExitCode;

use super::medium::Medium;
use super::report::Report;
use super::selection::Item;

/// Remove every item, in the order given, recording each outcome as it happens.
///
/// A failure on one object is recorded and the loop continues. That is the whole
/// point: abandoning nine hundred removals because the nine hundred and first
/// was unreachable helps nobody, and
/// [the plan](https://doc.dctl.sh/project/plan) §7 already has the vocabulary
/// for the result — the run finishes, the errors are counted, and the process
/// exits
/// [`ExitCode::PartialFailure`](crate::exit::ExitCode::PartialFailure) rather
/// than `0`.
///
/// Under `--dry-run` nothing is called on the store at all. Not "called and
/// ignored", not "called with a flag" — the branch is here, above the store, so
/// there is no code path from a dry run to a mutation.
///
/// ## The audit record, and why it comes from the same value the report does
///
/// One chained record per object, appended after the store has confirmed the
/// removal — for a vault, after the index row is committed away, which is what
/// makes a file count as gone ([the plan](https://doc.dctl.sh/project/plan) §6
/// step 8). Both the record and the
/// operator's report are derived from the *same* match arm on the same outcome,
/// so the log and the report cannot come to disagree about what happened to an
/// object: there is no second decision for one of them to make differently.
///
/// `Ok(false)` — something else deleted it between the listing and now — is
/// recorded as [`ExitCode::FileNotFound`](crate::exit::ExitCode::FileNotFound)
/// rather than as a success. This run did not remove it, and a log claiming
/// otherwise would attribute somebody else's deletion to this operator.
///
/// # Errors
/// A failure to *write the report* — a broken stdout other than a closed pipe —
/// or a failure to append the audit record, which fails the command because
/// [the plan](https://doc.dctl.sh/project/plan) §7 does not make the chain
/// optional. A failure to remove an object is data, not an error return,
/// because it must not stop the objects behind it.
pub async fn run(
    ctx: &Ctx,
    op: &'static str,
    remote: &str,
    medium: &Medium,
    items: &[Item],
    report: &mut Report<'_>,
) -> Result<()> {
    // Counted up front so the progress display and the summary have a
    // denominator: a percentage against an unknown total is a number nobody can
    // act on, and this total is genuinely known — the selection is complete
    // before the first removal.
    ctx.stats.add_total_files(items.len() as u64);

    for item in items {
        if ctx.is_dry_run() {
            report.would_remove(item)?;
            continue;
        }

        let outcome = medium.remove(&item.path).await;

        match &outcome {
            // Confirmed gone: for a vault, the index row has been committed
            // away, which is what makes a file count as removed.
            Ok(true) => report.removed(item)?,
            // Something else deleted it between the listing and now. Not a
            // removal this run performed, and not a failure either.
            Ok(false) => report.absent(item)?,
            Err(error) => report.failed(item, error.message())?,
        }

        // After the store confirmed, and never before. The size is the
        // plaintext length the listing measured, which is what makes "how much
        // was destroyed on the 3rd?" answerable; there is no plaintext hash,
        // because a removal reads no content.
        ctx.audit.record(
            &AuditEntry::new(
                op,
                match &outcome {
                    Ok(true) => ExitCode::Success,
                    Ok(false) => ExitCode::FileNotFound,
                    Err(error) => error.code(),
                },
            )
            .path(&item.path)
            // The audit chain's byte field is a `u64` by the preimage format's
            // definition (`audit::chain`), so an object the index never
            // measured is recorded as zero rather than changing what the chain
            // covers. `dctl ls` shows the same absence as `-`.
            .size(item.size.unwrap_or_default())
            // No direction: a removal destroys bytes where they lie, it does not
            // move them across a boundary. Dressing that up as an egress would
            // put a deletion in the answer to "who took data out".
            .objects(1)
            .remote(remote),
        )?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::globals::GlobalArgs;
    use crate::constants::REMOVAL_KIND_OBJECT;
    use crate::exit::ExitCode;
    use crate::session::Session;
    use clap::Parser;
    use dctl_core::Vault;
    use dctl_store::{Backend, LocalFs};
    use std::path::PathBuf;
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

    /// The verb and remote the tests drive the loop with, so every record a
    /// test writes still carries the fields a real one would.
    const TEST_OP: &str = "delete";
    const TEST_REMOTE: &str = "archive";

    fn item(path: &str, size: u64) -> Item {
        Item {
            path: path.to_string(),
            size: Some(size),
            kind: REMOVAL_KIND_OBJECT,
        }
    }

    /// A real vault over two temporary directories. Nothing is mocked: the
    /// objects are sealed, stored and indexed exactly as `dctl copy` stores them.
    struct Fixture {
        store: TempDir,
        _index: TempDir,
        index_path: PathBuf,
        medium: Medium,
    }

    async fn vault_with(files: &[(&str, &[u8])]) -> Fixture {
        let store = TempDir::new().expect("a temporary store");
        let index = TempDir::new().expect("a temporary index");
        let backend: Arc<dyn Backend> = Arc::new(LocalFs::new(store.path()));
        let index_path = index.path().join("index.redb");

        let vault = Vault::init(Arc::clone(&backend), &index_path, "pw")
            .await
            .expect("a fresh vault initialises")
            .vault;
        for (path, bytes) in files {
            vault
                .put_file(path, bytes, dctl_core::Modified::Now)
                .await
                .expect("a verified write");
        }

        let session = Session {
            vault,
            remote: "archive:".to_string(),
            index: index_path.clone(),
        };
        Fixture {
            store,
            _index: index,
            index_path,
            medium: Medium::Vault {
                session: Box::new(session),
                storage: crate::remote::RemoteSpec::Local(PathBuf::new()),
            },
        }
    }

    fn listed(fixture: &Fixture) -> Vec<String> {
        let Medium::Vault { session, .. } = &fixture.medium else {
            unreachable!("the fixture builds a vault")
        };
        session
            .vault
            .list("")
            .expect("the index reads")
            .into_iter()
            .map(|record| record.path)
            .collect()
    }

    /// Content objects present on the backend, by key.
    fn objects(fixture: &Fixture) -> Vec<String> {
        let directory = fixture.store.path().join("o");
        let Ok(entries) = std::fs::read_dir(&directory) else {
            return Vec::new();
        };
        entries
            .filter_map(|entry| Some(entry.ok()?.file_name().to_string_lossy().into_owned()))
            .collect()
    }

    #[tokio::test]
    async fn a_removal_takes_the_object_and_the_index_row_together() {
        // The end state the ordering exists to reach: nothing on the backend,
        // nothing in the index.
        let fixture = vault_with(&[("a.txt", b"hello")]).await;
        assert_eq!(objects(&fixture).len(), 1);

        let ctx = ctx(&["--quiet"]);
        let mut report = Report::new(&ctx);
        run(
            &ctx,
            TEST_OP,
            TEST_REMOTE,
            &fixture.medium,
            &[item("a.txt", 5)],
            &mut report,
        )
        .await
        .expect("the report writes");

        assert_eq!(report.totals().removed, 1);
        assert!(listed(&fixture).is_empty(), "the index row must be gone");
        assert!(objects(&fixture).is_empty(), "the object must be gone");
        assert!(fixture.index_path.exists(), "the index itself survives");
    }

    #[tokio::test]
    async fn a_dry_run_touches_neither_the_backend_nor_the_index() {
        // Asserted on the filesystem and on the index, not on a counter: a
        // counter that was never incremented proves nothing about what a store
        // was asked to do.
        let fixture = vault_with(&[("a.txt", b"hello"), ("b.txt", b"world")]).await;
        let before = objects(&fixture);

        let ctx = ctx(&["--dry-run", "--quiet"]);
        let mut report = Report::new(&ctx);
        run(
            &ctx,
            TEST_OP,
            TEST_REMOTE,
            &fixture.medium,
            &[item("a.txt", 5), item("b.txt", 5)],
            &mut report,
        )
        .await
        .expect("the report writes");

        assert_eq!(report.totals().would_remove, 2);
        assert_eq!(report.totals().removed, 0);
        assert_eq!(listed(&fixture), ["a.txt", "b.txt"]);
        assert_eq!(objects(&fixture), before);
        assert_eq!(ctx.stats.snapshot().files_deleted, 0);
    }

    #[tokio::test]
    async fn re_running_a_removal_converges_rather_than_failing() {
        // The idempotence the crash analysis in the module docs relies on: from
        // any partially-removed state, the same command finishes the job.
        let fixture = vault_with(&[("a.txt", b"hello")]).await;
        let ctx = ctx(&["--quiet"]);

        let mut first = Report::new(&ctx);
        run(
            &ctx,
            TEST_OP,
            TEST_REMOTE,
            &fixture.medium,
            &[item("a.txt", 5)],
            &mut first,
        )
        .await
        .unwrap();
        assert_eq!(first.totals().removed, 1);

        let mut second = Report::new(&ctx);
        run(
            &ctx,
            TEST_OP,
            TEST_REMOTE,
            &fixture.medium,
            &[item("a.txt", 5)],
            &mut second,
        )
        .await
        .unwrap();
        // Already gone: reported as absent, counted as neither a removal nor a
        // failure, and the run still exits clean.
        assert_eq!(second.totals().absent, 1);
        assert_eq!(second.totals().removed, 0);
        assert_eq!(second.totals().failed, 0);
        assert_eq!(ctx.outcome(), ExitCode::Success);
    }

    #[tokio::test]
    async fn a_partial_failure_is_never_reported_as_success() {
        // The objects are made unremovable by taking the write permission off
        // the directory holding their ciphertext. The run must report every one
        // of them by name, count them as errors, and exit 6 rather than 0.
        if !permissions_are_enforced() {
            // Windows has no such bit, and root ignores it, so the case cannot
            // be constructed. Skipping is honest; asserting nothing happened
            // would turn a missing condition into a passing test.
            return;
        }

        let fixture = vault_with(&[
            ("a.txt", b"1"),
            ("b.txt", b"2"),
            ("c.txt", b"3"),
            ("d.txt", b"4"),
            ("e.txt", b"5"),
        ])
        .await;

        let objects_dir = fixture.store.path().join("o");
        read_only(&objects_dir);

        let ctx = ctx(&["--quiet"]);
        let mut report = Report::new(&ctx);
        let items: Vec<Item> = ["a.txt", "b.txt", "c.txt", "d.txt", "e.txt"]
            .iter()
            .map(|path| item(path, 1))
            .collect();
        run(
            &ctx,
            TEST_OP,
            TEST_REMOTE,
            &fixture.medium,
            &items,
            &mut report,
        )
        .await
        .expect("the report writes even when every removal fails");

        writable(&objects_dir);

        let totals = report.totals();
        assert_eq!(totals.failed, 5, "every removal must be reported failed");
        assert_eq!(totals.removed, 0);
        assert_eq!(ctx.stats.snapshot().errors, 5);
        assert_eq!(
            ctx.outcome(),
            ExitCode::PartialFailure,
            "PLAN.md §7: a partial failure may not be rolled into a success"
        );
        // And the index still lists them, because nothing was confirmed removed.
        assert_eq!(listed(&fixture).len(), 5);
    }

    #[tokio::test]
    async fn the_loop_finishes_the_objects_behind_a_failure() {
        // A run that stopped at the first unreachable object would leave the
        // user re-running a destructive command to make progress.
        let fixture = vault_with(&[("a.txt", b"1")]).await;
        let ctx = ctx(&["--quiet"]);
        let mut report = Report::new(&ctx);

        // `missing.txt` is not there at all, so it reports absent; `a.txt`
        // behind it must still be removed.
        run(
            &ctx,
            TEST_OP,
            TEST_REMOTE,
            &fixture.medium,
            &[item("missing.txt", 0), item("a.txt", 1)],
            &mut report,
        )
        .await
        .unwrap();

        assert_eq!(report.totals().absent, 1);
        assert_eq!(report.totals().removed, 1);
        assert!(listed(&fixture).is_empty());
    }

    #[tokio::test]
    async fn the_total_the_progress_display_reads_is_the_real_selection_size() {
        let fixture = vault_with(&[("a.txt", b"1")]).await;
        let ctx = ctx(&["--dry-run", "--quiet"]);
        let mut report = Report::new(&ctx);
        run(
            &ctx,
            TEST_OP,
            TEST_REMOTE,
            &fixture.medium,
            &[item("a.txt", 1)],
            &mut report,
        )
        .await
        .unwrap();
        assert_eq!(ctx.stats.snapshot().files_total, 1);
    }

    /// Drop the write bit on a directory so its entries cannot be unlinked.
    #[cfg(unix)]
    fn read_only(directory: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt as _;
        let mut permissions = std::fs::metadata(directory)
            .expect("the object directory exists")
            .permissions();
        permissions.set_mode(0o500);
        std::fs::set_permissions(directory, permissions).expect("permissions can be tightened");
    }

    #[cfg(unix)]
    fn writable(directory: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt as _;
        let mut permissions = std::fs::metadata(directory)
            .expect("the object directory exists")
            .permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(directory, permissions).expect("permissions can be restored");
    }

    #[cfg(not(unix))]
    fn read_only(_directory: &std::path::Path) {}
    #[cfg(not(unix))]
    fn writable(_directory: &std::path::Path) {}

    /// Whether a read-only directory really refuses a write on this machine.
    ///
    /// Probed rather than assumed: `#![forbid(unsafe_code)]` rules out asking
    /// `geteuid`, and the question that actually matters is not "am I root" but
    /// "does the bit hold here" — which is also false on some mounts and in some
    /// containers. A probe answers the real question.
    fn permissions_are_enforced() -> bool {
        let probe = match TempDir::new() {
            Ok(probe) => probe,
            Err(_) => return false,
        };
        let victim = probe.path().join("victim");
        if std::fs::write(&victim, b"x").is_err() {
            return false;
        }
        read_only(probe.path());
        let refused = std::fs::remove_file(&victim).is_err();
        writable(probe.path());
        refused
    }
}
