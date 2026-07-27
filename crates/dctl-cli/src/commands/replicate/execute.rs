//! Moving the bytes, and proving they arrived.
//!
//! One object at a time: read it from the source store, hash its **ciphertext**,
//! hand both to the destination's verified write, and — at the stronger
//! `--verify` settings — read it back and compare. No key is derived, no
//! envelope is unwrapped, no plaintext exists at any point in this file. The
//! `encrypt` stage of `PLAN.md` §6 is absent from the progress display for the
//! same reason it is absent from the code: there is nothing here to encrypt,
//! because everything passing through is already sealed.
//!
//! ## Verification, and exactly what each level claims
//!
//! * `--verify checksum` (the default) — the object's BLAKE3 is computed from
//!   the bytes the source served and handed to [`dctl_store::Backend::put`],
//!   whose contract is to commit nothing if the stored bytes differ. The claim
//!   is *the
//!   destination stored what we sent*.
//! * `--verify sample` — as above, plus a window of the object is read back from
//!   the destination and compared with the source's bytes. The claim adds *and
//!   serves it back*, which is a different and weaker-sounding statement that has
//!   caught more real provider faults than the first.
//! * `--verify strict` — as above, with the whole object read back and its
//!   BLAKE3 compared. The claim is *the replica is this object*, and it is the
//!   only level that earns it. It is also the only level at which an object
//!   already present at the destination is re-read rather than assumed intact
//!   (see [`super::plan`]).
//!
//! ## One failure is not the whole run
//!
//! An object that cannot be read, cannot be written, or arrives wrong is
//! recorded against that object and the walk continues. Two things follow, and
//! both are deliberate. The report names every failure, so a run that moved
//! 9 998 of 10 000 objects says so rather than saying "done"; and the process
//! exits non-zero — 20 when a destination stored the wrong bytes, 6 otherwise —
//! because `PLAN.md` §7 forbids rolling a partial failure up into success. A
//! replication that stopped at the first failure would be worse: the objects it
//! had not reached yet are the ones with no second copy.

use dctl_store::{ByteRange, ContentHash, ObjectKey};

use crate::audit::record::Entry as AuditEntry;
use crate::cli::VerifyMode;
use crate::commands::replicate::VERB;
use crate::constants::{
    PLAN_REASON_CHECKSUM, PLAN_REASON_IDENTICAL, REPLICATE_REASON_MISMATCH,
    REPLICATE_REASON_TOO_LARGE, REPLICATE_REASON_UNREADABLE, REPLICATE_REASON_UNWRITABLE,
    REPLICATE_SAMPLE_WINDOW_BYTES, REPLICATE_VERIFY_CHECKSUM, REPLICATE_VERIFY_SAMPLE,
    REPLICATE_VERIFY_STRICT, REPLICATE_WHOLE_OBJECT_LIMIT,
};
use crate::ctx::Ctx;
use crate::error::{CliError, Result};
use crate::exit::ExitCode;
use crate::logging::fields;
use crate::output::{Stage, size};

use super::plan::{Action, Item, Plan, Summary};
use super::target::Store;

/// One line of commentary saying what a `--verify` strength actually checked.
///
/// Written for ciphertext rather than borrowed from
/// [`crate::commands::integrity::mode::describe`], whose sentences say
/// "decrypted". Borrowing the wrong sentence would have the run claim a stronger
/// guarantee than it made, in the one command whose whole selling point is that
/// it holds no key.
#[must_use]
pub const fn describe(verify: VerifyMode) -> &'static str {
    match verify {
        VerifyMode::Checksum => REPLICATE_VERIFY_CHECKSUM,
        VerifyMode::Sample => REPLICATE_VERIFY_SAMPLE,
        VerifyMode::Strict => REPLICATE_VERIFY_STRICT,
    }
}

/// What a replication actually did.
///
/// Deliberately not the plan it was built from: the two differ whenever reality
/// did, and reporting the plan after executing it is the shortest route to
/// claiming work that did not happen.
pub struct Outcome {
    /// One record per source object, with the action that really occurred.
    pub items: Vec<Item>,
    /// The counts, recomputed from those records.
    pub summary: Summary,
}

/// Carry out a plan.
///
/// # Errors
/// Only for a failure that makes the *run* impossible. A failure that belongs to
/// one object is recorded on that object and counted, so the walk reaches every
/// other object and the exit code still reports the shortfall.
pub async fn run(ctx: &Ctx, plan: &Plan, source: &Store, destination: &Store) -> Result<Outcome> {
    let verify = ctx.verify_mode();
    let planned = plan.summary();

    // Sized against what will be *read*, not against what will be written: a
    // strict run reads every object it reverifies and usually writes none of
    // them, and a bar sized against the writes would finish before the work did.
    let egress = plan.egress_bytes();
    ctx.stats.set_total_files(planned.objects);
    ctx.stats.set_total_bytes(egress);
    ctx.progress.set_totals(egress, planned.objects);

    let mut items = Vec::with_capacity(plan.items().len());
    let mut summary = Summary {
        objects: planned.objects,
        extra: planned.extra,
        ..Summary::default()
    };

    for item in plan.items() {
        let done = match item.action {
            Action::Skip => {
                ctx.stats.file_skipped();
                item.clone()
            }
            _ => {
                let done = one(ctx, item, source, destination, verify).await;
                // Step 8, after the destination's verified write has returned.
                // A skip is not recorded: nothing was written, and a log in
                // which "already there" and "copied there today" looked alike
                // could not answer when a replica actually gained an object.
                record(ctx, &done, destination)?;
                done.item
            }
        };
        tally(&mut summary, &done);
        items.push(done);
    }

    Ok(Outcome { items, summary })
}

/// Append one object's chained record.
///
/// The only family in DCTL whose records carry a **ciphertext** hash and no
/// plaintext one, and the asymmetry is the command's whole point: `replicate`
/// holds no key, derives nothing and unwraps nothing, so the sealed object's
/// BLAKE3 is the only digest that exists here. A plaintext hash in one of these
/// records would be a claim the command is built never to be able to make.
///
/// The digest is the one [`one`] handed to [`dctl_store::Backend::put`] — the
/// value the destination's verified write refused to commit anything else
/// against — so what the log attests to is exactly what the store accepted,
/// rather than a second hash of bytes read at a second moment.
///
/// # Errors
/// Whatever [`crate::audit::sink::Sink::record`] refused. Fatal to the run: the
/// log is unwritable for every object behind this one too, and replicating
/// 10 000 objects unrecorded is precisely what `PLAN.md` §7 forbids.
fn record(ctx: &Ctx, done: &Replicated, destination: &Store) -> Result<()> {
    let item = &done.item;
    let outcome = if item.action == Action::Failed {
        // The classification `failed` already chose, kept rather than
        // re-derived: `checksum_mismatch` and "could not be read" are different
        // findings and the log has to keep them apart.
        if item.reason == REPLICATE_REASON_MISMATCH {
            ExitCode::ChecksumMismatch
        } else {
            ExitCode::TemporaryError
        }
    } else {
        ExitCode::Success
    };

    ctx.audit.record(
        &AuditEntry::new(VERB, outcome)
            .path(&item.key)
            .size(item.size)
            .ciphertext_hash(&done.hash)
            // The resolved *name*, not the spec: `destination.spec` is the text
            // the operator typed, colon and all, and `remote == replica` is the
            // filter a compliance query runs years later. One remote must have
            // one spelling in the log or that query silently returns nothing.
            .remote(destination.name()),
    )
}

/// Add one finished object to the counts.
fn tally(summary: &mut Summary, item: &Item) {
    match item.action {
        Action::Replicate => {
            summary.replicated += 1;
            summary.bytes += item.size;
        }
        // A reverify that survived execution is one whose two copies were read
        // back and agreed; one that did not agree was re-replicated and is
        // counted above. It is kept apart from a skip on purpose: both left the
        // destination as it was, and only one of them *proved* anything. Folding
        // the two together would let a quarterly `--verify strict` report be
        // produced by a run that checked nothing.
        Action::Reverify => summary.reverified += 1,
        Action::Skip => summary.skipped += 1,
        Action::Failed => summary.failed += 1,
    }
}

/// Replicate, or re-verify, one object.
///
/// Never returns `Err`: an object's failure is *its* outcome, recorded in the
/// item it returns and in the run's counters, because the objects this run has
/// not reached yet are the ones with no second copy.
async fn one(
    ctx: &Ctx,
    item: &Item,
    source: &Store,
    destination: &Store,
    verify: VerifyMode,
) -> Replicated {
    if item.size > REPLICATE_WHOLE_OBJECT_LIMIT {
        return unread(failed(
            ctx,
            item,
            REPLICATE_REASON_TOO_LARGE,
            &format!(
                "'{}' is {} and this build moves an object in one piece, up to {}",
                item.key,
                size::bytes(item.size, ctx.out.units()),
                size::bytes(REPLICATE_WHOLE_OBJECT_LIMIT, ctx.out.units())
            ),
        ));
    }

    let key = ObjectKey::new(item.key.clone());
    let handle = ctx.progress.start_file(&item.key, item.size);
    ctx.progress.set_stage(&handle, Stage::Reading);

    let bytes = match source.backend().get(&key).await {
        Ok(bytes) => bytes,
        Err(error) => {
            ctx.progress.finish_file(handle);
            return unread(failed(
                ctx,
                item,
                REPLICATE_REASON_UNREADABLE,
                &format!(
                    "'{}' could not be read from '{}': {error}",
                    item.key, source.spec
                ),
            ));
        }
    };
    let expected = ContentHash::blake3(&bytes);

    // A reverify reads the destination's copy first: if the two agree, the
    // replica already holds this object and re-uploading it would spend egress
    // to reach the state it is already in.
    if item.action == Action::Reverify {
        ctx.progress.set_stage(&handle, Stage::Verifying);
        match destination.backend().get(&key).await {
            Ok(stored) if ContentHash::blake3(&stored).matches(&expected) => {
                // Credited even though nothing was written: the counter is
                // "bytes moved over the wire", and reading an object back from
                // a provider moves exactly as many of them as writing it would.
                // Leaving it uncredited would have a quarterly proof of a 40 TB
                // replica report 0% for eight hours.
                ctx.progress.advance(&handle, item.size);
                ctx.progress.finish_file(handle);
                ctx.stats.file_skipped();
                ctx.stats.add_verified_bytes(item.size);
                return Replicated {
                    item: Item {
                        action: Action::Reverify,
                        reason: PLAN_REASON_IDENTICAL,
                        ..item.clone()
                    },
                    hash: expected.hex(),
                };
            }
            // Either the copy differs or it could not be read. Both are answered
            // the same way — replicate it again — because the replica is the
            // copy that is allowed to be wrong, and rewriting it is cheap
            // relative to discovering the fault on restore day.
            Ok(_) | Err(_) => {}
        }
    }

    ctx.progress.set_stage(&handle, Stage::Uploading);
    if let Err(error) = destination
        .backend()
        .put(&key, bytes.clone(), &expected)
        .await
    {
        let classified = CliError::from(error);
        ctx.progress.finish_file(handle);
        let reason = if classified.code() == ExitCode::ChecksumMismatch {
            REPLICATE_REASON_MISMATCH
        } else {
            REPLICATE_REASON_UNWRITABLE
        };
        return Replicated {
            item: failed(
                ctx,
                item,
                reason,
                &format!(
                    "'{}' could not be stored at '{}': {}",
                    item.key,
                    destination.spec,
                    classified.message()
                ),
            ),
            // Read from the source and hashed, so the record can still name the
            // object that failed to land — which is the object somebody has to
            // go and check.
            hash: expected.hex(),
        };
    }
    // `Progress::advance` is what credits `Stats::add_bytes`, so the transferred
    // count is raised here and nowhere else. Adding it twice made a clean run
    // report 200% of itself moved.
    ctx.progress.advance(&handle, item.size);

    ctx.progress.set_stage(&handle, Stage::Verifying);
    if let Err(problem) = read_back(destination, &key, &bytes, &expected, verify).await {
        ctx.progress.finish_file(handle);
        return Replicated {
            item: failed(ctx, item, REPLICATE_REASON_MISMATCH, &problem),
            hash: expected.hex(),
        };
    }

    ctx.progress.set_stage(&handle, Stage::Done);
    ctx.progress.finish_file(handle);
    ctx.stats.add_verified_bytes(item.size);
    ctx.stats.file_done();

    tracing::debug!(
        { fields::REMOTE } = %destination.spec,
        object = %item.key,
        bytes = item.size,
        "object replicated"
    );

    Replicated {
        item: Item {
            action: Action::Replicate,
            reason: if item.action == Action::Reverify {
                // It was supposed to be identical and was not, which is the
                // finding a strict run exists to produce.
                PLAN_REASON_CHECKSUM
            } else {
                item.reason
            },
            ..item.clone()
        },
        hash: expected.hex(),
    }
}

/// One object's outcome, paired with the ciphertext digest that identifies it.
///
/// The pair exists because the report and the audit log want different halves of
/// the same fact: the report renders the [`Item`], and the record needs the
/// digest, which only lives for as long as the bytes were in hand.
struct Replicated {
    item: Item,
    /// BLAKE3 of the sealed bytes, lower-case hex, or empty when the object was
    /// never read and therefore never hashed.
    hash: String,
}

/// An outcome for an object whose bytes were never obtained.
///
/// A separate constructor rather than a default, so that "there is no digest
/// because nothing was read" is written down at each of the two places it is
/// true — and cannot be reached by forgetting to supply one.
const fn unread(item: Item) -> Replicated {
    Replicated {
        item,
        hash: String::new(),
    }
}

/// The extra read-back the stronger `--verify` levels ask for.
///
/// Returns the problem as prose rather than a [`CliError`] because there is
/// nothing to classify: every failure here means the same thing — the
/// destination does not serve back what it accepted — and only the detail
/// differs.
async fn read_back(
    destination: &Store,
    key: &ObjectKey,
    source_bytes: &[u8],
    expected: &ContentHash,
    verify: VerifyMode,
) -> std::result::Result<(), String> {
    match verify {
        // The verified write is the whole check: `Backend::put` commits nothing
        // whose stored bytes do not match `expected`.
        VerifyMode::Checksum => Ok(()),

        VerifyMode::Sample => {
            let window = REPLICATE_SAMPLE_WINDOW_BYTES.min(source_bytes.len() as u64);
            let served = destination
                .backend()
                .get_range(key, ByteRange::new(0, Some(window)))
                .await
                .map_err(|error| format!("'{key}' could not be read back: {error}"))?;

            let wanted = source_bytes.get(..served.len()).unwrap_or_default();
            if served.as_ref() == wanted {
                Ok(())
            } else {
                Err(format!(
                    "'{key}' was stored at '{}', but the first {} it serves back \
                     differ from the source",
                    destination.spec,
                    served.len()
                ))
            }
        }

        VerifyMode::Strict => {
            let served = destination
                .backend()
                .get(key)
                .await
                .map_err(|error| format!("'{key}' could not be read back: {error}"))?;

            if ContentHash::blake3(&served).matches(expected) {
                Ok(())
            } else {
                Err(format!(
                    "'{key}' was stored at '{}', but what it serves back has a \
                     different BLAKE3 from the source object",
                    destination.spec
                ))
            }
        }
    }
}

/// Record one object's failure everywhere it has to appear.
///
/// Three places, and all three matter: the operator's terminal, the counters
/// that decide the exit code, and the report a script parses. A failure recorded
/// in fewer than three is a failure some consumer will not see.
fn failed(ctx: &Ctx, item: &Item, reason: &'static str, message: &str) -> Item {
    ctx.out.error(message);
    tracing::warn!(
        object = %item.key,
        reason,
        "object not replicated"
    );

    // A destination that stored something other than what it was sent gets the
    // loud code, because it is the only failure here that means the *data* is
    // suspect rather than the run.
    if reason == REPLICATE_REASON_MISMATCH {
        ctx.stats.checksum_mismatch();
    } else {
        ctx.stats.error();
    }

    Item {
        action: Action::Failed,
        reason,
        ..item.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::GlobalArgs;
    use crate::commands::replicate::target::{Side, open};
    use crate::config::{Config, LocalDef, RemoteDef};
    use clap::Parser;
    use std::path::{Path, PathBuf};

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn ctx(extra: &[&str]) -> Ctx {
        Ctx::new(Harness::parse_from(std::iter::once("dctl").chain(extra.iter().copied())).globals)
    }

    /// A store declared in the configuration, so no envelope is needed.
    fn declared(config: &mut Config, name: &str, path: &Path) {
        std::fs::create_dir_all(path).unwrap();
        config.insert(
            name,
            RemoteDef::Local(LocalDef {
                path: path.to_path_buf(),
                verify: None,
                require_vault: true,
            }),
        );
    }

    /// Two declared stores on disk, the source seeded with `objects`.
    async fn stores(
        dir: &Path,
        objects: &[(&str, &[u8])],
    ) -> (Config, PathBuf, PathBuf, Store, Store) {
        let source_dir = dir.join("primary");
        let dest_dir = dir.join("offsite");
        let mut config = Config::default();
        declared(&mut config, "primary-store", &source_dir);
        declared(&mut config, "offsite-store", &dest_dir);

        for (key, body) in objects {
            let path = source_dir.join(key);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(path, body).unwrap();
        }

        let source = open(&config, "primary-store:", Side::Source).await.unwrap();
        let destination = open(&config, "offsite-store:", Side::Destination)
            .await
            .unwrap();
        (config, source_dir, dest_dir, source, destination)
    }

    #[tokio::test]
    async fn every_object_arrives_under_the_same_key_with_the_same_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let (_config, _source_dir, dest_dir, source, destination) = stores(
            dir.path(),
            &[("data/aa", b"first object"), ("data/nested/bb", b"second")],
        )
        .await;

        let context = ctx(&[]);
        let plan = Plan::build(
            source.backend(),
            destination.backend(),
            VerifyMode::Checksum,
        )
        .await
        .unwrap();
        let outcome = run(&context, &plan, &source, &destination).await.unwrap();

        assert_eq!(outcome.summary.replicated, 2);
        assert_eq!(outcome.summary.failed, 0);
        assert_eq!(
            std::fs::read(dest_dir.join("data").join("aa")).unwrap(),
            b"first object"
        );
        assert_eq!(
            std::fs::read(dest_dir.join("data").join("nested").join("bb")).unwrap(),
            b"second"
        );
        assert_eq!(context.outcome(), ExitCode::Success);
    }

    #[tokio::test]
    async fn a_second_run_moves_nothing_and_says_so() {
        // The property that makes a nightly offsite job affordable.
        let dir = tempfile::tempdir().unwrap();
        let (_config, _source_dir, _dest_dir, source, destination) =
            stores(dir.path(), &[("data/aa", b"body")]).await;
        let context = ctx(&[]);

        let first = Plan::build(
            source.backend(),
            destination.backend(),
            VerifyMode::Checksum,
        )
        .await
        .unwrap();
        run(&context, &first, &source, &destination).await.unwrap();

        let second = Plan::build(
            source.backend(),
            destination.backend(),
            VerifyMode::Checksum,
        )
        .await
        .unwrap();
        let outcome = run(&context, &second, &source, &destination).await.unwrap();
        assert_eq!(outcome.summary.replicated, 0);
        assert_eq!(outcome.summary.skipped, 1);
    }

    #[tokio::test]
    async fn strict_notices_a_replica_that_was_corrupted_in_place() {
        // Same key, same size, different bytes — the corruption a size check
        // cannot see, and the reason `--verify strict` exists.
        let dir = tempfile::tempdir().unwrap();
        let (_config, _source_dir, dest_dir, source, destination) =
            stores(dir.path(), &[("data/aa", b"good bytes")]).await;
        let context = ctx(&["--verify", "strict"]);

        let first = Plan::build(source.backend(), destination.backend(), VerifyMode::Strict)
            .await
            .unwrap();
        run(&context, &first, &source, &destination).await.unwrap();

        std::fs::write(dest_dir.join("data").join("aa"), b"evil bytes").unwrap();

        let second = Plan::build(source.backend(), destination.backend(), VerifyMode::Strict)
            .await
            .unwrap();
        assert_eq!(second.items()[0].action, Action::Reverify);

        let outcome = run(&context, &second, &source, &destination).await.unwrap();
        assert_eq!(outcome.summary.replicated, 1, "it must be replaced");
        assert_eq!(outcome.items[0].reason, PLAN_REASON_CHECKSUM);
        assert_eq!(
            std::fs::read(dest_dir.join("data").join("aa")).unwrap(),
            b"good bytes"
        );
    }

    #[tokio::test]
    async fn a_clean_replica_survives_a_strict_run_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let (_config, _source_dir, _dest_dir, source, destination) =
            stores(dir.path(), &[("data/aa", b"body")]).await;
        let context = ctx(&["--verify", "strict"]);

        let first = Plan::build(source.backend(), destination.backend(), VerifyMode::Strict)
            .await
            .unwrap();
        run(&context, &first, &source, &destination).await.unwrap();

        let second = Plan::build(source.backend(), destination.backend(), VerifyMode::Strict)
            .await
            .unwrap();
        let outcome = run(&context, &second, &source, &destination).await.unwrap();
        assert_eq!(outcome.summary.replicated, 0);
        // Proved, not assumed — and counted as such, so a report cannot pass a
        // size comparison off as a read-back.
        assert_eq!(outcome.summary.reverified, 1);
        assert_eq!(outcome.summary.skipped, 0);
        assert_eq!(outcome.items[0].reason, PLAN_REASON_IDENTICAL);
        assert_eq!(context.outcome(), ExitCode::Success);
    }

    #[tokio::test]
    async fn sampling_reads_a_window_back_and_accepts_a_good_one() {
        let dir = tempfile::tempdir().unwrap();
        let (_config, _source_dir, _dest_dir, source, destination) =
            stores(dir.path(), &[("data/aa", b"sampled body")]).await;
        let context = ctx(&["--verify", "sample"]);

        let plan = Plan::build(source.backend(), destination.backend(), VerifyMode::Sample)
            .await
            .unwrap();
        let outcome = run(&context, &plan, &source, &destination).await.unwrap();
        assert_eq!(outcome.summary.replicated, 1);
        assert_eq!(outcome.summary.failed, 0);
    }

    #[tokio::test]
    async fn one_failed_object_neither_stops_the_run_nor_is_reported_as_done() {
        // The object that cannot be read is removed after the plan is built, so
        // the walk meets a source that lists it and cannot serve it.
        let dir = tempfile::tempdir().unwrap();
        let (_config, source_dir, dest_dir, source, destination) = stores(
            dir.path(),
            &[("data/aa", b"fine"), ("data/gone", b"vanishing")],
        )
        .await;
        let context = ctx(&[]);

        let plan = Plan::build(
            source.backend(),
            destination.backend(),
            VerifyMode::Checksum,
        )
        .await
        .unwrap();
        std::fs::remove_file(source_dir.join("data").join("gone")).unwrap();

        let outcome = run(&context, &plan, &source, &destination).await.unwrap();
        assert_eq!(outcome.summary.replicated, 1, "the reachable object moved");
        assert_eq!(outcome.summary.failed, 1);
        assert!(
            dest_dir.join("data").join("aa").is_file(),
            "the walk must not stop at the first failure"
        );

        let failure = outcome
            .items
            .iter()
            .find(|item| item.action == Action::Failed)
            .expect("the failure must be in the report");
        assert_eq!(failure.reason, REPLICATE_REASON_UNREADABLE);
        // And the run must not exit 0 while claiming a complete replica.
        assert_eq!(context.outcome(), ExitCode::PartialFailure);
    }

    #[tokio::test]
    async fn an_object_too_large_for_one_buffer_is_refused_rather_than_attempted() {
        // Reported against the object and counted, not swallowed: an OOM kill
        // halfway through teaches an operator nothing.
        let dir = tempfile::tempdir().unwrap();
        let (_config, _source_dir, _dest_dir, source, destination) =
            stores(dir.path(), &[("data/aa", b"small")]).await;
        let context = ctx(&[]);

        let oversized = Item {
            action: Action::Replicate,
            key: "data/aa".into(),
            size: REPLICATE_WHOLE_OBJECT_LIMIT + 1,
            reason: PLAN_REASON_IDENTICAL,
        };
        let done = one(
            &context,
            &oversized,
            &source,
            &destination,
            VerifyMode::Checksum,
        )
        .await;
        assert_eq!(done.item.action, Action::Failed);
        assert_eq!(done.item.reason, REPLICATE_REASON_TOO_LARGE);
        assert_eq!(context.outcome(), ExitCode::PartialFailure);
    }

    #[test]
    fn each_verify_level_describes_ciphertext_and_never_decryption() {
        // Borrowing the integrity family's sentences would claim a decryption
        // this command cannot perform.
        for mode in [VerifyMode::Checksum, VerifyMode::Sample, VerifyMode::Strict] {
            let sentence = describe(mode);
            assert!(!sentence.is_empty());
            assert!(
                !sentence.contains("decrypt"),
                "'{sentence}' claims a decryption that never happened"
            );
        }
        assert_ne!(describe(VerifyMode::Checksum), describe(VerifyMode::Strict));
    }
}
