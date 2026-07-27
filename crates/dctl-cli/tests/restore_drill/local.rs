//! The drill against a local store: the run that happens on every `cargo test`.
//!
//! Local is not a lesser rehearsal. Everything the procedure claims — that the
//! index is a cache, that the phrase is a second key, that the bytes come back —
//! is decided in DCTL's own code, and a local backend exercises all of it in a
//! couple of seconds with no credentials and no bill. What it cannot exercise is
//! the provider: a listing that paginates, a ranged GET, a request that has to be
//! retried. That is what [`super::b2`] is for, and why "we ran the drill" is only
//! a true statement when both have run.
//!
//! Two assertions live here rather than in [`super::drill`], because only a
//! local run can make them: the store is a directory this process can read, so
//! it can be searched for plaintext, and the index can be listed to show exactly
//! what a rebuild did and did not recover.

use crate::drill;
use crate::harness::{Backend, VAULT_REMOTE};

/// A string that appears verbatim in the dataset and nowhere else.
///
/// Searched for across every byte of the store. Long enough that it cannot occur
/// by coincidence inside a key, a nonce or a length field and turn a passing
/// suite into a failing one for no reason.
const PLAINTEXT_MARKER: &[u8] = b"DCTL restore drill dataset.";

#[test]
fn the_whole_dataset_survives_a_destroyed_index_and_comes_back_on_the_phrase_alone() {
    let report = drill::run(Backend::Local);

    eprintln!("{}", report.summary());

    no_plaintext_reached_the_store(&report);
    the_rebuild_recovered_paths_but_neither_sizes_nor_times(&report);
}

/// The bytes that came back are the bytes that went in — and they were never
/// legible in between.
///
/// A restore drill is the one exercise that holds both trees at once, which
/// makes it the cheapest place to also prove the sealed half: every object under
/// the store is searched for a string that appears verbatim in the source. A
/// drill that proved data comes back while the store held it in the clear would
/// have verified a file copier.
fn no_plaintext_reached_the_store(report: &drill::Report) {
    let store = report.sandbox.path("store");
    let mut objects = 0_u64;
    let mut stack = vec![store.clone()];

    while let Some(directory) = stack.pop() {
        for child in std::fs::read_dir(&directory).expect("the local store is readable") {
            let path = child.expect("a store entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            objects += 1;
            let bytes = std::fs::read(&path).expect("a store object is readable");
            assert!(
                !contains(&bytes, PLAINTEXT_MARKER),
                "plaintext from the dataset is readable in {}",
                path.display()
            );
        }
    }

    assert_eq!(
        objects, report.objects_before,
        "the plaintext search did not cover every object in the store"
    );
}

/// What a rebuild recovers, stated as a test rather than only in prose.
///
/// `dctl index rebuild` is a **list-only pass**: it reads the encrypted name
/// records and writes the path→object mapping, and it deliberately does not
/// fetch object bodies, because doing so would turn a cheap reconciliation into
/// a full read of the dataset. The consequence is visible immediately — the rows
/// it writes carry no size and no modification time, and `lsl` renders both as
/// `-`.
///
/// This is pinned because it is the part of a recovery that surprises people,
/// and because it has a consequence the drill's manifest cannot see: a restore
/// from a rebuilt index stamps every file with the time of the restore, since
/// that is the only fact available. The bytes and the names are exact; the
/// timestamps are not the ones that were backed up. An auditor is entitled to be
/// told that in advance rather than to discover it from a tree where every file
/// looks freshly written.
///
/// If this ever fails because a rebuild started recovering sizes and times, the
/// fix is to update `docs/RESTORE_DRILL.md` and delete this function — not to
/// weaken it.
fn the_rebuild_recovered_paths_but_neither_sizes_nor_times(report: &drill::Report) {
    let listing = report
        .sandbox
        .run_with_phrase(
            &report.backend,
            &report.phrase,
            &["lsl", &format!("{VAULT_REMOTE}:")],
        )
        .expect_success("listing the rebuilt index");

    let rows: Vec<&str> = listing.stdout.lines().collect();
    assert_eq!(
        rows.len(),
        report.manifest.len(),
        "the rebuilt index lists {} rows for {} files\n{}",
        rows.len(),
        report.manifest.len(),
        listing.transcript()
    );

    for row in &rows {
        let mut columns = row.split_whitespace();
        assert_eq!(
            (columns.next(), columns.next()),
            (Some("-"), Some("-")),
            "a rebuilt row reports a size or a time it cannot know: {row}"
        );
    }
}

/// Whether `haystack` contains `needle`.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
