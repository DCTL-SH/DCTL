//! Integration tests for the SQLCipher-backed encrypted index: CRUD, ascending
//! enumeration, persistence across reopen, wrong-key resistance, and at-rest
//! metadata privacy (whole-DB SQLCipher encryption + per-row AEAD).

use dctl_index::{Index, Record};
use tempfile::TempDir;

fn sample(path: &str, size: u64) -> Record {
    Record {
        path: path.to_string(),
        object_key: format!("obj/{}", size),
        size,
        modified_unix: Some(1_700_000_000),
        content_hash: vec![1, 2, 3, 4],
    }
}

/// A row of the shape a rebuild leaves: mapped, but never opened, so no size and
/// no hash. Distinguishable from a genuinely empty file, which always has a hash.
fn unmeasured(path: &str) -> Record {
    Record {
        path: path.to_string(),
        object_key: format!("obj/{path}"),
        size: 0,
        modified_unix: None,
        content_hash: Vec::new(),
    }
}

/// The files a directory holds directly, in name order.
fn children_of(index: &Index, dir: &str) -> Vec<String> {
    let mut out = Vec::new();
    index
        .children(dir, |record| {
            out.push(record.path);
            true
        })
        .unwrap();
    out.sort();
    out
}

/// The directories a directory holds directly, in name order.
fn dirs_of(index: &Index, dir: &str) -> Vec<String> {
    let mut out = Vec::new();
    index
        .child_dirs(dir, |path| {
            out.push(path);
            true
        })
        .unwrap();
    out.sort();
    out
}

fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Reproduce the on-disk primary key for a path under a given index sub-key, so a
/// test can assert the exact ascending-key enumeration order the store guarantees.
/// Mirrors `Index`'s internal keying: `BLAKE3_keyed(HKDF(subkey,"index-keying-v1"), path)`.
fn storage_key(index_subkey: &[u8; 32], path: &str) -> [u8; 32] {
    let keying_key = dctl_crypto::keys::derive_subkey(index_subkey, b"index-keying-v1").unwrap();
    *blake3::keyed_hash(&keying_key, path.as_bytes()).as_bytes()
}

#[test]
fn put_get_delete_count() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("index.db");
    let idx = Index::open(&path, &[7u8; 32]).unwrap();

    assert_eq!(idx.count().unwrap(), 0);

    let record = sample("photos/2020/a.jpg", 111);
    idx.put(&record).unwrap();

    assert_eq!(idx.count().unwrap(), 1);
    assert!(idx.contains("photos/2020/a.jpg").unwrap());
    assert_eq!(idx.get("photos/2020/a.jpg").unwrap(), Some(record));
    assert_eq!(idx.get("nope").unwrap(), None);

    assert!(idx.delete("photos/2020/a.jpg").unwrap());
    assert!(!idx.delete("photos/2020/a.jpg").unwrap());
    assert_eq!(idx.count().unwrap(), 0);
}

#[test]
fn put_replaces_existing() {
    let dir = TempDir::new().unwrap();
    let idx = Index::open(&dir.path().join("i.db"), &[3u8; 32]).unwrap();
    idx.put(&sample("k", 1)).unwrap();
    idx.put(&sample("k", 2)).unwrap();
    assert_eq!(idx.count().unwrap(), 1);
    assert_eq!(idx.get("k").unwrap().unwrap().size, 2);
}

#[test]
fn enumeration_and_early_stop() {
    let dir = TempDir::new().unwrap();
    let idx = Index::open(&dir.path().join("i.db"), &[5u8; 32]).unwrap();
    for i in 0..5 {
        idx.put(&sample(&format!("f/{i}"), i)).unwrap();
    }
    assert_eq!(idx.all().unwrap().len(), 5);

    let mut seen = 0;
    idx.for_each(|_| {
        seen += 1;
        seen < 2 // stop after 2
    })
    .unwrap();
    assert_eq!(seen, 2);
}

/// `for_each` / `all` stream rows in ascending storage-key order (the `SELECT ...
/// ORDER BY key ASC`), regardless of insertion order — the enumeration is a
/// deterministic sort by the on-disk key, not by insertion sequence.
#[test]
fn enumeration_is_ascending_by_storage_key() {
    let subkey = [9u8; 32];
    let dir = TempDir::new().unwrap();
    let idx = Index::open(&dir.path().join("i.db"), &subkey).unwrap();

    // Insert in a deliberately non-sorted order.
    let paths = [
        "zeta/last.bin",
        "alpha/first.txt",
        "middle/thing",
        "photos/2020/a.jpg",
        "b",
    ];
    for (i, p) in paths.iter().enumerate() {
        idx.put(&sample(p, i as u64)).unwrap();
    }

    let got: Vec<String> = idx.all().unwrap().into_iter().map(|r| r.path).collect();
    assert_eq!(got.len(), paths.len());

    // The observed order must be exactly ascending by each path's storage key.
    let mut expected: Vec<String> = paths.iter().map(|p| p.to_string()).collect();
    expected.sort_by_key(|p| storage_key(&subkey, p));
    assert_eq!(
        got, expected,
        "enumeration must be ascending by storage key"
    );

    // And the returned key sequence is monotonically non-decreasing.
    let keys: Vec<[u8; 32]> = got.iter().map(|p| storage_key(&subkey, p)).collect();
    assert!(keys.windows(2).all(|w| w[0] <= w[1]));
}

/// A reopened database returns exactly the same records (durable persistence);
/// this is the same connection settings (WAL) re-attaching to the encrypted file.
#[test]
fn reopened_db_returns_same_records() {
    let subkey = [4u8; 32];
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("persist.db");

    let originals = [
        sample("docs/report.pdf", 10),
        sample("music/song.flac", 20),
        sample("code/main.rs", 30),
    ];
    {
        let idx = Index::open(&path, &subkey).unwrap();
        for r in &originals {
            idx.put(r).unwrap();
        }
    } // connection closed → checkpointed into the encrypted main DB file.

    // Reopen with the SAME sub-key: every record survives, byte-for-byte.
    let reopened = Index::open(&path, &subkey).unwrap();
    assert_eq!(reopened.count().unwrap(), originals.len() as u64);
    for r in &originals {
        assert_eq!(reopened.get(&r.path).unwrap().as_ref(), Some(r));
    }
    // Enumeration order is stable across reopen (deterministic ORDER BY key).
    let first = reopened.all().unwrap();
    let second = reopened.all().unwrap();
    assert_eq!(first, second);
}

/// Opening an existing DB with the WRONG sub-key derives the wrong SQLCipher key,
/// so the page header cannot be decrypted — the open itself fails (SQLITE_NOTADB),
/// and no rows are ever readable.
#[test]
fn wrong_subkey_cannot_read_records() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("i.db");
    {
        let idx = Index::open(&path, &[1u8; 32]).unwrap();
        idx.put(&sample("secret/file", 42)).unwrap();
    }

    // A different sub-key ⇒ different SQLCipher key ⇒ whole-DB decryption fails at open.
    let wrong = Index::open(&path, &[2u8; 32]);
    assert!(
        wrong.is_err(),
        "opening a SQLCipher DB with the wrong key must fail, never expose rows"
    );

    // The correct sub-key still opens and reads it.
    let right = Index::open(&path, &[1u8; 32]).unwrap();
    assert_eq!(right.count().unwrap(), 1);
    assert_eq!(right.get("secret/file").unwrap().unwrap().size, 42);
}

#[test]
fn database_does_not_leak_paths_at_rest() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("i.db");
    {
        let idx = Index::open(&path, &[8u8; 32]).unwrap();
        idx.put(&sample("TOPSECRET/directory/plans.txt", 7))
            .unwrap();
    }

    // Scan the main DB file and any WAL/SHM sidecars — SQLCipher encrypts them all,
    // and the per-row AEAD would protect a decrypted page anyway. No plaintext leaks.
    let mut raw = std::fs::read(&path).unwrap();
    for suffix in ["-wal", "-shm"] {
        let side = path.with_file_name(format!(
            "{}{}",
            path.file_name().unwrap().to_string_lossy(),
            suffix
        ));
        if let Ok(mut bytes) = std::fs::read(&side) {
            raw.append(&mut bytes);
        }
    }

    assert!(!contains_subsequence(
        &raw,
        b"TOPSECRET/directory/plans.txt"
    ));
    assert!(!contains_subsequence(&raw, b"TOPSECRET"));
    assert!(!contains_subsequence(&raw, b"plans.txt"));
    // The object_key value is also metadata; confirm it is not present in the clear.
    assert!(!contains_subsequence(&raw, b"obj/7"));
    // The directory rows carry names too, and they are sealed the same way — a
    // path that leaked only via the tree would leak just as completely.
    assert!(!contains_subsequence(&raw, b"directory"));
}

// ─────────────────────────────────────────────────────────────────────────────
// Directory-keyed listing.
//
// The defect these exist for: the row key is a keyed hash, so rows stream in an
// order unrelated to their paths, and every listing had to decrypt the whole
// index to answer a question about one directory. Measured on 100,000 files that
// was 413 ms per `readdir` and 417 s for a full walk — quadratic, because a walk
// performs one `readdir` per directory.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn a_directory_lists_what_is_directly_in_it_and_nothing_deeper() {
    let dir = TempDir::new().unwrap();
    let idx = Index::open(&dir.path().join("i.db"), &[11u8; 32]).unwrap();
    for path in [
        "photos/a.jpg",
        "photos/b.jpg",
        "photos/2024/deep.jpg",
        "docs/report.pdf",
        "top.txt",
    ] {
        idx.put(&sample(path, 1)).unwrap();
    }

    assert_eq!(
        children_of(&idx, "photos"),
        vec!["photos/a.jpg", "photos/b.jpg"],
        "a listing owes its own directory, not the subtree under it"
    );
    assert_eq!(dirs_of(&idx, "photos"), vec!["photos/2024"]);
    assert_eq!(
        children_of(&idx, ""),
        vec!["top.txt"],
        "the root holds what sits at the root and no more"
    );
    assert_eq!(dirs_of(&idx, ""), vec!["docs", "photos"]);
    assert_eq!(
        children_of(&idx, "top.txt"),
        Vec::<String>::new(),
        "a file is not a directory and holds nothing"
    );
}

#[test]
fn a_sibling_sharing_a_name_prefix_is_a_different_directory() {
    // `photos` and `photos-backup` share bytes and sort adjacently. A prefix
    // match would fold them; a parent hash cannot.
    let dir = TempDir::new().unwrap();
    let idx = Index::open(&dir.path().join("i.db"), &[12u8; 32]).unwrap();
    idx.put(&sample("photos/a.jpg", 1)).unwrap();
    idx.put(&sample("photos-backup/b.jpg", 2)).unwrap();

    assert_eq!(children_of(&idx, "photos"), vec!["photos/a.jpg"]);
    assert_eq!(children_of(&idx, "photos-backup"), vec!["photos-backup/b.jpg"]);
}

#[test]
fn a_directory_exists_exactly_while_something_is_under_it() {
    // A vault stores no directories, so one exists only because files imply it.
    // The reference count is what lets the last file's departure collect it
    // without a scan to discover the directory is now empty.
    let dir = TempDir::new().unwrap();
    let idx = Index::open(&dir.path().join("i.db"), &[13u8; 32]).unwrap();

    assert!(!idx.contains_dir("a/b").unwrap(), "nothing implies it yet");

    idx.put(&sample("a/b/one.txt", 1)).unwrap();
    idx.put(&sample("a/b/two.txt", 2)).unwrap();
    assert!(idx.contains_dir("a").unwrap());
    assert!(idx.contains_dir("a/b").unwrap());

    idx.delete("a/b/one.txt").unwrap();
    assert!(
        idx.contains_dir("a/b").unwrap(),
        "a directory with a file left in it still exists"
    );

    idx.delete("a/b/two.txt").unwrap();
    assert!(!idx.contains_dir("a/b").unwrap(), "its last file left");
    assert!(
        !idx.contains_dir("a").unwrap(),
        "and nothing is under its parent either, so that goes too"
    );
    assert_eq!(dirs_of(&idx, ""), Vec::<String>::new());
}

#[test]
fn a_deep_directory_survives_until_the_last_file_anywhere_beneath_it_goes() {
    // The count is of everything below, not of direct children — otherwise
    // deleting `a/b/c.txt` would collect `a` while `a/d.txt` still lived there.
    let dir = TempDir::new().unwrap();
    let idx = Index::open(&dir.path().join("i.db"), &[14u8; 32]).unwrap();
    idx.put(&sample("a/b/c.txt", 1)).unwrap();
    idx.put(&sample("a/d.txt", 2)).unwrap();

    idx.delete("a/b/c.txt").unwrap();
    assert!(!idx.contains_dir("a/b").unwrap(), "emptied");
    assert!(idx.contains_dir("a").unwrap(), "still holds a/d.txt");
    assert_eq!(children_of(&idx, "a"), vec!["a/d.txt"]);
}

#[test]
fn replacing_a_file_does_not_duplicate_the_directory_it_is_in() {
    // `put` over an existing path is a replacement, so the directory gains no
    // new reference — otherwise a file rewritten twice would keep its directory
    // alive after deletion.
    let dir = TempDir::new().unwrap();
    let idx = Index::open(&dir.path().join("i.db"), &[15u8; 32]).unwrap();
    idx.put(&sample("a/one.txt", 1)).unwrap();
    idx.put(&sample("a/one.txt", 2)).unwrap();
    idx.put(&sample("a/one.txt", 3)).unwrap();

    idx.delete("a/one.txt").unwrap();
    assert!(
        !idx.contains_dir("a").unwrap(),
        "three writes and one delete must leave nothing behind"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Maintained totals — what `statfs` reads.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn totals_follow_what_the_index_holds() {
    let dir = TempDir::new().unwrap();
    let idx = Index::open(&dir.path().join("i.db"), &[16u8; 32]).unwrap();
    assert_eq!(idx.totals().unwrap().objects, 0);
    assert_eq!(idx.totals().unwrap().measured_bytes(), Some(0));

    idx.put(&sample("a.bin", 100)).unwrap();
    idx.put(&sample("d/b.bin", 200)).unwrap();
    let totals = idx.totals().unwrap();
    assert_eq!((totals.objects, totals.measured_bytes()), (2, Some(300)));

    idx.delete("a.bin").unwrap();
    let totals = idx.totals().unwrap();
    assert_eq!((totals.objects, totals.measured_bytes()), (1, Some(200)));
}

#[test]
fn replacing_a_file_moves_the_total_by_the_difference() {
    // The bug a recount would not have: adding the new size without removing the
    // old one leaves `df` growing every time a file is rewritten.
    let dir = TempDir::new().unwrap();
    let idx = Index::open(&dir.path().join("i.db"), &[17u8; 32]).unwrap();
    idx.put(&sample("a.bin", 1000)).unwrap();
    idx.put(&sample("a.bin", 10)).unwrap();

    let totals = idx.totals().unwrap();
    assert_eq!(
        (totals.objects, totals.measured_bytes()),
        (1, Some(10)),
        "one file of ten bytes, not two files or 1010 bytes"
    );
}

#[test]
fn one_unmeasured_file_makes_the_total_unknown_rather_than_smaller() {
    // A rebuilt index maps every object without opening one. Reporting the sum
    // of the rest as though it were the whole is the same quiet lie a zero is.
    let dir = TempDir::new().unwrap();
    let idx = Index::open(&dir.path().join("i.db"), &[18u8; 32]).unwrap();
    idx.put(&sample("known.bin", 500)).unwrap();
    idx.put(&unmeasured("rebuilt.bin")).unwrap();

    let totals = idx.totals().unwrap();
    assert_eq!(totals.objects, 2, "both files are counted");
    assert_eq!(totals.measured_bytes(), None, "but the total is not known");

    // Measuring it resolves the doubt without double-counting the bytes.
    idx.put(&sample("rebuilt.bin", 7)).unwrap();
    let totals = idx.totals().unwrap();
    assert_eq!((totals.objects, totals.measured_bytes()), (2, Some(507)));
}

#[test]
fn totals_and_directories_survive_a_reopen() {
    // They are rows like any other, but a mistake here would show up only after
    // a restart — the worst place for one.
    let subkey = [19u8; 32];
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("persist.db");
    {
        let idx = Index::open(&path, &subkey).unwrap();
        idx.put(&sample("a/b/c.bin", 42)).unwrap();
    }
    let reopened = Index::open(&path, &subkey).unwrap();
    let totals = reopened.totals().unwrap();
    assert_eq!((totals.objects, totals.measured_bytes()), (1, Some(42)));
    assert_eq!(dirs_of(&reopened, "a"), vec!["a/b"]);
    assert_eq!(children_of(&reopened, "a/b"), vec!["a/b/c.bin"]);
}
