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
}
