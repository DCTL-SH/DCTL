//! Integration tests for the encrypted index: CRUD, enumeration, wrong-key
//! resistance, and at-rest metadata privacy.

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

#[test]
fn put_get_delete_count() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("index.redb");
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
    let idx = Index::open(&dir.path().join("i.redb"), &[3u8; 32]).unwrap();
    idx.put(&sample("k", 1)).unwrap();
    idx.put(&sample("k", 2)).unwrap();
    assert_eq!(idx.count().unwrap(), 1);
    assert_eq!(idx.get("k").unwrap().unwrap().size, 2);
}

#[test]
fn enumeration_and_early_stop() {
    let dir = TempDir::new().unwrap();
    let idx = Index::open(&dir.path().join("i.redb"), &[5u8; 32]).unwrap();
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

#[test]
fn wrong_subkey_cannot_read_records() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("i.redb");
    {
        let idx = Index::open(&path, &[1u8; 32]).unwrap();
        idx.put(&sample("secret/file", 42)).unwrap();
    }
    // Reopen with a different sub-key.
    let other = Index::open(&path, &[2u8; 32]).unwrap();
    // The entry exists on disk...
    assert_eq!(other.count().unwrap(), 1);
    // ...but is not addressable by the wrong keying key...
    assert_eq!(other.get("secret/file").unwrap(), None);
    // ...and enumerating fails to decrypt it (wrong content key).
    assert!(other.all().is_err());
}

#[test]
fn database_does_not_leak_paths_at_rest() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("i.redb");
    {
        let idx = Index::open(&path, &[8u8; 32]).unwrap();
        idx.put(&sample("TOPSECRET/directory/plans.txt", 7))
            .unwrap();
    }
    let raw = std::fs::read(&path).unwrap();
    assert!(!contains_subsequence(
        &raw,
        b"TOPSECRET/directory/plans.txt"
    ));
    assert!(!contains_subsequence(&raw, b"TOPSECRET"));
    assert!(!contains_subsequence(&raw, b"plans.txt"));
}
