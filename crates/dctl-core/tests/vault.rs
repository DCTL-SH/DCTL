//! End-to-end vault tests over the local backend: init/unlock, verified put/get,
//! overwrite, list, delete, wrong-password, and tamper detection.

use std::sync::Arc;

use dctl_core::{CoreError, Vault};
use dctl_store::{Backend, LocalFs};
use tempfile::TempDir;

struct Env {
    _store: TempDir,
    _index: TempDir,
    backend: Arc<dyn Backend>,
    index_path: std::path::PathBuf,
}

fn env() -> Env {
    let store = TempDir::new().unwrap();
    let index = TempDir::new().unwrap();
    let backend: Arc<dyn Backend> = Arc::new(LocalFs::new(store.path()));
    let index_path = index.path().join("vault.redb");
    Env {
        _store: store,
        _index: index,
        backend,
        index_path,
    }
}

#[tokio::test]
async fn init_unlock_put_get_roundtrip() {
    let e = env();
    {
        let vault = Vault::init(e.backend.clone(), &e.index_path, "pw")
            .await
            .unwrap();
        vault
            .put_file("photos/a.jpg", b"hello verified world")
            .await
            .unwrap();
    }
    let vault = Vault::unlock(e.backend.clone(), &e.index_path, "pw")
        .await
        .unwrap();
    let got = vault.get_file("photos/a.jpg").await.unwrap();
    assert_eq!(got.as_slice(), b"hello verified world");
}

#[tokio::test]
async fn wrong_password_fails_to_unlock() {
    let e = env();
    Vault::init(e.backend.clone(), &e.index_path, "correct")
        .await
        .unwrap();
    let result = Vault::unlock(e.backend.clone(), &e.index_path, "wrong").await;
    assert!(matches!(result, Err(CoreError::Unlock)));
}

#[tokio::test]
async fn put_overwrites_same_path() {
    let e = env();
    let vault = Vault::init(e.backend.clone(), &e.index_path, "pw")
        .await
        .unwrap();
    vault.put_file("k", b"first").await.unwrap();
    vault.put_file("k", b"second").await.unwrap();
    assert_eq!(vault.get_file("k").await.unwrap().as_slice(), b"second");
    assert_eq!(vault.list("").unwrap().len(), 1);
}

#[tokio::test]
async fn list_filters_by_prefix() {
    let e = env();
    let vault = Vault::init(e.backend.clone(), &e.index_path, "pw")
        .await
        .unwrap();
    vault.put_file("a/1", b"x").await.unwrap();
    vault.put_file("a/2", b"y").await.unwrap();
    vault.put_file("b/1", b"z").await.unwrap();

    let listed = vault.list("a/").unwrap();
    let paths: Vec<_> = listed.iter().map(|r| r.path.clone()).collect();
    assert_eq!(paths, vec!["a/1".to_string(), "a/2".to_string()]);
}

#[tokio::test]
async fn delete_removes_object_and_record() {
    let e = env();
    let vault = Vault::init(e.backend.clone(), &e.index_path, "pw")
        .await
        .unwrap();
    vault.put_file("gone", b"data").await.unwrap();

    assert!(vault.delete_file("gone").await.unwrap());
    assert!(!vault.delete_file("gone").await.unwrap());
    assert!(matches!(
        vault.get_file("gone").await.unwrap_err(),
        CoreError::NotFound(_)
    ));
}

#[tokio::test]
async fn restore_on_a_fresh_device_from_backend_only() {
    // Device A and device B share one backend but have separate local indexes.
    let store = TempDir::new().unwrap();
    let backend: Arc<dyn Backend> = Arc::new(LocalFs::new(store.path()));
    let idx_a = TempDir::new().unwrap();
    let idx_b = TempDir::new().unwrap();
    let a_path = idx_a.path().join("a.redb");
    let b_path = idx_b.path().join("b.redb");

    // Device A: create the vault and store some files, then go away.
    {
        let a = Vault::init(backend.clone(), &a_path, "pw").await.unwrap();
        a.put_file("photos/2026/a.jpg", b"alpha").await.unwrap();
        a.put_file("photos/2026/b.jpg", b"bravo").await.unwrap();
        a.put_file("docs/notes.txt", b"charlie").await.unwrap();
    }

    // Device B: SAME backend, a brand-new EMPTY index. Unlock with only the password.
    let b = Vault::unlock(backend.clone(), &b_path, "pw").await.unwrap();

    // (1) A file is readable even before any rebuild — resolved via the backend's
    //     authoritative name record. This is the core cross-device guarantee.
    assert_eq!(
        b.get_file("photos/2026/a.jpg").await.unwrap().as_slice(),
        b"alpha"
    );

    // (2) Rebuild the whole index from the backend; then everything lists and reads.
    let n = b.rebuild_index().await.unwrap();
    assert_eq!(n, 3, "all three name records rebuilt");
    let mut paths: Vec<_> = b.list("").unwrap().into_iter().map(|r| r.path).collect();
    paths.sort();
    assert_eq!(
        paths,
        vec![
            "docs/notes.txt".to_string(),
            "photos/2026/a.jpg".to_string(),
            "photos/2026/b.jpg".to_string(),
        ]
    );
    assert_eq!(
        b.get_file("docs/notes.txt").await.unwrap().as_slice(),
        b"charlie"
    );
    assert_eq!(
        b.get_file("photos/2026/b.jpg").await.unwrap().as_slice(),
        b"bravo"
    );

    // A path that was never stored is still NotFound (no name record to resolve).
    assert!(matches!(
        b.get_file("nope").await.unwrap_err(),
        CoreError::NotFound(_)
    ));
}

#[tokio::test]
async fn tampered_object_is_detected_on_read() {
    let e = env();
    let vault = Vault::init(e.backend.clone(), &e.index_path, "pw")
        .await
        .unwrap();
    vault
        .put_file("photos/a.jpg", b"the quick brown fox jumps")
        .await
        .unwrap();

    // Corrupt the stored content object directly on disk (under the "o/" prefix).
    let object_dir = e._store.path().join("o");
    let entry = std::fs::read_dir(&object_dir)
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    let mut bytes = std::fs::read(entry.path()).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xFF;
    std::fs::write(entry.path(), bytes).unwrap();

    assert!(vault.get_file("photos/a.jpg").await.is_err());
    assert!(vault.verify_file("photos/a.jpg").await.is_err());
}
