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

/// Deterministic pseudo-random bytes (xorshift64) — no `rand` dep, reproducible.
fn pseudo_random(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    for b in out.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = (x & 0xFF) as u8;
    }
    out
}

#[tokio::test]
async fn put_file_from_path_streams_multichunk_roundtrip() {
    let e = env();

    // A source file larger than the default 1 MiB chunk → genuinely multi-chunk.
    let src = TempDir::new().unwrap();
    let src_path = src.path().join("clip.bin");
    let data = pseudo_random(2 * 1024 * 1024 + 12_345);
    std::fs::write(&src_path, &data).unwrap();

    {
        let vault = Vault::init(e.backend.clone(), &e.index_path, "pw")
            .await
            .unwrap();
        vault
            .put_file_from_path("videos/clip.bin", &src_path)
            .await
            .unwrap();

        // get_file returns identical bytes.
        assert_eq!(
            vault.get_file("videos/clip.bin").await.unwrap().as_slice(),
            data.as_slice()
        );

        // list shows it with the right (plaintext) size.
        let listed = vault.list("").unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].path, "videos/clip.bin");
        assert_eq!(listed[0].size, data.len() as u64);
    }

    // Round-trips through a fresh unlock (index reopened from scratch on disk).
    let vault = Vault::unlock(e.backend.clone(), &e.index_path, "pw")
        .await
        .unwrap();
    assert_eq!(
        vault.get_file("videos/clip.bin").await.unwrap().as_slice(),
        data.as_slice()
    );
}

#[tokio::test]
async fn get_file_to_path_streams_multichunk_roundtrip() {
    let e = env();

    // A >1 MiB source (default chunk is 1 MiB) → genuinely multi-chunk.
    let src = TempDir::new().unwrap();
    let src_path = src.path().join("clip.bin");
    let data = pseudo_random(1024 * 1024 + 4_096);
    std::fs::write(&src_path, &data).unwrap();

    let out = TempDir::new().unwrap();
    let dest = out.path().join("nested/decrypted.bin");

    let vault = Vault::init(e.backend.clone(), &e.index_path, "pw")
        .await
        .unwrap();
    vault
        .put_file_from_path("videos/clip.bin", &src_path)
        .await
        .unwrap();

    // Streaming read to a file yields a byte-identical destination (parent auto-created).
    vault
        .get_file_to_path("videos/clip.bin", &dest)
        .await
        .unwrap();
    assert_eq!(std::fs::read(&dest).unwrap(), data);

    // Round-trips through a fresh unlock too (index reopened from disk).
    drop(vault);
    let vault = Vault::unlock(e.backend.clone(), &e.index_path, "pw")
        .await
        .unwrap();
    let dest2 = out.path().join("again.bin");
    vault
        .get_file_to_path("videos/clip.bin", &dest2)
        .await
        .unwrap();
    assert_eq!(std::fs::read(&dest2).unwrap(), data);
}

#[tokio::test]
async fn get_file_to_path_tamper_errors_and_leaves_no_dest() {
    let e = env();
    let vault = Vault::init(e.backend.clone(), &e.index_path, "pw")
        .await
        .unwrap();
    vault
        .put_file("photos/a.jpg", b"the quick brown fox jumps over")
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

    let out = TempDir::new().unwrap();
    let dest = out.path().join("decrypted.bin");
    assert!(
        vault.get_file_to_path("photos/a.jpg", &dest).await.is_err(),
        "a tampered object must be rejected"
    );
    assert!(
        !dest.exists(),
        "no dest file (not even a partial one) may be left behind on failure"
    );
}

#[tokio::test]
async fn get_file_to_path_cross_device_via_name_record() {
    // Device A stores; device B reads to a file with a brand-new empty index, resolving
    // the object purely through the authoritative §5 name record.
    let store = TempDir::new().unwrap();
    let backend: Arc<dyn Backend> = Arc::new(LocalFs::new(store.path()));
    let idx_a = TempDir::new().unwrap();
    let idx_b = TempDir::new().unwrap();

    let src = TempDir::new().unwrap();
    let src_path = src.path().join("movie.bin");
    let data = pseudo_random(1024 * 1024 + 777);
    std::fs::write(&src_path, &data).unwrap();

    {
        let a = Vault::init(backend.clone(), &idx_a.path().join("a.redb"), "pw")
            .await
            .unwrap();
        a.put_file_from_path("media/movie.bin", &src_path)
            .await
            .unwrap();
    }

    let b = Vault::unlock(backend.clone(), &idx_b.path().join("b.redb"), "pw")
        .await
        .unwrap();
    let out = TempDir::new().unwrap();
    let dest = out.path().join("movie.bin");
    b.get_file_to_path("media/movie.bin", &dest).await.unwrap();
    assert_eq!(std::fs::read(&dest).unwrap(), data);

    // A path that was never stored has no name record to resolve → NotFound.
    assert!(matches!(
        b.get_file_to_path("media/nope.bin", &out.path().join("x"))
            .await
            .unwrap_err(),
        CoreError::NotFound(_)
    ));
}

#[tokio::test]
async fn stream_and_buffered_puts_interoperate() {
    let e = env();
    let vault = Vault::init(e.backend.clone(), &e.index_path, "pw")
        .await
        .unwrap();

    // The same content stored both ways opens identically through get_file, i.e. the
    // streaming path produces an object the buffered reader decodes with no special case.
    let payload = pseudo_random(4096 + 7);
    let src = TempDir::new().unwrap();
    let src_path = src.path().join("s.bin");
    std::fs::write(&src_path, &payload).unwrap();

    vault.put_file("via/buffered", &payload).await.unwrap();
    vault
        .put_file_from_path("via/streamed", &src_path)
        .await
        .unwrap();

    assert_eq!(
        vault.get_file("via/buffered").await.unwrap().as_slice(),
        payload.as_slice()
    );
    assert_eq!(
        vault.get_file("via/streamed").await.unwrap().as_slice(),
        payload.as_slice()
    );
}

#[tokio::test]
async fn overwrite_gcs_the_previous_object() {
    let e = env();
    let vault = Vault::init(e.backend.clone(), &e.index_path, "pw")
        .await
        .unwrap();
    let obj_dir = e._store.path().join("o");
    let count = |dir: &std::path::Path| std::fs::read_dir(dir).map(|d| d.count()).unwrap_or(0);

    vault.put_file("k", b"first").await.unwrap();
    assert_eq!(count(&obj_dir), 1, "one object after first put");

    // Overwriting the same path must GC the previous ciphertext, not orphan it on the
    // untrusted backend (a private tool must not leave prior versions recoverable).
    vault.put_file("k", b"second and longer").await.unwrap();
    assert_eq!(
        count(&obj_dir),
        1,
        "overwrite GC'd the old object — no orphan left"
    );
    assert_eq!(
        vault.get_file("k").await.unwrap().as_slice(),
        b"second and longer"
    );
}

#[tokio::test]
async fn cross_device_delete_removes_object_and_name_record() {
    let store = TempDir::new().unwrap();
    let backend: Arc<dyn Backend> = Arc::new(LocalFs::new(store.path()));
    let idx_a = TempDir::new().unwrap();
    let idx_b = TempDir::new().unwrap();
    {
        let a = Vault::init(backend.clone(), &idx_a.path().join("a.redb"), "pw")
            .await
            .unwrap();
        a.put_file("secret.txt", b"classified").await.unwrap();
    }

    // Device B: fresh empty index. Delete resolves via the name record (no rebuild),
    // and must actually remove both the object and the name record from the backend.
    let b = Vault::unlock(backend.clone(), &idx_b.path().join("b.redb"), "pw")
        .await
        .unwrap();
    assert!(
        b.delete_file("secret.txt").await.unwrap(),
        "cross-device delete finds and removes it"
    );
    let count = |sub: &str| {
        std::fs::read_dir(store.path().join(sub))
            .map(|d| d.count())
            .unwrap_or(0)
    };
    assert_eq!(count("o"), 0, "content object removed");
    assert_eq!(count("n"), 0, "name record removed — nothing left behind");
    assert!(matches!(
        b.get_file("secret.txt").await.unwrap_err(),
        CoreError::NotFound(_)
    ));
    assert!(
        !b.delete_file("secret.txt").await.unwrap(),
        "second delete is a no-op"
    );
}

/// Path of the single stored content object under a `LocalFs` store's `o/` prefix. Only
/// valid when exactly one object exists (the sharing tests arrange that).
fn only_object_path(store: &std::path::Path) -> std::path::PathBuf {
    let dir = store.join("o");
    std::fs::read_dir(&dir)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path()
}

/// Raw bytes of that single stored content object.
fn only_object_bytes(store: &std::path::Path) -> Vec<u8> {
    std::fs::read(only_object_path(store)).unwrap()
}

#[tokio::test]
async fn shared_put_roundtrips_and_head_is_kem1() {
    let e = env();
    let owner = Vault::init(e.backend.clone(), &e.index_path, "pw")
        .await
        .unwrap();

    // A separate vault (its own root → its own identity) supplies a recipient to share to.
    let r_env = env();
    let recipient = Vault::init(r_env.backend.clone(), &r_env.index_path, "pw2")
        .await
        .unwrap();

    let data = b"hello asymmetric recipients";
    owner
        .put_file_shared("shared/a", data, &[recipient.identity().clone()])
        .await
        .unwrap();

    // The owner reads it back through the ordinary get_file (kem_id=1 branch exercised).
    assert_eq!(owner.get_file("shared/a").await.unwrap().as_slice(), data);

    // The stored object's head declares kem_id=1 (FORMAT.md §3: head byte 6 = kem_id).
    let obj = only_object_bytes(e._store.path());
    assert_eq!(obj[6], 1, "shared object head kem_id must be 1 (hybrid)");
}

#[tokio::test]
async fn recipient_in_set_decrypts_but_non_recipient_errors() {
    // Owner O shares to recipient B (not C). B is a recipient → opens the object via
    // get_file; C is not → the hybrid open finds no sub-record for its key_id and errors.
    // Name records are per-root, so B and C resolve the object through their OWN name
    // record (minted by a placeholder put) whose stored bytes we replace with O's object.
    let o_env = env();
    let o = Vault::init(o_env.backend.clone(), &o_env.index_path, "pw")
        .await
        .unwrap();
    let b_env = env();
    let b = Vault::init(b_env.backend.clone(), &b_env.index_path, "pw")
        .await
        .unwrap();
    let c_env = env();
    let c = Vault::init(c_env.backend.clone(), &c_env.index_path, "pw")
        .await
        .unwrap();

    // All three identities are distinct (independent random roots).
    assert_ne!(o.identity_key_id(), b.identity_key_id());
    assert_ne!(o.identity_key_id(), c.identity_key_id());
    assert_ne!(b.identity_key_id(), c.identity_key_id());

    let data = b"top secret shared payload";
    // Share to B only; C is deliberately excluded (O is auto-included per §12.8).
    o.put_file_shared("p", data, &[b.identity().clone()])
        .await
        .unwrap();
    let shared = only_object_bytes(o_env._store.path());

    // Mint a resolvable "p" on B and C (placeholder put), then repoint it at the shared
    // object by overwriting the stored object bytes in place (the object KEY is unchanged).
    b.put_file("p", b"placeholder").await.unwrap();
    std::fs::write(only_object_path(b_env._store.path()), &shared).unwrap();
    c.put_file("p", b"placeholder").await.unwrap();
    std::fs::write(only_object_path(c_env._store.path()), &shared).unwrap();

    // B is a recipient → decrypts to the original plaintext.
    assert_eq!(b.get_file("p").await.unwrap().as_slice(), data);
    // C is NOT a recipient → error (no kem_wrap sub-record for C's key_id).
    assert!(
        c.get_file("p").await.is_err(),
        "a non-recipient vault must not be able to open the shared object"
    );
}

#[tokio::test]
async fn owner_auto_included_even_when_not_passed() {
    // §12.8 owner-inclusion MUST: a kem_id=1 object has no symmetric fallback, so the
    // owner is always added to the recipient set even when not passed in `recipients`.
    let e = env();
    let owner = Vault::init(e.backend.clone(), &e.index_path, "pw")
        .await
        .unwrap();
    let r_env = env();
    let recipient = Vault::init(r_env.backend.clone(), &r_env.index_path, "pw2")
        .await
        .unwrap();
    assert_ne!(owner.identity_key_id(), recipient.identity_key_id());

    // The recipient set does NOT contain the owner's identity...
    let data = b"write-only backup with no symmetric fallback";
    owner
        .put_file_shared("backup/x", data, &[recipient.identity().clone()])
        .await
        .unwrap();

    // ...yet the owner still recovers it: put_file_shared auto-includes the owner.
    assert_eq!(owner.get_file("backup/x").await.unwrap().as_slice(), data);
    let obj = only_object_bytes(e._store.path());
    assert_eq!(obj[6], 1, "object must be hybrid (kem_id=1)");
}

#[tokio::test]
async fn shared_object_reads_via_get_file_to_path_and_verifies() {
    // Exercise the kem_id=1 branches of get_file_to_path (buffered) and verify_file with a
    // genuinely multi-chunk payload (> the 1 MiB default chunk). The owner is always a
    // recipient, so it can read/verify its own shared object.
    let e = env();
    let owner = Vault::init(e.backend.clone(), &e.index_path, "pw")
        .await
        .unwrap();
    let r_env = env();
    let recipient = Vault::init(r_env.backend.clone(), &r_env.index_path, "pw2")
        .await
        .unwrap();

    let data = pseudo_random(1024 * 1024 + 9_001);
    owner
        .put_file_shared("media/clip.bin", &data, &[recipient.identity().clone()])
        .await
        .unwrap();

    // verify_file (kem_id=1 branch): full tag/footer/content-hash check, no plaintext out.
    owner.verify_file("media/clip.bin").await.unwrap();

    // get_file_to_path (kem_id=1 buffered branch): byte-identical destination, parent made.
    let out = TempDir::new().unwrap();
    let dest = out.path().join("nested/clip.bin");
    owner
        .get_file_to_path("media/clip.bin", &dest)
        .await
        .unwrap();
    assert_eq!(std::fs::read(&dest).unwrap(), data);
}

#[tokio::test]
async fn publish_then_fetch_recipient_roundtrips_and_bad_key_errors() {
    let e = env();
    let vault = Vault::init(e.backend.clone(), &e.index_path, "pw")
        .await
        .unwrap();

    let key_id = vault.identity_key_id();
    // Fetch before publish → absent registry entry → error.
    assert!(
        vault.fetch_recipient(&key_id).await.is_err(),
        "an unpublished key_id has no registry entry"
    );

    vault.publish_identity().await.unwrap();
    let fetched = vault.fetch_recipient(&key_id).await.unwrap();

    // Round-trips to the exact same DRK1 and key_id (self-certifying trust anchor).
    assert!(
        fetched.encode() == vault.identity().encode(),
        "fetched DRK1 bytes must match the published identity"
    );
    assert_eq!(fetched.key_id(), key_id);

    // A key_id that was never published → error (absent).
    let mut wrong = key_id;
    wrong[0] ^= 0xFF;
    assert!(
        vault.fetch_recipient(&wrong).await.is_err(),
        "a wrong/absent key_id must error"
    );
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
