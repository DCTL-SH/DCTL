//! End-to-end vault tests over the local backend: init/unlock, verified put/get,
//! overwrite, list, delete, wrong-password, and tamper detection.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::Bytes;
use dctl_core::error::ErrorKind;
use dctl_core::{CoreError, Vault};
use dctl_store::{
    Backend, ByteRange, ContentHash, LocalFs, ObjectKey, ObjectMeta, Page, PutOutcome, StoreError,
};
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

/// Copy the single §12.6 grant sidecar (`g/<hex>`) from one `LocalFs` store to another,
/// under the same key — the sharing tests move the object + sidecar bytes across backends
/// because name records are per-root (see `recipient_in_set_decrypts_but_non_recipient_errors`).
fn copy_sidecar(from_store: &std::path::Path, to_store: &std::path::Path) {
    let src = std::fs::read_dir(from_store.join("g"))
        .expect("grant sidecar dir exists")
        .next()
        .expect("a sidecar file exists")
        .unwrap()
        .path();
    let fname = src.file_name().unwrap().to_owned();
    let dst_dir = to_store.join("g");
    std::fs::create_dir_all(&dst_dir).unwrap();
    std::fs::copy(&src, dst_dir.join(fname)).unwrap();
}

#[tokio::test]
async fn sidecar_add_grants_read_then_remove_revokes() {
    // O and B are distinct vaults (distinct roots → distinct identities) on separate
    // backends. Sharing ships the object + sidecar bytes to B's backend (name records are
    // per-root), exactly like the other cross-vault sharing tests.
    let o_env = env();
    let o = Vault::init(o_env.backend.clone(), &o_env.index_path, "pw")
        .await
        .unwrap();
    let b_env = env();
    let b = Vault::init(b_env.backend.clone(), &b_env.index_path, "pw2")
        .await
        .unwrap();
    assert_ne!(o.identity_key_id(), b.identity_key_id());

    let o_store = o_env._store.path();
    let b_store = b_env._store.path();

    // O uploads an object shared to OWNER-ONLY (B is not an inline recipient).
    let data = b"payload shared later via the grant sidecar, never re-uploaded".repeat(4);
    o.put_file_shared("clip", &data, &[]).await.unwrap();
    // The owner always reads its own object (inline).
    assert_eq!(
        o.get_file("clip").await.unwrap().as_slice(),
        data.as_slice()
    );

    // Mint a resolvable "clip" on B, then repoint it at O's shared object bytes.
    b.put_file("clip", b"placeholder").await.unwrap();
    let shared = only_object_bytes(o_store);
    std::fs::write(only_object_path(b_store), &shared).unwrap();

    // Before any grant: B is NOT a recipient (no inline sub-record, no sidecar) → errors.
    assert!(
        b.get_file("clip").await.is_err(),
        "B cannot read before being granted"
    );

    // O adds B via the sidecar (no object re-upload); ship the sidecar to B's store.
    o.share_add_recipients("clip", &[b.identity().clone()])
        .await
        .unwrap();
    copy_sidecar(o_store, b_store);

    // B now reads the EXACT bytes via the sidecar grant — buffered and streamed-to-path.
    assert_eq!(
        b.get_file("clip").await.unwrap().as_slice(),
        data.as_slice()
    );
    let out = TempDir::new().unwrap();
    let dest = out.path().join("nested/clip.out");
    b.get_file_to_path("clip", &dest).await.unwrap();
    assert_eq!(std::fs::read(&dest).unwrap(), data);
    // Adding B again is an idempotent no-op (already granted).
    o.share_add_recipients("clip", &[b.identity().clone()])
        .await
        .unwrap();

    // A sidecar carrying the right grant but bound to the WRONG object is rejected: corrupt
    // its file_id (offset 8), then its head_hash (offset 24), on B's store.
    let sc_path = std::fs::read_dir(b_store.join("g"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let mut sc = std::fs::read(&sc_path).unwrap();
    sc[8] ^= 0xFF;
    std::fs::write(&sc_path, &sc).unwrap();
    assert!(
        b.get_file("clip").await.is_err(),
        "sidecar bound to the wrong file_id is rejected"
    );
    copy_sidecar(o_store, b_store); // restore
    let mut sc = std::fs::read(&sc_path).unwrap();
    sc[24] ^= 0xFF;
    std::fs::write(&sc_path, &sc).unwrap();
    assert!(
        b.get_file("clip").await.is_err(),
        "sidecar with a wrong head_hash is rejected"
    );
    copy_sidecar(o_store, b_store); // restore
    assert_eq!(
        b.get_file("clip").await.unwrap().as_slice(),
        data.as_slice(),
        "the intact sidecar still grants B"
    );

    // O revokes B; ship the rewritten (empty) sidecar. B fails again.
    o.share_remove_recipient("clip", &b.identity_key_id())
        .await
        .unwrap();
    copy_sidecar(o_store, b_store);
    assert!(
        b.get_file("clip").await.is_err(),
        "B is revoked from the sidecar"
    );
    // The owner still reads it (inline recipient, unaffected by sidecar edits).
    assert_eq!(
        o.get_file("clip").await.unwrap().as_slice(),
        data.as_slice()
    );

    // Removing an already-absent grant errors.
    assert!(
        o.share_remove_recipient("clip", &b.identity_key_id())
            .await
            .is_err(),
        "removing an absent grant errors"
    );
}

/// A `Backend` wrapper that injects a **transient** fault (`StoreError::Backend`, the
/// class B2/S3 map every non-404 to — 5xx, timeout, throttling) on `get` of any grant
/// sidecar key (`g/…`) while its toggle is armed, delegating every other call unchanged.
/// It never fabricates a `NotFound`, so it models "the sidecar read failed transiently",
/// never "the sidecar is absent" — the exact distinction the fix turns on.
struct FaultyGrantGet {
    inner: Arc<dyn Backend>,
    fail_grant_get: AtomicBool,
}

impl FaultyGrantGet {
    fn new(inner: Arc<dyn Backend>) -> Self {
        Self {
            inner,
            fail_grant_get: AtomicBool::new(false),
        }
    }
    fn arm(&self) {
        self.fail_grant_get.store(true, Ordering::SeqCst);
    }
    fn disarm(&self) {
        self.fail_grant_get.store(false, Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl Backend for FaultyGrantGet {
    fn name(&self) -> &'static str {
        "faulty-grant-get"
    }

    async fn put(
        &self,
        key: &ObjectKey,
        data: Bytes,
        expected: &ContentHash,
    ) -> dctl_store::Result<PutOutcome> {
        self.inner.put(key, data, expected).await
    }

    async fn get(&self, key: &ObjectKey) -> dctl_store::Result<Bytes> {
        if self.fail_grant_get.load(Ordering::SeqCst) && key.as_str().starts_with("g/") {
            return Err(StoreError::Backend(
                "injected transient 503 on grant-sidecar GET".into(),
            ));
        }
        self.inner.get(key).await
    }

    async fn get_range(&self, key: &ObjectKey, range: ByteRange) -> dctl_store::Result<Bytes> {
        self.inner.get_range(key, range).await
    }

    async fn head(&self, key: &ObjectKey) -> dctl_store::Result<ObjectMeta> {
        self.inner.head(key).await
    }

    async fn exists(&self, key: &ObjectKey) -> dctl_store::Result<bool> {
        self.inner.exists(key).await
    }

    async fn delete(&self, key: &ObjectKey) -> dctl_store::Result<()> {
        self.inner.delete(key).await
    }

    async fn list_page(&self, prefix: &str, cursor: Option<String>) -> dctl_store::Result<Page> {
        self.inner.list_page(prefix, cursor).await
    }
}

/// Raw bytes of the single §12.6 grant sidecar (`g/<hex>`) in a `LocalFs` store.
fn only_sidecar_bytes(store: &std::path::Path) -> Vec<u8> {
    let p = std::fs::read_dir(store.join("g"))
        .expect("grant sidecar dir exists")
        .next()
        .expect("a sidecar file exists")
        .unwrap()
        .path();
    std::fs::read(p).unwrap()
}

/// Build a vault whose backend is a [`FaultyGrantGet`] over a fresh `LocalFs`, returning
/// the vault, the fault handle (to `arm`/`disarm`), and the store + index temp dirs (the
/// temp dirs must outlive the vault, so the caller holds them).
async fn faulty_vault(pw: &str) -> (Vault, Arc<FaultyGrantGet>, TempDir, TempDir) {
    let store = TempDir::new().unwrap();
    let index = TempDir::new().unwrap();
    let inner: Arc<dyn Backend> = Arc::new(LocalFs::new(store.path()));
    let faulty = Arc::new(FaultyGrantGet::new(inner));
    let backend: Arc<dyn Backend> = faulty.clone();
    let vault = Vault::init(backend, &index.path().join("v.redb"), pw)
        .await
        .unwrap();
    (vault, faulty, store, index)
}

#[tokio::test]
async fn share_add_recipients_transient_get_error_aborts_without_wiping_sidecar() {
    // [Fix A / HIGH] A transient error reading the EXISTING sidecar must ABORT the share,
    // never be swallowed into a fresh (grants=[], grant_gen=0) rewrite that silently
    // revokes prior recipients and rolls grant_gen backward (§12.6 monotonicity).
    let (o, faulty, o_store, _o_idx) = faulty_vault("pw").await;

    let b_env = env();
    let b = Vault::init(b_env.backend.clone(), &b_env.index_path, "pwb")
        .await
        .unwrap();
    let c_env = env();
    let c = Vault::init(c_env.backend.clone(), &c_env.index_path, "pwc")
        .await
        .unwrap();

    // Owner-only object, then grant B (fault disarmed). This first add also proves the
    // genuine-absence path: the not-yet-existing sidecar GET returns NotFound and the add
    // starts fresh at grant_gen 1.
    o.put_file_shared("clip", b"payload never re-uploaded", &[])
        .await
        .unwrap();
    o.share_add_recipients("clip", &[b.identity().clone()])
        .await
        .unwrap();
    let before = only_sidecar_bytes(o_store.path());

    // Arm the transient fault and try to add C: the existing-sidecar GET now 5xx's.
    faulty.arm();
    let err = o
        .share_add_recipients("clip", &[c.identity().clone()])
        .await
        .unwrap_err();

    // The share ABORTS with a transient/Store error — NOT swallowed into a fresh rewrite.
    assert!(
        matches!(err, CoreError::Store(_)),
        "a transient sidecar GET must surface as a Store error, got {err:?}"
    );
    assert_eq!(
        err.kind(),
        ErrorKind::Transient,
        "a transient backend fault must classify as retryable"
    );

    // The pre-existing sidecar is byte-for-byte unchanged: no grant wipe, no grant_gen
    // rollback — the HIGH-severity data loss the fix prevents.
    faulty.disarm();
    let after = only_sidecar_bytes(o_store.path());
    assert_eq!(
        before, after,
        "a transient error must not overwrite/wipe the existing sidecar"
    );

    // Sanity: with the fault cleared the add succeeds and does extend the sidecar.
    o.share_add_recipients("clip", &[c.identity().clone()])
        .await
        .unwrap();
    assert_ne!(
        only_sidecar_bytes(o_store.path()),
        before,
        "the recovered add extends the sidecar"
    );
}

#[tokio::test]
async fn get_file_sidecar_only_recipient_transient_get_error_is_retryable_not_denial() {
    // [Fix B / LOW] A sidecar-only recipient hitting a transient error on the sidecar GET
    // must get a RETRYABLE (Transient) error, never a false permanent "not a recipient".
    let o_env = env();
    let o = Vault::init(o_env.backend.clone(), &o_env.index_path, "pw")
        .await
        .unwrap();

    // B lives on the fault-injecting backend.
    let (b, faulty, b_store, _b_idx) = faulty_vault("pwb").await;
    assert_ne!(o.identity_key_id(), b.identity_key_id());

    // O grants B purely via the sidecar (B is NOT an inline recipient).
    let data = b"sidecar-only recipient payload, never re-uploaded".repeat(8);
    o.put_file_shared("clip", &data, &[]).await.unwrap();
    o.share_add_recipients("clip", &[b.identity().clone()])
        .await
        .unwrap();

    // Repoint B's "clip" at O's shared object bytes and ship the sidecar to B's store.
    b.put_file("clip", b"placeholder").await.unwrap();
    let shared = only_object_bytes(o_env._store.path());
    std::fs::write(only_object_path(b_store.path()), &shared).unwrap();
    copy_sidecar(o_env._store.path(), b_store.path());

    // Baseline (fault disarmed): B is a legitimate sidecar recipient and reads the bytes.
    assert_eq!(
        b.get_file("clip").await.unwrap().as_slice(),
        data.as_slice()
    );

    // Arm the transient fault: the sidecar GET now 5xx's.
    faulty.arm();
    let err = b.get_file("clip").await.unwrap_err();
    assert!(
        matches!(err, CoreError::Store(_)),
        "a transient sidecar GET must surface as a Store error, got {err:?}"
    );
    assert_eq!(
        err.kind(),
        ErrorKind::Transient,
        "a 503 on the sidecar read is retryable, not an authorization denial"
    );
    // Explicitly NOT the permanent not-a-recipient error (a Crypto/Format ⇒ Permanent).
    assert_ne!(
        err.kind(),
        ErrorKind::Permanent,
        "a transient fault must never masquerade as a permanent non-recipient"
    );
}

#[tokio::test]
async fn genuine_absent_sidecar_stays_permanent_not_a_recipient_and_share_add_starts_fresh() {
    // The NotFound branch the fix deliberately PRESERVES: a genuinely absent sidecar is
    // still a permanent "not a recipient" (fail-closed) for get, and still lets share_add
    // start a fresh grant_gen=1 sidecar. No fault injection — real absence.
    let o_env = env();
    let o = Vault::init(o_env.backend.clone(), &o_env.index_path, "pw")
        .await
        .unwrap();
    let b_env = env();
    let b = Vault::init(b_env.backend.clone(), &b_env.index_path, "pwb")
        .await
        .unwrap();

    // Owner-only object; no sidecar exists yet anywhere.
    let data = b"owner only, no sidecar yet";
    o.put_file_shared("clip", data, &[]).await.unwrap();

    // Repoint B's "clip" at O's object but ship NO sidecar → B is genuinely not a recipient.
    b.put_file("clip", b"placeholder").await.unwrap();
    std::fs::write(
        only_object_path(b_env._store.path()),
        only_object_bytes(o_env._store.path()),
    )
    .unwrap();

    // get_file on a genuinely absent sidecar ⇒ PERMANENT non-recipient, not Transient.
    let err = b.get_file("clip").await.unwrap_err();
    assert_eq!(
        err.kind(),
        ErrorKind::Permanent,
        "a truly absent sidecar is a permanent non-recipient, got {err:?}"
    );
    assert!(
        !matches!(err, CoreError::Store(_)),
        "genuine absence must NOT surface as a Store error"
    );

    // share_add on a genuinely absent sidecar starts fresh and creates the sidecar.
    o.share_add_recipients("clip", &[b.identity().clone()])
        .await
        .unwrap();
    assert!(
        std::fs::read_dir(o_env._store.path().join("g"))
            .unwrap()
            .next()
            .is_some(),
        "share_add created a fresh sidecar from genuine absence"
    );
}

#[tokio::test]
async fn share_add_on_missing_or_non_recipient_errors() {
    let e = env();
    let owner = Vault::init(e.backend.clone(), &e.index_path, "pw")
        .await
        .unwrap();
    let r_env = env();
    let stranger = Vault::init(r_env.backend.clone(), &r_env.index_path, "pw2")
        .await
        .unwrap();

    // Sharing a path that does not exist → NotFound.
    assert!(matches!(
        owner
            .share_add_recipients("nope", &[stranger.identity().clone()])
            .await
            .unwrap_err(),
        CoreError::NotFound(_)
    ));

    // A non-recipient vault cannot add recipients to an object it cannot read.
    owner.put_file_shared("doc", b"secret", &[]).await.unwrap();
    let shared = only_object_bytes(e._store.path());
    stranger.put_file("doc", b"placeholder").await.unwrap();
    std::fs::write(only_object_path(r_env._store.path()), &shared).unwrap();
    assert!(
        stranger
            .share_add_recipients("doc", &[stranger.identity().clone()])
            .await
            .is_err(),
        "a vault that cannot recover KW cannot grant"
    );

    // A plain kem_id=0 object has no recipients to add — rejected.
    owner.put_file("plain", b"symmetric").await.unwrap();
    assert!(
        owner
            .share_add_recipients("plain", &[stranger.identity().clone()])
            .await
            .is_err(),
        "kem_id=0 objects carry no grants"
    );
}
