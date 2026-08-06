//! End-to-end vault tests over the local backend: init/unlock, verified put/get,
//! overwrite, list, delete, wrong-password, and tamper detection.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::Bytes;
use dctl_core::error::ErrorKind;
use dctl_core::{CoreError, Modified, UnlockKey, Vault};
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

/// Create a vault and keep only the vault.
///
/// `Vault::init` returns a [`dctl_core::NewVault`] carrying the recovery phrase
/// beside the vault, because a caller that never sees the phrase has created a
/// vault whose second key nobody knows. Nothing in *this* file is about
/// recovery — that is `tests/recovery.rs` — so the phrase is dropped here on
/// purpose, in one place, rather than at forty call sites.
async fn init_vault(
    backend: Arc<dyn Backend>,
    index_path: &std::path::Path,
    password: &str,
) -> dctl_core::Result<Vault> {
    Ok(Vault::init(backend, index_path, password).await?.vault)
}

#[tokio::test]
async fn init_unlock_put_get_roundtrip() {
    let e = env();
    {
        let vault = init_vault(e.backend.clone(), &e.index_path, "pw")
            .await
            .unwrap();
        vault
            .put_file("photos/a.jpg", b"hello verified world", Modified::Now)
            .await
            .unwrap();
    }
    let vault = Vault::unlock(e.backend.clone(), &e.index_path, UnlockKey::Password("pw"))
        .await
        .unwrap();
    let got = vault.get_file("photos/a.jpg").await.unwrap();
    assert_eq!(got.as_slice(), b"hello verified world");
}

#[tokio::test]
async fn wrong_password_fails_to_unlock() {
    let e = env();
    init_vault(e.backend.clone(), &e.index_path, "correct")
        .await
        .unwrap();
    let result = Vault::unlock(
        e.backend.clone(),
        &e.index_path,
        UnlockKey::Password("wrong"),
    )
    .await;
    assert!(matches!(result, Err(CoreError::Unlock)));
}

#[tokio::test]
async fn a_store_with_no_envelope_is_not_a_vault_rather_than_a_wrong_password() {
    // §16.2 at its root. A plain object store has no envelope by definition, and
    // every store failure — including "there is no such object" — used to be
    // mapped to `CoreError::Unlock`, whose whole message is about a secret:
    // "unlock failed: wrong password or corrupted envelope". The CLI then
    // advised restoring `system/envelope.bin` from a replica, for a location
    // where no such object has ever existed.
    let e = env();
    // Deliberately populated: a plain store with real objects in it, so the
    // answer cannot be excused as "the location is empty".
    e.backend
        .put(
            &ObjectKey::new("notes.txt"),
            Bytes::from_static(b"not sealed"),
            &ContentHash::blake3(b"not sealed"),
            dctl_store::SourceModified::unknown(),
        )
        .await
        .unwrap();

    let Err(error) =
        Vault::unlock(e.backend.clone(), &e.index_path, UnlockKey::Password("pw")).await
    else {
        panic!("there is no vault here to unlock");
    };

    match &error {
        CoreError::NoVault(key) => assert!(
            key.contains("envelope"),
            "the message must name what is missing: {key}"
        ),
        other => panic!("a store with no envelope was reported as: {other}"),
    }
    let rendered = error.to_string();
    assert!(
        !rendered.contains("password"),
        "no password was involved: {rendered}"
    );
    // And an app branching on the FFI signal must not re-prompt for a secret
    // that cannot help.
    assert_ne!(error.kind(), ErrorKind::Auth);
}

#[tokio::test]
async fn a_store_that_cannot_be_read_is_reported_as_that_rather_than_as_a_bad_password() {
    // The other half of the same defect, and the more insidious one: a
    // permission error, a dead connection or a wrong endpoint all reached the
    // operator as "wrong password or corrupted envelope" — so the first thing
    // they did about a network problem was retype a secret.
    struct Unreadable;

    #[async_trait::async_trait]
    impl Backend for Unreadable {
        fn name(&self) -> &'static str {
            "unreadable"
        }
        async fn store_identity(&self) -> Result<Option<dctl_store::StoreIdentity>, StoreError> {
            // A store nobody can read is still *there*: the guard's question is
            // whether the container moved, not whether the objects in it can be
            // fetched, and answering "gone" here would change what this test is
            // about.
            Ok(Some(dctl_store::StoreIdentity::existence_only()))
        }
        /// Nothing: a store nobody can read has nothing to report about what it
        /// recorded either.
        fn checksum_support(&self) -> dctl_store::ChecksumSupport {
            dctl_store::ChecksumSupport::None("this store cannot be read at all")
        }
        async fn stored_checksum(
            &self,
            _: &ObjectKey,
        ) -> Result<dctl_store::StoredChecksum, StoreError> {
            Err(StoreError::Backend("permission denied".into()))
        }
        async fn put(
            &self,
            _: &ObjectKey,
            _: Bytes,
            _: &ContentHash,
            _: dctl_store::SourceModified,
        ) -> Result<PutOutcome, StoreError> {
            unimplemented!()
        }
        async fn get(&self, _: &ObjectKey) -> Result<Bytes, StoreError> {
            Err(StoreError::Backend("403 forbidden".into()))
        }
        async fn get_range(&self, _: &ObjectKey, _: ByteRange) -> Result<Bytes, StoreError> {
            Err(StoreError::Backend("403 forbidden".into()))
        }
        async fn head(&self, _: &ObjectKey) -> Result<ObjectMeta, StoreError> {
            Err(StoreError::Backend("403 forbidden".into()))
        }
        async fn exists(&self, _: &ObjectKey) -> Result<bool, StoreError> {
            Err(StoreError::Backend("403 forbidden".into()))
        }
        async fn delete(&self, _: &ObjectKey) -> Result<(), StoreError> {
            unimplemented!()
        }
        async fn list_page(&self, _: &str, _: Option<String>) -> Result<Page, StoreError> {
            Err(StoreError::Backend("403 forbidden".into()))
        }

        async fn list_staging(
            &self,
            _: &str,
            _: Option<String>,
        ) -> Result<dctl_store::StagingListing, StoreError> {
            Err(StoreError::Backend("403 forbidden".into()))
        }

        async fn put_stream(
            &self,
            _: &ObjectKey,
            _: dctl_store::ObjectStream,
            _: dctl_store::SourceModified,
        ) -> Result<PutOutcome, StoreError> {
            unimplemented!()
        }

        async fn list_incomplete_uploads(
            &self,
            _: &str,
            _: Option<String>,
        ) -> Result<dctl_store::IncompleteUploads, StoreError> {
            Err(StoreError::Backend("403 forbidden".into()))
        }

        async fn abort_incomplete_upload(
            &self,
            _: &dctl_store::IncompleteUpload,
        ) -> Result<(), StoreError> {
            unimplemented!()
        }
    }

    let index = TempDir::new().unwrap();
    let backend: Arc<dyn Backend> = Arc::new(Unreadable);
    let Err(error) = Vault::unlock(
        backend,
        &index.path().join("vault.redb"),
        UnlockKey::Password("pw"),
    )
    .await
    else {
        panic!("a store that refuses to be read cannot yield a vault");
    };

    match &error {
        CoreError::Store(StoreError::Backend(detail)) => {
            assert!(detail.contains("403"), "the cause must survive: {detail}");
        }
        other => panic!("an unreadable store was reported as: {other}"),
    }
    assert!(
        !error.to_string().contains("password"),
        "{}",
        error.to_string()
    );
}

#[tokio::test]
async fn put_overwrites_same_path() {
    let e = env();
    let vault = init_vault(e.backend.clone(), &e.index_path, "pw")
        .await
        .unwrap();
    vault.put_file("k", b"first", Modified::Now).await.unwrap();
    vault.put_file("k", b"second", Modified::Now).await.unwrap();
    assert_eq!(vault.get_file("k").await.unwrap().as_slice(), b"second");
    assert_eq!(vault.list("").unwrap().len(), 1);
}

#[tokio::test]
async fn list_filters_by_prefix() {
    let e = env();
    let vault = init_vault(e.backend.clone(), &e.index_path, "pw")
        .await
        .unwrap();
    vault.put_file("a/1", b"x", Modified::Now).await.unwrap();
    vault.put_file("a/2", b"y", Modified::Now).await.unwrap();
    vault.put_file("b/1", b"z", Modified::Now).await.unwrap();

    let listed = vault.list("a/").unwrap();
    let paths: Vec<_> = listed.iter().map(|r| r.path.clone()).collect();
    assert_eq!(paths, vec!["a/1".to_string(), "a/2".to_string()]);
}

#[tokio::test]
async fn delete_removes_object_and_record() {
    let e = env();
    let vault = init_vault(e.backend.clone(), &e.index_path, "pw")
        .await
        .unwrap();
    vault
        .put_file("gone", b"data", Modified::Now)
        .await
        .unwrap();

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
        let a = init_vault(backend.clone(), &a_path, "pw").await.unwrap();
        a.put_file("photos/2026/a.jpg", b"alpha", Modified::Now)
            .await
            .unwrap();
        a.put_file("photos/2026/b.jpg", b"bravo", Modified::Now)
            .await
            .unwrap();
        a.put_file("docs/notes.txt", b"charlie", Modified::Now)
            .await
            .unwrap();
    }

    // Device B: SAME backend, a brand-new EMPTY index. Unlock with only the password.
    let b = Vault::unlock(backend.clone(), &b_path, UnlockKey::Password("pw"))
        .await
        .unwrap();

    // (1) A file is readable even before any rebuild — resolved via the backend's
    //     authoritative name record. This is the core cross-device guarantee.
    assert_eq!(
        b.get_file("photos/2026/a.jpg").await.unwrap().as_slice(),
        b"alpha"
    );

    // (2) Rebuild the whole index from the backend; then everything lists and reads.
    let rebuilt = b.rebuild_index().await.unwrap();
    assert_eq!(rebuilt.files, 3, "all three name records rebuilt");
    // And every one of them describable from its own object header: a rebuild
    // that mapped three paths and measured none of them used to pass this test.
    assert_eq!(
        rebuilt.measured, 3,
        "every row described from its object header"
    );
    assert_eq!(rebuilt.unmeasured, 0);
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
async fn a_rebuilt_row_carries_the_size_time_and_hash_the_object_was_sealed_with() {
    // The whole of what a rebuild recovers, compared field by field against the
    // row the original write produced. A rebuild used to write `size: 0`, no
    // time and an empty hash, which is an index `check` cannot compare, `size`
    // under-reports from and `sync` re-uploads the entire dataset against — and
    // nothing ever filled the fields in, so a recovered machine stayed that way.
    const WHEN: i64 = 1_551_675_967;

    let store = TempDir::new().unwrap();
    let backend: Arc<dyn Backend> = Arc::new(LocalFs::new(store.path()));
    let idx_a = TempDir::new().unwrap();
    let idx_b = TempDir::new().unwrap();
    let a_path = idx_a.path().join("a.redb");
    let b_path = idx_b.path().join("b.redb");

    let original = {
        let a = init_vault(backend.clone(), &a_path, "pw").await.unwrap();
        a.put_file("photos/a.jpg", b"alpha", Modified::At(WHEN))
            .await
            .unwrap();
        // Stored through the streaming path too, because it seals its metadata
        // in a different function and a fix applied to one of the two would
        // leave every large file undated.
        let source = idx_a.path().join("big.bin");
        std::fs::write(&source, b"bravo bravo").unwrap();
        a.put_file_from_path("docs/big.bin", &source, Modified::At(WHEN - 1))
            .await
            .unwrap();
        a.list("").unwrap()
    };

    let b = Vault::unlock(backend.clone(), &b_path, UnlockKey::Password("pw"))
        .await
        .unwrap();
    let rebuilt = b.rebuild_index().await.unwrap();
    assert_eq!(
        (rebuilt.files, rebuilt.measured, rebuilt.unmeasured),
        (2, 2, 0)
    );

    let recovered = b.list("").unwrap();
    assert_eq!(
        recovered, original,
        "a rebuilt row is the row that was written"
    );
    // Stated separately so a failure names the field rather than dumping two
    // structs: these three are exactly what was missing.
    for row in &recovered {
        assert_ne!(row.size, 0, "{} lost its size", row.path);
        assert!(!row.content_hash.is_empty(), "{} lost its hash", row.path);
    }
    assert_eq!(recovered[0].modified_unix, Some(WHEN - 1));
    assert_eq!(recovered[1].modified_unix, Some(WHEN));
}

#[tokio::test]
async fn a_file_stored_with_no_known_time_rebuilds_undated_rather_than_dated_1970() {
    // `Modified::Unknown` means nobody knows when the content changed, and the
    // object records that as the `0` sentinel. Reading the sentinel back as a
    // time would put `1970-01-01T00:00:00Z` on the file — a fabricated fact, and
    // the exact substitution `Modified::Unknown` exists to refuse, because the
    // epoch makes every such file look older than every other file.
    let store = TempDir::new().unwrap();
    let backend: Arc<dyn Backend> = Arc::new(LocalFs::new(store.path()));
    let idx_a = TempDir::new().unwrap();
    let idx_b = TempDir::new().unwrap();

    {
        let a = init_vault(backend.clone(), &idx_a.path().join("a.redb"), "pw")
            .await
            .unwrap();
        a.put_file("undated.bin", b"x", Modified::Unknown)
            .await
            .unwrap();
    }

    let b = Vault::unlock(
        backend.clone(),
        &idx_b.path().join("b.redb"),
        UnlockKey::Password("pw"),
    )
    .await
    .unwrap();
    // Still fully measured: the size and the hash are known, only the time is not.
    let rebuilt = b.rebuild_index().await.unwrap();
    assert_eq!(rebuilt.measured, 1);

    let row = b.list("").unwrap().pop().expect("the row is there");
    assert_eq!(row.size, 1);
    assert_eq!(
        row.modified_unix, None,
        "an unrecorded time must come back absent, never as the epoch"
    );
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
        let vault = init_vault(e.backend.clone(), &e.index_path, "pw")
            .await
            .unwrap();
        vault
            .put_file_from_path("videos/clip.bin", &src_path, Modified::Now)
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
    let vault = Vault::unlock(e.backend.clone(), &e.index_path, UnlockKey::Password("pw"))
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

    let vault = init_vault(e.backend.clone(), &e.index_path, "pw")
        .await
        .unwrap();
    vault
        .put_file_from_path("videos/clip.bin", &src_path, Modified::Now)
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
    let vault = Vault::unlock(e.backend.clone(), &e.index_path, UnlockKey::Password("pw"))
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
    let vault = init_vault(e.backend.clone(), &e.index_path, "pw")
        .await
        .unwrap();
    vault
        .put_file(
            "photos/a.jpg",
            b"the quick brown fox jumps over",
            Modified::Now,
        )
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
        let a = init_vault(backend.clone(), &idx_a.path().join("a.redb"), "pw")
            .await
            .unwrap();
        a.put_file_from_path("media/movie.bin", &src_path, Modified::Now)
            .await
            .unwrap();
    }

    let b = Vault::unlock(
        backend.clone(),
        &idx_b.path().join("b.redb"),
        UnlockKey::Password("pw"),
    )
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
    let vault = init_vault(e.backend.clone(), &e.index_path, "pw")
        .await
        .unwrap();

    // The same content stored both ways opens identically through get_file, i.e. the
    // streaming path produces an object the buffered reader decodes with no special case.
    let payload = pseudo_random(4096 + 7);
    let src = TempDir::new().unwrap();
    let src_path = src.path().join("s.bin");
    std::fs::write(&src_path, &payload).unwrap();

    vault
        .put_file("via/buffered", &payload, Modified::Now)
        .await
        .unwrap();
    vault
        .put_file_from_path("via/streamed", &src_path, Modified::Now)
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
    let vault = init_vault(e.backend.clone(), &e.index_path, "pw")
        .await
        .unwrap();
    let obj_dir = e._store.path().join("o");
    let count = |dir: &std::path::Path| std::fs::read_dir(dir).map(|d| d.count()).unwrap_or(0);

    vault.put_file("k", b"first", Modified::Now).await.unwrap();
    assert_eq!(count(&obj_dir), 1, "one object after first put");

    // Overwriting the same path must GC the previous ciphertext, not orphan it on the
    // untrusted backend (a private tool must not leave prior versions recoverable).
    vault
        .put_file("k", b"second and longer", Modified::Now)
        .await
        .unwrap();
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
        let a = init_vault(backend.clone(), &idx_a.path().join("a.redb"), "pw")
            .await
            .unwrap();
        a.put_file("secret.txt", b"classified", Modified::Now)
            .await
            .unwrap();
    }

    // Device B: fresh empty index. Delete resolves via the name record (no rebuild),
    // and must actually remove both the object and the name record from the backend.
    let b = Vault::unlock(
        backend.clone(),
        &idx_b.path().join("b.redb"),
        UnlockKey::Password("pw"),
    )
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
/// Deliver a shared object into `store` at the key it names itself by, and
/// return its `file_id`.
///
/// These fixtures used to mint a path on the recipient with a placeholder
/// `put_file` and then overwrite that placeholder's *bytes* with the owner's
/// object — putting object A's bytes at key B. That is precisely the
/// substitution an object's `file_id` now has to answer for: the fixture was
/// staging an attack in order to stage a share, and it only worked because the
/// invariant was missing.
///
/// A real recipient receives the object at its own `o/<hex file_id>` key and
/// reads it with `get_shared`, which is keyed by `file_id` rather than by a path
/// the recipient's index would have had to be told about. So does this.
fn deliver_shared_object(store: &std::path::Path, bytes: &[u8]) -> [u8; 16] {
    let mut file_id = [0u8; 16];
    file_id.copy_from_slice(&bytes[52..68]);
    let dir = store.join("o");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(hex::encode(file_id)), bytes).unwrap();
    file_id
}

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

/// The 16-byte `file_id` of the single stored content object, decoded from its
/// `o/<hex file_id>` backend key (the object filename under the `o/` prefix).
fn only_object_file_id(store: &std::path::Path) -> [u8; 16] {
    let p = only_object_path(store);
    let name = p.file_name().unwrap().to_str().unwrap();
    hex::decode(name).unwrap().try_into().unwrap()
}

#[tokio::test]
async fn shared_put_roundtrips_and_head_is_kem1() {
    let e = env();
    let owner = init_vault(e.backend.clone(), &e.index_path, "pw")
        .await
        .unwrap();

    // A separate vault (its own root → its own identity) supplies a recipient to share to.
    let r_env = env();
    let recipient = init_vault(r_env.backend.clone(), &r_env.index_path, "pw2")
        .await
        .unwrap();

    let data = b"hello asymmetric recipients";
    owner
        .put_file_shared(
            "shared/a",
            data,
            &[recipient.identity().clone()],
            Modified::Now,
        )
        .await
        .unwrap();

    // The owner reads it back through the ordinary get_file (kem_id=1 branch exercised).
    assert_eq!(owner.get_file("shared/a").await.unwrap().as_slice(), data);

    // The stored object's head declares kem_id=1
    // (crates/dctl-decode/FORMAT.md §3: head byte 6 = kem_id).
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
    let o = init_vault(o_env.backend.clone(), &o_env.index_path, "pw")
        .await
        .unwrap();
    let b_env = env();
    let b = init_vault(b_env.backend.clone(), &b_env.index_path, "pw")
        .await
        .unwrap();
    let c_env = env();
    let c = init_vault(c_env.backend.clone(), &c_env.index_path, "pw")
        .await
        .unwrap();

    // All three identities are distinct (independent random roots).
    assert_ne!(o.identity_key_id(), b.identity_key_id());
    assert_ne!(o.identity_key_id(), c.identity_key_id());
    assert_ne!(b.identity_key_id(), c.identity_key_id());

    let data = b"top secret shared payload";
    // Share to B only; C is deliberately excluded (O is auto-included per §12.8).
    o.put_file_shared("p", data, &[b.identity().clone()], Modified::Now)
        .await
        .unwrap();
    let shared = only_object_bytes(o_env._store.path());

    // Mint a resolvable "p" on B and C (placeholder put), then repoint it at the shared
    // object by overwriting the stored object bytes in place (the object KEY is unchanged).
    b.put_file("p", b"placeholder", Modified::Now)
        .await
        .unwrap();
    let b_shared = deliver_shared_object(b_env._store.path(), &shared);
    c.put_file("p", b"placeholder", Modified::Now)
        .await
        .unwrap();
    let c_shared = deliver_shared_object(c_env._store.path(), &shared);

    // B is a recipient → decrypts to the original plaintext.
    assert_eq!(b.get_shared(&b_shared).await.unwrap().as_slice(), data);
    // C is NOT a recipient → error (no kem_wrap sub-record for C's key_id).
    assert!(
        c.get_shared(&c_shared).await.is_err(),
        "a non-recipient vault must not be able to open the shared object"
    );
}

#[tokio::test]
async fn owner_auto_included_even_when_not_passed() {
    // §12.8 owner-inclusion MUST: a kem_id=1 object has no symmetric fallback, so the
    // owner is always added to the recipient set even when not passed in `recipients`.
    let e = env();
    let owner = init_vault(e.backend.clone(), &e.index_path, "pw")
        .await
        .unwrap();
    let r_env = env();
    let recipient = init_vault(r_env.backend.clone(), &r_env.index_path, "pw2")
        .await
        .unwrap();
    assert_ne!(owner.identity_key_id(), recipient.identity_key_id());

    // The recipient set does NOT contain the owner's identity...
    let data = b"write-only backup with no symmetric fallback";
    owner
        .put_file_shared(
            "backup/x",
            data,
            &[recipient.identity().clone()],
            Modified::Now,
        )
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
    let owner = init_vault(e.backend.clone(), &e.index_path, "pw")
        .await
        .unwrap();
    let r_env = env();
    let recipient = init_vault(r_env.backend.clone(), &r_env.index_path, "pw2")
        .await
        .unwrap();

    let data = pseudo_random(1024 * 1024 + 9_001);
    owner
        .put_file_shared(
            "media/clip.bin",
            &data,
            &[recipient.identity().clone()],
            Modified::Now,
        )
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
    let vault = init_vault(e.backend.clone(), &e.index_path, "pw")
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
    let vault = init_vault(e.backend.clone(), &e.index_path, "pw")
        .await
        .unwrap();
    vault
        .put_file("photos/a.jpg", b"the quick brown fox jumps", Modified::Now)
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
    let o = init_vault(o_env.backend.clone(), &o_env.index_path, "pw")
        .await
        .unwrap();
    let b_env = env();
    let b = init_vault(b_env.backend.clone(), &b_env.index_path, "pw2")
        .await
        .unwrap();
    assert_ne!(o.identity_key_id(), b.identity_key_id());

    let o_store = o_env._store.path();
    let b_store = b_env._store.path();

    // O uploads an object shared to OWNER-ONLY (B is not an inline recipient).
    let data = b"payload shared later via the grant sidecar, never re-uploaded".repeat(4);
    o.put_file_shared("clip", &data, &[], Modified::Now)
        .await
        .unwrap();
    // The owner always reads its own object (inline).
    assert_eq!(
        o.get_file("clip").await.unwrap().as_slice(),
        data.as_slice()
    );

    // Mint a resolvable "clip" on B, then repoint it at O's shared object bytes.
    b.put_file("clip", b"placeholder", Modified::Now)
        .await
        .unwrap();
    let shared = only_object_bytes(o_store);
    let b_shared = deliver_shared_object(b_store, &shared);

    // Before any grant: B is NOT a recipient (no inline sub-record, no sidecar) → errors.
    assert!(
        b.get_shared(&b_shared).await.is_err(),
        "B cannot read before being granted"
    );

    // O adds B via the sidecar (no object re-upload); ship the sidecar to B's store.
    o.share_add_recipients("clip", &[b.identity().clone()])
        .await
        .unwrap();
    copy_sidecar(o_store, b_store);

    // B now reads the EXACT bytes via the sidecar grant — buffered and streamed-to-path.
    assert_eq!(
        b.get_shared(&b_shared).await.unwrap().as_slice(),
        data.as_slice()
    );
    let out = TempDir::new().unwrap();
    let dest = out.path().join("nested/clip.out");
    b.get_shared_to_path(&b_shared, &dest).await.unwrap();
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
        b.get_shared(&b_shared).await.is_err(),
        "sidecar bound to the wrong file_id is rejected"
    );
    copy_sidecar(o_store, b_store); // restore
    let mut sc = std::fs::read(&sc_path).unwrap();
    sc[24] ^= 0xFF;
    std::fs::write(&sc_path, &sc).unwrap();
    assert!(
        b.get_shared(&b_shared).await.is_err(),
        "sidecar with a wrong head_hash is rejected"
    );
    copy_sidecar(o_store, b_store); // restore
    assert_eq!(
        b.get_shared(&b_shared).await.unwrap().as_slice(),
        data.as_slice(),
        "the intact sidecar still grants B"
    );

    // O revokes B; ship the rewritten (empty) sidecar. B fails again.
    o.share_remove_recipient("clip", &b.identity_key_id())
        .await
        .unwrap();
    copy_sidecar(o_store, b_store);
    assert!(
        b.get_shared(&b_shared).await.is_err(),
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
/// class B2/S3 map every non-404 to — 5xx, timeout, throttling) on selected operations
/// while the matching toggle is armed, delegating every other call unchanged. It never
/// fabricates a `NotFound`, so each fault models "the read/write failed transiently",
/// never "the object is absent" — the exact distinction the fixes turn on. The three
/// toggles are independent:
/// - `fail_grant_get`: fault `get` of any grant sidecar (`g/…`).
/// - `fail_imported_get`: fault `get` of any §13 imported-key object (`k/…`) — the per-entry
///   DIK1 read `load_imported_identities` does on unlock.
/// - `fail_discovery_put`: fault `put` of any §14 discovery record (`d/…`) — the DGD1 write
///   `share_add_recipients` does AFTER the grant-sidecar (`g/…`) put has already succeeded.
struct FaultyGrantGet {
    inner: Arc<dyn Backend>,
    fail_grant_get: AtomicBool,
    fail_imported_get: AtomicBool,
    fail_discovery_put: AtomicBool,
}

impl FaultyGrantGet {
    fn new(inner: Arc<dyn Backend>) -> Self {
        Self {
            inner,
            fail_grant_get: AtomicBool::new(false),
            fail_imported_get: AtomicBool::new(false),
            fail_discovery_put: AtomicBool::new(false),
        }
    }
    fn arm(&self) {
        self.fail_grant_get.store(true, Ordering::SeqCst);
    }
    fn disarm(&self) {
        self.fail_grant_get.store(false, Ordering::SeqCst);
    }
    /// Arm a TRANSIENT fault on `get` of any §13 imported-key object (`k/…`), modeling a
    /// 5xx/timeout on the per-entry DIK1 read — never a fabricated NotFound.
    fn arm_imported(&self) {
        self.fail_imported_get.store(true, Ordering::SeqCst);
    }
    fn disarm_imported(&self) {
        self.fail_imported_get.store(false, Ordering::SeqCst);
    }
    /// Arm a TRANSIENT fault on `put` of any §14 discovery record (`d/…`), modeling a
    /// mid-DGD1-phase 5xx that strikes only AFTER the grant sidecar (`g/…`) put succeeded.
    fn arm_discovery_put(&self) {
        self.fail_discovery_put.store(true, Ordering::SeqCst);
    }
    fn disarm_discovery_put(&self) {
        self.fail_discovery_put.store(false, Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl Backend for FaultyGrantGet {
    fn name(&self) -> &'static str {
        "faulty-grant-get"
    }

    async fn store_identity(&self) -> dctl_store::Result<Option<dctl_store::StoreIdentity>> {
        self.inner.store_identity().await
    }

    /// Forwarded: this double changes what is *served*, not what the store
    /// behind it recorded.
    fn checksum_support(&self) -> dctl_store::ChecksumSupport {
        self.inner.checksum_support()
    }

    async fn stored_checksum(
        &self,
        key: &ObjectKey,
    ) -> dctl_store::Result<dctl_store::StoredChecksum> {
        self.inner.stored_checksum(key).await
    }

    async fn put(
        &self,
        key: &ObjectKey,
        data: Bytes,
        expected: &ContentHash,
        modified: dctl_store::SourceModified,
    ) -> dctl_store::Result<PutOutcome> {
        if self.fail_discovery_put.load(Ordering::SeqCst) && key.as_str().starts_with("d/") {
            return Err(StoreError::Backend(
                "injected transient 503 on discovery-record PUT".into(),
            ));
        }
        self.inner.put(key, data, expected, modified).await
    }

    async fn get(&self, key: &ObjectKey) -> dctl_store::Result<Bytes> {
        if self.fail_grant_get.load(Ordering::SeqCst) && key.as_str().starts_with("g/") {
            return Err(StoreError::Backend(
                "injected transient 503 on grant-sidecar GET".into(),
            ));
        }
        if self.fail_imported_get.load(Ordering::SeqCst) && key.as_str().starts_with("k/") {
            return Err(StoreError::Backend(
                "injected transient 503 on imported-key GET".into(),
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

    async fn list_staging(
        &self,
        prefix: &str,
        cursor: Option<String>,
    ) -> dctl_store::Result<dctl_store::StagingListing> {
        self.inner.list_staging(prefix, cursor).await
    }

    async fn put_stream(
        &self,
        key: &ObjectKey,
        source: dctl_store::ObjectStream,
        modified: dctl_store::SourceModified,
    ) -> dctl_store::Result<PutOutcome> {
        self.inner.put_stream(key, source, modified).await
    }

    async fn list_incomplete_uploads(
        &self,
        prefix: &str,
        cursor: Option<String>,
    ) -> dctl_store::Result<dctl_store::IncompleteUploads> {
        self.inner.list_incomplete_uploads(prefix, cursor).await
    }

    async fn abort_incomplete_upload(
        &self,
        upload: &dctl_store::IncompleteUpload,
    ) -> dctl_store::Result<()> {
        self.inner.abort_incomplete_upload(upload).await
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
    let vault = init_vault(backend, &index.path().join("v.redb"), pw)
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
    let b = init_vault(b_env.backend.clone(), &b_env.index_path, "pwb")
        .await
        .unwrap();
    let c_env = env();
    let c = init_vault(c_env.backend.clone(), &c_env.index_path, "pwc")
        .await
        .unwrap();

    // Owner-only object, then grant B (fault disarmed). This first add also proves the
    // genuine-absence path: the not-yet-existing sidecar GET returns NotFound and the add
    // starts fresh at grant_gen 1.
    o.put_file_shared("clip", b"payload never re-uploaded", &[], Modified::Now)
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
    let o = init_vault(o_env.backend.clone(), &o_env.index_path, "pw")
        .await
        .unwrap();

    // B lives on the fault-injecting backend.
    let (b, faulty, b_store, _b_idx) = faulty_vault("pwb").await;
    assert_ne!(o.identity_key_id(), b.identity_key_id());

    // O grants B purely via the sidecar (B is NOT an inline recipient).
    let data = b"sidecar-only recipient payload, never re-uploaded".repeat(8);
    o.put_file_shared("clip", &data, &[], Modified::Now)
        .await
        .unwrap();
    o.share_add_recipients("clip", &[b.identity().clone()])
        .await
        .unwrap();

    // Repoint B's "clip" at O's shared object bytes and ship the sidecar to B's store.
    b.put_file("clip", b"placeholder", Modified::Now)
        .await
        .unwrap();
    let shared = only_object_bytes(o_env._store.path());
    let b_shared = deliver_shared_object(b_store.path(), &shared);
    copy_sidecar(o_env._store.path(), b_store.path());

    // Baseline (fault disarmed): B is a legitimate sidecar recipient and reads the bytes.
    assert_eq!(
        b.get_shared(&b_shared).await.unwrap().as_slice(),
        data.as_slice()
    );

    // Arm the transient fault: the sidecar GET now 5xx's.
    faulty.arm();
    let err = b.get_shared(&b_shared).await.unwrap_err();
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
    let o = init_vault(o_env.backend.clone(), &o_env.index_path, "pw")
        .await
        .unwrap();
    let b_env = env();
    let b = init_vault(b_env.backend.clone(), &b_env.index_path, "pwb")
        .await
        .unwrap();

    // Owner-only object; no sidecar exists yet anywhere.
    let data = b"owner only, no sidecar yet";
    o.put_file_shared("clip", data, &[], Modified::Now)
        .await
        .unwrap();

    // Repoint B's "clip" at O's object but ship NO sidecar → B is genuinely not a recipient.
    b.put_file("clip", b"placeholder", Modified::Now)
        .await
        .unwrap();
    let b_shared =
        deliver_shared_object(b_env._store.path(), &only_object_bytes(o_env._store.path()));

    // get_file on a genuinely absent sidecar ⇒ PERMANENT non-recipient, not Transient.
    let err = b.get_shared(&b_shared).await.unwrap_err();
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
    let owner = init_vault(e.backend.clone(), &e.index_path, "pw")
        .await
        .unwrap();
    let r_env = env();
    let stranger = init_vault(r_env.backend.clone(), &r_env.index_path, "pw2")
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
    owner
        .put_file_shared("doc", b"secret", &[], Modified::Now)
        .await
        .unwrap();
    let shared = only_object_bytes(e._store.path());
    stranger
        .put_file("doc", b"placeholder", Modified::Now)
        .await
        .unwrap();
    let _r_shared = deliver_shared_object(r_env._store.path(), &shared);
    assert!(
        stranger
            .share_add_recipients("doc", &[stranger.identity().clone()])
            .await
            .is_err(),
        "a vault that cannot recover KW cannot grant"
    );

    // A plain kem_id=0 object has no recipients to add — rejected.
    owner
        .put_file("plain", b"symmetric", Modified::Now)
        .await
        .unwrap();
    assert!(
        owner
            .share_add_recipients("plain", &[stranger.identity().clone()])
            .await
            .is_err(),
        "kem_id=0 objects carry no grants"
    );
}

// ── §13 imported-key store + §14 shared-object discovery (end-to-end, LocalFs) ──

#[tokio::test]
async fn import_keypair_round_trips_across_reunlock() {
    // A fresh vault holds only its root-derived identity; an imported keypair persists in the
    // `k/*` store and reloads into the identity set on the next unlock (multi-identity).
    let store = TempDir::new().unwrap();
    let backend: Arc<dyn Backend> = Arc::new(LocalFs::new(store.path()));
    let idx1 = TempDir::new().unwrap();
    let p1 = idx1.path().join("a.redb");

    let key_id = {
        let o = init_vault(backend.clone(), &p1, "pw").await.unwrap();
        assert_eq!(
            o.identity_key_ids().len(),
            1,
            "fresh vault: root identity only"
        );
        let kid = o.import_keypair().await.unwrap();
        // import_keypair(&self) writes k/*; the in-memory set refreshes on the next unlock.
        assert_eq!(o.identity_key_ids().len(), 1);
        kid
    };

    // Re-unlock with a FRESH index: the k/* store is listed + reloaded.
    let idx2 = TempDir::new().unwrap();
    let p2 = idx2.path().join("b.redb");
    let o2 = Vault::unlock(backend.clone(), &p2, UnlockKey::Password("pw"))
        .await
        .unwrap();
    let ids = o2.identity_key_ids();
    assert_eq!(ids.len(), 2, "root + imported after reload");
    assert!(
        ids.contains(&key_id),
        "the imported identity reloaded on unlock"
    );
}

#[tokio::test]
async fn imported_identity_discovers_reads_and_revokes_shared_object() {
    use dctl_crypto::kem;

    // One shared backend; owner O is the only vault (a second vault can't share the fixed
    // envelope key). An IMPORTED external identity `ext` plays recipient "B": O seals to
    // ext's public key AND imports ext's private key, so after a re-unlock reloads the k/*
    // store, O-as-ext discovers and reads the shared object via the multi-identity path.
    let store = TempDir::new().unwrap();
    let backend: Arc<dyn Backend> = Arc::new(LocalFs::new(store.path()));
    let idx1 = TempDir::new().unwrap();
    let p1 = idx1.path().join("v1.redb");

    let ext = kem::generate_external();
    let ext_key_id = ext.key_id;

    let data = pseudo_random(200_003);
    {
        let o = init_vault(backend.clone(), &p1, "pw").await.unwrap();
        // Import ext's private material (from-material variant), then share the object to
        // ext via the grant sidecar (owner-only object first → sidecar grant writes a DGD1).
        let returned = o.import_keypair_material(&ext).await.unwrap();
        assert_eq!(returned, ext_key_id);

        o.put_file_shared("docs/report.txt", &data, &[], Modified::Now)
            .await
            .unwrap();
        o.share_add_recipients("docs/report.txt", std::slice::from_ref(&ext.public))
            .await
            .unwrap();
    }

    // Re-unlock with a FRESH index → forces reload of k/* and name-record resolution.
    let idx2 = TempDir::new().unwrap();
    let p2 = idx2.path().join("v2.redb");
    let o2 = Vault::unlock(backend.clone(), &p2, UnlockKey::Password("pw"))
        .await
        .unwrap();
    assert!(
        o2.identity_key_ids().contains(&ext_key_id),
        "imported identity must reload after restart"
    );

    // discover_shared enumerates the object under ext's key_id with the correct path/size.
    let discovered = o2.discover_shared().await.unwrap();
    let found = discovered
        .iter()
        .find(|s| s.path == "docs/report.txt")
        .expect("ext discovers the shared object");
    assert_eq!(found.size, data.len() as u64, "discovered size matches");

    // get_shared returns the EXACT bytes (fetch o/<file_id> + multi-identity open).
    let got = o2.get_shared(&found.file_id).await.unwrap();
    assert_eq!(
        got.as_slice(),
        data.as_slice(),
        "get_shared returns exact bytes"
    );

    // get_shared_to_path materializes the same bytes atomically.
    let out_dir = TempDir::new().unwrap();
    let dest = out_dir.path().join("out.bin");
    o2.get_shared_to_path(&found.file_id, &dest).await.unwrap();
    assert_eq!(std::fs::read(&dest).unwrap(), data);

    // Revoke ext: removes the sidecar grant AND deletes the DGD1 discovery record.
    o2.share_remove_recipient("docs/report.txt", &ext_key_id)
        .await
        .unwrap();
    let after = o2.discover_shared().await.unwrap();
    assert!(
        !after.iter().any(|s| s.path == "docs/report.txt"),
        "after revoke, ext no longer discovers the object"
    );
}

#[tokio::test]
async fn unlock_transient_imported_key_get_error_fails_not_silently_drops_identity() {
    // [Fix / HIGH] `load_imported_identities` must PROPAGATE a transient error on the per-entry
    // GET of a `k/<key_id>` DIK1 — never swallow it as "skip". Swallowing would silently drop a
    // legitimate imported identity so the identity set shrinks on a network blip, and a later
    // open of a genuinely-owned object would return a false, PERMANENT "not a recipient". Only
    // `StoreError::NotFound` (a TOCTOU delete between LIST and GET) is a valid skip.
    //
    // Fails against the old `Err(e) => { warn; continue }` code: there, the armed unlock would
    // SUCCEED with the imported identity silently missing, so `unwrap_err()` below would panic.
    let (o, faulty, _store, idx) = faulty_vault("pw").await;
    let idx_path = idx.path().join("v.redb");

    // Import an external keypair → a `k/<kid>` DIK1 now exists on the backend.
    let kid = o.import_keypair().await.unwrap();
    drop(o); // release the local index so the SAME backend + index can be re-unlocked

    // Re-unlock with the transient `k/*` GET fault ARMED: unlock MUST fail — not succeed with
    // the imported identity silently dropped.
    faulty.arm_imported();
    let backend: Arc<dyn Backend> = faulty.clone();
    let err = match Vault::unlock(backend, &idx_path, UnlockKey::Password("pw")).await {
        Ok(_) => panic!("armed transient k/* GET must fail unlock, not drop the identity"),
        Err(e) => e,
    };
    assert!(
        matches!(err, CoreError::Store(_)),
        "a transient k/* GET must surface as a Store error, got {err:?}"
    );
    assert_eq!(
        err.kind(),
        ErrorKind::Transient,
        "a transient backend fault on the DIK1 read must classify as retryable"
    );

    // Disarm and re-unlock: it now succeeds AND the imported identity is restored — proving the
    // identity was genuinely present all along (the armed unlock did not drop it, it aborted).
    faulty.disarm_imported();
    let backend: Arc<dyn Backend> = faulty.clone();
    let o2 = Vault::unlock(backend, &idx_path, UnlockKey::Password("pw"))
        .await
        .unwrap();
    assert!(
        o2.identity_key_ids().contains(&kid),
        "after the fault clears, the imported identity reloads into the set"
    );
}

#[tokio::test]
async fn share_add_self_heals_missing_discovery_record_on_retry() {
    use dctl_crypto::kem;

    // [Fix / MEDIUM] `share_add_recipients` must write the §14 `d/<kid>/<file_id>` DGD1 for
    // EVERY requested (non-owner) recipient (idempotent verified-write) and must NOT early-return
    // when nothing NEW is granted — so a retry after a mid-DGD1-phase transient failure SELF-HEALS
    // the missing discovery record. An imported identity `ext` stands in for recipient "B" on the
    // single faulty backend (so `discover_shared` on this vault enumerates as B), exactly like
    // `imported_identity_discovers_reads_and_revokes_shared_object`.
    //
    // Fails against the old code: on the retry `ext` is already in the sidecar (added=0), the old
    // path early-returned on empty `newly_added`, so the DGD1 was never (re)written and the final
    // `discover_shared` would not list the object.
    let (o, faulty, store, idx) = faulty_vault("pw").await;
    let idx_path = idx.path().join("v.redb");

    let ext = kem::generate_external();
    let ext_kid = ext.key_id;
    assert_eq!(o.import_keypair_material(&ext).await.unwrap(), ext_kid);

    // Owner-only object: no inline recipients → no sidecar and no DGD1 exist yet.
    let data = b"payload shared to B via the grant sidecar, never re-uploaded";
    o.put_file_shared("clip", data, &[], Modified::Now)
        .await
        .unwrap();
    drop(o); // release the index; re-unlock loads `ext` into the in-memory identity set

    // Re-unlock so the vault holds `ext` (root + imported) and can discover as B.
    let backend: Arc<dyn Backend> = faulty.clone();
    let o2 = Vault::unlock(backend, &idx_path, UnlockKey::Password("pw"))
        .await
        .unwrap();
    assert!(o2.identity_key_ids().contains(&ext_kid));

    // Arm the DGD1 (`d/*`) PUT fault and grant `ext`: the grant sidecar (`g/*`) PUT succeeds but
    // the discovery-record (`d/*`) PUT fails → `share_add_recipients` returns a transient Store
    // error with the grant persisted but the discovery record missing.
    faulty.arm_discovery_put();
    let err = o2
        .share_add_recipients("clip", std::slice::from_ref(&ext.public))
        .await
        .unwrap_err();
    assert!(
        matches!(err, CoreError::Store(_)),
        "the failed DGD1 PUT must surface as a Store error, got {err:?}"
    );
    assert_eq!(err.kind(), ErrorKind::Transient);

    // Grant PRESENT, discovery ABSENT. The sidecar was written (a `g/*` object exists), yet the
    // object is NOT yet discoverable by `ext`.
    assert!(
        !only_sidecar_bytes(store.path()).is_empty(),
        "the grant sidecar was written before the DGD1 PUT failed"
    );
    let before = o2.discover_shared().await.unwrap();
    assert!(
        !before.iter().any(|s| s.path == "clip"),
        "the discovery record was never written — ext does not discover the object yet"
    );
    // Grant-present cross-check: the object is readable by `file_id` despite the missing DGD1.
    let file_id = only_object_file_id(store.path());
    assert_eq!(
        o2.get_shared(&file_id).await.unwrap().as_slice(),
        data,
        "grant present ⇒ the object reads via file_id even with no discovery record"
    );

    // Retry the SAME add with the fault cleared. Nothing NEW is granted (`ext` is already in the
    // sidecar → added=0), which is exactly the condition the old early-return skipped. The fixed
    // code still (idempotently) writes the DGD1, so the discovery record self-heals.
    faulty.disarm_discovery_put();
    o2.share_add_recipients("clip", std::slice::from_ref(&ext.public))
        .await
        .unwrap();
    let after = o2.discover_shared().await.unwrap();
    let found = after
        .iter()
        .find(|s| s.path == "clip")
        .expect("after the retry, ext discovers the self-healed object");
    assert_eq!(found.size, data.len() as u64, "discovered size matches");
    assert_eq!(
        found.file_id, file_id,
        "discovery points at the same object"
    );
}

// ── the index records when the source changed, not when the vault was written ──

/// A day, in seconds. Far enough outside any comparison's tolerance that a
/// record stamped with the write time cannot be mistaken for one stamped with
/// the source's.
const A_DAY: i64 = 86_400;

/// A source file whose modification time is `A_DAY` in the past.
///
/// Backdating is the whole fixture. A file written and stored inside the same
/// second produces a write time and a source time that agree by accident, so a
/// vault that records the wrong one still looks correct — which is precisely how
/// this went unnoticed.
fn aged_source(dir: &std::path::Path, name: &str, bytes: &[u8]) -> (std::path::PathBuf, i64) {
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    let when = std::time::SystemTime::now() - std::time::Duration::from_secs(A_DAY as u64);
    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(when)
        .unwrap();
    let seconds = when
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    (path, seconds)
}

/// The record the index holds for exactly `path`.
fn record(vault: &Vault, path: &str) -> dctl_index::Record {
    vault
        .list(path)
        .unwrap()
        .into_iter()
        .find(|record| record.path == path)
        .expect("the vault holds the path it was just given")
}

#[tokio::test]
async fn a_streamed_put_records_the_sources_modification_time() {
    // The defect, at the layer that caused it. `put_file_from_path` stamped
    // `now_unix()`, which is a true statement about the *write* and says nothing
    // about the file it was made from — so a vault destination could never match
    // its source by time, and every incremental `copy` re-sent the whole dataset.
    let e = env();
    let src = TempDir::new().unwrap();
    let (source, modified) = aged_source(src.path(), "clip.bin", b"streamed payload");

    let vault = init_vault(e.backend.clone(), &e.index_path, "pw")
        .await
        .unwrap();
    let metadata = std::fs::metadata(&source).unwrap();
    vault
        .put_file_from_path("videos/clip.bin", &source, Modified::of(&metadata))
        .await
        .unwrap();

    assert_eq!(
        record(&vault, "videos/clip.bin").modified_unix,
        Some(modified),
        "the index must carry the source's time, not the moment of the write"
    );
}

#[tokio::test]
async fn a_buffered_put_records_the_time_it_was_handed() {
    // The buffered path had the identical defect and needs its own proof: the two
    // write paths build their `Record` independently, so a fix applied to one and
    // forgotten in the other would leave `dctl copy` (buffered) broken while
    // `dctl backup` (streamed) worked, which is the hardest kind of half-fix to
    // notice.
    let e = env();
    let vault = init_vault(e.backend.clone(), &e.index_path, "pw")
        .await
        .unwrap();

    vault
        .put_file("notes.txt", b"content", Modified::At(1_500_000_000))
        .await
        .unwrap();
    assert_eq!(
        record(&vault, "notes.txt").modified_unix,
        Some(1_500_000_000)
    );

    // …and an overwrite re-states it rather than inheriting the first write's,
    // which is what makes a re-copied file compare equal on the run after it.
    vault
        .put_file("notes.txt", b"edited!", Modified::At(1_600_000_000))
        .await
        .unwrap();
    assert_eq!(
        record(&vault, "notes.txt").modified_unix,
        Some(1_600_000_000)
    );
}

#[tokio::test]
async fn a_stream_with_no_source_time_records_the_clock_and_never_the_spools() {
    // `dctl rcat` spools standard input to a temporary file and stores *that*.
    // The temp file's own modification time is the moment of the spool and looks
    // exactly like a real answer, so the streaming path must take the caller's
    // word — `Modified::Now` — rather than reading the file it was handed.
    //
    // Proven by handing it a source backdated a day: a record carrying that day
    // would mean the file's time had been read after all.
    let e = env();
    let src = TempDir::new().unwrap();
    let (spool, aged) = aged_source(src.path(), "spool.tmp", b"piped bytes");

    let vault = init_vault(e.backend.clone(), &e.index_path, "pw")
        .await
        .unwrap();
    vault
        .put_file_from_path("dump.bin", &spool, Modified::Now)
        .await
        .unwrap();

    let recorded = record(&vault, "dump.bin")
        .modified_unix
        .expect("the clock is available");
    assert!(
        recorded > aged,
        "the spool's own time ({aged}) must not become the record's ({recorded})"
    );
}

#[tokio::test]
async fn a_source_with_no_readable_time_is_recorded_as_absent() {
    // The third claim, and the one with teeth. An unknown time must reach the
    // index as *nothing*: a comparison reads absence as "these were never
    // comparable" and transfers the file, while a fabricated `now` would read as
    // a real answer and could match a source it had never been compared with.
    let e = env();
    let vault = init_vault(e.backend.clone(), &e.index_path, "pw")
        .await
        .unwrap();

    vault
        .put_file("mystery.bin", b"x", Modified::Unknown)
        .await
        .unwrap();
    assert_eq!(record(&vault, "mystery.bin").modified_unix, None);
}

#[tokio::test]
async fn a_shared_object_records_its_source_time_like_any_other() {
    // The §12 write path builds its own `Record`, so it gets its own assertion.
    // A share is still a stored copy of something with an age.
    let e = env();
    let vault = init_vault(e.backend.clone(), &e.index_path, "pw")
        .await
        .unwrap();

    vault
        .put_file_shared("shared/report.txt", b"payload", &[], Modified::At(1_234))
        .await
        .unwrap();
    assert_eq!(
        record(&vault, "shared/report.txt").modified_unix,
        Some(1_234)
    );
}

#[tokio::test]
async fn a_file_is_sealed_from_a_reader_that_was_never_a_file_on_disk() {
    // The primitive a read-write mount is built on. A file written through a
    // mount arrives as arbitrary writes at arbitrary offsets and cannot be
    // sealed until it is closed, so it must be spilled somewhere first — and
    // that spill has to be encrypted, or a mounted vault leaves plaintext on
    // disk for as long as a file is open. Sealing therefore has to accept a
    // reader over that spill rather than a path to plaintext.
    //
    // `Cursor` stands in for the decrypting view here: it is seekable, it is not
    // a file, and nothing about it touches the filesystem.
    let e = env();
    let vault = init_vault(e.backend.clone(), &e.index_path, "pw")
        .await
        .expect("a vault");

    // Larger than one chunk, so the two-pass layout (prepare hashes and plans,
    // emit seals) is genuinely exercised rather than fitting in a single frame.
    let plaintext: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let reader = std::io::Cursor::new(plaintext.clone());

    vault
        .put_file_from_source(
            "from/memory.bin",
            reader,
            plaintext.len() as u64,
            Modified::At(1_700_000_000),
        )
        .await
        .expect("a reader is a valid source");

    // It reads back byte-identical, which is the only claim that matters.
    let restored = vault
        .get_file("from/memory.bin")
        .await
        .expect("the file is there");
    assert_eq!(
        restored.as_slice(),
        plaintext.as_slice(),
        "what was sealed from a reader must come back exactly"
    );

    // And it is a first-class vault entry: indexed, sized, and listed like any
    // other, not a special case that happens to decrypt.
    let listed = vault.list("from/").expect("a listing");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].path, "from/memory.bin");
    assert_eq!(listed[0].size, plaintext.len() as u64);
    assert_eq!(listed[0].modified_unix, Some(1_700_000_000));
}

#[tokio::test]
async fn a_substituted_object_is_refused_rather_than_returned_as_the_file_asked_for() {
    // The defect this project exists to make impossible, found by audit and
    // reproduced here before it was fixed.
    //
    // Every integrity check on the read path is INTERNAL to whatever object is
    // present: the chunk tags verify, `meta.size` matches the plaintext, and the
    // content hash is compared against that object's OWN metadata. Together they
    // prove "this is a valid object". None proves "this is the object you asked
    // for".
    //
    // So a backend with write access — the adversary the security model says is
    // handled — copies one object over another's key. Every check passed and
    // `get_file` returned the attacker's plaintext reporting success. Measured:
    // reading `wages.csv` returned "ATTACKER CONTROLLED CONTENT" and exit 0.
    let e = env();
    let vault = init_vault(e.backend.clone(), &e.index_path, "pw")
        .await
        .expect("a vault");

    vault
        .put_file("wages.csv", b"the file the caller asked for", Modified::Now)
        .await
        .expect("stored");
    vault
        .put_file("decoy.txt", b"ATTACKER CONTROLLED CONTENT", Modified::Now)
        .await
        .expect("stored");

    let wages_key = vault
        .object_key_of("wages.csv")
        .await
        .expect("resolvable")
        .expect("present");
    let decoy_key = vault
        .object_key_of("decoy.txt")
        .await
        .expect("resolvable")
        .expect("present");

    let decoy_bytes = e
        .backend
        .get(&dctl_store::ObjectKey::new(decoy_key))
        .await
        .expect("readable");
    let expected = dctl_store::ContentHash::blake3(&decoy_bytes);
    e.backend
        .put(
            &dctl_store::ObjectKey::new(wages_key),
            decoy_bytes,
            &expected,
            dctl_store::SourceModified::unknown(),
        )
        .await
        .expect("the attacker can write to the bucket");

    // Returning the decoy's plaintext — or any plaintext — would be the tool
    // reporting success for something it did not do.
    match vault.get_file("wages.csv").await {
        Err(_) => {}
        Ok(bytes) => panic!(
            "object substitution went undetected: reading 'wages.csv' returned {:?}",
            String::from_utf8_lossy(bytes.as_slice())
        ),
    }
}
