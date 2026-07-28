//! Integration tests for the `LocalFs` backend — the verified-write contract,
//! range reads, listing/pagination, idempotent delete, and key-safety.

use bytes::Bytes;
use dctl_store::{Backend, ByteRange, ContentHash, LocalFs, ObjectKey, SourceModified, StoreError};
use tempfile::TempDir;

fn blake3(data: &[u8]) -> ContentHash {
    ContentHash::blake3(data)
}

/// A time far from any clock this test could be run against, so a backend that
/// stamped "now" instead of storing what it was given cannot pass by accident.
/// 2020-01-01T00:00:00Z.
const AGED: i64 = 1_577_836_800;

#[tokio::test]
async fn a_written_modification_time_comes_back_from_head_and_from_a_listing() {
    // The property `sync` is incremental because of. A `put` that accepted the
    // time and dropped it would still store the bytes, still verify them, and
    // still pass every other test in this file — and every later run would
    // compare the object against its source, find the destination stamped with
    // the moment of the write, and transfer it again.
    //
    // Both read paths are asserted because they are different code: `head` stats
    // one path and `list_page` walks the tree, and a transfer compares against
    // the *listing*.
    let dir = TempDir::new().unwrap();
    let fs = LocalFs::new(dir.path());
    let key = ObjectKey::new("nested/dir/aged.bin");
    let data = Bytes::from_static(b"written now, modified in 2020");

    fs.put(&key, data.clone(), &blake3(&data), SourceModified::at(AGED))
        .await
        .unwrap();

    assert_eq!(fs.head(&key).await.unwrap().modified_unix, Some(AGED));
    let page = fs.list_page("nested/", None).await.unwrap();
    assert_eq!(
        page.items.first().map(|item| item.modified_unix),
        Some(Some(AGED)),
        "a listing must report the same time `head` does"
    );
}

#[tokio::test]
async fn the_streaming_write_stamps_the_time_too() {
    // A separate code path — `put_from_path` streams and never buffers — and one
    // a small fixture never reaches through `put`. `backup` of a large file goes
    // through here, so a stamp applied only on the buffered path would make
    // exactly the big files re-transfer forever.
    let dir = TempDir::new().unwrap();
    let src = TempDir::new().unwrap();
    let fs = LocalFs::new(dir.path());
    let key = ObjectKey::new("streamed/aged.bin");
    let data = vec![7u8; 4096];
    let src_path = src.path().join("source.bin");
    std::fs::write(&src_path, &data).unwrap();

    fs.put_from_path(&key, &src_path, &blake3(&data), SourceModified::at(AGED))
        .await
        .unwrap();

    assert_eq!(fs.head(&key).await.unwrap().modified_unix, Some(AGED));
}

#[tokio::test]
async fn an_unknown_time_leaves_the_write_time_rather_than_stamping_the_epoch() {
    // The honest fallback. Stamping 1970 would make every such object look older
    // than every local file and invert `--update` over all of them.
    let dir = TempDir::new().unwrap();
    let fs = LocalFs::new(dir.path());
    let key = ObjectKey::new("unstamped.bin");
    let data = Bytes::from_static(b"no time to give");

    fs.put(
        &key,
        data.clone(),
        &blake3(&data),
        SourceModified::unknown(),
    )
    .await
    .unwrap();

    let reported = fs.head(&key).await.unwrap().modified_unix.unwrap();
    assert!(
        reported > AGED,
        "expected a recent write time, got {reported}"
    );
}

#[tokio::test]
async fn a_pre_epoch_time_survives_the_write() {
    // A restored archive legitimately holds them, and a backend that clamped to
    // zero would silently rewrite the fact it was asked to store.
    let dir = TempDir::new().unwrap();
    let fs = LocalFs::new(dir.path());
    let key = ObjectKey::new("ancient.bin");
    let data = Bytes::from_static(b"older than the epoch");

    fs.put(
        &key,
        data.clone(),
        &blake3(&data),
        SourceModified::at(-86_400),
    )
    .await
    .unwrap();

    // The backend model reports whole seconds since the epoch and cannot express
    // a negative one, so what is asserted is what a reader can observe: the file
    // on disk carries the time it was given.
    let on_disk = std::fs::metadata(dir.path().join("ancient.bin"))
        .unwrap()
        .modified()
        .unwrap();
    assert_eq!(
        on_disk,
        std::time::UNIX_EPOCH - std::time::Duration::from_secs(86_400)
    );
}

#[tokio::test]
async fn put_get_head_roundtrip() {
    let dir = TempDir::new().unwrap();
    let fs = LocalFs::new(dir.path());
    let key = ObjectKey::new("nested/dir/object.bin");
    let data = Bytes::from_static(b"hello, verified world");

    let outcome = fs
        .put(
            &key,
            data.clone(),
            &blake3(&data),
            SourceModified::unknown(),
        )
        .await
        .unwrap();
    assert_eq!(outcome.size, data.len() as u64);
    assert!(outcome.verified.matches(&blake3(&data)));

    assert_eq!(fs.get(&key).await.unwrap(), data);
    assert!(fs.exists(&key).await.unwrap());
    assert_eq!(fs.head(&key).await.unwrap().size, data.len() as u64);
}

#[tokio::test]
async fn mismatch_commits_nothing() {
    let dir = TempDir::new().unwrap();
    let fs = LocalFs::new(dir.path());
    let key = ObjectKey::new("x.bin");

    let err = fs
        .put(
            &key,
            Bytes::from_static(b"actual data"),
            &blake3(b"different data"),
            SourceModified::unknown(),
        )
        .await
        .unwrap_err();

    assert!(matches!(err, StoreError::ChecksumMismatch { .. }));
    assert!(
        !fs.exists(&key).await.unwrap(),
        "nothing may be committed on mismatch"
    );
}

#[tokio::test]
async fn put_from_path_streams_a_file_and_verifies() {
    let dir = TempDir::new().unwrap();
    let src = TempDir::new().unwrap();
    let fs = LocalFs::new(dir.path());

    // Larger than any internal copy buffer, to exercise the multi-block streaming path.
    let data: Vec<u8> = (0u32..300_000).map(|i| (i % 251) as u8).collect();
    let src_path = src.path().join("payload.bin");
    std::fs::write(&src_path, &data).unwrap();

    let key = ObjectKey::new("streamed/object.bin");
    let outcome = fs
        .put_from_path(&key, &src_path, &blake3(&data), SourceModified::unknown())
        .await
        .unwrap();
    assert_eq!(outcome.size, data.len() as u64);
    assert!(outcome.verified.matches(&blake3(&data)));

    // The streamed object reads back byte-identical.
    assert_eq!(fs.get(&key).await.unwrap(), Bytes::from(data));
}

#[tokio::test]
async fn put_from_path_rejects_wrong_expected_hash() {
    let dir = TempDir::new().unwrap();
    let src = TempDir::new().unwrap();
    let fs = LocalFs::new(dir.path());

    let src_path = src.path().join("payload.bin");
    std::fs::write(&src_path, b"the real bytes").unwrap();

    let key = ObjectKey::new("wrong.bin");
    let err = fs
        .put_from_path(
            &key,
            &src_path,
            &blake3(b"some other bytes"),
            SourceModified::unknown(),
        )
        .await
        .unwrap_err();

    // Verified-write holds on the streaming path too: mismatch commits nothing.
    assert!(matches!(err, StoreError::ChecksumMismatch { .. }));
    assert!(
        !fs.exists(&key).await.unwrap(),
        "nothing may be committed on a streaming hash mismatch"
    );
}

#[tokio::test]
async fn get_to_path_streams_a_file_correctly() {
    let dir = TempDir::new().unwrap();
    let out = TempDir::new().unwrap();
    let fs = LocalFs::new(dir.path());

    // Larger than the internal copy buffer, to exercise the multi-block streaming path.
    let data: Vec<u8> = (0u32..300_000).map(|i| (i % 251) as u8).collect();
    let key = ObjectKey::new("streamed/object.bin");
    fs.put(
        &key,
        Bytes::from(data.clone()),
        &blake3(&data),
        SourceModified::unknown(),
    )
    .await
    .unwrap();

    // Streaming download reproduces the object byte-for-byte, creating parent dirs.
    let dest = out.path().join("nested/copy.bin");
    fs.get_to_path(&key, &dest).await.unwrap();
    assert_eq!(std::fs::read(&dest).unwrap(), data);

    // A missing object surfaces as NotFound, like `get`.
    assert!(matches!(
        fs.get_to_path(&ObjectKey::new("absent.bin"), &out.path().join("x"))
            .await
            .unwrap_err(),
        StoreError::NotFound(_)
    ));
}

#[tokio::test]
async fn range_reads_match_slices_and_clamp() {
    let dir = TempDir::new().unwrap();
    let fs = LocalFs::new(dir.path());
    let key = ObjectKey::new("r.bin");
    let data = Bytes::from((0u8..100).collect::<Vec<u8>>());
    fs.put(
        &key,
        data.clone(),
        &blake3(&data),
        SourceModified::unknown(),
    )
    .await
    .unwrap();

    let mid = fs
        .get_range(&key, ByteRange::new(10, Some(20)))
        .await
        .unwrap();
    assert_eq!(&mid[..], &data[10..30]);

    let tail = fs
        .get_range(&key, ByteRange::from_offset(90))
        .await
        .unwrap();
    assert_eq!(&tail[..], &data[90..100]);

    // Length past EOF is clamped, not an error.
    let clamped = fs
        .get_range(&key, ByteRange::new(95, Some(999)))
        .await
        .unwrap();
    assert_eq!(&clamped[..], &data[95..100]);

    // Offset past EOF is an error.
    assert!(matches!(
        fs.get_range(&key, ByteRange::from_offset(1000))
            .await
            .unwrap_err(),
        StoreError::RangeOutOfBounds { .. }
    ));
}

#[tokio::test]
async fn delete_is_idempotent() {
    let dir = TempDir::new().unwrap();
    let fs = LocalFs::new(dir.path());
    let key = ObjectKey::new("d.bin");
    let data = Bytes::from_static(b"z");
    fs.put(
        &key,
        data.clone(),
        &blake3(&data),
        SourceModified::unknown(),
    )
    .await
    .unwrap();

    fs.delete(&key).await.unwrap();
    assert!(!fs.exists(&key).await.unwrap());
    assert!(matches!(
        fs.get(&key).await.unwrap_err(),
        StoreError::NotFound(_)
    ));
    fs.delete(&key).await.unwrap(); // deleting again is a no-op success
}

#[tokio::test]
async fn listing_filters_by_prefix_and_paginates_by_cursor() {
    let dir = TempDir::new().unwrap();
    let fs = LocalFs::new(dir.path());
    for i in 0..5u8 {
        let key = ObjectKey::new(format!("p/{i:03}"));
        let data = Bytes::from(vec![i]);
        fs.put(
            &key,
            data.clone(),
            &blake3(&data),
            SourceModified::unknown(),
        )
        .await
        .unwrap();
    }
    fs.put(
        &ObjectKey::new("q/other"),
        Bytes::from_static(b"o"),
        &blake3(b"o"),
        SourceModified::unknown(),
    )
    .await
    .unwrap();

    let page = fs.list_page("p/", None).await.unwrap();
    assert_eq!(page.items.len(), 5);
    assert!(page.items.iter().all(|m| m.key.as_str().starts_with("p/")));

    let page2 = fs.list_page("p/", Some("p/002".to_string())).await.unwrap();
    let keys: Vec<_> = page2
        .items
        .iter()
        .map(|m| m.key.as_str().to_string())
        .collect();
    assert_eq!(keys, vec!["p/003".to_string(), "p/004".to_string()]);
}

#[tokio::test]
async fn prepare_upload_is_unsupported() {
    // LocalFs keeps the trait default: there is no notion of a delegated direct upload to
    // a local directory, so it must surface a clear backend error rather than a ticket.
    let dir = TempDir::new().unwrap();
    let fs = LocalFs::new(dir.path());
    // `UploadTicket` is intentionally non-Debug (it carries bearer transport creds), so
    // match by reference rather than `unwrap_err()`.
    let result = fs.prepare_upload(&ObjectKey::new("x.bin"), 10, None).await;
    assert!(matches!(&result, Err(StoreError::Backend(_))));
    if let Err(err) = result {
        assert!(
            err.to_string().contains("delegated upload unsupported"),
            "unexpected error: {err}"
        );
    }
}

#[tokio::test]
async fn rejects_path_traversal_keys() {
    let dir = TempDir::new().unwrap();
    let fs = LocalFs::new(dir.path());
    let err = fs
        .put(
            &ObjectKey::new("../escape"),
            Bytes::from_static(b"x"),
            &blake3(b"x"),
            SourceModified::unknown(),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::InvalidKey(_)));
}

/// Real filenames that the old substring rule (`name.contains(".tmp.")`) treated
/// as DCTL's own half-written objects and hid from every listing.
///
/// Each spelling is one somebody actually uses: a dated temp convention, a
/// Postgres dump pipeline, an Office lock file that gets backed up with the tree,
/// and — the two that matter most for an upgrade — the staging names *older DCTL
/// builds themselves wrote*, which are ordinary files as far as this build is
/// concerned and must restore whole.
const NAMES_THAT_LOOK_TEMPORARY: &[&str] = &[
    "report.tmp.2024.csv",
    "db.tmp.2024-07-27.sql",
    "~$report.tmp.docx",
    "nested/dir/client.tmp.2024.dat",
    "photo.jpg.tmp.4711.0",
    "photo.jpg.dctltmp.4711.0",
];

#[tokio::test]
async fn a_file_whose_name_looks_temporary_survives_a_whole_round_trip() {
    // The data-loss defect this closes, end to end on a real filesystem.
    //
    // Under the substring rule every one of these was stored, was readable by
    // key, and was **absent from every listing**. So `dctl copy remote: /out`
    // reported `Files: 5 / 5, Errors: 0`, exit 0, and left them behind; `sync`
    // never removed them from a destination; `purge` reported success over them;
    // and `scrub` called the remote healthy without reading them. Nothing in the
    // product ever said a word.
    let dir = TempDir::new().unwrap();
    let fs = LocalFs::new(dir.path());

    for name in NAMES_THAT_LOOK_TEMPORARY {
        let key = ObjectKey::new((*name).to_string());
        let body = Bytes::from(format!("IMPORTANT USER DATA in {name}"));
        fs.put(
            &key,
            body.clone(),
            &blake3(&body),
            SourceModified::unknown(),
        )
        .await
        .unwrap();
        assert_eq!(fs.get(&key).await.unwrap(), body, "{name}");
    }

    let listed: Vec<String> = fs
        .list_page("", None)
        .await
        .unwrap()
        .items
        .iter()
        .map(|meta| meta.key.to_string())
        .collect();

    for name in NAMES_THAT_LOOK_TEMPORARY {
        assert!(
            listed.iter().any(|key| key == name),
            "{name} was stored and is unreachable through a listing; \
             every command that enumerates would silently omit it. Listed: {listed:?}"
        );
    }
    assert_eq!(listed.len(), NAMES_THAT_LOOK_TEMPORARY.len());
}

#[tokio::test]
async fn a_staging_file_left_by_a_crash_is_not_listed_as_an_object() {
    // The other half of the same rule, so closing the data-loss hole cannot be
    // "stop skipping anything". A staging file was never committed and was never
    // reported to anybody as stored, so a listing that showed it would invent an
    // object out of a half-written upload.
    let dir = TempDir::new().unwrap();
    let fs = LocalFs::new(dir.path());

    let real = ObjectKey::new("kept.bin");
    let body = Bytes::from_static(b"committed");
    fs.put(
        &real,
        body.clone(),
        &blake3(&body),
        SourceModified::unknown(),
    )
    .await
    .unwrap();

    // Exactly what a SIGKILL between the write and the rename leaves behind.
    let abandoned = dir
        .path()
        .join(format!("{}9999.0", dctl_store::STAGING_NAME_PREFIX));
    std::fs::write(&abandoned, b"half an upload").unwrap();
    assert!(abandoned.exists());

    let listed: Vec<String> = fs
        .list_page("", None)
        .await
        .unwrap()
        .items
        .iter()
        .map(|meta| meta.key.to_string())
        .collect();
    assert_eq!(listed, vec!["kept.bin".to_string()]);
}

#[tokio::test]
async fn a_name_at_the_filesystem_limit_is_storable() {
    // The staging name no longer carries the object's own name, so a filename
    // that is legal on the filesystem is storable. The old spelling appended a
    // suffix to the *filename*, which pushed a 245-byte name past NAME_MAX as a
    // staging file — and because the suffix embedded the process id, the cutoff
    // moved between runs and the same backup failed on some nights only.
    let dir = TempDir::new().unwrap();
    let fs = LocalFs::new(dir.path());

    // 250 bytes: legal everywhere NAME_MAX is 255, and long enough that any
    // suffix carrying a pid would have overflowed it.
    let key = ObjectKey::new("x".repeat(250));
    let body = Bytes::from_static(b"at the limit");

    fs.put(
        &key,
        body.clone(),
        &blake3(&body),
        SourceModified::unknown(),
    )
    .await
    .expect("a name the filesystem accepts must be storable");
    assert_eq!(fs.get(&key).await.unwrap(), body);
    assert_eq!(fs.list_page("", None).await.unwrap().items.len(), 1);
}

#[tokio::test]
async fn a_store_that_moves_out_from_under_a_run_is_a_failure_and_not_a_reported_success() {
    // Measured on the release binary before this guard existed. A `dctl copy` of
    // 25 files into a vault, with the vault's object store renamed away three
    // seconds in:
    //
    //      Transferred: 9.54 MiB / 9.54 MiB, 100%, 2.71 MiB/s
    //         Verified: 9.54 MiB checksum-matched
    //            Files: 25 / 25
    //           Errors: 0
    //
    // Exit 0, and not one of those objects was in a vault. `create_dir_all`
    // re-created the store path, every write landed in the new empty directory,
    // and the post-write read-back passed because it re-read the same wrong
    // place. The next command exited 7: "no vault at this location".
    //
    // Work reported as done that did not happen — `PLAN.md` §6 — and the
    // write-side twin of the unmounted-volume defect the read side already
    // guards.
    //
    // Asserted here rather than against the binary, and that is not a
    // convenience: the property is about one *process* whose store changes
    // underneath it, and a store legitimately replaced *between* two runs is
    // simply a different store, which this must not refuse. One `LocalFs` across
    // the rename is exactly the run being described, with no sleep and no race.
    let dir = TempDir::new().unwrap();
    let root = dir.path().join("store");
    std::fs::create_dir(&root).unwrap();

    let fs = LocalFs::new(&root);
    let first = ObjectKey::new("a.bin");
    let data = Bytes::from_static(b"the first object, written while the store was there");
    fs.put(
        &first,
        data.clone(),
        &blake3(&data),
        SourceModified::unknown(),
    )
    .await
    .expect("a write into the store as opened");

    // The store moves away, and something else takes its place — which is what
    // `create_dir_all` does, and why "is a directory there?" is the wrong
    // question.
    std::fs::rename(&root, dir.path().join("store-moved")).unwrap();
    std::fs::create_dir(&root).unwrap();

    let second = ObjectKey::new("b.bin");
    let more = Bytes::from_static(b"bytes that must not land in a directory nobody named");
    let error = fs
        .put(
            &second,
            more.clone(),
            &blake3(&more),
            SourceModified::unknown(),
        )
        .await
        .expect_err("a write into a replaced store must fail");
    match &error {
        StoreError::RootChanged { root: named, .. } => {
            assert!(
                named.contains("store"),
                "the refusal names no root: {named}"
            );
        }
        other => panic!("expected RootChanged, got {other}"),
    }

    // The streaming path is separate code and takes the same guard.
    let source = dir.path().join("source.bin");
    std::fs::write(&source, &more).unwrap();
    let streamed = fs
        .put_from_path(&second, &source, &blake3(&more), SourceModified::unknown())
        .await
        .expect_err("a streamed write into a replaced store must fail");
    assert!(matches!(streamed, StoreError::RootChanged { .. }));

    // The bytes, not the counter: nothing landed in the replacement.
    let landed: Vec<_> = std::fs::read_dir(&root)
        .unwrap()
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        landed.is_empty(),
        "objects were written into the directory that replaced the store: {landed:?}"
    );
}

#[tokio::test]
async fn a_root_that_did_not_exist_yet_is_still_created_by_the_first_write() {
    // The other half of the rule, and the one that decides it has no false
    // positives: `dctl config create backup local path=/srv/new` names a
    // directory that does not exist, and the first transfer through it has
    // always created one. A guard that refused here would break the ordinary
    // case in order to catch the rare one.
    let dir = TempDir::new().unwrap();
    let root = dir.path().join("not-yet");
    let fs = LocalFs::new(&root);

    let key = ObjectKey::new("nested/first.bin");
    let data = Bytes::from_static(b"the write that creates the store");
    fs.put(
        &key,
        data.clone(),
        &blake3(&data),
        SourceModified::unknown(),
    )
    .await
    .expect("the first write creates the root");
    assert_eq!(fs.get(&key).await.unwrap(), data);
}
