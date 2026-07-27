//! Integration tests for the `LocalFs` backend — the verified-write contract,
//! range reads, listing/pagination, idempotent delete, and key-safety.

use bytes::Bytes;
use dctl_store::{Backend, ByteRange, ContentHash, LocalFs, ObjectKey, StoreError};
use tempfile::TempDir;

fn blake3(data: &[u8]) -> ContentHash {
    ContentHash::blake3(data)
}

#[tokio::test]
async fn put_get_head_roundtrip() {
    let dir = TempDir::new().unwrap();
    let fs = LocalFs::new(dir.path());
    let key = ObjectKey::new("nested/dir/object.bin");
    let data = Bytes::from_static(b"hello, verified world");

    let outcome = fs.put(&key, data.clone(), &blake3(&data)).await.unwrap();
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
        .put_from_path(&key, &src_path, &blake3(&data))
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
        .put_from_path(&key, &src_path, &blake3(b"some other bytes"))
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
    fs.put(&key, Bytes::from(data.clone()), &blake3(&data))
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
    fs.put(&key, data.clone(), &blake3(&data)).await.unwrap();

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
    fs.put(&key, data.clone(), &blake3(&data)).await.unwrap();

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
        fs.put(&key, data.clone(), &blake3(&data)).await.unwrap();
    }
    fs.put(
        &ObjectKey::new("q/other"),
        Bytes::from_static(b"o"),
        &blake3(b"o"),
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
        fs.put(&key, body.clone(), &blake3(&body)).await.unwrap();
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
    fs.put(&real, body.clone(), &blake3(&body)).await.unwrap();

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

    fs.put(&key, body.clone(), &blake3(&body))
        .await
        .expect("a name the filesystem accepts must be storable");
    assert_eq!(fs.get(&key).await.unwrap(), body);
    assert_eq!(fs.list_page("", None).await.unwrap().items.len(), 1);
}
