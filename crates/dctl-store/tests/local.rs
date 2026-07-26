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
