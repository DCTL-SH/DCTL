//! Live S3-compatible round-trip. Ignored by default; runs only with real creds:
//!
//! ```sh
//! DCTL_S3_ENDPOINT=... DCTL_S3_REGION=... DCTL_S3_BUCKET=... \
//!   DCTL_S3_ACCESS_KEY=... DCTL_S3_SECRET_KEY=... \
//!   cargo test -p dctl-store --test s3_live -- --ignored --nocapture
//! ```
//!
//! Works against any S3-compatible endpoint (AWS, R2, Wasabi, MinIO, or
//! Backblaze's S3 API). `s3_full_round_trip` exercises the small-file path
//! (put -> head/exists -> get -> range -> list -> delete).
//! `s3_stream_from_path_round_trip` exercises the constant-memory streaming path:
//! `put_from_path` on a >100 MiB source drives CreateMultipartUpload / UploadPart /
//! CompleteMultipartUpload, then `get_to_path` streams it back for a byte-identical
//! compare. This same path is what R2 uses (it reuses the S3 client).
//!
//! LIVE VERIFICATION STATUS: **never run.** No S3 or R2 credentials have existed in
//! this environment, so not one line below has been executed against a live endpoint.
//! That sentence used to be buried under two tests that printed `skipping …` and
//! reported **ok**, which is why `gated::require` now makes a missing variable a
//! failure — see `tests/gated/mod.rs` for the whole argument, and
//! `tests/credential_gate.rs` for what stops it coming back.
//!
//! What covers the S3 backend meanwhile is offline and stated plainly: the SigV4
//! signing is checked against AWS's own published test vectors, the presigned-URL
//! assembly and the `x-amz-meta-mtime` write are unit-tested in `s3::client`, and
//! nothing else is claimed.

mod gated;

use bytes::Bytes;
use dctl_store::Deadlines;
use dctl_store::{
    Backend, ByteRange, ContentHash, HashAlgo, Hasher, ObjectKey, S3Backend, S3Config,
    SourceModified,
};

/// Bytes for the streaming test source. Exceeds S3's 100 MiB multipart threshold so
/// `put_from_path` takes the multipart branch (2 parts at the 100 MiB part size),
/// rather than falling back to the single-shot path.
const STREAM_SOURCE_LEN: u64 = 100 * 1024 * 1024 + 6 * 1024 * 1024;

/// Every variable an S3 round trip needs, in the order [`S3Config::new`] takes them.
const S3_VARS: &[&str] = &[
    "DCTL_S3_ENDPOINT",
    "DCTL_S3_REGION",
    "DCTL_S3_BUCKET",
    "DCTL_S3_ACCESS_KEY",
    "DCTL_S3_SECRET_KEY",
];

/// The endpoint configuration, or a failure naming what is missing.
fn config_or_fail(test: &str) -> S3Config {
    let values = gated::require(test, S3_VARS);
    S3Config::new(
        values[0].clone(),
        values[1].clone(),
        values[2].clone(),
        values[3].clone(),
        values[4].clone(),
    )
}

/// Write a deterministic `len`-byte pattern to `path` in fixed-size blocks, so the test
/// fixture itself never holds the whole file in memory.
fn write_pattern_file(path: &std::path::Path, len: u64) {
    use std::io::Write as _;
    let mut f = std::io::BufWriter::new(std::fs::File::create(path).unwrap());
    let block: Vec<u8> = (0u32..1_048_576).map(|i| (i % 251) as u8).collect();
    let mut written = 0u64;
    while written < len {
        let take = ((len - written) as usize).min(block.len());
        f.write_all(&block[..take]).unwrap();
        written += take as u64;
    }
    f.flush().unwrap();
}

/// Stream-hash a file under `algo` without holding it in memory (constant memory).
fn hash_file(path: &std::path::Path, algo: HashAlgo) -> ContentHash {
    use std::io::Read as _;
    let mut f = std::fs::File::open(path).unwrap();
    let mut hasher = Hasher::new(algo);
    let mut buf = vec![0u8; 1_048_576];
    loop {
        let n = f.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    hasher.finalize()
}

#[tokio::test]
#[ignore = "needs a live S3 endpoint: DCTL_S3_ENDPOINT, DCTL_S3_REGION, DCTL_S3_BUCKET, \
            DCTL_S3_ACCESS_KEY, DCTL_S3_SECRET_KEY"]
async fn s3_full_round_trip() {
    let config = config_or_fail("s3_full_round_trip");

    let s3 = S3Backend::new(config, Deadlines::default()).unwrap();
    let key = ObjectKey::new(format!("dctl-s3-test/roundtrip-{}.bin", std::process::id()));
    let data = Bytes::from((0u8..=255).cycle().take(5000).collect::<Vec<u8>>());
    let expected = ContentHash::blake3(&data);

    let outcome = s3
        .put(&key, data.clone(), &expected, SourceModified::unknown())
        .await
        .unwrap();
    assert_eq!(outcome.size, data.len() as u64);

    assert!(s3.exists(&key).await.unwrap());
    assert_eq!(s3.head(&key).await.unwrap().size, data.len() as u64);
    assert_eq!(s3.get(&key).await.unwrap(), data);

    let mid = s3
        .get_range(&key, ByteRange::new(100, Some(50)))
        .await
        .unwrap();
    assert_eq!(&mid[..], &data[100..150]);

    let page = s3.list_page("dctl-s3-test/", None).await.unwrap();
    assert!(page.items.iter().any(|m| m.key == key));

    s3.delete(&key).await.unwrap();
    assert!(!s3.exists(&key).await.unwrap());

    eprintln!("s3_full_round_trip: OK");
}

#[tokio::test]
#[ignore = "needs a live S3 endpoint: DCTL_S3_ENDPOINT, DCTL_S3_REGION, DCTL_S3_BUCKET, \
            DCTL_S3_ACCESS_KEY, DCTL_S3_SECRET_KEY"]
async fn s3_stream_from_path_round_trip() {
    let config = config_or_fail("s3_stream_from_path_round_trip");

    let s3 = S3Backend::new(config, Deadlines::default()).unwrap();
    let key = ObjectKey::new(format!("dctl-s3-test/stream-{}.bin", std::process::id()));

    // Build a >100 MiB source on disk (constant memory) and its blake3 (DCTL's algo).
    let tmp = tempfile::TempDir::new().unwrap();
    let src = tmp.path().join("source.bin");
    write_pattern_file(&src, STREAM_SOURCE_LEN);
    let expected = hash_file(&src, HashAlgo::Blake3);

    // put_from_path: streamed multipart upload, verified.
    let outcome = s3
        .put_from_path(&key, &src, &expected, SourceModified::unknown())
        .await
        .unwrap();
    assert_eq!(outcome.size, STREAM_SOURCE_LEN);
    assert!(outcome.verified.matches(&expected));
    assert_eq!(s3.head(&key).await.unwrap().size, STREAM_SOURCE_LEN);

    // get_to_path: streamed download, byte-identical (compared via streamed hash).
    let dest = tmp.path().join("download.bin");
    s3.get_to_path(&key, &dest).await.unwrap();
    assert_eq!(std::fs::metadata(&dest).unwrap().len(), STREAM_SOURCE_LEN);
    assert!(hash_file(&dest, HashAlgo::Blake3).matches(&expected));

    s3.delete(&key).await.unwrap();
    assert!(!s3.exists(&key).await.unwrap());

    eprintln!("s3_stream_from_path_round_trip: OK");
}
