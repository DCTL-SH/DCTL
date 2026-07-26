//! Live B2 round-trip test. Ignored by default; runs only when the environment
//! provides real credentials:
//!
//! ```sh
//! DCTL_B2_KEY_ID=... DCTL_B2_APP_KEY=... DCTL_B2_BUCKET=... \
//!   cargo test -p dctl-store --test b2_live -- --ignored --nocapture
//! ```
//!
//! `b2_full_round_trip` exercises the small-file path (put → verify → head/exists →
//! get → range → list → delete). `b2_stream_from_path_round_trip` exercises the
//! constant-memory streaming path: `put_from_path` on a >100 MiB source drives the
//! native large-file (multipart) API, then `get_to_path` streams it back for a
//! byte-identical compare.
//!
//! LIVE VERIFICATION STATUS: pending the user's B2 credentials. These tests have NOT
//! yet been run against a live bucket — the user must first rotate the DCTL001 B2 key
//! and export it via the `DCTL_B2_*` env vars, then run with `--ignored`. They never
//! run in CI (no creds → skipped; and `#[ignore]` keeps them out of the default run).

use bytes::Bytes;
use dctl_store::b2::{B2Backend, B2Credentials};
use dctl_store::{Backend, ByteRange, ContentHash, HashAlgo, Hasher, ObjectKey};

/// Bytes for the streaming test source. Exceeds B2's 100 MiB large-file threshold so
/// `put_from_path` takes the multipart branch (≥ 2 parts for the usual ~100 MB part
/// size), rather than falling back to the single-shot path.
const STREAM_SOURCE_LEN: u64 = 100 * 1024 * 1024 + 6 * 1024 * 1024;

fn creds_from_env() -> Option<(String, String, String)> {
    Some((
        std::env::var("DCTL_B2_KEY_ID").ok()?,
        std::env::var("DCTL_B2_APP_KEY").ok()?,
        std::env::var("DCTL_B2_BUCKET").ok()?,
    ))
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
#[ignore = "requires live B2 credentials via DCTL_B2_* env vars"]
async fn b2_full_round_trip() {
    let Some((key_id, app_key, bucket)) = creds_from_env() else {
        eprintln!("skipping b2_full_round_trip: DCTL_B2_* not set");
        return;
    };

    let b2 = B2Backend::new(B2Credentials::new(key_id, app_key), bucket).unwrap();
    let key = ObjectKey::new(format!("dctl-test/roundtrip-{}.bin", std::process::id()));
    let data = Bytes::from((0u8..=255).cycle().take(5000).collect::<Vec<u8>>());
    let expected = ContentHash::sha1(&data);

    // put (verified)
    let outcome = b2.put(&key, data.clone(), &expected).await.unwrap();
    assert_eq!(outcome.size, data.len() as u64);

    // head / exists
    assert!(b2.exists(&key).await.unwrap());
    assert_eq!(b2.head(&key).await.unwrap().size, data.len() as u64);

    // get (full)
    assert_eq!(b2.get(&key).await.unwrap(), data);

    // get_range (streaming seek)
    let mid = b2
        .get_range(&key, ByteRange::new(100, Some(50)))
        .await
        .unwrap();
    assert_eq!(&mid[..], &data[100..150]);

    // list_page sees it under its prefix
    let page = b2.list_page("dctl-test/", None).await.unwrap();
    assert!(page.items.iter().any(|m| m.key == key));

    // delete (idempotent)
    b2.delete(&key).await.unwrap();
    assert!(!b2.exists(&key).await.unwrap());
    b2.delete(&key).await.unwrap();

    eprintln!("b2_full_round_trip: OK");
}

#[tokio::test]
#[ignore = "requires live B2 credentials via DCTL_B2_* env vars"]
async fn b2_stream_from_path_round_trip() {
    let Some((key_id, app_key, bucket)) = creds_from_env() else {
        eprintln!("skipping b2_stream_from_path_round_trip: DCTL_B2_* not set");
        return;
    };

    let b2 = B2Backend::new(B2Credentials::new(key_id, app_key), bucket).unwrap();
    let key = ObjectKey::new(format!("dctl-test/stream-{}.bin", std::process::id()));

    // Build a >100 MiB source on disk (constant memory) and its SHA-1 (B2's algo).
    let tmp = tempfile::TempDir::new().unwrap();
    let src = tmp.path().join("source.bin");
    write_pattern_file(&src, STREAM_SOURCE_LEN);
    let expected = hash_file(&src, HashAlgo::Sha1);

    // put_from_path: streamed multipart upload, verified.
    let outcome = b2.put_from_path(&key, &src, &expected).await.unwrap();
    assert_eq!(outcome.size, STREAM_SOURCE_LEN);
    assert!(outcome.verified.matches(&expected));
    assert_eq!(b2.head(&key).await.unwrap().size, STREAM_SOURCE_LEN);

    // get_to_path: streamed download, byte-identical (compared via streamed hash).
    let dest = tmp.path().join("download.bin");
    b2.get_to_path(&key, &dest).await.unwrap();
    assert_eq!(std::fs::metadata(&dest).unwrap().len(), STREAM_SOURCE_LEN);
    assert!(hash_file(&dest, HashAlgo::Sha1).matches(&expected));

    b2.delete(&key).await.unwrap();
    assert!(!b2.exists(&key).await.unwrap());

    eprintln!("b2_stream_from_path_round_trip: OK");
}
