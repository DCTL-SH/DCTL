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
//! LIVE VERIFICATION STATUS: **run**, on 2026-07-27, against bucket DCTL001. All
//! four pass. They still never run in CI — `#[ignore]` keeps them out of the
//! default run, and asking for them without credentials is a **failure** rather
//! than a skip (`tests/gated/mod.rs`) — so this line is the only record that they
//! have been exercised. Re-run them after any change under `b2/` and update the
//! date.
//!
//! ## What these four still do not cover
//!
//! Stated because the header used to say "pending" long after it was stale, and
//! a stale status line is worse than none: a reader takes "these tests pass" for
//! "this backend is exercised".
//!
//! * **Version pagination on delete.** `delete` must remove *every* version of a
//!   name, and it used to issue one `b2_list_file_versions` and stop — so a name
//!   with more than a thousand versions was reported deleted while its oldest
//!   copies stayed alive and readable. Verified manually on 2026-07-27: 1 005
//!   versions of one key uploaded through the raw API, then
//!   `dctl deletefile b2:…` → **0 versions remaining**, gone from `dctl ls`,
//!   `dctl cat` exit 4. Not automated here because building the pile takes seven
//!   minutes of round trips; the wire-format half is unit-tested in
//!   `b2::api::tests`.
//! * **Retry and re-authentication.** There is none to test (see the b2 probe
//!   findings F10 and F13).
//! * **Source modification time.** Covered by
//!   `b2_stores_and_returns_the_source_modification_time`: written as the
//!   documented `src_last_modified_millis` file-info key and read back from
//!   both `head` and `list_page`, with the fallback to `uploadTimestamp` for
//!   an object that never recorded one. It is no longer the *only* thing that
//!   covers the write: `b2::upload` now assembles the header set and the
//!   `b2_start_large_file` body as values, and unit-tests both, so deleting the
//!   time fails `cargo test --workspace` rather than only this file.

mod gated;

use bytes::Bytes;
use dctl_store::b2::{B2Backend, B2Credentials};
use dctl_store::{Backend, ByteRange, ContentHash, HashAlgo, Hasher, ObjectKey, SourceModified};

/// Bytes for the streaming test source. Exceeds B2's 100 MiB large-file threshold so
/// `put_from_path` takes the multipart branch (≥ 2 parts for the usual ~100 MB part
/// size), rather than falling back to the single-shot path.
const STREAM_SOURCE_LEN: u64 = 100 * 1024 * 1024 + 6 * 1024 * 1024;

/// Every variable a live B2 round trip needs.
const B2_VARS: &[&str] = &["DCTL_B2_KEY_ID", "DCTL_B2_APP_KEY", "DCTL_B2_BUCKET"];

/// A connected backend, or a failure naming what is missing.
///
/// The bucket has no default on purpose. These tests write into whatever they
/// are given, and a maintainer who exported keys for something else should not
/// discover that by finding objects in it.
fn backend_or_fail(test: &str) -> B2Backend {
    let creds = gated::require(test, B2_VARS);
    B2Backend::new(
        B2Credentials::new(creds[0].clone(), creds[1].clone()),
        creds[2].clone(),
    )
    .expect("a b2 backend from live credentials")
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
#[ignore = "needs a live B2 bucket: DCTL_B2_KEY_ID, DCTL_B2_APP_KEY, DCTL_B2_BUCKET"]
async fn b2_full_round_trip() {
    let b2 = backend_or_fail("b2_full_round_trip");
    let key = ObjectKey::new(format!("dctl-test/roundtrip-{}.bin", std::process::id()));
    let data = Bytes::from((0u8..=255).cycle().take(5000).collect::<Vec<u8>>());
    let expected = ContentHash::sha1(&data);

    // put (verified)
    let outcome = b2
        .put(&key, data.clone(), &expected, SourceModified::unknown())
        .await
        .unwrap();
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
#[ignore = "needs a live B2 bucket: DCTL_B2_KEY_ID, DCTL_B2_APP_KEY, DCTL_B2_BUCKET"]
async fn b2_stores_and_returns_the_source_modification_time() {
    // The property `sync` is incremental because of, on the backend where it is
    // least obvious it can be done at all: B2 stamps its own `uploadTimestamp`,
    // and the old code reported that as the object's modification time. So every
    // object looked like it had been "modified" at the moment of the upload,
    // every comparison found every file changed, and a nightly `sync` re-uploaded
    // the whole bucket.
    //
    // The time goes in the documented `src_last_modified_millis` file-info key —
    // rclone's spelling too, so the two tools read each other's buckets — and it
    // must come back from **`list_page`**, because that is what a transfer
    // compares against. `head` is asserted as well since they are separate calls.
    //
    // What this adds to `b2::upload`'s own tests is the half they cannot reach:
    // that B2 *accepts* the key and hands it back. That the key is sent at all is
    // now proved offline, in the gate.
    //
    // 2020-01-01T00:00:00Z: far from any clock this test can run against, so a
    // backend that quietly reported "now" cannot pass by accident.
    const AGED: i64 = 1_577_836_800;
    let b2 = backend_or_fail("b2_stores_and_returns_the_source_modification_time");
    let prefix = format!("dctl-test/mtime-{}/", std::process::id());
    let key = ObjectKey::new(format!("{prefix}aged.bin"));
    let data = Bytes::from_static(b"written now, modified in 2020");

    b2.put(
        &key,
        data.clone(),
        &ContentHash::sha1(&data),
        SourceModified::at(AGED),
    )
    .await
    .unwrap();

    assert_eq!(
        b2.head(&key).await.unwrap().modified_unix,
        Some(AGED),
        "head must report the writer's time, not the upload timestamp"
    );
    let page = b2.list_page(&prefix, None).await.unwrap();
    assert_eq!(
        page.items.first().map(|item| item.modified_unix),
        Some(Some(AGED)),
        "a listing must report the same time head does — this is what sync reads"
    );

    // An object written without a time still reports one: B2's own upload
    // timestamp, which is the migration rule for every object in every existing
    // bucket. Absent would be worse — `dctl lsl` would print a blank column for
    // half a bucket, and `--update` could not protect anything.
    let untimed = ObjectKey::new(format!("{prefix}untimed.bin"));
    b2.put(
        &untimed,
        data.clone(),
        &ContentHash::sha1(&data),
        SourceModified::unknown(),
    )
    .await
    .unwrap();
    let reported = b2.head(&untimed).await.unwrap().modified_unix.unwrap();
    assert!(
        reported > AGED,
        "an object with no recorded source time falls back to its upload time, got {reported}"
    );

    b2.delete(&key).await.unwrap();
    b2.delete(&untimed).await.unwrap();
    eprintln!("b2_stores_and_returns_the_source_modification_time: OK");
}

#[tokio::test]
#[ignore = "needs a live B2 bucket: DCTL_B2_KEY_ID, DCTL_B2_APP_KEY, DCTL_B2_BUCKET"]
async fn b2_stream_from_path_round_trip() {
    let b2 = backend_or_fail("b2_stream_from_path_round_trip");
    let key = ObjectKey::new(format!("dctl-test/stream-{}.bin", std::process::id()));

    // Build a >100 MiB source on disk (constant memory) and its SHA-1 (B2's algo).
    let tmp = tempfile::TempDir::new().unwrap();
    let src = tmp.path().join("source.bin");
    write_pattern_file(&src, STREAM_SOURCE_LEN);
    let expected = hash_file(&src, HashAlgo::Sha1);

    // put_from_path: streamed multipart upload, verified.
    let outcome = b2
        .put_from_path(&key, &src, &expected, SourceModified::unknown())
        .await
        .unwrap();
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

#[tokio::test]
#[ignore = "needs a live B2 bucket: DCTL_B2_KEY_ID, DCTL_B2_APP_KEY, DCTL_B2_BUCKET"]
async fn b2_prepare_upload_ticket_shape() {
    let b2 = backend_or_fail("b2_prepare_upload_ticket_shape");
    let key = ObjectKey::new(format!("dctl-test/ticket-{}.bin", std::process::id()));

    // A delegated ticket is a live b2_get_upload_url + the exact POST the client replays.
    let ticket = b2.prepare_upload(&key, 4096, None).await.unwrap();
    assert_eq!(ticket.method, "POST");
    assert!(ticket.url.contains("b2_upload_file"), "url: {}", ticket.url);
    assert_eq!(ticket.expires_unix, None); // token-scoped, not signed-expiry
    assert!(ticket.headers.iter().any(|(k, _)| k == "Authorization"));
    assert!(
        ticket
            .headers
            .contains(&("X-Bz-Content-Sha1".to_string(), "do_not_verify".to_string()))
    );

    eprintln!("b2_prepare_upload_ticket_shape: OK");
}
