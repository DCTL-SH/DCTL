//! The B2 backend against a local B2 endpoint: everything a live bucket is not
//! needed for.
//!
//! `b2_live.rs` needs an account, so until this file existed every statement
//! about *where* B2 cuts an object, *what* it sends for a retried part, and
//! whether a configured part size reaches the wire rested either on reading the
//! code or on uploading gigabytes into a real bucket. Reading the code is how
//! four claims in `HANDOVER.md` §11.4 turned out false, and uploading gigabytes
//! is not something a gate can do on every commit.
//!
//! What runs here is the **real** [`B2Backend`], unchanged, pointed at
//! [`support::mock_b2`] — a loopback listener that verifies the SHA-1 of every
//! body it receives and enforces B2's own large-file rules. What that buys and
//! what it does not is in that module's documentation.
//!
//! The memory contract has its own file: `b2_upload_memory.rs`, which must hold
//! exactly one test for the reason it explains.

mod support;

use bytes::Bytes;
use dctl_store::b2::{B2Backend, B2Credentials};
use dctl_store::{Backend, ContentHash, HashAlgo, ObjectKey, SourceModified};
use support::mock_b2::{APP_KEY, BUCKET, KEY_ID, MockB2};
use tempfile::TempDir;

/// Part size these tests run at: B2's own floor, which is the smallest value
/// `with_part_size` honours rather than raises, and therefore the cheapest way to
/// drive a real multi-part upload.
const PART: u64 = 5_000_000;

/// What B2 advertises in these tests. Deliberately different from [`PART`] and
/// from the compiled default, so a client that sized anything from the provider's
/// advice is caught rather than flattered.
const ADVERTISED: u64 = 7_000_000;

async fn backend(mock: &MockB2, part_size: Option<u64>) -> B2Backend {
    B2Backend::new(B2Credentials::new(KEY_ID, APP_KEY), BUCKET)
        .expect("the backend builds")
        .with_authorize_url(mock.authorize_url())
        .with_part_size(part_size)
}

fn blake3(data: &[u8]) -> ContentHash {
    ContentHash::compute(HashAlgo::Blake3, data)
}

/// A source file of `len` bytes of a repeating pattern, and its BLAKE3.
fn source(dir: &TempDir, name: &str, len: usize) -> (std::path::PathBuf, Vec<u8>, ContentHash) {
    let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
    let path = dir.path().join(name);
    std::fs::write(&path, &data).expect("a source file");
    let hash = blake3(&data);
    (path, data, hash)
}

// ── where the object is cut ──────────────────────────────────────────────────

#[tokio::test]
async fn an_object_of_exactly_one_part_is_one_request_and_one_byte_more_is_a_large_file() {
    // The cutoff and the part size are the same number, which is what keeps the
    // memory contract to one figure. When they were two, the *small* side was the
    // expensive one: a 99 MiB object cost 203 MiB of anonymous memory against a
    // 100 MiB cutoff, more than a 4 GiB object did.
    let mock = MockB2::start(ADVERTISED).await;
    let b2 = backend(&mock, Some(PART)).await;
    let dir = TempDir::new().expect("a temporary directory");

    let (exact, _, exact_hash) = source(&dir, "exact.bin", PART as usize);
    b2.put_from_path(
        &ObjectKey::new("o/exact"),
        &exact,
        &exact_hash,
        SourceModified::unknown(),
    )
    .await
    .expect("an object of exactly one part stores");

    let (over, _, over_hash) = source(&dir, "over.bin", PART as usize + 1);
    b2.put_from_path(
        &ObjectKey::new("o/over"),
        &over,
        &over_hash,
        SourceModified::unknown(),
    )
    .await
    .expect("an object one byte larger stores");

    let state = mock.state();
    assert_eq!(
        state.singles.len(),
        1,
        "exactly one object should have gone down the single-shot path: {:?}",
        state.singles
    );
    assert_eq!(state.singles[0].len as u64, PART);
    assert_eq!(
        state.large.len(),
        1,
        "exactly one object should have gone down the large-file path"
    );
    let large = &state.large[0];
    assert!(large.finished, "the large file was never finished");
    assert_eq!(
        large.parts.len(),
        2,
        "one byte over one part is two parts, the second of them one byte"
    );
    assert_eq!(large.parts[1].len, 1);
}

#[tokio::test]
async fn the_part_size_b2_advertises_is_reported_and_not_obeyed() {
    // B2's `recommendedPartSize` is advisory, per-account, and arrives from the
    // network. Sizing from it would make DCTL's peak memory whatever the provider
    // said that morning — see `b2::constants::DEFAULT_PART_SIZE`. rclone reaches
    // the same conclusion: it parses the field and never sizes an upload with it.
    let mock = MockB2::start(ADVERTISED).await;
    let b2 = backend(&mock, Some(PART)).await;
    let dir = TempDir::new().expect("a temporary directory");

    // Three parts at the configured size; two at the advertised one.
    let (path, _, hash) = source(&dir, "advice.bin", (PART * 2) as usize + 1);
    b2.put_from_path(
        &ObjectKey::new("o/advice"),
        &path,
        &hash,
        SourceModified::unknown(),
    )
    .await
    .expect("the object stores");

    let state = mock.state();
    let large = state.large.first().expect("a large file was started");
    assert_eq!(
        large.parts.len(),
        3,
        "cut at the configured {PART}-byte part, not the advertised {ADVERTISED}-byte one"
    );
    assert_eq!(large.parts[0].len as u64, PART);
}

#[tokio::test]
async fn a_part_size_below_b2s_floor_is_raised_rather_than_sent() {
    // An upload that starts, runs, and is rejected at the second part with a part
    // below the provider's minimum is the failure clamping exists to prevent.
    let mock = MockB2::start(ADVERTISED).await;
    let b2 = backend(&mock, Some(1024)).await;
    assert_eq!(
        b2.upload_peak_bytes(),
        5_000_000,
        "a part size under B2's floor must be raised to it, and the peak with it"
    );
    let dir = TempDir::new().expect("a temporary directory");
    let (path, _, hash) = source(&dir, "clamped.bin", 5_000_000 + 10);
    b2.put_from_path(
        &ObjectKey::new("o/clamped"),
        &path,
        &hash,
        SourceModified::unknown(),
    )
    .await
    .expect("the object stores");

    let state = mock.state();
    let large = state.large.first().expect("a large file was started");
    assert_eq!(large.parts[0].len, 5_000_000);
}

// ── what a retry sends ───────────────────────────────────────────────────────

#[tokio::test]
async fn a_refused_part_is_re_sent_byte_for_byte_and_finished_once() {
    // B2 answers a busy storage pod with `503 no tomes available`, and its
    // documented remedy is a *new* upload URL. The re-sent part has to be the same
    // bytes under the same number, or the finish call names a SHA-1 for a part the
    // provider does not hold.
    let mock = MockB2::start(ADVERTISED).await;
    let b2 = backend(&mock, Some(PART)).await;
    let dir = TempDir::new().expect("a temporary directory");
    let (path, data, hash) = source(&dir, "retried.bin", (PART + PART / 2) as usize);

    mock.fail_next("/b2_upload_part/large-1", 503, "service_unavailable");
    b2.put_from_path(
        &ObjectKey::new("o/retried"),
        &path,
        &hash,
        SourceModified::unknown(),
    )
    .await
    .expect("a refused part is retried and the object stores");

    let state = mock.state();
    // Three attempts for two parts: the refusal, then both real ones.
    assert_eq!(
        state.count("/b2_upload_part/large-1"),
        3,
        "expected one refused attempt and two parts"
    );
    // A fresh part URL per attempt, which is the whole reason the retry encloses
    // the URL fetch: replaying the old one arrives at the same busy pod.
    assert_eq!(
        state.count("/b2_get_upload_part_url"),
        3,
        "a retried part must ask for a new upload URL"
    );
    let large = state.large.first().expect("a large file was started");
    assert!(large.finished, "the large file was never finished");
    assert_eq!(
        large.parts.len(),
        2,
        "a re-sent part replaces its predecessor rather than adding one"
    );
    // The bytes that arrived are the bytes that were meant to: the mock verified
    // each part's SHA-1 against the header, and the finish call's array is the
    // list of those same hashes in order.
    let expected: Vec<String> = [&data[..PART as usize], &data[PART as usize..]]
        .iter()
        .map(|part| ContentHash::sha1(part).hex())
        .collect();
    assert_eq!(large.finished_with, expected);
}

#[tokio::test]
async fn a_large_file_that_cannot_be_finished_is_cancelled_rather_than_left_unfinished() {
    // An unfinished large file is billed, is invisible to `b2_list_file_names`,
    // and is the one class of debris `cleanup` reports as `unsupported` by name.
    // Not leaving one behind is the only remedy this build has.
    let mock = MockB2::start(ADVERTISED).await;
    let b2 = backend(&mock, Some(PART)).await;
    let dir = TempDir::new().expect("a temporary directory");
    let (path, _, hash) = source(&dir, "doomed.bin", (PART + 1) as usize);

    // A `400` is never retried — the request is wrong and will be equally wrong
    // next time — so this fails the upload rather than merely delaying it.
    mock.fail_next("/b2_finish_large_file", 400, "bad_request");
    let error = b2
        .put_from_path(
            &ObjectKey::new("o/doomed"),
            &path,
            &hash,
            SourceModified::unknown(),
        )
        .await
        .expect_err("a refused finish must fail the write");
    assert!(
        format!("{error}").contains("400"),
        "the failure should name what the provider said: {error}"
    );

    let state = mock.state();
    let large = state.large.first().expect("a large file was started");
    assert!(!large.finished);
    assert!(
        large.cancelled,
        "the abandoned large file was not cancelled — it would be billed forever"
    );
}

// ── the verified write ───────────────────────────────────────────────────────

#[tokio::test]
async fn a_source_that_does_not_hash_to_the_expected_value_is_never_finished() {
    // The verified-write contract: `put_from_path` must not report success unless
    // the bytes it sent hash to what the caller declared. Checked *before* the
    // finish call, which is what commits — so a wrong file is never an object.
    let mock = MockB2::start(ADVERTISED).await;
    let b2 = backend(&mock, Some(PART)).await;
    let dir = TempDir::new().expect("a temporary directory");
    let (path, _, _) = source(&dir, "mismatch.bin", (PART + 1) as usize);

    let error = b2
        .put_from_path(
            &ObjectKey::new("o/mismatch"),
            &path,
            &blake3(b"something else entirely"),
            SourceModified::unknown(),
        )
        .await
        .expect_err("a hash that does not describe the file must fail the write");
    assert!(
        format!("{error}").to_lowercase().contains("checksum"),
        "the failure should name the mismatch: {error}"
    );

    let state = mock.state();
    let large = state.large.first().expect("a large file was started");
    assert!(!large.finished, "a mismatched object must not be committed");
    assert!(large.cancelled, "and must not be left unfinished either");
}

#[tokio::test]
async fn the_buffered_put_cuts_the_same_object_the_same_way() {
    // `Backend::put` and `Backend::put_from_path` are two doors into one
    // behaviour, and the pair has drifted before: the buffered path once carried
    // its own copy of the `b2_start_large_file` body and lost the source's
    // modification time from one of them. Same object, same part boundaries.
    let mock = MockB2::start(ADVERTISED).await;
    let b2 = backend(&mock, Some(PART)).await;
    let data: Vec<u8> = (0..(PART + PART / 2) as usize)
        .map(|i| (i % 251) as u8)
        .collect();

    b2.put(
        &ObjectKey::new("o/buffered"),
        Bytes::from(data.clone()),
        &blake3(&data),
        SourceModified::unknown(),
    )
    .await
    .expect("the buffered path stores");

    let state = mock.state();
    let large = state.large.first().expect("a large file was started");
    assert!(large.finished);
    assert_eq!(large.parts.len(), 2);
    assert_eq!(large.parts[0].len as u64, PART);
    assert_eq!(large.parts[1].len as u64, PART / 2);
    assert_eq!(
        large.parts[0].sha1,
        ContentHash::sha1(&data[..PART as usize]).hex()
    );
}
