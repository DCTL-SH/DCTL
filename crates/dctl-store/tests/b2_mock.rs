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
use dctl_store::guard::Strength;
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

/// How many requests arrived whose path *starts* with `prefix`.
///
/// [`support::mock_b2::State::count`] matches on a suffix, which is right for
/// the endpoints B2 addresses by name and silently wrong for the two it
/// addresses by id: `/b2_upload_file/<bucket>` and `/b2_upload_part/<file>` end
/// with the id, so a suffix of `"/b2_upload_file/"` matches nothing and an
/// assertion built on it reads zero however many uploads were sent.
fn sent(mock: &MockB2, prefix: &str) -> usize {
    mock.state()
        .requests
        .iter()
        .filter(|seen| seen.path.starts_with(prefix))
        .count()
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

// ── the bucket this run has been writing into ────────────────────────────────

#[tokio::test]
async fn the_bucket_identity_is_re_resolved_and_not_read_back_from_the_session() {
    // The whole point of B2's `store_identity`, and until this test it could be
    // replaced by `Ok(None)` — which disables the guard outright — with the
    // workspace suite staying green.
    //
    // The trap it exists to avoid is small and quiet: `AuthState` already holds
    // a `bucket_id`, resolved when this run authorized, and answering with that
    // would compile, read naturally and compare a cached value against itself
    // forever. A bucket deleted and re-created mid-run keeps its *name* and gets
    // a **new id**, so the fresh lookup is the only thing that can see it.
    let mock = MockB2::start(ADVERTISED).await;
    let b2 = backend(&mock, None).await;

    let before = b2
        .store_identity()
        .await
        .expect("the bucket resolves")
        .expect("and is there");
    assert_eq!(before.strength(), Strength::Distinguishing);

    // Deleted and re-created under the same name: the session's cached id is
    // untouched and the provider's answer has changed.
    mock.recreate_bucket("b2b1c0ffee00000000000002");
    let after = b2
        .store_identity()
        .await
        .expect("the replacement resolves")
        .expect("and is there");

    assert_ne!(
        before, after,
        "a re-created bucket must not compare equal to the one it replaced"
    );
    // Stated as the guard states it, because that is the decision this value is
    // for: writes into the replacement are refused, not logged and continued.
    assert_eq!(
        dctl_store::guard::identity::verdict(Some(&before), Some(&after)),
        dctl_store::guard::identity::Verdict::Replaced
    );
    // And the lookup really went to the provider each time, rather than being
    // answered from anything this process was already holding.
    assert_eq!(mock.state().count("/b2_list_buckets"), 2);
}

#[tokio::test]
async fn a_deleted_bucket_is_an_absence_and_a_failed_lookup_is_an_error() {
    // Two answers that must not be folded into one. B2 reports a name that
    // matches nothing with `200` and an empty array, and that absence is a fact
    // the guard acts on — `Gone`, and the run stops rather than writing into a
    // bucket somebody deleted underneath it. A request that *failed* is not that
    // fact: "I could not look" carried back as `Ok(None)` would read as "the
    // bucket is gone" and refuse a run over a network hiccup, and carried back
    // as `Ok(Some(..))` would bless one.
    let mock = MockB2::start(ADVERTISED).await;
    let b2 = backend(&mock, None).await;

    let before = b2
        .store_identity()
        .await
        .expect("the bucket resolves")
        .expect("and is there");

    mock.delete_bucket();
    assert_eq!(
        b2.store_identity()
            .await
            .expect("the lookup still succeeds"),
        None,
        "a bucket that is not listed is an absence, not a failure"
    );
    assert_eq!(
        dctl_store::guard::identity::verdict(Some(&before), None),
        dctl_store::guard::identity::Verdict::Gone
    );

    // `403` is B2's storage/transaction cap and this module classifies it as
    // terminal, so it arrives as one error rather than as a retry storm.
    mock.fail_next("/b2_list_buckets", 403, "storage_cap_exceeded");
    let error = b2
        .store_identity()
        .await
        .expect_err("a refused lookup is not an answer about the bucket");
    assert!(
        format!("{error}").contains("403"),
        "the failure must carry what the provider said: {error}"
    );
}

// ── the receipt a provider hands back ────────────────────────────────────────

#[tokio::test]
async fn a_receipt_that_names_a_different_sha1_is_refused_rather_than_believed() {
    // The only check DCTL has against a provider that accepts an upload and
    // stores something else. B2 answers every upload with the `contentSha1` it
    // computed over what it received; comparing it against the digest that was
    // sent is what turns "the request succeeded" into "the object is the object".
    //
    // Deleting the comparison leaves a `put` that returns `Ok` for bytes the
    // provider says are not the bytes that were sent — a transfer reported as
    // complete for an object that is not there, which is `PLAN.md` §6's
    // forbidden outcome arriving through the one field designed to prevent it.
    //
    // Both upload shapes are asserted, because they are separate call sites over
    // one helper and the single-shot path is the one almost every object takes.
    let mock = MockB2::start(ADVERTISED).await;
    mock.echo_sha1("0000000000000000000000000000000000000000");

    let b2 = backend(&mock, None).await;
    let data = Bytes::from_static(b"the bytes that were sent");
    let error = b2
        .put(
            &ObjectKey::new("o/single.bin"),
            data.clone(),
            &blake3(&data),
            SourceModified::unknown(),
        )
        .await
        .expect_err("a receipt that does not describe what was sent is not a success");
    assert!(
        matches!(error, dctl_store::StoreError::ChecksumMismatch { .. }),
        "the failure must name the disagreement rather than the transport: {error}"
    );
    // And exactly once. B2 checked the body against the header it was sent and
    // accepted it, so a different digest in the answer is what B2 holds — a
    // fact five more uploads of the same bytes cannot change. Asserted by
    // count, because the wrapped `Retried` error above is the only other trace
    // a re-upload would leave and an operator would read it as a flaky link.
    assert_eq!(
        sent(&mock, "/b2_upload_file/"),
        1,
        "a settled disagreement must not be re-uploaded"
    );

    // The multipart path, over the same helper and a separate call site.
    let mock = MockB2::start(ADVERTISED).await;
    mock.echo_sha1("1111111111111111111111111111111111111111");
    let b2 = backend(&mock, Some(PART)).await;
    let big = Bytes::from(vec![7u8; (PART * 2) as usize + 5]);
    let error = b2
        .put(
            &ObjectKey::new("o/large.bin"),
            big.clone(),
            &blake3(&big),
            SourceModified::unknown(),
        )
        .await
        .expect_err("a part whose receipt disagrees is not a stored part");
    assert!(
        matches!(error, dctl_store::StoreError::ChecksumMismatch { .. }),
        "the failure must name the disagreement: {error}"
    );
    // One part sent, not six. The multipart path is where a retry costs the
    // most — it re-reads and re-sends a whole part — and it is the path a large
    // object always takes.
    assert_eq!(
        sent(&mock, "/b2_upload_part/"),
        1,
        "a settled disagreement must not re-send the part"
    );

    // The control: the same objects against a mock that answers honestly, so the
    // refusal is about the receipt and not about the sizes or the mock.
    let mock = MockB2::start(ADVERTISED).await;
    let b2 = backend(&mock, Some(PART)).await;
    b2.put(
        &ObjectKey::new("o/single.bin"),
        data.clone(),
        &blake3(&data),
        SourceModified::unknown(),
    )
    .await
    .expect("an honest receipt stores");
    b2.put(
        &ObjectKey::new("o/large.bin"),
        big.clone(),
        &blake3(&big),
        SourceModified::unknown(),
    )
    .await
    .expect("and so does a multipart one");
}

#[tokio::test]
async fn a_put_whose_declared_hash_is_not_its_bytes_never_reaches_the_network() {
    // The guard at the other end of the same claim, and the cheaper one: the
    // caller states what it believes it is storing, and this backend checks that
    // belief against the buffer in its hand before a byte leaves the process.
    //
    // Without it a caller whose hash and bytes had come apart — a read that was
    // retried, a buffer reused, an index entry copied from the wrong row — would
    // upload the bytes, receive an honest receipt for them, and record the wrong
    // digest against the object. Every later `verify` would then compare the
    // object against a hash nothing ever had, and report a corrupt archive.
    //
    // Asserted by request count as well as by error, because "refused" and
    // "refused before it was sent" are different guarantees and only the second
    // one is free.
    let mock = MockB2::start(ADVERTISED).await;
    let b2 = backend(&mock, None).await;
    let data = Bytes::from_static(b"these are the bytes");

    let error = b2
        .put(
            &ObjectKey::new("o/mislabelled.bin"),
            data,
            &blake3(b"but this is some other file's hash"),
            SourceModified::unknown(),
        )
        .await
        .expect_err("bytes that are not what the caller says they are must not be stored");
    assert!(
        matches!(error, dctl_store::StoreError::ChecksumMismatch { .. }),
        "{error}"
    );
    assert_eq!(
        sent(&mock, "/b2_upload_file/"),
        0,
        "the refusal must come before the upload, not after it"
    );
}
