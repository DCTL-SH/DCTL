//! S3 and R2 against a local S3 endpoint: everything credentials are not needed for.
//!
//! Two of DCTL's five providers had never been run against anything at all.
//! `s3_live.rs` needs an account and this environment has none, so every
//! statement about the S3 family — that it signs correctly, that it addresses
//! path-style, that it pages a listing, that it cuts a multipart upload where it
//! says it does, that it cleans up after a failure — rested on reading the code.
//! Reading the code is how four claims in `HANDOVER.md` §11.4 turned out false.
//!
//! What runs here is the **real** `S3Backend` and the **real** `R2Backend`,
//! unchanged, pointed at [`support::mock_s3`] — a loopback listener that verifies
//! every SigV4 signature by recomputing it independently. What that buys and what
//! it does not is set out in that module's documentation and repeated in
//! `HANDOVER.md`: this proves the protocol DCTL speaks, not the provider's
//! behaviour under load, its consistency model, or its error catalogue.
//!
//! Every test that could be satisfied by a client that did nothing asserts the
//! request the server actually saw, not merely that the call returned `Ok`.
//!
//! ## The provider answering *no*
//!
//! The last group in this file is about the requests S3 refuses, and it needed a
//! fault aimed at an **operation** rather than at the next request to arrive —
//! [`support::mock_s3::When`] says why a positional `script` cannot express one.
//! DCTL issues a multipart upload as a single call, and the provider can refuse
//! it at three moments with three different consequences: nothing opened,
//! parts left billing, or — the expensive one — every byte uploaded and the
//! object still not existing. Four of those arms could be deleted with
//! `cargo test --workspace` staying green before this group existed
//! (`handover-scripts/protocol-2026-07-30/reinstate-before.txt`).

mod support;

use bytes::Bytes;
use dctl_store::Deadlines;
use dctl_store::{
    Backend, ByteRange, ContentHash, HashAlgo, ObjectKey, R2Backend, RetryPolicy, Retrying,
    S3Backend, S3Config, SourceModified, StoreError,
};
use std::sync::Arc;
use std::time::Duration;

/// The real network schedule, with the waiting taken out.
///
/// The delays themselves are asserted exactly in `dctl_store::retry::classify`,
/// which is a pure function and needs no server. Making this suite sleep for
/// fifteen seconds per exhausted-budget test would buy a second, slower copy of
/// that assertion — so what is exercised here is the part only a server can
/// answer: how many requests really left the client, and what arrived.
fn impatient() -> RetryPolicy {
    RetryPolicy {
        first_backoff: Duration::ZERO,
        max_backoff: Duration::ZERO,
        ..RetryPolicy::network()
    }
}

use support::mock_s3::{ACCESS_KEY, BUCKET, MockS3, REGION, SECRET_KEY};

/// Part size the multipart tests run at.
///
/// S3's floor is 5 MiB and [`S3Config::with_part_size`] clamps to it, so this is
/// the smallest value that is honoured rather than raised — which makes it the
/// cheapest way to exercise a real multi-part upload. Before `chunk_size` was
/// wired the part size was a compiled-in 100 MiB and this path could only have
/// been reached by moving 100 MiB per test.
const PART: u64 = 5 * 1024 * 1024;

fn config(endpoint: &str) -> S3Config {
    S3Config::new(endpoint, REGION, BUCKET, ACCESS_KEY, SECRET_KEY)
}

fn backend(mock: &MockS3) -> S3Backend {
    S3Backend::new(config(mock.endpoint()), Deadlines::default()).expect("the backend builds")
}

/// A backend cut at the 5 MiB floor, for the tests whose subject is the parts.
///
/// [`backend`] keeps the shipped 100 MiB `DEFAULT_PART_SIZE`, which is right for
/// every test about an ordinary write. A test about multipart built on it takes
/// the single-shot arm instead and then asserts about parts that were never
/// sent — it does not fail loudly, it stops testing its own subject, which is
/// why this is a named helper and not a `with_part_size` repeated four times.
fn multipart_backend(mock: &MockS3) -> S3Backend {
    S3Backend::new(
        config(mock.endpoint()).with_part_size(Some(PART)),
        Deadlines::default(),
    )
    .expect("the backend builds")
}

fn hash(data: &[u8]) -> ContentHash {
    ContentHash::compute(HashAlgo::Blake3, data)
}

fn key(name: &str) -> ObjectKey {
    ObjectKey::new(name)
}

// ── signing ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn every_request_carries_a_signature_the_server_can_reproduce() {
    // The load-bearing test. The mock recomputes SigV4 from the bytes that
    // arrived and answers 403 SignatureDoesNotMatch on any disagreement, so a
    // canonical URI, canonical query, signed-header list or payload hash that is
    // wrong by one character fails here exactly as it would at AWS.
    let mock = MockS3::start().await;
    let s3 = backend(&mock);
    let data = Bytes::from_static(b"signed and stored");

    s3.put(
        &key("a/b.bin"),
        data.clone(),
        &hash(&data),
        SourceModified::unknown(),
    )
    .await
    .expect("a signed PUT is accepted");
    s3.head(&key("a/b.bin"))
        .await
        .expect("a signed HEAD is accepted");
    s3.get(&key("a/b.bin"))
        .await
        .expect("a signed GET is accepted");
    s3.list_page("a/", None)
        .await
        .expect("a signed LIST is accepted");
    s3.delete(&key("a/b.bin"))
        .await
        .expect("a signed DELETE is accepted");

    // Every one of those really went over the wire; none was short-circuited.
    let state = mock.state();
    assert_eq!(state.count("PUT"), 1);
    assert_eq!(state.count("HEAD"), 1);
    assert_eq!(state.count("DELETE"), 1);
    assert_eq!(state.count("GET"), 2, "one object read and one listing");
}

#[tokio::test]
async fn a_wrong_secret_is_rejected_by_the_signature_rather_than_accepted() {
    // Proves the check above is a check: if the mock accepted anything, every
    // assertion in this file would pass against a client that signed nothing.
    let mock = MockS3::start().await;
    let mut cfg = config(mock.endpoint());
    cfg = S3Config::new(
        cfg.endpoint.clone(),
        REGION,
        BUCKET,
        ACCESS_KEY,
        "not-the-right-secret",
    );
    let s3 = S3Backend::new(cfg, Deadlines::default()).expect("the backend builds");

    let data = Bytes::from_static(b"x");
    let error = s3
        .put(
            &key("k"),
            data.clone(),
            &hash(&data),
            SourceModified::unknown(),
        )
        .await
        .expect_err("a bad signature must not be accepted");
    assert!(
        error.to_string().contains("403") || error.to_string().contains("SignatureDoesNotMatch"),
        "unexpected error: {error}"
    );
    assert!(mock.state().objects.is_empty(), "nothing was stored");
}

#[tokio::test]
async fn a_key_with_characters_that_need_encoding_survives_the_round_trip() {
    // The canonical URI is signed, so a key whose encoding differs between the
    // signature and the request line fails the signature — which is the failure
    // mode a space or a plus in a filename provokes.
    let mock = MockS3::start().await;
    let s3 = backend(&mock);
    let data = Bytes::from_static(b"awkward");

    for name in [
        "holiday photos/a b.jpg",
        "notes+drafts/x.md",
        "caf\u{e9}/re\u{301}sume\u{301}.txt",
        "10%/report.csv",
        "a~b_c-d.e",
    ] {
        s3.put(
            &key(name),
            data.clone(),
            &hash(&data),
            SourceModified::unknown(),
        )
        .await
        .unwrap_or_else(|error| panic!("'{name}' was refused: {error}"));
        let back = s3
            .get(&key(name))
            .await
            .unwrap_or_else(|error| panic!("'{name}': {error}"));
        assert_eq!(back, data, "'{name}' did not round trip");
    }
}

// ── addressing ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn objects_are_addressed_path_style_with_the_bucket_first() {
    // `path_style` is a documented field on S3Config and the only way to see
    // which addressing a request used is to look at the request. A
    // virtual-hosted request would arrive at `/key` and be answered 404 by a
    // server expecting `/{bucket}/{key}` — which is precisely what happens to an
    // operator whose MinIO does not do virtual hosting.
    let mock = MockS3::start().await;
    let s3 = backend(&mock);
    let data = Bytes::from_static(b"placed");
    s3.put(
        &key("deep/tree/file.bin"),
        data.clone(),
        &hash(&data),
        SourceModified::unknown(),
    )
    .await
    .expect("stored");

    let state = mock.state();
    let seen = state.requests_for("PUT", "file.bin");
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0].path,
        format!("/{BUCKET}/deep/tree/file.bin"),
        "the bucket must be the first path segment"
    );
}

#[tokio::test]
async fn a_listing_asks_for_v2_with_the_prefix_and_the_page_size() {
    let mock = MockS3::start().await;
    let s3 = backend(&mock);
    s3.list_page("photos/2024/", None).await.expect("listed");

    let state = mock.state();
    let seen = state
        .requests
        .iter()
        .find(|seen| seen.method == "GET")
        .expect("a GET was made");
    assert_eq!(seen.param("list-type").as_deref(), Some("2"));
    assert_eq!(seen.param("prefix").as_deref(), Some("photos/2024/"));
    assert_eq!(
        seen.param("max-keys").as_deref(),
        Some("1000"),
        "S3's maximum page, so a listing is not multiplied into per-request charges"
    );
}

// ── round trips ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_write_is_readable_whole_and_in_ranges() {
    let mock = MockS3::start().await;
    let s3 = backend(&mock);
    let data = Bytes::from((0u8..=255).cycle().take(4096).collect::<Vec<u8>>());

    s3.put(
        &key("blob"),
        data.clone(),
        &hash(&data),
        SourceModified::unknown(),
    )
    .await
    .expect("stored");
    assert_eq!(s3.get(&key("blob")).await.expect("read"), data);

    // A bounded range, which is what the mount's seek path issues.
    let window = s3
        .get_range(
            &key("blob"),
            ByteRange {
                offset: 1000,
                length: Some(64),
            },
        )
        .await
        .expect("ranged read");
    assert_eq!(window.len(), 64);
    assert_eq!(&window[..], &data[1000..1064]);

    // An open-ended range, which is what a resume issues.
    let tail = s3
        .get_range(
            &key("blob"),
            ByteRange {
                offset: 4000,
                length: None,
            },
        )
        .await
        .expect("open-ended read");
    assert_eq!(&tail[..], &data[4000..]);

    // The Range header really went, rather than the whole object being pulled
    // and sliced locally — the difference is the egress bill.
    let state = mock.state();
    let ranged = state
        .requests
        .iter()
        .filter(|seen| seen.method == "GET" && seen.headers.contains_key("range"))
        .count();
    assert_eq!(ranged, 2);
}

#[tokio::test]
async fn a_put_whose_hash_does_not_match_never_reaches_the_network() {
    // The verified-write contract's cheapest half: the caller's own claim about
    // the bytes is checked before a request is made, so a mismatch costs nothing
    // and stores nothing.
    let mock = MockS3::start().await;
    let s3 = backend(&mock);
    let data = Bytes::from_static(b"actual");
    let wrong = hash(b"something else");

    let error = s3
        .put(&key("k"), data, &wrong, SourceModified::unknown())
        .await
        .expect_err("a mismatch must be refused");
    assert!(
        matches!(error, StoreError::ChecksumMismatch { .. }),
        "{error}"
    );
    assert_eq!(mock.state().requests.len(), 0, "no request was made");
}

#[tokio::test]
async fn a_missing_object_is_not_found_rather_than_a_backend_error() {
    // The distinction every caller branches on: `exists` returns false, `get`
    // returns NotFound, and neither is reported as a transport failure.
    let mock = MockS3::start().await;
    let s3 = backend(&mock);

    assert!(!s3.exists(&key("absent")).await.expect("exists answers"));
    assert!(matches!(
        s3.get(&key("absent")).await.expect_err("get fails"),
        StoreError::NotFound(_)
    ));
    assert!(matches!(
        s3.head(&key("absent")).await.expect_err("head fails"),
        StoreError::NotFound(_)
    ));
    // Delete is idempotent, as S3's is: removing what is not there succeeds.
    s3.delete(&key("absent"))
        .await
        .expect("delete is idempotent");
}

#[tokio::test]
async fn the_source_modification_time_survives_a_write_and_a_head() {
    // The half of the incremental-sync fix that S3 can deliver. `list_page`
    // deliberately reports no time (ListObjectsV2 carries no user metadata), so
    // HEAD is the only place the value can be observed at all — which is why it
    // is asserted through the wire rather than through the renderer.
    let mock = MockS3::start().await;
    let s3 = backend(&mock);
    let data = Bytes::from_static(b"dated");

    s3.put(
        &key("t"),
        data.clone(),
        &hash(&data),
        SourceModified::at(1_577_836_800),
    )
    .await
    .expect("stored");

    let meta = s3.head(&key("t")).await.expect("described");
    assert_eq!(meta.modified_unix, Some(1_577_836_800));
    assert_eq!(meta.size, data.len() as u64);

    // In rclone's spelling, so a bucket written here reads correctly there.
    let state = mock.state();
    assert_eq!(
        state.objects["t"]
            .metadata
            .get("x-amz-meta-mtime")
            .map(String::as_str),
        Some("1577836800.000000000")
    );

    // And a listing still reports no time, which is the documented gap rather
    // than an oversight: substituting the provider's LastModified would make
    // every destination object look newer than its source.
    let page = s3.list_page("", None).await.expect("listed");
    assert!(page.items.iter().all(|item| item.modified_unix.is_none()));
}

// ── pagination ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_listing_crosses_pages_without_losing_or_repeating_an_object() {
    // The failure this catches is silent and total: a continuation token that is
    // sent as the wrong parameter, or not sent at all, produces a listing that
    // stops at the first page. On `sync --delete` in the other direction that is
    // a destination truncated to match a source nobody finished reading.
    let mock = MockS3::start().await;
    let s3 = backend(&mock);

    // The mock pages at whatever `max-keys` asks for; the client asks for 1000,
    // so the corpus has to exceed that to force a second page.
    let total = 2_500;
    for index in 0..total {
        mock.seed(&format!("bulk/{index:05}"), b"x");
    }

    let mut seen: Vec<String> = Vec::new();
    let mut cursor = None;
    let mut pages = 0;
    loop {
        let page = s3.list_page("bulk/", cursor).await.expect("a page lists");
        pages += 1;
        seen.extend(page.items.iter().map(|item| item.key.to_string()));
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
        assert!(pages < 10, "the listing is not terminating");
    }

    assert_eq!(pages, 3, "2,500 objects at 1,000 a page");
    assert_eq!(seen.len(), total, "every object appeared once");
    let unique: std::collections::BTreeSet<&String> = seen.iter().collect();
    assert_eq!(unique.len(), total, "no object appeared twice");
}

#[tokio::test]
async fn a_prefix_scopes_a_listing_to_the_objects_beneath_it() {
    let mock = MockS3::start().await;
    let s3 = backend(&mock);
    mock.seed("photos/a.jpg", b"a");
    mock.seed("photos/2024/b.jpg", b"b");
    mock.seed("photos-backup/c.jpg", b"c");
    mock.seed("other/d.jpg", b"d");

    let page = s3.list_page("photos/", None).await.expect("listed");
    let keys: Vec<String> = page.items.iter().map(|item| item.key.to_string()).collect();
    assert_eq!(keys, ["photos/2024/b.jpg", "photos/a.jpg"]);
}

#[tokio::test]
async fn a_truncated_listing_body_is_an_error_and_never_an_empty_bucket() {
    // The defect the XML parser was hardened against, now provable end to end: a
    // body that stops half way through must not parse as a listing with no
    // objects in it. An empty listing is the worst wrong answer this client can
    // give — `sync --delete` towards the bucket would remove everything in it.
    let mock = MockS3::start().await;
    let s3 = backend(&mock);
    mock.seed("a", b"1");
    mock.script(
        200,
        "<?xml version=\"1.0\"?><ListBucketResult><Contents><Key>a</Key><Size>1</Size>",
    );

    let error = s3
        .list_page("", None)
        .await
        .expect_err("a truncated listing must not read as an empty one");
    assert!(
        error.to_string().contains("truncated") || error.to_string().contains("complete"),
        "{error}"
    );
}

// ── multipart ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_object_at_the_cutoff_is_one_request_and_one_byte_more_is_multipart() {
    // The threshold, asserted at the boundary rather than approximately. It is
    // inclusive — `use_multipart` compares with `>` — so exactly `PART` bytes
    // stays a single PUT.
    let mock = MockS3::start().await;
    let s3 = S3Backend::new(
        config(mock.endpoint()).with_part_size(Some(PART)),
        Deadlines::default(),
    )
    .expect("the backend builds");

    let exact = Bytes::from(vec![b'a'; PART as usize]);
    s3.put(
        &key("exact"),
        exact.clone(),
        &hash(&exact),
        SourceModified::unknown(),
    )
    .await
    .expect("stored");
    assert_eq!(mock.state().count("POST"), 0, "no multipart was started");
    assert_eq!(mock.state().count("PUT"), 1);

    let over = Bytes::from(vec![b'b'; PART as usize + 1]);
    s3.put(
        &key("over"),
        over.clone(),
        &hash(&over),
        SourceModified::unknown(),
    )
    .await
    .expect("stored");

    let state = mock.state();
    assert_eq!(state.count("POST"), 2, "one create and one complete");
    assert_eq!(state.count("PUT"), 3, "one single-shot plus two parts");
    assert_eq!(state.objects["over"].body.len(), PART as usize + 1);
    assert_eq!(state.objects["over"].body, over.to_vec());
    assert_eq!(state.aborted.len(), 0);
    assert_eq!(state.completed.len(), 1);
}

#[tokio::test]
async fn a_multipart_upload_cuts_parts_at_the_configured_size() {
    // What `chunk_size` now controls, and what it controlled before this pass:
    // nothing. The setting was in the config file, in `config providers`, and
    // read by no code at all.
    let mock = MockS3::start().await;
    let s3 = S3Backend::new(
        config(mock.endpoint()).with_part_size(Some(PART)),
        Deadlines::default(),
    )
    .expect("the backend builds");

    let size = PART as usize * 2 + 17;
    let data = Bytes::from(vec![b'c'; size]);
    s3.put(
        &key("cut"),
        data.clone(),
        &hash(&data),
        SourceModified::unknown(),
    )
    .await
    .expect("stored");

    let state = mock.state();
    let parts = state.requests_for("PUT", "cut");
    assert_eq!(parts.len(), 3, "two full parts and a remainder");
    assert_eq!(parts[0].body_len, PART as usize);
    assert_eq!(parts[1].body_len, PART as usize);
    assert_eq!(parts[2].body_len, 17);
    // Numbered from one and in order, which is what the completion manifest
    // claims and what the assembled object depends on.
    assert_eq!(parts[0].param("partNumber").as_deref(), Some("1"));
    assert_eq!(parts[2].param("partNumber").as_deref(), Some("3"));
    assert_eq!(state.objects["cut"].body, data.to_vec());
}

#[tokio::test]
async fn a_streamed_upload_from_a_file_cuts_the_same_parts_as_a_buffered_one() {
    // The two paths are separate code and have to agree, or a large file behaves
    // one way through `put` and another through `put_from_path`.
    let mock = MockS3::start().await;
    let s3 = S3Backend::new(
        config(mock.endpoint()).with_part_size(Some(PART)),
        Deadlines::default(),
    )
    .expect("the backend builds");

    let size = PART as usize * 2 + 17;
    let data = vec![b'd'; size];
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("big.bin");
    std::fs::write(&path, &data).expect("the fixture is written");

    s3.put_from_path(
        &key("streamed"),
        &path,
        &hash(&data),
        SourceModified::at(42),
    )
    .await
    .expect("stored");

    let state = mock.state();
    let parts = state.requests_for("PUT", "streamed");
    assert_eq!(parts.len(), 3);
    assert_eq!(parts[0].body_len, PART as usize);
    assert_eq!(parts[2].body_len, 17);
    assert_eq!(state.objects["streamed"].body, data);
    // The metadata goes on the *create*, not on the parts, which is where S3
    // takes it — putting it on a part would silently lose the timestamp.
    assert_eq!(
        state.objects["streamed"]
            .metadata
            .get("x-amz-meta-mtime")
            .map(String::as_str),
        Some("42.000000000")
    );
}

#[tokio::test]
async fn a_multipart_upload_that_fails_partway_is_aborted_rather_than_left_billing() {
    // Abandoned parts are stored and charged for and appear in no listing. The
    // client aborts on any error; this makes that observable, because the only
    // other evidence is a bill.
    let mock = MockS3::start().await;
    let s3 = S3Backend::new(
        config(mock.endpoint()).with_part_size(Some(PART)),
        Deadlines::default(),
    )
    .expect("the backend builds");

    let data = Bytes::from(vec![b'e'; PART as usize * 2]);
    // The create succeeds; the first part upload is answered 500.
    mock.script(200, "<InitiateMultipartUploadResult><UploadId>scripted</UploadId></InitiateMultipartUploadResult>");
    mock.script(500, "<Error><Code>InternalError</Code></Error>");

    let error = s3
        .put(
            &key("doomed"),
            data.clone(),
            &hash(&data),
            SourceModified::unknown(),
        )
        .await
        .expect_err("the upload must fail");
    assert!(error.to_string().contains("500"), "{error}");

    let state = mock.state();
    assert_eq!(
        state.aborted,
        vec!["scripted".to_string()],
        "the upload the client started must be the upload it aborted"
    );
    assert!(
        !state.objects.contains_key("doomed"),
        "nothing was committed"
    );
}

#[tokio::test]
async fn a_streamed_upload_verifies_the_whole_file_hash_before_committing() {
    // The order that matters: the parts are uploaded, the whole-file hash is
    // checked, and only then is the upload completed. A file that changed under
    // the read must not be committed, and the abort must clean up after it.
    let mock = MockS3::start().await;
    let s3 = S3Backend::new(
        config(mock.endpoint()).with_part_size(Some(PART)),
        Deadlines::default(),
    )
    .expect("the backend builds");

    let data = vec![b'f'; PART as usize + 1];
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("changed.bin");
    std::fs::write(&path, &data).expect("written");

    let error = s3
        .put_from_path(
            &key("mismatch"),
            &path,
            &hash(b"different bytes"),
            SourceModified::unknown(),
        )
        .await
        .expect_err("a hash mismatch must not commit");
    assert!(
        matches!(error, StoreError::ChecksumMismatch { .. }),
        "{error}"
    );

    let state = mock.state();
    assert!(
        !state.objects.contains_key("mismatch"),
        "nothing was committed"
    );
    assert_eq!(state.aborted.len(), 1, "the upload was aborted");
    assert!(state.completed.is_empty(), "no completion was sent");
}

// ── error classification ─────────────────────────────────────────────────────

#[tokio::test]
async fn a_provider_error_is_reported_with_its_status_and_its_code() {
    // What an operator has to be able to act on. `403 InvalidAccessKeyId` and
    // `503 SlowDown` need different responses from a human, and an error that
    // said only "s3 error" would send both to the same place.
    for (status, code) in [
        (403, "InvalidAccessKeyId"),
        (403, "AccessDenied"),
        (503, "SlowDown"),
        (500, "InternalError"),
        (400, "InvalidArgument"),
    ] {
        let mock = MockS3::start().await;
        let s3 = backend(&mock);
        mock.script(status, &format!("<Error><Code>{code}</Code></Error>"));

        let data = Bytes::from_static(b"x");
        let error = s3
            .put(
                &key("k"),
                data.clone(),
                &hash(&data),
                SourceModified::unknown(),
            )
            .await
            .expect_err("a provider error must surface");
        let text = error.to_string();
        assert!(text.contains(&status.to_string()), "{status}: {text}");
        assert!(text.contains(code), "{code}: {text}");
    }
}

#[tokio::test]
async fn a_slow_down_is_retried_until_the_write_succeeds() {
    // The fault this whole layer exists for, driven for real rather than argued
    // about. `503 SlowDown` is the one error AWS documents as "retry with
    // backoff", and until `dctl_store::retry` existed it failed a DCTL write on
    // the **first** response with exactly one request made — because retrying
    // was B2's alone.
    //
    // Asserted on the request the server actually saw, not on `Ok(())`: a
    // wrapper that swallowed the failure and reported success without sending a
    // second `PUT` would satisfy the return value and nothing else.
    let mock = MockS3::start().await;
    let s3 = Retrying::with_policy(Arc::new(backend(&mock)), impatient());
    mock.script(503, "<Error><Code>SlowDown</Code></Error>");
    mock.script(503, "<Error><Code>SlowDown</Code></Error>");

    let data = Bytes::from_static(b"x");
    s3.put(
        &key("k"),
        data.clone(),
        &hash(&data),
        SourceModified::unknown(),
    )
    .await
    .expect("the third attempt is not throttled");

    let state = mock.state();
    assert_eq!(
        state.count("PUT"),
        3,
        "two refusals and the write that stuck"
    );
    assert_eq!(
        state.objects.get("k").map(|o| o.body.clone()),
        Some(data.to_vec()),
        "the object that landed is the one that was asked for"
    );
}

#[tokio::test]
async fn an_exhausted_budget_reports_the_attempts_it_really_made() {
    // The other half, and the one `HANDOVER.md` §11.2 is actually about: when
    // retrying does not help, the failure that reaches the operator has to carry
    // the number of attempts rather than a claim about them. Every backend error
    // used to arrive with the hint "Retries were exhausted" over a run that had
    // made exactly one.
    let mock = MockS3::start().await;
    let policy = impatient();
    let s3 = Retrying::with_policy(Arc::new(backend(&mock)), policy);
    for _ in 0..policy.max_attempts {
        mock.script(503, "<Error><Code>SlowDown</Code></Error>");
    }

    let data = Bytes::from_static(b"x");
    let error = s3
        .put(
            &key("k"),
            data.clone(),
            &hash(&data),
            SourceModified::unknown(),
        )
        .await
        .expect_err("a permanently throttled endpoint cannot be written to");

    assert_eq!(mock.state().count("PUT"), policy.max_attempts as usize);
    assert_eq!(error.attempts(), Some(policy.max_attempts));
    assert!(error.to_string().contains("SlowDown"), "{error}");
}

#[tokio::test]
async fn a_wrong_key_is_refused_once_and_never_retried() {
    // The direction that matters more than the retry itself. A `403` is a stable
    // fact, and classifying it as temporary is what makes a permanently wrong
    // credential produce an exit code telling a scheduler to back off and try
    // again — forever.
    let mock = MockS3::start().await;
    let policy = impatient();
    let s3 = Retrying::with_policy(Arc::new(backend(&mock)), policy);
    mock.script(403, "<Error><Code>InvalidAccessKeyId</Code></Error>");

    let data = Bytes::from_static(b"x");
    let error = s3
        .put(
            &key("k"),
            data.clone(),
            &hash(&data),
            SourceModified::unknown(),
        )
        .await
        .expect_err("a wrong key cannot succeed");

    assert_eq!(mock.state().count("PUT"), 1, "a wrong key is not a wait");
    assert_eq!(
        error.attempts(),
        None,
        "nothing was retried, so nothing may be claimed"
    );
    assert!(error.to_string().contains("InvalidAccessKeyId"), "{error}");
}

#[tokio::test]
async fn a_read_is_retried_as_well_as_a_write() {
    // A wrapper that covered `put` and forwarded the rest would pass every
    // assertion above. The read path is the one a restore depends on.
    let mock = MockS3::start().await;
    let s3 = Retrying::with_policy(Arc::new(backend(&mock)), impatient());
    mock.seed("k", b"restored");
    mock.script(500, "<Error><Code>InternalError</Code></Error>");

    let body = s3
        .get(&key("k"))
        .await
        .expect("the retry reaches the object");
    assert_eq!(body, Bytes::from_static(b"restored"));
    assert_eq!(mock.state().count("GET"), 2);
}

#[tokio::test]
async fn a_server_that_names_a_wait_is_obeyed_and_not_argued_with() {
    // `Retry-After` wins over the client's schedule: waiting less than a
    // throttling server asked for is how being rate-limited becomes being
    // blocked. One second, because the assertion is that the wait *happened*.
    let mock = MockS3::start().await;
    let s3 = Retrying::with_policy(Arc::new(backend(&mock)), impatient());
    mock.script_with_headers(
        503,
        "<Error><Code>SlowDown</Code></Error>",
        &[("Retry-After", "1")],
    );

    let started = std::time::Instant::now();
    let data = Bytes::from_static(b"x");
    s3.put(
        &key("k"),
        data.clone(),
        &hash(&data),
        SourceModified::unknown(),
    )
    .await
    .expect("the second attempt succeeds");
    assert!(
        started.elapsed() >= std::time::Duration::from_millis(900),
        "the server asked for a second and waited {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn the_error_a_provider_returns_still_reads_the_way_it_always_did() {
    // The rendering is a contract: `HANDOVER.md` quotes it and scripts grep for
    // it. Structuring the error so the retry layer can classify it must not have
    // changed one character of what an operator sees.
    let mock = MockS3::start().await;
    let s3 = backend(&mock);
    mock.script(400, "<Error><Code>InvalidArgument</Code></Error>");

    let data = Bytes::from_static(b"x");
    let error = s3
        .put(
            &key("k"),
            data.clone(),
            &hash(&data),
            SourceModified::unknown(),
        )
        .await
        .expect_err("a 400 is refused");
    assert_eq!(error.to_string(), "s3 error 400: InvalidArgument");
    assert_eq!(mock.state().count("PUT"), 1, "a 400 is not a wait");
}

// ── R2 ───────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn the_r2_backend_speaks_the_same_protocol_through_its_own_config() {
    // R2 is a distinct provider type that derives its endpoint and pins its
    // signing region to `auto`. Both are unobservable without a Cloudflare
    // account, so the test drives the real `R2Backend` through the config it
    // builds for itself, with only the endpoint pointed at the mock — which is
    // what an operator with a jurisdiction-specific endpoint does too.
    let mock = MockS3::start().await;
    let mut cfg = R2Backend::config("account-id", BUCKET, ACCESS_KEY, SECRET_KEY);
    assert_eq!(cfg.endpoint, "https://account-id.r2.cloudflarestorage.com");
    assert_eq!(cfg.region, "auto");
    cfg.endpoint = mock.endpoint().to_string();

    let r2 = R2Backend::from_config(cfg, Deadlines::default()).expect("the backend builds");
    let data = Bytes::from_static(b"cloudflare");

    r2.put(
        &key("r2/obj"),
        data.clone(),
        &hash(&data),
        SourceModified::at(7),
    )
    .await
    .expect("stored");
    assert_eq!(r2.get(&key("r2/obj")).await.expect("read"), data);
    assert_eq!(
        r2.head(&key("r2/obj"))
            .await
            .expect("described")
            .modified_unix,
        Some(7)
    );
    assert_eq!(
        r2.name(),
        "r2",
        "the provider names itself in every log line"
    );

    // Signed for `auto`, not for a region carried over from an S3 config. R2
    // answers SignatureDoesNotMatch to anything else, so this is the one thing
    // about R2 that a mock can and must check.
    let state = mock.state();
    let seen = state.requests_for("PUT", "obj");
    let authorization = seen[0]
        .headers
        .get("authorization")
        .expect("a signed request");
    assert!(
        authorization.contains("/auto/s3/aws4_request"),
        "R2 must be signed for the 'auto' region: {authorization}"
    );
}

#[tokio::test]
async fn r2_cuts_multipart_uploads_the_same_way_s3_does() {
    // The R2 backend delegates to the shared client, and this is what proves the
    // delegation is complete rather than partial: the same threshold, the same
    // part boundaries, the same abort behaviour.
    let mock = MockS3::start().await;
    let mut cfg =
        R2Backend::config("account-id", BUCKET, ACCESS_KEY, SECRET_KEY).with_part_size(Some(PART));
    cfg.endpoint = mock.endpoint().to_string();
    let r2 = R2Backend::from_config(cfg, Deadlines::default()).expect("the backend builds");

    let data = Bytes::from(vec![b'g'; PART as usize + 100]);
    r2.put(
        &key("r2big"),
        data.clone(),
        &hash(&data),
        SourceModified::unknown(),
    )
    .await
    .expect("stored");

    let state = mock.state();
    let parts = state.requests_for("PUT", "r2big");
    assert_eq!(parts.len(), 2);
    assert_eq!(parts[0].body_len, PART as usize);
    assert_eq!(parts[1].body_len, 100);
    assert_eq!(state.objects["r2big"].body, data.to_vec());
}

// ── streaming download ───────────────────────────────────────────────────────

#[tokio::test]
async fn a_download_to_a_file_commits_only_a_body_of_the_declared_length() {
    // The S3 override of `get_to_path` streams to a temporary file, checks the
    // committed length against Content-Length, and renames. A short-but-clean
    // body must not be committed as though it were whole.
    let mock = MockS3::start().await;
    let s3 = backend(&mock);
    let data = Bytes::from(vec![b'h'; 100_000]);
    s3.put(
        &key("dl"),
        data.clone(),
        &hash(&data),
        SourceModified::unknown(),
    )
    .await
    .expect("stored");

    let dir = tempfile::tempdir().expect("temp dir");
    let out = dir.path().join("out.bin");
    s3.get_to_path(&key("dl"), &out).await.expect("downloaded");
    assert_eq!(std::fs::read(&out).expect("read back"), data.to_vec());

    // A missing object is NotFound here too, and leaves no partial file behind.
    let absent = dir.path().join("absent.bin");
    assert!(matches!(
        s3.get_to_path(&key("nope"), &absent)
            .await
            .expect_err("fails"),
        StoreError::NotFound(_)
    ));
    assert!(!absent.exists(), "a failed download left a file behind");
}

// ── the streaming put: no spool, same wire ───────────────────────────────────

/// Feed `data` to `s3` through a streaming put, exactly as a vault's sealer does.
async fn streamed_put(s3: &S3Backend, key: &str, data: &[u8]) -> dctl_store::Result<()> {
    use std::io::Write as _;
    let (mut writer, stream) = dctl_store::object_stream(data.len() as u64, HashAlgo::Blake3);
    let owned = data.to_vec();
    let producing = tokio::task::spawn_blocking(move || {
        writer.write_all(&owned).expect("the pipe takes the bytes");
        writer.finish().expect("and the end of them");
    });
    let outcome = s3
        .put_stream(&ObjectKey::new(key), stream, SourceModified::unknown())
        .await;
    producing.await.expect("the producer finished");
    outcome.map(|_| ())
}

#[tokio::test]
async fn a_streamed_multipart_put_stores_the_object_byte_for_byte() {
    // The vault's write path, end to end against a server that assembles the
    // parts in the order it was given them: a client that sent the right bytes in
    // the wrong parts would still round-trip through its own `get`, and would
    // not through this.
    let mock = support::mock_s3::MockS3::start().await;
    let s3 = multipart_backend(&mock);
    let data: Vec<u8> = (0..(PART as usize * 2 + 4096))
        .map(|i| (i % 251) as u8)
        .collect();

    streamed_put(&s3, "o/streamed", &data)
        .await
        .expect("the streamed put stores");

    let state = mock.state();
    assert_eq!(state.completed.len(), 1, "the upload was never completed");
    assert!(state.aborted.is_empty(), "{:?}", state.aborted);
    let stored = s3
        .get(&ObjectKey::new("o/streamed"))
        .await
        .expect("the object reads back");
    assert_eq!(stored.as_ref(), data.as_slice());
}

#[tokio::test]
async fn a_producer_that_dies_mid_object_aborts_the_upload_and_stores_nothing() {
    let mock = support::mock_s3::MockS3::start().await;
    let s3 = multipart_backend(&mock);

    let (mut writer, stream) = dctl_store::object_stream(PART * 3, HashAlgo::Blake3);
    let producing = tokio::task::spawn_blocking(move || {
        use std::io::Write as _;
        let part: Vec<u8> = (0..PART as usize + 4096).map(|i| (i % 251) as u8).collect();
        let _ = writer.write_all(&part);
        drop(writer);
    });
    let error = s3
        .put_stream(
            &ObjectKey::new("o/never-finished"),
            stream,
            SourceModified::unknown(),
        )
        .await
        .expect_err("a stream that stopped must not be committed");
    producing.await.expect("the producer ran");

    assert!(
        error.to_string().contains("stopped before it finished"),
        "{error}"
    );
    let state = mock.state();
    assert!(state.completed.is_empty(), "an upload was completed anyway");
    assert_eq!(state.aborted.len(), 1, "the parts were left billing");
    assert!(!state.objects.contains_key("o/never-finished"));
}

// ── unfinished multipart uploads: seen, and reclaimed ────────────────────────

/// Leave one open upload on the server, the way a `SIGKILL` does.
///
/// DCTL aborts its own on every error path, so the only way to reach the state a
/// killed process leaves is to make the abort itself fail — which is exactly what
/// a process that is no longer running looks like to the server.
async fn abandon_one(mock: &support::mock_s3::MockS3, s3: &S3Backend, key: &str) {
    let (mut writer, stream) = dctl_store::object_stream(PART * 3, HashAlgo::Blake3);
    let producing = tokio::task::spawn_blocking(move || {
        use std::io::Write as _;
        let part: Vec<u8> = (0..PART as usize + 16).map(|i| (i % 251) as u8).collect();
        let _ = writer.write_all(&part);
        drop(writer);
    });
    // The abort is refused for as long as this is set, which is what the server
    // sees when the client is no longer there to send one. A one-shot `script`
    // cannot express it: armed before the put, it is spent on the
    // CreateMultipartUpload and no upload is ever opened.
    mock.refuse_aborts();
    let _ = s3
        .put_stream(&ObjectKey::new(key), stream, SourceModified::unknown())
        .await;
    producing.await.expect("the producer ran");
}

#[tokio::test]
async fn an_upload_no_object_listing_shows_is_enumerated_and_aborted() {
    // §11.3 item 12 on the S3 family. The parts of an incomplete upload are
    // stored and billed and `ListObjectsV2` does not return them, so until
    // `ListMultipartUploads` was wired the only honest thing `cleanup` could say
    // was `unsupported`.
    let mock = support::mock_s3::MockS3::start().await;
    let s3 = multipart_backend(&mock);
    mock.started_seconds_ago(3600);
    abandon_one(&mock, &s3, "o/abandoned").await;

    // It is really there and it is really not an object.
    let objects = s3
        .list_page("", None)
        .await
        .expect("the object listing works");
    assert!(
        objects.items.is_empty(),
        "an incomplete upload must not appear as an object: {:?}",
        objects.items
    );

    let dctl_store::IncompleteUploads::Page(page) = s3
        .list_incomplete_uploads("", None)
        .await
        .expect("the upload listing works")
    else {
        panic!("s3 speaks multipart and must not answer NotMultipart");
    };
    assert_eq!(page.items.len(), 1, "{:?}", page.items);
    assert_eq!(page.items[0].key.as_str(), "o/abandoned");
    let started = page.items[0]
        .started_unix
        .expect("S3 dates every upload with <Initiated>, and --min-age reads it");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after 1970")
        .as_secs() as i64;
    assert!(
        (3500..3700).contains(&(now - started)),
        "an upload started an hour ago read as {} seconds old",
        now - started
    );

    mock.allow_aborts();
    s3.abort_incomplete_upload(&page.items[0])
        .await
        .expect("the abort succeeds");
    let dctl_store::IncompleteUploads::Page(after) = s3
        .list_incomplete_uploads("", None)
        .await
        .expect("the upload listing works")
    else {
        panic!("s3 speaks multipart");
    };
    assert!(after.items.is_empty(), "{:?}", after.items);
}

#[tokio::test]
async fn the_s3_upload_listing_is_scoped_by_prefix_and_paged_by_key_and_id() {
    // The two markers, exercised. S3 allows any number of concurrent uploads
    // against one key, so a pager that resumed from `NextKeyMarker` alone would
    // restart at that key's first upload and never terminate — which is the
    // defect `b2::api::ListFileVersionsResponse` documents for version listings,
    // arriving at a different endpoint.
    let mock = support::mock_s3::MockS3::start().await;
    let s3 = multipart_backend(&mock);
    for key in ["photos/a", "photos/a", "photos/b", "docs/c"] {
        abandon_one(&mock, &s3, key).await;
    }

    let dctl_store::IncompleteUploads::Page(scoped) = s3
        .list_incomplete_uploads("photos/", None)
        .await
        .expect("the upload listing works")
    else {
        panic!("s3 speaks multipart");
    };
    assert_eq!(scoped.items.len(), 3, "{:?}", scoped.items);
    assert!(
        scoped
            .items
            .iter()
            .all(|u| u.key.as_str().starts_with("photos/")),
        "a scoped sweep must not see another prefix's uploads: {:?}",
        scoped.items
    );
    // Two of them are the *same key* and different uploads, which is what makes
    // the id half of the cursor load-bearing.
    let same_key: Vec<&dctl_store::IncompleteUpload> = scoped
        .items
        .iter()
        .filter(|u| u.key.as_str() == "photos/a")
        .collect();
    assert_eq!(same_key.len(), 2);
    assert_ne!(same_key[0].id, same_key[1].id);

    let mut seen: Vec<String> = Vec::new();
    let mut cursor = None;
    for _ in 0..10 {
        let dctl_store::IncompleteUploads::Page(page) = s3
            .list_incomplete_uploads("", cursor.clone())
            .await
            .expect("the upload listing works")
        else {
            panic!("s3 speaks multipart");
        };
        seen.extend(page.items.iter().map(|u| u.id.clone()));
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    assert_eq!(seen.len(), 4, "{seen:?}");
    assert_eq!(
        seen.iter().collect::<std::collections::BTreeSet<_>>().len(),
        4,
        "the pager repeated a page: {seen:?}"
    );
}

// ── the deadline, and the framing it needs ───────────────────────────────────

/// A backend that gives up after `idle` seconds of silence.
fn deadlined(mock: &MockS3, idle: u64) -> S3Backend {
    S3Backend::new(
        config(mock.endpoint()),
        Deadlines::from_seconds(DEADLINE_CONNECT_SECS, idle),
    )
    .expect("the backend builds")
}

/// Long enough that connecting to loopback is never the thing that fails.
const DEADLINE_CONNECT_SECS: u64 = 30;

/// Short enough to measure inside a test, long enough that a loaded machine does
/// not decide the outcome.
const IDLE_SECS: u64 = 2;

#[tokio::test]
async fn a_framed_request_body_still_declares_its_length() {
    // The property the whole upload path rests on, and the one whose failure
    // would look like a provider problem rather than a DCTL one.
    //
    // `--timeout` is an inactivity deadline, so an upload has to report progress
    // as it goes; DCTL cannot see the socket, so it frames the body and reports
    // hyper taking each frame (`dctl_store::deadline::http` says why that is the
    // closest seam reqwest leaves open). A framed body would ordinarily become
    // `Transfer-Encoding: chunked` — and B2's uploader requires `Content-Length`
    // while S3 signs a payload whose length is part of the canonical request, so
    // both would break.
    //
    // `ReportingBody::size_hint` is what prevents it. This is that, asserted on
    // the bytes the server actually received.
    let mock = MockS3::start().await;
    let s3 = backend(&mock);

    let data = Bytes::from(vec![7u8; 300 * 1024]);
    s3.put(
        &key("framed.bin"),
        data.clone(),
        &hash(&data),
        SourceModified::unknown(),
    )
    .await
    .expect("a framed body is accepted");

    let state = mock.state();
    let put = state
        .requests_for("PUT", "framed.bin")
        .first()
        .copied()
        .cloned()
        .expect("the upload really happened");

    assert_eq!(
        put.headers.get("content-length").map(String::as_str),
        Some(data.len().to_string().as_str()),
        "a framed body must declare its exact length: {:?}",
        put.headers
    );
    assert!(
        !put.headers.contains_key("transfer-encoding"),
        "and must not fall back to chunked, which neither provider accepts: {:?}",
        put.headers
    );
    assert_eq!(
        put.body_len,
        data.len(),
        "and every byte must arrive — framing is invisible to the provider or it \
         is a corruption bug rather than a timeout feature"
    );
}

#[tokio::test]
async fn a_provider_that_accepts_and_then_goes_silent_is_given_up_on() {
    // The failure `--timeout` exists for, and the one no status code can
    // express: the connection is established, the request is delivered, and the
    // answer never comes. Without a deadline this is a hang — the retry layer
    // never gets a turn, because nothing ever fails.
    let mock = MockS3::start().await;
    let s3 = deadlined(&mock, IDLE_SECS);
    mock.stall_next();

    let started = std::time::Instant::now();
    let error = s3
        .head(&key("anything.bin"))
        .await
        .expect_err("a request nobody answers must not succeed");
    let took = started.elapsed();

    assert!(
        matches!(&error, StoreError::Transport { .. }),
        "a stall is a transport failure — nothing answered: {error:?}"
    );
    assert!(
        error.to_string().contains("--timeout"),
        "and the report names the dial the operator would turn: {error}"
    );
    assert!(
        took >= Duration::from_secs(IDLE_SECS),
        "it must wait the time it was told to, not less: {took:?}"
    );
    assert!(
        took < Duration::from_secs(IDLE_SECS * 5),
        "and not appreciably more: {took:?}"
    );
}

#[tokio::test]
async fn the_operator_chooses_the_number_and_a_larger_one_really_waits_longer() {
    // The point of the whole entry. `HANDOVER.md` §11.2 recorded that a
    // black-holed network *did* terminate — at 200 s — and that the problem was
    // that 200 s was nobody's choice. Two runs, two numbers, and the difference
    // has to be the operator's.
    let brisk = {
        let mock = MockS3::start().await;
        let s3 = deadlined(&mock, 1);
        mock.stall_next();
        let started = std::time::Instant::now();
        let _ = s3.head(&key("x.bin")).await;
        started.elapsed()
    };
    let patient = {
        let mock = MockS3::start().await;
        let s3 = deadlined(&mock, 4);
        mock.stall_next();
        let started = std::time::Instant::now();
        let _ = s3.head(&key("x.bin")).await;
        started.elapsed()
    };

    assert!(
        patient > brisk + Duration::from_secs(1),
        "the flag has to change the answer: 1 s waited {brisk:?}, 4 s waited {patient:?}"
    );
}

#[tokio::test]
async fn a_transfer_that_keeps_moving_outlives_a_deadline_shorter_than_itself() {
    // **The direction that matters more**, and the one a total-operation
    // deadline would fail. reqwest's own `read_timeout` is armed once per
    // request and never re-armed until the response headers arrive, so wiring
    // `--timeout` to it would have aborted every upload slower than the
    // deadline *while it was succeeding* — which is worse than having no
    // deadline at all, because it destroys work rather than merely waiting.
    //
    // Here the object is large enough to take many frames and the deadline is
    // short. The transfer must complete: every frame the connection takes is
    // progress, and progress is what the deadline is measured against.
    let mock = MockS3::start().await;
    let s3 = deadlined(&mock, IDLE_SECS);

    let data = Bytes::from(vec![3u8; 4 * 1024 * 1024]);
    s3.put(
        &key("slow.bin"),
        data.clone(),
        &hash(&data),
        SourceModified::unknown(),
    )
    .await
    .expect("a transfer that is moving must never be given up on");

    assert_eq!(
        mock.state().objects.get("slow.bin").map(|o| o.body.len()),
        Some(data.len()),
        "and all of it must land"
    );

    let read = s3.get(&key("slow.bin")).await.expect("and read back");
    assert_eq!(read, data);
}

#[tokio::test]
async fn a_run_that_asked_for_no_deadline_waits_for_a_silent_provider() {
    // Zero is rclone's "wait forever" (`fs/fshttp/dialer.go:102`,
    // `if c.timeout > 0`), and it has to genuinely disable the clock rather than
    // be read as a deadline of no length — which would abort every request
    // instantly and look, from the outside, like a broken network.
    //
    // Proved by outliving a deadline that would have fired several times over,
    // rather than by waiting forever, which no test can do.
    let mock = MockS3::start().await;
    let s3 =
        S3Backend::new(config(mock.endpoint()), Deadlines::none()).expect("the backend builds");
    mock.stall_next();

    let outcome = tokio::time::timeout(
        Duration::from_secs(IDLE_SECS * 2),
        s3.head(&key("anything.bin")),
    )
    .await;

    assert!(
        outcome.is_err(),
        "with no deadline the request must still be waiting, not reporting a \
         timeout DCTL invented: {outcome:?}"
    );
}

// ── the three ways a multipart upload fails, told apart ──────────────────────
//
// `HANDOVER.md` §11.3 item 10. DCTL issues a multipart upload as one call, and
// the provider can refuse it at three different moments with three different
// consequences:
//
//   * the **create** is refused — nothing was ever opened, so there is nothing to
//     abort and nothing to bill, and the only wrong answer is reporting success;
//   * a **part** is refused — parts are stored and charged for, so an upload
//     abandoned here costs money until somebody notices (covered above by
//     `a_multipart_upload_that_fails_partway_is_aborted_rather_than_left_billing`);
//   * the **complete** is refused — every byte arrived, and the object still does
//     not exist. This is the expensive one to get wrong: a client that read the
//     completion's status loosely has uploaded a 4 GiB object, been told no, and
//     reported yes.
//
// Reaching the first and third needs a fault aimed at *an operation* rather than
// at the next request to arrive, which is what `MockS3::fail` and `When` are
// for — `support::mock_s3::When` documents why a positional `script` cannot
// express it. Before them, six `return Err` arms across these paths were
// unreachable in the plain gate.

use support::mock_s3::When;

/// The five hundred a provider gives when its own storage is unhappy.
const INTERNAL_ERROR: &str =
    "<Error><Code>InternalError</Code><Message>we are sorry</Message></Error>";

#[tokio::test]
async fn a_refused_create_never_reports_an_object_that_was_never_started() {
    // Three separate copies of this arm — the buffered `put`, the streaming
    // `put_from_path`, and the producer-fed `put_stream` — because each opens
    // its own upload. All three were unreachable. A backend that reported
    // success here would have `sync` record the object as transferred and never
    // look at it again.
    let mock = MockS3::start().await;
    let s3 = multipart_backend(&mock);
    let data = vec![b'c'; PART as usize + 32];

    mock.fail(
        "POST",
        When::Carrying("uploads".into()),
        503,
        INTERNAL_ERROR,
    );

    // Buffered.
    let error = s3
        .put(
            &key("buffered"),
            Bytes::from(data.clone()),
            &hash(&data),
            SourceModified::unknown(),
        )
        .await
        .expect_err("an upload that was never opened is not a stored object");
    assert!(error.to_string().contains("503"), "{error}");

    // Streamed from a file.
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("big.bin");
    std::fs::write(&path, &data).expect("written");
    let error = s3
        .put_from_path(
            &key("from-path"),
            &path,
            &hash(&data),
            SourceModified::unknown(),
        )
        .await
        .expect_err("nor is one whose create was refused");
    assert!(error.to_string().contains("503"), "{error}");

    // Fed by a producer. Not `streamed_put`: that helper insists the producer
    // hands over every byte, and here it must not — a create the provider
    // refused means nothing downstream is reading, so the write side is
    // *supposed* to be cut off part-way. A helper that asserted otherwise would
    // report this arm as a producer fault.
    let (mut writer, stream) = dctl_store::object_stream(data.len() as u64, HashAlgo::Blake3);
    let owned = data.clone();
    let producing = tokio::task::spawn_blocking(move || {
        use std::io::Write as _;
        let _ = writer.write_all(&owned);
        drop(writer);
    });
    let error = s3
        .put_stream(&key("streamed"), stream, SourceModified::unknown())
        .await
        .expect_err("nor is one fed by a producer");
    producing.await.expect("the producer ran");
    assert!(error.to_string().contains("503"), "{error}");

    let state = mock.state();
    assert!(state.objects.is_empty(), "{:?}", state.objects.keys());
    assert!(state.completed.is_empty(), "{:?}", state.completed);
    // Nothing to abort: an upload that was never created has no id, and a client
    // that sent an abort here would be guessing at one.
    assert!(
        state.aborted.is_empty(),
        "an upload that never opened must not be aborted: {:?}",
        state.aborted
    );
}

#[tokio::test]
async fn a_refused_completion_is_a_failure_even_though_every_byte_arrived() {
    // The one that matters most and the one a loose client gets wrong. Every
    // part is on the provider and acknowledged; only the call that turns them
    // into an object is refused. There is no local signal — the bytes went out,
    // the hashes matched, the parts were accepted — so the *only* thing standing
    // between this and a false success is reading the completion's status.
    let mock = MockS3::start().await;
    let s3 = multipart_backend(&mock);
    let data = vec![b'd'; PART as usize * 2];

    mock.fail(
        "POST",
        When::Carrying("uploadId".into()),
        500,
        INTERNAL_ERROR,
    );

    let error = s3
        .put(
            &key("never-committed"),
            Bytes::from(data.clone()),
            &hash(&data),
            SourceModified::unknown(),
        )
        .await
        .expect_err("an upload the provider refused to complete is not stored");
    assert!(error.to_string().contains("500"), "{error}");

    // And the producer-fed writer, which is the one a vault actually uses and
    // which carries its **own** copy of this check — three writers, three
    // copies, and a test that covered two of them would leave the third
    // deletable with the gate staying green.
    let error = streamed_put(&s3, "streamed-never-committed", &data)
        .await
        .expect_err("nor may the producer-fed writer commit an upload S3 refused");
    assert!(error.to_string().contains("500"), "{error}");

    let state = mock.state();
    // The parts really did arrive, or this proves nothing about the completion.
    assert!(
        state.count("PUT") >= 2,
        "the parts were never uploaded, so the completion is not what failed: {}",
        state.count("PUT")
    );
    assert!(
        !state.objects.contains_key("never-committed"),
        "the object exists, which means the client's own view is what committed it"
    );
    assert!(state.completed.is_empty(), "{:?}", state.completed);
    assert!(
        !state.objects.contains_key("streamed-never-committed"),
        "the streamed writer committed an object the provider refused"
    );
}

#[tokio::test]
async fn a_producer_that_declares_more_than_it_supplies_commits_nothing() {
    // The other half of `HANDOVER.md` §26.1's worst outcome, on S3's two
    // streaming arms: a producer that ends **cleanly** having handed over fewer
    // bytes than it declared. Nothing errors — the stream closes properly, every
    // part that was sent was accepted — so the only thing between this and a
    // short object stored under the right name is the client comparing what it
    // filled against what it was promised.
    //
    // Both arms carry their own copy of that comparison, because the object goes
    // through a different one either side of the multipart threshold, and the
    // sub-threshold arm is the one a small file takes.
    let mock = MockS3::start().await;
    let s3 = multipart_backend(&mock);

    // Above the threshold: the multipart loop's per-part check.
    let declared = PART * 3;
    let (mut writer, stream) = dctl_store::object_stream(declared, HashAlgo::Blake3);
    let producing = tokio::task::spawn_blocking(move || {
        use std::io::Write as _;
        let part = vec![b'h'; PART as usize + 4096];
        writer
            .write_all(&part)
            .expect("the pipe takes what there is");
        writer.finish().expect("and the producer says it is done");
    });
    let error = s3
        .put_stream(&key("short-multipart"), stream, SourceModified::unknown())
        .await
        .expect_err("an object shorter than its declaration must not be committed");
    producing.await.expect("the producer ran");
    assert!(
        matches!(error, StoreError::ShortWrite { .. }),
        "a short object is a write that stopped, not a checksum failure: {error:?}"
    );

    // Below the threshold: the single-shot arm's whole-object check.
    let (mut writer, stream) = dctl_store::object_stream(4096, HashAlgo::Blake3);
    let producing = tokio::task::spawn_blocking(move || {
        use std::io::Write as _;
        writer
            .write_all(&[b'i'; 512])
            .expect("the pipe takes what there is");
        writer.finish().expect("and the producer says it is done");
    });
    let error = s3
        .put_stream(&key("short-single"), stream, SourceModified::unknown())
        .await
        .expect_err("nor may the one-request arm commit a short object");
    producing.await.expect("the producer ran");
    assert!(matches!(error, StoreError::ShortWrite { .. }), "{error:?}");

    let state = mock.state();
    assert!(
        !state.objects.contains_key("short-multipart")
            && !state.objects.contains_key("short-single"),
        "a short object was stored: {:?}",
        state.objects.keys().collect::<Vec<_>>()
    );
    assert!(state.completed.is_empty(), "{:?}", state.completed);
    // The multipart attempt opened an upload, so it has to have been closed
    // again — a short producer that left parts billing would be §24.1's defect
    // with a different cause.
    assert_eq!(state.aborted.len(), 1, "{:?}", state.aborted);

    // **Where the multipart arm's own length check earns its place**, and the
    // only observable it has. Refusing the object is not it: `sealed()` after
    // the loop refuses it anyway, with the same error. What the per-part check
    // buys is refusing it *before* the padding goes on the wire.
    //
    // Without it, `fill` returns 1 MiB into a 5 MiB buffer and the other 4 MiB
    // are the zeroes the buffer was allocated with — so all three planned parts
    // are uploaded, in full, to a provider that charges for them, and only then
    // is the object refused. Three parts instead of one, and 15 MiB of mostly
    // zeroes across somebody's uplink, for an object that was never going to
    // exist. The plan was three parts; the count is what says so.
    let parts = state
        .requests
        .iter()
        .filter(|seen| seen.method == "PUT" && seen.param("partNumber").is_some())
        .count();
    assert_eq!(
        parts, 1,
        "a short producer must be noticed at the first part, not after every          planned part has been uploaded and paid for: {parts} part uploads"
    );
}

#[test]
fn the_single_shot_arms_own_length_check_cannot_fire_and_the_line_above_it_is_why() {
    // An **arithmetic argument** rather than a test, in the shape
    // `HANDOVER.md` §26.5 names for exactly this case — a guard whose
    // precondition the code above it already disposes of. It is here so that
    // the claim is checked by the compiler and by a reader, rather than being a
    // comment somebody deletes.
    //
    // `put_object_stream`'s sub-multipart arm reads:
    //
    //     let filled = source.fill(&mut whole).await?;
    //     let expected = source.sealed().await?;      // <-- returns ShortWrite
    //     if filled as u64 != size { return Err(ShortWrite { .. }) }
    //
    // `sealed` is `window()` followed by `agreed()`, and `agreed` refuses with
    // `StoreError::ShortWrite { expected: len, actual: consumed }` whenever the
    // producer handed over fewer bytes than it declared
    // (`incoming/stream.rs`). `filled` **is** `consumed` for this arm — one
    // `fill` over one buffer of exactly `size` — so `filled != size` implies
    // `consumed != len`, which means the `?` one line earlier has already
    // returned. The third line is unreachable, and its error would be identical
    // if it were not.
    //
    // The `?` ordering is the whole of it, and it is not accidental: `sealed`
    // has to run before anything is committed, and running it before the length
    // check is what makes the *stricter* refusal the one that fires. A future
    // edit that moved `sealed` below the check would make the check reachable
    // and this test's name a lie — which is the failure mode worth a test.
    //
    // Asserted rather than asserted-about: the same short-producer input, driven
    // through the real backend, must come back with the error `agreed` produces.
    // The assertion is on the *numbers*, because that is what tells the two
    // apart — `agreed` reports the whole object's declaration and what arrived,
    // while the dead check would report the same two values by construction.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    runtime.block_on(async {
        let mock = MockS3::start().await;
        let s3 = multipart_backend(&mock);
        let (mut writer, stream) = dctl_store::object_stream(4096, HashAlgo::Blake3);
        let producing = tokio::task::spawn_blocking(move || {
            use std::io::Write as _;
            writer.write_all(&[b'j'; 700]).expect("the pipe takes it");
            writer.finish().expect("and the producer closes");
        });
        let error = s3
            .put_stream(&key("dead-check"), stream, SourceModified::unknown())
            .await
            .expect_err("a short object is refused either way");
        producing.await.expect("the producer ran");

        match error {
            StoreError::ShortWrite { expected, actual } => {
                assert_eq!(expected, 4096, "the declaration");
                assert_eq!(actual, 700, "and what really arrived");
            }
            other => panic!("the refusal changed shape: {other:?}"),
        }
        assert!(
            mock.state().objects.is_empty(),
            "and nothing may be stored either way"
        );
    });
}

#[tokio::test]
async fn a_refused_single_shot_put_is_not_a_stored_object() {
    // The other half of the same rule, on the path every small object takes.
    // `When::Without` is what separates it from a part upload: same method, same
    // path, and only the absence of `?partNumber` tells them apart.
    let mock = MockS3::start().await;
    let s3 = backend(&mock);
    let data = b"small enough for one request";

    mock.fail(
        "PUT",
        When::Without("partNumber".into()),
        403,
        "<Error><Code>AccessDenied</Code></Error>",
    );

    let error = s3
        .put(
            &key("refused"),
            Bytes::from_static(data),
            &hash(data),
            SourceModified::unknown(),
        )
        .await
        .expect_err("a refused write is not a write");
    assert!(error.to_string().contains("403"), "{error}");
    assert!(error.to_string().contains("AccessDenied"), "{error}");
    assert!(mock.state().objects.is_empty());

    // And the same backend stores once the provider stops refusing — so the
    // failure above was the rule and not a broken fixture.
    mock.clear_rules();
    s3.put(
        &key("refused"),
        Bytes::from_static(data),
        &hash(data),
        SourceModified::unknown(),
    )
    .await
    .expect("the write succeeds once the refusal is lifted");
    assert_eq!(
        s3.get(&key("refused"))
            .await
            .expect("it reads back")
            .as_ref(),
        data
    );
}

#[tokio::test]
async fn a_completion_refused_once_succeeds_on_the_retry_and_commits_exactly_one_object() {
    // The recovery half, and the reason `fail_once` exists beside `fail`. A
    // provider hiccup on the completion is transient, so the retry layer should
    // carry it — but a retry that re-ran the *whole* upload would double the
    // bytes on the wire and leave the first upload's parts billing, and a retry
    // that completed twice would be a client the provider has to de-duplicate
    // for.
    let mock = MockS3::start().await;
    let s3 = Retrying::with_policy(
        Arc::new(multipart_backend(&mock)) as Arc<dyn Backend>,
        impatient(),
    );
    let data = vec![b'g'; PART as usize * 2];

    mock.fail_once(
        "POST",
        When::Carrying("uploadId".into()),
        503,
        INTERNAL_ERROR,
    );

    s3.put(
        &key("eventually"),
        Bytes::from(data.clone()),
        &hash(&data),
        SourceModified::unknown(),
    )
    .await
    .expect("a transient completion failure is retried through");

    let state = mock.state();
    assert_eq!(
        state.completed.len(),
        1,
        "exactly one upload may be completed: {:?}",
        state.completed
    );
    assert_eq!(
        state.objects.get("eventually").map(|o| o.body.len()),
        Some(data.len()),
        "and the object has to be whole"
    );
}
