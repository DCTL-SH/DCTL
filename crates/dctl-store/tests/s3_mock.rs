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

mod support;

use bytes::Bytes;
use dctl_store::{
    Backend, ByteRange, ContentHash, HashAlgo, ObjectKey, R2Backend, S3Backend, S3Config,
    SourceModified, StoreError,
};

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
    S3Backend::new(config(mock.endpoint())).expect("the backend builds")
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
    let s3 = S3Backend::new(cfg).expect("the backend builds");

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
    let s3 = S3Backend::new(config(mock.endpoint()).with_part_size(Some(PART)))
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
    let s3 = S3Backend::new(config(mock.endpoint()).with_part_size(Some(PART)))
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
    let s3 = S3Backend::new(config(mock.endpoint()).with_part_size(Some(PART)))
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
    let s3 = S3Backend::new(config(mock.endpoint()).with_part_size(Some(PART)))
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
    let s3 = S3Backend::new(config(mock.endpoint()).with_part_size(Some(PART)))
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
async fn a_retryable_status_is_not_retried_and_that_is_a_known_gap() {
    // Not an aspiration — a measurement. B2 has `b2/retry.rs`; the S3 family has
    // nothing, so a 503 SlowDown, which is the one error AWS documents as
    // "retry with backoff", fails the transfer on the first response. This test
    // pins the *current* behaviour so that adding a retry layer is a visible
    // change rather than a silent one, and `HANDOVER.md` §11.3 carries it as an
    // open item rather than as a claim that S3 retries.
    let mock = MockS3::start().await;
    let s3 = backend(&mock);
    mock.script(503, "<Error><Code>SlowDown</Code></Error>");

    let data = Bytes::from_static(b"x");
    let error = s3
        .put(
            &key("k"),
            data.clone(),
            &hash(&data),
            SourceModified::unknown(),
        )
        .await
        .expect_err("a 503 fails the write today");
    assert!(error.to_string().contains("SlowDown"), "{error}");
    assert_eq!(
        mock.state().count("PUT"),
        1,
        "exactly one attempt: there is no request-level retry on the S3 path"
    );
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

    let r2 = R2Backend::from_config(cfg).expect("the backend builds");
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
    let r2 = R2Backend::from_config(cfg).expect("the backend builds");

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
