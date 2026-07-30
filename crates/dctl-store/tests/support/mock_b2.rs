//! A local HTTP listener that speaks enough of the B2 native API to hold the B2
//! backend to account without spending a live bucket on it.
//!
//! ## Why this exists
//!
//! B2 is the one cloud provider this repository has credentials for, which made
//! it the *only* one whose upload behaviour was ever measured — and the measuring
//! was done by copying gigabytes into a real bucket inside a cgroup. That is the
//! right way to establish a memory figure and the wrong way to keep it: the
//! statement "an upload holds one part and not two" is a property of a few lines
//! in `b2::upload`, and a property that can only be re-checked by uploading a
//! gigabyte is a property that stops being re-checked.
//!
//! Only [`B2Backend::with_authorize_url`] is needed to point the whole client
//! here: B2's authorization reply carries the `apiUrl` every later call is built
//! on, and `b2_get_upload_url` hands out the per-pod URL each upload lands on. So
//! this server answers `b2_authorize_account` with its own address and directs
//! the rest of the conversation from there, exactly as Backblaze does.
//!
//! ## What it proves, and what it cannot
//!
//! It **verifies the SHA-1 of every body it receives** against the
//! `X-Bz-Content-Sha1` header the client sent, and answers `400` on a mismatch —
//! the check B2 itself makes, and the one that separates "the bytes arrived" from
//! "a request arrived". It enforces the large-file rules that produce a rejected
//! upload at the ten-thousandth part rather than the first: parts numbered from
//! one, contiguous, and a `partSha1Array` at finish that matches what was sent.
//!
//! It proves nothing about Backblaze's own behaviour — its pod rotation, its
//! consistency, its error catalogue, its throughput. `b2_live.rs` and the cgroup
//! measurements in `HANDOVER.md` §25 are what cover those, and this file is not a
//! substitute for either.
//!
//! ## Large bodies are counted and hashed, never kept
//!
//! Deliberate, and load-bearing for `tests/b2_upload_memory.rs`: that test reads
//! the process's own peak resident memory, and this server lives in the same
//! process. A mock that held each part would put its own buffers into the number
//! being measured and quietly make the client look twice as expensive as it is.
//! Anything over [`BODY_KEEP_LIMIT`] is streamed through a hasher in
//! [`READ_CHUNK`]-sized reads and dropped.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use sha1::{Digest, Sha1};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// The application key pair every test authorizes with. Not secrets: this server
/// is bound to loopback on an ephemeral port and lives for one test.
pub const KEY_ID: &str = "0011223344556677889900000";
pub const APP_KEY: &str = "K001mockapplicationkeynotreal";
/// The bucket the server answers for, and the id it reports for it.
pub const BUCKET: &str = "dctl-mock-b2";
pub const BUCKET_ID: &str = "b2b1c0ffee00000000000001";
/// The account the key belongs to.
pub const ACCOUNT_ID: &str = "0011223344556677";

/// Bodies at or below this are kept so a test can assert what arrived; bigger
/// ones are hashed and counted only.
///
/// One mebibyte covers every JSON request the client makes by three orders of
/// magnitude and excludes every part, which is the split that matters — see the
/// module documentation for why a mock that kept parts would corrupt the memory
/// measurement it is there to support.
pub const BODY_KEEP_LIMIT: usize = 1024 * 1024;

/// Read granularity for a body that is not kept.
const READ_CHUNK: usize = 64 * 1024;

/// One request, as the server saw it.
#[derive(Clone, Debug)]
pub struct Seen {
    pub method: String,
    /// Path with no query string, exactly as it arrived.
    pub path: String,
    pub headers: BTreeMap<String, String>,
    /// How many body bytes arrived, whether or not they were kept.
    pub body_len: usize,
    /// SHA-1 of the body, hex, computed from the bytes on the wire.
    pub body_sha1: String,
    /// The body itself, for the small ones. `None` above [`BODY_KEEP_LIMIT`].
    pub body: Option<Vec<u8>>,
}

impl Seen {
    /// A header's value, by lower-case name.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }

    /// The body parsed as JSON, for the endpoints that send one.
    #[must_use]
    pub fn json(&self) -> Option<serde_json::Value> {
        serde_json::from_slice(self.body.as_ref()?).ok()
    }
}

/// One part of one large file, as it arrived: how big and what it hashed to.
///
/// Not the bytes. See the module documentation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartReceipt {
    pub number: u32,
    pub len: usize,
    pub sha1: String,
}

/// One large file the server is holding open.
#[derive(Clone, Debug, Default)]
pub struct LargeFile {
    pub name: String,
    pub parts: Vec<PartReceipt>,
    pub finished: bool,
    pub cancelled: bool,
    /// The `partSha1Array` the finish call named, in order.
    pub finished_with: Vec<String>,
    /// When `b2_start_large_file` was called, in epoch milliseconds — what
    /// `b2_list_unfinished_large_files` reports and what `--min-age` reads.
    ///
    /// Settable by a test, because the whole point of the age is to separate an
    /// upload somebody abandoned last week from one another process is half way
    /// through, and a test that had to sleep through a `--min-age` to say so
    /// would be slower and no more convincing.
    pub started_millis: i64,
}

/// One object stored through the single-shot path: its length and hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SingleUpload {
    pub name: String,
    pub len: usize,
    pub sha1: String,
}

/// A failure the server will answer with instead of doing the real thing.
#[derive(Clone, Debug)]
struct Scripted {
    /// Which path suffix it applies to, so a test can fail an upload without
    /// failing the authorization that precedes it.
    path_suffix: String,
    status: u16,
    body: String,
}

/// Everything the server remembers.
#[derive(Clone, Debug, Default)]
pub struct State {
    pub requests: Vec<Seen>,
    /// Single-shot uploads, in arrival order.
    pub singles: Vec<SingleUpload>,
    /// Large files by file id, in creation order.
    pub large: Vec<LargeFile>,
    scripted: Vec<Scripted>,
    next_id: u64,
    /// The `recommendedPartSize` authorization reports.
    recommended_part_size: u64,
    /// The id `b2_list_buckets` reports for [`BUCKET`], or [`None`] when the
    /// bucket is not there at all.
    ///
    /// Separate from the id authorization hands out in its `allowed` block,
    /// because those two answers coming apart is the whole subject of the
    /// store-identity guard: a run authorizes once and caches what it was told,
    /// and the bucket can be deleted and re-created underneath it afterwards.
    bucket_id: Option<String>,
    /// What every upload response reports as `contentSha1`, when it is not to be
    /// the hash of the bytes that actually arrived.
    ///
    /// The one thing a provider can do that no amount of care on this side
    /// prevents: accept the bytes, answer `200`, and describe something else.
    /// DCTL's whole claim about a stored object rests on comparing the receipt
    /// against the digest it sent, so a mock that always echoes honestly can
    /// never show that the comparison happens.
    echoed_sha1: Option<String>,
    /// The `uploadTimestamp` the next `b2_start_large_file` records, in epoch
    /// milliseconds.
    ///
    /// Settable so a test can age an upload without sleeping through a
    /// `--min-age`. Defaults to the clock, which is what a real server does.
    start_time_millis: i64,
}

impl State {
    /// How many requests arrived whose path ends with `suffix`.
    #[must_use]
    pub fn count(&self, suffix: &str) -> usize {
        self.requests
            .iter()
            .filter(|seen| seen.path.ends_with(suffix))
            .count()
    }

    /// Requests whose path ends with `suffix`, in arrival order.
    #[must_use]
    pub fn requests_for(&self, suffix: &str) -> Vec<&Seen> {
        self.requests
            .iter()
            .filter(|seen| seen.path.ends_with(suffix))
            .collect()
    }
}

/// A running mock B2 endpoint.
pub struct MockB2 {
    authorize_url: String,
    state: Arc<Mutex<State>>,
}

impl MockB2 {
    /// Bind an ephemeral loopback port and start serving.
    ///
    /// `recommended_part_size` is what authorization reports. It is a parameter
    /// because DCTL deliberately does **not** size uploads from it — see
    /// `b2::constants::DEFAULT_PART_SIZE` — and a test that proves the client
    /// ignores B2's advice needs the advice to be something else.
    pub async fn start(recommended_part_size: u64) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port is available");
        let port = listener
            .local_addr()
            .expect("the listener has an address")
            .port();
        let state = Arc::new(Mutex::new(State {
            recommended_part_size,
            bucket_id: Some(BUCKET_ID.to_string()),
            start_time_millis: now_millis(),
            ..State::default()
        }));
        let base = format!("http://127.0.0.1:{port}");
        let serving = Arc::clone(&state);
        let serving_base = base.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let state = Arc::clone(&serving);
                let base = serving_base.clone();
                tokio::spawn(async move {
                    // A connection that dies mid-request is the client going
                    // away, which the retry tests do deliberately.
                    let _ = serve(stream, state, base).await;
                });
            }
        });
        Self {
            authorize_url: format!("{base}/b2api/v2/b2_authorize_account"),
            state,
        }
    }

    /// What `B2Backend::with_authorize_url` should be given.
    #[must_use]
    pub fn authorize_url(&self) -> &str {
        &self.authorize_url
    }

    /// An owned copy of everything the server has seen.
    ///
    /// A snapshot rather than a guard, for the reason `mock_s3` gives at length:
    /// a `MutexGuard` held across an `.await` in a `#[tokio::test]` compiles and
    /// then deadlocks against the task recording the next request.
    #[must_use]
    pub fn state(&self) -> State {
        self.state
            .lock()
            .expect("the mock state is not poisoned")
            .clone()
    }

    /// The bucket is gone: `b2_list_buckets` stops reporting it.
    ///
    /// What a customer does with `b2 delete-bucket` while a long run is in
    /// flight, and what a store-identity probe has to be able to see. The
    /// authorization this run already cached still names the old id, which is
    /// exactly why a guard that read the cached value would answer "carry on".
    pub fn delete_bucket(&self) {
        self.state
            .lock()
            .expect("the mock state is not poisoned")
            .bucket_id = None;
    }

    /// The next `b2_start_large_file` records an upload that started `seconds`
    /// ago.
    ///
    /// So a test can put an upload on the wrong side of a `--min-age` without
    /// sleeping through one — which would be slower and no more convincing.
    pub fn started_seconds_ago(&self, seconds: i64) {
        if let Ok(mut state) = self.state.lock() {
            state.start_time_millis = now_millis() - seconds * 1000;
        }
    }

    /// Every subsequent upload response reports `sha1` rather than the hash of
    /// what arrived.
    ///
    /// A `200` with a wrong receipt, which is the shape of the failure that
    /// matters: an error would be caught by any code path at all, and a rejected
    /// upload is a retry. This is the provider saying it stored something other
    /// than what was sent, in the one field that could say so.
    pub fn echo_sha1(&self, sha1: &str) {
        self.state
            .lock()
            .expect("the mock state is not poisoned")
            .echoed_sha1 = Some(sha1.to_string());
    }

    /// The bucket is back under the same name and a **new** id — B2 mints one per
    /// creation, and that is what makes a bucket identity distinguishing rather
    /// than merely present.
    pub fn recreate_bucket(&self, bucket_id: &str) {
        self.state
            .lock()
            .expect("the mock state is not poisoned")
            .bucket_id = Some(bucket_id.to_string());
    }

    /// Answer the next request whose path ends with `path_suffix` with `status`
    /// and `body` instead of doing the real thing, once.
    pub fn fail_next(&self, path_suffix: &str, status: u16, code: &str) {
        self.state
            .lock()
            .expect("the mock state is not poisoned")
            .scripted
            .push(Scripted {
                path_suffix: path_suffix.to_string(),
                status,
                body: format!(
                    r#"{{"status":{status},"code":"{code}","message":"scripted by the mock"}}"#
                ),
            });
    }
}

/// Serve one connection: one request, one response, then close.
///
/// No keep-alive, for the reason `mock_s3` gives: deciding when a client has
/// finished is the part of HTTP worth not re-implementing, and `reqwest` handles
/// `Connection: close` perfectly well.
async fn serve(
    mut stream: TcpStream,
    state: Arc<Mutex<State>>,
    base: String,
) -> std::io::Result<()> {
    let mut buffer = Vec::new();
    let mut chunk = vec![0u8; READ_CHUNK];

    let head_end = loop {
        if let Some(index) = find_subsequence(&buffer, b"\r\n\r\n") {
            break index + 4;
        }
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Ok(());
        }
        buffer.extend_from_slice(&chunk[..read]);
    };

    let head = String::from_utf8_lossy(&buffer[..head_end]).into_owned();
    let mut lines = head.lines();
    let Some(request_line) = lines.next() else {
        return respond(&mut stream, 400, b"").await;
    };
    let mut parts = request_line.split_whitespace();
    let (Some(method), Some(target)) = (parts.next(), parts.next()) else {
        return respond(&mut stream, 400, b"").await;
    };
    let method = method.to_string();
    let path = target
        .split_once('?')
        .map_or(target, |(p, _)| p)
        .to_string();

    let mut headers: BTreeMap<String, String> = BTreeMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }

    // Read exactly the declared body, hashing as it arrives and keeping it only
    // if it is small. Every request the client makes sets Content-Length; a
    // chunked body would be a change worth failing on rather than guessing at.
    let want: usize = headers
        .get("content-length")
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    let keep = want <= BODY_KEEP_LIMIT;
    let mut hasher = Sha1::new();
    let mut kept: Vec<u8> = Vec::new();
    let mut have = 0usize;

    let carried = buffer.len().saturating_sub(head_end).min(want);
    if carried > 0 {
        let slice = &buffer[head_end..head_end + carried];
        hasher.update(slice);
        if keep {
            kept.extend_from_slice(slice);
        }
        have = carried;
    }
    while have < want {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        let take = read.min(want - have);
        hasher.update(&chunk[..take]);
        if keep {
            kept.extend_from_slice(&chunk[..take]);
        }
        have += take;
    }
    let body_sha1 = hex::encode(hasher.finalize());

    let seen = Seen {
        method,
        path: path.clone(),
        headers,
        body_len: have,
        body_sha1,
        body: keep.then_some(kept),
    };

    let (status, body) = {
        let mut guard = state.lock().expect("the mock state is not poisoned");
        guard.requests.push(seen.clone());
        if let Some(index) = guard
            .scripted
            .iter()
            .position(|s| path.ends_with(&s.path_suffix))
        {
            let scripted = guard.scripted.remove(index);
            (scripted.status, scripted.body)
        } else {
            handle(&seen, &mut guard, &base)
        }
    };
    respond(&mut stream, status, body.as_bytes()).await
}

/// The real handler: one arm per endpoint the client actually calls.
///
/// Anything else is `404` with a body naming the path, so a client that starts
/// speaking a new call fails here loudly instead of being quietly humoured.
fn handle(seen: &Seen, state: &mut State, base: &str) -> (u16, String) {
    let path = seen.path.as_str();
    if path.ends_with("/b2_authorize_account") {
        return authorize(seen, state, base);
    }
    if path.ends_with("/b2_list_buckets") {
        return list_buckets(seen, state);
    }
    if path.ends_with("/b2_get_upload_url") {
        state.next_id += 1;
        let token = format!("upload-token-{}", state.next_id);
        return (
            200,
            format!(
                r#"{{"uploadUrl":"{base}/b2_upload_file/{BUCKET_ID}","authorizationToken":"{token}"}}"#
            ),
        );
    }
    if path.starts_with("/b2_upload_file/") {
        return upload_file(seen, state);
    }
    if path.ends_with("/b2_start_large_file") {
        return start_large_file(seen, state);
    }
    if path.ends_with("/b2_get_upload_part_url") {
        let Some(file_id) = seen.json().and_then(|b| string_field(&b, "fileId")) else {
            return (400, error_body(400, "bad_request", "no fileId"));
        };
        state.next_id += 1;
        let token = format!("part-token-{}", state.next_id);
        return (
            200,
            format!(
                r#"{{"uploadUrl":"{base}/b2_upload_part/{file_id}","authorizationToken":"{token}"}}"#
            ),
        );
    }
    if path.starts_with("/b2_upload_part/") {
        return upload_part(seen, state);
    }
    if path.ends_with("/b2_finish_large_file") {
        return finish_large_file(seen, state);
    }
    if path.ends_with("/b2_cancel_large_file") {
        return cancel_large_file(seen, state);
    }
    if path.ends_with("/b2_list_unfinished_large_files") {
        return list_unfinished(seen, state);
    }
    (404, error_body(404, "not_found", path))
}

fn authorize(seen: &Seen, state: &State, base: &str) -> (u16, String) {
    // Basic auth over the key pair, exactly as B2 wants it. A wrong key is a
    // 401 with B2's own code, so the retry classifier's "a wrong application key
    // is not a temporary condition" rule is exercisable here.
    let expected = format!(
        "Basic {}",
        base64_encode(format!("{KEY_ID}:{APP_KEY}").as_bytes())
    );
    if seen.header("authorization") != Some(expected.as_str()) {
        return (401, error_body(401, "unauthorized", "bad application key"));
    }
    let recommended = state.recommended_part_size;
    (
        200,
        format!(
            r#"{{"accountId":"{ACCOUNT_ID}","authorizationToken":"session-token",
                 "apiUrl":"{base}","downloadUrl":"{base}",
                 "recommendedPartSize":{recommended},"absoluteMinimumPartSize":5000000,
                 "allowed":{{"bucketId":"{BUCKET_ID}","bucketName":"{BUCKET}"}}}}"#
        ),
    )
}

/// `b2_list_buckets`, filtered by the `bucketName` the caller asked about.
///
/// B2 answers a name that matches nothing with `200` and an **empty** array, not
/// with a `404`, and the distinction is the one the store guard turns on: an
/// empty list is "the bucket is not there", which is an absence a caller may act
/// on, while a non-2xx is "I could not look", which is not. Answering the miss
/// with an error here would let a backend that confused the two pass.
fn list_buckets(seen: &Seen, state: &State) -> (u16, String) {
    let asked = seen
        .json()
        .and_then(|body| string_field(&body, "bucketName"))
        .unwrap_or_default();
    let matched = match (&state.bucket_id, asked == BUCKET) {
        (Some(id), true) => format!(
            r#"{{"bucketId":"{id}","accountId":"{ACCOUNT_ID}","bucketName":"{BUCKET}","bucketType":"allPrivate"}}"#
        ),
        _ => String::new(),
    };
    (200, format!(r#"{{"buckets":[{matched}]}}"#))
}

fn upload_file(seen: &Seen, state: &mut State) -> (u16, String) {
    let Some(name) = seen.header("x-bz-file-name").map(str::to_string) else {
        return (400, error_body(400, "bad_request", "no X-Bz-File-Name"));
    };
    let Some(declared) = seen.header("x-bz-content-sha1") else {
        return (400, error_body(400, "bad_request", "no X-Bz-Content-Sha1"));
    };
    if !declared.eq_ignore_ascii_case(&seen.body_sha1) {
        return (400, error_body(400, "bad_request", "sha1 does not match"));
    }
    state.singles.push(SingleUpload {
        name: percent_decode(&name),
        len: seen.body_len,
        sha1: seen.body_sha1.clone(),
    });
    let echoed = state
        .echoed_sha1
        .clone()
        .unwrap_or_else(|| seen.body_sha1.clone());
    (
        200,
        format!(
            r#"{{"fileId":"single-{}","contentSha1":"{echoed}"}}"#,
            state.singles.len(),
        ),
    )
}

fn start_large_file(seen: &Seen, state: &mut State) -> (u16, String) {
    let Some(name) = seen.json().and_then(|b| string_field(&b, "fileName")) else {
        return (400, error_body(400, "bad_request", "no fileName"));
    };
    let started_millis = state.start_time_millis;
    state.large.push(LargeFile {
        name,
        started_millis,
        ..LargeFile::default()
    });
    let file_id = format!("large-{}", state.large.len());
    (200, format!(r#"{{"fileId":"{file_id}"}}"#))
}

fn upload_part(seen: &Seen, state: &mut State) -> (u16, String) {
    let file_id = seen.path.trim_start_matches("/b2_upload_part/").to_string();
    let Some(number) = seen
        .header("x-bz-part-number")
        .and_then(|v| v.parse::<u32>().ok())
    else {
        return (400, error_body(400, "bad_request", "no X-Bz-Part-Number"));
    };
    let Some(declared) = seen.header("x-bz-content-sha1") else {
        return (400, error_body(400, "bad_request", "no X-Bz-Content-Sha1"));
    };
    if !declared.eq_ignore_ascii_case(&seen.body_sha1) {
        return (
            400,
            error_body(400, "bad_request", "part sha1 does not match"),
        );
    }
    let Some(file) = large_file_mut(state, &file_id) else {
        return (400, error_body(400, "bad_request", "no such large file"));
    };
    let receipt = PartReceipt {
        number,
        len: seen.body_len,
        sha1: seen.body_sha1.clone(),
    };
    // A re-sent part replaces the one before it, which is what B2 does: a part
    // is addressed by its number, so retrying one is idempotent rather than
    // additive. Recording both would make a retry look like an extra part.
    match file.parts.iter().position(|p| p.number == number) {
        Some(index) => file.parts[index] = receipt,
        None => file.parts.push(receipt),
    }
    let echoed = state
        .echoed_sha1
        .clone()
        .unwrap_or_else(|| seen.body_sha1.clone());
    (200, format!(r#"{{"contentSha1":"{echoed}"}}"#))
}

fn finish_large_file(seen: &Seen, state: &mut State) -> (u16, String) {
    let Some(body) = seen.json() else {
        return (400, error_body(400, "bad_request", "no body"));
    };
    let Some(file_id) = string_field(&body, "fileId") else {
        return (400, error_body(400, "bad_request", "no fileId"));
    };
    let sha1s: Vec<String> = body
        .get("partSha1Array")
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let Some(file) = large_file_mut(state, &file_id) else {
        return (400, error_body(400, "bad_request", "no such large file"));
    };
    // B2 rejects a finish whose array does not describe the parts it holds. So
    // does this: a client that sent the parts and then named the wrong hashes
    // would otherwise pass every assertion in the suite.
    file.parts.sort_by_key(|p| p.number);
    let held: Vec<String> = file.parts.iter().map(|p| p.sha1.clone()).collect();
    let numbers: Vec<u32> = file.parts.iter().map(|p| p.number).collect();
    let contiguous: Vec<u32> = (1..=numbers.len() as u32).collect();
    if numbers != contiguous {
        return (400, error_body(400, "bad_request", "parts are not 1..n"));
    }
    if held != sha1s {
        return (
            400,
            error_body(400, "bad_request", "partSha1Array does not match the parts"),
        );
    }
    file.finished = true;
    file.finished_with = sha1s;
    (200, format!(r#"{{"fileId":"{file_id}"}}"#))
}

/// `b2_list_unfinished_large_files`: every large file this server is still
/// holding open.
///
/// The whole point of the endpoint is that these are **not** objects: nothing in
/// `b2_list_file_names` mentions them, and their parts are stored and billed. So
/// this reads from the same `large` list the finish and cancel handlers write to,
/// and filters out exactly the ones that reached one of those two.
///
/// Honours `namePrefix`, `startFileId` and `maxFileCount`, because a client that
/// ignored any of the three would still pass a single-page test and then either
/// sweep the wrong prefix or loop forever on a big bucket.
fn list_unfinished(seen: &Seen, state: &State) -> (u16, String) {
    let body = seen.json().unwrap_or(serde_json::Value::Null);
    let prefix = string_field(&body, "namePrefix").unwrap_or_default();
    let start = string_field(&body, "startFileId");
    // B2's ceiling for *this* endpoint is 100, not the 10 000 of
    // `b2_list_file_names`, and it is a refusal rather than a clamp. Enforced
    // here because a mock that accepted 1000 is exactly why a sweep that could
    // never work passed every offline gate and then failed on the first real
    // bucket with `400 bad_request`.
    let max = body
        .get("maxFileCount")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(100);
    if !(1..=100).contains(&max) {
        return (
            400,
            serde_json::json!({
                "status": 400,
                "code": "bad_request",
                "message": "maxFileCount must be in the range 1 - 100",
            })
            .to_string(),
        );
    }
    let max = max as usize;

    let open: Vec<(String, &LargeFile)> = state
        .large
        .iter()
        .enumerate()
        .filter(|(_, file)| !file.finished && !file.cancelled)
        .filter(|(_, file)| file.name.starts_with(&prefix))
        .map(|(index, file)| (format!("large-{}", index + 1), file))
        .collect();

    // `startFileId` is *inclusive* in B2's API: the cursor names the first file of
    // the next page rather than the last of the previous one.
    let from = start.map_or(0, |start| {
        open.iter().position(|(id, _)| *id == start).unwrap_or(0)
    });
    let page: Vec<&(String, &LargeFile)> = open[from..].iter().take(max).collect();
    let next = open.get(from + page.len()).map(|(id, _)| id.clone());

    let files: Vec<String> = page
        .iter()
        .map(|(id, file)| {
            format!(
                r#"{{"fileId":"{id}","fileName":"{}","uploadTimestamp":{}}}"#,
                file.name, file.started_millis
            )
        })
        .collect();
    let next_json = next.map_or_else(|| "null".to_string(), |id| format!(r#""{id}""#));
    (
        200,
        format!(
            r#"{{"files":[{}],"nextFileId":{next_json}}}"#,
            files.join(",")
        ),
    )
}

fn cancel_large_file(seen: &Seen, state: &mut State) -> (u16, String) {
    let Some(file_id) = seen.json().and_then(|b| string_field(&b, "fileId")) else {
        return (400, error_body(400, "bad_request", "no fileId"));
    };
    let Some(file) = large_file_mut(state, &file_id) else {
        return (400, error_body(400, "bad_request", "no such large file"));
    };
    file.cancelled = true;
    (200, format!(r#"{{"fileId":"{file_id}"}}"#))
}

/// The wall clock in epoch milliseconds, which is what B2 stamps an upload with.
fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| i64::try_from(since.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// The large file `file_id` names, by the `large-N` id this server mints.
fn large_file_mut<'a>(state: &'a mut State, file_id: &str) -> Option<&'a mut LargeFile> {
    let index: usize = file_id.strip_prefix("large-")?.parse().ok()?;
    state.large.get_mut(index.checked_sub(1)?)
}

fn string_field(body: &serde_json::Value, key: &str) -> Option<String> {
    body.get(key)?.as_str().map(str::to_string)
}

fn error_body(status: u16, code: &str, message: &str) -> String {
    format!(r#"{{"status":{status},"code":"{code}","message":"{message}"}}"#)
}

async fn respond(stream: &mut TcpStream, status: u16, body: &[u8]) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        reason(status),
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await
}

const fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        429 => "Too Many Requests",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Percent-decoding, for the file name the client URL-encodes into a header.
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&input[index + 1..index + 3], 16) {
                out.push(byte);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Base64, standard alphabet with padding — enough to rebuild the `Authorization`
/// header `reqwest`'s `basic_auth` produces.
///
/// Hand-written rather than pulled in as a dependency: this is the only base64 in
/// the crate's tests, and a test-support file is not a reason to add a crate to
/// the dependency tree of a product sold on a small audited surface.
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for group in input.chunks(3) {
        let b0 = u32::from(group[0]);
        let b1 = group.get(1).copied().map_or(0, u32::from);
        let b2 = group.get(2).copied().map_or(0, u32::from);
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);
        out.push(if group.len() > 1 {
            ALPHABET[((triple >> 6) & 0x3F) as usize] as char
        } else {
            '='
        });
        out.push(if group.len() > 2 {
            ALPHABET[(triple & 0x3F) as usize] as char
        } else {
            '='
        });
    }
    out
}
