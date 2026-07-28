//! A local HTTP listener that speaks enough of the S3 API to hold the S3 and R2
//! backends to account without an AWS or Cloudflare account.
//!
//! ## Why this exists
//!
//! S3 and R2 are two of DCTL's five providers and neither had ever been
//! exercised against anything. `tests/s3_live.rs` needs credentials and this
//! environment has none, so every claim about the S3 family rested on reading
//! the code. That is exactly the position `PLAN.md` §6 says not to be in, and
//! "no credentials" is not a reason for "no coverage": the parts of an S3 client
//! that go wrong are the parts a local server can check.
//!
//! ## What it actually proves, and what it cannot
//!
//! The server **recomputes the SigV4 signature** of every request from what it
//! received and rejects a mismatch with a real `SignatureDoesNotMatch`. That is
//! the load-bearing property: a canonical URI, a canonical query string, a
//! signed-header list or a payload hash that is wrong by one character produces
//! a different signature, so any of those defects fails here the same way it
//! would fail at AWS. It is not a re-implementation of the client's signing —
//! it is an independent one, driven from the bytes on the wire.
//!
//! It also holds objects, so a round trip is a real round trip: what `put`
//! serialises is what `get` parses back.
//!
//! What it does **not** prove is anything about a real provider's behaviour —
//! its eventual consistency, its rate limiting, its error catalogue, or the
//! quirks R2 and MinIO have that AWS does not. `HANDOVER.md` §11.2 says so
//! plainly and this comment is not a substitute for that.
//!
//! ## Why it is hand-written
//!
//! HTTP/1.1 with no chunked request bodies and no keep-alive pipelining is about
//! two hundred lines, and the alternative is a web-framework dependency in the
//! dependency tree of a product whose selling point is a small audited surface.
//! Every request the client makes sets `Content-Length`, so the parser needs no
//! transfer-encoding support; anything it cannot parse is answered `400` rather
//! than guessed at, which is how a test discovers the client started sending
//! something new.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

type HmacSha256 = Hmac<Sha256>;

/// The credentials every test signs with. Not secrets: this server is bound to
/// loopback on an ephemeral port and lives for the duration of one test.
pub const ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
pub const SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
/// The bucket the server answers for.
pub const BUCKET: &str = "dctl-mock";
/// The region requests are expected to be signed for.
pub const REGION: &str = "us-east-1";

/// One stored object.
#[derive(Clone, Debug, Default)]
pub struct StoredObject {
    pub body: Vec<u8>,
    /// `x-amz-meta-*` headers, lower-cased, as they arrived.
    pub metadata: BTreeMap<String, String>,
}

/// One request, as the server saw it.
#[derive(Clone, Debug)]
pub struct Seen {
    pub method: String,
    /// Path with no query string, exactly as it arrived on the wire.
    pub path: String,
    /// Raw query string, or `""`.
    pub query: String,
    pub headers: BTreeMap<String, String>,
    pub body_len: usize,
}

impl Seen {
    /// The value of one query parameter, if present.
    #[must_use]
    pub fn param(&self, name: &str) -> Option<String> {
        self.query.split('&').find_map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (key == name).then(|| percent_decode(value))
        })
    }
}

/// A response the server will give instead of doing the real thing.
#[derive(Clone, Debug)]
pub struct Scripted {
    pub status: u16,
    pub body: String,
    /// Headers sent with it.
    ///
    /// Exists for `Retry-After`, which is the one header whose *presence*
    /// changes what the client does rather than what it reports — a retry layer
    /// that ignored it would pass every other assertion in the suite while
    /// turning a throttled client into a blocked one.
    pub headers: Vec<(String, String)>,
}

/// One response: status, body **bytes**, and any extra headers.
///
/// Bytes rather than a `String` because an object body is arbitrary data. A
/// `String` here silently ran every stored object through
/// `from_utf8_lossy`, which turns any byte above 0x7F into U+FFFD — so a
/// round-trip test on binary data failed for a reason that had nothing to do
/// with the client.
type Response = (u16, Vec<u8>, Vec<(String, String)>);

/// One multipart upload the server is holding open: the key it will become, the
/// metadata its create carried, and the parts received so far by number.
#[derive(Clone, Debug, Default)]
struct Upload {
    key: String,
    metadata: BTreeMap<String, String>,
    parts: BTreeMap<u32, Vec<u8>>,
}

/// Everything the server remembers.
#[derive(Clone, Debug, Default)]
pub struct State {
    pub objects: BTreeMap<String, StoredObject>,
    /// In-flight multipart uploads, by upload id.
    uploads: BTreeMap<String, Upload>,
    /// Multipart uploads that were aborted, so a test can assert cleanup.
    pub aborted: Vec<String>,
    /// Multipart uploads that were completed.
    pub completed: Vec<String>,
    pub requests: Vec<Seen>,
    /// Responses to give instead of the real answer, consumed in order.
    scripted: Vec<Scripted>,
    next_upload_id: u64,
}

impl State {
    /// Requests whose method and path-suffix match, in arrival order.
    #[must_use]
    pub fn requests_for(&self, method: &str, key_suffix: &str) -> Vec<&Seen> {
        self.requests
            .iter()
            .filter(|seen| seen.method == method && seen.path.ends_with(key_suffix))
            .collect()
    }

    /// How many requests of one method the server has answered.
    #[must_use]
    pub fn count(&self, method: &str) -> usize {
        self.requests
            .iter()
            .filter(|seen| seen.method == method)
            .count()
    }
}

/// A running mock S3 endpoint.
pub struct MockS3 {
    endpoint: String,
    state: Arc<Mutex<State>>,
}

impl MockS3 {
    /// Bind an ephemeral loopback port and start serving.
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port is available");
        let port = listener
            .local_addr()
            .expect("the listener has an address")
            .port();
        let state = Arc::new(Mutex::new(State::default()));
        let serving = Arc::clone(&state);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let state = Arc::clone(&serving);
                tokio::spawn(async move {
                    // A connection that dies mid-request is the client going
                    // away, which several tests do deliberately.
                    let _ = serve(stream, state).await;
                });
            }
        });
        Self {
            endpoint: format!("http://127.0.0.1:{port}"),
            state,
        }
    }

    /// The base URL an `S3Config` should point at.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// An owned copy of everything the server has seen and stored.
    ///
    /// A **snapshot**, not a guard, and that is not a stylistic preference. A
    /// `MutexGuard` is not `Send`, but `#[tokio::test]` does not require its
    /// future to be `Send`, so a test that held one across an `.await` compiled
    /// perfectly and then deadlocked against the server task recording the next
    /// request — a hang with no message, in a test suite whose whole purpose is
    /// to make S3 failures legible. Copying is free at these sizes.
    #[must_use]
    pub fn state(&self) -> State {
        self.state
            .lock()
            .expect("the mock state is not poisoned")
            .clone()
    }

    /// Queue a response to give instead of the real answer, once.
    pub fn script(&self, status: u16, body: &str) {
        self.script_with_headers(status, body, &[]);
    }

    /// The same, carrying headers — `Retry-After` above all.
    pub fn script_with_headers(&self, status: u16, body: &str, headers: &[(&str, &str)]) {
        self.state
            .lock()
            .expect("the mock state is not poisoned")
            .scripted
            .push(Scripted {
                status,
                body: body.to_string(),
                headers: headers
                    .iter()
                    .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
                    .collect(),
            });
    }

    /// Put an object into the server without going through the client, so a
    /// read path can be tested against bytes the client did not write.
    pub fn seed(&self, key: &str, body: &[u8]) {
        self.state
            .lock()
            .expect("the mock state is not poisoned")
            .objects
            .insert(
                key.to_string(),
                StoredObject {
                    body: body.to_vec(),
                    metadata: BTreeMap::new(),
                },
            );
    }
}

/// Serve one connection: one request, one response, then close.
///
/// No keep-alive. `reqwest` handles a `Connection: close` perfectly well and the
/// alternative is a loop that has to decide when a client has finished, which is
/// the part of HTTP worth not re-implementing.
async fn serve(mut stream: TcpStream, state: Arc<Mutex<State>>) -> std::io::Result<()> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 8192];

    // Read until the end of the headers.
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
        return respond(&mut stream, 400, b"", &[]).await;
    };
    let mut parts = request_line.split_whitespace();
    let (Some(method), Some(target)) = (parts.next(), parts.next()) else {
        return respond(&mut stream, 400, b"", &[]).await;
    };
    let method = method.to_string();
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let (path, query) = (path.to_string(), query.to_string());

    let mut headers: BTreeMap<String, String> = BTreeMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }

    // Read exactly the declared body. Every request the client makes sets
    // Content-Length; a chunked body would be a change worth failing on.
    let want: usize = headers
        .get("content-length")
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    let mut body = buffer[head_end..].to_vec();
    while body.len() < want {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(want);

    {
        let mut guard = state.lock().expect("the mock state is not poisoned");
        guard.requests.push(Seen {
            method: method.clone(),
            path: path.clone(),
            query: query.clone(),
            headers: headers.clone(),
            body_len: body.len(),
        });
    }

    // Authentication first, exactly as a provider does it: an unsigned or
    // wrongly-signed request never reaches the object store.
    if let Err(problem) = verify_signature(&method, &path, &query, &headers, &body) {
        return respond(
            &mut stream,
            403,
            error_xml("SignatureDoesNotMatch", &problem).as_bytes(),
            &[],
        )
        .await;
    }

    // A scripted response pre-empts the real handler, which is how a retry or an
    // error-classification test provokes a failure that cannot otherwise happen.
    let scripted = {
        let mut guard = state.lock().expect("the mock state is not poisoned");
        if guard.scripted.is_empty() {
            None
        } else {
            Some(guard.scripted.remove(0))
        }
    };
    if let Some(scripted) = scripted {
        return respond(
            &mut stream,
            scripted.status,
            scripted.body.as_bytes(),
            &scripted.headers,
        )
        .await;
    }

    let (status, response, extra) = handle(&state, &method, &path, &query, &headers, body);
    respond(&mut stream, status, &response, &extra).await
}

/// The S3 operations this server implements.
#[allow(clippy::too_many_lines)]
fn handle(
    state: &Arc<Mutex<State>>,
    method: &str,
    path: &str,
    query: &str,
    headers: &BTreeMap<String, String>,
    body: Vec<u8>,
) -> Response {
    let mut guard = state.lock().expect("the mock state is not poisoned");

    // Path-style addressing: /{bucket}[/{key}].
    let trimmed = path.trim_start_matches('/');
    let (bucket, key) = trimmed.split_once('/').unwrap_or((trimmed, ""));
    if bucket != BUCKET {
        return (
            404,
            error_xml("NoSuchBucket", "the mock serves one bucket").into_bytes(),
            Vec::new(),
        );
    }
    let key = percent_decode(key);

    let params = parse_query(query);
    let has = |name: &str| params.iter().any(|(k, _)| k == name);
    let param = |name: &str| {
        params
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    };

    match method {
        "PUT" if has("partNumber") => {
            let upload_id = param("uploadId").unwrap_or_default();
            let number: u32 = param("partNumber")
                .and_then(|value| value.parse().ok())
                .unwrap_or(0);
            let Some(upload) = guard.uploads.get_mut(&upload_id) else {
                return (
                    404,
                    error_xml("NoSuchUpload", "unknown upload id").into_bytes(),
                    Vec::new(),
                );
            };
            let etag = format!("\"{}\"", &hex::encode(Sha256::digest(&body))[..32]);
            upload.parts.insert(number, body);
            (200, Vec::new(), vec![("ETag".into(), etag)])
        }

        "PUT" => {
            let metadata = headers
                .iter()
                .filter(|(name, _)| name.starts_with("x-amz-meta-"))
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect();
            guard.objects.insert(key, StoredObject { body, metadata });
            (200, Vec::new(), Vec::new())
        }

        "POST" if has("uploads") => {
            guard.next_upload_id += 1;
            let id = format!("upload-{}", guard.next_upload_id);
            let metadata = headers
                .iter()
                .filter(|(name, _)| name.starts_with("x-amz-meta-"))
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect();
            guard.uploads.insert(
                id.clone(),
                Upload {
                    key: key.clone(),
                    metadata,
                    parts: BTreeMap::new(),
                },
            );
            (
                200,
                format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                     <InitiateMultipartUploadResult><Bucket>{BUCKET}</Bucket>\
                     <Key>{key}</Key><UploadId>{id}</UploadId>\
                     </InitiateMultipartUploadResult>"
                )
                .into_bytes(),
                Vec::new(),
            )
        }

        "POST" if has("uploadId") => {
            let id = param("uploadId").unwrap_or_default();
            let Some(upload) = guard.uploads.remove(&id) else {
                return (
                    404,
                    error_xml("NoSuchUpload", "unknown upload id").into_bytes(),
                    Vec::new(),
                );
            };
            // Assembled in part-number order, which is what S3 guarantees and
            // what a manifest listing the parts out of order would break.
            let assembled: Vec<u8> = upload.parts.values().flatten().copied().collect();
            let key = upload.key;
            guard.completed.push(id);
            guard.objects.insert(
                key.clone(),
                StoredObject {
                    body: assembled,
                    metadata: upload.metadata,
                },
            );
            (
                200,
                format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                     <CompleteMultipartUploadResult><Bucket>{BUCKET}</Bucket>\
                     <Key>{key}</Key></CompleteMultipartUploadResult>"
                )
                .into_bytes(),
                Vec::new(),
            )
        }

        "DELETE" if has("uploadId") => {
            let id = param("uploadId").unwrap_or_default();
            guard.uploads.remove(&id);
            guard.aborted.push(id);
            (204, Vec::new(), Vec::new())
        }

        "DELETE" => {
            guard.objects.remove(&key);
            (204, Vec::new(), Vec::new())
        }

        "HEAD" => match guard.objects.get(&key) {
            None => (404, Vec::new(), Vec::new()),
            Some(object) => {
                let mut extra: Vec<(String, String)> = object
                    .metadata
                    .iter()
                    .map(|(name, value)| (name.clone(), value.clone()))
                    .collect();
                extra.push(("Content-Length".into(), object.body.len().to_string()));
                // A HEAD carries the length in a header and no body, which is
                // the shape `head` reads the size out of.
                (200, Vec::new(), extra)
            }
        },

        "GET" if key.is_empty() || has("list-type") => {
            let prefix = param("prefix").unwrap_or_default();
            let max: usize = param("max-keys")
                .and_then(|value| value.parse().ok())
                .unwrap_or(1000);
            let after = param("continuation-token").unwrap_or_default();

            let mut selected: Vec<(&String, &StoredObject)> = guard
                .objects
                .iter()
                .filter(|(name, _)| name.starts_with(&prefix) && **name > after)
                .collect();
            selected.sort_by(|a, b| a.0.cmp(b.0));

            let truncated = selected.len() > max;
            let page = &selected[..selected.len().min(max)];
            let next = page.last().map(|(name, _)| (*name).clone());

            let mut xml =
                String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult>");
            for (name, object) in page {
                xml.push_str(&format!(
                    "<Contents><Key>{name}</Key><Size>{}</Size>\
                     <LastModified>2024-01-01T00:00:00.000Z</LastModified></Contents>",
                    object.body.len()
                ));
            }
            xml.push_str(&format!("<IsTruncated>{truncated}</IsTruncated>"));
            if truncated && let Some(token) = next {
                xml.push_str(&format!(
                    "<NextContinuationToken>{token}</NextContinuationToken>"
                ));
            }
            xml.push_str("</ListBucketResult>");
            (200, xml.into_bytes(), Vec::new())
        }

        "GET" => {
            let Some(object) = guard.objects.get(&key) else {
                return (
                    404,
                    error_xml("NoSuchKey", "no such object").into_bytes(),
                    Vec::new(),
                );
            };
            match headers.get("range") {
                None => (
                    200,
                    object.body.clone(),
                    vec![("Content-Length".into(), object.body.len().to_string())],
                ),
                Some(range) => {
                    let Some((first, last)) = parse_range(range, object.body.len()) else {
                        return (
                            416,
                            error_xml("InvalidRange", "unparseable range").into_bytes(),
                            Vec::new(),
                        );
                    };
                    let slice = &object.body[first..=last];
                    (
                        206,
                        slice.to_vec(),
                        vec![
                            ("Content-Length".into(), slice.len().to_string()),
                            (
                                "Content-Range".into(),
                                format!("bytes {first}-{last}/{}", object.body.len()),
                            ),
                        ],
                    )
                }
            }
        }

        other => (
            405,
            error_xml("MethodNotAllowed", &format!("{other} is not implemented")).into_bytes(),
            Vec::new(),
        ),
    }
}

// ── SigV4 verification ───────────────────────────────────────────────────────

/// Recompute the request's signature and compare it with the one presented.
///
/// An independent implementation of SigV4, driven from the bytes that arrived,
/// so a defect in the client's canonicalisation shows up as a mismatch rather
/// than as two copies of the same mistake agreeing with each other.
fn verify_signature(
    method: &str,
    path: &str,
    query: &str,
    headers: &BTreeMap<String, String>,
    body: &[u8],
) -> Result<(), String> {
    let authorization = headers
        .get("authorization")
        .ok_or_else(|| "no Authorization header".to_string())?;

    let credential = field(authorization, "Credential=")
        .ok_or_else(|| "no Credential in Authorization".to_string())?;
    let signed_headers = field(authorization, "SignedHeaders=")
        .ok_or_else(|| "no SignedHeaders in Authorization".to_string())?;
    let presented = field(authorization, "Signature=")
        .ok_or_else(|| "no Signature in Authorization".to_string())?;

    let mut scope = credential.splitn(5, '/');
    let key_id = scope.next().unwrap_or_default();
    if key_id != ACCESS_KEY {
        return Err(format!("unknown access key '{key_id}'"));
    }
    let date = scope.next().unwrap_or_default().to_string();
    let region = scope.next().unwrap_or_default().to_string();
    let service = scope.next().unwrap_or_default().to_string();

    let amz_date = headers
        .get("x-amz-date")
        .ok_or_else(|| "no x-amz-date header".to_string())?;
    if !amz_date.starts_with(&date) {
        return Err(format!("scope date {date} does not match {amz_date}"));
    }

    // The payload hash is what the client signed. Checking it against the body
    // that actually arrived is the part that makes this a verified write: a body
    // altered in flight produces a different hash and a different signature.
    let declared = headers
        .get("x-amz-content-sha256")
        .ok_or_else(|| "no x-amz-content-sha256 header".to_string())?;
    let actual = hex::encode(Sha256::digest(body));
    if declared != &actual && declared != "UNSIGNED-PAYLOAD" {
        return Err(format!(
            "payload hash {declared} but body hashes to {actual}"
        ));
    }

    let mut canonical_headers = String::new();
    for name in signed_headers.split(';') {
        let value = headers
            .get(name)
            .ok_or_else(|| format!("signed header '{name}' was not sent"))?;
        canonical_headers.push_str(&format!("{name}:{}\n", value.trim()));
    }

    let canonical_query = canonical_query_of(query);
    let canonical_request = format!(
        "{method}\n{path}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{declared}"
    );
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{date}/{region}/{service}/aws4_request\n{}",
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );

    let k_date = hmac(format!("AWS4{SECRET_KEY}").as_bytes(), date.as_bytes());
    let k_region = hmac(&k_date, region.as_bytes());
    let k_service = hmac(&k_region, service.as_bytes());
    let signing = hmac(&k_service, b"aws4_request");
    let expected = hex::encode(hmac(&signing, string_to_sign.as_bytes()));

    if expected == presented {
        Ok(())
    } else {
        Err(format!(
            "signature mismatch\n  canonical request:\n{canonical_request}\n  expected {expected}, got {presented}"
        ))
    }
}

fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// The value of `name=` up to the next `,` or end of string.
fn field(header: &str, name: &str) -> Option<String> {
    let start = header.find(name)? + name.len();
    let rest = &header[start..];
    let end = rest.find(',').unwrap_or(rest.len());
    Some(rest[..end].trim().to_string())
}

/// AWS's canonical query string: parameters URI-encoded and sorted by key.
///
/// The query arrives already encoded, so this only has to sort it — which is
/// exactly the check worth making, because a client that sorted before encoding
/// would order `X-Amz-Credential` and `X-Amz-Date` differently from AWS.
fn canonical_query_of(query: &str) -> String {
    if query.is_empty() {
        return String::new();
    }
    let mut pairs: Vec<String> = query
        .split('&')
        .map(|pair| {
            if pair.contains('=') {
                pair.to_string()
            } else {
                format!("{pair}=")
            }
        })
        .collect();
    pairs.sort();
    pairs.join("&")
}

// ── plumbing ─────────────────────────────────────────────────────────────────

async fn respond(
    stream: &mut TcpStream,
    status: u16,
    body: &[u8],
    extra: &[(String, String)],
) -> std::io::Result<()> {
    let mut head = format!(
        "HTTP/1.1 {status} {}\r\nConnection: close\r\n",
        reason(status)
    );
    let mut declared_length = false;
    for (name, value) in extra {
        if name.eq_ignore_ascii_case("content-length") {
            declared_length = true;
        }
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    if !declared_length {
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await?;
    // A HEAD response declares a length and sends no body, which is what makes
    // `head` read a size the object really has rather than the length of an
    // empty string.
    stream.write_all(body).await?;
    stream.flush().await?;
    stream.shutdown().await
}

const fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        206 => "Partial Content",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        416 => "Range Not Satisfiable",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Unknown",
    }
}

fn error_xml(code: &str, message: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>{code}</Code><Message>{message}</Message></Error>"
    )
}

fn parse_query(query: &str) -> Vec<(String, String)> {
    if query.is_empty() {
        return Vec::new();
    }
    query
        .split('&')
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (percent_decode(key), percent_decode(value))
        })
        .collect()
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or("");
            if let Ok(byte) = u8::from_str_radix(hex, 16) {
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

/// `bytes=first-last` or `bytes=first-`, clamped to the object.
fn parse_range(header: &str, len: usize) -> Option<(usize, usize)> {
    let spec = header.trim().strip_prefix("bytes=")?;
    let (first, last) = spec.split_once('-')?;
    let first: usize = first.parse().ok()?;
    if first >= len {
        return None;
    }
    let last = if last.is_empty() {
        len - 1
    } else {
        last.parse::<usize>().ok()?.min(len - 1)
    };
    (first <= last).then_some((first, last))
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
