//! The shared S3 protocol client: SigV4-signed requests and the object operations.
//! Reused by every S3-family provider backend (generic S3, R2, …).
//!
//! # The source modification time, and the half of it this protocol will not give
//! back
//!
//! A write records the source's own last-modified time as the user-metadata key
//! `x-amz-meta-mtime`, spelled the way `rclone` spells it (float seconds), so a
//! bucket written by DCTL keeps its timestamps when read by rclone and the other
//! way round. [`head`](S3Client::head) reads it back, which is what
//! `dctl cat`/`dctl stat` see.
//!
//! **`ListObjectsV2` does not return user metadata**, so
//! [`list_page`](S3Client::list_page) cannot report it — and a listing is what
//! `sync`, `copy` and `check` compare with. So an incremental `sync` to S3 or R2
//! is **not** delivered by this change: those two providers still re-transfer an
//! unchanged tree, exactly as they did before. The time is written and is not
//! lost; what is missing is a way to read it back a page at a time.
//!
//! Closing it means one `HEAD` per listed object, which is what rclone does
//! (`readMetaData`) — a per-object request against a provider that bills them,
//! and therefore a cost decision to make deliberately rather than a line to slip
//! in here. Until that decision is made, this module reports what it can and this
//! paragraph is the whole of the claim.
//!
//! `list_page` deliberately keeps answering `None` for the time rather than
//! substituting the object's `LastModified`. That value is when the provider
//! accepted the upload, so it is always "now" for a fresh copy — which would make
//! every destination object look *newer* than its source and cause `--update` to
//! skip the entire tree. An absent time transfers; a wrong one loses data.

use std::path::Path;

use bytes::Bytes;
use reqwest::{Method, StatusCode};

use crate::backend::UploadTicket;
use crate::checksum::{ContentHash, Hasher};
use crate::error::{Result, StoreError};
use crate::model::{ByteRange, ObjectKey, ObjectMeta, Page, PutOutcome};
use crate::modified::SourceModified;
use crate::streaming;

use super::config::S3Config;
use super::constants::{
    H_SRC_MODIFIED, LIST_PAGE_SIZE, MAX_PART_SIZE, MIN_PART_SIZE, PRESIGN_TTL_SECS, S3_SERVICE,
};

/// The name every failure from this client is attributed to.
///
/// One string for both providers that use it. `R2Backend` reports `"r2"` from
/// [`Backend::name`](crate::Backend::name) — which is what selects its retry
/// schedule and what an operator sees in a log field — while the protocol error
/// keeps saying `s3`, because the protocol *is* S3 and a message reading
/// `r2 error 503` would send a reader to Cloudflare's error catalogue for a code
/// that is in Amazon's.
const S3_BACKEND_NAME: &str = "s3";
use super::sigv4;
use super::xml;

/// Render a source modification time the way S3 user metadata carries one.
///
/// Float seconds with nanosecond places, which is what rclone writes and parses.
/// DCTL records whole seconds, so the fractional part is always zero — written
/// out in full anyway, because a bare integer is a *different string* to a reader
/// expecting this format and the point of borrowing the spelling is that both
/// tools accept it.
fn render_src_modified(modified: SourceModified) -> Option<String> {
    modified
        .unix()
        .map(|seconds| format!("{seconds}.000000000"))
}

/// Read back what [`render_src_modified`] wrote, in whole seconds.
///
/// [`None`] for absent or unparsable metadata: another tool may have written
/// anything into that key, and a `head` that failed because of it would make an
/// otherwise-readable object undescribable. Truncated towards negative infinity
/// so a pre-epoch fraction does not move the file forwards in time.
fn parse_src_modified(value: &str) -> Option<i64> {
    let (seconds, fraction) = value.split_once('.').unwrap_or((value, ""));
    let seconds: i64 = seconds.parse().ok()?;
    // A negative time with a fractional part is that many seconds *before* the
    // epoch plus a fraction more, so it floors one second further back.
    if seconds < 0 && fraction.chars().any(|digit| digit != '0') {
        return seconds.checked_sub(1);
    }
    Some(seconds)
}

pub(crate) struct S3Client {
    http: reqwest::Client,
    config: S3Config,
    /// Who is told about bytes as they cross the link, part by part and body
    /// chunk by body chunk. See [`crate::meter`]. Held here rather than on the
    /// two backends because S3 and R2 differ in an endpoint and a region and in
    /// nothing else that moves bytes — one field, one pair of loops, one answer.
    meter: std::sync::Arc<dyn crate::meter::Meter>,
}

impl S3Client {
    pub(crate) fn new(config: S3Config) -> Result<Self> {
        Ok(Self {
            http: crate::tls::post_quantum_client()?,
            config,
            meter: crate::meter::unmetered(),
        })
    }

    /// The same client, declaring every part and body chunk it moves.
    pub(crate) fn with_meter(mut self, meter: std::sync::Arc<dyn crate::meter::Meter>) -> Self {
        self.meter = meter;
        self
    }

    // ---- signing + transport -------------------------------------------------

    /// Sign and send a request. `key` is the object key (None = bucket-level).
    /// `query_params` are canonicalized; `body` (if any) is hashed and signed.
    async fn send(
        &self,
        method: Method,
        key: Option<&str>,
        query_params: &[(&str, String)],
        extra_headers: &[(&str, String)],
        body: Option<Bytes>,
    ) -> Result<reqwest::Response> {
        let cfg = &self.config;
        let uri_path = match key {
            Some(k) => format!("/{}/{}", cfg.bucket, uri_encode(k, false)),
            None => format!("/{}", cfg.bucket),
        };
        let canonical_query = canonical_query(query_params);

        let host = host_of(&cfg.endpoint);
        let payload = body.as_deref().unwrap_or(&[]);
        let payload_hash = sigv4::sha256_hex(payload);
        let amz_date = amz_datetime(now_unix());

        let mut signed_headers: Vec<(String, String)> = vec![
            ("host".to_string(), host.clone()),
            ("x-amz-content-sha256".to_string(), payload_hash.clone()),
            ("x-amz-date".to_string(), amz_date.clone()),
        ];
        for (k, v) in extra_headers {
            signed_headers.push(((*k).to_string(), v.clone()));
        }

        let authorization = sigv4::authorization(
            method.as_str(),
            &uri_path,
            &canonical_query,
            &signed_headers,
            &payload_hash,
            &cfg.access_key,
            &cfg.secret_key,
            &cfg.region,
            S3_SERVICE,
            &amz_date,
        );

        let url = if canonical_query.is_empty() {
            format!("{}{}", cfg.endpoint.trim_end_matches('/'), uri_path)
        } else {
            format!(
                "{}{}?{}",
                cfg.endpoint.trim_end_matches('/'),
                uri_path,
                canonical_query
            )
        };

        tracing::debug!(method = method.as_str(), key, "s3 request");
        let mut req = self
            .http
            .request(method, &url)
            .header("x-amz-content-sha256", &payload_hash)
            .header("x-amz-date", &amz_date)
            .header("Authorization", &authorization);
        for (k, v) in extra_headers {
            req = req.header(*k, v);
        }
        if let Some(b) = body {
            req = req.body(b);
        }
        // `Transport`, not `Backend`: nothing answered, so the request may never
        // have reached the provider — which is the case `crate::retry` exists
        // for, and which a formatted string could only have expressed by being
        // searched for later. See `crate::error` for why the classification
        // lives in the type.
        req.send().await.map_err(|e| StoreError::Transport {
            backend: S3_BACKEND_NAME,
            detail: e.to_string(),
        })
    }

    /// Turn a refused response into the error an operator reads and the retry
    /// layer classifies.
    ///
    /// The rendering is unchanged — `s3 error 503: SlowDown` — because
    /// `HANDOVER.md` quotes it and scripts grep for it. What is new is that the
    /// status, the code and any `Retry-After` survive as *fields*, so a `503
    /// SlowDown` is retried because it is a 503 and not because somebody matched
    /// on the message.
    async fn error(resp: reqwest::Response) -> StoreError {
        let status = resp.status().as_u16();
        let retry_after_secs = resp
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<u64>().ok());
        let body = resp.bytes().await.unwrap_or_default();
        let text = String::from_utf8_lossy(&body);
        let code = xml::extract_tag(&text, "Code").unwrap_or_else(|| "?".to_string());
        StoreError::Provider {
            backend: S3_BACKEND_NAME,
            status,
            code,
            retry_after_secs,
        }
    }

    /// Whether the bucket is still there, as `HEAD /bucket` answers it.
    ///
    /// `None` for a bucket that is not there — which the guard reads as "nothing
    /// to lose", the same as a directory a first write will create. A `403` is
    /// **not** absence: the bucket exists and this key may not describe it, so
    /// answering `None` would tell the guard the store had vanished and refuse
    /// every later write for a credential problem. It is reported as the
    /// provider error it is.
    pub(crate) async fn bucket_identity(&self) -> Result<Option<crate::guard::StoreIdentity>> {
        let resp = self.send(Method::HEAD, None, &[], &[], None).await?;
        if resp.status().is_success() {
            return Ok(Some(crate::guard::StoreIdentity::existence_only()));
        }
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Err(Self::error(resp).await)
    }

    // ---- operations ----------------------------------------------------------

    pub(crate) async fn put(
        &self,
        key: &ObjectKey,
        data: Bytes,
        expected: &ContentHash,
        modified: SourceModified,
    ) -> Result<PutOutcome> {
        let caller = ContentHash::compute(expected.algo, &data);
        if !caller.matches(expected) {
            return Err(StoreError::ChecksumMismatch {
                expected: expected.hex(),
                actual: caller.hex(),
            });
        }

        if !streaming::use_multipart(data.len() as u64, self.config.part_size()) {
            self.put_single(key.as_str(), data.clone(), modified)
                .await?;
            // One window, because a single-shot `PUT` *is* one window. The
            // multipart arm charges per part inside its own loop, so charging
            // here as well would bill the object twice.
            crate::meter::charge(self.meter.as_ref(), data.len() as u64).await;
        } else {
            self.put_multipart(key.as_str(), &data, modified).await?;
        }
        Ok(PutOutcome {
            size: data.len() as u64,
            verified: caller,
        })
    }

    /// The user-metadata headers a write carries, as `send` wants them.
    ///
    /// Signed along with everything else: `send` folds `extra_headers` into the
    /// SigV4 canonical request, so metadata that arrived at the provider without
    /// having been signed would be rejected rather than silently dropped.
    fn metadata_headers(modified: SourceModified) -> Vec<(&'static str, String)> {
        render_src_modified(modified)
            .map(|value| vec![(H_SRC_MODIFIED, value)])
            .unwrap_or_default()
    }

    async fn put_single(&self, key: &str, data: Bytes, modified: SourceModified) -> Result<()> {
        // S3 recomputes the body SHA-256 and rejects if it differs from the signed
        // x-amz-content-sha256, so this is a verified write.
        let resp = self
            .send(
                Method::PUT,
                Some(key),
                &[],
                &Self::metadata_headers(modified),
                Some(data),
            )
            .await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(Self::error(resp).await)
        }
    }

    /// In-memory multipart upload (the buffered `>100 MiB` path reachable via
    /// [`put`](Self::put)). Aborts the upload on any error so no orphaned parts linger and
    /// get billed — mirroring the streaming sibling [`put_multipart_from_path`].
    async fn put_multipart(&self, key: &str, data: &[u8], modified: SourceModified) -> Result<()> {
        let create = self
            .send(
                Method::POST,
                Some(key),
                &[("uploads", String::new())],
                &Self::metadata_headers(modified),
                None,
            )
            .await?;
        if !create.status().is_success() {
            return Err(Self::error(create).await);
        }
        let body = create
            .text()
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        let upload_id = xml::extract_tag(&body, "UploadId")
            .ok_or_else(|| StoreError::Backend("s3: no UploadId in response".into()))?;

        match self.upload_parts_and_complete(key, &upload_id, data).await {
            Ok(()) => Ok(()),
            Err(e) => {
                // Abort so no partial upload lingers as orphaned, billed parts. Keep the
                // original error; a failed abort is logged, not surfaced.
                let _ = self.abort_multipart(key, &upload_id).await;
                Err(e)
            }
        }
    }

    /// Upload every part of the in-memory `data` slice, then complete the multipart upload.
    /// Any error propagates to [`put_multipart`], which aborts the upload.
    async fn upload_parts_and_complete(
        &self,
        key: &str,
        upload_id: &str,
        data: &[u8],
    ) -> Result<()> {
        // Grow the part size for very large objects so the part count stays within S3's
        // 10,000-part cap; normal objects keep PART_SIZE.
        let part_size = streaming::adaptive_part_size(
            data.len() as u64,
            self.config.part_size(),
            MIN_PART_SIZE,
            MAX_PART_SIZE,
            streaming::MAX_PARTS,
        )?;
        let plan = streaming::plan_parts(data.len() as u64, part_size);
        tracing::debug!(
            bytes = data.len(),
            part_size,
            parts = plan.len(),
            "s3 upload (multipart)"
        );

        let mut parts_xml = String::from("<CompleteMultipartUpload>");
        for span in &plan {
            let start = span.offset as usize;
            let end = start + span.len as usize;
            let etag = self
                .upload_part(
                    key,
                    upload_id,
                    span.number,
                    Bytes::copy_from_slice(&data[start..end]),
                )
                .await?;
            parts_xml.push_str(&format!(
                "<Part><PartNumber>{}</PartNumber><ETag>{etag}</ETag></Part>",
                span.number
            ));
            // Charged once the part is acknowledged: a retried part used the
            // link on every attempt and is charged for every attempt.
            crate::meter::charge(self.meter.as_ref(), span.len).await;
        }
        parts_xml.push_str("</CompleteMultipartUpload>");

        let complete = self
            .send(
                Method::POST,
                Some(key),
                &[("uploadId", upload_id.to_string())],
                &[],
                Some(Bytes::from(parts_xml)),
            )
            .await?;
        if complete.status().is_success() {
            Ok(())
        } else {
            Err(Self::error(complete).await)
        }
    }

    /// Streaming counterpart of [`put`](Self::put): store the file at `source` under
    /// `key`, verified, without ever holding the whole file in memory.
    ///
    /// Below the multipart threshold the (bounded) file is read and handed to the verified
    /// single-shot [`put`], exactly matching the buffered path. Above it, the file is
    /// streamed part-by-part through the S3 multipart API at `O(part_size)` memory — same
    /// threshold and part size as the live-verified buffered [`put_multipart`], only fed
    /// from a file instead of an in-RAM slice.
    pub(crate) async fn put_from_path(
        &self,
        key: &ObjectKey,
        source: &Path,
        expected: &ContentHash,
        modified: SourceModified,
    ) -> Result<PutOutcome> {
        let size = tokio::fs::metadata(source).await?.len();

        // Below the threshold: read the bounded file and use the verified single-shot
        // path, exactly like `put` (in-memory guard + SigV4 body verification).
        if !streaming::use_multipart(size, self.config.part_size()) {
            let data = tokio::fs::read(source).await?;
            return self.put(key, Bytes::from(data), expected, modified).await;
        }

        let verified = self
            .put_multipart_from_path(key.as_str(), source, expected, modified)
            .await?;
        Ok(PutOutcome { size, verified })
    }

    /// Stream a large file through the S3 multipart API, aborting the upload on any error
    /// so nothing partial is ever committed. Returns the verified whole-file hash.
    async fn put_multipart_from_path(
        &self,
        key: &str,
        source: &Path,
        expected: &ContentHash,
        modified: SourceModified,
    ) -> Result<ContentHash> {
        let create = self
            .send(
                Method::POST,
                Some(key),
                &[("uploads", String::new())],
                &Self::metadata_headers(modified),
                None,
            )
            .await?;
        if !create.status().is_success() {
            return Err(Self::error(create).await);
        }
        let body = create
            .text()
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        let upload_id = xml::extract_tag(&body, "UploadId")
            .ok_or_else(|| StoreError::Backend("s3: no UploadId in response".into()))?;

        match self
            .upload_and_complete(key, &upload_id, source, expected)
            .await
        {
            Ok(verified) => Ok(verified),
            Err(e) => {
                // Abort so no partial upload lingers or gets committed.
                let _ = self.abort_multipart(key, &upload_id).await;
                Err(e)
            }
        }
    }

    /// Upload every part streamed from `source`, verify the whole-file hash against
    /// `expected`, then complete the multipart upload (which commits the object).
    async fn upload_and_complete(
        &self,
        key: &str,
        upload_id: &str,
        source: &Path,
        expected: &ContentHash,
    ) -> Result<ContentHash> {
        let size = tokio::fs::metadata(source).await?.len();
        // Grow the part size for very large objects so the part count stays within S3's
        // 10,000-part cap; normal objects keep PART_SIZE. Computed once from the total and
        // used for the whole upload.
        let part_size = streaming::adaptive_part_size(
            size,
            self.config.part_size(),
            MIN_PART_SIZE,
            MAX_PART_SIZE,
            streaming::MAX_PARTS,
        )?;
        let plan = streaming::plan_parts(size, part_size);
        tracing::debug!(
            bytes = size,
            part_size,
            parts = plan.len(),
            "s3 stream (multipart)"
        );

        let mut file = tokio::fs::File::open(source).await?;
        // One reusable part buffer keeps peak memory at O(part_size).
        let mut buf = vec![0u8; part_size as usize];
        // Whole-file hash under the caller's algorithm, folded part-by-part, so the
        // verified-write contract holds without ever buffering the whole file.
        let mut whole = Hasher::new(expected.algo);
        let mut parts_xml = String::from("<CompleteMultipartUpload>");

        for span in &plan {
            let want = span.len as usize;
            let n = streaming::fill_buf(&mut file, &mut buf[..want]).await?;
            if n != want {
                return Err(StoreError::Backend(
                    "s3 stream: source file shorter than expected (changed under read)".into(),
                ));
            }
            whole.update(&buf[..want]);
            let etag = self
                .upload_part(
                    key,
                    upload_id,
                    span.number,
                    Bytes::copy_from_slice(&buf[..want]),
                )
                .await?;
            parts_xml.push_str(&format!(
                "<Part><PartNumber>{}</PartNumber><ETag>{etag}</ETag></Part>",
                span.number
            ));
            // Charged once the part is acknowledged: a retried part used the
            // link on every attempt and is charged for every attempt.
            crate::meter::charge(self.meter.as_ref(), want as u64).await;
        }
        parts_xml.push_str("</CompleteMultipartUpload>");

        // Verify the streamed bytes hash to `expected` BEFORE completing (which commits).
        let verified = whole.finalize();
        if !verified.matches(expected) {
            return Err(StoreError::ChecksumMismatch {
                expected: expected.hex(),
                actual: verified.hex(),
            });
        }

        let complete = self
            .send(
                Method::POST,
                Some(key),
                &[("uploadId", upload_id.to_string())],
                &[],
                Some(Bytes::from(parts_xml)),
            )
            .await?;
        if !complete.status().is_success() {
            return Err(Self::error(complete).await);
        }
        Ok(verified)
    }

    /// Upload one part (S3 re-verifies the body against the SigV4 `x-amz-content-sha256`)
    /// and return its ETag for the completion manifest.
    async fn upload_part(
        &self,
        key: &str,
        upload_id: &str,
        part_number: u32,
        chunk: Bytes,
    ) -> Result<String> {
        let query = [
            ("partNumber", part_number.to_string()),
            ("uploadId", upload_id.to_string()),
        ];
        let resp = self
            .send(Method::PUT, Some(key), &query, &[], Some(chunk))
            .await?;
        if !resp.status().is_success() {
            return Err(Self::error(resp).await);
        }
        Ok(resp
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string())
    }

    /// Abort an in-flight multipart upload so no partial upload is committed or lingers.
    /// Best-effort: callers invoke it on the error path and keep the original error.
    async fn abort_multipart(&self, key: &str, upload_id: &str) -> Result<()> {
        let resp = self
            .send(
                Method::DELETE,
                Some(key),
                &[("uploadId", upload_id.to_string())],
                &[],
                None,
            )
            .await?;
        if resp.status().is_success() || resp.status() == StatusCode::NOT_FOUND {
            Ok(())
        } else {
            Err(Self::error(resp).await)
        }
    }

    pub(crate) async fn get(&self, key: &ObjectKey) -> Result<Bytes> {
        let bytes = self.fetch(key, None).await?;
        crate::meter::charge(self.meter.as_ref(), bytes.len() as u64).await;
        Ok(bytes)
    }

    pub(crate) async fn get_range(&self, key: &ObjectKey, range: ByteRange) -> Result<Bytes> {
        let header = match range.length {
            Some(len) => format!("bytes={}-{}", range.offset, range.offset + len - 1),
            None => format!("bytes={}-", range.offset),
        };
        let bytes = self.fetch(key, Some(header)).await?;
        crate::meter::charge(self.meter.as_ref(), bytes.len() as u64).await;
        Ok(bytes)
    }

    /// Streaming download (the S3-family override of
    /// [`Backend::get_to_path`](crate::backend::Backend::get_to_path)): copy the object
    /// body straight to `dest` at constant memory (temp → fsync → atomic rename) without
    /// ever holding the whole object in RAM. A missing object maps to `NotFound`.
    pub(crate) async fn get_to_path(&self, key: &ObjectKey, dest: &Path) -> Result<()> {
        let resp = self.fetch_response(key, None).await?;
        // Verify the committed length against the object's declared Content-Length so a
        // short-but-clean body is not atomically committed as if whole.
        let expected_len = streaming::content_length(&resp);
        streaming::stream_to_file(resp, dest, expected_len, self.meter.as_ref()).await
    }

    async fn fetch(&self, key: &ObjectKey, range: Option<String>) -> Result<Bytes> {
        let resp = self.fetch_response(key, range).await?;
        resp.bytes()
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    /// Send a GET (optionally ranged) and return the response once its status is
    /// confirmed successful. Maps 404 to `NotFound`; other non-2xx to a backend error.
    async fn fetch_response(
        &self,
        key: &ObjectKey,
        range: Option<String>,
    ) -> Result<reqwest::Response> {
        let extra: Vec<(&str, String)> = match range {
            Some(r) => vec![("range", r)],
            None => vec![],
        };
        let resp = self
            .send(Method::GET, Some(key.as_str()), &[], &extra, None)
            .await?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Err(StoreError::NotFound(key.to_string()));
        }
        if !resp.status().is_success() {
            return Err(Self::error(resp).await);
        }
        Ok(resp)
    }

    pub(crate) async fn head(&self, key: &ObjectKey) -> Result<ObjectMeta> {
        let resp = self
            .send(Method::HEAD, Some(key.as_str()), &[], &[], None)
            .await?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Err(StoreError::NotFound(key.to_string()));
        }
        if !resp.status().is_success() {
            return Err(Self::error(resp).await);
        }
        let size = resp
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        // The source's own time when the object carries one, and nothing when it
        // does not — never the object's `Last-Modified`, which is when the
        // provider accepted the upload. See the module documentation.
        let modified_unix = resp
            .headers()
            .get(H_SRC_MODIFIED)
            .and_then(|v| v.to_str().ok())
            .and_then(parse_src_modified);
        Ok(ObjectMeta {
            key: key.clone(),
            size,
            modified_unix,
        })
    }

    pub(crate) async fn exists(&self, key: &ObjectKey) -> Result<bool> {
        match self.head(key).await {
            Ok(_) => Ok(true),
            Err(StoreError::NotFound(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    pub(crate) async fn delete(&self, key: &ObjectKey) -> Result<()> {
        let resp = self
            .send(Method::DELETE, Some(key.as_str()), &[], &[], None)
            .await?;
        // S3 delete is idempotent: 204 whether or not the object existed.
        if resp.status().is_success() || resp.status() == StatusCode::NOT_FOUND {
            Ok(())
        } else {
            Err(Self::error(resp).await)
        }
    }

    pub(crate) async fn list_page(&self, prefix: &str, cursor: Option<String>) -> Result<Page> {
        let mut params = vec![
            ("list-type", "2".to_string()),
            ("max-keys", LIST_PAGE_SIZE.to_string()),
            ("prefix", prefix.to_string()),
        ];
        if let Some(token) = cursor {
            params.push(("continuation-token", token));
        }
        let resp = self.send(Method::GET, None, &params, &[], None).await?;
        if !resp.status().is_success() {
            return Err(Self::error(resp).await);
        }
        let body = resp
            .text()
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        let listing = xml::parse_list(&body)?;
        let items = listing
            .items
            .into_iter()
            // No time: `ListObjectsV2` does not return user metadata, and the
            // `LastModified` it does return is the upload time — which would make
            // every destination object look newer than its source and cause
            // `--update` to skip the whole tree. See the module documentation.
            .map(|(k, size)| ObjectMeta {
                key: ObjectKey::new(k),
                size,
                modified_unix: None,
            })
            .collect();
        Ok(Page {
            items,
            next_cursor: listing.next_token,
            // An object store holds keys, not filesystem entries: there is
            // nothing here that could be a symbolic link, so there is nothing
            // to report about one.
            ..Page::default()
        })
    }

    /// Issue a delegated (presigned) PUT authorization for `key` — the S3/R2
    /// implementation of [`Backend::prepare_upload`](crate::backend::Backend::prepare_upload).
    ///
    /// Builds a SigV4 **presigned PUT URL** valid for [`PRESIGN_TTL_SECS`]. The wall clock
    /// is read here (via [`now_unix`]); the pure builder [`presign_put`] takes the
    /// timestamp as a parameter so the signature math stays offline-testable. `content_len`
    /// is not part of the S3 signature (only `host`, plus `x-amz-content-sha256` when a
    /// hash is bound), so the client is free to send it as an ordinary header.
    pub(crate) fn prepare_upload(
        &self,
        key: &ObjectKey,
        content_len: u64,
        content_sha256: Option<&[u8; 32]>,
    ) -> Result<UploadTicket> {
        let _ = content_len;
        let (url, headers, expires_unix) = presign_put(
            &self.config,
            key.as_str(),
            content_sha256,
            now_unix(),
            PRESIGN_TTL_SECS,
        );
        Ok(UploadTicket {
            method: "PUT".to_string(),
            url,
            headers,
            expires_unix: Some(expires_unix),
        })
    }
}

// ---- helpers -----------------------------------------------------------------

fn host_of(endpoint: &str) -> String {
    endpoint
        .strip_prefix("https://")
        .or_else(|| endpoint.strip_prefix("http://"))
        .unwrap_or(endpoint)
        .trim_end_matches('/')
        .to_string()
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// AWS URI encoding. `encode_slash=false` keeps `/` (for path segments).
fn uri_encode(s: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else if b == b'/' && !encode_slash {
            out.push('/');
        } else {
            out.push('%');
            out.push(hex_upper(b >> 4));
            out.push(hex_upper(b & 0x0f));
        }
    }
    out
}

fn hex_upper(n: u8) -> char {
    if n < 10 {
        (b'0' + n) as char
    } else {
        (b'A' + n - 10) as char
    }
}

/// Canonical query string: URI-encoded keys and values, sorted by key.
fn canonical_query(params: &[(&str, String)]) -> String {
    let mut encoded: Vec<(String, String)> = params
        .iter()
        .map(|(k, v)| (uri_encode(k, true), uri_encode(v, true)))
        .collect();
    encoded.sort();
    encoded
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// Format a unix timestamp as `YYYYMMDDTHHMMSSZ` (UTC), no external date crate.
fn amz_datetime(unix: i64) -> String {
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let (hh, mm, ss) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    format!("{y:04}{m:02}{d:02}T{hh:02}{mm:02}{ss:02}Z")
}

/// Howard Hinnant's civil-from-days algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

// ---- presigned (delegated) upload --------------------------------------------

/// Assemble a SigV4 presigned **PUT** for `key`: the full URL (query includes
/// `X-Amz-Signature`), the headers the client must send verbatim, and the absolute
/// expiry (`now_unix + ttl_secs`).
///
/// Pure and deterministic in `now_unix` — the caller injects the wall clock so the
/// signature math is unit-testable offline. When `content_sha256` is `Some`, its lowercase
/// hex is bound into the signature (adding `x-amz-content-sha256` to the signed headers and
/// returning it as a client header); otherwise the payload is signed as `UNSIGNED-PAYLOAD`
/// and no content header is required.
fn presign_put(
    cfg: &S3Config,
    key: &str,
    content_sha256: Option<&[u8; 32]>,
    now_unix: i64,
    ttl_secs: u64,
) -> (String, Vec<(String, String)>, u64) {
    let host = host_of(&cfg.endpoint);
    let canonical_uri = format!("/{}/{}", cfg.bucket, uri_encode(key, false));
    let amz_date = amz_datetime(now_unix);

    // Bind the content hash only when supplied; else UNSIGNED-PAYLOAD. When bound, the
    // same header is both signed and handed back for the client to send verbatim.
    let (payload_hash, extra_signed, client_headers) = match content_sha256 {
        Some(h) => {
            let hex = hex::encode(h);
            let hdr = ("x-amz-content-sha256".to_string(), hex.clone());
            (hex, vec![hdr.clone()], vec![hdr])
        }
        None => ("UNSIGNED-PAYLOAD".to_string(), Vec::new(), Vec::new()),
    };

    let query = presign_query_string(
        "PUT",
        &host,
        &canonical_uri,
        &extra_signed,
        &payload_hash,
        &cfg.access_key,
        &cfg.secret_key,
        &cfg.region,
        S3_SERVICE,
        &amz_date,
        ttl_secs,
    );
    let url = format!(
        "{}{}?{}",
        cfg.endpoint.trim_end_matches('/'),
        canonical_uri,
        query
    );
    let expires_unix = (now_unix.max(0) as u64).saturating_add(ttl_secs);
    (url, client_headers, expires_unix)
}

/// The query-string variant of [`sigv4::authorization`]: build the canonical query for a
/// SigV4 presigned request and append `X-Amz-Signature`. Reuses the exact canonical-query
/// encoding of the buffered path ([`canonical_query`] / [`uri_encode`]) and the shared
/// signing crux ([`sigv4::sign_canonical_request`]), so header-signed and presigned
/// requests share one implementation of the SigV4 math.
///
/// `host` is the value of the mandatory signed `host` header; `extra_signed_headers` are
/// additional headers bound into the signature (added to both the canonical headers and
/// `X-Amz-SignedHeaders`). `payload_hash` is `"UNSIGNED-PAYLOAD"` or lowercase hex.
#[allow(clippy::too_many_arguments)]
fn presign_query_string(
    method: &str,
    host: &str,
    canonical_uri: &str,
    extra_signed_headers: &[(String, String)],
    payload_hash: &str,
    access_key: &str,
    secret_key: &str,
    region: &str,
    service: &str,
    amz_date: &str,
    expires_secs: u64,
) -> String {
    let credential = format!(
        "{access_key}/{}",
        sigv4::credential_scope(amz_date, region, service)
    );

    let mut headers: Vec<(String, String)> = vec![("host".to_string(), host.to_string())];
    headers.extend(extra_signed_headers.iter().cloned());
    let (signed_headers, canonical_headers) = sigv4::canonicalize_headers(&headers);

    // The presign query params, minus the signature itself. `canonical_query` URI-encodes
    // and sorts them (so `/` in the credential → `%2F`, `;` in signed-headers → `%3B`),
    // exactly matching the canonical query that goes into the signature below.
    let params: Vec<(&str, String)> = vec![
        ("X-Amz-Algorithm", "AWS4-HMAC-SHA256".to_string()),
        ("X-Amz-Credential", credential),
        ("X-Amz-Date", amz_date.to_string()),
        ("X-Amz-Expires", expires_secs.to_string()),
        ("X-Amz-SignedHeaders", signed_headers.clone()),
    ];
    let cq = canonical_query(&params);

    let canonical_request = format!(
        "{method}\n{canonical_uri}\n{cq}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    );
    let signature =
        sigv4::sign_canonical_request(&canonical_request, secret_key, region, service, amz_date);
    format!("{cq}&X-Amz-Signature={signature}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_source_time_is_written_in_the_spelling_rclone_reads() {
        // Borrowed on purpose (`backend/s3/s3.go`, `metaMtime`): a private format
        // would make every object DCTL wrote look, to rclone, like a file
        // modified when it was uploaded — and the other way round.
        assert_eq!(
            render_src_modified(SourceModified::at(1_577_836_800)).as_deref(),
            Some("1577836800.000000000")
        );
        assert_eq!(render_src_modified(SourceModified::unknown()), None);
    }

    /// The header set a write actually carries, key included.
    ///
    /// `render_src_modified` being tested was never enough: it could be correct
    /// while the header it feeds was named something else, or while nothing sent
    /// it at all. Every S3 write goes through this one function, and no S3
    /// credentials exist in this environment — `tests/s3_live.rs` has never run —
    /// so this is the only thing standing between the sync fix and a silent
    /// regression on S3 and R2 (`HANDOVER.md` §11.2).
    #[test]
    fn a_write_carries_the_source_time_as_the_user_metadata_header() {
        assert_eq!(
            S3Client::metadata_headers(SourceModified::at(1_577_836_800)),
            vec![("x-amz-meta-mtime", "1577836800.000000000".to_string())]
        );
    }

    #[test]
    fn a_write_with_no_source_time_carries_no_metadata_at_all() {
        // Absent rather than zero: an object stamped 1970 looks older than every
        // local file and inverts `--update` over all of them. S3's own
        // `LastModified` then stands, which `head` deliberately does not read.
        assert!(S3Client::metadata_headers(SourceModified::unknown()).is_empty());
    }

    #[test]
    fn a_written_time_reads_back_as_the_same_whole_second() {
        for seconds in [0_i64, 1, 1_577_836_800, -86_400] {
            let rendered =
                render_src_modified(SourceModified::at(seconds)).expect("a known time renders");
            assert_eq!(parse_src_modified(&rendered), Some(seconds), "{seconds}");
        }
    }

    #[test]
    fn a_time_another_tool_wrote_is_read_or_ignored_but_never_fatal() {
        // rclone writes a real fraction; a stray value from anything else must
        // not make an otherwise-readable object undescribable.
        assert_eq!(
            parse_src_modified("1577836800.123456789"),
            Some(1_577_836_800)
        );
        assert_eq!(parse_src_modified("1577836800"), Some(1_577_836_800));
        assert_eq!(parse_src_modified("yesterday"), None);
        assert_eq!(parse_src_modified(""), None);
    }

    #[test]
    fn a_pre_epoch_fraction_floors_backwards_rather_than_forwards() {
        // -1.5 s is one and a half seconds *before* the epoch, so its whole
        // second is -2. Truncating towards zero would move the file forwards.
        assert_eq!(parse_src_modified("-1.500000000"), Some(-2));
        assert_eq!(parse_src_modified("-1.000000000"), Some(-1));
    }

    // AWS's published DUMMY credentials for SigV4 examples — never real secrets.
    const AWS_EXAMPLE_ACCESS: &str = "AKIAIOSFODNN7EXAMPLE";
    const AWS_EXAMPLE_SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    /// Unix seconds for `20130524T000000Z`, the AWS presigned-example timestamp.
    const AWS_EXAMPLE_UNIX: i64 = 1_369_353_600;

    /// **Offline SigV4 presign KAT.** Reproduces AWS's published presigned-URL example
    /// (S3, GET `/test.txt`, virtual-hosted host, `UNSIGNED-PAYLOAD`, 24 h expiry) — see
    /// <https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html>.
    ///
    /// Fully deterministic (pinned timestamp, no clock, no network): asserting the exact
    /// query — canonical params **and** the `X-Amz-Signature` AWS publishes — proves the
    /// canonical-request assembly + signing-key derivation + HMAC math are correct.
    #[test]
    fn presign_matches_aws_documented_vector() {
        let query = presign_query_string(
            "GET",
            "examplebucket.s3.amazonaws.com",
            "/test.txt",
            &[],
            "UNSIGNED-PAYLOAD",
            AWS_EXAMPLE_ACCESS,
            AWS_EXAMPLE_SECRET,
            "us-east-1",
            "s3",
            "20130524T000000Z",
            86_400,
        );
        assert_eq!(
            query,
            "X-Amz-Algorithm=AWS4-HMAC-SHA256\
             &X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request\
             &X-Amz-Date=20130524T000000Z\
             &X-Amz-Expires=86400\
             &X-Amz-SignedHeaders=host\
             &X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
        );
    }

    fn example_config() -> S3Config {
        S3Config::new(
            "https://s3.us-east-1.amazonaws.com",
            "us-east-1",
            "examplebucket",
            AWS_EXAMPLE_ACCESS,
            AWS_EXAMPLE_SECRET,
        )
    }

    /// Path-style PUT presign: URL, query params, and expiry assemble as expected, and an
    /// unbound payload hands the client no content header.
    #[test]
    fn presign_put_assembles_url_params_and_expiry() {
        let cfg = example_config();
        let (url, headers, expires) =
            presign_put(&cfg, "path/to obj.bin", None, AWS_EXAMPLE_UNIX, 900);

        assert!(
            url.starts_with("https://s3.us-east-1.amazonaws.com/examplebucket/path/to%20obj.bin?"),
            "unexpected url: {url}"
        );
        assert!(url.contains("X-Amz-Algorithm=AWS4-HMAC-SHA256"));
        assert!(url.contains(
            "X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request"
        ));
        assert!(url.contains("X-Amz-Date=20130524T000000Z"));
        assert!(url.contains("X-Amz-Expires=900"));
        assert!(url.contains("X-Amz-SignedHeaders=host"));
        assert!(url.contains("&X-Amz-Signature="));
        // UNSIGNED-PAYLOAD → nothing extra for the client to send.
        assert!(headers.is_empty());
        assert_eq!(expires, AWS_EXAMPLE_UNIX as u64 + 900);
    }

    /// Binding a content SHA-256 adds `x-amz-content-sha256` to the signed headers (its
    /// `;` separator URL-encodes to `%3B`) and returns it for the client to send verbatim.
    #[test]
    fn presign_put_binds_content_sha256_when_given() {
        let cfg = example_config();
        let hash = [0x11u8; 32];
        let hex = "11".repeat(32);
        let (url, headers, _) = presign_put(&cfg, "k", Some(&hash), AWS_EXAMPLE_UNIX, 900);

        assert_eq!(headers, vec![("x-amz-content-sha256".to_string(), hex)]);
        assert!(
            url.contains("X-Amz-SignedHeaders=host%3Bx-amz-content-sha256"),
            "unexpected url: {url}"
        );
    }
}
