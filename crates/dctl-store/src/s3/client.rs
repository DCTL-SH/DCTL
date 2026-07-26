//! The shared S3 protocol client: SigV4-signed requests and the object operations.
//! Reused by every S3-family provider backend (generic S3, R2, …).

use bytes::Bytes;
use reqwest::{Method, StatusCode};

use crate::checksum::ContentHash;
use crate::error::{Result, StoreError};
use crate::model::{ByteRange, ObjectKey, ObjectMeta, Page, PutOutcome};

use super::config::{S3_SERVICE, S3Config};
use super::sigv4;
use super::xml;

/// Objects larger than this use the multipart upload API.
const MULTIPART_THRESHOLD: usize = 100 * 1024 * 1024;
/// Multipart part size (>= S3's 5 MiB minimum).
const PART_SIZE: usize = 100 * 1024 * 1024;
/// Objects returned per listing page.
const LIST_PAGE_SIZE: u32 = 1000;

pub(crate) struct S3Client {
    http: reqwest::Client,
    config: S3Config,
}

impl S3Client {
    pub(crate) fn new(config: S3Config) -> Result<Self> {
        Ok(Self {
            http: crate::tls::post_quantum_client()?,
            config,
        })
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
        req.send()
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn error(resp: reqwest::Response) -> StoreError {
        let status = resp.status().as_u16();
        let body = resp.bytes().await.unwrap_or_default();
        let text = String::from_utf8_lossy(&body);
        let code = xml::extract_tag(&text, "Code").unwrap_or_else(|| "?".to_string());
        StoreError::Backend(format!("s3 error {status}: {code}"))
    }

    // ---- operations ----------------------------------------------------------

    pub(crate) async fn put(
        &self,
        key: &ObjectKey,
        data: Bytes,
        expected: &ContentHash,
    ) -> Result<PutOutcome> {
        let caller = ContentHash::compute(expected.algo, &data);
        if !caller.matches(expected) {
            return Err(StoreError::ChecksumMismatch {
                expected: expected.hex(),
                actual: caller.hex(),
            });
        }

        if data.len() <= MULTIPART_THRESHOLD {
            self.put_single(key.as_str(), data.clone()).await?;
        } else {
            self.put_multipart(key.as_str(), &data).await?;
        }
        Ok(PutOutcome {
            size: data.len() as u64,
            verified: caller,
        })
    }

    async fn put_single(&self, key: &str, data: Bytes) -> Result<()> {
        // S3 recomputes the body SHA-256 and rejects if it differs from the signed
        // x-amz-content-sha256, so this is a verified write.
        let resp = self
            .send(Method::PUT, Some(key), &[], &[], Some(data))
            .await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(Self::error(resp).await)
        }
    }

    async fn put_multipart(&self, key: &str, data: &[u8]) -> Result<()> {
        let create = self
            .send(
                Method::POST,
                Some(key),
                &[("uploads", String::new())],
                &[],
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

        let mut parts_xml = String::from("<CompleteMultipartUpload>");
        let mut part_number = 1u32;
        let mut offset = 0usize;
        while offset < data.len() {
            let end = (offset + PART_SIZE).min(data.len());
            let chunk = Bytes::copy_from_slice(&data[offset..end]);
            let query = [
                ("partNumber", part_number.to_string()),
                ("uploadId", upload_id.clone()),
            ];
            let resp = self
                .send(Method::PUT, Some(key), &query, &[], Some(chunk))
                .await?;
            if !resp.status().is_success() {
                return Err(Self::error(resp).await);
            }
            let etag = resp
                .headers()
                .get("etag")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            parts_xml.push_str(&format!(
                "<Part><PartNumber>{part_number}</PartNumber><ETag>{etag}</ETag></Part>"
            ));
            offset = end;
            part_number += 1;
        }
        parts_xml.push_str("</CompleteMultipartUpload>");

        let complete = self
            .send(
                Method::POST,
                Some(key),
                &[("uploadId", upload_id)],
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

    pub(crate) async fn get(&self, key: &ObjectKey) -> Result<Bytes> {
        self.fetch(key, None).await
    }

    pub(crate) async fn get_range(&self, key: &ObjectKey, range: ByteRange) -> Result<Bytes> {
        let header = match range.length {
            Some(len) => format!("bytes={}-{}", range.offset, range.offset + len - 1),
            None => format!("bytes={}-", range.offset),
        };
        self.fetch(key, Some(header)).await
    }

    async fn fetch(&self, key: &ObjectKey, range: Option<String>) -> Result<Bytes> {
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
        resp.bytes()
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
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
        Ok(ObjectMeta {
            key: key.clone(),
            size,
            modified_unix: None,
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
            .map(|(k, size)| ObjectMeta {
                key: ObjectKey::new(k),
                size,
                modified_unix: None,
            })
            .collect();
        Ok(Page {
            items,
            next_cursor: listing.next_token,
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
