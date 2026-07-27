//! Backblaze B2 storage backend.
//!
//! Implements the [`Backend`](crate::backend::Backend) trait over the B2 native
//! API v2: SHA-1-verified single-file and large-file (multipart) uploads, Range
//! downloads, prefix listing, and version-aware delete. Authorization is cached
//! and the bucket id is resolved from the (bucket-scoped) key or `b2_list_buckets`.

mod api;
mod config;
mod constants;
mod download;
mod listing;
mod name;
mod retry;
mod upload;

pub use config::B2Credentials;

use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use serde::de::DeserializeOwned;
use tokio::sync::Mutex;

use crate::backend::{Backend, UploadTicket};
use crate::checksum::ContentHash;
use crate::error::{Result, StoreError};
use crate::model::{ByteRange, ObjectKey, ObjectMeta, Page, PutOutcome};

use api::{AuthState, AuthorizeResponse, ListBucketsResponse};
use retry::{Attempt, Observed};

/// One attempt's result: the value, or everything needed to decide whether to
/// make another attempt. See [`retry`].
type Attempted<T> = std::result::Result<T, Attempt>;

/// A `Backend` backed by a Backblaze B2 bucket.
pub struct B2Backend {
    pub(crate) client: reqwest::Client,
    creds: B2Credentials,
    pub(crate) bucket_name: String,
    auth: Mutex<Option<AuthState>>,
}

impl B2Backend {
    /// Create a backend for `bucket_name` using `creds`. Authorization happens
    /// lazily on first use.
    pub fn new(creds: B2Credentials, bucket_name: impl Into<String>) -> Result<Self> {
        // Hybrid post-quantum TLS (falls back to classical if the server lacks it).
        let client = crate::tls::post_quantum_client()?;
        Ok(Self {
            client,
            creds,
            bucket_name: bucket_name.into(),
            auth: Mutex::new(None),
        })
    }

    /// Current authorization, authorizing on first call.
    pub(crate) async fn auth(&self) -> Result<AuthState> {
        let mut guard = self.auth.lock().await;
        if let Some(state) = guard.as_ref() {
            return Ok(state.clone());
        }
        let state = self.authorize().await?;
        *guard = Some(state.clone());
        Ok(state)
    }

    /// Drop the cached authorization so the next [`auth`](Self::auth) re-fetches
    /// one.
    ///
    /// B2 tokens expire after 24 hours, and the cache had no way to notice: a
    /// `dctl mount` left up over a weekend, or a multi-day first sync, started
    /// answering `401 expired_auth_token` and could not recover, because nothing
    /// ever cleared the `OnceLock`-shaped state this replaces. The only caller is
    /// the retry path, and only for the one `401` that means the token aged out
    /// rather than that the key is wrong.
    pub(crate) async fn forget_auth(&self) {
        *self.auth.lock().await = None;
    }

    async fn authorize(&self) -> Result<AuthState> {
        let parsed: AuthorizeResponse = retry::run(constants::EP_AUTHORIZE, |_| async {
            let resp = self
                .client
                .get(constants::AUTHORIZE_URL)
                .basic_auth(&self.creds.key_id, Some(&self.creds.app_key))
                .send()
                .await
                .map_err(transport_attempt)?;
            read_json(resp).await
        })
        .await?;
        tracing::debug!(api_url = %parsed.api_url, "b2 authorized");

        let bucket_id = match parsed.allowed.bucket_id.clone() {
            Some(id) => id,
            None => {
                self.resolve_bucket_id(
                    &parsed.api_url,
                    &parsed.authorization_token,
                    &parsed.account_id,
                )
                .await?
            }
        };

        Ok(AuthState {
            api_url: parsed.api_url,
            download_url: parsed.download_url,
            auth_token: parsed.authorization_token,
            bucket_id,
            recommended_part_size: parsed.recommended_part_size.max(constants::MIN_PART_SIZE),
        })
    }

    async fn resolve_bucket_id(
        &self,
        api_url: &str,
        token: &str,
        account_id: &str,
    ) -> Result<String> {
        let url = format!(
            "{api_url}/{}/{}",
            constants::API_PREFIX,
            constants::EP_LIST_BUCKETS
        );
        let listed: ListBucketsResponse = retry::run(constants::EP_LIST_BUCKETS, |_| async {
            let resp = self
                .client
                .post(&url)
                .header(constants::H_AUTHORIZATION, token)
                .json(
                    &serde_json::json!({ "accountId": account_id, "bucketName": self.bucket_name }),
                )
                .send()
                .await
                .map_err(transport_attempt)?;
            read_json(resp).await
        })
        .await?;
        listed
            .buckets
            .into_iter()
            .find(|b| b.bucket_name == self.bucket_name)
            .map(|b| b.bucket_id)
            .ok_or_else(|| StoreError::Backend(format!("bucket not found: {}", self.bucket_name)))
    }

    /// Authenticated POST of a JSON body to a `b2api/v2` endpoint, parsed into
    /// `T`, retried while the provider says the failure will not last.
    ///
    /// The authorization is re-read on **every** attempt rather than captured
    /// once, so an expired token that the retry path has just cleared is replaced
    /// before the next try instead of being sent again. The caller's `body` is
    /// built before the first attempt and reused: the only authorization-derived
    /// field any B2 request body carries is `bucketId`, which identifies the
    /// bucket and not the session, so re-authorizing cannot change it.
    pub(crate) async fn post_json<T: DeserializeOwned>(
        &self,
        endpoint: &'static str,
        body: serde_json::Value,
    ) -> Result<T> {
        retry::run(endpoint, |_| async {
            let auth = self.auth().await.map_err(Attempt::transport)?;
            self.post_json_once(&auth, endpoint, body.clone()).await
        })
        .await
    }

    /// One attempt at [`post_json`](Self::post_json), for the callers that own an
    /// outer retry loop of their own.
    ///
    /// The upload paths need that: B2 answers a busy storage pod with `503`, and
    /// its documented remedy is to ask for a **new** upload URL and send the
    /// bytes there. A retry that replayed the same URL would keep arriving at the
    /// same busy pod, so the loop has to enclose the `b2_get_upload_url` call as
    /// well as the upload — which means this layer must not retry underneath it.
    async fn post_json_once<T: DeserializeOwned>(
        &self,
        auth: &AuthState,
        endpoint: &str,
        body: serde_json::Value,
    ) -> Attempted<T> {
        tracing::debug!(endpoint, "b2 api request");
        let url = format!("{}/{}/{}", auth.api_url, constants::API_PREFIX, endpoint);
        let resp = self
            .client
            .post(&url)
            .header(constants::H_AUTHORIZATION, &auth.auth_token)
            .json(&body)
            .send()
            .await
            .map_err(transport_attempt)?;
        self.observe_expiry(read_json(resp).await).await
    }

    /// Clear the cached authorization when `attempted` failed because the token
    /// aged out, and pass the result through untouched.
    ///
    /// Done here rather than in [`retry::run`] because the driver is deliberately
    /// generic over the operation and knows nothing about B2 sessions, and doing
    /// it in each call site by hand is the arrangement that works until somebody
    /// adds the next call site.
    async fn observe_expiry<T>(&self, attempted: Attempted<T>) -> Attempted<T> {
        if let Err(failed) = &attempted
            && failed.observed.is_expired_token()
        {
            tracing::info!("b2 authorization token expired; re-authorizing before the retry");
            self.forget_auth().await;
        }
        attempted
    }
}

/// Map a reqwest transport error into a backend error.
pub(crate) fn reqwest_err(e: reqwest::Error) -> StoreError {
    StoreError::Backend(e.to_string())
}

/// A request that never got an answer: nothing observed, so the retry decision
/// is made on the absence of a status rather than on a guess about the message.
fn transport_attempt(e: reqwest::Error) -> Attempt {
    Attempt::transport(reqwest_err(e))
}

/// Read a response, erroring on non-2xx status, then deserialize the body as `T`.
///
/// Carries the status, B2's own error `code` and any `Retry-After` alongside the
/// error, because those three facts are what decide whether another attempt can
/// possibly differ — and reading them back out of a formatted message later is a
/// rule that breaks the first time somebody rewords it.
async fn read_json<T: DeserializeOwned>(resp: reqwest::Response) -> Attempted<T> {
    let status = resp.status();
    let retry_after = retry_after_of(resp.headers());
    let bytes = resp.bytes().await.map_err(transport_attempt)?;
    if !status.is_success() {
        return Err(Attempt {
            observed: Observed {
                status: Some(status.as_u16()),
                code: b2_error_code(&bytes),
                retry_after,
            },
            error: StoreError::Backend(format!(
                "b2 api error {}: {}",
                status.as_u16(),
                String::from_utf8_lossy(&bytes)
            )),
        });
    }
    serde_json::from_slice(&bytes).map_err(|e| {
        // A 2xx whose body will not parse is not a transport failure and not
        // something a second identical request would fix; it is reported as it
        // is, and `Observed::transport` is only how it reaches the classifier.
        Attempt::transport(StoreError::Backend(format!("b2 json parse: {e}")))
    })
}

/// B2's machine-readable `code` from an error body, when it sent one.
///
/// It is what separates the `401` that means "this token aged out" from the
/// `401` that means "this application key is wrong" — one is worth retrying and
/// the other is worth reporting immediately.
fn b2_error_code(body: &[u8]) -> Option<String> {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()?
        .get("code")?
        .as_str()
        .map(str::to_owned)
}

/// The `Retry-After` a response carried, in seconds.
///
/// Only the delta-seconds form is read. RFC 9110 also permits an HTTP date, and
/// B2 does not send one; a date therefore falls back to this module's own
/// schedule rather than being mis-parsed into a wait of zero.
fn retry_after_of(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    headers
        .get(constants::H_RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
        .map(Duration::from_secs)
}

#[async_trait]
impl Backend for B2Backend {
    fn name(&self) -> &'static str {
        "b2"
    }

    async fn put(
        &self,
        key: &ObjectKey,
        data: Bytes,
        expected: &ContentHash,
    ) -> Result<PutOutcome> {
        upload::put(self, key, data, expected).await
    }

    async fn put_from_path(
        &self,
        key: &ObjectKey,
        source: &std::path::Path,
        expected: &ContentHash,
    ) -> Result<PutOutcome> {
        upload::put_from_path(self, key, source, expected).await
    }

    async fn get(&self, key: &ObjectKey) -> Result<Bytes> {
        download::get(self, key).await
    }

    async fn get_to_path(&self, key: &ObjectKey, dest: &std::path::Path) -> Result<()> {
        download::get_to_path(self, key, dest).await
    }

    async fn get_range(&self, key: &ObjectKey, range: ByteRange) -> Result<Bytes> {
        download::get_range(self, key, range).await
    }

    async fn head(&self, key: &ObjectKey) -> Result<ObjectMeta> {
        listing::head(self, key).await
    }

    async fn exists(&self, key: &ObjectKey) -> Result<bool> {
        listing::exists(self, key).await
    }

    async fn delete(&self, key: &ObjectKey) -> Result<()> {
        listing::delete(self, key).await
    }

    async fn list_page(&self, prefix: &str, cursor: Option<String>) -> Result<Page> {
        listing::list_page(self, prefix, cursor).await
    }

    async fn prepare_upload(
        &self,
        key: &ObjectKey,
        content_len: u64,
        content_sha256: Option<&[u8; 32]>,
    ) -> Result<UploadTicket> {
        upload::prepare_upload(self, key, content_len, content_sha256).await
    }
}
