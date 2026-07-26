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
mod upload;

pub use config::B2Credentials;

use async_trait::async_trait;
use bytes::Bytes;
use serde::de::DeserializeOwned;
use tokio::sync::Mutex;

use crate::backend::Backend;
use crate::checksum::ContentHash;
use crate::error::{Result, StoreError};
use crate::model::{ByteRange, ObjectKey, ObjectMeta, Page, PutOutcome};

use api::{AuthState, AuthorizeResponse, ListBucketsResponse};

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

    async fn authorize(&self) -> Result<AuthState> {
        let resp = self
            .client
            .get(constants::AUTHORIZE_URL)
            .basic_auth(&self.creds.key_id, Some(&self.creds.app_key))
            .send()
            .await
            .map_err(reqwest_err)?;
        let parsed: AuthorizeResponse = parse_json(resp).await?;
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
        let resp = self
            .client
            .post(&url)
            .header(constants::H_AUTHORIZATION, token)
            .json(&serde_json::json!({ "accountId": account_id, "bucketName": self.bucket_name }))
            .send()
            .await
            .map_err(reqwest_err)?;
        let listed: ListBucketsResponse = parse_json(resp).await?;
        listed
            .buckets
            .into_iter()
            .find(|b| b.bucket_name == self.bucket_name)
            .map(|b| b.bucket_id)
            .ok_or_else(|| StoreError::Backend(format!("bucket not found: {}", self.bucket_name)))
    }

    /// Authenticated POST of a JSON body to a `b2api/v2` endpoint, parsed into `T`.
    pub(crate) async fn post_json<T: DeserializeOwned>(
        &self,
        auth: &AuthState,
        endpoint: &str,
        body: serde_json::Value,
    ) -> Result<T> {
        tracing::debug!(endpoint, "b2 api request");
        let url = format!("{}/{}/{}", auth.api_url, constants::API_PREFIX, endpoint);
        let resp = self
            .client
            .post(&url)
            .header(constants::H_AUTHORIZATION, &auth.auth_token)
            .json(&body)
            .send()
            .await
            .map_err(reqwest_err)?;
        parse_json(resp).await
    }
}

/// Map a reqwest transport error into a backend error.
pub(crate) fn reqwest_err(e: reqwest::Error) -> StoreError {
    StoreError::Backend(e.to_string())
}

/// Read a response, erroring on non-2xx status, then deserialize the body as `T`.
pub(crate) async fn parse_json<T: DeserializeOwned>(resp: reqwest::Response) -> Result<T> {
    let status = resp.status();
    let bytes = resp.bytes().await.map_err(reqwest_err)?;
    if !status.is_success() {
        return Err(StoreError::Backend(format!(
            "b2 api error {}: {}",
            status.as_u16(),
            String::from_utf8_lossy(&bytes)
        )));
    }
    serde_json::from_slice(&bytes).map_err(|e| StoreError::Backend(format!("b2 json parse: {e}")))
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

    async fn get(&self, key: &ObjectKey) -> Result<Bytes> {
        download::get(self, key).await
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
}
