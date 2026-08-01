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
use crate::deadline::{Answered, Deadlines, Expired};
use crate::error::{Result, StoreError};
use crate::model::{ByteRange, ObjectKey, ObjectMeta, Page, PutOutcome};
use crate::modified::SourceModified;

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
    /// Who is told about bytes as they cross the link, part by part and body
    /// chunk by body chunk. See [`crate::meter`].
    pub(crate) meter: std::sync::Arc<dyn crate::meter::Meter>,
    /// How large a part is, and therefore how much memory an upload costs. See
    /// [`part_size`](Self::part_size) and the contract in [`constants`].
    part_size: u64,
    /// Where `b2_authorize_account` is asked. See
    /// [`with_authorize_url`](Self::with_authorize_url).
    authorize_url: String,
    /// How long this run waits for a link that has gone quiet, and for one that
    /// will not answer at all. See [`crate::deadline`].
    ///
    /// Held rather than passed per call because half of it — the connect
    /// deadline — is built into [`client`](Self::client) and cannot be changed
    /// afterwards. One field, set once, so the two halves cannot drift apart.
    pub(crate) deadlines: Deadlines,
}

/// This backend's name, as [`Backend::name`] spells it and as a stalled request
/// is attributed.
pub(crate) const B2_BACKEND_NAME: &str = "b2";

impl B2Backend {
    /// Create a backend for `bucket_name` using `creds`. Authorization happens
    /// lazily on first use.
    /// `deadlines` is a required argument rather than a builder, and the
    /// difference is the point. A builder can be forgotten, and this crate has
    /// already paid for that once: `crate::meter` was written into each arm of
    /// the CLI's construction match and four of the five arms dropped it, so
    /// `--bwlimit` was inert on every cloud provider with nothing to indicate
    /// it. A positional argument cannot be dropped — the compiler will not
    /// accept the call without it.
    pub fn new(
        creds: B2Credentials,
        bucket_name: impl Into<String>,
        deadlines: Deadlines,
    ) -> Result<Self> {
        // Hybrid post-quantum TLS (falls back to classical if the server lacks it).
        let client = crate::tls::post_quantum_client(&deadlines)?;
        Ok(Self {
            client,
            creds,
            bucket_name: bucket_name.into(),
            auth: Mutex::new(None),
            meter: crate::meter::unmetered(),
            part_size: constants::DEFAULT_PART_SIZE,
            authorize_url: constants::AUTHORIZE_URL.to_string(),
            deadlines,
        })
    }

    /// The same backend, asking `b2_authorize_account` at `url`.
    ///
    /// **The only address in the whole conversation that is not discovered.**
    /// B2's authorization reply carries the `apiUrl` every later call is built
    /// on, the `downloadUrl` reads go to, and — indirectly, through
    /// `b2_get_upload_url` — the pod each upload lands on. So one override here
    /// is enough to point the entire client at a server a test controls, which
    /// is what `tests/support/mock_b2.rs` does.
    ///
    /// It exists for the reason `mock_s3` exists: B2 is the one cloud provider
    /// this repository has credentials for, its part-buffering behaviour is a
    /// memory contract stated in `HANDOVER.md`, and a contract that can only be
    /// checked by spending money on a live bucket is a contract that stops being
    /// checked.
    ///
    /// It is **also** a `b2` remote's `endpoint` setting arriving. That setting
    /// was declared on `B2Def`, accepted by `dctl config create`, printed by
    /// `dctl config show` — and dropped by the resolver, so an operator pointing
    /// a remote at their own gateway talked to Backblaze anyway. See
    /// `dctl_cli::config::reach`.
    #[must_use]
    pub fn with_authorize_url(mut self, url: impl Into<String>) -> Self {
        self.authorize_url = url.into();
        self
    }

    /// The endpoint this backend authorizes against.
    ///
    /// The far end of the `endpoint` setting's journey, and public for the
    /// reason `SftpBackend::chunk_size` is: §21.7's lesson is that the *middle*
    /// of a setting's path is where this project loses one, so both ends are
    /// pinned and the resolver's end alone is not enough.
    #[must_use]
    pub fn authorize_url(&self) -> &str {
        &self.authorize_url
    }

    /// The same backend, declaring every part and body chunk it moves to
    /// `meter`. A builder, for the reason [`crate::LocalFs::with_meter`] gives.
    #[must_use]
    pub fn with_meter(mut self, meter: std::sync::Arc<dyn crate::meter::Meter>) -> Self {
        self.meter = meter;
        self
    }

    /// The same backend, cutting large files into `part_size`-byte parts.
    ///
    /// `None` keeps the module's default part size; anything outside the
    /// envelope B2 publishes is clamped into it rather than refused, for the
    /// reason `config::clamp_part_size` gives.
    ///
    /// This is the operator's handle on how much memory an upload costs — one
    /// part, once, is the whole of it — which is why it is a builder on the
    /// backend and not a constant. A remote's `chunk_size` setting arrives here.
    #[must_use]
    pub fn with_part_size(mut self, part_size: Option<u64>) -> Self {
        if let Some(size) = part_size {
            self.part_size = config::clamp_part_size(size);
        }
        self
    }

    /// The part size in force, in bytes.
    ///
    /// Also the single-shot cutoff: an object of exactly this many bytes is one
    /// `b2_upload_file`, and one byte more is a large file. They are the same
    /// number on purpose — it is the size of the one buffer an upload holds, so
    /// splitting it into two settings would make the peak the *larger* of two
    /// numbers while looking like a single knob. The S3 client states it the same
    /// way for the same reason.
    #[must_use]
    pub(crate) const fn part_size(&self) -> u64 {
        self.part_size
    }

    /// The most memory one upload will hold, whatever the object's size.
    ///
    /// The contract in [`constants`], as a number this backend states rather than
    /// a paragraph somebody has to find: one part, times the number of parts in
    /// flight. A 10 GiB object and a 200 MiB object cost the same, and the cost
    /// is this.
    ///
    /// It is public because it is the honest answer to the question a buyer sizing
    /// a container asks, and because a figure the program will not say out loud is
    /// a figure that drifts from the code. `tests/b2_upload_memory.rs` measures the
    /// process against exactly this value, so raising the concurrency without
    /// raising the constant fails a test rather than a customer's `docker run -m`.
    ///
    /// It does **not** include the process's own baseline — an unlocked vault's
    /// Argon2id working set dominates that — and it is not the whole of a
    /// `dctl copy`, which also stages the sealed object on disk. `HANDOVER.md` §25
    /// carries the measured totals.
    #[must_use]
    pub const fn upload_peak_bytes(&self) -> u64 {
        self.part_size
            .saturating_mul(constants::UPLOAD_PARTS_IN_FLIGHT)
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
        let parsed: AuthorizeResponse = retry::run(
            constants::EP_AUTHORIZE,
            self.deadlines.run,
            &self.deadlines.stall,
            |_| async {
                let watch = self.deadlines.watch();
                let response = watch
                    .guard(
                        self.client
                            .get(&self.authorize_url)
                            .basic_auth(&self.creds.key_id, Some(&self.creds.app_key))
                            .send(),
                    )
                    .await
                    .map_err(stalled_attempt)?
                    .map_err(transport_attempt)?;
                read_json(Answered { watch, response }).await
            },
        )
        .await?;
        // `recommendedPartSize` is read and reported and is deliberately not what
        // parts are cut at — `constants::DEFAULT_PART_SIZE` says why a figure that
        // *is* the process's peak memory must not arrive from the network. Both
        // numbers are logged so an operator comparing throughput against
        // Backblaze's own advice can see the divergence instead of deducing it.
        tracing::debug!(
            api_url = %parsed.api_url,
            b2_recommended_part_size = parsed.recommended_part_size,
            part_size = self.part_size,
            "b2 authorized"
        );

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
            account_id: parsed.account_id,
            api_url: parsed.api_url,
            download_url: parsed.download_url,
            auth_token: parsed.authorization_token,
            bucket_id,
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
        let listed: ListBucketsResponse = retry::run(
            constants::EP_LIST_BUCKETS,
            self.deadlines.run,
            &self.deadlines.stall,
            |_| async {
                let watch = self.deadlines.watch();
                let response = watch
                    .guard(
                        self.client
                            .post(&url)
                            .header(constants::H_AUTHORIZATION, token)
                            .json(&serde_json::json!({
                                "accountId": account_id,
                                "bucketName": self.bucket_name,
                            }))
                            .send(),
                    )
                    .await
                    .map_err(stalled_attempt)?
                    .map_err(transport_attempt)?;
                read_json(Answered { watch, response }).await
            },
        )
        .await?;
        listed
            .buckets
            .into_iter()
            .find(|b| b.bucket_name == self.bucket_name)
            .map(|b| b.bucket_id)
            // `NotFound`, not `Backend`: a bucket that is not there is an
            // absence and the caller decides what it means. `store_identity`
            // reads it as "nothing to lose"; an operation that needed the id
            // reports it as the missing bucket it is.
            .ok_or_else(|| StoreError::NotFound(format!("bucket {}", self.bucket_name)))
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
        retry::run(
            endpoint,
            self.deadlines.run,
            &self.deadlines.stall,
            |_| async {
                let auth = self.auth().await.map_err(Attempt::transport)?;
                self.post_json_once(&auth, endpoint, body.clone()).await
            },
        )
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
        let watch = self.deadlines.watch();
        let response = watch
            .guard(
                self.client
                    .post(&url)
                    .header(constants::H_AUTHORIZATION, &auth.auth_token)
                    .json(&body)
                    .send(),
            )
            .await
            .map_err(stalled_attempt)?
            .map_err(transport_attempt)?;
        self.observe_expiry(read_json(Answered { watch, response }).await)
            .await
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

/// A request that stopped moving bytes for as long as the operator was willing
/// to wait.
///
/// Classified exactly like the line above and for the same reason: nothing
/// answered, so another attempt — on another connection — is the thing worth
/// doing. `StoreError::Transport` rather than `Backend` so the *outer* retry
/// layer agrees, since `crate::retry::observed` reads that variant as transient
/// and reads `Backend` as permanent.
///
/// **Unless it was the run's own window that closed**, and the split is the
/// point. `--timeout` and `--max-duration` both arrive here as an [`Expired`]
/// and they mean opposite things: one is a link that went quiet, which another
/// connection may fix, and one is the operator's deadline, which nothing fixes.
/// Sending the second down the transient path is what turns an exact 30 s
/// deadline into a run still going 943.6 s later (§32.9).
fn stalled_attempt(expired: Expired) -> Attempt {
    let error = expired.into_store_error(B2_BACKEND_NAME);
    if expired.is_run_deadline() {
        Attempt::run_deadline(error)
    } else {
        Attempt::transport(error)
    }
}

/// Read a response, erroring on non-2xx status, then deserialize the body as `T`.
///
/// Carries the status, B2's own error `code` and any `Retry-After` alongside the
/// error, because those three facts are what decide whether another attempt can
/// possibly differ — and reading them back out of a formatted message later is a
/// rule that breaks the first time somebody rewords it.
async fn read_json<T: DeserializeOwned>(resp: Answered) -> Attempted<T> {
    let status = resp.status();
    let retry_after = retry_after_of(resp.headers());
    // Under the same watch the request was made under, so a body that stops
    // arriving is the stall it is rather than a request that looked instant
    // because its headers were.
    let bytes = resp
        .bytes()
        .await
        .map_err(stalled_attempt)?
        .map_err(transport_attempt)?;
    if !status.is_success() {
        return Err(Attempt {
            observed: Observed {
                status: Some(status.as_u16()),
                code: b2_error_code(&bytes),
                retry_after,
                settled: false,
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

    /// The bucket's own id, resolved **fresh** from `b2_list_buckets`.
    ///
    /// Fresh, and that is the whole point: the id cached in [`AuthState`] was
    /// resolved when this run authorized, so comparing it against itself would
    /// answer `Proceed` for a bucket that had been deleted since. B2 gives a
    /// re-created bucket a new id, which makes this a genuinely
    /// [`distinguishing`](crate::guard::Strength::Distinguishing) identity —
    /// one of only two providers that can offer one.
    ///
    /// A bucket that is not there is `None` rather than an error: a
    /// configuration may name a bucket somebody has yet to create, and the guard
    /// reads absence as "nothing to lose".
    async fn store_identity(&self) -> Result<Option<crate::guard::StoreIdentity>> {
        let auth = self.auth().await?;
        match self
            .resolve_bucket_id(&auth.api_url, &auth.auth_token, &auth.account_id)
            .await
        {
            Ok(id) => Ok(Some(crate::guard::StoreIdentity::distinguishing(id))),
            Err(StoreError::NotFound(_)) => Ok(None),
            Err(other) => Err(other),
        }
    }

    async fn put(
        &self,
        key: &ObjectKey,
        data: Bytes,
        expected: &ContentHash,
        modified: SourceModified,
    ) -> Result<PutOutcome> {
        let moved = data.len() as u64;
        let outcome = upload::put(self, key, data, expected, modified).await?;
        crate::meter::charge(self.meter.as_ref(), moved).await;
        Ok(outcome)
    }

    async fn put_from_path(
        &self,
        key: &ObjectKey,
        source: &std::path::Path,
        expected: &ContentHash,
        modified: SourceModified,
    ) -> Result<PutOutcome> {
        upload::put_from_path(self, key, source, expected, modified).await
    }

    /// The same two arms as [`put_from_path`](Backend::put_from_path), fed by a
    /// producer instead of by a file — so a sealed object reaches the bucket
    /// without ever being written to local disk.
    ///
    /// The memory contract is unchanged and is still one part:
    /// [`upload_peak_bytes`](B2Backend::upload_peak_bytes) states it, and the
    /// pipe in front of it adds its own bounded term
    /// ([`incoming::constants`](crate::incoming::constants)). What went is the
    /// spool, and with it the page cache that used to be charged to the same
    /// cgroup as the program.
    async fn put_stream(
        &self,
        key: &ObjectKey,
        source: crate::incoming::ObjectStream,
        modified: SourceModified,
    ) -> Result<PutOutcome> {
        upload::put_stream(self, key, source, modified).await
    }

    async fn get(&self, key: &ObjectKey) -> Result<Bytes> {
        let bytes = download::get(self, key).await?;
        crate::meter::charge(self.meter.as_ref(), bytes.len() as u64).await;
        Ok(bytes)
    }

    async fn get_to_path(&self, key: &ObjectKey, dest: &std::path::Path) -> Result<()> {
        download::get_to_path(self, key, dest).await
    }

    async fn get_range(&self, key: &ObjectKey, range: ByteRange) -> Result<Bytes> {
        let bytes = download::get_range(self, key, range).await?;
        crate::meter::charge(self.meter.as_ref(), bytes.len() as u64).await;
        Ok(bytes)
    }

    async fn head(&self, key: &ObjectKey) -> Result<ObjectMeta> {
        listing::head(self, key).await
    }

    /// SHA-1: B2 computes one over every object it accepts and keeps it in the
    /// file's own metadata, where `b2_list_file_names` reports it back.
    ///
    /// The algorithm is B2's choice, not DCTL's — the upload path already sends
    /// `X-Bz-Content-Sha1` and B2 refuses a body that does not match it — so a
    /// re-read is folded through SHA-1 to be comparable with what B2 is holding.
    fn checksum_support(&self) -> crate::recorded::ChecksumSupport {
        crate::recorded::ChecksumSupport::Recorded(crate::checksum::HashAlgo::Sha1)
    }

    /// What B2 recorded for this object, or why it has nothing for this one.
    async fn stored_checksum(&self, key: &ObjectKey) -> Result<crate::recorded::StoredChecksum> {
        listing::stored_checksum(self, key).await
    }

    async fn exists(&self, key: &ObjectKey) -> Result<bool> {
        listing::exists(self, key).await
    }

    async fn delete(&self, key: &ObjectKey) -> Result<()> {
        listing::delete(self, key).await
    }

    /// Nothing is ever written under a temporary key here, so nothing can be
    /// abandoned under one.
    ///
    /// Measured rather than assumed: a `SIGKILL` three seconds into a copy to a
    /// live B2 bucket leaves the bucket holding `system/envelope.bin` and
    /// nothing else. The upload goes straight to the final key with a checksum
    /// the provider verifies, so there is no staging namespace to sweep.
    ///
    /// What an interrupted *large* upload leaves is an unfinished large file,
    /// which is billed and which no object listing shows — a different class,
    /// asked for separately, and now answered:
    /// [`list_incomplete_uploads`](Backend::list_incomplete_uploads).
    async fn list_staging(
        &self,
        _prefix: &str,
        _cursor: Option<String>,
    ) -> Result<crate::staging::StagingListing> {
        Ok(crate::staging::StagingListing::NotStaged(
            crate::staging::NOT_STAGED_REASON,
        ))
    }

    /// The large files this account started and never finished, through
    /// `b2_list_unfinished_large_files` — the only call in the API that can see
    /// them.
    async fn list_incomplete_uploads(
        &self,
        prefix: &str,
        cursor: Option<String>,
    ) -> Result<crate::multipart::IncompleteUploads> {
        upload::list_unfinished(self, prefix, cursor).await
    }

    /// `b2_cancel_large_file`, which releases every part the upload was holding.
    async fn abort_incomplete_upload(
        &self,
        upload: &crate::multipart::IncompleteUpload,
    ) -> Result<()> {
        upload::abort_unfinished(self, upload).await
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
