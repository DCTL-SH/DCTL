//! The provider-neutral storage `Backend` trait.

use async_trait::async_trait;
use bytes::Bytes;

use crate::checksum::ContentHash;
use crate::error::{Result, StoreError};
use crate::guard::StoreIdentity;
use crate::model::{ByteRange, ObjectKey, ObjectMeta, Page, PutOutcome};
use crate::modified::SourceModified;
use crate::staging::StagingListing;

/// A delegated (presigned) authorization to upload exactly ONE object key.
///
/// The bytes uploaded are an already-sealed DSF1 object; this delegates only
/// **transport** — the issuer hands a client (e.g. an iOS `URLSession` background
/// upload) the exact request it must replay, and never sees plaintext / DEK / KW.
///
/// Not `Debug`: `url` (S3/R2) embeds a SigV4 signature and `headers` (B2) carry a
/// short-lived upload-auth token — short-lived transport credentials that must not be
/// logged, mirroring [`S3Config`](crate::s3::S3Config) / `B2Credentials`.
pub struct UploadTicket {
    /// HTTP method the client must use: `"PUT"` for S3/R2, `"POST"` for B2.
    pub method: String,
    /// The presigned URL (S3/R2) or the B2 `uploadUrl`.
    pub url: String,
    /// Headers the client MUST send verbatim (order preserved).
    pub headers: Vec<(String, String)>,
    /// SigV4 absolute expiry as a unix timestamp (S3/R2); `None` when the ticket is
    /// scoped by an opaque token's own lifetime instead (B2).
    pub expires_unix: Option<u64>,
}

/// A storage backend: moves opaque objects to/from a provider.
///
/// Three invariants every implementation must uphold:
/// - **Verified write:** [`put`](Backend::put) must not report success unless the
///   stored bytes match `expected`. On mismatch it must leave nothing committed.
/// - **Range read:** [`get_range`](Backend::get_range) must return exactly the
///   requested bytes without transferring the whole object (streaming-seek).
/// - **The writer's time comes back:** a `put` carrying a known
///   [`SourceModified`] must be readable back through [`head`](Backend::head) and
///   [`list_page`](Backend::list_page) as that same whole second — or the
///   implementation must document, in its own module, exactly why its protocol
///   cannot. This is the property `sync` is incremental *because of*, and the one
///   whose absence made every run a full run.
#[async_trait]
pub trait Backend: Send + Sync {
    /// Short, stable backend identifier (e.g. `"local"`, `"b2"`).
    ///
    /// Also what selects this backend's retry schedule
    /// ([`RetryPolicy::for_backend`](crate::retry::RetryPolicy::for_backend)),
    /// so it is a decision and not a label.
    fn name(&self) -> &'static str;

    /// What the provider says this backend's container is, **right now**.
    ///
    /// [`None`] means there is nothing there — a bucket that has not been
    /// created, a directory a first write will make. That is not an error: a
    /// configuration may legitimately name a place that does not exist yet.
    ///
    /// Deliberately **not** a provided method. A default returning `None` would
    /// give any backend added later a silently unguarded write path, which is
    /// exactly the shape of defect `remote::registry::Built` documents about the
    /// meter: five arms, four of which forgot. Requiring an answer means a new
    /// provider cannot compile without deciding what it can tell about its own
    /// container, and [`StoreIdentity::existence_only`] is how it says
    /// "nothing, beyond that it is there".
    ///
    /// # Errors
    /// Whatever the probe reported. A store that cannot be identified is one
    /// [`Guarded`](crate::guard::Guarded) will not write into: recording
    /// "unknown" and carrying on is the silent partial answer the guard exists
    /// to remove.
    async fn store_identity(&self) -> Result<Option<StoreIdentity>>;

    /// Atomically store `data` under `key`, verifying it matches `expected`, and
    /// record `modified` as the object's last-modified time.
    ///
    /// `modified` describes the **content**, not this call — see
    /// [`SourceModified`]. [`SourceModified::unknown`] leaves the provider's own
    /// timestamp standing, which is what DCTL's internal bookkeeping objects want
    /// and what a copy from a source that reports no time has always defaulted to.
    async fn put(
        &self,
        key: &ObjectKey,
        data: Bytes,
        expected: &ContentHash,
        modified: SourceModified,
    ) -> Result<PutOutcome>;

    /// Store the file at `source` under `key`, verifying it matches `expected`.
    ///
    /// This is the streaming counterpart of [`put`](Backend::put): it exists so a huge
    /// file can be stored without ever holding its whole body in memory. The **provided
    /// default** simply reads `source` into memory and delegates to [`put`], preserving
    /// the verified-write contract for every backend unchanged — backends that can stream
    /// straight from a path (e.g. [`LocalFs`](crate::local::LocalFs)) override this to run
    /// at `O(buffer)` memory. (True multipart-from-file for B2/S3/R2 is a follow-up.)
    async fn put_from_path(
        &self,
        key: &ObjectKey,
        source: &std::path::Path,
        expected: &ContentHash,
        modified: SourceModified,
    ) -> Result<PutOutcome> {
        let data = tokio::fs::read(source).await?;
        self.put(key, Bytes::from(data), expected, modified).await
    }

    /// Fetch the entire object.
    async fn get(&self, key: &ObjectKey) -> Result<Bytes>;

    /// Download the object at `key` to the local file `dest`, streaming.
    ///
    /// This is the streaming counterpart of [`get`](Backend::get): it exists so a huge
    /// object can be read to disk without ever holding its whole body in memory. The
    /// **provided default** simply calls [`get`] and writes the returned bytes to `dest`,
    /// so every backend has a correct implementation unchanged — backends that can stream
    /// straight to a path (e.g. [`LocalFs`](crate::local::LocalFs)) override this to run at
    /// `O(buffer)` memory. (True streaming download for B2/S3/R2 is a follow-up; they keep
    /// the buffered default for now.)
    async fn get_to_path(&self, key: &ObjectKey, dest: &std::path::Path) -> Result<()> {
        let bytes = self.get(key).await?;
        if let Some(parent) = dest.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(dest, &bytes).await?;
        Ok(())
    }

    /// Fetch a byte range (streaming-seek primitive). Length past EOF is clamped.
    async fn get_range(&self, key: &ObjectKey, range: ByteRange) -> Result<Bytes>;

    /// Object metadata without transferring the body.
    async fn head(&self, key: &ObjectKey) -> Result<ObjectMeta>;

    /// Whether the object exists.
    async fn exists(&self, key: &ObjectKey) -> Result<bool>;

    /// Delete the object. Idempotent: deleting a missing object succeeds.
    async fn delete(&self, key: &ObjectKey) -> Result<()>;

    /// One page of a prefix listing. Pass the previous page's `next_cursor` to
    /// continue; `None` starts from the beginning. Keeps memory constant.
    ///
    /// **Never includes staging files.** A write that has not reached its commit
    /// is not an object, and offering one here is how a `copy` restores a
    /// truncated file. What was abandoned is a separate question, asked of
    /// [`list_staging`](Backend::list_staging).
    async fn list_page(&self, prefix: &str, cursor: Option<String>) -> Result<Page>;

    /// One page of the **staging debris** under `prefix` — the objects a write
    /// abandoned before its commit — or the reason this backend has none.
    ///
    /// The second question, asked separately, and the whole of the fix for a
    /// `cleanup` that reported `OK removed: 0 object(s), 0 B` over a store
    /// holding a 528 KiB staging file that a `SIGKILL` had left there. Discovery
    /// used to go through [`list_page`](Backend::list_page), which
    /// *deliberately* omits exactly those keys, so the sweep could not see what
    /// it existed to remove and said so in its own source while the verdict said
    /// the opposite.
    ///
    /// Deliberately **not** a provided method, for the reason
    /// [`store_identity`](Backend::store_identity) is not: a default returning an
    /// empty page would hand every backend added later a silent false all-clear,
    /// which is the precise defect this method closes. A new provider must
    /// decide, and [`StagingListing::NotStaged`] is how it says "nothing is ever
    /// written under a temporary key here, and here is why".
    ///
    /// Implementations must return **only** keys that satisfy
    /// [`is_staging_key`](crate::staging::is_staging_key). The sweep checks it
    /// again before deleting anything — not as a second opinion, since it is the
    /// same function, but because this is the one call in the binary whose
    /// answer is turned straight into `delete`.
    ///
    /// # Errors
    /// Whatever enumerating reported. A failure is an error and never an empty
    /// page: "I could not look" and "there is nothing there" are the two answers
    /// this whole method exists to keep apart.
    async fn list_staging(&self, prefix: &str, cursor: Option<String>) -> Result<StagingListing>;

    /// Issue a delegated authorization for a client to upload the single object `key`
    /// **directly** to the backend (see [`UploadTicket`]).
    ///
    /// `content_len` is the exact byte length the client will send. `content_sha256`,
    /// when supplied, is the SHA-256 of those (already-sealed) bytes; backends that can
    /// bind it into the authorization do so (S3/R2 sign it), tightening the delegation to
    /// exactly those bytes. The bytes are opaque ciphertext — issuing a ticket never
    /// exposes plaintext or key material.
    ///
    /// The **provided default** returns a clear error: most backends (e.g.
    /// [`LocalFs`](crate::local::LocalFs)) have no notion of delegated upload. Backends
    /// that support it (S3, R2, B2) override this.
    async fn prepare_upload(
        &self,
        key: &ObjectKey,
        content_len: u64,
        content_sha256: Option<&[u8; 32]>,
    ) -> Result<UploadTicket> {
        let _ = (key, content_len, content_sha256);
        Err(StoreError::Backend(format!(
            "delegated upload unsupported by this backend: {}",
            self.name()
        )))
    }
}
