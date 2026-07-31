//! The provider-neutral storage `Backend` trait.

use async_trait::async_trait;
use bytes::Bytes;

use crate::checksum::ContentHash;
use crate::error::{Result, StoreError};
use crate::guard::StoreIdentity;
use crate::incoming::ObjectStream;
use crate::model::{ByteRange, ObjectKey, ObjectMeta, Page, PutOutcome};
use crate::modified::SourceModified;
use crate::multipart::{IncompleteUpload, IncompleteUploads};
use crate::recorded::{ChecksumSupport, StoredChecksum};
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

    /// Store an object that **does not exist yet**, taking its bytes in bounded
    /// windows as something else produces them.
    ///
    /// The third source shape, beside [`put`](Backend::put)'s buffer and
    /// [`put_from_path`](Backend::put_from_path)'s file, and the only one that
    /// fits a vault: a sealed object is made by encrypting the user's file, and
    /// before this method existed the only way to hand one to a backend was to
    /// produce it onto local disk first. That spool cost one object of scratch
    /// storage per upload — and, because a spool's page cache is charged to the
    /// same cgroup as the program, it is why `docker run -m 512m` was not a safe
    /// way to run a 4 GiB upload however flat the resident memory looked.
    ///
    /// # The memory contract
    ///
    /// ```text
    /// peak = window × windows-in-flight  +  part size × parts-in-flight
    /// ```
    ///
    /// Every term is a named constant — [`incoming::constants`](crate::incoming::constants)
    /// for the first pair, the provider's own `constants` module for the second —
    /// and **no term is a function of the object's size**. There is no page-cache
    /// term because there is no spool.
    ///
    /// # The verified-write contract, with the promise at the other end
    ///
    /// Nobody knows a sealed object's digest before it has been sealed, so this
    /// method cannot be handed an `expected` the way the other two are. The
    /// promise arrives with the stream's last message instead, and
    /// [`ObjectStream::agreed`] is where it is checked: it refuses an object that
    /// did not turn out to be the length its producer declared, refuses one whose
    /// bytes do not fold to the digest the producer folded, and refuses to answer
    /// at all until the stream has been read to its end. **An implementation must
    /// not commit anything until `agreed` has returned**, and it has no digest to
    /// report in its [`PutOutcome`] until it does — which is the forcing function
    /// rather than a rule to remember.
    ///
    /// # This stream is consumed once
    ///
    /// There is no rewind. [`Retrying`](crate::Retrying) therefore forwards this
    /// call without retrying it, and says so at its own call site; retry for a
    /// streamed write is per *request*, one layer down, where a part is re-sent
    /// from the buffer already in hand.
    ///
    /// Deliberately **not** a provided method, for the reason
    /// [`store_identity`](Backend::store_identity) has none: a default that
    /// buffered the whole stream would compile everywhere, pass every correctness
    /// test, and silently reintroduce the `O(object)` cost this exists to remove —
    /// on whichever backend somebody forgot.
    ///
    /// # Errors
    /// Whatever the write reported, plus the three refusals
    /// [`ObjectStream::agreed`] can make. Nothing is left committed on any of them.
    async fn put_stream(
        &self,
        key: &ObjectKey,
        source: ObjectStream,
        modified: SourceModified,
    ) -> Result<PutOutcome>;

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

    /// What digest, if any, this backend recorded for every object it stores.
    ///
    /// Synchronous and infallible, because it is a property of the **provider**
    /// rather than of any object: a report has to be able to say what a run can
    /// prove before the run spends an hour proving it, and a question that cost
    /// a round trip would be asked after the first line was already printed.
    /// The per-object answer is [`stored_checksum`](Backend::stored_checksum).
    ///
    /// Deliberately **not** a provided method, for the reason
    /// [`store_identity`](Backend::store_identity) has none, and this time with
    /// the defect already measured. A default of "none" would give every
    /// backend added later a `verify` that cannot detect rot and does not say
    /// so; a default of "recorded" would make it claim a comparison it never
    /// makes. Both are silent, and one of them loses data. See
    /// [`crate::recorded`] for what was measured on the shipped binary.
    fn checksum_support(&self) -> ChecksumSupport;

    /// The digest the provider recorded for **this** object when it was
    /// written.
    ///
    /// The value `dctl verify` compares a full re-read against on a plain
    /// remote, and the only thing on that side capable of noticing a flipped
    /// byte: the bytes and the recorded digest live in different places, so rot
    /// moves one and not the other.
    ///
    /// Callers are expected to have established that the object exists — with
    /// [`head`](Backend::head), which a read-back needs for the size anyway.
    /// [`StoredChecksum::Absent`] therefore means *the object is there and
    /// there is no digest for it*, never *there is no object*.
    ///
    /// A backend whose [`checksum_support`](Backend::checksum_support) is
    /// [`ChecksumSupport::None`] answers [`StoredChecksum::Absent`] here for
    /// every key, and must not make a request to do it.
    ///
    /// # Errors
    /// Whatever asking the provider reported, and
    /// [`StoreError::NotFound`](crate::error::StoreError::NotFound) where the
    /// provider answers the question and the object turns out not to be there.
    async fn stored_checksum(&self, key: &ObjectKey) -> Result<StoredChecksum>;

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

    /// One page of the **multipart uploads** this backend started under `prefix`
    /// and never finished — or the reason this backend cannot have any.
    ///
    /// The third question, after "what is stored?" and "what did we abandon under
    /// a temporary key?". Its subject is the one class of debris that is billed
    /// from the moment it exists and that **no object listing can show**: a part
    /// accepted by a provider belongs to no object until the finish call arrives,
    /// so `b2_list_file_names` and `ListObjectsV2` both step straight over it.
    /// See [`multipart`](crate::multipart) for what that costs and why it needs
    /// its own call.
    ///
    /// Deliberately **not** a provided method, for the reason
    /// [`list_staging`](Backend::list_staging) is not: a default answering "none"
    /// is a false all-clear about storage somebody is paying for, and
    /// [`IncompleteUploads::NotMultipart`] is how a backend with no multipart
    /// protocol says so honestly.
    ///
    /// # Errors
    /// Whatever enumerating reported. A failure is an error and never an empty
    /// page — "I could not look" and "there is nothing there" are the two answers
    /// this method exists to keep apart.
    async fn list_incomplete_uploads(
        &self,
        prefix: &str,
        cursor: Option<String>,
    ) -> Result<IncompleteUploads>;

    /// Cancel one unfinished upload, releasing the parts it is holding.
    ///
    /// Idempotent in the way that matters: an upload that is already gone — swept
    /// by another run, or finished by the process that owned it between the
    /// listing and this call — succeeds rather than failing the sweep, because
    /// the state the caller wanted is the state that obtains.
    ///
    /// `upload` must be one this backend returned from
    /// [`list_incomplete_uploads`](Backend::list_incomplete_uploads): the handle
    /// inside it is the provider's own and cannot be constructed from a key.
    ///
    /// Deliberately **not** a provided method, for the same reason as its
    /// listing: a default that quietly did nothing would let a sweep report
    /// reclaimed storage it had not reclaimed.
    ///
    /// # Errors
    /// Whatever the provider said, except a "no such upload" which is success.
    async fn abort_incomplete_upload(&self, upload: &IncompleteUpload) -> Result<()>;

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
