//! The decorator: any [`Backend`], with the retry layer in front of it.
//!
//! # Why a wrapper and not a default method on the trait
//!
//! A provided method cannot wrap the *other* methods of the same trait — a
//! default `get` that retried would be overridden by every implementation that
//! has a real `get`, which is all of them. So "lift retry to the `Backend`
//! trait" means exactly this: one type that **is** a `Backend`, holds a
//! `Backend`, and retries every call it forwards. One implementation, installed
//! once at construction, rather than five copies inside five providers that
//! drift apart one commit at a time.
//!
//! # Every operation here is safe to attempt again
//!
//! Stated per method rather than assumed, because "retry the write" is exactly
//! the kind of thing that duplicates data in a tool that gets it wrong.
//!
//! * [`Backend::put`] / [`Backend::put_from_path`] — a write is addressed by
//!   **key** and is verified: the contract on the trait is that it does not
//!   report success unless the stored bytes match, and leaves nothing committed
//!   when they do not. Repeating one overwrites the same key with the same
//!   bytes. It cannot append, and it cannot produce a second object.
//! * [`Backend::delete`] — documented as idempotent on the trait; deleting a
//!   missing object succeeds.
//! * [`Backend::get`], `get_range`, `get_to_path`, `head`, `exists`,
//!   `list_page` — reads, and `get_to_path` stages and renames rather than
//!   writing `dest` in place, so a repeat cannot leave a half-file behind.
//! * [`Backend::prepare_upload`] — issues an authorization and stores nothing.
//!
//! What is **not** here is a retry of a partial transfer's remainder. Each
//! attempt starts the operation over. For an object large enough that this
//! matters the provider-side chunking already retries per part, one layer down
//! (`b2::retry`), which is why that module stays.
//!
//! # The metered bytes are the bytes that crossed the link
//!
//! A retried `put` charges [`Meter`](crate::Meter) on every attempt, because
//! every attempt really did use the link. `--bwlimit` therefore paces a run that
//! is retrying at the rate it was asked to, rather than sprinting through the
//! repeats — which is the behaviour a limiter exists for and the opposite of
//! what "charge once per object" would give.

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;

use crate::backend::{Backend, UploadTicket};
use crate::checksum::ContentHash;
use crate::deadline::RunDeadline;
use crate::error::Result;
use crate::model::{ByteRange, ObjectKey, ObjectMeta, Page, PutOutcome};
use crate::modified::SourceModified;

use super::driver::run;
use super::policy::RetryPolicy;

/// A [`Backend`] that tries again when the reason a call failed will not last,
/// and stops when the run's own window closes.
pub struct Retrying {
    inner: Arc<dyn Backend>,
    policy: RetryPolicy,
    /// When the run has to be over — `--max-duration`.
    ///
    /// A required argument at both constructors rather than a builder with a
    /// default, and that is deliberate. This decorator is the layer that
    /// multiplies `--timeout` into the 943.6 s §32.9 measured, so a construction
    /// site that *could* forget to say what bounds the run is a site that will:
    /// eleven flags reached `dctl --help` and did nothing by exactly that
    /// route. [`RunDeadline::unbounded`] is how a caller says "nothing bounds
    /// this", out loud, at the call site.
    deadline: RunDeadline,
}

impl Retrying {
    /// Wrap `inner` with the schedule its own [`Backend::name`] selects, inside
    /// a run that has to be over at `deadline`.
    ///
    /// The name rather than a parameter for the schedule, so a caller cannot
    /// hand `local:` the network schedule by mistake and nobody has to remember
    /// which is which at five construction sites. [`RetryPolicy::for_backend`]
    /// is where the mapping lives and is exhaustive over the providers this
    /// build ships. The deadline *is* a parameter, for the opposite reason:
    /// there is no name to derive it from and no safe default to inherit.
    #[must_use]
    pub fn wrap(inner: Arc<dyn Backend>, deadline: RunDeadline) -> Arc<dyn Backend> {
        let policy = RetryPolicy::for_backend(inner.name());
        Arc::new(Self {
            inner,
            policy,
            deadline,
        })
    }

    /// The same wrapper with an explicit schedule.
    ///
    /// For the tests that need a schedule which does not sleep, and for a caller
    /// that has a reason to be less patient than the provider's default. Not the
    /// ordinary path: [`Retrying::wrap`] is.
    #[must_use]
    pub fn with_policy(
        inner: Arc<dyn Backend>,
        policy: RetryPolicy,
        deadline: RunDeadline,
    ) -> Arc<dyn Backend> {
        Arc::new(Self {
            inner,
            policy,
            deadline,
        })
    }
}

#[async_trait]
impl Backend for Retrying {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    async fn put(
        &self,
        key: &ObjectKey,
        data: Bytes,
        expected: &ContentHash,
        modified: SourceModified,
    ) -> Result<PutOutcome> {
        run("put", self.policy, self.deadline, |_| {
            // `Bytes` is a refcounted handle: cloning it per attempt copies a
            // pointer and a counter, not the object.
            let data = data.clone();
            async move { self.inner.put(key, data, expected, modified).await }
        })
        .await
    }

    async fn put_from_path(
        &self,
        key: &ObjectKey,
        source: &Path,
        expected: &ContentHash,
        modified: SourceModified,
    ) -> Result<PutOutcome> {
        run(
            "put_from_path",
            self.policy,
            self.deadline,
            |_| async move {
                self.inner
                    .put_from_path(key, source, expected, modified)
                    .await
            },
        )
        .await
    }

    /// Forwarded **without** a retry, and that is a property of the argument
    /// rather than an omission.
    ///
    /// Every other operation here is safe to attempt again because its input is
    /// still in hand — a `Bytes` clones, a path re-opens, a listing re-runs. An
    /// [`ObjectStream`](crate::ObjectStream) is none of those: it is a live pipe
    /// from a producer that has already encrypted and discarded the windows the
    /// first attempt consumed, so a second attempt would upload the *tail* of the
    /// object and the verified-write check would refuse it — after the whole thing
    /// had crossed the link. Retrying an unrewindable stream is not resilience,
    /// it is a second failure at twice the cost.
    ///
    /// What does retry is the layer underneath, where it can: a B2 or S3 part is
    /// re-sent from the buffer already in hand (`b2::retry`), which is the part of
    /// the transfer a transient failure actually lands on. A whole-object retry is
    /// the caller's, from the source file that is still on disk — and the caller
    /// that seals is the one place that can rewind, because it owns the plaintext.
    async fn put_stream(
        &self,
        key: &ObjectKey,
        source: crate::incoming::ObjectStream,
        modified: SourceModified,
    ) -> Result<PutOutcome> {
        self.inner.put_stream(key, source, modified).await
    }

    async fn get(&self, key: &ObjectKey) -> Result<Bytes> {
        run("get", self.policy, self.deadline, |_| async move {
            self.inner.get(key).await
        })
        .await
    }

    async fn get_to_path(&self, key: &ObjectKey, dest: &Path) -> Result<()> {
        run("get_to_path", self.policy, self.deadline, |_| async move {
            self.inner.get_to_path(key, dest).await
        })
        .await
    }

    async fn get_range(&self, key: &ObjectKey, range: ByteRange) -> Result<Bytes> {
        run("get_range", self.policy, self.deadline, |_| async move {
            self.inner.get_range(key, range).await
        })
        .await
    }

    async fn head(&self, key: &ObjectKey) -> Result<ObjectMeta> {
        run("head", self.policy, self.deadline, |_| async move {
            self.inner.head(key).await
        })
        .await
    }

    /// Forwarded unchanged: a capability is not something a retry can alter.
    fn checksum_support(&self) -> crate::recorded::ChecksumSupport {
        self.inner.checksum_support()
    }

    async fn stored_checksum(&self, key: &ObjectKey) -> Result<crate::recorded::StoredChecksum> {
        run(
            "stored_checksum",
            self.policy,
            self.deadline,
            |_| async move { self.inner.stored_checksum(key).await },
        )
        .await
    }

    async fn exists(&self, key: &ObjectKey) -> Result<bool> {
        run("exists", self.policy, self.deadline, |_| async move {
            self.inner.exists(key).await
        })
        .await
    }

    async fn delete(&self, key: &ObjectKey) -> Result<()> {
        run("delete", self.policy, self.deadline, |_| async move {
            self.inner.delete(key).await
        })
        .await
    }

    async fn list_page(&self, prefix: &str, cursor: Option<String>) -> Result<Page> {
        run("list_page", self.policy, self.deadline, |_| {
            let cursor = cursor.clone();
            async move { self.inner.list_page(prefix, cursor).await }
        })
        .await
    }

    /// Retried like every other read. Enumeration stores nothing, so repeating
    /// it can produce a stale answer at worst — and a sweep that gave up on the
    /// first dropped packet would leave the debris it was run to reclaim.
    async fn list_staging(
        &self,
        prefix: &str,
        cursor: Option<String>,
    ) -> Result<crate::staging::StagingListing> {
        run("list_staging", self.policy, self.deadline, |_| {
            let cursor = cursor.clone();
            async move { self.inner.list_staging(prefix, cursor).await }
        })
        .await
    }

    /// Retried like every other read: enumeration stores nothing, and a sweep
    /// that gave up on the first dropped packet would leave billed parts behind.
    async fn list_incomplete_uploads(
        &self,
        prefix: &str,
        cursor: Option<String>,
    ) -> Result<crate::multipart::IncompleteUploads> {
        run(
            "list_incomplete_uploads",
            self.policy,
            self.deadline,
            |_| {
                let cursor = cursor.clone();
                async move { self.inner.list_incomplete_uploads(prefix, cursor).await }
            },
        )
        .await
    }

    /// Retried, because it is idempotent by construction: an upload cancelled
    /// twice is cancelled, and both providers' "no such upload" is read as success
    /// at the backend. It is the same argument [`Backend::delete`] rests on.
    async fn abort_incomplete_upload(
        &self,
        upload: &crate::multipart::IncompleteUpload,
    ) -> Result<()> {
        run(
            "abort_incomplete_upload",
            self.policy,
            self.deadline,
            |_| async move { self.inner.abort_incomplete_upload(upload).await },
        )
        .await
    }

    async fn prepare_upload(
        &self,
        key: &ObjectKey,
        content_len: u64,
        content_sha256: Option<&[u8; 32]>,
    ) -> Result<UploadTicket> {
        run(
            "prepare_upload",
            self.policy,
            self.deadline,
            |_| async move {
                self.inner
                    .prepare_upload(key, content_len, content_sha256)
                    .await
            },
        )
        .await
    }

    /// Retried like everything else, and that is the point of the layering.
    ///
    /// `guard::Guarded` sits *above* this wrapper, so the probe it makes travels
    /// through here: a `HEAD` on a bucket that answers `503` is tried again
    /// rather than read as "the bucket is gone", which would refuse every write
    /// for the rest of the run over one moment of throttling.
    async fn store_identity(&self) -> Result<Option<crate::guard::StoreIdentity>> {
        run(
            "store_identity",
            self.policy,
            self.deadline,
            |_| async move { self.inner.store_identity().await },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::StoreError;
    use crate::testing::CountingBackend;
    use std::time::Duration;

    /// A schedule that retries as usual and waits for nothing, so the suite
    /// spends no wall-clock time on delays `super::super::classify` already
    /// asserts exactly.
    fn instant() -> RetryPolicy {
        RetryPolicy {
            first_backoff: Duration::ZERO,
            max_backoff: Duration::ZERO,
            ..RetryPolicy::network()
        }
    }

    fn busy() -> StoreError {
        StoreError::Provider {
            backend: "test",
            status: 503,
            code: "SlowDown".to_string(),
            retry_after_secs: None,
        }
    }

    fn key() -> ObjectKey {
        ObjectKey::new("a/b.bin")
    }

    #[tokio::test]
    async fn every_operation_is_retried_and_not_merely_the_convenient_ones() {
        // The assertion that would have caught a wrapper implementing three
        // methods and forwarding the rest: each operation is failed twice and
        // must still succeed, which only happens if that particular method went
        // through the driver. A wrapper is exactly the shape of code where one
        // forgotten method is invisible.
        let key = key();
        let data = Bytes::from_static(b"payload");
        let hash = crate::testing::payload_hash();
        let range = ByteRange::new(0, Some(1));

        // Written as a method call rather than a closure on purpose: a closure
        // returning a boxed future that borrows its own argument cannot have its
        // lifetimes inferred, and working around that would put more machinery
        // in the test than in the thing under test.
        macro_rules! retried {
            ($name:expr, $($call:tt)+) => {{
                let inner = Arc::new(CountingBackend::failing($name, 2, busy()));
                let counter = Arc::clone(&inner);
                let backend = Retrying::with_policy(inner, instant(), RunDeadline::unbounded());
                let outcome = backend.$($call)+.await;
                assert!(outcome.is_ok(), "{}: {:?}", $name, outcome.err());
                assert_eq!(
                    counter.calls($name),
                    3,
                    "{} was not retried by the wrapper",
                    $name
                );
            }};
        }

        retried!(
            "put",
            put(&key, data.clone(), &hash, SourceModified::unknown())
        );
        retried!("get", get(&key));
        retried!("get_range", get_range(&key, range));
        retried!("head", head(&key));
        retried!("exists", exists(&key));
        retried!("delete", delete(&key));
        retried!("list_page", list_page("", None));
        retried!("list_staging", list_staging("", None));
    }

    #[tokio::test]
    async fn a_permanent_failure_is_forwarded_once_and_unchanged() {
        let inner = Arc::new(CountingBackend::failing(
            "get",
            u32::MAX,
            StoreError::NotFound("a/b.bin".into()),
        ));
        let counter = Arc::clone(&inner);
        let backend = Retrying::with_policy(inner, instant(), RunDeadline::unbounded());

        let error = backend
            .get(&ObjectKey::new("a/b.bin"))
            .await
            .expect_err("still missing");
        assert_eq!(counter.calls("get"), 1);
        assert!(matches!(error, StoreError::NotFound(_)));
        assert_eq!(error.attempts(), None);
    }

    #[tokio::test]
    async fn the_wrapper_reports_the_provider_name_it_wraps() {
        // `Backend::name` decides the schedule, the log fields and — through
        // `RetryPolicy::for_backend` — the patience. A wrapper that answered
        // "retrying" would silently give every provider the fallback policy.
        let inner = Arc::new(CountingBackend::failing("get", 0, busy()));
        let backend = Retrying::wrap(inner, RunDeadline::unbounded());
        assert_eq!(backend.name(), "test");
    }

    #[tokio::test]
    async fn an_exhausted_operation_reports_the_attempts_it_made() {
        let inner = Arc::new(CountingBackend::failing("get", u32::MAX, busy()));
        let counter = Arc::clone(&inner);
        let policy = instant();
        let backend = Retrying::with_policy(inner, policy, RunDeadline::unbounded());

        let error = backend
            .get(&ObjectKey::new("a/b.bin"))
            .await
            .expect_err("permanently busy");
        assert_eq!(counter.calls("get"), policy.max_attempts as usize);
        assert_eq!(error.attempts(), Some(policy.max_attempts));
    }

    #[tokio::test]
    async fn the_wrappers_schedule_stops_at_the_runs_deadline() {
        // The decorator is where §32.9's multiplication happens, so it is where
        // the run's deadline has to arrive. Same failing backend, same schedule;
        // the only difference is that this run had a window and it has closed.
        let inner = Arc::new(CountingBackend::failing("get", u32::MAX, busy()));
        let counter = Arc::clone(&inner);
        let policy = instant();
        let backend = Retrying::with_policy(
            inner,
            policy,
            RunDeadline::starting_at(
                std::time::Instant::now() - std::time::Duration::from_secs(60),
                Some(std::time::Duration::from_secs(30)),
            ),
        );

        let error = backend
            .get(&ObjectKey::new("a/b.bin"))
            .await
            .expect_err("the window is gone");
        assert_eq!(
            counter.calls("get"),
            0,
            "a backend must not be called at all once the run's window has closed"
        );
        assert!(matches!(error, StoreError::RunDeadline { .. }), "{error}");
    }

    #[tokio::test]
    async fn a_run_still_inside_its_window_retries_exactly_as_before() {
        // The direction this feature could have broken. A deadline the run is
        // comfortably inside must change nothing.
        let inner = Arc::new(CountingBackend::failing("get", 2, busy()));
        let counter = Arc::clone(&inner);
        let backend = Retrying::with_policy(
            inner,
            instant(),
            RunDeadline::starting_now(Some(std::time::Duration::from_secs(600))),
        );
        backend
            .get(&ObjectKey::new("a/b.bin"))
            .await
            .expect("the third attempt succeeds");
        assert_eq!(counter.calls("get"), 3);
    }
}
