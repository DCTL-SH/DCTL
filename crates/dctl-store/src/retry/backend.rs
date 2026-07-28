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
use crate::error::Result;
use crate::model::{ByteRange, ObjectKey, ObjectMeta, Page, PutOutcome};
use crate::modified::SourceModified;

use super::driver::run;
use super::policy::RetryPolicy;

/// A [`Backend`] that tries again when the reason a call failed will not last.
pub struct Retrying {
    inner: Arc<dyn Backend>,
    policy: RetryPolicy,
}

impl Retrying {
    /// Wrap `inner` with the schedule its own [`Backend::name`] selects.
    ///
    /// The name rather than a parameter, so a caller cannot hand `local:` the
    /// network schedule by mistake and nobody has to remember which is which at
    /// five construction sites. [`RetryPolicy::for_backend`] is where the
    /// mapping lives and is exhaustive over the providers this build ships.
    #[must_use]
    pub fn wrap(inner: Arc<dyn Backend>) -> Arc<dyn Backend> {
        let policy = RetryPolicy::for_backend(inner.name());
        Arc::new(Self { inner, policy })
    }

    /// The same wrapper with an explicit schedule.
    ///
    /// For the tests that need a schedule which does not sleep, and for a caller
    /// that has a reason to be less patient than the provider's default. Not the
    /// ordinary path: [`Retrying::wrap`] is.
    #[must_use]
    pub fn with_policy(inner: Arc<dyn Backend>, policy: RetryPolicy) -> Arc<dyn Backend> {
        Arc::new(Self { inner, policy })
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
        run("put", self.policy, |_| {
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
        run("put_from_path", self.policy, |_| async move {
            self.inner
                .put_from_path(key, source, expected, modified)
                .await
        })
        .await
    }

    async fn get(&self, key: &ObjectKey) -> Result<Bytes> {
        run(
            "get",
            self.policy,
            |_| async move { self.inner.get(key).await },
        )
        .await
    }

    async fn get_to_path(&self, key: &ObjectKey, dest: &Path) -> Result<()> {
        run("get_to_path", self.policy, |_| async move {
            self.inner.get_to_path(key, dest).await
        })
        .await
    }

    async fn get_range(&self, key: &ObjectKey, range: ByteRange) -> Result<Bytes> {
        run("get_range", self.policy, |_| async move {
            self.inner.get_range(key, range).await
        })
        .await
    }

    async fn head(&self, key: &ObjectKey) -> Result<ObjectMeta> {
        run("head", self.policy, |_| async move {
            self.inner.head(key).await
        })
        .await
    }

    async fn exists(&self, key: &ObjectKey) -> Result<bool> {
        run("exists", self.policy, |_| async move {
            self.inner.exists(key).await
        })
        .await
    }

    async fn delete(&self, key: &ObjectKey) -> Result<()> {
        run("delete", self.policy, |_| async move {
            self.inner.delete(key).await
        })
        .await
    }

    async fn list_page(&self, prefix: &str, cursor: Option<String>) -> Result<Page> {
        run("list_page", self.policy, |_| {
            let cursor = cursor.clone();
            async move { self.inner.list_page(prefix, cursor).await }
        })
        .await
    }

    async fn prepare_upload(
        &self,
        key: &ObjectKey,
        content_len: u64,
        content_sha256: Option<&[u8; 32]>,
    ) -> Result<UploadTicket> {
        run("prepare_upload", self.policy, |_| async move {
            self.inner
                .prepare_upload(key, content_len, content_sha256)
                .await
        })
        .await
    }

    /// Retried like everything else, and that is the point of the layering.
    ///
    /// `guard::Guarded` sits *above* this wrapper, so the probe it makes travels
    /// through here: a `HEAD` on a bucket that answers `503` is tried again
    /// rather than read as "the bucket is gone", which would refuse every write
    /// for the rest of the run over one moment of throttling.
    async fn store_identity(&self) -> Result<Option<crate::guard::StoreIdentity>> {
        run("store_identity", self.policy, |_| async move {
            self.inner.store_identity().await
        })
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
                let backend = Retrying::with_policy(inner, instant());
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
    }

    #[tokio::test]
    async fn a_permanent_failure_is_forwarded_once_and_unchanged() {
        let inner = Arc::new(CountingBackend::failing(
            "get",
            u32::MAX,
            StoreError::NotFound("a/b.bin".into()),
        ));
        let counter = Arc::clone(&inner);
        let backend = Retrying::with_policy(inner, instant());

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
        let backend = Retrying::wrap(inner);
        assert_eq!(backend.name(), "test");
    }

    #[tokio::test]
    async fn an_exhausted_operation_reports_the_attempts_it_made() {
        let inner = Arc::new(CountingBackend::failing("get", u32::MAX, busy()));
        let counter = Arc::clone(&inner);
        let policy = instant();
        let backend = Retrying::with_policy(inner, policy);

        let error = backend
            .get(&ObjectKey::new("a/b.bin"))
            .await
            .expect_err("permanently busy");
        assert_eq!(counter.calls("get"), policy.max_attempts as usize);
        assert_eq!(error.attempts(), Some(policy.max_attempts));
    }
}
