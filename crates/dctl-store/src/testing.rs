//! A [`Backend`] that fails on cue and counts what was asked of it.
//!
//! Compiled only under `cfg(test)`. It exists because the properties
//! [`crate::retry`] and [`crate::guard`] are about cannot be observed against a
//! real provider inside the plain `cargo test --workspace` gate: "this operation
//! was attempted three times" needs a backend that fails exactly twice, and "a
//! store that changed identity refuses the write" needs one whose identity a
//! test can change between two calls. Both are the *decorators'* behaviour, not
//! any provider's, and driving them with a fake is what makes them provable
//! without credentials — the same argument `sftp::ops` makes for the staged
//! write.
//!
//! Every method records its own name, so a wrapper that forwarded some
//! operations and quietly bypassed others is caught by a count rather than by
//! review.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};

use async_trait::async_trait;
use bytes::Bytes;

use crate::backend::Backend;
use crate::checksum::{ContentHash, HashAlgo};
use crate::error::{Result, StoreError};
use crate::guard::StoreIdentity;
use crate::model::{ByteRange, ObjectKey, ObjectMeta, Page, PutOutcome};
use crate::modified::SourceModified;

/// A backend that counts calls and fails the first `failures` calls to one
/// named operation.
pub struct CountingBackend {
    /// Which operation fails, by the name this module records it under.
    failing: &'static str,
    /// How many more times that operation must fail before it succeeds.
    remaining: AtomicU32,
    /// What it fails with.
    error: Mutex<StoreError>,
    /// Calls per operation name.
    calls: Mutex<BTreeMap<&'static str, usize>>,
}

impl CountingBackend {
    /// A backend whose `failing` operation fails its first `failures` calls with
    /// `error`, and succeeds after that.
    ///
    /// `u32::MAX` is the "never succeeds" case, which is what an exhausted-budget
    /// assertion needs.
    #[must_use]
    pub fn failing(failing: &'static str, failures: u32, error: StoreError) -> Self {
        Self {
            failing,
            remaining: AtomicU32::new(failures),
            error: Mutex::new(error),
            calls: Mutex::new(BTreeMap::new()),
        }
    }

    /// How many times `operation` has been called.
    #[must_use]
    pub fn calls(&self, operation: &str) -> usize {
        self.calls
            .lock()
            .expect("the call log is not poisoned")
            .get(operation)
            .copied()
            .unwrap_or(0)
    }

    /// Record one call, and decide whether it fails.
    fn attempt(&self, operation: &'static str) -> Result<()> {
        *self
            .calls
            .lock()
            .expect("the call log is not poisoned")
            .entry(operation)
            .or_insert(0) += 1;
        if operation != self.failing {
            return Ok(());
        }
        let remaining = self.remaining.load(Ordering::SeqCst);
        if remaining == 0 {
            return Ok(());
        }
        if remaining != u32::MAX {
            self.remaining.store(remaining - 1, Ordering::SeqCst);
        }
        Err(clone_error(
            &self.error.lock().expect("the error is not poisoned"),
        ))
    }
}

/// Copy a [`StoreError`] for a second return.
///
/// [`StoreError`] is not `Clone` — [`StoreError::Io`] wraps a
/// [`std::io::Error`], which is not — and this fake has to return the same
/// failure more than once. Only the variants the retry tests use are reproduced
/// exactly; anything else becomes an [`StoreError::Io`] carrying the original
/// text, which is honest about being a copy rather than pretending to be the
/// original.
fn clone_error(error: &StoreError) -> StoreError {
    match error {
        StoreError::Provider {
            backend,
            status,
            code,
            retry_after_secs,
        } => StoreError::Provider {
            backend,
            status: *status,
            code: code.clone(),
            retry_after_secs: *retry_after_secs,
        },
        StoreError::Transport { backend, detail } => StoreError::Transport {
            backend,
            detail: detail.clone(),
        },
        StoreError::NotFound(key) => StoreError::NotFound(key.clone()),
        StoreError::Backend(message) => StoreError::Backend(message.clone()),
        StoreError::RootChanged { root, detail } => StoreError::RootChanged {
            root: root.clone(),
            detail,
        },
        StoreError::Retried { attempts, source } => StoreError::Retried {
            attempts: *attempts,
            source: Box::new(clone_error(source)),
        },
        other => StoreError::Io(std::io::Error::other(other.to_string())),
    }
}

#[async_trait]
impl Backend for CountingBackend {
    fn name(&self) -> &'static str {
        "test"
    }

    async fn put(
        &self,
        _key: &ObjectKey,
        data: Bytes,
        expected: &ContentHash,
        _modified: SourceModified,
    ) -> Result<PutOutcome> {
        self.attempt("put")?;
        Ok(PutOutcome {
            size: data.len() as u64,
            verified: expected.clone(),
        })
    }

    /// Drains the stream and reports what it was told, so a decorator's
    /// behaviour around a streamed write is observable without a provider.
    ///
    /// Draining is the point rather than an incidental: a fake that dropped the
    /// stream would look identical to one that stored it, and the property the
    /// retry wrapper is tested for — that a consumed stream is **not** offered a
    /// second time — can only be seen by a fake that really consumed it.
    async fn put_stream(
        &self,
        _key: &ObjectKey,
        mut source: crate::incoming::ObjectStream,
        _modified: SourceModified,
    ) -> Result<PutOutcome> {
        self.attempt("put_stream")?;
        let mut size = 0u64;
        while let Some(window) = source.window().await? {
            size += window.len() as u64;
        }
        Ok(PutOutcome {
            size,
            verified: source.agreed()?,
        })
    }

    async fn get(&self, _key: &ObjectKey) -> Result<Bytes> {
        self.attempt("get")?;
        Ok(Bytes::from_static(b"payload"))
    }

    async fn get_range(&self, _key: &ObjectKey, _range: ByteRange) -> Result<Bytes> {
        self.attempt("get_range")?;
        Ok(Bytes::from_static(b"p"))
    }

    async fn head(&self, key: &ObjectKey) -> Result<ObjectMeta> {
        self.attempt("head")?;
        Ok(ObjectMeta {
            key: key.clone(),
            size: 7,
            modified_unix: None,
        })
    }

    async fn exists(&self, _key: &ObjectKey) -> Result<bool> {
        self.attempt("exists")?;
        Ok(true)
    }

    async fn delete(&self, _key: &ObjectKey) -> Result<()> {
        self.attempt("delete")
    }

    async fn list_page(&self, _prefix: &str, _cursor: Option<String>) -> Result<Page> {
        self.attempt("list_page")?;
        Ok(Page::default())
    }

    async fn list_staging(
        &self,
        _prefix: &str,
        _cursor: Option<String>,
    ) -> Result<crate::staging::StagingListing> {
        self.attempt("list_staging")?;
        Ok(crate::staging::StagingListing::Page(
            crate::staging::StagingPage::default(),
        ))
    }

    async fn list_incomplete_uploads(
        &self,
        _prefix: &str,
        _cursor: Option<String>,
    ) -> Result<crate::multipart::IncompleteUploads> {
        self.attempt("list_incomplete_uploads")?;
        Ok(crate::multipart::IncompleteUploads::Page(
            crate::multipart::IncompletePage::default(),
        ))
    }

    async fn abort_incomplete_upload(
        &self,
        _upload: &crate::multipart::IncompleteUpload,
    ) -> Result<()> {
        self.attempt("abort_incomplete_upload")
    }

    async fn store_identity(&self) -> Result<Option<StoreIdentity>> {
        self.attempt("store_identity")?;
        Ok(Some(StoreIdentity::distinguishing("counting")))
    }
}

/// A backend whose store identity a test can change between two calls.
///
/// The other half of what a fake is needed for. `guard::Guarded`'s property is
/// about one *process* whose store changes underneath it, and arranging that
/// against a real provider means renaming a directory, deleting a bucket or
/// unplugging a host — none of which the plain `cargo test --workspace` gate can
/// do, and two of which need credentials. What the decorator does with a changed
/// identity is not any provider's behaviour anyway; it is the decorator's, and
/// this is what makes it assertable.
pub struct IdentifiedBackend {
    /// The current identity, or `None` for a store that is not there.
    identity: Mutex<Option<StoreIdentity>>,
    /// Whether the probe itself fails.
    unprobeable: bool,
    calls: Mutex<BTreeMap<&'static str, usize>>,
}

impl IdentifiedBackend {
    /// A backend whose store currently identifies as `token`.
    #[must_use]
    pub fn at(token: &str) -> Self {
        Self {
            identity: Mutex::new(Some(StoreIdentity::distinguishing(token))),
            unprobeable: false,
            calls: Mutex::new(BTreeMap::new()),
        }
    }

    /// A backend whose store does not exist yet — the `dctl config create …
    /// path=/srv/new` case, where a first write legitimately creates it.
    #[must_use]
    pub fn absent() -> Self {
        Self {
            identity: Mutex::new(None),
            unprobeable: false,
            calls: Mutex::new(BTreeMap::new()),
        }
    }

    /// A backend whose store cannot be identified at all.
    #[must_use]
    pub fn unprobeable() -> Self {
        Self {
            identity: Mutex::new(None),
            unprobeable: true,
            calls: Mutex::new(BTreeMap::new()),
        }
    }

    /// The store is now a *different* one — a directory renamed away and
    /// re-created, a bucket deleted and made again.
    pub fn become_store(&self, token: &str) {
        *self.identity.lock().expect("not poisoned") = Some(StoreIdentity::distinguishing(token));
    }

    /// The store is gone.
    pub fn vanish(&self) {
        *self.identity.lock().expect("not poisoned") = None;
    }

    /// How many times the store was asked what it is.
    ///
    /// The figure the probe-rate assertion rests on: a guard that cost one
    /// provider round trip per write is the reason
    /// `guard::constants::PROBE_INTERVAL` exists, and counting is the only way
    /// to tell a bounded rate from an unbounded one.
    #[must_use]
    pub fn probes(&self) -> usize {
        self.calls("store_identity")
    }

    /// How many times `operation` reached the provider.
    #[must_use]
    pub fn calls(&self, operation: &str) -> usize {
        self.calls
            .lock()
            .expect("not poisoned")
            .get(operation)
            .copied()
            .unwrap_or(0)
    }

    fn record(&self, operation: &'static str) {
        *self
            .calls
            .lock()
            .expect("not poisoned")
            .entry(operation)
            .or_insert(0) += 1;
    }
}

#[async_trait]
impl Backend for IdentifiedBackend {
    fn name(&self) -> &'static str {
        "test"
    }

    async fn store_identity(&self) -> Result<Option<StoreIdentity>> {
        self.record("store_identity");
        if self.unprobeable {
            return Err(StoreError::Backend(
                "the store cannot be identified: the provider did not answer".into(),
            ));
        }
        Ok(self.identity.lock().expect("not poisoned").clone())
    }

    async fn put(
        &self,
        _key: &ObjectKey,
        data: Bytes,
        expected: &ContentHash,
        _modified: SourceModified,
    ) -> Result<PutOutcome> {
        self.record("put");
        Ok(PutOutcome {
            size: data.len() as u64,
            verified: expected.clone(),
        })
    }

    /// Drains the stream, so a guard that refused before the producer was asked
    /// is distinguishable from one that refused after it had encrypted an object.
    async fn put_stream(
        &self,
        _key: &ObjectKey,
        mut source: crate::incoming::ObjectStream,
        _modified: SourceModified,
    ) -> Result<PutOutcome> {
        self.record("put_stream");
        let mut size = 0u64;
        while let Some(window) = source.window().await? {
            size += window.len() as u64;
        }
        Ok(PutOutcome {
            size,
            verified: source.agreed()?,
        })
    }

    async fn get(&self, _key: &ObjectKey) -> Result<Bytes> {
        self.record("get");
        Ok(Bytes::from_static(b"payload"))
    }

    async fn get_range(&self, _key: &ObjectKey, _range: ByteRange) -> Result<Bytes> {
        self.record("get_range");
        Ok(Bytes::from_static(b"p"))
    }

    async fn head(&self, key: &ObjectKey) -> Result<ObjectMeta> {
        self.record("head");
        Ok(ObjectMeta {
            key: key.clone(),
            size: 7,
            modified_unix: None,
        })
    }

    async fn exists(&self, _key: &ObjectKey) -> Result<bool> {
        self.record("exists");
        Ok(true)
    }

    async fn delete(&self, _key: &ObjectKey) -> Result<()> {
        self.record("delete");
        Ok(())
    }

    async fn list_page(&self, _prefix: &str, _cursor: Option<String>) -> Result<Page> {
        self.record("list_page");
        Ok(Page::default())
    }

    async fn list_staging(
        &self,
        _prefix: &str,
        _cursor: Option<String>,
    ) -> Result<crate::staging::StagingListing> {
        self.record("list_staging");
        Ok(crate::staging::StagingListing::Page(
            crate::staging::StagingPage::default(),
        ))
    }

    async fn list_incomplete_uploads(
        &self,
        _prefix: &str,
        _cursor: Option<String>,
    ) -> Result<crate::multipart::IncompleteUploads> {
        self.record("list_incomplete_uploads");
        Ok(crate::multipart::IncompleteUploads::Page(
            crate::multipart::IncompletePage::default(),
        ))
    }

    async fn abort_incomplete_upload(
        &self,
        _upload: &crate::multipart::IncompleteUpload,
    ) -> Result<()> {
        self.record("abort_incomplete_upload");
        Ok(())
    }
}

/// The hash of this fake's canned body, for a caller that wants a `put` to
/// verify.
#[must_use]
pub fn payload_hash() -> ContentHash {
    ContentHash::compute(HashAlgo::Blake3, b"payload")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_named_operation_fails_exactly_as_often_as_asked() {
        let backend = CountingBackend::failing("get", 2, StoreError::NotFound("k".into()));
        let key = ObjectKey::new("k");
        assert!(backend.get(&key).await.is_err());
        assert!(backend.get(&key).await.is_err());
        assert!(backend.get(&key).await.is_ok());
        assert_eq!(backend.calls("get"), 3);
    }

    #[tokio::test]
    async fn other_operations_are_untouched_and_still_counted() {
        let backend = CountingBackend::failing("get", u32::MAX, StoreError::NotFound("k".into()));
        assert!(backend.head(&ObjectKey::new("k")).await.is_ok());
        assert_eq!(backend.calls("head"), 1);
        assert_eq!(backend.calls("get"), 0);
    }
}
