//! The decorator: any [`Backend`], refusing to write into a store that is no
//! longer the one this run has been using.
//!
//! # When the identity is recorded
//!
//! At the **first operation of the run**, whatever it is, and then never again.
//! Not at construction, because that would put a provider round trip in front of
//! `dctl ls` and every other command that will not write a byte; and not at the
//! first *write*, because by then a `copy` has already listed the destination and
//! a store that vanished in between would have gone unnoticed. The first
//! operation is the earliest moment the run touches the store at all, which is
//! exactly the window the guard has to cover: nothing has been written before
//! it, so there is nothing yet to be reported wrongly.
//!
//! A probe that fails is propagated rather than swallowed. A store that cannot
//! be identified is one nothing should be written into, and recording "unknown"
//! and carrying on would be the silent partial answer this module exists to
//! remove.
//!
//! # What is checked, and what is not
//!
//! Writes — `put`, `put_from_path`, `delete`. Reads are not: a read from a
//! replaced store returns [`StoreError::NotFound`], which is honest, and the
//! read side already has its own guard one layer up (`HANDOVER.md` §11.2, the
//! unmounted-volume case). The failure being removed here is the *write* half,
//! where a run reports objects as stored and verified into a container that is
//! not the store.
//!
//! # How often the store is probed, and what that trade is
//!
//! At most once per [`PROBE_INTERVAL`](super::constants::PROBE_INTERVAL) —
//! **not** once per write, and the difference was measured rather than assumed.
//! A probe on `local:` is one `stat`; on B2 it is a `b2_list_buckets` round trip,
//! which is a billed transaction, and probing per write turned a three-object
//! copy into a bucket into eighteen seconds and would add one API call per object
//! to every sync. A guard nobody can afford to leave switched on is not a guard,
//! so the *rate* is bounded rather than the guard being optional.
//!
//! What that costs, said plainly: a store that vanishes is caught within the
//! interval rather than on the very next write, so up to one interval's worth of
//! a run can be written first. On the two providers where that window could
//! otherwise be a *silent* success it is closed from the other side as well —
//! the SFTP write path no longer re-creates its base
//! ([`sftp::path::ancestor_dirs_below`](crate::sftp)), and a deleted B2 bucket
//! refuses uploads outright — so what the window really covers is the narrow
//! case of a container deleted **and re-created** mid-run.
//!
//! `local:` is unaffected either way: [`LocalFs`](crate::LocalFs) checks its own
//! root immediately before every single write, and that check is a `stat` it can
//! afford.
//!
//! # What this does not claim
//!
//! It is a check, not a lock. A store that vanishes between the check and the
//! request that publishes the object is a race the provider owns. What it
//! removes is the **silent** case — a whole run's worth of objects written
//! somewhere else and reported as success — and on the two providers whose
//! protocols cannot distinguish a replacement it removes the removal half, which
//! is the half those two write paths used to create for themselves.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use tokio::sync::OnceCell;

use crate::backend::{Backend, UploadTicket};
use crate::checksum::ContentHash;
use crate::error::Result;
use crate::model::{ByteRange, ObjectKey, ObjectMeta, Page, PutOutcome};
use crate::modified::SourceModified;

use super::constants::PROBE_INTERVAL;
use super::identity::{StoreIdentity, Verdict, refuse, verdict};

/// A [`Backend`] that refuses a write into a store that has moved out from
/// under the run.
pub struct Guarded {
    inner: Arc<dyn Backend>,
    /// What the store was when this run first touched it, or [`None`] when there
    /// was nothing there to record.
    opened_as: OnceCell<Option<StoreIdentity>>,
    /// What the refusal names, so an operator is told which store rather than
    /// which key.
    container: String,
    /// The shortest time between two probes.
    interval: Duration,
    /// When the store was last asked what it is.
    last_probe: Mutex<Option<Instant>>,
}

impl Guarded {
    /// Wrap `inner`, naming its container the way a refusal should read.
    #[must_use]
    pub fn wrap(inner: Arc<dyn Backend>, container: impl Into<String>) -> Arc<dyn Backend> {
        Self::with_interval(inner, container, PROBE_INTERVAL)
    }

    /// The same wrapper, probing at most once per `interval`.
    ///
    /// `Duration::ZERO` checks before every write, which is what the tests below
    /// want and what makes the rule assertable one call at a time. Not the
    /// ordinary path: [`Guarded::wrap`] is, and the module documentation says
    /// what the interval buys.
    #[must_use]
    pub fn with_interval(
        inner: Arc<dyn Backend>,
        container: impl Into<String>,
        interval: Duration,
    ) -> Arc<dyn Backend> {
        Arc::new(Self {
            inner,
            opened_as: OnceCell::new(),
            container: container.into(),
            interval,
            last_probe: Mutex::new(None),
        })
    }

    /// Whether enough time has passed to ask the provider again.
    ///
    /// Records the moment as taken when it answers `true`, so two concurrent
    /// writers cannot both decide to probe. Deliberately a plain `Mutex` held
    /// across no `.await`: the whole critical section is two clock reads.
    fn due_to_probe(&self) -> bool {
        let mut last = match self.last_probe.lock() {
            Ok(guard) => guard,
            // A poisoned lock means another task panicked mid-check. Probing is
            // the safe direction — it can only refuse a write that should have
            // been refused — so the guard stays on rather than switching itself
            // off because of an unrelated failure.
            Err(poisoned) => poisoned.into_inner(),
        };
        let now = Instant::now();
        match *last {
            Some(previous) if now.duration_since(previous) < self.interval => false,
            _ => {
                *last = Some(now);
                true
            }
        }
    }

    /// The identity this run recorded, probing once if it has not yet.
    async fn opened_as(&self) -> Result<&Option<StoreIdentity>> {
        self.opened_as
            .get_or_try_init(|| async {
                let identity = self.inner.store_identity().await?;
                // The recording *is* a probe, so the interval starts here rather
                // than at the first write: a run that recorded the store a
                // millisecond ago has nothing to learn by asking again.
                if let Ok(mut last) = self.last_probe.lock() {
                    *last = Some(Instant::now());
                }
                match &identity {
                    Some(id) => tracing::debug!(
                        backend = self.inner.name(),
                        container = %self.container,
                        strength = id.strength().label(),
                        "store identity recorded for this run"
                    ),
                    // Not a warning. `dctl config create backup local
                    // path=/srv/new` names a container that does not exist yet,
                    // and the first write through it legitimately creates one.
                    None => tracing::debug!(
                        backend = self.inner.name(),
                        container = %self.container,
                        "no store to record; the first write will create it"
                    ),
                }
                Ok(identity)
            })
            .await
    }

    /// Refuse if the store is no longer the one this run recorded.
    async fn require_same_store(&self) -> Result<()> {
        let recorded = self.opened_as().await?.clone();
        if !self.due_to_probe() {
            return Ok(());
        }
        let now = self.inner.store_identity().await?;
        match verdict(recorded.as_ref(), now.as_ref()) {
            Verdict::Proceed => Ok(()),
            other => {
                // ERROR, not WARN. Everything after this point in the run would
                // otherwise have been written into a different place and
                // reported as stored, which is the outcome the whole module
                // exists to stop being reported as a success.
                tracing::error!(
                    backend = self.inner.name(),
                    container = %self.container,
                    "the store this run was writing into is no longer there"
                );
                Err(refuse(&self.container, other))
            }
        }
    }
}

#[async_trait]
impl Backend for Guarded {
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
        self.require_same_store().await?;
        self.inner.put(key, data, expected, modified).await
    }

    async fn put_from_path(
        &self,
        key: &ObjectKey,
        source: &Path,
        expected: &ContentHash,
        modified: SourceModified,
    ) -> Result<PutOutcome> {
        self.require_same_store().await?;
        self.inner
            .put_from_path(key, source, expected, modified)
            .await
    }

    /// Guarded like the other two writes, and checked **before** the producer is
    /// asked for its first window.
    ///
    /// The ordering matters more here than anywhere else in this file: a streamed
    /// write is what a large object takes, a large object is what is still running
    /// when somebody swaps a disk, and the producer on the other end of the stream
    /// is a sealer that would otherwise spend minutes encrypting into a store this
    /// run never opened. Refusing first drops the stream, which closes the channel,
    /// which stops the sealer at its next window.
    async fn put_stream(
        &self,
        key: &ObjectKey,
        source: crate::incoming::ObjectStream,
        modified: SourceModified,
    ) -> Result<PutOutcome> {
        self.require_same_store().await?;
        self.inner.put_stream(key, source, modified).await
    }

    async fn delete(&self, key: &ObjectKey) -> Result<()> {
        self.require_same_store().await?;
        self.inner.delete(key).await
    }

    // ── reads: recorded on, never refused ────────────────────────────────
    //
    // Each still touches `opened_as` so the identity is captured at the run's
    // first operation rather than at its first write — a `copy` lists the
    // destination before it stores anything, and a store that vanished in
    // between would otherwise never have been recorded at all.

    async fn get(&self, key: &ObjectKey) -> Result<Bytes> {
        self.opened_as().await?;
        self.inner.get(key).await
    }

    async fn get_to_path(&self, key: &ObjectKey, dest: &Path) -> Result<()> {
        self.opened_as().await?;
        self.inner.get_to_path(key, dest).await
    }

    async fn get_range(&self, key: &ObjectKey, range: ByteRange) -> Result<Bytes> {
        self.opened_as().await?;
        self.inner.get_range(key, range).await
    }

    async fn head(&self, key: &ObjectKey) -> Result<ObjectMeta> {
        self.opened_as().await?;
        self.inner.head(key).await
    }

    async fn exists(&self, key: &ObjectKey) -> Result<bool> {
        self.opened_as().await?;
        self.inner.exists(key).await
    }

    async fn list_page(&self, prefix: &str, cursor: Option<String>) -> Result<Page> {
        self.opened_as().await?;
        self.inner.list_page(prefix, cursor).await
    }

    /// Recorded on like every other read, and refused at the other end.
    ///
    /// This is the one read whose answer becomes a `delete`, which is an
    /// argument for refusing it here — and the argument does not survive
    /// contact with where the guard already is. A sweep that enumerated a
    /// replacement would have every one of its deletions refused by
    /// [`Guarded::delete`], so no key is removed from a store this run did not
    /// open; refusing the listing as well would buy one clear error in place of
    /// N, at the cost of making this the only read in the trait with its own
    /// rule. The property is pinned at the destructive end, where it holds.
    async fn list_staging(
        &self,
        prefix: &str,
        cursor: Option<String>,
    ) -> Result<crate::staging::StagingListing> {
        self.opened_as().await?;
        self.inner.list_staging(prefix, cursor).await
    }

    /// Recorded on like every other read, and refused at the destructive end —
    /// the same argument [`Guarded::list_staging`] makes and for the same reason:
    /// the sweep's *cancellations* are what a replaced store must not receive, and
    /// that is [`abort_incomplete_upload`](Guarded::abort_incomplete_upload).
    async fn list_incomplete_uploads(
        &self,
        prefix: &str,
        cursor: Option<String>,
    ) -> Result<crate::multipart::IncompleteUploads> {
        self.opened_as().await?;
        self.inner.list_incomplete_uploads(prefix, cursor).await
    }

    /// Guarded, because it destroys stored bytes.
    ///
    /// An abort throws away every part an upload was holding, so it belongs with
    /// `delete` and not with the listings: a sweep that enumerated a *replacement*
    /// store must not be able to cancel that store's live uploads on the strength
    /// of a listing it took from somewhere else.
    async fn abort_incomplete_upload(
        &self,
        upload: &crate::multipart::IncompleteUpload,
    ) -> Result<()> {
        self.require_same_store().await?;
        self.inner.abort_incomplete_upload(upload).await
    }

    async fn prepare_upload(
        &self,
        key: &ObjectKey,
        content_len: u64,
        content_sha256: Option<&[u8; 32]>,
    ) -> Result<UploadTicket> {
        self.require_same_store().await?;
        self.inner
            .prepare_upload(key, content_len, content_sha256)
            .await
    }

    async fn store_identity(&self) -> Result<Option<StoreIdentity>> {
        self.inner.store_identity().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HashAlgo;
    use crate::error::StoreError;
    use crate::testing::IdentifiedBackend;

    fn key() -> ObjectKey {
        ObjectKey::new("a/b.bin")
    }

    /// A guard that checks before every write.
    ///
    /// The shipped interval is a cost decision about billed provider round
    /// trips (see the module docs); the *rule* is what these tests are about, and
    /// a test that had to sleep through an interval to observe it would be
    /// slower and no more convincing.
    fn checked(inner: Arc<dyn Backend>, container: &str) -> Arc<dyn Backend> {
        Guarded::with_interval(inner, container, Duration::ZERO)
    }

    fn payload() -> (Bytes, ContentHash) {
        let data = Bytes::from_static(b"payload");
        let hash = ContentHash::compute(HashAlgo::Blake3, &data);
        (data, hash)
    }

    #[tokio::test]
    async fn a_store_that_is_replaced_mid_run_refuses_the_next_write() {
        // The whole defect in one test, at the level the property lives: one
        // *process* whose store changes underneath it. A store legitimately
        // replaced *between* two runs is simply a different store, which is why
        // the identity is recorded per run rather than persisted.
        let inner = Arc::new(IdentifiedBackend::at("store-a"));
        let counter = Arc::clone(&inner);
        let backend = checked(Arc::clone(&inner) as Arc<dyn Backend>, "/srv/vault");
        let (data, hash) = payload();

        backend
            .put(&key(), data.clone(), &hash, SourceModified::unknown())
            .await
            .expect("the store is the one the run recorded");

        // Renamed away and re-created: something is there, and it is not the
        // store. Existence alone would have passed here, which is the reason the
        // guard compares identity.
        inner.become_store("store-b");

        let error = backend
            .put(&key(), data, &hash, SourceModified::unknown())
            .await
            .expect_err("a replacement must not be written into");
        assert!(matches!(error, StoreError::RootChanged { .. }), "{error}");
        assert!(error.to_string().contains("/srv/vault"), "{error}");
        assert!(error.to_string().contains("replaced"), "{error}");
        assert_eq!(
            counter.calls("put"),
            1,
            "the refused write must not reach the provider"
        );
    }

    #[tokio::test]
    async fn a_sweep_cannot_delete_debris_out_of_a_store_that_was_replaced() {
        // `cleanup` reads a list of abandoned keys and then deletes every one of
        // them, so the window between those two steps is the one place in this
        // command where a replaced store would be destructive. The enumeration
        // is a read and is recorded on rather than refused, like every other
        // read; the property is pinned where it bites.
        let inner = Arc::new(IdentifiedBackend::at("store-a"));
        let counter = Arc::clone(&inner);
        let backend = checked(Arc::clone(&inner) as Arc<dyn Backend>, "/srv/vault");

        backend
            .list_staging("", None)
            .await
            .expect("the store is the one the run recorded");
        inner.become_store("store-b");

        let error = backend
            .delete(&key())
            .await
            .expect_err("a replacement must not be deleted from");
        assert!(matches!(error, StoreError::RootChanged { .. }), "{error}");
        assert_eq!(
            counter.calls("delete"),
            0,
            "the refused deletion must not reach the provider"
        );
    }

    #[tokio::test]
    async fn a_store_that_vanishes_mid_run_refuses_the_next_write() {
        let inner = Arc::new(IdentifiedBackend::at("store-a"));
        let counter = Arc::clone(&inner);
        let backend = checked(Arc::clone(&inner) as Arc<dyn Backend>, "b2:DCTL001");
        let (data, hash) = payload();

        backend
            .put(&key(), data.clone(), &hash, SourceModified::unknown())
            .await
            .expect("the bucket is there");
        inner.vanish();

        let error = backend
            .put(&key(), data, &hash, SourceModified::unknown())
            .await
            .expect_err("a deleted bucket must not be written into");
        assert!(error.to_string().contains("removed"), "{error}");
        assert_eq!(counter.calls("put"), 1);
    }

    #[tokio::test]
    async fn a_store_that_did_not_exist_yet_admits_the_write_that_creates_it() {
        // `dctl config create backup local path=/srv/new`. The guard must not
        // break the ordinary first run to catch the rare mid-run one.
        let inner = Arc::new(IdentifiedBackend::absent());
        let backend = checked(inner, "/srv/new");
        let (data, hash) = payload();
        backend
            .put(&key(), data, &hash, SourceModified::unknown())
            .await
            .expect("a first write creates the store");
    }

    #[tokio::test]
    async fn the_identity_is_recorded_at_the_first_operation_and_not_the_first_write() {
        // A `copy` lists the destination before it stores anything. Recording at
        // the first *write* would mean a store that vanished between the listing
        // and the first object was never recorded at all — and an unrecorded
        // store admits every write, which is the defect back again by a
        // different route.
        let inner = Arc::new(IdentifiedBackend::at("store-a"));
        let backend = checked(Arc::clone(&inner) as Arc<dyn Backend>, "/srv/vault");

        backend
            .list_page("", None)
            .await
            .expect("the listing works");
        inner.vanish();

        let (data, hash) = payload();
        let error = backend
            .put(&key(), data, &hash, SourceModified::unknown())
            .await
            .expect_err("the store was recorded by the listing");
        assert!(matches!(error, StoreError::RootChanged { .. }), "{error}");
    }

    #[tokio::test]
    async fn a_delete_is_guarded_as_well_as_a_write() {
        // A `sync --delete` against a replaced store would otherwise remove
        // objects from a container the run never chose.
        let inner = Arc::new(IdentifiedBackend::at("store-a"));
        let counter = Arc::clone(&inner);
        let backend = checked(Arc::clone(&inner) as Arc<dyn Backend>, "/srv/vault");
        backend.head(&key()).await.expect("records the identity");
        inner.become_store("store-b");

        assert!(backend.delete(&key()).await.is_err());
        assert_eq!(counter.calls("delete"), 0);
    }

    #[tokio::test]
    async fn reads_are_recorded_on_but_never_refused() {
        // A read from a replaced store returns `NotFound`, which is honest, and
        // the read side has its own guard one layer up. Refusing here would make
        // `dctl ls` fail on a store somebody legitimately swapped between two
        // commands.
        let inner = Arc::new(IdentifiedBackend::at("store-a"));
        let backend = checked(Arc::clone(&inner) as Arc<dyn Backend>, "/srv/vault");
        backend.head(&key()).await.expect("records the identity");
        inner.become_store("store-b");

        assert!(backend.head(&key()).await.is_ok());
        assert!(backend.list_page("", None).await.is_ok());
    }

    #[tokio::test]
    async fn the_probe_interval_limits_the_rate_and_does_not_switch_the_guard_off() {
        // The shipped configuration, not the zero-interval one the other tests
        // use. Two properties at once: writes inside the interval do not each
        // cost a provider round trip, and the guard still refuses once the
        // interval has passed. A rate limit that quietly became an off switch
        // would satisfy the first and be worthless.
        let inner = Arc::new(IdentifiedBackend::at("store-a"));
        let counter = Arc::clone(&inner);
        let backend = Guarded::with_interval(
            Arc::clone(&inner) as Arc<dyn Backend>,
            "b2:DCTL001",
            Duration::from_millis(60),
        );
        let (data, hash) = payload();

        for _ in 0..4 {
            backend
                .put(&key(), data.clone(), &hash, SourceModified::unknown())
                .await
                .expect("the store is the one the run recorded");
        }
        assert_eq!(counter.calls("put"), 4);
        assert_eq!(
            counter.probes(),
            1,
            "four writes inside one interval must cost one probe, not four"
        );

        inner.become_store("store-b");
        tokio::time::sleep(Duration::from_millis(80)).await;
        let error = backend
            .put(&key(), data, &hash, SourceModified::unknown())
            .await
            .expect_err("the interval has passed and the store has changed");
        assert!(matches!(error, StoreError::RootChanged { .. }), "{error}");
    }

    #[tokio::test]
    async fn a_probe_that_fails_stops_the_run_rather_than_guessing() {
        // Recording "unknown" and carrying on would be the silent partial answer
        // the module exists to remove: an unrecorded store admits every write.
        let inner = Arc::new(IdentifiedBackend::unprobeable());
        let backend = checked(inner, "b2:DCTL001");
        let (data, hash) = payload();
        let error = backend
            .put(&key(), data, &hash, SourceModified::unknown())
            .await
            .expect_err("an unidentifiable store is not written into");
        assert!(
            error.to_string().contains("cannot be identified"),
            "{error}"
        );
    }
}
