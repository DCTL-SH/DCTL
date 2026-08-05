//! A vault over a store that serves fewer bytes than it holds.
//!
//! # Why this was unreached
//!
//! Every other test in this crate reaches the store through [`LocalFs`], which
//! reads a real file: its `head` and its `get_range` cannot disagree, and a
//! range it answers is either the bytes that are there or an error. The crate's
//! existing fakes do not change that — `Unreadable` and `FaultyGrantGet` inject
//! *failures* on `get` and `put`, and forward `get_range` to the real backend
//! verbatim. So no test in the workspace has ever handed the reader a range that
//! came back **short but successful**, and the two places where it holds a
//! provider to what it asked for — the ranged fetch behind every chunk, and the
//! footer read that closes a verify — were never executed. Deleting either left
//! `cargo test --workspace` green.
//!
//! Nothing else would have caught it. The per-chunk Poly1305 tags are computed
//! over whatever ciphertext arrives, so a *short* window does not fail a tag —
//! it fails to be a window at all, and the decoder below would be handed a
//! buffer shorter than the geometry it was told to decrypt.
//!
//! # What a store that short-serves actually is
//!
//! Not a corrupted one, which is why it is the interesting case. Every byte it
//! hands over is genuinely that object's; it simply stops. That is what a
//! connection dropped mid-response looks like to the layer above it, what a
//! caching proxy that stored a partial body serves forever afterwards, and what
//! a bucket restored from an interrupted copy holds. B2 and S3 both answer a
//! range request with a body and a length, and the two coming apart is a network
//! event rather than a provider bug.
//!
//! The consequence of believing one is precise. `dctl verify` and `dctl check`
//! exist to answer one question — *is the archive still intact* — and a
//! read-back that accepted short windows would answer **yes** for an object
//! nobody has all of. `dctl mount` would serve the same short window into a
//! `read()` and the file would be silently wrong in the middle. Both are
//! [the plan](https://doc.dctl.sh/project/plan) §6's forbidden outcome reached
//! through the command that is supposed to prevent it.

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use dctl_core::{Modified, Vault};
use dctl_store::{
    Backend, ByteRange, ContentHash, LocalFs, ObjectKey, ObjectMeta, Page, PutOutcome,
    SourceModified, StagingListing, StoreIdentity,
};
use tempfile::TempDir;

/// A store that holds everything and will not serve past `keep` bytes of any
/// object.
///
/// A decorator over a real [`LocalFs`] rather than a hand-built fake, so the
/// object under it is one this crate really sealed and every method except the
/// one under test behaves exactly as production does. In particular `head`
/// reports the **true** size: the disagreement has to be between what the store
/// says and what it serves, because a store whose `head` was also short is
/// caught one step earlier by `confirm_object_length` and would prove nothing
/// about the guards below it.
struct ShortServing {
    inner: Arc<dyn Backend>,
    /// The first offset that will not be served. Ranges are clamped to it, and a
    /// range starting at or past it comes back empty.
    keep: u64,
}

#[async_trait]
impl Backend for ShortServing {
    fn name(&self) -> &'static str {
        "short-serving"
    }

    async fn store_identity(&self) -> dctl_store::Result<Option<StoreIdentity>> {
        self.inner.store_identity().await
    }

    /// Forwarded: this double changes what is *served*, not what the store
    /// behind it recorded.
    fn checksum_support(&self) -> dctl_store::ChecksumSupport {
        self.inner.checksum_support()
    }

    async fn stored_checksum(
        &self,
        key: &ObjectKey,
    ) -> dctl_store::Result<dctl_store::StoredChecksum> {
        self.inner.stored_checksum(key).await
    }

    async fn put(
        &self,
        key: &ObjectKey,
        data: Bytes,
        expected: &ContentHash,
        modified: SourceModified,
    ) -> dctl_store::Result<PutOutcome> {
        self.inner.put(key, data, expected, modified).await
    }

    async fn put_from_path(
        &self,
        key: &ObjectKey,
        source: &Path,
        expected: &ContentHash,
        modified: SourceModified,
    ) -> dctl_store::Result<PutOutcome> {
        self.inner
            .put_from_path(key, source, expected, modified)
            .await
    }

    async fn get(&self, key: &ObjectKey) -> dctl_store::Result<Bytes> {
        // Clamped too, so a caller that reaches for the whole object gets the
        // same truncated store the ranged path sees rather than a second,
        // kinder one.
        let whole = self.inner.get(key).await?;
        let end = usize::try_from(self.keep)
            .unwrap_or(usize::MAX)
            .min(whole.len());
        Ok(whole.slice(..end))
    }

    async fn get_range(&self, key: &ObjectKey, range: ByteRange) -> dctl_store::Result<Bytes> {
        let bytes = self.inner.get_range(key, range).await?;
        let start = range.offset;
        if start >= self.keep {
            return Ok(Bytes::new());
        }
        let allowed = usize::try_from(self.keep - start).unwrap_or(usize::MAX);
        Ok(bytes.slice(..allowed.min(bytes.len())))
    }

    async fn head(&self, key: &ObjectKey) -> dctl_store::Result<ObjectMeta> {
        self.inner.head(key).await
    }

    async fn exists(&self, key: &ObjectKey) -> dctl_store::Result<bool> {
        self.inner.exists(key).await
    }

    async fn delete(&self, key: &ObjectKey) -> dctl_store::Result<()> {
        self.inner.delete(key).await
    }

    async fn list_page(&self, prefix: &str, cursor: Option<String>) -> dctl_store::Result<Page> {
        self.inner.list_page(prefix, cursor).await
    }

    async fn list_staging(
        &self,
        prefix: &str,
        cursor: Option<String>,
    ) -> dctl_store::Result<StagingListing> {
        self.inner.list_staging(prefix, cursor).await
    }

    async fn put_stream(
        &self,
        key: &ObjectKey,
        source: dctl_store::ObjectStream,
        modified: SourceModified,
    ) -> dctl_store::Result<PutOutcome> {
        self.inner.put_stream(key, source, modified).await
    }

    async fn list_incomplete_uploads(
        &self,
        prefix: &str,
        cursor: Option<String>,
    ) -> dctl_store::Result<dctl_store::IncompleteUploads> {
        self.inner.list_incomplete_uploads(prefix, cursor).await
    }

    async fn abort_incomplete_upload(
        &self,
        upload: &dctl_store::IncompleteUpload,
    ) -> dctl_store::Result<()> {
        self.inner.abort_incomplete_upload(upload).await
    }
}

/// Chunk size the object under test is sealed at, in bytes.
///
/// Small enough that a modest payload is many chunks — the ranged reader fetches
/// one span at a time, so a single-chunk object would never exercise the loop
/// the guard lives in.
const CHUNK: usize = 4096;

/// The store, the index and the object's key, with one file already sealed.
struct Sealed {
    _store: TempDir,
    _index: TempDir,
    store_path: std::path::PathBuf,
    index_path: std::path::PathBuf,
    /// The stored object's real length, which is what every `keep` below is
    /// measured against.
    object_len: u64,
    payload: Vec<u8>,
}

/// Seal one multi-chunk file into a fresh vault over a real local store.
async fn sealed() -> Sealed {
    let store = TempDir::new().expect("a store directory");
    let index = TempDir::new().expect("an index directory");
    let store_path = store.path().to_path_buf();
    let index_path = index.path().join("vault.redb");
    let backend: Arc<dyn Backend> = Arc::new(LocalFs::new(&store_path));

    // A repeating, non-constant payload: a short window of it differs from the
    // right window, so nothing here can pass by accident.
    let payload: Vec<u8> = (0..CHUNK * 6 + 17).map(|n| (n % 251) as u8).collect();
    let vault = Vault::init(Arc::clone(&backend), &index_path, "pw")
        .await
        .expect("a vault initialises")
        .vault;
    vault
        .put_file("big.bin", &payload, Modified::Now)
        .await
        .expect("the file seals");

    // The object's key, found by listing rather than by guessing at the naming
    // scheme — this file is about the reader, not about how objects are named.
    let page = backend
        .list_page("o/", None)
        .await
        .expect("the store lists");
    let key = ObjectKey::new(
        page.items
            .first()
            .expect("one sealed object")
            .key
            .as_str()
            .to_string(),
    );
    let object_len = backend.head(&key).await.expect("the object is there").size;
    drop(vault);

    Sealed {
        _store: store,
        _index: index,
        store_path,
        index_path,
        object_len,
        payload,
    }
}

/// Unlock the same vault over a store that will not serve past `keep`.
///
/// `keep` is a ceiling on **every** object, the envelope included — so this only
/// works because a one-slot `DKE1` envelope is a couple of hundred bytes and
/// every `keep` below is measured against a multi-chunk object thousands of
/// bytes long. Stated rather than assumed: an envelope that fell past the
/// ceiling would fail to unlock, and a test that failed there would look exactly
/// like one whose guard fired.
async fn short_vault(sealed: &Sealed, keep: u64) -> Vault {
    let backend: Arc<dyn Backend> = Arc::new(ShortServing {
        inner: Arc::new(LocalFs::new(&sealed.store_path)),
        keep,
    });
    assert!(
        keep > 4096,
        "the ceiling has to clear the envelope, or the failure is the unlock"
    );
    Vault::unlock(
        backend,
        &sealed.index_path,
        dctl_core::UnlockKey::Password("pw"),
    )
    .await
    .expect("the envelope is far shorter than the ceiling")
}

#[tokio::test]
async fn a_window_the_store_will_not_serve_in_full_is_refused_not_decrypted() {
    // The guard behind every ranged read the product makes: `dctl mount`'s seek,
    // `dctl cat --offset`, and the window loop that `verify` and `check` are
    // built on. The reader asks for exactly one chunk span; a provider that
    // answers with fewer bytes has not answered the question.
    //
    // `keep` is set inside the payload, so the header and the first spans arrive
    // whole and the shortfall lands in the middle of a chunk — the shape a
    // dropped connection has, and the one where every byte received is genuine.
    let sealed = sealed().await;
    let vault = short_vault(&sealed, sealed.object_len / 2).await;

    let error = vault
        .verify_file("big.bin")
        .await
        .expect_err("a store that stops mid-object cannot pass a verify");
    let message = error.to_string();
    assert!(
        message.contains("ranged read returned") && message.contains("expected"),
        "the refusal must say the provider came up short, and by how much: {message}"
    );
    // Named as a transfer problem rather than a corrupt object, because those
    // two findings send an operator to completely different places — one to the
    // network, one to a second copy of the archive.
    assert!(
        matches!(error, dctl_core::CoreError::Integrity(_)),
        "a short answer is an integrity finding: {error}"
    );

    // The whole-file read is refused for the same reason, so no command reaches
    // a kinder path to the same bytes.
    assert!(vault.get_file("big.bin").await.is_err());

    // And the control: the same object, the same code, a store that serves
    // everything — so the refusal is about the shortfall and not about the
    // decorator.
    let whole = short_vault(&sealed, u64::MAX).await;
    whole
        .verify_file("big.bin")
        .await
        .expect("an object served in full verifies");
    assert_eq!(
        whole
            .get_file("big.bin")
            .await
            .expect("and reads back")
            .as_slice(),
        sealed.payload.as_slice()
    );
}

#[tokio::test]
async fn a_footer_the_store_will_not_serve_in_full_is_refused_not_skipped() {
    // §3's trailing footer is a BLAKE3 over everything before it, and `verify`
    // folds the ciphertext as it decrypts so the comparison costs no second
    // pass. This is the read that fetches the recorded value.
    //
    // `keep` is set so every chunk arrives whole and the footer arrives in part.
    // Without the length check the comparison runs against a prefix of the
    // recorded hash, which cannot match — so the *failure* still happens, and it
    // says the object's footer does not match the bytes it served. That is a
    // report of a corrupt archive for a store that merely stopped talking, and
    // that substitution is the whole defect: an operator told their data is
    // damaged goes looking for a backup instead of at their network.
    let sealed = sealed().await;
    let footer_len = 32;
    let vault = short_vault(&sealed, sealed.object_len - footer_len / 2).await;

    let error = vault
        .verify_file("big.bin")
        .await
        .expect_err("a partial footer cannot close a verify");
    let message = error.to_string();
    assert!(
        message.contains("declares a footer and holds"),
        "the refusal must say the footer itself came up short: {message}"
    );
    assert!(
        !message.contains("does not match the bytes it served"),
        "a short read must not be reported as a hash mismatch: {message}"
    );
}
