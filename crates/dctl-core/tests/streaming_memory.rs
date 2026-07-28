//! Nothing a vault does to a whole object may cost the object.
//!
//! `PLAN.md` §16.2 requires memory to stay `O(concurrency)`, and the promise the
//! whole tool is sold on — play a huge encrypted video straight off a bucket —
//! is the same property said in a user's words. It was not true. Measured on the
//! release binary under a hard cgroup cap, before the change:
//!
//! | object  | copy in   | copy out  | cat       | verify    |
//! |---------|-----------|-----------|-----------|-----------|
//! | 256 MiB | 786 MiB   | 528 MiB   | 528 MiB   | 272 MiB   |
//! | 1 GiB   | 3090 MiB  | 2064 MiB  | 2064 MiB  | 1040 MiB  |
//!
//! Every column dead straight in the object's size, and a 256 MiB object could
//! not be moved inside a 512 MiB cap at all.
//!
//! ## Why these tests assert on *requests* rather than on resident memory
//!
//! Because peak RSS is a property of a process and these are library tests. The
//! honest proof is the measurement above, repeated after the fix and recorded in
//! `HANDOVER.md`; what a test can do is pin the mechanism that produced it, and
//! do so deterministically.
//!
//! The mechanism is exactly this: a constant-memory path asks the backend for
//! **windows**, and a buffering one asks for the **whole object**. So the
//! backend below records the largest single response it ever hands back and
//! whether anybody asked for an object whole. A regression to a buffered read is
//! then not a slower test or a flaky threshold — it is one enormous response
//! where there should have been a run of small ones, which is visible however
//! big or small the fixture is.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use async_trait::async_trait;
use bytes::Bytes;
use dctl_core::{Modified, Vault};
use dctl_store::{
    Backend, ByteRange, ContentHash, LocalFs, ObjectKey, ObjectMeta, Page, PutOutcome,
    SourceModified,
};
use tempfile::TempDir;

/// Comfortably more than one window of the format's 1 MiB chunks, so a buffered
/// read and a windowed one cannot be confused for one another, and small enough
/// that a debug-build test seals it in well under a second.
const OBJECT_BYTES: usize = 24 * 1024 * 1024;

/// The largest single response a windowed read is allowed to produce.
///
/// `STREAM_WINDOW_CHUNKS` chunks of at most `MAX_CHUNK_SIZE`, with room for the
/// per-chunk tags — spelled as its own number rather than computed from the
/// constant, so that raising the constant has to be a deliberate edit here too
/// rather than something a test silently follows.
const WINDOW_CEILING: u64 = 16 * 1024 * 1024;

/// A real [`LocalFs`], watched.
///
/// Every method delegates; nothing is simulated. The two facts recorded are the
/// ones that separate a streaming read from a buffering one.
#[derive(Debug)]
struct Watched {
    inner: LocalFs,
    /// Bytes in the largest single response any call has returned.
    largest_response: AtomicU64,
    /// Bytes in the largest single body any call has been *given*.
    largest_request: AtomicU64,
    /// Whether anything asked for an object whole.
    asked_for_whole_object: AtomicBool,
}

impl Watched {
    fn new(root: &Path) -> Self {
        Self {
            inner: LocalFs::new(root),
            largest_response: AtomicU64::new(0),
            largest_request: AtomicU64::new(0),
            asked_for_whole_object: AtomicBool::new(false),
        }
    }

    fn note_response(&self, bytes: usize) {
        self.largest_response
            .fetch_max(bytes as u64, Ordering::Relaxed);
    }

    fn reset(&self) {
        self.largest_response.store(0, Ordering::Relaxed);
        self.largest_request.store(0, Ordering::Relaxed);
        self.asked_for_whole_object.store(false, Ordering::Relaxed);
    }

    fn largest_response(&self) -> u64 {
        self.largest_response.load(Ordering::Relaxed)
    }

    fn largest_request(&self) -> u64 {
        self.largest_request.load(Ordering::Relaxed)
    }

    fn asked_for_whole_object(&self) -> bool {
        self.asked_for_whole_object.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl Backend for Watched {
    fn name(&self) -> &'static str {
        self.inner.name()
    }
    async fn store_identity(&self) -> dctl_store::Result<Option<dctl_store::StoreIdentity>> {
        self.inner.store_identity().await
    }
    async fn put(
        &self,
        key: &ObjectKey,
        data: Bytes,
        expected: &ContentHash,
        modified: SourceModified,
    ) -> dctl_store::Result<PutOutcome> {
        self.largest_request
            .fetch_max(data.len() as u64, Ordering::Relaxed);
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
        // The call that cannot be bounded: it returns whatever is there.
        // A read path that reaches for it has already lost.
        self.asked_for_whole_object.store(true, Ordering::Relaxed);
        let bytes = self.inner.get(key).await?;
        self.note_response(bytes.len());
        Ok(bytes)
    }
    async fn get_to_path(&self, key: &ObjectKey, dest: &Path) -> dctl_store::Result<()> {
        self.inner.get_to_path(key, dest).await
    }
    async fn get_range(&self, key: &ObjectKey, range: ByteRange) -> dctl_store::Result<Bytes> {
        let bytes = self.inner.get_range(key, range).await?;
        self.note_response(bytes.len());
        Ok(bytes)
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
}

struct Fixture {
    _store: TempDir,
    _index: TempDir,
    vault: Vault,
    watched: Arc<Watched>,
    plaintext: Vec<u8>,
}

/// A real vault holding one multi-window object, written from a real file
/// through the streaming store — which is the path a transfer uses.
async fn fixture() -> Fixture {
    let store = TempDir::new().expect("a temporary store");
    let index = TempDir::new().expect("a temporary index");
    let watched = Arc::new(Watched::new(store.path()));
    let backend: Arc<dyn Backend> = Arc::clone(&watched) as Arc<dyn Backend>;
    let index_path = index.path().join("index.redb");

    let vault = Vault::init(Arc::clone(&backend), &index_path, "pw")
        .await
        .expect("a fresh vault initialises")
        .vault;

    // Not random: a pattern makes an assertion failure legible, and the object
    // is not being compressed by anything.
    let plaintext: Vec<u8> = (0..OBJECT_BYTES).map(|i| (i % 251) as u8).collect();
    let source = index.path().join("source.bin");
    std::fs::write(&source, &plaintext).expect("a source file");

    vault
        .put_file_from_path("big.bin", &source, Modified::At(1_700_000_000))
        .await
        .expect("the object stores");

    Fixture {
        _store: store,
        _index: index,
        vault,
        watched,
        plaintext,
    }
}

#[tokio::test]
async fn storing_a_file_never_hands_the_backend_the_whole_object() {
    // The write half. `put_file` seals the plaintext in memory and hands the
    // finished object to `Backend::put` as one buffer — which is why `copy` of a
    // 1 GiB file peaked at 3090 MiB. The streaming store seals to a temp and
    // uses `put_from_path`, so the only buffers the backend is ever *given* are
    // the vault's own small bookkeeping records.
    let fixture = fixture().await;
    assert!(
        fixture.watched.largest_request() < WINDOW_CEILING,
        "the backend was handed a {}-byte body while storing a {OBJECT_BYTES}-byte \
         file — the object was buffered",
        fixture.watched.largest_request()
    );
}

#[tokio::test]
async fn a_streamed_read_asks_for_windows_and_never_for_the_object() {
    let fixture = fixture().await;
    fixture.watched.reset();

    let mut out = Vec::with_capacity(OBJECT_BYTES);
    let streamed = fixture
        .vault
        .stream_file_to("big.bin", &mut out)
        .await
        .expect("the object streams back");

    // It has to be the right bytes, or the rest of the assertions are about a
    // read that did not happen.
    assert_eq!(out, fixture.plaintext, "the streamed bytes must be exact");
    assert_eq!(streamed.bytes, OBJECT_BYTES as u64);
    assert_eq!(
        streamed.plaintext_hash,
        *blake3::hash(&fixture.plaintext).as_bytes(),
        "the digest handed back is the digest of what was streamed"
    );

    assert!(
        !fixture.watched.asked_for_whole_object(),
        "a streamed read fetched the object whole"
    );
    assert!(
        fixture.watched.largest_response() <= WINDOW_CEILING,
        "a single response of {} bytes for a {OBJECT_BYTES}-byte object is not a \
         window",
        fixture.watched.largest_response()
    );
}

#[tokio::test]
async fn a_streamed_read_to_a_file_is_bounded_and_exact() {
    // The call the transfer engine's download stage makes.
    let fixture = fixture().await;
    let dest = fixture._index.path().join("out.bin");
    fixture.watched.reset();

    let streamed = fixture
        .vault
        .get_file_to_path("big.bin", &dest)
        .await
        .expect("the object decrypts to disk");

    assert_eq!(
        std::fs::read(&dest).expect("the destination exists"),
        fixture.plaintext
    );
    assert_eq!(streamed.bytes, OBJECT_BYTES as u64);
    assert!(
        !fixture.watched.asked_for_whole_object(),
        "a download fetched the object whole"
    );
    assert!(
        fixture.watched.largest_response() <= WINDOW_CEILING,
        "a download's largest response was {} bytes",
        fixture.watched.largest_response()
    );
}

#[tokio::test]
async fn verifying_never_pulls_the_whole_object() {
    // `verify_file` streamed its *plaintext* to a sink and documented itself as
    // constant-memory, while `Backend::get` pulled the entire ciphertext first.
    // A scrub of a 1 GiB object peaked at 1040 MiB for exactly that reason: the
    // buffer nobody had counted was the whole object.
    let fixture = fixture().await;
    fixture.watched.reset();

    fixture
        .vault
        .verify_file("big.bin")
        .await
        .expect("an intact object verifies");

    assert!(
        !fixture.watched.asked_for_whole_object(),
        "verify fetched the object whole — this is the 1040 MiB scrub"
    );
    assert!(
        fixture.watched.largest_response() <= WINDOW_CEILING,
        "verify's largest response was {} bytes",
        fixture.watched.largest_response()
    );
}

#[tokio::test]
async fn a_streamed_read_still_refuses_a_tampered_chunk() {
    // Bounding the memory must not have bought anything at the expense of what a
    // read proves. Every chunk is authenticated before it is written, so a
    // flipped ciphertext byte deep in the payload is refused.
    let fixture = fixture().await;
    let objects = fixture._store.path().join("o");
    for entry in std::fs::read_dir(&objects).expect("the object directory exists") {
        let path = entry.expect("a directory entry").path();
        let mut bytes = std::fs::read(&path).expect("readable");
        let at = bytes.len() / 2;
        bytes[at] ^= 0x80;
        std::fs::write(&path, &bytes).expect("overwritten");
    }

    let mut out = Vec::new();
    assert!(
        fixture
            .vault
            .stream_file_to("big.bin", &mut out)
            .await
            .is_err(),
        "a flipped ciphertext byte must not be served"
    );
    assert!(
        fixture.vault.verify_file("big.bin").await.is_err(),
        "and the same object must not verify"
    );
}

#[tokio::test]
async fn a_streamed_read_still_folds_the_footer() {
    // The check a windowed read very nearly dropped in silence. The footer is a
    // BLAKE3 over the object's own ciphertext, so it covers the one region no
    // chunk tag claims; flipping the last byte of the object leaves every chunk
    // tag valid and every plaintext byte correct. Without the fold, `dctl verify`
    // reported a corrupt object as healthy.
    let fixture = fixture().await;
    let objects = fixture._store.path().join("o");
    for entry in std::fs::read_dir(&objects).expect("the object directory exists") {
        let path = entry.expect("a directory entry").path();
        let mut bytes = std::fs::read(&path).expect("readable");
        if let Some(last) = bytes.last_mut() {
            *last ^= 0xFF;
        }
        std::fs::write(&path, &bytes).expect("overwritten");
    }

    assert!(
        fixture.vault.verify_file("big.bin").await.is_err(),
        "a flipped footer byte must fail verification"
    );
    let mut out = Vec::new();
    assert!(
        fixture
            .vault
            .stream_file_to("big.bin", &mut out)
            .await
            .is_err(),
        "and must fail a streamed read too"
    );
}

#[tokio::test]
async fn bytes_appended_past_the_last_chunk_are_caught() {
    // The one accidental corruption the footer's own hash does not reach either,
    // and the reason `verify_file` asks the provider how long the object really
    // is. Nothing here changes a byte the geometry accounts for, so every chunk
    // tag, the plaintext hash and the footer all still pass.
    let fixture = fixture().await;
    let objects = fixture._store.path().join("o");
    for entry in std::fs::read_dir(&objects).expect("the object directory exists") {
        let path = entry.expect("a directory entry").path();
        let mut bytes = std::fs::read(&path).expect("readable");
        bytes.extend_from_slice(b"appended by something else");
        std::fs::write(&path, &bytes).expect("overwritten");
    }

    let error = fixture
        .vault
        .verify_file("big.bin")
        .await
        .expect_err("an object longer than its geometry must not pass");
    assert!(
        format!("{error}").contains("geometry"),
        "the refusal must say what disagreed: {error}"
    );
}
