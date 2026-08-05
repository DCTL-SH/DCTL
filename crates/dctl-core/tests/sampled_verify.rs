//! What a sampled verify proves, what it costs, and what it honestly cannot see.
//!
//! Four claims, each pinned because each is the contract:
//!
//! * **The asymmetry IS the contract.** A corrupt chunk outside the sample
//!   passes a sampled verify and fails a strict one. If the sampled call ever
//!   starts failing on un-sampled damage, it has secretly become a full read —
//!   the exact misrepresentation `--verify sample` shipped with for a release —
//!   and the first test here goes red.
//! * **The sample is cheaper, measurably.** Fewer ranged reads than strict, or
//!   the mode's entire reason to exist is gone.
//! * **Head and tail are never left to chance.** Truncation and torn uploads
//!   concentrate at the seams, so corrupting the first chunk fails a sampled
//!   verify under any seed.
//! * **No whole-object claim is smuggled in.** A corrupted footer — the
//!   whole-object statement's home — is invisible to a sample, deliberately.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use bytes::Bytes;
use dctl_core::{MIN_CHUNK_SIZE, Modified, SamplePlan, Vault, sample_indices};
use dctl_store::{
    Backend, ByteRange, ChecksumSupport, ContentHash, IncompleteUpload, IncompleteUploads, LocalFs,
    ObjectKey, ObjectMeta, Page, PutOutcome, SourceModified, StagingListing, StoreIdentity,
    StoredChecksum,
};
use tempfile::TempDir;

/// A real [`LocalFs`], with its ranged reads counted.
struct Counting {
    inner: LocalFs,
    get_ranges: AtomicU64,
}

impl Counting {
    fn new(root: &Path) -> Self {
        Self {
            inner: LocalFs::new(root.to_path_buf()),
            get_ranges: AtomicU64::new(0),
        }
    }

    fn get_ranges(&self) -> u64 {
        self.get_ranges.load(Ordering::SeqCst)
    }

    fn reset(&self) {
        self.get_ranges.store(0, Ordering::SeqCst);
    }
}

#[async_trait]
impl Backend for Counting {
    fn name(&self) -> &'static str {
        self.inner.name()
    }
    async fn store_identity(&self) -> dctl_store::Result<Option<StoreIdentity>> {
        self.inner.store_identity().await
    }
    fn checksum_support(&self) -> ChecksumSupport {
        self.inner.checksum_support()
    }
    async fn stored_checksum(&self, key: &ObjectKey) -> dctl_store::Result<StoredChecksum> {
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
    async fn put_stream(
        &self,
        key: &ObjectKey,
        source: dctl_store::ObjectStream,
        modified: SourceModified,
    ) -> dctl_store::Result<PutOutcome> {
        self.inner.put_stream(key, source, modified).await
    }
    async fn get(&self, key: &ObjectKey) -> dctl_store::Result<Bytes> {
        self.inner.get(key).await
    }
    async fn get_range(&self, key: &ObjectKey, range: ByteRange) -> dctl_store::Result<Bytes> {
        self.get_ranges.fetch_add(1, Ordering::SeqCst);
        self.inner.get_range(key, range).await
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
    async fn list_incomplete_uploads(
        &self,
        prefix: &str,
        cursor: Option<String>,
    ) -> dctl_store::Result<IncompleteUploads> {
        self.inner.list_incomplete_uploads(prefix, cursor).await
    }
    async fn abort_incomplete_upload(&self, upload: &IncompleteUpload) -> dctl_store::Result<()> {
        self.inner.abort_incomplete_upload(upload).await
    }
}

const CHUNKS: u64 = 65;
const CHUNK: u64 = MIN_CHUNK_SIZE as u64;
/// 64 full chunks and a 17-byte tail, so the last chunk is genuinely short.
const PLAINTEXT: u64 = 64 * CHUNK + 17;
/// Poly1305 tag per chunk.
const TAG: u64 = 16;
/// §3 trailing footer.
const FOOTER: u64 = 32;

struct Fixture {
    _store: TempDir,
    _index: TempDir,
    vault: Vault,
    watched: Arc<Counting>,
    store_root: PathBuf,
}

async fn fixture() -> Fixture {
    let store = TempDir::new().expect("a temporary store");
    let index = TempDir::new().expect("a temporary index");
    let watched = Arc::new(Counting::new(store.path()));
    let backend: Arc<dyn Backend> = Arc::clone(&watched) as Arc<dyn Backend>;
    let index_path = index.path().join("index.redb");

    let vault = Vault::init(Arc::clone(&backend), &index_path, "pw")
        .await
        .expect("a fresh vault initialises")
        .vault
        .with_chunk_size(Some(CHUNK));

    // A pattern, so a wrong byte names its offset.
    let plaintext: Vec<u8> = (0..PLAINTEXT as usize).map(|i| (i % 251) as u8).collect();
    let source = index.path().join("source.bin");
    std::fs::write(&source, &plaintext).expect("a source file");
    vault
        .put_file_from_path("big.bin", &source, Modified::At(1_700_000_000))
        .await
        .expect("the object stores");
    watched.reset();

    let store_root = store.path().to_path_buf();
    Fixture {
        _store: store,
        _index: index,
        vault,
        watched,
        store_root,
    }
}

/// The stored object's file on disk — the largest file under the store, which
/// on this fixture is unambiguous: one sealed object plus tiny system records.
fn object_file(root: &Path) -> PathBuf {
    let mut best: Option<(u64, PathBuf)> = None;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("the store lists") {
            let entry = entry.expect("a store entry");
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                let len = entry.metadata().expect("metadata").len();
                if best.as_ref().is_none_or(|(b, _)| len > *b) {
                    best = Some((len, path));
                }
            }
        }
    }
    best.expect("the store holds the object").1
}

/// Flip one ciphertext byte inside chunk `index` of the stored object.
fn corrupt_chunk(root: &Path, index: u64) {
    let path = object_file(root);
    let mut bytes = std::fs::read(&path).expect("the object reads");
    let payload = bytes.len() as u64 - FOOTER - (PLAINTEXT + TAG * CHUNKS);
    let at = (payload + index * (CHUNK + TAG) + 7) as usize;
    bytes[at] ^= 0x01;
    std::fs::write(&path, &bytes).expect("the corruption lands");
}

#[tokio::test]
async fn damage_outside_the_sample_passes_sampled_and_fails_strict() {
    // The asymmetry that IS the honest contract. If this goes red because the
    // sampled call caught the un-sampled chunk, sampling has silently become
    // a full read again — the misrepresentation this mode existed to end.
    let fx = fixture().await;
    let plan = SamplePlan {
        samples: 2,
        seed: 42,
    };

    // Compute the picks the run will make, and corrupt a chunk it will skip.
    let reader = fx
        .vault
        .open_range_reader("big.bin")
        .await
        .expect("the object opens");
    let picks = sample_indices(plan.seed, reader.file_id(), CHUNKS, plan.samples);
    drop(reader);
    let victim = (1..CHUNKS - 1)
        .find(|index| !picks.contains(index))
        .expect("a 65-chunk object always has an unsampled interior chunk");
    corrupt_chunk(&fx.store_root, victim);

    let sampled = fx
        .vault
        .verify_file_sampled("big.bin", &plan)
        .await
        .expect("damage outside the sample is invisible to a sample");
    assert_eq!(sampled.chunks_total, CHUNKS);
    assert!(
        sampled.chunks_read < CHUNKS,
        "a sample that read the whole object is not a sample"
    );

    fx.vault
        .verify_file("big.bin")
        .await
        .expect_err("the strict verify is the one that must catch it");
}

#[tokio::test]
async fn a_sample_costs_measurably_fewer_reads_than_strict() {
    let fx = fixture().await;

    fx.watched.reset();
    fx.vault
        .verify_file_sampled(
            "big.bin",
            &SamplePlan {
                samples: 2,
                seed: 7,
            },
        )
        .await
        .expect("a clean object samples clean");
    let sampled = fx.watched.get_ranges();

    fx.watched.reset();
    fx.vault
        .verify_file("big.bin")
        .await
        .expect("a clean object verifies clean");
    let strict = fx.watched.get_ranges();

    assert!(
        sampled < strict,
        "a sampled verify issued {sampled} ranged reads against strict's \
         {strict}; the sample must be cheaper or it is a lie about cost"
    );
    // Header probe + at most (2 mandatory + 2 sampled) runs. A small, stated
    // ceiling rather than an exact count, so window churn cannot flake it.
    assert!(
        sampled <= 6,
        "a 2-sample verify issued {sampled} ranged reads; the cost must be \
         proportional to the sample, not the object"
    );
}

#[tokio::test]
async fn the_seams_are_always_read() {
    // Chunk 0 is in every sample; corrupting it must fail a sampled verify
    // under any seed — the seams are not left to chance.
    let fx = fixture().await;
    corrupt_chunk(&fx.store_root, 0);
    for seed in [1u64, 99, 4_242] {
        fx.vault
            .verify_file_sampled("big.bin", &SamplePlan { samples: 1, seed })
            .await
            .expect_err("the first chunk is mandatory in every sample");
    }
}

#[tokio::test]
async fn a_sample_makes_no_whole_object_claim() {
    // The footer holds the whole-object statement, and no subset of chunks can
    // evaluate it. A sampled verify must not pretend otherwise — not even by
    // fetching the footer and comparing nothing.
    let fx = fixture().await;
    let path = object_file(&fx.store_root);
    let mut bytes = std::fs::read(&path).expect("the object reads");
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    std::fs::write(&path, &bytes).expect("the corruption lands");

    fx.vault
        .verify_file_sampled(
            "big.bin",
            &SamplePlan {
                samples: 4,
                seed: 5,
            },
        )
        .await
        .expect("a footer is outside any sample's claim");
    fx.vault
        .verify_file("big.bin")
        .await
        .expect_err("the whole-object statement belongs to strict");
}
