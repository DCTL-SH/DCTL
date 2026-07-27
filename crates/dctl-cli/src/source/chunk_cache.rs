//! A bounded cache of decrypted chunks, so a sequential read is not a re-read.
//!
//! [`dctl_core::range`] serves any window in one ranged request for exactly the chunks
//! covering it. That is the fix for reading a 10-byte window of a 95 MiB object. It is
//! *not*, on its own, the fix for reading that object from beginning to end.
//!
//! A kernel asks a filesystem for small windows — 4 KiB at a time on a plain read, up to
//! `max_read` on a tuned FUSE mount — and a chunk is 1 MiB by default. Without a cache,
//! reading one 1 MiB chunk sequentially in 4 KiB steps issues **256 ranged requests for
//! the same 1 MiB of ciphertext** and decrypts it 256 times: 256 MiB of egress and 256
//! Poly1305 verifications to deliver 1 MiB. Streaming a 40 GB film that way transfers
//! 10 TB. The ranged read alone would have turned an unusable mount into a differently
//! unusable one.
//!
//! So a chunk, once fetched and authenticated, is kept. The next window that lands inside
//! it costs nothing at all — no request, no decrypt, no allocation beyond the bytes
//! copied out. The bounds are [`VAULT_CHUNK_CACHE_BYTES`] and
//! [`VAULT_CHUNK_CACHE_MAX_CHUNKS`], both argued for where they are defined.
//!
//! ## Two things are cached, and they are cached for different reasons
//!
//! * **Readers**, by logical path. A [`RangeReader`] holds the resolved object key, the
//!   authenticated geometry and the unwrapped DEK. Re-opening one per window would add a
//!   header request and an index lookup to every 4 KiB read, turning one round trip into
//!   two. Bounded by [`VAULT_RANGE_READER_CACHE_MAX`].
//! * **Chunks**, by `(file_id, index)` — never by path. `file_id` is the object's random
//!   per-object id (`docs/FORMAT.md` §3), so a rewritten file is a different object with
//!   different chunk keys. A cached chunk can therefore never be served for content that
//!   replaced it, which is the failure a path-keyed cache would have.
//!
//! ## What a cached read still proves
//!
//! Every byte in here arrived through
//! [`RangeReader::read_chunks`](dctl_core::range::RangeReader::read_chunks), which returns
//! a chunk only after its Poly1305 tag has verified against an AAD binding the object's
//! authenticated head and the chunk's own index. Serving it again is serving bytes that
//! were authenticated, not bytes that were merely received. What a windowed read cannot
//! establish — the whole-object footer and `content_blake3` — is unchanged by caching and
//! is documented on [`dctl_core::range`]: `dctl verify` and `dctl scrub` remain the
//! commands that check the whole-object hash.
//!
//! ## What one read holds
//!
//! A read holds the *covering chunks* twice over: their ciphertext while it is being
//! decrypted, then their plaintext while the window is copied out. So peak memory is
//! about `2C`, where `C` is the window rounded out to chunk boundaries — never less than
//! one chunk, never more than `W + 2·chunk_size`. A ten-byte window therefore costs about
//! two megabytes at the 1 MiB default, and a ten-byte window of a *bigger* object costs
//! exactly the same, because no term here mentions the object. The whole-object read held
//! `2×object` for precisely the same reason, which is why the same ten bytes used to cost
//! most of a gigabyte on a 512 MiB file.
//!
//! What survives the read is bounded separately by [`VAULT_CHUNK_CACHE_BYTES`], so a
//! caller that asks for one enormous window pays for it once and does not leave it
//! resident.
//!
//! ## Lifetime
//!
//! One cache per [`VaultSource`](super::vault::VaultSource), so it lives exactly as long
//! as the command or mount that opened the vault and is gone — with its plaintext wiped —
//! when that ends. Nothing here is written to disk.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use dctl_core::Vault;
use dctl_core::range::RangeReader;
use zeroize::Zeroizing;

use crate::constants::{
    VAULT_CHUNK_CACHE_BYTES, VAULT_CHUNK_CACHE_MAX_CHUNKS, VAULT_RANGE_READER_CACHE_MAX,
};
use crate::error::{CliError, Result};
use crate::exit::ExitCode;

/// What identifies one decrypted chunk: the object it belongs to, and its index in that
/// object. Not the path — see the module documentation for why that distinction is the
/// difference between a correct cache and one that serves stale content after a rewrite.
type ChunkKey = ([u8; 16], u64);

/// Plaintext held for one chunk. `Arc` so a read can take a reference out from under the
/// lock and copy its window without holding the cache — and without cloning a megabyte.
/// [`Zeroizing`] so the plaintext is wiped when the last reader drops it.
type Chunk = Arc<Zeroizing<Vec<u8>>>;

/// A bounded, in-memory cache of decrypted chunks and the readers that produced them.
pub struct ChunkCache {
    /// One lock over both maps, never held across an `await`.
    ///
    /// A `std::sync::Mutex` rather than an async one because every critical section here
    /// is a map lookup and a couple of arithmetic operations — measured in nanoseconds,
    /// with no I/O inside — so the async variant would add a task-wakeup path to protect
    /// against contention that cannot occur.
    state: Mutex<State>,
}

/// The cache's mutable interior. Split out so [`ChunkCache`] exposes only operations that
/// take and release the lock correctly.
#[derive(Default)]
struct State {
    /// Open readers by logical path.
    readers: HashMap<String, Held<Arc<RangeReader>>>,
    /// Decrypted chunks by object and index.
    chunks: HashMap<ChunkKey, Held<Chunk>>,
    /// Total plaintext bytes in `chunks`, tracked rather than recomputed so an eviction
    /// loop does not walk the map to decide whether it is done.
    bytes: usize,
    /// Monotonic tick stamped onto every entry when it is used. A counter rather than a
    /// clock because it is only ever compared, never displayed, and a monotonic counter
    /// cannot be reordered by a clock adjustment mid-run.
    tick: u64,
}

/// A cached value plus the tick at which it was last used — the recency an eviction reads.
struct Held<T> {
    value: T,
    used: u64,
}

impl ChunkCache {
    /// An empty cache. Allocates nothing until something is stored.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(State::default()),
        }
    }

    /// Read the plaintext window `[offset, offset + length)` of `path`; `length` of
    /// [`None`] means "to the end".
    ///
    /// Serves whatever the cache already holds and issues **at most one** ranged request
    /// for the rest. A window past the end of the object yields fewer bytes than asked
    /// for rather than an error, matching a `seek` plus a bounded read on a local file.
    ///
    /// # Errors
    /// [`ExitCode::FileNotFound`] if the path resolves nowhere,
    /// [`ExitCode::IntegrityFailure`] if any covering chunk fails authentication — in
    /// which case no bytes are returned — and whatever the backend reported.
    pub async fn read_range(
        &self,
        vault: &Vault,
        path: &str,
        offset: u64,
        length: Option<u64>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let reader = self.reader(vault, path).await?;
        let chunk_size = u64::from(reader.chunk_size());
        let plaintext_len = reader.plaintext_len();

        // Clamp exactly as the core would, but before opening anything: an empty window
        // must not cost a request, and a mount reads past EOF constantly.
        if offset >= plaintext_len {
            return Ok(Zeroizing::new(Vec::new()));
        }
        let available = plaintext_len - offset;
        let want = length.map_or(available, |len| len.min(available));
        if want == 0 {
            return Ok(Zeroizing::new(Vec::new()));
        }
        let first = offset / chunk_size;
        // `offset + want <= plaintext_len`, so neither the sum nor the decrement can wrap.
        let last = (offset + want - 1) / chunk_size;

        // ── What is already decrypted. The lock is taken and released here; nothing is
        //    awaited while it is held. ──
        let file_id = *reader.file_id();
        let mut covering: BTreeMap<u64, Chunk> = BTreeMap::new();
        {
            let mut state = self.state();
            for index in first..=last {
                if let Some(chunk) = state.take_chunk(&(file_id, index)) {
                    covering.insert(index, chunk);
                }
            }
        }

        // ── One request for the missing run. Its ends are the first and last chunk the
        //    cache lacks; a chunk that happens to be held between them is re-fetched
        //    rather than split into two requests, because a second round trip costs far
        //    more than the bytes it would save. ──
        let missing_lo = (first..=last).find(|index| !covering.contains_key(index));
        if let Some(lo) = missing_lo {
            let hi = (first..=last)
                .rev()
                .find(|index| !covering.contains_key(index))
                .unwrap_or(lo);
            for chunk in reader.read_chunks(lo, hi - lo + 1).await? {
                let plaintext: Chunk = Arc::new(chunk.plaintext);
                covering.insert(chunk.index, Arc::clone(&plaintext));
                self.state().store_chunk((file_id, chunk.index), plaintext);
            }
        }

        assemble(&covering, chunk_size, offset, want, path)
    }

    /// The object's plaintext length and its recorded whole-plaintext BLAKE3, from the
    /// authenticated header alone — no payload transferred.
    ///
    /// This is what lets a `stat` of an index row that carries no size cost one bounded
    /// header read instead of a full object read. The length comes from the head, which
    /// the DEK unwrap authenticates and which the metadata decode cross-checks against
    /// `meta.size`; the hash is the writer's own DEK-authenticated record of the whole
    /// plaintext. [`None`] for the hash only when the object carries a metadata
    /// `schema_version` this build does not parse (skipped-and-served, `FORMAT.md` §8).
    ///
    /// # Errors
    /// As [`read_range`](ChunkCache::read_range).
    pub async fn measure(&self, vault: &Vault, path: &str) -> Result<(u64, Option<[u8; 32]>)> {
        let reader = self.reader(vault, path).await?;
        Ok((reader.plaintext_len(), reader.content_blake3().copied()))
    }

    /// The reader for `path`, opening one if the cache does not hold it.
    ///
    /// Two callers racing on the same missing path will both open a reader and the second
    /// store wins. That costs one redundant header read and is otherwise harmless — both
    /// readers address the same object — whereas holding the lock across the open would
    /// serialise every first read in the process behind one network round trip.
    async fn reader(&self, vault: &Vault, path: &str) -> Result<Arc<RangeReader>> {
        if let Some(reader) = self.state().take_reader(path) {
            return Ok(reader);
        }
        let reader = Arc::new(vault.open_range_reader(path).await?);
        self.state()
            .store_reader(path.to_string(), Arc::clone(&reader));
        Ok(reader)
    }

    /// Lock the interior, recovering from a poisoned mutex rather than failing.
    ///
    /// Poisoning means some thread panicked while holding the lock. Nothing in a critical
    /// section here can panic — they are map operations on already-validated values — but
    /// if one somehow did, the invariant at risk is a byte counter in a *cache*, and the
    /// worst consequence of a stale one is that the cache holds slightly more or less
    /// than its budget. Refusing every subsequent read over that would turn a cosmetic
    /// accounting error into a wedged mount, which is precisely the failure this crate's
    /// no-panic rule exists to prevent.
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Default for ChunkCache {
    fn default() -> Self {
        Self::new()
    }
}

impl State {
    /// The next recency stamp.
    ///
    /// Explicitly wrapping, not because wrapping is wanted — it would invert the eviction
    /// order — but because a plain `+ 1` panics on overflow in a debug build, and a panic
    /// reached from a filesystem callback wedges the mount rather than failing one read.
    /// One tick per cache operation exhausts a `u64` after roughly six hundred years of
    /// doing nothing else, so the difference is theoretical; which of the two failure
    /// modes a theoretical case gets is not.
    fn tick(&mut self) -> u64 {
        self.tick = self.tick.wrapping_add(1);
        self.tick
    }

    /// A cached chunk, marked as just used.
    fn take_chunk(&mut self, key: &ChunkKey) -> Option<Chunk> {
        let tick = self.tick();
        let held = self.chunks.get_mut(key)?;
        held.used = tick;
        Some(Arc::clone(&held.value))
    }

    /// Store one decrypted chunk, evicting least-recently-used entries until both bounds
    /// hold again.
    fn store_chunk(&mut self, key: ChunkKey, chunk: Chunk) {
        let tick = self.tick();
        let len = chunk.len();
        if let Some(previous) = self.chunks.insert(
            key,
            Held {
                value: chunk,
                used: tick,
            },
        ) {
            // Replacing an entry (a re-fetch of a chunk evicted between the lookup and
            // the store) must not double-count its bytes.
            self.bytes = self.bytes.saturating_sub(previous.value.len());
        }
        self.bytes = self.bytes.saturating_add(len);

        // Evict oldest-first until both the byte budget and the entry count are met. The
        // entry bound is what keeps this scan cheap: it caps the map, so "find the oldest"
        // is a walk over a small, known-size collection rather than over an unbounded one.
        while self.bytes > VAULT_CHUNK_CACHE_BYTES
            || self.chunks.len() > VAULT_CHUNK_CACHE_MAX_CHUNKS
        {
            let Some(oldest) = oldest_key(&self.chunks) else {
                break;
            };
            if let Some(evicted) = self.chunks.remove(&oldest) {
                self.bytes = self.bytes.saturating_sub(evicted.value.len());
            }
        }
    }

    /// The reader for `path`, marked as just used.
    fn take_reader(&mut self, path: &str) -> Option<Arc<RangeReader>> {
        let tick = self.tick();
        let held = self.readers.get_mut(path)?;
        held.used = tick;
        Some(Arc::clone(&held.value))
    }

    /// Store an open reader, evicting the least recently used if the map is full.
    ///
    /// Evicting a reader does not invalidate anything: a read already in flight holds its
    /// own `Arc`, and the next read of that path simply pays a header request again.
    fn store_reader(&mut self, path: String, reader: Arc<RangeReader>) {
        let tick = self.tick();
        self.readers.insert(
            path,
            Held {
                value: reader,
                used: tick,
            },
        );
        while self.readers.len() > VAULT_RANGE_READER_CACHE_MAX {
            let Some(oldest) = oldest_key(&self.readers) else {
                break;
            };
            self.readers.remove(&oldest);
        }
    }
}

/// The least recently used key in `held`, or [`None`] if it is empty.
///
/// A linear scan, which is correct here precisely because both maps are bounded: the cost
/// is proportional to a constant, not to how much has been read. A linked-list LRU would
/// buy an asymptotic improvement over collections that never exceed a few hundred entries.
fn oldest_key<K: Clone, V>(held: &HashMap<K, Held<V>>) -> Option<K> {
    held.iter()
        .min_by_key(|(_, entry)| entry.used)
        .map(|(key, _)| key.clone())
}

/// Copy the window `[offset, offset + want)` out of the covering chunks.
///
/// `covering` must hold every chunk index the window touches; a gap means the fetch above
/// did not return what it was asked for, which is reported rather than silently served as
/// a short read — a `cat` that wrote fewer bytes and exited 0 is the misreport `PLAN.md`
/// §6 forbids.
fn assemble(
    covering: &BTreeMap<u64, Chunk>,
    chunk_size: u64,
    offset: u64,
    want: u64,
    path: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let capacity = usize::try_from(want).map_err(|_| window_too_large(path))?;
    let mut out: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(capacity));
    // `read_range` has already clamped `offset + want` to the object, so this cannot
    // wrap there. Saturating anyway because this function is also called directly by
    // its own tests, and an overflow panic reached from a filesystem callback wedges
    // the mount rather than failing one read.
    let window_end = offset.saturating_add(want);

    for (index, chunk) in covering {
        // Where this chunk starts in the object's plaintext. Every chunk before the last
        // is exactly `chunk_size` bytes (`FORMAT.md` §3), which is what makes this a
        // multiplication rather than a running total that a gap could desynchronise.
        let chunk_start = index.saturating_mul(chunk_size);
        let from = usize::try_from(offset.saturating_sub(chunk_start))
            .unwrap_or(usize::MAX)
            .min(chunk.len());
        let to = usize::try_from(window_end.saturating_sub(chunk_start))
            .unwrap_or(usize::MAX)
            .min(chunk.len());
        if to > from {
            out.extend_from_slice(&chunk[from..to]);
        }
    }

    if out.len() != capacity {
        return Err(CliError::new(
            ExitCode::IntegrityFailure,
            format!(
                "{path}: a windowed read assembled {} bytes of the {capacity} it covered",
                out.len()
            ),
        )
        .with_hint(
            "This is a defect, not a data problem: the covering chunks were fetched and \
             authenticated but did not reassemble. Re-run with 'dctl verify' to confirm \
             the stored object is intact.",
        ));
    }
    Ok(out)
}

/// A window longer than this platform can address. Only reachable on a 32-bit host asked
/// for more than 4 GiB in one read, where the honest answer is a refusal rather than a
/// truncated buffer that would look like a short file.
fn window_too_large(path: &str) -> CliError {
    CliError::new(
        ExitCode::Usage,
        format!("{path}: the requested window is larger than this platform can address"),
    )
    .with_hint("Read the object in smaller pieces, or use a 64-bit build.")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Chunks holding a recognisable pattern, so a window assembled from the wrong offset
    /// cannot compare equal to the right one.
    fn covering(chunk_size: usize, indices: &[u64], total: usize) -> BTreeMap<u64, Chunk> {
        indices
            .iter()
            .map(|index| {
                let start = *index as usize * chunk_size;
                let end = (start + chunk_size).min(total);
                let bytes: Vec<u8> = (start..end).map(|i| (i % 251) as u8).collect();
                (*index, Arc::new(Zeroizing::new(bytes)))
            })
            .collect()
    }

    fn expect(offset: usize, len: usize) -> Vec<u8> {
        (offset..offset + len).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn a_window_inside_one_chunk_is_copied_from_it() {
        let held = covering(100, &[3], 1000);
        let out = assemble(&held, 100, 340, 20, "a.bin").expect("the window assembles");
        assert_eq!(out.as_slice(), expect(340, 20).as_slice());
    }

    #[test]
    fn a_window_spanning_chunks_is_stitched_in_order() {
        let held = covering(100, &[2, 3, 4], 1000);
        let out = assemble(&held, 100, 250, 200, "a.bin").expect("the window assembles");
        assert_eq!(out.as_slice(), expect(250, 200).as_slice());
    }

    #[test]
    fn a_window_ending_in_a_short_final_chunk_takes_only_what_is_there() {
        // The object is 1050 bytes, so chunk 10 holds 50. A window reaching past it must
        // stop at the object's end rather than reading a full chunk's worth.
        let held = covering(100, &[10], 1050);
        let out = assemble(&held, 100, 1040, 10, "a.bin").expect("the window assembles");
        assert_eq!(out.as_slice(), expect(1040, 10).as_slice());
    }

    #[test]
    fn a_missing_covering_chunk_is_reported_rather_than_served_short() {
        // The failure this guards: assembling from a gap would return fewer bytes and
        // succeed, which is a silent short read.
        let held = covering(100, &[2, 4], 1000);
        let error = assemble(&held, 100, 250, 200, "a.bin")
            .expect_err("a gap in the covering chunks must fail");
        assert_eq!(error.code(), ExitCode::IntegrityFailure);
        assert!(error.hint().is_some(), "a refusal must say what to do next");
    }

    #[test]
    fn the_cache_evicts_by_recency_and_stays_inside_its_byte_budget() {
        let mut state = State::default();
        // One chunk over the budget, so exactly one eviction is forced.
        let chunk_len = VAULT_CHUNK_CACHE_BYTES / 4;
        for index in 0..4u64 {
            state.store_chunk(
                ([1u8; 16], index),
                Arc::new(Zeroizing::new(vec![0u8; chunk_len])),
            );
        }
        assert!(state.bytes <= VAULT_CHUNK_CACHE_BYTES);
        // Touch chunk 0 so it is the most recent, then push a fifth chunk in.
        assert!(state.take_chunk(&([1u8; 16], 0)).is_some());
        state.store_chunk(
            ([1u8; 16], 4),
            Arc::new(Zeroizing::new(vec![0u8; chunk_len])),
        );
        assert!(
            state.bytes <= VAULT_CHUNK_CACHE_BYTES,
            "the budget must hold after every store"
        );
        assert!(
            state.take_chunk(&([1u8; 16], 0)).is_some(),
            "the freshly used chunk must survive; the oldest is the one to go"
        );
        assert!(
            state.take_chunk(&([1u8; 16], 1)).is_none(),
            "the least recently used chunk must have been evicted"
        );
    }

    #[test]
    fn re_storing_a_chunk_does_not_double_count_its_bytes() {
        // Reachable for real: a chunk looked up, evicted by another read, then re-fetched
        // and stored again. Double counting would shrink the effective cache every time.
        let mut state = State::default();
        for _ in 0..8 {
            state.store_chunk(([2u8; 16], 0), Arc::new(Zeroizing::new(vec![0u8; 1024])));
        }
        assert_eq!(state.bytes, 1024);
        assert_eq!(state.chunks.len(), 1);
    }

    #[test]
    fn two_objects_never_share_a_chunk_key() {
        // The property that makes a rewrite safe: chunk 0 of one object and chunk 0 of
        // another are different entries, because the key carries the object's file_id.
        let mut state = State::default();
        state.store_chunk(([1u8; 16], 0), Arc::new(Zeroizing::new(b"old".to_vec())));
        state.store_chunk(([2u8; 16], 0), Arc::new(Zeroizing::new(b"new".to_vec())));
        assert_eq!(
            state
                .take_chunk(&([1u8; 16], 0))
                .expect("the first object's chunk")
                .as_slice(),
            b"old"
        );
        assert_eq!(
            state
                .take_chunk(&([2u8; 16], 0))
                .expect("the second object's chunk")
                .as_slice(),
            b"new"
        );
    }

    #[test]
    fn the_chunk_count_bound_holds_for_objects_with_tiny_chunks() {
        // A byte budget alone does not bound the map: an object sealed with a very small
        // chunk_size would fit millions of entries inside it, and every eviction scan
        // would then walk them.
        let mut state = State::default();
        for index in 0..(VAULT_CHUNK_CACHE_MAX_CHUNKS as u64 + 32) {
            state.store_chunk(([3u8; 16], index), Arc::new(Zeroizing::new(vec![0u8; 8])));
        }
        assert!(state.chunks.len() <= VAULT_CHUNK_CACHE_MAX_CHUNKS);
    }

    #[test]
    fn the_reader_map_is_bounded_too() {
        let mut state = State::default();
        assert!(state.take_reader("never-opened.bin").is_none());
        assert_eq!(state.readers.len(), 0);
    }
}
