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
//! ## Chunks can also arrive before they are asked for
//!
//! Caching turns a re-read into nothing; it does not turn the *first* read of a chunk into
//! nothing, and on a network filesystem that first read is a provider round trip a video
//! player waits out. [`ChunkCache::warm`] is the other half: a caller that knows where a
//! reader is going — a mount serving a sequential read — can have the next chunks fetched
//! and authenticated while the current one is being consumed, which is [the plan](https://doc.dctl.sh/project/plan) §15's
//! "serve chunk *k* while fetching *k+1…k+P*". It lands in the same bounded cache, so
//! read-ahead cannot grow memory beyond what a read already could.
//!
//! ## Two things are cached, and they are cached for different reasons
//!
//! * **Readers**, by logical path. A [`RangeReader`] holds the resolved object key, the
//!   authenticated geometry and the unwrapped DEK. Re-opening one per window would add a
//!   header request and an index lookup to every 4 KiB read, turning one round trip into
//!   two. Bounded by [`VAULT_RANGE_READER_CACHE_MAX`].
//! * **Chunks**, by `(file_id, index)` — never by path. `file_id` is the object's random
//!   per-object id (`crates/dctl-decode/FORMAT.md` §3), so a rewritten file is a different object with
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
use tokio::sync::Notify;
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
struct State {
    /// Open readers by logical path.
    readers: HashMap<String, Held<Arc<RangeReader>>>,
    /// Decrypted chunks by object and index.
    chunks: HashMap<ChunkKey, Held<Chunk>>,
    /// Chunks a task is fetching right now, so a second task wanting one waits for
    /// the flight instead of fetching it again.
    ///
    /// This is what makes read-ahead and a fast reader cooperate rather than race:
    /// without it, a reader that catches up to the warm task's window re-fetches the
    /// very bytes already on the wire — a duplicate transfer issued precisely when
    /// the link is slowest. An entry is inserted only by the task that will fetch,
    /// and removed — with its waiters notified — when that fetch resolves, by a
    /// guard that runs on success, on error and on cancellation alike, so nothing
    /// waits on a flight that no longer exists.
    in_flight: HashMap<ChunkKey, Arc<Notify>>,
    /// Total plaintext bytes in `chunks`, tracked rather than recomputed so an eviction
    /// loop does not walk the map to decide whether it is done.
    bytes: usize,
    /// The byte bound eviction enforces. Starts at [`VAULT_CHUNK_CACHE_BYTES`] and is
    /// raised — never lowered — by [`ChunkCache::set_budget`], because the useful
    /// working set is the caller's to know: a mount warming `depth` windows ahead
    /// needs the cache to hold what it warmed, or read-ahead evicts the very chunks
    /// the reader is about to ask for and the warm becomes wasted egress.
    budget_bytes: usize,
    /// The entry-count bound beside it, kept proportional so the linear eviction scan
    /// stays a walk over a small collection whatever the chunk size.
    budget_chunks: usize,
    /// Monotonic tick stamped onto every entry when it is used. A counter rather than a
    /// clock because it is only ever compared, never displayed, and a monotonic counter
    /// cannot be reordered by a clock adjustment mid-run.
    tick: u64,
}

impl Default for State {
    fn default() -> Self {
        Self {
            readers: HashMap::new(),
            chunks: HashMap::new(),
            in_flight: HashMap::new(),
            bytes: 0,
            budget_bytes: VAULT_CHUNK_CACHE_BYTES,
            budget_chunks: VAULT_CHUNK_CACHE_MAX_CHUNKS,
            tick: 0,
        }
    }
}

/// A cached value plus the tick at which it was last used — the recency an eviction reads.
struct Held<T> {
    value: T,
    used: u64,
}

/// What [`ChunkCache::partition`] found for the chunks a window still lacks: either a
/// claim this task must now fetch, or flights other tasks already own.
enum Work<'cache> {
    /// Chunks nobody was fetching. The guard holds the claim; fetching them is now
    /// this task's obligation, discharged through [`ChunkCache::fetch_claimed`].
    Fetch(FlightGuard<'cache>),
    /// Every missing chunk is already on somebody's wire. Wait for these flights,
    /// then look again.
    Wait(Vec<(u64, Arc<Notify>)>),
}

/// A claim on in-flight chunks, resolved on drop.
///
/// Removal-and-notify lives in `Drop` rather than after the fetch so that every exit —
/// the stored chunk, the propagated error, and a cancelled task — resolves the flight.
/// A marker that outlived its fetch would make every later read of that chunk wait on
/// a wakeup that can never come, which is a wedged mount with no error anywhere.
struct FlightGuard<'cache> {
    cache: &'cache ChunkCache,
    file_id: [u8; 16],
    /// Ascending, as `partition` builds it — which is what lets the fetch walk it as
    /// contiguous runs without sorting.
    indexes: Vec<u64>,
}

impl Drop for FlightGuard<'_> {
    fn drop(&mut self) {
        let mut state = self.cache.state();
        for index in &self.indexes {
            // Only the claimer inserts a marker for a chunk, and only its guard removes
            // it, so this key is ours by construction.
            if let Some(flight) = state.in_flight.remove(&(self.file_id, *index)) {
                flight.notify_waiters();
            }
        }
    }
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

        // ── Assemble the covering set in rounds. Each round takes what the cache
        //    holds, then either fetches the chunks nobody has claimed or waits for the
        //    flights that already carry them — never both fetching and waiting in one
        //    round, and never fetching a byte that is already on the wire. One round
        //    is the ordinary case; a second happens only when a flight this read
        //    waited on resolved without leaving its chunk behind (its fetch failed,
        //    or the budget evicted the chunk before this read looked), and then the
        //    next round claims the chunk itself and meets the bytes — or the error —
        //    first-hand. Each round removes at least one chunk from the missing set
        //    or waits on a flight that must resolve, so the loop terminates. ──
        let file_id = *reader.file_id();
        let mut covering: BTreeMap<u64, Chunk> = BTreeMap::new();
        while let Some(work) = self.partition(file_id, first, last, &mut covering) {
            match work {
                Work::Fetch(guard) => {
                    for (index, chunk) in self.fetch_claimed(&reader, &guard).await? {
                        covering.insert(index, chunk);
                    }
                }
                Work::Wait(flights) => {
                    for (index, flight) in flights {
                        // Register interest before re-checking the flight, so a
                        // resolution landing between the check and the await cannot
                        // be missed — an unregistered waiter would sleep forever.
                        let notified = flight.notified();
                        tokio::pin!(notified);
                        notified.as_mut().enable();
                        if self.flight_is_current(&(file_id, index), &flight) {
                            notified.await;
                        }
                    }
                }
            }
        }

        assemble(&covering, chunk_size, offset, want, path)
    }

    /// Fetch, authenticate and retain the chunks covering `[offset, offset + length)`
    /// **without assembling a window**.
    ///
    /// The read-ahead a mount performs between reads: a player streaming a film asks for
    /// chunk *k*, and by the time it asks for *k+1* the provider round trip for it has
    /// already happened. [The plan](https://doc.dctl.sh/project/plan) §15 names this as the thing that makes a streaming mount
    /// feel local, because on a network filesystem the cost is latency rather than
    /// decryption — ChaCha20-Poly1305 pushes multiple gigabytes a second and a provider
    /// does not.
    ///
    /// Distinct from `read_range` in the one way that matters here: it never allocates the
    /// window. Warming sixteen megabytes through `read_range` would build a sixteen-megabyte
    /// plaintext buffer and immediately drop it, which is a copy of everything the mount is
    /// about to serve — so this stops at the cache, where the chunks are what a later read
    /// wants anyway.
    ///
    /// **Advisory, and therefore silent.** A failure here is not a failure of anything the
    /// caller asked for: nothing has been promised to a reader, and the read that follows
    /// will meet the same error and report it properly, with a path and an errno. Returning
    /// a `Result` nobody could act on would only invite a caller to surface a warning about
    /// a request the user never made. What it does instead is leave a debug record, which is
    /// where a "why is this mount slow" investigation looks.
    pub async fn warm(&self, vault: &Vault, path: &str, offset: u64, length: u64) {
        if length == 0 {
            return;
        }
        let Ok(reader) = self.reader(vault, path).await else {
            // The object could not be opened at all. The read that follows will say so.
            return;
        };
        let chunk_size = u64::from(reader.chunk_size());
        let plaintext_len = reader.plaintext_len();
        if offset >= plaintext_len {
            return;
        }

        let want = length.min(plaintext_len - offset);
        if want == 0 {
            return;
        }
        let first = offset / chunk_size;
        let last = (offset + want - 1) / chunk_size;

        // Only the chunks that are missing, that nobody else is fetching, and only the
        // runs of them: a chunk already held is exactly what read-ahead was trying to
        // achieve, and one already in flight is read-ahead (or a reader) at work —
        // waiting on it would make the advisory path block, and re-fetching it would
        // make a warm cache cost more than a cold one. So warming claims what it can
        // and otherwise walks away.
        let file_id = *reader.file_id();
        let guard = {
            let mut state = self.state();
            let mut claimed = Vec::new();
            for index in first..=last {
                if state.chunks.contains_key(&(file_id, index))
                    || state.in_flight.contains_key(&(file_id, index))
                {
                    continue;
                }
                state
                    .in_flight
                    .insert((file_id, index), Arc::new(Notify::new()));
                claimed.push(index);
            }
            FlightGuard {
                cache: self,
                file_id,
                indexes: claimed,
            }
        };
        if guard.indexes.is_empty() {
            // Everything the window covers is decrypted or arriving. Nothing to do,
            // and nothing to report: this is read-ahead working.
            return;
        }

        match self.fetch_claimed(&reader, &guard).await {
            Ok(fetched) => {
                tracing::debug!(
                    { crate::logging::fields::PATH } = path,
                    offset,
                    chunks = fetched.len(),
                    "read-ahead warmed the chunk cache"
                );
            }
            Err(error) => {
                // Deliberately not propagated — see the note above. The read that needs
                // these bytes will fetch them again and fail visibly.
                // `CliError`'s `Display` is the message, and is what every other
                // diagnostic in this crate renders.
                tracing::debug!(
                    { crate::logging::fields::PATH } = path,
                    offset,
                    "read-ahead did not complete: {error}"
                );
            }
        }
    }

    /// Raise the cache's byte and entry budgets to fit a caller's working set.
    ///
    /// Raise, never lower: the defaults are the floor argued at
    /// [`VAULT_CHUNK_CACHE_BYTES`], and shrinking a cache mid-run would evict a
    /// working set some reader is mid-way through. The caller that knows better is
    /// the mount: warming `depth` read-ahead windows is only useful if the cache can
    /// hold `depth + 1` of them — the windows arriving plus the one being consumed —
    /// otherwise read-ahead evicts what the reader is about to ask for, and every
    /// warmed byte is fetched twice.
    pub fn set_budget(&self, bytes: usize, max_chunks: usize) {
        let mut state = self.state();
        state.budget_bytes = bytes.max(VAULT_CHUNK_CACHE_BYTES);
        state.budget_chunks = max_chunks.max(VAULT_CHUNK_CACHE_MAX_CHUNKS);
    }

    /// One round of [`read_range`](ChunkCache::read_range)'s assembly: take what the
    /// cache holds into `covering`, and say what to do about the rest.
    ///
    /// [`None`] when `covering` is complete. Otherwise a claim to fetch — taking
    /// priority so a task that can make progress does — or, when every missing chunk
    /// is on somebody's wire, the flights to wait for.
    fn partition<'cache>(
        &'cache self,
        file_id: [u8; 16],
        first: u64,
        last: u64,
        covering: &mut BTreeMap<u64, Chunk>,
    ) -> Option<Work<'cache>> {
        let mut state = self.state();
        let mut claimed = Vec::new();
        let mut flights = Vec::new();
        for index in first..=last {
            if covering.contains_key(&index) {
                continue;
            }
            if let Some(chunk) = state.take_chunk(&(file_id, index)) {
                covering.insert(index, chunk);
            } else if let Some(flight) = state.in_flight.get(&(file_id, index)) {
                flights.push((index, Arc::clone(flight)));
            } else {
                state
                    .in_flight
                    .insert((file_id, index), Arc::new(Notify::new()));
                claimed.push(index);
            }
        }
        drop(state);

        if !claimed.is_empty() {
            // Flights found alongside a claim are deliberately dropped: fetching what
            // this round claimed comes first, and the next round will find those
            // chunks cached — or their flights still current, and wait then.
            return Some(Work::Fetch(FlightGuard {
                cache: self,
                file_id,
                indexes: claimed,
            }));
        }
        if !flights.is_empty() {
            return Some(Work::Wait(flights));
        }
        None
    }

    /// Fetch, authenticate and cache the claimed chunks, as contiguous runs.
    ///
    /// One ranged request per run. A claim is usually one run; it splits only where a
    /// chunk mid-window was cached or in flight when the claim was made, and the
    /// requests on either side of it are the round trips that were genuinely owed.
    ///
    /// # Errors
    /// Whatever [`RangeReader::read_chunks`] reported for the run that failed; runs
    /// fetched before it are already cached and stay.
    async fn fetch_claimed(
        &self,
        reader: &RangeReader,
        guard: &FlightGuard<'_>,
    ) -> Result<Vec<(u64, Chunk)>> {
        let mut fetched = Vec::with_capacity(guard.indexes.len());
        let mut runs: Vec<(u64, u64)> = Vec::new();
        for &index in &guard.indexes {
            match runs.last_mut() {
                Some((lo, count)) if lo.saturating_add(*count) == index => *count += 1,
                _ => runs.push((index, 1)),
            }
        }
        for (lo, count) in runs {
            for chunk in reader.read_chunks(lo, count).await? {
                let plaintext: Chunk = Arc::new(chunk.plaintext);
                self.state()
                    .store_chunk((guard.file_id, chunk.index), Arc::clone(&plaintext));
                fetched.push((chunk.index, plaintext));
            }
        }
        Ok(fetched)
    }

    /// Whether `flight` is still the marker for `key` — the same allocation, not
    /// merely a marker under the same key, so a resolved-and-reclaimed chunk is not
    /// mistaken for one still on its first flight.
    fn flight_is_current(&self, key: &ChunkKey, flight: &Arc<Notify>) -> bool {
        self.state()
            .in_flight
            .get(key)
            .is_some_and(|current| Arc::ptr_eq(current, flight))
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

    /// The reader for `path`, opening one if the cache does not hold one that
    /// still addresses the object that path currently names.
    ///
    /// **The identity check is not optional.** A reader holds a resolved object
    /// key, its authenticated geometry and its unwrapped DEK, and this cache is
    /// keyed by *path* — so after a rewrite the same path names a different
    /// object while the cached reader still addresses the old one. Measured
    /// against a live B2 vault: a file replaced through the CLI was served
    /// through an open mount as the **old bytes under the new size**, because
    /// `getattr` reads the length from the index while the read came from the
    /// superseded object. That is a corrupt read, not a stale one, and it is
    /// precisely the failure this module's own documentation says a path-keyed
    /// cache would have — the chunk map avoids it by keying on `file_id`, and
    /// the reader map has to earn the same property by asking.
    ///
    /// The question is answered by the local index, so it costs no round trip:
    /// one keyed lookup against redb, against the header read and DEK unwrap a
    /// re-open would cost. A path that has vanished falls through to the open,
    /// which reports the absence properly.
    ///
    /// Two callers racing on the same missing path will both open a reader and the second
    /// store wins. That costs one redundant header read and is otherwise harmless — both
    /// readers address the same object — whereas holding the lock across the open would
    /// serialise every first read in the process behind one network round trip.
    async fn reader(&self, vault: &Vault, path: &str) -> Result<Arc<RangeReader>> {
        // Bound first, so the lock guard is released before the await below:
        // this mutex is never held across one.
        let cached = self.state().take_reader(path);
        if let Some(reader) = cached {
            match vault.object_key_of(path).await? {
                // Still the same object: the cached reader is exactly right.
                Some(current) if current == reader.object_key() => return Ok(reader),
                // The path now names something else — or nothing. Either way
                // this reader is no longer an answer about `path`, and the
                // chunks it produced are keyed by the old object's `file_id`,
                // so they cannot be served for the new one either.
                _ => self.state().forget_reader(path),
            }
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
        while self.bytes > self.budget_bytes || self.chunks.len() > self.budget_chunks {
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

    /// Forget the reader for `path`, and every chunk it produced.
    ///
    /// Called when a path stops resolving to the object its cached reader
    /// addresses. The chunks go too: they are keyed by the old object's
    /// `file_id`, so they could never be served for the new object, and
    /// holding them would only spend the budget on bytes nothing can ask for.
    fn forget_reader(&mut self, path: &str) {
        let Some(stale) = self.readers.remove(path) else {
            return;
        };
        let file_id = *stale.value.file_id();
        self.chunks.retain(|(object, _), chunk| {
            let keep = *object != file_id;
            if !keep {
                self.bytes = self.bytes.saturating_sub(chunk.value.len());
            }
            keep
        });
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
/// a short read — a `cat` that wrote fewer bytes and exited 0 is the misreport
/// [the plan](https://doc.dctl.sh/project/plan) §6 forbids.
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

/// The in-flight protocol, proved against a real vault over a watched store.
///
/// Separate from the `assemble` tests below because these need a seeded vault,
/// a backend double and a multi-threaded runtime; those need three maps and a
/// pattern. What these prove is the wire discipline: no byte fetched twice, no
/// waiter left asleep, no working set evicted out from under its reader.
#[cfg(test)]
mod flight_tests {
    use super::*;
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::Duration;

    use async_trait::async_trait;
    use bytes::Bytes;
    use dctl_core::{MIN_CHUNK_SIZE, Modified, Vault};
    use dctl_store::{
        Backend, ByteRange, ChecksumSupport, ContentHash, IncompleteUpload, IncompleteUploads,
        LocalFs, ObjectKey, ObjectMeta, Page, PutOutcome, SourceModified, StagingListing,
        StoreIdentity, StoredChecksum,
    };
    use tempfile::TempDir;

    /// Any ranged read at least this long is a chunk fetch.
    ///
    /// The only other ranged read the vault issues is the header probe, whose
    /// length is pinned at 4096 (`OBJECT_HEADER_PROBE_LEN`); the smallest chunk
    /// fetch is one [`MIN_CHUNK_SIZE`] chunk plus its 16-byte tag. The gap
    /// between the two is what makes the classification exact rather than
    /// heuristic.
    const CHUNK_FETCH_FLOOR: u64 = MIN_CHUNK_SIZE as u64 + 8;

    /// A real [`LocalFs`], watched — and slowed, so two tasks genuinely overlap.
    ///
    /// The sleep is the test's stand-in for a provider round trip. Without it a
    /// loopback fetch completes before the racing task has looked at the cache,
    /// and a test meaning to prove "a chunk on the wire is not fetched twice"
    /// would pass whether or not that is true.
    struct Counting {
        inner: LocalFs,
        delay: Duration,
        chunk_fetch_calls: AtomicU64,
        chunk_fetch_bytes: AtomicU64,
        /// Fail the next chunk fetch with a not-found, once. What the
        /// failed-flight test uses to make the *first* claimer lose.
        fail_next_chunk_fetch: AtomicBool,
    }

    impl Counting {
        fn new(root: &Path, delay: Duration) -> Self {
            Self {
                inner: LocalFs::new(root.to_path_buf()),
                delay,
                chunk_fetch_calls: AtomicU64::new(0),
                chunk_fetch_bytes: AtomicU64::new(0),
                fail_next_chunk_fetch: AtomicBool::new(false),
            }
        }

        fn chunk_fetch_calls(&self) -> u64 {
            self.chunk_fetch_calls.load(Ordering::SeqCst)
        }

        fn chunk_fetch_bytes(&self) -> u64 {
            self.chunk_fetch_bytes.load(Ordering::SeqCst)
        }

        fn reset(&self) {
            self.chunk_fetch_calls.store(0, Ordering::SeqCst);
            self.chunk_fetch_bytes.store(0, Ordering::SeqCst);
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
            // An unbounded range is a whole-object read; both it and any bounded
            // range past the floor are chunk traffic. Only the header probe is
            // smaller.
            let requested = range.length.unwrap_or(u64::MAX);
            if requested >= CHUNK_FETCH_FLOOR {
                if self.fail_next_chunk_fetch.swap(false, Ordering::SeqCst) {
                    return Err(dctl_store::StoreError::NotFound(key.as_str().to_string()));
                }
                self.chunk_fetch_calls.fetch_add(1, Ordering::SeqCst);
                self.chunk_fetch_bytes
                    .fetch_add(requested, Ordering::SeqCst);
                tokio::time::sleep(self.delay).await;
            }
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
        async fn list_page(
            &self,
            prefix: &str,
            cursor: Option<String>,
        ) -> dctl_store::Result<Page> {
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
        async fn abort_incomplete_upload(
            &self,
            upload: &IncompleteUpload,
        ) -> dctl_store::Result<()> {
            self.inner.abort_incomplete_upload(upload).await
        }
    }

    struct Fixture {
        _store: TempDir,
        _index: TempDir,
        vault: Arc<Vault>,
        watched: Arc<Counting>,
        plaintext: Vec<u8>,
    }

    /// A real vault over a watched local store, holding one object of `chunks`
    /// minimum-size chunks — small enough that a debug build seals it
    /// instantly, chunked enough that a window has structure to race over.
    async fn fixture(chunks: usize, delay: Duration) -> Fixture {
        let store = TempDir::new().expect("a temporary store");
        let index = TempDir::new().expect("a temporary index");
        let watched = Arc::new(Counting::new(store.path(), delay));
        let backend: Arc<dyn Backend> = Arc::clone(&watched) as Arc<dyn Backend>;
        let index_path = index.path().join("index.redb");

        let vault = Vault::init(Arc::clone(&backend), &index_path, "pw")
            .await
            .expect("a fresh vault initialises")
            .vault
            .with_chunk_size(Some(u64::from(MIN_CHUNK_SIZE)));

        // A pattern rather than randomness, so a wrong byte names its offset.
        let plaintext: Vec<u8> = (0..chunks * MIN_CHUNK_SIZE as usize)
            .map(|i| (i % 251) as u8)
            .collect();
        let source = index.path().join("source.bin");
        std::fs::write(&source, &plaintext).expect("a source file");
        vault
            .put_file_from_path("big.bin", &source, Modified::At(1_700_000_000))
            .await
            .expect("the object stores");
        watched.reset();

        Fixture {
            _store: store,
            _index: index,
            vault: Arc::new(vault),
            watched,
            plaintext,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_chunk_already_on_the_wire_is_awaited_rather_than_fetched_twice() {
        // A reader racing the warm task over the same window — the mount's
        // steady state on a slow link. Whatever the interleaving, every chunk
        // must cross the wire exactly once: the loser of each claim waits for
        // the winner's flight instead of re-issuing it. Without the in-flight
        // registry both sides fetch the whole window and this counts double.
        let fx = fixture(8, Duration::from_millis(25)).await;
        let cache = Arc::new(ChunkCache::new());
        let length = fx.plaintext.len() as u64;

        let warm = tokio::spawn({
            let cache = Arc::clone(&cache);
            let vault = Arc::clone(&fx.vault);
            async move { cache.warm(&vault, "big.bin", 0, length).await }
        });
        let read = tokio::spawn({
            let cache = Arc::clone(&cache);
            let vault = Arc::clone(&fx.vault);
            async move { cache.read_range(&vault, "big.bin", 0, None).await }
        });

        let bytes = read
            .await
            .expect("the read task runs")
            .expect("the read succeeds");
        warm.await.expect("the warm task runs");

        assert_eq!(&bytes[..], &fx.plaintext[..], "the window is byte-exact");
        let stride = u64::from(MIN_CHUNK_SIZE) + 16;
        assert_eq!(
            fx.watched.chunk_fetch_bytes(),
            8 * stride,
            "every chunk crossed the wire exactly once; more means the race \
             fetched bytes that were already in flight"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_failed_flight_wakes_its_waiter_and_the_waiter_fetches_for_itself() {
        // The claimer's fetch fails; the task waiting on that flight must be
        // woken and then meet the store first-hand — a marker that outlived its
        // fetch would leave the waiter asleep forever, a wedged mount with no
        // error anywhere. The test completing at all is the wake; the waiter's
        // clean read is the reclaim.
        let fx = fixture(4, Duration::from_millis(25)).await;
        let cache = Arc::new(ChunkCache::new());

        fx.watched
            .fail_next_chunk_fetch
            .store(true, Ordering::SeqCst);
        let loser = tokio::spawn({
            let cache = Arc::clone(&cache);
            let vault = Arc::clone(&fx.vault);
            async move { cache.read_range(&vault, "big.bin", 0, None).await }
        });
        // Give the loser time to claim, then queue up behind its flight.
        tokio::time::sleep(Duration::from_millis(10)).await;
        let waiter = tokio::spawn({
            let cache = Arc::clone(&cache);
            let vault = Arc::clone(&fx.vault);
            async move { cache.read_range(&vault, "big.bin", 0, None).await }
        });

        let lost = loser.await.expect("the loser task runs");
        let won = waiter
            .await
            .expect("the waiter task runs")
            .expect("the waiter reclaims the failed flight and reads");
        assert!(
            lost.is_err(),
            "the injected failure surfaced on the claimer"
        );
        assert_eq!(
            &won[..],
            &fx.plaintext[..],
            "the waiter's read is byte-exact"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_rewritten_object_is_never_served_from_the_readers_cached_for_its_old_one() {
        // Measured against a live B2 vault, and the reason this check exists:
        // a file replaced through the CLI was served through an open mount as
        // the OLD bytes under the NEW size — `getattr` takes the length from
        // the index while the read came from the superseded object. A corrupt
        // read, not a stale one. The chunk map avoids this by keying on
        // `file_id`; the reader map is keyed by path and has to earn the same
        // property by asking the index whether the path still names the object
        // its reader holds.
        let fx = fixture(4, Duration::ZERO).await;
        let cache = ChunkCache::new();

        let first = cache
            .read_range(&fx.vault, "big.bin", 0, None)
            .await
            .expect("the first read succeeds");
        assert_eq!(&first[..], &fx.plaintext[..]);

        // Replace the object behind the same logical path, exactly as a second
        // process writing to the vault would.
        let replacement: Vec<u8> = (0..fx.plaintext.len())
            .map(|i| ((i + 13) % 251) as u8)
            .collect();
        let source = fx._index.path().join("replacement.bin");
        std::fs::write(&source, &replacement).expect("a source file");
        fx.vault
            .put_file_from_path("big.bin", &source, Modified::At(1_700_000_100))
            .await
            .expect("the rewrite stores");

        let after = cache
            .read_range(&fx.vault, "big.bin", 0, None)
            .await
            .expect("the read after the rewrite succeeds");
        assert_eq!(
            &after[..],
            &replacement[..],
            "a cached reader must not keep serving the object the path used to name"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn raising_the_budget_keeps_a_working_set_the_floor_would_evict() {
        // More chunks than the entry floor holds: at the defaults a second pass
        // re-fetches what the first evicted, and with the budget raised — the
        // mount's move, sized to its read-ahead — the second pass costs
        // nothing. This is the geometry defect measured on the loopback rig:
        // a cache exactly one window deep turns read-ahead into wasted egress.
        let fx = fixture(VAULT_CHUNK_CACHE_MAX_CHUNKS * 2, Duration::ZERO).await;

        let floor = ChunkCache::new();
        floor
            .read_range(&fx.vault, "big.bin", 0, None)
            .await
            .expect("the first pass reads");
        fx.watched.reset();
        floor
            .read_range(&fx.vault, "big.bin", 0, None)
            .await
            .expect("the second pass reads");
        assert!(
            fx.watched.chunk_fetch_calls() > 0,
            "at the floor, a working set twice the entry bound cannot be held \
             and the second pass pays again — if this stops failing, the floor \
             grew and this test should shrink with it"
        );

        let raised = ChunkCache::new();
        raised.set_budget(
            VAULT_CHUNK_CACHE_BYTES * 4,
            VAULT_CHUNK_CACHE_MAX_CHUNKS * 4,
        );
        raised
            .read_range(&fx.vault, "big.bin", 0, None)
            .await
            .expect("the first pass reads");
        fx.watched.reset();
        raised
            .read_range(&fx.vault, "big.bin", 0, None)
            .await
            .expect("the second pass reads");
        assert_eq!(
            fx.watched.chunk_fetch_calls(),
            0,
            "with the budget raised past the working set, a re-read is served \
             entirely from the cache"
        );
    }
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
