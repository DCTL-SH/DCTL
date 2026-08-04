//! What the mount remembers between an `open` and the `release` that ends it.
//!
//! FUSE lets a filesystem hand the kernel a 64-bit *file handle* on `open` and
//! `opendir`, and quotes it back on every `read`, `readdir` and `release`. Using
//! it is not optional bookkeeping here; both of the things it carries are
//! properties a stateless filesystem gets wrong:
//!
//! * **A directory being read is a snapshot.** `readdir` is resumable — the
//!   kernel asks for entries from an offset, comes back for more, and expects
//!   the sequence not to have shifted underneath. Re-listing on every call would
//!   let a file added between two calls duplicate or hide an entry, which
//!   surfaces as `ls` printing a name twice or missing one. So `opendir` reads
//!   the directory once and `readdir` serves from that.
//! * **A file being read has a read-ahead position.** [`Handle::File`] carries
//!   how far ahead the chunk cache has already been warmed, so the mount can
//!   tell a sequential reader from a seeking one and only spend a request when
//!   the reader has actually moved past what was fetched.
//!
//! ## Handles are numbered, not pointers
//!
//! The value handed to the kernel is an index into this table. It could be a
//! pointer — plenty of FUSE filesystems do exactly that, in C — and the reason
//! not to is that the kernel is free to send a handle back after the mount has
//! decided it was released, including one it invented. An index is validated by
//! looking it up; a pointer is validated by being dereferenced.
//!
//! ## The table is bounded by the kernel, not by a constant
//!
//! There is no cap here, and that is deliberate rather than an omission: an entry
//! exists only between `open` and `release`, one per file description the kernel
//! is holding open, and the kernel is already bounded by the calling process's
//! descriptor limit. A cap would turn "this program opened a lot of files" into
//! an error the program has no way to interpret, while the actual failure mode —
//! a handle leaked because a `release` was lost — is a bug to fix rather than a
//! quota to enforce.

use std::collections::HashMap;
use std::sync::Arc;

use fuser::FileHandle;

use super::tree::Listing;

/// One thing the kernel currently has open.
pub enum Handle {
    /// An open file.
    File {
        /// Full logical path of the object being read.
        ///
        /// Held by path rather than by inode so that a `read` needs no second
        /// lookup, and because the path is what every layer below this one
        /// addresses objects by.
        path: String,
        /// Plaintext offset the read-ahead has already covered.
        ///
        /// The mount warms the chunks past a read; this is where that warming
        /// reached, so the next read only pays for read-ahead when it has moved
        /// beyond it. Without it a player reading a 1 MiB chunk in 4 KiB steps
        /// would schedule 256 read-aheads of the same bytes.
        prefetched_to: u64,
        /// Where the current sequential run began — reset on every jump.
        ///
        /// Progress measured from here is what *earns* read-ahead depth. The
        /// kernel splits one application read into many smaller ones, so "the
        /// read after this one moved forward" is true eight times over inside a
        /// single `dd` of a seek test and proves nothing about streaming; a
        /// full window of progress from the last jump is the evidence the
        /// pipeline deepens on.
        streak_base: u64,
    },
    /// An open directory, with the listing it was opened on.
    Directory {
        /// The snapshot `readdir` serves from. `Arc` so a callback can take it
        /// out from under the table's lock and format entries without holding
        /// every other operation up.
        listing: Arc<Listing>,
    },
}

/// The open-handle table.
///
/// Not internally synchronised — [`super::state`] owns it behind the mount's one
/// lock, so that a handle cannot be released between the moment a `read` resolves
/// it and the moment it is used.
pub struct HandleTable {
    open: HashMap<u64, Handle>,
    /// Next handle to hand out. Monotonic, so a number the kernel sends after a
    /// release resolves to nothing rather than to whatever took its place.
    next: u64,
}

impl Default for HandleTable {
    fn default() -> Self {
        Self::new()
    }
}

impl HandleTable {
    /// An empty table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            open: HashMap::new(),
            // Zero is what `fuser`'s default `open` replies with, and therefore
            // what a filesystem that does not track handles uses. Starting above
            // it means a zero arriving here is recognisably "no handle" rather
            // than an alias for the first file ever opened.
            next: 1,
        }
    }

    /// Register an open file and return the handle to give the kernel.
    pub fn open_file(&mut self, path: String) -> FileHandle {
        self.insert(Handle::File {
            path,
            prefetched_to: 0,
            streak_base: 0,
        })
    }

    /// Register an open directory over the listing it was opened on.
    pub fn open_directory(&mut self, listing: Arc<Listing>) -> FileHandle {
        self.insert(Handle::Directory { listing })
    }

    /// The path an open file handle refers to, if it is one.
    ///
    /// [`None`] for a handle that was never issued, has been released, or names a
    /// directory — all three of which are `EBADF` to the caller, and none of
    /// which may resolve to somebody else's file.
    #[must_use]
    pub fn path_of(&self, handle: FileHandle) -> Option<&str> {
        match self.open.get(&handle.0) {
            Some(Handle::File { path, .. }) => Some(path.as_str()),
            _ => None,
        }
    }

    /// The listing an open directory handle was opened on, if it is one.
    #[must_use]
    pub fn listing_of(&self, handle: FileHandle) -> Option<Arc<Listing>> {
        match self.open.get(&handle.0) {
            Some(Handle::Directory { listing }) => Some(Arc::clone(listing)),
            _ => None,
        }
    }

    /// Claim the read-ahead windows that keep the watermark `depth × window`
    /// bytes ahead of a reader at `from`.
    ///
    /// Returns the whole windows to warm — each `(start, length)` with `length`
    /// exactly `window` — and moves the watermark past them. Empty when the
    /// horizon is already covered, which is what turns "warm after every read"
    /// into "warm once per window of progress": a kernel reading a 1 MiB chunk
    /// in 4 KiB steps claims nothing 255 times out of 256.
    ///
    /// The depth is the pipeline. At depth one the next window is claimed only
    /// when the reader arrives at the watermark, and every boundary stalls for a
    /// provider round trip; at depth two the claim fires a full window early, so
    /// the fetch overlaps the reader's consumption of what is already resident —
    /// [`MOUNT_READ_AHEAD_DEPTH`](crate::constants::MOUNT_READ_AHEAD_DEPTH)
    /// argues the figure.
    ///
    /// **Depth is earned by proven progress, never spent on a jump.** Every
    /// jump — a seek in either direction, or the first read of a handle —
    /// resets the streak and claims at most one window. From there the
    /// pipeline deepens one window per full window read past the streak base,
    /// up to `depth`. The evidence has to be a *window*, not merely a forward
    /// read: the kernel splits one application read into many smaller ones, so
    /// a seek's single megabyte arrives as eight "forward" reads, and a
    /// depth spent on that arithmetic would cost a seek-heavy player
    /// `depth × window` of speculative egress per seek, queued ahead of the
    /// very reads it is waiting on — measured on a 12 MB/s WAN as seek latency
    /// climbing monotonically through the run, and on loopback as seek medians
    /// tripling. Only whole windows are ever claimed, so partial progress
    /// never issues a fragment request.
    pub fn claim_read_ahead(
        &mut self,
        handle: FileHandle,
        from: u64,
        window: u64,
        depth: u64,
    ) -> Vec<(u64, u64)> {
        let Some(Handle::File {
            prefetched_to,
            streak_base,
            ..
        }) = self.open.get_mut(&handle.0)
        else {
            return Vec::new();
        };
        if window == 0 {
            return Vec::new();
        }
        let horizon = window.saturating_mul(depth);
        // Strictly past the watermark, or more than the horizon behind it:
        // this reader jumped, and its history no longer predicts anything.
        if from > *prefetched_to || prefetched_to.saturating_sub(from) > horizon {
            *streak_base = from;
        }
        let progressed = from.saturating_sub(*streak_base) / window;
        let earned = progressed.saturating_add(1).min(depth.max(1));
        let target = from.saturating_add(window.saturating_mul(earned));
        let start = (*prefetched_to).max(from);
        let missing = target.saturating_sub(start) / window;
        if missing == 0 {
            return Vec::new();
        }
        let mut windows = Vec::with_capacity(usize::try_from(missing).unwrap_or(usize::MAX));
        let mut at = start;
        for _ in 0..missing {
            windows.push((at, window));
            at = at.saturating_add(window);
        }
        *prefetched_to = at;
        windows
    }

    /// Forget a handle. Answers whether it was one this table had issued.
    pub fn release(&mut self, handle: FileHandle) -> bool {
        self.open.remove(&handle.0).is_some()
    }

    /// How many handles are open.
    ///
    /// Read at the end of a mount, where a non-zero count says the kernel still
    /// had files open when the session ended — ordinary at unmount, and a leak if
    /// it grows. No `is_empty` beside it: the interesting fact is the number, and
    /// a boolean would hide the difference between one stale handle and ten
    /// thousand.
    #[must_use]
    pub fn len(&self) -> usize {
        self.open.len()
    }

    /// Store a handle under the next unused number.
    ///
    /// Saturating rather than wrapping. Wrapping would eventually re-issue a
    /// number a live descriptor still holds, which is the one failure this table
    /// exists to prevent; saturating means a process that opened 2^64 files stops
    /// getting new handles, which no process will reach and which fails safely by
    /// colliding with an entry that has to be released first.
    fn insert(&mut self, handle: Handle) -> FileHandle {
        let number = self.next;
        self.next = self.next.saturating_add(1);
        self.open.insert(number, handle);
        FileHandle(number)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mount::inode::Kind;
    use crate::mount::tree::Child;

    fn listing(names: &[&str]) -> Arc<Listing> {
        Arc::new(Listing {
            children: names
                .iter()
                .map(|name| Child {
                    name: (*name).to_string(),
                    path: (*name).to_string(),
                    kind: Kind::File,
                    size: Some(0),
                    modified_unix: None,
                })
                .collect(),
            subtree_bytes: Some(0),
            subtree_objects: names.len() as u64,
        })
    }

    #[test]
    fn a_handle_resolves_to_the_file_it_was_opened_on() {
        let mut table = HandleTable::new();
        let handle = table.open_file("photos/a.jpg".into());
        assert_eq!(table.path_of(handle), Some("photos/a.jpg"));
    }

    #[test]
    fn a_handle_the_table_never_issued_resolves_to_nothing() {
        // The kernel is free to send anything back; a lookup is what validates
        // it, which is why the value is an index and not a pointer.
        let table = HandleTable::new();
        assert_eq!(table.path_of(FileHandle(0)), None);
        assert_eq!(table.path_of(FileHandle(99)), None);
        assert!(table.listing_of(FileHandle(1)).is_none());
    }

    #[test]
    fn a_released_handle_stops_resolving() {
        let mut table = HandleTable::new();
        let handle = table.open_file("a.txt".into());
        assert!(table.release(handle));
        assert_eq!(table.path_of(handle), None);
        // …and releasing it twice is not a success the second time.
        assert!(!table.release(handle));
    }

    #[test]
    fn a_number_is_never_re_issued_while_the_process_runs() {
        // A recycled number would let a stale descriptor address a file opened
        // after it — the one failure this table exists to prevent.
        let mut table = HandleTable::new();
        let first = table.open_file("a.txt".into());
        table.release(first);
        let second = table.open_file("b.txt".into());
        assert_ne!(first, second);
        assert_eq!(table.path_of(second), Some("b.txt"));
    }

    #[test]
    fn a_directory_handle_is_not_a_file_handle() {
        // `read` on a directory and `readdir` on a file are both EBADF, and the
        // table must not let either through by returning the wrong shape.
        let mut table = HandleTable::new();
        let dir = table.open_directory(listing(&["a.txt"]));
        assert_eq!(table.path_of(dir), None);
        assert!(table.listing_of(dir).is_some());

        let file = table.open_file("a.txt".into());
        assert!(table.listing_of(file).is_none());
    }

    #[test]
    fn a_directory_handle_serves_the_listing_it_was_opened_on() {
        // `readdir` is resumable, so the sequence may not shift between calls.
        let mut table = HandleTable::new();
        let handle = table.open_directory(listing(&["a.txt", "b.txt"]));
        let served = table.listing_of(handle).unwrap();
        assert_eq!(served.children.len(), 2);
        assert_eq!(served.children[0].name, "a.txt");
    }

    #[test]
    fn read_ahead_is_claimed_once_per_window_rather_than_once_per_read() {
        // The whole point of the watermark: a kernel reading a 1 MiB chunk in
        // 4 KiB steps must not schedule 256 read-aheads of the same bytes.
        let mut table = HandleTable::new();
        let handle = table.open_file("film.mkv".into());

        // The first read is a jump from nowhere: one window, not a burst.
        assert_eq!(
            table.claim_read_ahead(handle, 0, 1_000, 2),
            vec![(0, 1_000)]
        );
        // Reads inside the first window prove nothing yet — one application
        // read arrives as many kernel reads, and none of them may spend a
        // request.
        assert!(table.claim_read_ahead(handle, 100, 1_000, 2).is_empty());
        assert!(table.claim_read_ahead(handle, 200, 1_000, 2).is_empty());
        assert!(table.claim_read_ahead(handle, 999, 1_000, 2).is_empty());
        // A full window of progress is the proof of a stream: the pipeline
        // deepens to two here, and only here.
        assert_eq!(
            table.claim_read_ahead(handle, 1_000, 1_000, 2),
            vec![(1_000, 1_000), (2_000, 1_000)]
        );
        // From then on: nothing inside a window, one refill per window crossed.
        assert!(table.claim_read_ahead(handle, 1_100, 1_000, 2).is_empty());
        assert_eq!(
            table.claim_read_ahead(handle, 2_000, 1_000, 2),
            vec![(3_000, 1_000)]
        );
    }

    #[test]
    fn a_seek_spends_one_window_and_streaming_earns_the_rest() {
        // A seek-heavy reader must not pay depth × window of speculative
        // egress per jump — on a slow link that queue is exactly what its next
        // seek waits behind, measured as seek latency climbing through a run.
        // One window on the jump; the pipeline deepens only once progress
        // inside the horizon proves a stream.
        let mut table = HandleTable::new();
        let handle = table.open_file("film.mkv".into());
        assert_eq!(
            table.claim_read_ahead(handle, 0, 1_000, 2),
            vec![(0, 1_000)]
        );
        // A far forward seek: one window again, at the new position.
        assert_eq!(
            table.claim_read_ahead(handle, 50_000, 1_000, 2),
            vec![(50_000, 1_000)]
        );
        // The seek's own tail — the kernel's split of the same application
        // read — moves forward without proving anything, and claims nothing.
        // This is the line that went to 3x the seek median on loopback when
        // depth was spent on that arithmetic instead of on evidence.
        assert!(table.claim_read_ahead(handle, 50_200, 1_000, 2).is_empty());
        // A full window read past the seek is streaming: depth is earned now.
        assert_eq!(
            table.claim_read_ahead(handle, 51_000, 1_000, 2),
            vec![(51_000, 1_000), (52_000, 1_000)]
        );
    }

    #[test]
    fn the_pipeline_stays_a_window_ahead_of_a_sequential_reader() {
        // Depth two means the fetch of window k+1 overlaps the consumption of
        // window k. If the refill arrived only when the reader reached the
        // watermark, every boundary would stall for a round trip — the
        // stop-and-go this depth exists to remove.
        let mut table = HandleTable::new();
        let handle = table.open_file("film.mkv".into());
        assert_eq!(table.claim_read_ahead(handle, 0, 1_000, 2).len(), 1);
        // Crossing into the second window earns depth two: the third window's
        // fetch is claimed while the second is being consumed — the reader
        // never arrives at an unclaimed watermark again.
        assert_eq!(
            table.claim_read_ahead(handle, 1_000, 1_000, 2),
            vec![(1_000, 1_000), (2_000, 1_000)]
        );
        // And from inside the second window, the boundary ahead is already
        // covered; the refill lands one window per window of progress.
        assert!(table.claim_read_ahead(handle, 1_500, 1_000, 2).is_empty());
        assert_eq!(
            table.claim_read_ahead(handle, 2_000, 1_000, 2),
            vec![(3_000, 1_000)]
        );
    }

    #[test]
    fn seeking_backwards_re_arms_the_read_ahead() {
        // A reader that jumps back is not sequential from the watermark's point
        // of view, and its next read must be able to warm what it is heading for.
        let mut table = HandleTable::new();
        let handle = table.open_file("film.mkv".into());
        assert_eq!(table.claim_read_ahead(handle, 10_000, 1_000, 2).len(), 1);
        // A window of streaming earns depth two.
        assert_eq!(
            table.claim_read_ahead(handle, 11_000, 1_000, 2),
            vec![(11_000, 1_000), (12_000, 1_000)]
        );
        // Back to the start: more than the horizon behind the watermark, so no
        // claim, and the watermark is not moved backwards by the attempt…
        assert!(table.claim_read_ahead(handle, 0, 1_000, 2).is_empty());
        // …but forward progress back toward the watermark re-arms warming.
        assert_eq!(
            table.claim_read_ahead(handle, 12_500, 1_000, 2),
            vec![(13_000, 1_000)]
        );
    }

    #[test]
    fn read_ahead_cannot_be_claimed_on_a_directory_or_a_stale_handle() {
        let mut table = HandleTable::new();
        let dir = table.open_directory(listing(&[]));
        assert!(table.claim_read_ahead(dir, 0, 1_000, 2).is_empty());
        assert!(
            table
                .claim_read_ahead(FileHandle(4_242), 0, 1_000, 2)
                .is_empty()
        );
    }

    #[test]
    fn a_read_ahead_window_at_the_end_of_the_address_space_does_not_wrap() {
        // An arithmetic overflow here is a panic inside `read`, which wedges the
        // mount rather than failing one operation.
        let mut table = HandleTable::new();
        let handle = table.open_file("a.bin".into());
        // Nothing addressable lies past the end, so nothing is claimed — and
        // nothing panics.
        assert!(
            table
                .claim_read_ahead(handle, u64::MAX, u64::MAX, 2)
                .is_empty()
        );
        // Just short of the end, the one window that fits is claimed, clamped.
        assert_eq!(
            table.claim_read_ahead(handle, u64::MAX - 1, 1, 2),
            vec![(u64::MAX - 1, 1)]
        );
        // And the watermark it left is saturated, not wrapped.
        assert!(
            table
                .claim_read_ahead(handle, u64::MAX - 1, 1, 2)
                .is_empty()
        );
    }

    #[test]
    fn the_count_tracks_what_is_open_and_returns_to_nothing() {
        // The number logged at the end of a mount: a count that did not come back
        // to zero after every release would be a leak reported as normal.
        let mut table = HandleTable::new();
        assert_eq!(table.len(), 0);
        let handle = table.open_file("a.txt".into());
        assert_eq!(table.len(), 1);
        table.release(handle);
        assert_eq!(table.len(), 0);
    }
}
