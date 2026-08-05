//! Open remote files, kept between ranged reads.
//!
//! Every `get_range` used to open the remote file, `fstat` it, seek locally
//! and read — then drop the handle, which sends a close. Two extra protocol
//! round trips per fetch, on the path a mounted vault spends all its time in:
//! a mount reading a film fetches one chunk after another from the *same*
//! object and paid for a fresh handle every time. On a link where a round trip
//! is milliseconds rather than microseconds that is the dominant per-request
//! cost, and `HANDOVER.md` §40.5 names it as the next thing to fix.
//!
//! So a handle is kept, keyed by remote path, and the next read of the same
//! object reuses it — one `SSH_FXP_READ` and nothing else.
//!
//! ## Why this lives on the [`Link`](super::dial::Link)
//!
//! Because a handle is only meaningful inside the session that opened it, and
//! putting the cache anywhere else would mean writing invalidation code that
//! has to be right. Here there is none to write: a session that dies is
//! discarded whole, the next operation dials a fresh [`Link`] whose cache is
//! empty, and the dead one's handles close when its last `Arc` drops. The
//! re-dial path did not have to learn anything about this module.
//!
//! ## What a cached handle serves
//!
//! The file **as it was opened** — a POSIX server keeps serving the inode the
//! descriptor names, so an object replaced by another process is not observed
//! until the entry is evicted. That is safe here for reasons that are
//! properties of the design rather than luck: DCTL never appends in place
//! (every write is stage-then-rename), so its own writes produce a new inode
//! and evict the entry at the same moment; the objects this path fetches are
//! content-addressed (`o/<file-id>`), so a given key's bytes never change; and
//! a mount already caches decrypted chunks above this layer, so a reader was
//! never seeing a live view anyway.

use std::collections::VecDeque;
use std::sync::{Mutex, MutexGuard, PoisonError};

use openssh_sftp_client::file::File;

use super::CACHED_READ_HANDLES;

/// One remote file, open, with what its `fstat` said.
struct Cached {
    path: String,
    file: File,
    /// The size the handle was opened at. Coherent with the handle for the
    /// reason the module doc gives — the descriptor pins the file, and nothing
    /// DCTL writes changes an object in place.
    size: u64,
}

/// The open handles one session is holding.
///
/// Most-recently-used at the front, so the eviction is a `pop_back` and the
/// scan is over a collection bounded by [`CACHED_READ_HANDLES`].
#[derive(Default)]
pub(crate) struct HandleCache {
    entries: Mutex<VecDeque<Cached>>,
}

impl HandleCache {
    /// The open handle for `path`, if this session still holds one.
    ///
    /// The returned `File` is a clone — the library reference-counts the
    /// underlying handle and closes it when the last clone drops, so the
    /// cache's copy and the caller's copy keep it open together.
    pub(crate) fn get(&self, path: &str) -> Option<(File, u64)> {
        let mut entries = self.entries();
        let at = entries.iter().position(|entry| entry.path == path)?;
        let entry = entries.remove(at)?;
        let answer = (entry.file.clone(), entry.size);
        entries.push_front(entry);
        Some(answer)
    }

    /// Keep `file` for the next read of `path`.
    pub(crate) fn put(&self, path: String, file: File, size: u64) {
        let mut entries = self.entries();
        if let Some(at) = entries.iter().position(|entry| entry.path == path) {
            entries.remove(at);
        }
        entries.push_front(Cached { path, file, size });
        // Dropping the entry is the close: the library sends `SSH_FXP_CLOSE`
        // when the last clone of a handle goes, so there is no async teardown
        // for this synchronous section to do.
        while entries.len() > CACHED_READ_HANDLES {
            entries.pop_back();
        }
    }

    /// Forget the handle for `path` — it failed, or what it names has changed.
    pub(crate) fn evict(&self, path: &str) {
        let mut entries = self.entries();
        if let Some(at) = entries.iter().position(|entry| entry.path == path) {
            entries.remove(at);
        }
    }

    /// Lock the entries, recovering from a poisoned mutex rather than failing.
    ///
    /// Nothing in a critical section here can panic — they are `VecDeque`
    /// operations on already-validated values — and turning a theoretical
    /// poisoning into a backend that refuses every read would be the worse
    /// outcome. A stale cache is at worst a handle that lives too long.
    fn entries(&self) -> MutexGuard<'_, VecDeque<Cached>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }
}
