//! The producer's end of the pipe: a [`std::io::Write`] that sends windows.
//!
//! It is a blocking `Write` on purpose. The thing that fills it is
//! `dctl_crypto`'s sealer, which is CPU-bound synchronous code running on
//! `tokio::task::spawn_blocking`, and giving it an async sink would mean either
//! rewriting the sealer around futures or bridging with a `block_on` inside a
//! runtime thread. `Sender::blocking_send` is the sanctioned bridge for exactly
//! this arrangement, and it is what applies the back-pressure the memory contract
//! is made of: when the channel is full the sealer stops, mid-object, until the
//! backend takes a window.

use std::io::{self, Write};

use bytes::Bytes;
use tokio::sync::mpsc::Sender;

use super::Window;
use super::constants::WINDOW_LEN;
use crate::checksum::{ContentHash, HashAlgo, Hasher};

/// What a failed send means, in the words the producer's caller will see.
///
/// A send fails for exactly one reason: the receiver was dropped, which happens
/// when the backend gave up. The sealer is told so as an ordinary I/O error, and
/// stops — which is the right shape, because the alternative is a sealer that
/// keeps encrypting a four-gigabyte object into a channel nobody is reading.
const RECEIVER_GONE: &str = "the backend stopped taking this object's bytes";

/// The producer's handle on an object being written.
///
/// Accumulates into one window, sends it when it is full, and folds a digest over
/// every byte on the way past. Dropping it without calling [`finish`](Self::finish)
/// or [`fail`](Self::fail) closes the channel with no terminal message, which the
/// consumer reports as a producer that stopped without finishing — never as a
/// complete object.
pub struct ObjectWriter {
    tx: Sender<Window>,
    /// The window being filled. Allocated once, at full capacity, and re-taken
    /// after each send, so the producer holds exactly one window at a time.
    buf: Vec<u8>,
    /// Folded over every byte written, so the terminal message can carry the
    /// digest of the whole object without a second pass over it.
    hasher: Option<Hasher>,
    algo: HashAlgo,
    /// Bytes handed to [`write`](Write::write) so far.
    produced: u64,
}

impl ObjectWriter {
    /// Wrap the sending half of a window channel.
    pub(super) fn new(tx: Sender<Window>, algo: HashAlgo) -> Self {
        Self {
            tx,
            buf: Vec::with_capacity(WINDOW_LEN),
            hasher: Some(Hasher::new(algo)),
            algo,
            produced: 0,
        }
    }

    /// How many bytes have been written so far.
    #[must_use]
    pub const fn produced(&self) -> u64 {
        self.produced
    }

    /// Send whatever is in the window buffer, if anything.
    ///
    /// Blocking, and that is the point — see the module docs.
    fn send_window(&mut self) -> io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let full = std::mem::replace(&mut self.buf, Vec::with_capacity(WINDOW_LEN));
        self.tx
            .blocking_send(Window::Bytes(Bytes::from(full)))
            .map_err(|_| io::Error::other(RECEIVER_GONE))
    }

    /// Declare the object complete and hand over the digest of everything written.
    ///
    /// Returns that digest as well as sending it, because the vault wants it for
    /// its own index record and re-deriving it would mean a third pass over bytes
    /// that no longer exist anywhere.
    ///
    /// # Errors
    /// [`io::Error`] when the backend has already stopped listening.
    pub fn finish(mut self) -> io::Result<ContentHash> {
        self.send_window()?;
        let digest = self
            .hasher
            .take()
            .ok_or_else(|| io::Error::other("this object was already finished"))?
            .finalize();
        self.tx
            .blocking_send(Window::Done(digest.clone()))
            .map_err(|_| io::Error::other(RECEIVER_GONE))?;
        Ok(digest)
    }

    /// Abandon the object, naming why.
    ///
    /// The consumer surfaces `why` as the failure of the whole write, so a sealer
    /// that could not read its source reports *that* rather than the backend
    /// reporting a stream which stopped early. Best-effort: if the backend has
    /// already given up there is nobody left to tell, and its own error is the one
    /// that will be reported.
    pub fn fail(self, why: impl Into<String>) {
        let _ = self.tx.blocking_send(Window::Failed(why.into()));
    }

    /// The digest algorithm both ends of this pipe fold under.
    #[must_use]
    pub const fn algo(&self) -> HashAlgo {
        self.algo
    }
}

impl Write for ObjectWriter {
    /// Take as much of `data` as fits in the current window and send the window
    /// once it is full.
    ///
    /// A short return is legal and is what happens whenever `data` straddles a
    /// window boundary; `write_all` — which is what the sealer calls — loops. The
    /// alternative, taking the whole slice however large, would let one
    /// `write_all` of a big ciphertext chunk put more than one window in memory
    /// at once and quietly break the bound this whole module exists to hold.
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        let room = WINDOW_LEN.saturating_sub(self.buf.len());
        let take = room.min(data.len());
        self.buf.extend_from_slice(&data[..take]);
        if let Some(hasher) = self.hasher.as_mut() {
            hasher.update(&data[..take]);
        }
        self.produced += take as u64;
        if self.buf.len() >= WINDOW_LEN {
            self.send_window()?;
        }
        Ok(take)
    }

    /// Send the partial window.
    ///
    /// Honest rather than a no-op: a caller that flushes is asking for what it has
    /// written to be on its way, and the only thing standing between the two is
    /// this buffer. Nothing in the sealer flushes mid-object, so this costs no
    /// short windows in practice.
    fn flush(&mut self) -> io::Result<()> {
        self.send_window()
    }
}
