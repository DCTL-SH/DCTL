//! An object's bytes on their way to a backend, with no file behind them.
//!
//! [`Backend::put`](crate::Backend::put) takes an object that is already in
//! memory and [`put_from_path`](crate::Backend::put_from_path) takes one that is
//! already on disk. Neither shape fits the thing a vault actually has: an object
//! that **does not exist yet** and is being produced, chunk by chunk, by a sealer
//! reading the user's file. Until this module the answer was to produce it onto
//! local disk first and then hand over the path — the spool — which cost one
//! object of scratch storage per upload and, because those pages are charged to
//! the same cgroup as the program, made a hard memory cap mean something other
//! than what an operator set it to.
//!
//! What is here is the third shape: a **bounded pipe**. The producer writes
//! windows into an [`ObjectWriter`]; the backend takes them out of an
//! [`ObjectStream`]; the channel between them holds a fixed number of windows and
//! blocks the producer when it is full, so the sealer runs exactly as fast as the
//! link will take its output and never further ahead. [`constants`] states the
//! peak that results and every term in it is a constant.
//!
//! ## The digest travels with the bytes, and arrives last
//!
//! A streaming write cannot be handed its expected hash up front — nobody knows
//! the BLAKE3 of a sealed object until the object has been sealed, and sealing it
//! twice to learn it is the spool again by another name. So the promise moves to
//! the end: the producer folds a digest over everything it writes and sends it as
//! the stream's final message, and [`ObjectStream::agreed`] compares it against a
//! digest the consumer folded over everything it handed out.
//!
//! That is a real check and it is worth being exact about which one, because it
//! is **not** the same check the spool path made. What it proves is that the pipe
//! delivered, in order and without loss or duplication, exactly what the sealer
//! produced — which is precisely the class of defect a streaming rewrite
//! introduces. What proves the rest of the chain is unchanged and lives where it
//! always did: `local:` re-reads the staging file off the disk and hashes it
//! before the rename, B2 has the provider echo back the SHA-1 of every part it
//! accepted, and S3 re-verifies every part body against the SigV4
//! `x-amz-content-sha256` it was signed with. Nothing here weakens any of those;
//! what it replaces is a hash of a temporary file compared against a second hash
//! of the same temporary file.
//!
//! [`agreed`](ObjectStream::agreed) also checks the **length**: a producer that
//! promised a hundred megabytes and delivered ninety would otherwise commit a
//! short object on any backend whose protocol does not count for itself. It is
//! the same "length before content" ordering the local verified write already
//! applies, for the same reason — a short object is a write that stopped, not a
//! file that was altered, and the two have opposite remedies.
//!
//! ## A stream is consumed once, and that decides where retry lives
//!
//! There is no rewinding this. A backend that fails half way through cannot be
//! handed the same stream again, which is why [`Retrying`](crate::Retrying) does
//! not retry [`put_stream`](crate::Backend::put_stream) and says so at its own
//! call site. Retry for a streamed write lives one layer *down*, per request: a
//! B2 part is re-sent from the buffer already in hand, and a whole-object retry
//! is the caller's decision to seal again from the source that is still on disk.

pub mod constants;
mod stream;
mod writer;

pub use constants::{WINDOW_LEN, WINDOWS_IN_FLIGHT, pipe_peak_bytes};
pub use stream::ObjectStream;
pub use writer::ObjectWriter;

use crate::checksum::{ContentHash, HashAlgo};

/// One message from the producer to the backend.
///
/// Three variants rather than a `Result<Bytes>` stream, because "the object ended
/// and here is its digest" and "the producer gave up" are different facts from
/// "here are some bytes", and a channel that closed with neither of them said is
/// a fourth: a producer that died without a word. All four are distinguishable
/// here and every one of them is an error except the first two, which is what
/// stops a killed sealer from looking like a complete small object.
pub(crate) enum Window {
    /// Bytes to store, in order.
    Bytes(bytes::Bytes),
    /// The producer wrote its last byte; this is the digest of all of them.
    Done(ContentHash),
    /// The producer failed, and this is what it said.
    Failed(String),
}

/// Create a producer/consumer pair for one object of `len` bytes.
///
/// `len` is the exact length the producer will write, declared before it writes
/// anything, because the multipart backends need it: it decides single-shot
/// against multipart, it sizes the parts, and it is what keeps the part count
/// inside the provider's ten-thousand-part cap. A producer that cannot state its
/// length cannot use this path — see [`Backend::put_stream`](crate::Backend::put_stream)
/// for the one caller in this workspace that is in that position and what it does
/// instead.
///
/// `algo` is the digest both ends fold under, so the hash the backend reports in
/// its [`PutOutcome`](crate::PutOutcome) is in the same alphabet as everything
/// else the caller holds.
#[must_use]
pub fn object_stream(len: u64, algo: HashAlgo) -> (ObjectWriter, ObjectStream) {
    // Bounded, and this bound *is* the memory contract: a full channel blocks the
    // producer's next `write`, which is what makes a sealer run at the link's
    // speed rather than at the disk's.
    let (tx, rx) = tokio::sync::mpsc::channel(constants::WINDOWS_IN_FLIGHT);
    (
        ObjectWriter::new(tx, algo),
        ObjectStream::new(len, algo, rx),
    )
}
