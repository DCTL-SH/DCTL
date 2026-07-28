//! The tunables that bound this crate's working set.
//!
//! There is one number here and it is the whole memory contract: everything a
//! vault does to an object of any size is performed inside a window of
//! [`STREAM_WINDOW_CHUNKS`] chunks, so peak memory is set by a constant in this
//! file rather than by the file being moved.

/// How many payload chunks a sequential stream holds at once.
///
/// **This is the constant the memory bound is made of.** A streaming read
/// fetches this many chunks in one ranged request, authenticates them, writes
/// their plaintext out and drops them, so the peak working set of moving an
/// object of *any* size is
///
/// ```text
/// STREAM_WINDOW_CHUNKS × chunk_size × 2   (ciphertext window + its plaintext)
/// ```
///
/// which at the format's 1 MiB default chunk size is 16 MiB — flat from a 1 MiB
/// object to a 10 GB one. That is the property the whole tool rests on and it
/// was absent: `copy` of a 1 GiB file peaked at 3090 MiB of resident memory and
/// a 256 MiB file could not be moved inside a 512 MiB cap at all.
///
/// **Why eight and not one.** Every window costs one round trip, and on a
/// provider the round trip — not the decryption — is what a sequential read
/// spends its time in. One chunk per request would issue ten thousand requests
/// for a 10 GB object and pay the full latency of each; eight amortises that
/// eightfold while keeping the bound to a number an operator can hold in their
/// head. It is deliberately not tuned upward beyond that: the point of this
/// constant is that it is small and fixed, and a window large enough to matter
/// against RAM would be a size limit wearing a different hat.
///
/// **Why not proportional to the object.** Because that is the defect. Any rule
/// of the form "a fraction of the file" reintroduces a memory cost that grows
/// with the data, which is the thing a 10 GB video may not have.
pub const STREAM_WINDOW_CHUNKS: u64 = 8;

/// Working-buffer size for the crate's constant-memory hashing and copy passes
/// over data that is *not* chunk-framed — a source file being hashed, a temp
/// object being read back.
///
/// Independent of [`STREAM_WINDOW_CHUNKS`] because it bounds a different thing:
/// those passes have no chunk geometry to follow, so the only question is how
/// much of a syscall's cost each read amortises. 128 KiB is the size at which
/// per-call overhead has stopped mattering on every filesystem tested and well
/// below any figure that would show up next to the chunk window.
pub const STREAM_BUF_LEN: usize = 128 * 1024;
