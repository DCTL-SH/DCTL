//! The streaming write's memory contract, and the two numbers it is made of.
//!
//! ```text
//! peak(pipe) = WINDOW_LEN × (WINDOWS_IN_FLIGHT + 2)
//! ```
//!
//! **No term in it is a function of the object's size**, and there is no
//! page-cache term, because a streamed write has no spool: the producer seals
//! into this pipe and the backend takes windows out of it, and nothing is ever
//! written to local disk on the way. That is the whole of the difference from
//! [`put_from_path`](crate::Backend::put_from_path), whose bytes are `O(1)` in
//! memory and `O(object)` on disk — and whose disk pages are charged to the same
//! cgroup as the program, which is why a 512 MiB container was not a safe place
//! to run a 4 GiB upload however flat the resident memory looked.
//!
//! The `+ 2` is the two windows that exist outside the channel at any moment: the
//! one the producer is filling, and the one the backend is draining. Both are
//! real and both are one window, so the bound is stated with them in it rather
//! than as a channel capacity that quietly under-counts by two.
//!
//! A backend adds its own term on top, and it is a different constant per family:
//!
//! * `local:` and `sftp:` add nothing — a window is written straight out.
//! * `b2:`, `s3:` and `r2:` add `part_size × parts-in-flight`, which is the
//!   multipart contract stated in
//!   [`b2::constants`](crate::b2) and `s3::constants`. Both multipliers are one.
//!
//! So the whole peak of a streamed vault write is
//!
//! ```text
//! chunk_size                                  the sealer's own working buffer
//! + WINDOW_LEN × (WINDOWS_IN_FLIGHT + 2)      this pipe
//! + part_size × UPLOAD_PARTS_IN_FLIGHT        the object stores only
//! ```
//!
//! every term a named constant, and not one of them a function of the object.

/// Bytes per window handed from the producer to the backend.
///
/// One mebibyte. Large enough that the per-window cost — a channel send, a task
/// wake, and on the object stores a `memcpy` into the part buffer — is invisible
/// beside the encryption of the same bytes; small enough that four of them in
/// flight is a number an operator sizing a container can ignore.
///
/// Deliberately **not** the sealer's chunk size and not the backend's part size.
/// Tying it to the chunk size would make the pipe's depth move when somebody
/// tuned the format's framing; tying it to the part size would make a small-part
/// configuration — the one an operator chooses precisely because memory is
/// scarce — also shrink the pipe and lose throughput for no reason they asked
/// for.
pub const WINDOW_LEN: usize = 1024 * 1024;

/// How many filled windows may wait between the producer and the backend.
///
/// Four. This is the depth that lets the sealer keep encrypting while the
/// previous window is on the wire: at zero the two would run strictly in turn and
/// a network round trip would idle the CPU, and past four the pipe is deeper than
/// any provider's acknowledgement latency can drain and the extra megabytes buy
/// nothing.
///
/// It is a named constant rather than a literal in the channel constructor
/// because it is the second factor in the contract above: raising it raises the
/// peak by a megabyte a step, and the change that did it would otherwise be a
/// number inside a call with no visible connection to a memory figure anybody
/// quoted. `tests/put_stream_memory.rs` computes its ceiling from this constant,
/// so raising the depth without raising the ceiling fails a test that names the
/// reason.
pub const WINDOWS_IN_FLIGHT: usize = 4;

/// The pipe's own peak working set, in bytes — the contract above, evaluated.
///
/// Public because it is the honest answer to the question a buyer sizing a
/// container asks, and because a figure the program will not say out loud is a
/// figure that drifts from the code. [`B2Backend::upload_peak_bytes`](crate::b2::B2Backend::upload_peak_bytes)
/// is the same idea for the multipart term.
#[must_use]
pub const fn pipe_peak_bytes() -> u64 {
    WINDOW_LEN as u64 * (WINDOWS_IN_FLIGHT as u64 + 2)
}
