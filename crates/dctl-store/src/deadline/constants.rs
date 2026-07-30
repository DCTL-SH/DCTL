//! The two numbers an operator sets when a backup window is not theirs to
//! choose, and the one number that decides how finely progress is observed.
//!
//! Both defaults are rclone's, taken from `fs/config.go` rather than invented,
//! because rclone's observable behaviour is the bar this tool is measured
//! against and an operator migrating a script should not find that the same
//! flag means a different length of patience.

use std::time::Duration;

/// How long a transfer may move **no bytes at all** before it is given up on.
///
/// Five minutes, which is rclone's `--timeout` default — `fs/config.go:120-123`,
/// `Default: 5 * 60 * time.Second`, `Help: "IO idle timeout"`. The word *idle*
/// in that help string is the whole of the semantics and is worth stating twice:
/// this is time **since the last byte moved**, not time since the transfer
/// started. A 4 GiB object over a slow uplink takes hours and is never once
/// close to this deadline, because every frame that leaves resets it.
///
/// Five minutes rather than something brisk because the failure it exists to
/// bound is a link that has died silently, and the cost of being wrong in the
/// impatient direction is worse than the cost of being wrong in the patient one:
/// a deadline that fires on a healthy transfer destroys work that was
/// succeeding, while one that fires late merely costs the operator the
/// difference. A provider that pauses to rebalance a bucket, a TCP retransmit
/// storm, and an `ssh` session waiting behind a `ProxyCommand` that is
/// re-authenticating all produce quiet periods measured in seconds to a minute;
/// none of them produces five.
pub const DEFAULT_IDLE: Duration = Duration::from_secs(5 * 60);

/// How long establishing a connection may take before it is given up on.
///
/// Sixty seconds, rclone's `--contimeout` default (`fs/config.go:115-118`,
/// `Default: 60 * time.Second`, `Help: "Connect timeout"`).
///
/// Separate from [`DEFAULT_IDLE`] because the two bound different failures and
/// want different numbers. A connection that has not been established is a
/// connection over which nothing is at risk: giving up costs one round of
/// backoff and nothing else, so this can be — and is — an order of magnitude
/// more impatient than the deadline on a transfer that is already carrying
/// data.
///
/// Sixty seconds is also comfortably longer than the worst honest case this
/// tool meets: a `sftp:` host behind `ProxyCommand cloudflared access ssh`
/// establishes a tunnel, a TLS session and an SSH handshake before the first
/// SFTP packet, and doing all three from cold on a congested link has been
/// measured in the tens of seconds.
pub const DEFAULT_CONNECT: Duration = Duration::from_secs(60);

/// The value of `--timeout` or `--contimeout` that means *wait as long as it
/// takes*.
///
/// Zero, matching rclone, where the deadline is only armed at all when the
/// configured duration is positive (`fs/fshttp/dialer.go:102`,
/// `if c.timeout > 0`, and again at `:113` and `:123` before each nudge; a Go
/// `net.Dialer` with `Timeout: 0` likewise does not bound the dial).
///
/// It is a supported answer rather than a degenerate one. An operator restoring
/// a hundred terabytes over a link that stalls for twenty minutes at a time has
/// a real reason to say "never give up", and the alternative — picking a number
/// large enough to mean the same thing — is a number that is wrong on the day it
/// is not.
pub const DISABLED_SECONDS: u64 = 0;

/// How much of a request body is handed to the HTTP stack at a time.
///
/// This is the **grain of the upload's progress signal**, and it is the reason
/// this constant is not merely a buffer size. DCTL cannot see the socket:
/// `reqwest` owns the connector and its `Conn` type is `pub(crate)`, so the
/// per-`Read`/`Write` deadline rclone sets on the connection itself
/// (`fs/fshttp/dialer.go:101-127`) has no equivalent here. What DCTL can see is
/// hyper *asking for the next frame*, and hyper only asks while its write buffer
/// has room — `can_buffer` in `hyper/src/proto/h1/io.rs:152` — which it only has
/// once the socket has accepted what was already queued. So "a frame was taken"
/// is a statement about the connection, one buffer upstream of the wire.
///
/// 64 KiB is chosen against both ends of that. It is the same order as a tuned
/// TCP send buffer, so a frame is roughly a window's worth rather than an
/// arbitrary slice; it gives 1 600 progress reports across a 100 MiB part, which
/// makes the deadline's resolution far finer than any timeout worth setting; and
/// it costs nothing in memory, because [`bytes::Bytes::split_to`] hands out a
/// view of the buffer the part already occupies rather than a copy of it. The
/// memory contract in `crate::b2::constants` — one part, once — is unchanged by
/// framing, and `b2_upload_memory.rs` is what holds that.
pub const UPLOAD_FRAME_LEN: usize = 64 * 1024;

// ── the rules these numbers have to keep ─────────────────────────────────────
//
// Compile-time, for the reason `crate::retry::constants` gives: a constant that
// has drifted out of range is not a behaviour worth discovering at `cargo test`,
// it is a build that should not produce a binary.

/// Connecting is the impatient half. If these ever converge, the justification
/// above — that a connection carrying no data is cheap to abandon — has stopped
/// being true and should be deleted rather than quietly kept.
const _: () = assert!(DEFAULT_CONNECT.as_nanos() < DEFAULT_IDLE.as_nanos());

/// A frame has to be smaller than the smallest part any provider will accept,
/// or framing would be a no-op on the one path it exists for. B2's minimum part
/// is 5 MiB and S3's is the same; 64 KiB is two orders below both.
const _: () = assert!(UPLOAD_FRAME_LEN < 5 * 1024 * 1024);

/// …and larger than nothing, since a zero-length frame would be a body that
/// never ends.
const _: () = assert!(UPLOAD_FRAME_LEN > 0);
