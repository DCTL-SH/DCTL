//! `dctl-secmem` — secure memory for long-lived key material.
//!
//! `zeroize` wipes RAM copies, but it cannot help once the OS has paged a key to
//! swap or captured it in a core dump: those bytes persist on disk after the
//! process exits and are recoverable forensically. This crate pins sensitive
//! pages in RAM (`mlock`/`VirtualLock`), excludes them from dumps where the
//! platform allows (`madvise`), and exposes [`LockedSecret`], a buffer on pages
//! of its own that is locked on construction and unlocked + zeroized on drop.
//!
//! **The pages are its own for a reason.** `madvise(MADV_DONTDUMP)` refuses any
//! address that is not page-aligned, and a heap allocation never is, so the
//! core-dump exclusion failed silently for every secret on every Linux host until
//! the allocation was changed to whole pages — see [`LockedSecret`] and [`page`].
//! Whether it took is now [`observable`](LockedSecret::dump_exclusion) rather
//! than assumed.
//!
//! **This is the ONE DCTL crate permitted to contain `unsafe`.** It isolates every
//! platform FFI call so the crypto core (`dctl-crypto`) can stay
//! `#![forbid(unsafe_code)]`. Every `unsafe` block carries a `// SAFETY:` note.
//!
//! All locking is **best-effort**: some environments (unprivileged containers,
//! low `RLIMIT_MEMLOCK`) deny `mlock`. Failures are logged at `warn!` and are
//! never fatal — the zeroize-on-drop protection always applies. `warn!` because
//! both failures put key bytes on a disk the process does not control, and a
//! disclosure nobody sees at the default level is not a disclosure.
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod budget;
mod harden;
mod lock;
pub mod page;
mod secret;

pub use budget::{opportunistic_chunk_lock_enabled, rlimit_memlock_budget};
pub use harden::apple_harden_crash_reporter;
pub use lock::{DumpExclusion, Protection, lock_memory, unlock_memory};
pub use secret::LockedSecret;
