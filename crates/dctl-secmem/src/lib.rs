//! `dctl-secmem` — secure memory for long-lived key material.
//!
//! `zeroize` wipes RAM copies, but it cannot help once the OS has paged a key to
//! swap or captured it in a core dump: those bytes persist on disk after the
//! process exits and are recoverable forensically. This crate pins sensitive
//! pages in RAM (`mlock`/`VirtualLock`), excludes them from dumps where the
//! platform allows (`madvise`), and exposes [`LockedSecret`], a heap buffer that
//! is locked on construction and unlocked + zeroized on drop.
//!
//! **This is the ONE DCTL crate permitted to contain `unsafe`.** It isolates every
//! platform FFI call so the crypto core (`dctl-crypto`) can stay
//! `#![forbid(unsafe_code)]`. Every `unsafe` block carries a `// SAFETY:` note.
//!
//! All locking is **best-effort**: some environments (unprivileged containers,
//! low `RLIMIT_MEMLOCK`) deny `mlock`. Failures are logged, never fatal — the
//! zeroize-on-drop protection always applies.
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod budget;
mod harden;
mod lock;
mod secret;

pub use budget::{opportunistic_chunk_lock_enabled, rlimit_memlock_budget};
pub use harden::apple_harden_crash_reporter;
pub use lock::{lock_memory, unlock_memory};
pub use secret::LockedSecret;
