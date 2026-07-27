//! The read-only filesystem a vault is served through.
//!
//! `PLAN.md` §15 asks for a mount whose *whole* design is the streaming case: a
//! player seeking to 45:00 in a fifty-gigabyte film should fetch the covering
//! chunks and nothing else. That is what this module is, and it is only possible
//! because of what came before it — [`Source::read_range`](crate::source::Source::read_range)
//! serves a byte window at O(window) on both implementations
//! (`docs/FORMAT.md` §3), and [`chunk_cache`](crate::source::chunk_cache) keeps
//! the decrypted chunks so a kernel reading in 4 KiB steps does not re-fetch the
//! same megabyte 256 times. A FUSE `read(ino, offset, size)` maps onto that call
//! directly, with no whole-object path anywhere behind it.
//!
//! The verb — parsing, validating, refusing the flags this engine cannot honour
//! — lives in [`crate::commands::mount`]. This module is the filesystem.
//!
//! ## Read-only is enforced, not assumed
//!
//! Every mutating operation returns `EROFS`, from one place ([`refuse`]), and the
//! mount is additionally attached with the kernel's own `ro` flag so most of them
//! never reach userspace at all. Both, rather than either: the kernel flag is the
//! cheap defence and the callback is the true one, and a filesystem that accepted
//! a write and dropped it would be `PLAN.md` §6's misreport with a filesystem's
//! authority behind it — the program that wrote would see success, and its data
//! would not exist.
//!
//! ## No callback may panic
//!
//! A panic inside a filesystem callback is not one failed operation. The release
//! profile builds with `panic = "abort"`, so it takes the process down with a
//! mount still attached; the mountpoint becomes a dead directory that hangs
//! every process touching it — on macOS including Finder — until somebody finds
//! the right `umount` incantation. So every callback returns an errno on failure,
//! every index is checked, every arithmetic operation that could overflow is
//! `checked_` or `saturating_`, and the crate lints (`clippy::unwrap_used`,
//! `expect_used`, `panic`) are what stop the rule from decaying.
//!
//! `fuser` gives one more layer under that: a reply dropped without being sent
//! answers `EIO` rather than leaving the caller blocked forever. It is a safety
//! net for a bug, not a licence to have one.
//!
//! ## Directories do not exist, and are not invented twice
//!
//! A vault stores one record per file, keyed by its logical path, and nothing
//! that says `photos/2024` was ever a thing a user made. Every directory the
//! mount shows is therefore *inferred from the paths of the objects beneath it* —
//! and the inference is the one
//! [`commands::listing::dirs`](crate::commands::listing::dirs) already makes for
//! `dctl lsd` and `dctl tree`, reused rather than restated. [`tree`] feeds one
//! directory's worth of entries through the same [`Aggregator`], so what a mount
//! calls a directory and what `dctl lsd` calls a directory cannot drift apart.
//!
//! Two consequences follow, and both are visible through the mount: there is no
//! such thing as an empty directory in a vault, because nothing implies one; and
//! `mkdir` fails with `EROFS` rather than creating something the format cannot
//! store.
//!
//! [`Aggregator`]: crate::commands::listing::dirs::Aggregator
//!
//! ## The vault is unlocked once, and stays unlocked
//!
//! **This is a security property a user should be told about rather than
//! discover.** The password is asked for exactly once, at mount time, and the
//! unwrapped root key stays in this process's memory for as long as the mount is
//! up — that is what makes a mount usable at all, and it is not a detail that can
//! be tuned away. What follows from it:
//!
//! * **Anyone who can read the mountpoint reads plaintext.** No password, no
//!   prompt. By default the FUSE session is restricted to the user who started it
//!   (`SessionACL::Owner`); `--allow-other` removes that restriction and lets
//!   *every* local account read the vault, and `--allow-root` lets root.
//! * **A machine left unattended with a mount up is a machine with the vault
//!   open.** A screen lock does not close it. Anything running as that user —
//!   a backup agent, a search indexer, a browser extension with filesystem access
//!   — reads it too, and reads it as ordinary files.
//! * **The key material outlives the last read.** Root key, unwrapped DEKs and a
//!   bounded working set of decrypted chunks live in RAM until the mount ends.
//!   They are wiped on drop ([`Zeroizing`](zeroize::Zeroizing)) and never written
//!   to disk by this module — `--vfs-cache-mode` is the flag that would put
//!   plaintext on disk, and this engine refuses every value but `off`.
//! * **The remedy is to unmount.** Ending the mount drops the session, wipes the
//!   keys and returns the vault to needing a password. That is why unmounting is
//!   the security-relevant action, and why leaving a mount up "so it is there
//!   when I need it" is the decision worth making deliberately.
//!
//! ## What a read through the mount proves
//!
//! Every byte served carries its chunk's Poly1305 tag, verified against an AAD
//! binding the object's authenticated head and that chunk's index, so
//! substitution, reordering, splicing from another object and truncation are all
//! caught and reported as `EIO` rather than served. What a *windowed* read cannot
//! establish is the whole-object statement — the trailing footer BLAKE3 and the
//! recorded `content_blake3` both cover bytes a seek never fetched.
//! [`dctl verify`](crate::commands::verify) and `dctl scrub` remain the reads
//! that make it. See [`crate::source::vault`], which is where that argument
//! lives.
//!
//! ## Where the work happens
//!
//! `fuser`'s callbacks are synchronous and DCTL's read path is `async`, so the
//! session loop runs on a thread of its own and every callback that can touch a
//! provider hands its work — and its reply — to the Tokio runtime. See
//! [`session`] for the thread and the signal handling, and [`fs`] for the
//! dispatch. Nothing blocks the session loop, which is what lets a directory
//! listing complete while a fifty-gigabyte read is in flight.

pub mod attr;
pub mod config;
pub mod errno;
pub mod fs;
pub mod handle;
pub mod inode;
pub mod preflight;
pub mod refuse;
pub mod session;
pub mod state;
pub mod tree;

pub use config::MountConfig;
pub use preflight::check as preflight;
pub use session::mount;
