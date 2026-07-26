//! The one way anything in this binary reads stored data.
//!
//! Every read-side verb — `ls`, `lsd`, `lsl`, `lsjson`, `tree`, `size`, `cat`,
//! and the integrity family behind them — needs exactly two capabilities: *tell
//! me what is under this prefix*, and *give me these bytes*. Those are the two
//! methods on [`Source`], and there are exactly two implementations of it: a
//! sealed vault ([`vault`]) and a plain object store ([`plain`]).
//!
//! ## Why one abstraction rather than a branch per command
//!
//! The alternative writes itself, and it is what the write path did before it
//! was fixed: each command opens its own session, asks "is this a vault?", and
//! takes one of two paths. Five commands then hold five copies of a resolution
//! rule that must agree, and they diverge one commit at a time — a vault chain
//! followed here and not there, a remote name re-parsed as a relative directory
//! somewhere else. That divergence had a name in this project's history (S6) and
//! its symptom was `dctl copy ./src vault:photos` writing into a *directory*
//! called `vault`, discarding `photos`, and exiting 0.
//!
//! So the decision is made once, in [`open`], from a [`RemoteSpec`](crate::remote::RemoteSpec) that has
//! already been parsed. A command never learns which implementation it got, and
//! therefore cannot be the place where the two drift apart.
//!
//! ## Enumeration is a stream, and that is not negotiable
//!
//! `PLAN.md` §16.2 forbids ever materialising the full file list in RAM: a
//! ten-million-object vault has to list on a laptop, and a renderer written
//! against a slice works perfectly on a developer's ten-file fixture and dies on
//! the dataset the tool exists for. [`Source::enumerate`] therefore hands back
//! an [`Entries`] cursor — a thing you pull one entry from — and never a `Vec`.
//!
//! One of the two implementations cannot honour that yet, and says so plainly
//! rather than hiding it: [`Vault::list`](dctl_core::Vault::list) materialises
//! every record before it returns, which is the **core's** limitation and not
//! this layer's. See [`vault`] for exactly where that buffering lives and what
//! removing it will take. The point of drawing the boundary here anyway is that
//! the day it is removed, one `impl` changes and no call site does.
//!
//! The plain implementation has no such excuse and takes none: it walks
//! [`Backend::list_page`](dctl_store::Backend::list_page) cursors and holds one
//! provider page at a time (see [`plain`]).
//!
//! ## Reads are whole-buffer, and wiped on drop
//!
//! [`Source::read`] and [`Source::read_range`] return
//! [`Zeroizing<Vec<u8>>`](zeroize::Zeroizing) rather than a `Read`. Two reasons,
//! and only one of them is the core's:
//!
//! * Plaintext that came out of a vault is key-adjacent material by the time it
//!   is in a buffer, and `PLAN.md` §7 wants it gone from memory when the buffer
//!   dies rather than left in a freed page. A plain store's bytes were never
//!   secret, but one return type means no caller has to know which it is
//!   holding — and wiping bytes that did not need wiping costs a `memset`.
//! * `dctl_core::Vault` exposes `get_file`, which decrypts and authenticates a
//!   whole object, and nothing narrower. A streaming reader here would be a
//!   façade over a buffer that already exists.
//!
//! That makes a vault read O(object) in memory. It is stated on
//! [`Source::read_range`] and repeated in [`vault`] because it is the kind of
//! cost that must be found in the documentation rather than in an OOM.
//!
//! ## The path vocabulary
//!
//! Every path crossing this trait is a **logical path**: `/`-separated, NFC, no
//! leading separator, relative to the source's root. Callers hand in what
//! [`RemoteSpec`](crate::remote::RemoteSpec) or
//! [`Target`](crate::commands::listing::Target) already
//! canonicalised, and get the same spelling back, so a path from a listing can
//! be fed straight to a read without a conversion step that only one of the two
//! implementations would get right.

pub mod entry;
pub mod open;
pub mod plain;
pub mod vault;

pub use entry::Entry;
pub use open::open;

use async_trait::async_trait;
use zeroize::Zeroizing;

use crate::error::Result;

/// A cursor over the objects under one prefix.
///
/// ## The ordering contract
///
/// **Every implementation must yield entries in ascending lexicographic order of
/// logical path, and must never repeat one.** This is not a convenience: the
/// directory aggregation behind `lsd` closes a directory the instant a path
/// leaves it, and `tree` nests without a second pass. Both produce *silently
/// wrong* output — not an error — if a source interleaves subtrees, and silently
/// wrong is the one failure mode this tool may not have. A B-tree range scan and
/// a sorted provider listing both give the ordering for free, which is why it is
/// cheap to demand.
///
/// ## Why not `Iterator`
///
/// Pulling the next entry can perform I/O and can fail, which a `std::iter`
/// signature cannot express without yielding `Result<Entry>` — and the natural
/// `for entry in source` over that *silently truncates* the listing at the first
/// failure unless every caller remembers to break. A truncated listing that
/// exits zero is precisely the misreport `PLAN.md` §6 forbids, so the failure is
/// made unavoidable instead: `next` returns `Result` and the loop cannot advance
/// without handling it.
#[async_trait]
pub trait Entries: Send {
    /// The next entry in path order, or `None` once the prefix is exhausted.
    ///
    /// An exhausted cursor keeps answering `None`; it is never an error to ask
    /// again.
    ///
    /// # Errors
    /// Whatever the index or the provider reported. A failure part-way through
    /// is an error and never a short listing.
    async fn next(&mut self) -> Result<Option<Entry>>;
}

/// Something objects can be listed from and read out of.
///
/// Held behind a `Box<dyn Source>` by every caller, which is what makes the
/// vault/plain decision invisible above [`open`].
#[async_trait]
pub trait Source: Send + Sync {
    /// Open a cursor over every object whose logical path lies under `prefix`.
    ///
    /// `prefix` matches **whole path components**, so listing `photos` does not
    /// report `photos-backup/a.jpg`. Both implementations sit on top of a
    /// byte-wise prefix match — the index's and the provider's — and both
    /// correct it, because a plain `starts_with` here is the bug that makes
    /// `sync` delete a neighbouring tree. An empty prefix addresses everything.
    ///
    /// # Errors
    /// Whatever the index or provider reported while opening the listing.
    async fn enumerate(&self, prefix: &str) -> Result<Box<dyn Entries>>;

    /// Read one object whole.
    ///
    /// # Errors
    /// [`ExitCode::FileNotFound`](crate::exit::ExitCode::FileNotFound) when no
    /// such object exists, and
    /// [`ExitCode::IntegrityFailure`](crate::exit::ExitCode::IntegrityFailure)
    /// when a vault's bytes fail authentication — in which case the data is
    /// **not** returned.
    async fn read(&self, path: &str) -> Result<Zeroizing<Vec<u8>>>;

    /// Read a byte window: `length` of [`None`] means "to the end".
    ///
    /// A window past the end of the object yields fewer bytes than asked for
    /// rather than an error, matching what a `seek` plus a bounded read does on
    /// a local file — `dctl cat --offset` on a file that shrank should report an
    /// honest short read, not a failure.
    ///
    /// **Cost differs by implementation, sharply.** A plain store performs a
    /// genuine ranged read: seeking 40 GB into an object costs one request. A
    /// vault decrypts and authenticates the *whole* object and then slices,
    /// because `dctl_core` exposes no ranged read — so memory and egress are
    /// O(object), not O(window). See [`vault`].
    ///
    /// # Errors
    /// As [`Source::read`].
    async fn read_range(
        &self,
        path: &str,
        offset: u64,
        length: Option<u64>,
    ) -> Result<Zeroizing<Vec<u8>>>;

    /// Describe one object without reading it, or [`None`] if it is not there.
    ///
    /// `None` is the answer for "no such object", never an error, because every
    /// caller of this is asking a question whose negative answer is ordinary:
    /// pre-flighting a `cat` argument, or deciding whether a destination already
    /// holds a file. Reserving the error channel for *failures to look* is what
    /// keeps "it is not there" distinguishable from "we could not tell".
    ///
    /// # Errors
    /// Whatever the index or provider reported while looking.
    async fn stat(&self, path: &str) -> Result<Option<Entry>>;
}
