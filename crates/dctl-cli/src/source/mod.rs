//! The one way anything in this binary reads stored data.
//!
//! Every read-side verb — `ls`, `lsd`, `lsl`, `lsjson`, `tree`, `size`, `cat`,
//! and the integrity family behind them — needs three capabilities: *tell me
//! what is under this prefix*, *give me these bytes*, and *prove these bytes are
//! still intact without handing them to me*. Those are the methods on
//! [`Source`], and there are exactly two implementations of it: a sealed vault
//! ([`vault`]) and a plain object store ([`plain`]).
//!
//! The third is [`Source::verify`], and it is separate from
//! [`Source::read`] because a scrub must touch every byte of a fifty-gigabyte
//! object without ever holding one. What a pass *means* differs between the two
//! implementations, sharply and unavoidably, so the claim is a value the caller
//! receives rather than an assumption it makes — see [`assurance`] for what a
//! clean read proves about the *bytes*, [`inventory`] for whether the run could
//! have noticed an object that is *gone*, and [`claims`] for why the two travel
//! as one value.
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
//! [`Zeroizing<Vec<u8>>`](zeroize::Zeroizing) rather than a `Read`. Plaintext
//! that came out of a vault is key-adjacent material by the time it is in a
//! buffer, and `PLAN.md` §7 wants it gone from memory when the buffer dies rather
//! than left in a freed page. A plain store's bytes were never secret, but one
//! return type means no caller has to know which it is holding — and wiping bytes
//! that did not need wiping costs a `memset`.
//!
//! The *size* of that buffer is now the caller's to choose on both
//! implementations. [`Source::read`] is whole-object by definition. A
//! [`Source::read_range`] is O(window): a plain store issues a ranged `GET`, and
//! a vault fetches and authenticates only the chunks covering the window
//! (`docs/FORMAT.md` §3) rather than opening the whole object to slice it. That
//! is a change — the vault used to transfer and decrypt everything, which cost
//! +97 MB of resident memory to return a 10-byte window of a 95 MiB object, and
//! it needed a pre-flight warning on `cat` to say so. Both the cost and the
//! warning are gone. See [`vault`] for what a windowed read of a sealed object
//! does and does not authenticate, and [`chunk_cache`] for why the chunks are
//! kept between reads.
//!
//! ## And a hint, which is not a fourth capability
//!
//! [`Source::prefetch`] sits beside the three above and is deliberately not one
//! of them: it returns nothing, promises nothing, and cannot fail in any way a
//! caller could act on. It exists because `PLAN.md` §15 makes *latency*, not
//! decryption, the thing a streaming mount has to hide — a player asking for
//! chunk *k* should find *k+1* already fetched — and only the source knows what
//! "the next chunk" is. The caller says where a reader is heading; each
//! implementation decides what that is worth, and one of the two decides it is
//! worth nothing (see [`plain`], which has no cache for a fetch to land in).
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

pub mod assurance;
pub mod chunk_cache;
pub mod claims;
pub mod entry;
pub mod inventory;
pub mod open;
pub mod plain;
pub mod sizes;
pub mod vault;

pub use assurance::Assurance;
pub use claims::Claims;
pub use entry::Entry;
pub use inventory::Inventory;
// `Opened` is deliberately not re-exported: nothing names the type, because the
// point of it is that a caller receives the source and its scope together and
// asks the value for both. A name in this list would be an invitation to take
// one of the two apart somewhere else.
pub use open::open;
pub use sizes::Sizes;

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

    /// What the walk behind this cursor did about the symbolic links it met.
    ///
    /// Meaningful once the cursor is exhausted, and empty for every source that
    /// walks no filesystem — a sealed vault lists an index, and an index holds
    /// paths rather than directory entries.
    ///
    /// A method on the cursor rather than a field on each entry, because a
    /// skipped link produced *no entry*: that is the whole defect. Anything that
    /// travelled with the entries would therefore have travelled with nothing,
    /// which is how the omission stayed invisible through five commands.
    ///
    /// The provided default is "nothing to say", so a source that genuinely has
    /// none does not have to state it — and a source that walks a tree cannot
    /// forget, because the two backends that do are the two that override.
    fn links(&self) -> dctl_store::LinkReport {
        dctl_store::LinkReport::default()
    }

    /// What the walk behind this cursor passed over that was neither a file, a
    /// directory nor a link.
    ///
    /// Beside [`links`](Entries::links) and for the identical reason: a fifo the
    /// walk skipped produced *no entry*, so nothing that travelled with the
    /// entries could have carried it, and the silence went through five
    /// commands. Empty for every source that walks no filesystem.
    fn specials(&self) -> dctl_store::SpecialReport {
        dctl_store::SpecialReport::default()
    }
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

    /// Enumerate as the **destination of a transfer**: every entry must
    /// describe what is restorably there, not what a local record believes.
    ///
    /// The default is [`enumerate`](Source::enumerate), which is correct for
    /// every source whose listing already *is* the store — a plain remote pages
    /// the provider's own listing, and a deleted key simply is not in it. The
    /// sealed source overrides this: its ordinary listing answers from the
    /// local index, and an index row whose stored object was deleted behind
    /// the tool's back looks exactly like a live file — size, mtime, hash, all
    /// describing bytes that are no longer restorable. A nightly that compared
    /// against those rows reported `Checks: 150/150, Errors: 0` over a
    /// destination that had lost data, and the loss surfaced at restore. The
    /// override reconciles the rows against the backend's own object listing
    /// and marks the casualties ([`Entry::object_missing`]), so the planner
    /// re-uploads them.
    ///
    /// A separate method rather than a flag on `enumerate` so the price — one
    /// paginated backend listing — is paid exactly where the honesty is owed:
    /// `ls`, `tree`, `size` and source-side walks keep the index's speed.
    ///
    /// # Errors
    /// As [`enumerate`](Source::enumerate), plus whatever the backend's
    /// listing reported.
    async fn enumerate_destination(&self, prefix: &str) -> Result<Box<dyn Entries>> {
        self.enumerate(prefix).await
    }

    /// Whether the object behind `path` is actually there — in the *store*,
    /// not merely in a record of it.
    ///
    /// For a source whose listing is the store, presence in the listing IS
    /// presence, and the honest implementation is a constant `true`. For the
    /// sealed source the two can disagree — an index row survives the deletion
    /// of its object — and this is the probe that tells them apart. Required
    /// rather than defaulted: a source added later must say which kind it is,
    /// because a default `true` on a recorded listing is exactly the ghost-row
    /// `Match` this method exists to prevent.
    ///
    /// # Errors
    /// Whatever the probe reported. "Could not ask" must surface as an error,
    /// never as either answer.
    async fn exists(&self, path: &str) -> Result<bool>;

    /// What the `size` on every [`Entry`] this source yields measures.
    ///
    /// Not a way to ask which implementation is in hand — see [`sizes`] — but
    /// the unit the numbers are in, which `dctl size` has to print because it
    /// reduces a whole vault to one figure that people reconcile against a
    /// provider invoice. A total that does not say whether it counted plaintext
    /// or ciphertext is a number two readers will read two ways, and `PLAN.md`
    /// §6's rule against misreporting covers being ambiguous just as much as it
    /// covers being wrong.
    fn sizes(&self) -> Sizes;

    /// Read one object whole.
    ///
    /// # Errors
    /// [`ExitCode::FileNotFound`](crate::exit::ExitCode::FileNotFound) when no
    /// such object exists, and
    /// [`ExitCode::IntegrityFailure`](crate::exit::ExitCode::IntegrityFailure)
    /// when a vault's bytes fail authentication — in which case the data is
    /// **not** returned.
    async fn read(&self, path: &str) -> Result<Zeroizing<Vec<u8>>>;

    /// Write one object's entire contents to `out`, holding none of it.
    ///
    /// The constant-memory form of [`Source::read`], and the one every caller
    /// that is going to *write the bytes somewhere* should use. `read` returns a
    /// `Vec`, so `dctl cat` of an 806 MiB object peaked at 1624 MiB of resident
    /// memory and a 10 GB video needed 20 GB of RAM — for a command whose entire
    /// job is to move bytes from one place to another without keeping them.
    ///
    /// **The whole-object statement is preserved, and that is the point.** A
    /// sealed source streams in bounded windows while folding a BLAKE3 over the
    /// plaintext and comparing it against the hash the object itself records, so
    /// this makes exactly the claim `read` makes — unlike
    /// [`Source::read_range`], which cannot, because it never sees the bytes
    /// outside its window. Serving a whole-object request through the ranged
    /// path would have been the easy way to bound the memory and it would have
    /// quietly traded away the check.
    ///
    /// **Bytes reach `out` before that statement completes.** Each has been
    /// authenticated by its own chunk's tag, but the final comparison cannot
    /// happen until the last byte has been hashed, so a caller writing to a pipe
    /// may already have emitted a prefix when this returns an integrity failure.
    /// That is unavoidable for a stream and it is why the transfer commands
    /// write through a staging file and a rename instead.
    ///
    /// # Errors
    /// As [`Source::read`], plus any failure to write to `out`.
    async fn stream_to(
        &self,
        path: &str,
        out: &mut (dyn tokio::io::AsyncWrite + Unpin + Send),
    ) -> Result<u64>;

    /// Read a byte window: `length` of [`None`] means "to the end".
    ///
    /// A window past the end of the object yields fewer bytes than asked for
    /// rather than an error, matching what a `seek` plus a bounded read does on
    /// a local file — `dctl cat --offset` on a file that shrank should report an
    /// honest short read, not a failure.
    ///
    /// **Both implementations serve a window at O(window), and an implementation
    /// that cannot must not be added silently.** A plain store issues a ranged
    /// `GET`; a vault computes the chunks covering the window from the object's
    /// authenticated geometry and fetches exactly those (`docs/FORMAT.md` §3).
    /// Seeking 40 GB into an object costs one request on either. A source that
    /// served a window by moving the whole object would make `dctl cat --count 4`
    /// a 40 GB transfer that returns four bytes and exits 0 — a cost discovered
    /// on an invoice, with nothing tying it to the command. The vault did exactly
    /// that until it learned to read a chunk range, and the announcement it
    /// needed in the meantime is gone with it.
    ///
    /// **What a window authenticates is not what a whole read authenticates.** On
    /// a vault every returned byte carries a Poly1305 tag binding it to this
    /// object at this chunk index, but the footer BLAKE3 and the object's
    /// recorded whole-plaintext hash both cover bytes a window never fetched and
    /// are therefore *not* checked here. That is by design and not a shortcut —
    /// [`Source::verify`] is the read that makes the whole-object statement. See
    /// [`vault`].
    ///
    /// # Errors
    /// As [`Source::read`].
    async fn read_range(
        &self,
        path: &str,
        offset: u64,
        length: Option<u64>,
    ) -> Result<Zeroizing<Vec<u8>>>;

    /// The BLAKE3 of one object's **plaintext**, when this source can establish
    /// one, or [`None`] when the object is not there.
    ///
    /// The value `--checksum` compares, and the reason it is a method rather
    /// than a field on [`Entry`] is that the two implementations pay wildly
    /// different prices for it. A vault already knows: it recorded the digest at
    /// write time under the verified-write contract, and answering costs an
    /// index lookup. A plain store has to **read the object** — and it can,
    /// because a plain store's bytes *are* the plaintext, so the hash of what it
    /// holds is exactly the hash a vault would have recorded for the same file.
    ///
    /// # Why the price is worth paying rather than refusing the flag
    ///
    /// `--checksum` into a plain destination used to work exactly once. The
    /// first run into an empty destination exited 0 because there was nothing to
    /// compare; every run after it exited **7** with
    /// `--checksum: no content hash for '<file>'` (`HANDOVER.md` §11.2). A
    /// nightly job that succeeds on the first night and fails every night after
    /// is worse than one that never worked.
    ///
    /// Reading to answer is not a new cost model, it is the *existing* one:
    /// `--checksum` already reads and hashes every file on the local side, and
    /// `super::super::commands::transfer::checksum` already documents that
    /// comparing two local trees costs a full pass over both. What was missing
    /// was the other half of that pass. Where the plain side is a network
    /// remote the cost is real and is announced once per run rather than
    /// discovered on an invoice — see
    /// [`CHECKSUM_READS_DESTINATION_NOTE`](crate::constants::CHECKSUM_READS_DESTINATION_NOTE).
    ///
    /// The alternative — refusing `--checksum` at the flag — was the other
    /// option on the table and is the weaker one: it makes a nightly
    /// `--checksum sync` to a plain remote work zero times instead of once, and
    /// rclone answers the same question by negotiating a hash both sides can
    /// produce (`fs/operations/operations.go:60-66`) rather than by refusing.
    ///
    /// # Errors
    /// Whatever reading the object reported. A `--checksum` run that cannot read
    /// one object has to say which, because the alternative is a comparison
    /// silently made on incomplete information.
    async fn content_hash(&self, path: &str) -> Result<Option<Vec<u8>>>;

    /// Warm whatever this source caches for `[offset, offset + length)`, ahead of
    /// a read that has not happened yet.
    ///
    /// A hint, and shaped like one: no return value, no error channel, no promise
    /// that anything was fetched. That is not laziness about the signature — it is
    /// the only honest shape. Nothing has been asked for on a user's behalf, so
    /// there is no operation to report as having failed, and the read that follows
    /// meets the same failure and reports it with a path and a reason. A `Result`
    /// here would invite a caller to surface a warning about a request the user
    /// never made.
    ///
    /// **The reason this is on the trait rather than inside one implementation.**
    /// `PLAN.md` §15 makes latency, not decryption, the thing a streaming mount
    /// has to hide: a player asking for chunk *k* should find *k+1* already
    /// fetched. Only the source knows what "the next chunk" is — for a vault it is
    /// a covering-chunk range in the decrypted-chunk cache, and for a plain store
    /// there is no cache to warm at all — so the caller states *where the reader
    /// is going* and each implementation decides what that is worth.
    ///
    /// Deliberately not given a default implementation. A default no-op would let
    /// a source added later silently lose read-ahead, and a mount that quietly
    /// stopped hiding latency is a performance regression with nothing to point
    /// at; an explicit empty body says "there is nothing to warm here" and can be
    /// read as the decision it is.
    async fn prefetch(&self, path: &str, offset: u64, length: u64);

    /// Declare the working set this source should keep resident, in bytes and
    /// entries.
    ///
    /// A hint like [`prefetch`](Source::prefetch), and for the same reason: no
    /// promise, no error channel. A source with a cache raises its budget to at
    /// least this — never lowers it below its own floor — and a source without one
    /// has nothing to size.
    ///
    /// The caller that knows the working set is the mount: read-ahead keeps
    /// `depth` windows in flight, and warming windows a cache cannot hold evicts
    /// the chunks the reader is about to ask for — every warmed byte fetched
    /// twice, which is worse than no read-ahead at all. Stating the budget where
    /// the depth is chosen keeps the two from drifting apart.
    ///
    /// Not defaulted, exactly as `prefetch` is not: an implementation must say
    /// "there is nothing to size here" in its own body, where the statement can
    /// be read as the decision it is.
    fn tune_cache(&self, bytes: usize, max_chunks: usize);

    /// Describe one object without reading it, or [`None`] if it is not there.
    ///
    /// `None` is the answer for "no such object", never an error, because every
    /// caller of this is asking a question whose negative answer is ordinary:
    /// pre-flighting a `cat` argument, or deciding whether a destination already
    /// holds a file. Reserving the error channel for *failures to look* is what
    /// keeps "it is not there" distinguishable from "we could not tell".
    ///
    /// **Accuracy outranks cheapness here.** Every range flag is resolved
    /// against the size this returns, so a size that is merely *plausible* makes
    /// `dctl cat` write the wrong number of bytes and exit 0. An implementation
    /// that cannot describe an object from metadata alone must read it rather
    /// than answer with a placeholder; where that can happen is documented on
    /// the implementation (see [`vault`]).
    ///
    /// That is why a `Some` from here always carries a measured
    /// [`Entry::size`], even though an *enumeration* legitimately yields entries
    /// whose size nobody ever measured. Enumerating a vault must not cost a full
    /// read of it, so a listing reports the absence honestly; a `stat` is asked
    /// about one object by name and pays the read rather than leaving its caller
    /// to invent a length.
    ///
    /// # Errors
    /// Whatever the index or provider reported while looking.
    async fn stat(&self, path: &str) -> Result<Option<Entry>>;

    /// Re-read one object end to end and prove it is intact, without
    /// materialising it.
    ///
    /// This is what `dctl scrub` runs, and the reason it is not
    /// [`Source::read`] with the result thrown away: memory here is O(chunk) or
    /// O(window), never O(object), so a fifty-gigabyte object is scrubbed on a
    /// laptop. Nothing is returned on success because there is nothing a caller
    /// should do with the bytes — asking for them is what `read` is for, and a
    /// verification that also handed back plaintext would be one refactor away
    /// from serving data that failed the check.
    ///
    /// **What a pass proves depends on the source** ([`Source::assurance`]).
    /// A sealed vault authenticates every chunk against a key and compares the
    /// object's own recorded content hash; a plain store has nothing to compare
    /// against and can only establish that every byte came back. Callers that
    /// publish a verdict must publish the assurance with it.
    ///
    /// # Errors
    /// [`ExitCode::FileNotFound`](crate::exit::ExitCode::FileNotFound) when the
    /// object is gone,
    /// [`ExitCode::IntegrityFailure`](crate::exit::ExitCode::IntegrityFailure)
    /// when its bytes are not the bytes that were stored, and
    /// [`ExitCode::TemporaryError`](crate::exit::ExitCode::TemporaryError) when
    /// the provider never answered. Those three are different findings and a
    /// caller is expected to keep them apart.
    async fn verify(&self, path: &str) -> Result<()>;

    /// The strongest claim a successful [`Source::verify`] supports here.
    ///
    /// Synchronous and infallible: it is a property of the *kind* of source, not
    /// of any object in it, so a report can state what a run will prove before
    /// the run starts rather than after the bill arrives.
    fn assurance(&self) -> Assurance;

    /// Where the list of objects a run over this source examines comes from —
    /// and therefore whether an object that is **gone** can be noticed.
    ///
    /// Beside [`Source::assurance`] and deliberately not folded into it: the two
    /// answer different questions and do not move together. A plain B2 remote
    /// reports [`Assurance::ProviderChecksum`], because the provider recorded a
    /// digest at write time, and [`Inventory::SelfReported`], because the only
    /// list of what it holds is the list it just produced. A gate that read the
    /// first and assumed the second let a **deleted** object exit 0 on every
    /// plain remote there is (`HANDOVER.md` §36).
    ///
    /// **Deliberately not given a default implementation.** A default of
    /// [`Inventory::Recorded`] would let a source added later claim to detect a
    /// loss it cannot see, and a default of [`Inventory::SelfReported`] would
    /// silently downgrade a source that does keep a record. Both are decisions
    /// the implementation has to make out loud; see [`inventory`] for why the
    /// weaker of the two is not repairable by writing a manifest.
    fn inventory(&self) -> Inventory;
}
