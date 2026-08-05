//! One of the two trees a comparison reads.
//!
//! `check` is symmetrical: neither argument is privileged, and both are opened
//! the same way through [`crate::source::open`], so `dctl check archive: ./photos`
//! and `dctl check ./photos archive:` are the same walk with the labels swapped.
//! Everything that could make the two sides behave differently — a vault chain
//! followed on one side only, a prefix applied to one and not the other — is
//! avoided by there being exactly one `Side` type and one way to build it.
//!
//! ## Comparison keys, and why they are not the paths
//!
//! The two sides address their objects differently. A remote side rooted at
//! `photos` yields `photos/a.jpg`; a local side pointed at `./photos` yields
//! `a.jpg`. Comparing those directly would report every file as missing on both
//! sides at once. So each side reports a **key** — the path relative to its own
//! root — and keeps the full path privately for the reads it may have to do.
//!
//! The degenerate case is a root that names one object rather than a tree
//! (`archive:photos/a.jpg`), where the relative path is empty. The key is then
//! the object's own name, because an empty key would collide with any other
//! side's empty key and compare two unrelated objects as though they were one.
//!
//! ## Streaming, and the one entry held
//!
//! A side holds exactly one entry at a time — the lookahead the merge in
//! [`super::walk`] needs — on top of the [`Entries`] cursor, which is itself
//! O(page). Comparing two ten-million-object trees therefore costs two entries
//! of memory, not twenty million, which is what [the plan](https://doc.dctl.sh/project/plan) §16.2 requires and
//! what makes `check` usable on the datasets it exists for.
//!
//! ## Filters
//!
//! The global `--include`/`--exclude`/`--max-depth`/size flags are applied here,
//! through the listing family's [`Filter`] — the binary's one implementation of
//! those patterns. A second implementation would eventually disagree with `ls`
//! about which files exist, and a user reconciling a `check` against a listing
//! would have no way to tell which of the two was lying.
//!
//! The filter is applied to **both** sides identically. Filtering only the
//! source would report every excluded file as `missing-on-src`, which is a
//! finding manufactured by the filter rather than by the data.

use crate::commands::listing::{self, Filter};
use crate::ctx::Ctx;
use crate::error::Result;
use crate::output::hex;
use crate::platform::path;
use crate::source::{self, Entries, Source};

use super::difference::Entry;

/// One object as one side described it.
pub struct Found {
    /// The full logical path inside that side's source, which is what a read
    /// needs. Never printed in the report: it speaks in keys, so that a path
    /// appearing in `--missing-on-dst` can be fed straight to `dctl copy
    /// --files-from`. The accessor exists for the ghost-row warning, which
    /// names the path an operator must go look at.
    path: String,
    /// The comparison view, keyed relative to the side's own root.
    pub entry: Entry,
}

impl Found {
    /// The full logical path inside the side's source.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
}

impl Found {
    /// The comparison key: what both sides have to agree on for a path to be
    /// considered the same object.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.entry.path
    }
}

/// One tree, opened and being walked in path order.
pub struct Side {
    /// Kept for the lifetime of the walk. A sealed source owns the unlocked
    /// vault and the open index its cursor reads through, so dropping it early
    /// would work today — the sealed cursor buffers — and break the day that
    /// buffering is removed.
    source: Box<dyn Source>,
    entries: Box<dyn Entries>,
    /// The logical prefix this side was opened at; empty for a local directory,
    /// whose scoping lives in the path the source itself was built on.
    root: String,
    filter: Filter,
    /// The one entry of lookahead the merge needs.
    head: Option<Found>,
    /// Set once the cursor has answered `None`, so an exhausted side stops
    /// asking the provider.
    exhausted: bool,
}

impl Side {
    /// Open the tree `target` names.
    ///
    /// # Errors
    /// Whatever [`crate::source::open`] reported: an unresolvable remote or an
    /// unreadable configuration, or a vault that will not unlock. Never an empty
    /// listing — a comparison against a tree that was never read would report
    /// every path as missing and invite a user to "repair" it by copying a whole
    /// dataset over one that was fine.
    pub async fn open(ctx: &Ctx, target: &super::Target, filter: Filter) -> Result<Self> {
        let opened = source::open(ctx, &target.spec()).await?;
        let entries = opened.enumerate().await?;
        let root = opened.prefix().to_string();
        let source = opened.into_source();
        Ok(Self {
            source,
            entries,
            root,
            filter,
            head: None,
            exhausted: false,
        })
    }

    /// The next entry in key order without consuming it.
    ///
    /// # Errors
    /// Whatever the index or provider reported. A failure part-way through is an
    /// error and never a short listing, because a truncated side would be
    /// reported as a tree that is missing the files it never got to.
    pub async fn peek(&mut self) -> Result<Option<&Found>> {
        while self.head.is_none() && !self.exhausted {
            let Some(entry) = self.entries.next().await? else {
                self.exhausted = true;
                break;
            };

            // Building the listing view costs a clone of the path, so it is
            // skipped entirely when no filter is in force — which is the case on
            // every run that does not ask for one.
            if self.filter.is_restricting()
                && !self
                    .filter
                    .matches(&listing::Entry::from_source(entry.clone(), &self.root))
            {
                continue;
            }

            self.head = Some(found(entry, &self.root));
        }
        Ok(self.head.as_ref())
    }

    /// Take the entry [`Side::peek`] reported.
    pub fn take(&mut self) -> Option<Found> {
        self.head.take()
    }

    /// The content hash of one object, read back if the source recorded none.
    ///
    /// A vault knows the plaintext BLAKE3 of everything it holds and answers
    /// from the index for nothing; an object store does not, and the only honest
    /// way to obtain one is to read the object and hash it. That is what
    /// `--checksum` costs against anything but a vault, and it is the reason the
    /// flag means something at all: refusing to compute the hash would leave the
    /// only comparison that proves contents permanently unusable against a local
    /// tree.
    ///
    /// Memory is O(object): [`Source::read`] is the only read this layer has, as
    /// its own documentation says. The cost is documented rather than capped —
    /// a size limit would trade a stated cost for an arbitrary refusal.
    ///
    /// # Errors
    /// Whatever the read reported, including an
    /// [`ExitCode::IntegrityFailure`](crate::exit::ExitCode::IntegrityFailure)
    /// for a vault object whose bytes do not authenticate. The caller turns that
    /// into [`Difference::Error`](super::difference::Difference::Error) for the
    /// path rather than failing the whole run, so one damaged object does not
    /// hide the state of everything after it.
    pub async fn hash(&self, found: &Found) -> Result<String> {
        if let Some(recorded) = &found.entry.hash {
            return Ok(recorded.clone());
        }
        let bytes = self.source.read(&found.path).await?;
        Ok(hex::encode(blake3::hash(&bytes).as_bytes()))
    }

    /// Whether this side's listing is a record rather than the store itself.
    ///
    /// The question that decides whether an entry needs confirming: a
    /// `Recorded` inventory can list a path whose object is gone, and a
    /// comparison that trusted the row would call the loss a `Match`.
    #[must_use]
    pub fn recorded(&self) -> bool {
        matches!(self.source.inventory(), crate::source::Inventory::Recorded)
    }

    /// Ask the store — not the listing — whether `found`'s object is there.
    ///
    /// One existence probe, no payload bytes. Only worth calling on a
    /// [`recorded`](Side::recorded) side; a self-reported listing already IS
    /// the store's answer.
    ///
    /// # Errors
    /// Whatever the probe reported. The caller must turn that into
    /// [`Difference::Error`](super::difference::Difference::Error) rather than
    /// either verdict — "could not ask" is a third answer.
    pub async fn confirm(&self, found: &Found) -> Result<bool> {
        self.source.exists(&found.path).await
    }
}

/// Convert a source entry into this side's view of it.
fn found(entry: source::Entry, root: &str) -> Found {
    let mut view = Entry::new(key_for(&entry.path, root), entry.size);
    if let Some(unix) = entry.modified_unix {
        view = view.modified(unix);
    }
    // A recorded hash is carried across; an absent one stays absent, so that
    // `Comparison::same` can tell "not comparable" from "different" rather than
    // being handed an invented value.
    if let Some(digest) = &entry.content_hash {
        view = view.hashed(hex::encode(digest));
    }
    Found {
        path: entry.path,
        entry: view,
    }
}

/// The comparison key for `full` inside a side rooted at `root`.
///
/// Whole-component containment, not a byte-wise strip: `photos` is not the
/// parent of `photos-backup`, and taking `root.len()` bytes off the latter would
/// produce the key `-backup/a.jpg` and compare it against nothing.
fn key_for(full: &str, root: &str) -> String {
    let root = root.trim_end_matches(path::SEPARATOR);
    if root.is_empty() || !path::is_under(root, full) {
        return full.to_string();
    }
    if full.len() == root.len() {
        // The root names this one object. Its own name is the only key that can
        // meet the other side, whose root is a directory containing it.
        return path::file_name(full).to_string();
    }
    full.get(root.len() + path::SEPARATOR.len_utf8()..)
        .unwrap_or(full)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::GlobalArgs;
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn ctx(args: &[&str]) -> Ctx {
        Ctx::new(Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied())).globals)
    }

    fn tree(files: &[(&str, &[u8])]) -> tempfile::TempDir {
        let root = tempfile::TempDir::new().expect("a temporary directory");
        for (relative, bytes) in files {
            let path = root.path().join(relative);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("the parent directory is created");
            }
            std::fs::write(&path, bytes).expect("the fixture file is written");
        }
        root
    }

    async fn keys(side: &mut Side) -> Vec<String> {
        let mut out = Vec::new();
        while side.peek().await.expect("the side reads").is_some() {
            let found = side.take().expect("peek reported an entry");
            out.push(found.key().to_string());
        }
        out
    }

    async fn side(ctx: &Ctx, spec: &str, filter: Filter) -> Side {
        let target = super::super::Target::parse(spec).expect("a well-formed target");
        Side::open(ctx, &target, filter)
            .await
            .expect("the side opens")
    }

    #[tokio::test]
    async fn a_side_yields_keys_relative_to_its_own_root() {
        // The property the whole comparison rests on: two differently-rooted
        // sides describe the same file with the same key.
        let root = tree(&[("a.txt", b"1"), ("sub/b.txt", b"22")]);
        let mut local = side(&ctx(&[]), &root.path().to_string_lossy(), Filter::default()).await;
        assert_eq!(keys(&mut local).await, vec!["a.txt", "sub/b.txt"]);
    }

    #[tokio::test]
    async fn an_exhausted_side_keeps_answering_none() {
        let root = tree(&[]);
        let mut empty = side(&ctx(&[]), &root.path().to_string_lossy(), Filter::default()).await;
        assert!(empty.peek().await.unwrap().is_none());
        assert!(empty.peek().await.unwrap().is_none());
        assert!(empty.take().is_none());
    }

    #[tokio::test]
    async fn filters_apply_while_the_side_is_walked() {
        let root = tree(&[("a.jpg", b"1"), ("b.txt", b"2")]);
        let context = ctx(&["--include", "*.jpg"]);
        let filter = Filter::from_globals(&context.globals).expect("the pattern compiles");
        let mut only_jpg = side(&context, &root.path().to_string_lossy(), filter).await;
        assert_eq!(keys(&mut only_jpg).await, vec!["a.jpg"]);
    }

    #[tokio::test]
    async fn a_hash_is_computed_from_the_object_when_the_source_recorded_none() {
        // A plain store knows no plaintext hash, so `--checksum` against one is
        // only meaningful because the bytes are read and hashed here.
        let root = tree(&[("a.txt", b"hello world")]);
        let mut plain = side(&ctx(&[]), &root.path().to_string_lossy(), Filter::default()).await;
        plain.peek().await.unwrap().expect("one entry");
        let found = plain.take().expect("one entry");
        assert_eq!(found.entry.hash, None, "a plain store records no hash");
        assert_eq!(
            plain.hash(&found).await.unwrap(),
            blake3::hash(b"hello world").to_hex().to_string()
        );
    }

    #[test]
    fn a_key_strips_whole_components_only() {
        assert_eq!(key_for("photos/a.jpg", "photos"), "a.jpg");
        assert_eq!(key_for("photos/a.jpg", "photos/"), "a.jpg");
        assert_eq!(key_for("a.jpg", ""), "a.jpg");
        // `photos` is not the parent of `photos-backup`; a byte-wise strip would
        // produce "-backup/a.jpg".
        assert_eq!(
            key_for("photos-backup/a.jpg", "photos"),
            "photos-backup/a.jpg"
        );
        // A root that names one object keys it by its own name, so it can meet
        // the same file inside a directory on the other side.
        assert_eq!(key_for("photos/a.jpg", "photos/a.jpg"), "a.jpg");
        // Multibyte roots are stripped on a character boundary.
        assert_eq!(key_for("caf\u{e9}/a.jpg", "caf\u{e9}"), "a.jpg");
    }
}
