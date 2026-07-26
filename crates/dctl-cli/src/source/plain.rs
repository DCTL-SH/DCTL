//! The plain source: an object store, read as it stands.
//!
//! No decryption, no index, no translation — the keys a provider reports are the
//! paths this hands back, and the bytes it stores are the bytes it returns. That
//! is what `dctl ls ./photos` and `dctl ls archive-store:` both need: one is a
//! directory of ordinary files, the other is a directory of a vault's opaque
//! objects, and in neither case is there anything to unseal.
//!
//! ## Pagination is the whole design
//!
//! [`Backend::list_page`] exists because `PLAN.md` §16.2 requires listings to
//! cost O(page) and not O(objects): a bucket with ten million keys must list on a
//! laptop. This implementation therefore walks cursors and holds **one provider
//! page** — one round trip's worth of metadata — no matter how large the store
//! is. Collecting the pages into a `Vec` first would be one line shorter and
//! would put the memory ceiling back where the tool cannot ship with it.
//!
//! Unlike the sealed source, this side has no excuse available to it: the
//! streaming primitive already exists at the layer below, so using anything else
//! would be a choice.
//!
//! ## What is not known here
//!
//! A plain store reports a key, a size and usually a modification time. It does
//! **not** report a plaintext BLAKE3, so [`Entry::content_hash`] stays [`None`]
//! — a provider's own checksum is a statement about the bytes it happens to be
//! holding, which is a different claim from "this is the hash of the file that
//! was written", and rendering one where the other is expected would make
//! `dctl hashsum` quietly wrong.

use std::collections::VecDeque;
use std::sync::Arc;

use async_trait::async_trait;
use dctl_store::{Backend, ByteRange, ObjectKey, ObjectMeta, StoreError};
use zeroize::Zeroizing;

use crate::config::Config;
use crate::error::Result;
use crate::platform::path;
use crate::remote::RemoteSpec;

use super::entry::Entry;
use super::{Entries, Source};

/// An object store, read without interpretation.
pub struct PlainSource {
    backend: Arc<dyn Backend>,
}

impl PlainSource {
    /// Build the backend `spec` names and read it directly.
    ///
    /// Takes the already-loaded configuration rather than reading one, so that
    /// [`super::open`] resolves the file exactly once per run. Two loads would
    /// be two chances to disagree about which remotes exist — and on a run where
    /// the file changed underneath, two different answers to the same question.
    ///
    /// # Errors
    /// [`ExitCode::FatalError`](crate::exit::ExitCode::FatalError) for a remote
    /// the configuration and the provider shorthands both fail to explain, or
    /// for one whose settings are incomplete.
    pub fn open(config: &Config, spec: &RemoteSpec) -> Result<Self> {
        let resolved = crate::remote::resolve::resolve(spec, config)?;
        Ok(Self::new(crate::remote::registry::build(&resolved)?))
    }

    /// Read an already-built backend.
    ///
    /// The seam a test drives: a `LocalFs` over a temporary directory is a real
    /// backend, so the tests below exercise the same code a `local:` remote runs
    /// without needing a configuration file to point at it.
    #[must_use]
    pub const fn new(backend: Arc<dyn Backend>) -> Self {
        Self { backend }
    }
}

#[async_trait]
impl Source for PlainSource {
    async fn enumerate(&self, prefix: &str) -> Result<Box<dyn Entries>> {
        Ok(Box::new(Paged {
            backend: Arc::clone(&self.backend),
            prefix: prefix.to_string(),
            cursor: None,
            exhausted: false,
            page: VecDeque::new(),
        }))
    }

    async fn read(&self, path: &str) -> Result<Zeroizing<Vec<u8>>> {
        let bytes = self.backend.get(&ObjectKey::new(path)).await?;
        Ok(Zeroizing::new(bytes.to_vec()))
    }

    async fn read_range(
        &self,
        path: &str,
        offset: u64,
        length: Option<u64>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let range = ByteRange::new(offset, length);
        match self.backend.get_range(&ObjectKey::new(path), range).await {
            Ok(bytes) => Ok(Zeroizing::new(bytes.to_vec())),
            // The trait promises a short read past the end rather than a
            // failure, so that a window resolved against a size the object no
            // longer has behaves the way a `seek` on a local file does. The
            // backend is stricter; the softening belongs here, at the boundary
            // that made the promise, and not in every caller.
            Err(StoreError::RangeOutOfBounds { .. }) => Ok(Zeroizing::new(Vec::new())),
            Err(error) => Err(error.into()),
        }
    }

    async fn stat(&self, path: &str) -> Result<Option<Entry>> {
        match self.backend.head(&ObjectKey::new(path)).await {
            Ok(meta) => Ok(Some(from_meta(meta))),
            // "Not there" is the ordinary negative answer to this question, so
            // it travels as `Ok(None)`; the error channel stays reserved for a
            // failure to *look*, which is the case a caller must not confuse
            // with an absent object.
            Err(StoreError::NotFound(_)) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
}

/// A cursor that pulls one provider page at a time.
struct Paged {
    backend: Arc<dyn Backend>,
    /// The prefix the listing was opened at, re-sent with every page because a
    /// cursor is only meaningful together with the query that produced it.
    prefix: String,
    /// Where the next page resumes; [`None`] before the first request.
    cursor: Option<String>,
    /// Set once the provider reports no continuation, so an exhausted cursor
    /// answers `None` without issuing further requests.
    exhausted: bool,
    /// The current page, drained from the front. This — and nothing larger — is
    /// the memory a listing of any store costs.
    page: VecDeque<Entry>,
}

impl Paged {
    /// Fetch the next page and load whatever survives the prefix check.
    ///
    /// A page can legitimately produce nothing: the provider matches prefixes by
    /// bytes, so an entire page may consist of `photos-backup/...` keys during a
    /// listing of `photos`. The caller's loop therefore re-enters rather than
    /// concluding the listing is over.
    async fn fetch(&mut self) -> Result<()> {
        let page = self
            .backend
            .list_page(&self.prefix, self.cursor.clone())
            .await?;

        // A provider that returns no items and repeats the cursor it was given
        // has nothing further to say. Believing it would spin forever, and a
        // command that hangs is harder to diagnose than one that stops early —
        // so the listing ends here rather than looping on a broken pager.
        let stalled = page.items.is_empty() && page.next_cursor == self.cursor;

        self.page = page
            .items
            .into_iter()
            // Whole-component containment, for the same reason the sealed source
            // applies it: `photos` is not the parent of `photos-backup`, and a
            // byte-wise match would report a neighbouring tree as though the
            // user had asked for it.
            .filter(|meta| path::is_under(&self.prefix, meta.key.as_str()))
            .map(from_meta)
            .collect();

        self.exhausted = stalled || page.next_cursor.is_none();
        self.cursor = page.next_cursor;
        Ok(())
    }
}

#[async_trait]
impl Entries for Paged {
    async fn next(&mut self) -> Result<Option<Entry>> {
        loop {
            if let Some(entry) = self.page.pop_front() {
                return Ok(Some(entry));
            }
            if self.exhausted {
                return Ok(None);
            }
            self.fetch().await?;
        }
    }
}

/// Translate provider metadata into the provider-neutral entry.
fn from_meta(meta: ObjectMeta) -> Entry {
    // No `with_content_hash`: see the module documentation on why a provider's
    // checksum is not the plaintext hash a vault records.
    Entry::new(meta.key.as_str(), meta.size).with_modified(meta.modified_unix)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dctl_store::LocalFs;
    use std::path::Path;
    use tempfile::TempDir;

    /// A real directory tree behind a real `LocalFs`, with `files` written into
    /// it. The same backend a `local:` remote builds.
    struct Fixture {
        _root: TempDir,
        source: PlainSource,
    }

    fn tree_with(files: &[(&str, &[u8])]) -> Fixture {
        let root = TempDir::new().expect("a temporary directory");
        for (relative, bytes) in files {
            let path = root.path().join(relative);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("the parent directory is created");
            }
            std::fs::write(&path, bytes).expect("the fixture file is written");
        }
        let backend: Arc<dyn Backend> = Arc::new(LocalFs::new(root.path()));
        Fixture {
            _root: root,
            source: PlainSource::new(backend),
        }
    }

    /// A fixture with more objects than one provider page holds, so the paging
    /// loop is genuinely exercised rather than being a code path a small test
    /// never enters.
    fn wide_tree(count: usize) -> (TempDir, PlainSource) {
        let root = TempDir::new().expect("a temporary directory");
        for n in 0..count {
            std::fs::write(root.path().join(format!("f{n:05}.bin")), b"x")
                .expect("the fixture file is written");
        }
        let backend: Arc<dyn Backend> = Arc::new(LocalFs::new(root.path()));
        (root, PlainSource::new(backend))
    }

    async fn paths(source: &PlainSource, prefix: &str) -> Vec<String> {
        let mut cursor = source.enumerate(prefix).await.expect("a listing opens");
        let mut out = Vec::new();
        while let Some(entry) = cursor.next().await.expect("a page cannot fail") {
            out.push(entry.path);
        }
        out
    }

    #[tokio::test]
    async fn every_file_is_enumerated_once_in_path_order() {
        let fixture = tree_with(&[
            ("b/second.txt", b"22"),
            ("a.txt", b"1"),
            ("b/first.txt", b"333"),
        ]);
        assert_eq!(
            paths(&fixture.source, "").await,
            ["a.txt", "b/first.txt", "b/second.txt"]
        );
    }

    #[tokio::test]
    async fn a_prefix_scopes_the_listing_to_whole_components() {
        let fixture = tree_with(&[
            ("photos/a.jpg", b"a"),
            ("photos-backup/b.jpg", b"b"),
            ("other/c.jpg", b"c"),
        ]);
        assert_eq!(paths(&fixture.source, "photos").await, ["photos/a.jpg"]);
    }

    #[tokio::test]
    async fn an_empty_directory_enumerates_to_nothing_without_failing() {
        let fixture = tree_with(&[]);
        let mut cursor = fixture
            .source
            .enumerate("")
            .await
            .expect("an empty listing still opens");
        assert!(cursor.next().await.expect("no failure").is_none());
        assert!(cursor.next().await.expect("no failure").is_none());
    }

    #[tokio::test]
    async fn a_prefix_that_matches_nothing_is_empty_rather_than_everything() {
        let fixture = tree_with(&[("a.txt", b"1")]);
        assert!(paths(&fixture.source, "nowhere").await.is_empty());
    }

    #[tokio::test]
    async fn a_listing_crosses_page_boundaries_without_losing_or_repeating_an_object() {
        // The property the cursor exists for. `LocalFs` pages at a thousand
        // keys, so this spans three pages and would silently truncate if the
        // continuation were dropped.
        let (_root, source) = wide_tree(2_500);
        let listed = paths(&source, "").await;

        assert_eq!(listed.len(), 2_500, "every object must be reported once");
        let mut sorted = listed.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), listed.len(), "no object may repeat");
        assert_eq!(sorted, listed, "entries must arrive in path order");
    }

    #[tokio::test]
    async fn a_read_returns_the_stored_bytes() {
        let fixture = tree_with(&[("notes/today.md", b"as stored")]);
        let bytes = fixture
            .source
            .read("notes/today.md")
            .await
            .expect("the object reads back");
        assert_eq!(bytes.as_slice(), b"as stored");
    }

    #[tokio::test]
    async fn a_missing_path_is_reported_rather_than_read_as_empty() {
        let fixture = tree_with(&[("a.txt", b"1")]);
        let error = fixture
            .source
            .read("nope.txt")
            .await
            .expect_err("a missing object must fail");
        assert_eq!(error.code(), crate::exit::ExitCode::FileNotFound);
        assert!(error.hint().is_some(), "a refusal must say what to do next");
    }

    #[tokio::test]
    async fn a_range_read_returns_exactly_its_window() {
        let fixture = tree_with(&[("a.bin", b"0123456789")]);
        let source = &fixture.source;

        assert_eq!(
            source.read_range("a.bin", 4, Some(3)).await.unwrap().as_slice(),
            b"456"
        );
        assert_eq!(
            source.read_range("a.bin", 7, None).await.unwrap().as_slice(),
            b"789"
        );
        assert_eq!(
            source.read_range("a.bin", 8, Some(999)).await.unwrap().as_slice(),
            b"89"
        );
        // Past the end is a short read, matching what the trait promises and
        // what a seek on a local file does — the backend's own refusal is
        // softened here rather than in each caller.
        assert!(source.read_range("a.bin", 10, Some(5)).await.unwrap().is_empty());
        assert!(source.read_range("a.bin", 4_000, None).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn stat_describes_an_object_and_answers_none_for_a_missing_one() {
        let fixture = tree_with(&[("photos/a.jpg", b"12345")]);

        let found = fixture
            .source
            .stat("photos/a.jpg")
            .await
            .expect("the lookup succeeds")
            .expect("the object is there");
        assert_eq!(found.path, "photos/a.jpg");
        assert_eq!(found.size, 5);
        // A plain store cannot claim a plaintext hash it never recorded.
        assert_eq!(found.content_hash, None);

        assert!(
            fixture
                .source
                .stat("photos/missing.jpg")
                .await
                .expect("the lookup still succeeds")
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_directory_is_not_an_object() {
        // `stat` answers about objects. A directory is not one, and reporting it
        // as a zero-byte object would make `dctl cat` on it look survivable.
        let fixture = tree_with(&[("photos/a.jpg", b"1")]);
        assert!(
            fixture
                .source
                .stat("photos")
                .await
                .expect("the lookup succeeds")
                .is_none()
        );
    }

    #[test]
    fn a_local_spec_needs_no_configuration_to_resolve() {
        // The headless case `PLAN.md` §14 requires: a bare path is a legitimate
        // source with no config file anywhere in sight.
        let root = TempDir::new().unwrap();
        let spec = RemoteSpec::Local(root.path().to_path_buf());
        assert!(PlainSource::open(&Config::default(), &spec).is_ok());
        let _: &Path = root.path();
    }

    #[test]
    fn an_unknown_remote_is_named_rather_than_guessed_at() {
        let spec = RemoteSpec::Named {
            remote: "nosuchremote".into(),
            path: String::new(),
        };
        let error = PlainSource::open(&Config::default(), &spec)
            .err()
            .expect("an unconfigured remote cannot be built");
        assert_eq!(error.code(), crate::exit::ExitCode::FatalError);
        assert!(
            error.message().contains("nosuchremote"),
            "the refusal must name the remote: {}",
            error.message()
        );
    }
}
