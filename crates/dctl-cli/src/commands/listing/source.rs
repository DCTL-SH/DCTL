//! Where entries come from, one page at a time.
//!
//! The listing family is written against [`Pages`] and never against a `Vec`,
//! because `PLAN.md` §16.2 is explicit that the full file set is **never** held
//! in RAM: memory stays O(page), not O(files). A renderer that took a slice
//! would work perfectly on a developer's ten-file test vault and fall over on
//! the ten-million-file dataset the tool is designed for, and the fix at that
//! point is a rewrite of all six commands rather than of one `impl`.
//!
//! ## Why a page here and a single entry one layer down
//!
//! [`crate::source::Entries`] — the binary's one read abstraction — hands out
//! one entry per call, which is the right shape for `cat` and for the integrity
//! verbs. The renderers want a batch, because the alternative is a boxed future
//! per object and this is the hot loop of a ten-million-row listing.
//! [`Streamed`] is the adapter: it pulls [`LIST_PAGE_SIZE`] entries and hands
//! them over together. Nothing above it can see past the page it is holding,
//! which is the property that matters.
//!
//! ## The ordering contract
//!
//! **Every implementation must yield entries in ascending lexicographic order of
//! logical path, and must not repeat one.** [`super::dirs`] closes a directory
//! the instant the path leaves it and [`super::super::tree`] nests without a
//! second pass; both produce silently wrong output — not an error — if a source
//! interleaves subtrees. [`crate::source::Entries`] makes the same promise, so
//! honouring it here is a matter of not reordering what arrives.

use async_trait::async_trait;

use crate::constants::LIST_PAGE_SIZE;
use crate::ctx::Ctx;
use crate::error::Result;
#[cfg(test)]
use crate::platform::path;
use crate::source::{self, Entries};

use super::entry::Entry;
use super::target::Target;

/// A cursor over the objects under one listing root.
///
/// Implementors must honour the ordering contract in the module documentation.
#[async_trait]
pub trait Pages: Send {
    /// The next page of entries, or `None` once the listing is exhausted.
    ///
    /// A page is never empty: an implementation that has filtered its last page
    /// down to nothing returns `None` rather than an empty `Vec`, so a caller's
    /// loop cannot spin.
    ///
    /// # Errors
    /// Whatever the underlying index or provider reported. A failure part-way
    /// through a listing is an error, never a short read — a truncated listing
    /// that looked complete would be the worst possible output of a tool whose
    /// central promise is not to misreport (`PLAN.md` §6).
    async fn next_page(&mut self) -> Result<Option<Vec<Entry>>>;

    /// What the sizes on this listing's entries measure.
    ///
    /// Carried up from [`crate::source::Source::sizes`] untouched. Only `size`
    /// reads it — the per-object verbs render a length beside the path it
    /// belongs to, which is unambiguous on its own — but it is exposed here
    /// rather than fetched separately so that the figure and its unit come from
    /// the same source that produced the entries. A basis looked up a second
    /// time is a basis that can end up describing a different listing.
    fn sizes(&self) -> source::Sizes;
}

/// A page cursor over the binary's one read abstraction.
///
/// Holds the [`Source`](crate::source::Source) it enumerated as well as the
/// cursor, because a source is not always inert: a sealed one owns the unlocked
/// vault and the open index the cursor reads through. Dropping it early would
/// work today — the sealed cursor buffers — and would break on the day that
/// buffering is removed, which is the worst possible moment to discover an
/// ownership assumption. It is also what answers [`Pages::sizes`], so the unit
/// a total is reported in comes from the same object that produced the numbers.
pub struct Streamed {
    /// Kept alive for the lifetime of the listing. See above.
    source: Box<dyn source::Source>,
    entries: Box<dyn Entries>,
    root: String,
    page_size: usize,
}

impl Streamed {
    /// Batch `entries` into pages, rooted at `root`.
    fn new(source: Box<dyn source::Source>, entries: Box<dyn Entries>, root: &str) -> Self {
        Self {
            source,
            entries,
            root: root.to_string(),
            // A zero page would make `next_page` return an empty page forever.
            page_size: LIST_PAGE_SIZE.max(1),
        }
    }
}

#[async_trait]
impl Pages for Streamed {
    async fn next_page(&mut self) -> Result<Option<Vec<Entry>>> {
        let mut page = Vec::new();

        while page.len() < self.page_size {
            let Some(entry) = self.entries.next().await? else {
                break;
            };
            page.push(Entry::from_source(entry, &self.root));
        }

        if page.is_empty() {
            Ok(None)
        } else {
            Ok(Some(page))
        }
    }

    fn sizes(&self) -> source::Sizes {
        self.source.sizes()
    }
}

/// A cursor over entries already in memory.
///
/// Not a production path, and `cfg(test)` so that it cannot quietly become one:
/// it is how the renderers' own tests drive a listing whose contents they chose,
/// without a vault, a backend or a temporary directory. It keeps the
/// whole-component root check a real source performs, so a test exercising
/// prefix scoping exercises the same rule the real thing applies.
#[cfg(test)]
pub struct Pager {
    /// Remaining entries, reversed so that a page is a run of cheap pops rather
    /// than an O(n) drain from the front.
    remaining: Vec<source::Entry>,
    root: String,
    page_size: usize,
    /// The basis this pager claims for its sizes. Defaults to the plain one,
    /// which is what a fixture of made-up numbers most resembles.
    sizes: source::Sizes,
}

#[cfg(test)]
impl Pager {
    /// Page over `entries`, which must be sorted ascending by path, at the
    /// default page size.
    #[must_use]
    pub fn new(entries: Vec<source::Entry>, root: impl Into<String>) -> Self {
        Self::with_page_size(entries, root, LIST_PAGE_SIZE)
    }

    /// Page over `entries` at an explicit page size.
    ///
    /// Separate constructor rather than a parameter on [`Pager::new`] because
    /// the page size is a property of the *provider* — one page is one round
    /// trip — and only a test has a reason to choose it.
    #[must_use]
    pub fn with_page_size(
        mut entries: Vec<source::Entry>,
        root: impl Into<String>,
        page_size: usize,
    ) -> Self {
        entries.reverse();
        Self {
            remaining: entries,
            root: root.into(),
            // A zero page would make `next_page` return an empty page forever.
            page_size: page_size.max(1),
            sizes: source::Sizes::Stored,
        }
    }

    /// Claim a different basis for the sizes this pager yields.
    ///
    /// Lets `size`'s tests assert on the sealed wording without unlocking a
    /// vault, which is the only difference the basis makes to any renderer.
    #[must_use]
    pub const fn with_sizes(mut self, sizes: source::Sizes) -> Self {
        self.sizes = sizes;
        self
    }
}

#[cfg(test)]
#[async_trait]
impl Pages for Pager {
    async fn next_page(&mut self) -> Result<Option<Vec<Entry>>> {
        let mut page = Vec::new();

        while page.len() < self.page_size {
            let Some(entry) = self.remaining.pop() else {
                break;
            };

            // The rule a real source applies, applied here too: an index matches
            // a prefix by bytes, so a listing of `photos` also sees
            // `photos-backup`.
            if !path::is_under(&self.root, &entry.path) {
                continue;
            }

            page.push(Entry::from_source(entry, &self.root));
        }

        if page.is_empty() {
            Ok(None)
        } else {
            Ok(Some(page))
        }
    }

    fn sizes(&self) -> source::Sizes {
        self.sizes
    }
}

/// Open a paged view of the objects under `target`.
///
/// One call, whatever the target turns out to be. A sealed vault and a plain
/// directory both arrive here as a [`Source`](crate::source::Source), and this
/// function cannot tell them apart — which is the point. A listing command that
/// could would be a listing command that eventually treats them differently, and
/// then `dctl ls archive:` and `dctl ls ./photos` stop agreeing about what a
/// prefix means.
///
/// # Errors
/// Whatever [`crate::source::open`] reported: an unresolvable remote or an
/// unreadable configuration ([`ExitCode::FatalError`]), or a vault that will not
/// unlock ([`ExitCode::VaultLocked`]). Never an empty listing — reporting "no
/// objects" for something that was never read is the misreport `PLAN.md` §6
/// forbids, and a script that branched on it would delete a backup it believed
/// had already been superseded.
///
/// [`ExitCode::FatalError`]: crate::exit::ExitCode::FatalError
/// [`ExitCode::VaultLocked`]: crate::exit::ExitCode::VaultLocked
pub async fn open(ctx: &Ctx, target: &Target) -> Result<Box<dyn Pages>> {
    let source = source::open(ctx, &target.spec()).await?;
    let entries = source.enumerate(target.prefix()).await?;
    Ok(Box::new(Streamed::new(source, entries, target.prefix())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::listing::tests_support::{ctx, listed};
    use crate::exit::ExitCode;

    async fn drain(pages: &mut dyn Pages) -> Vec<String> {
        let mut out = Vec::new();
        while let Some(page) = pages.next_page().await.expect("the pager cannot fail") {
            assert!(!page.is_empty(), "a page must never be empty");
            out.extend(page.into_iter().map(|entry| entry.path().to_string()));
        }
        out
    }

    #[tokio::test]
    async fn every_entry_is_yielded_exactly_once_in_order() {
        let mut pager = Pager::new(
            vec![
                listed("a.txt", 1, None),
                listed("b/c.txt", 2, None),
                listed("b/d.txt", 3, None),
            ],
            "",
        );
        assert_eq!(drain(&mut pager).await, vec!["a.txt", "b/c.txt", "b/d.txt"]);
    }

    #[tokio::test]
    async fn paging_does_not_change_what_is_yielded() {
        // The property that lets a renderer ignore page boundaries entirely.
        let entries: Vec<source::Entry> = (0..25)
            .map(|n| listed(&format!("f{n:02}.txt"), n, None))
            .collect();
        let whole = drain(&mut Pager::with_page_size(entries.clone(), "", 1000)).await;
        for page_size in [1, 2, 7, 25, 26] {
            let paged = drain(&mut Pager::with_page_size(entries.clone(), "", page_size)).await;
            assert_eq!(paged, whole, "page size {page_size}");
        }
    }

    #[tokio::test]
    async fn a_zero_page_size_cannot_stall_the_listing() {
        let mut pager = Pager::with_page_size(vec![listed("a", 1, None)], "", 0);
        assert_eq!(drain(&mut pager).await, vec!["a"]);
    }

    #[tokio::test]
    async fn an_exhausted_pager_keeps_returning_none() {
        let mut pager = Pager::new(Vec::new(), "");
        assert!(pager.next_page().await.unwrap().is_none());
        assert!(pager.next_page().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_sibling_with_a_shared_prefix_is_not_inside_the_root() {
        // `photos` is not the parent of `photos-backup`. A byte-wise prefix
        // match — which is what the index does — would report both.
        let mut pager = Pager::new(
            vec![
                listed("photos-backup/x.jpg", 1, None),
                listed("photos/a.jpg", 2, None),
                listed("photos", 3, None),
            ],
            "photos",
        );
        assert_eq!(drain(&mut pager).await, vec!["photos/a.jpg", "photos"]);
    }

    #[tokio::test]
    async fn a_page_that_filters_down_to_nothing_ends_the_listing() {
        // Otherwise the caller's `while let Some(page)` loop spins forever.
        let mut pager = Pager::with_page_size(
            vec![listed("other/a", 1, None), listed("other/b", 2, None)],
            "photos",
            1,
        );
        assert!(pager.next_page().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn the_basis_of_the_sizes_travels_with_the_listing() {
        // `size` prints this word beside a number a user reconciles against an
        // invoice, so it has to arrive from the same object that produced the
        // number rather than being decided again further up.
        let entries = vec![listed("a.txt", 1, None)];
        assert_eq!(
            Pager::new(entries.clone(), "").sizes(),
            source::Sizes::Stored
        );
        assert_eq!(
            Pager::new(entries, "")
                .with_sizes(source::Sizes::Plaintext)
                .sizes(),
            source::Sizes::Plaintext
        );
    }

    #[tokio::test]
    async fn a_sealed_listing_reports_plaintext_sizes_and_a_plain_one_stored() {
        // End to end through `open`, so the wiring from `Source::sizes` to the
        // page cursor is exercised rather than assumed. Same directory of bytes,
        // two views, two honest answers about what their numbers mean.
        let dir = tempfile::TempDir::new().unwrap();
        let store = dir.path().join("store");
        std::fs::create_dir_all(&store).unwrap();
        let index = dir.path().join("index.redb");

        {
            use std::sync::Arc;
            let backend: std::sync::Arc<dyn dctl_store::Backend> =
                Arc::new(dctl_store::LocalFs::new(&store));
            let vault = dctl_core::Vault::init(backend, &index, "pw")
                .await
                .unwrap()
                .vault;
            vault.put_file("a.txt", b"hello").await.unwrap();
        }

        let config = dir.path().join("config.toml");
        std::fs::write(
            &config,
            format!(
                "[remotes.store]\ntype = \"local\"\npath = {:?}\nrequire_vault = true\n\n\
                 [remotes.archive]\ntype = \"vault\"\nbase = \"store\"\n",
                store.to_string_lossy()
            ),
        )
        .unwrap();

        let context = ctx(&[
            "--config",
            &config.to_string_lossy(),
            "--index",
            &index.to_string_lossy(),
            "--password",
            "pw",
        ]);

        let sealed = open(&context, &Target::parse(Some("archive:"), None).unwrap())
            .await
            .expect("the vault lists");
        assert_eq!(sealed.sizes(), source::Sizes::Plaintext);

        let plain = open(&context, &Target::parse(Some("store:"), None).unwrap())
            .await
            .expect("the store lists");
        assert_eq!(plain.sizes(), source::Sizes::Stored);
    }

    #[tokio::test]
    async fn entries_are_rooted_at_the_listing_prefix() {
        let mut pager = Pager::new(vec![listed("photos/2024/a.jpg", 1, None)], "photos");
        let page = pager.next_page().await.unwrap().expect("one page");
        assert_eq!(page[0].relative(), "2024/a.jpg");
    }

    #[tokio::test]
    async fn a_local_directory_lists_for_real() {
        // The gap this module used to be: every target, local or remote, came
        // back as "not implemented" because nothing here could reach an engine.
        let root = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(root.path().join("sub")).unwrap();
        std::fs::write(root.path().join("a.txt"), b"1").unwrap();
        std::fs::write(root.path().join("sub/b.txt"), b"22").unwrap();

        let target = Target::parse(Some(&root.path().to_string_lossy()), None).unwrap();
        let mut pages = open(&ctx(&[]), &target).await.expect("a directory lists");
        assert_eq!(drain(pages.as_mut()).await, vec!["a.txt", "sub/b.txt"]);
    }

    #[tokio::test]
    async fn an_empty_directory_lists_as_empty_rather_than_failing() {
        let root = tempfile::TempDir::new().unwrap();
        let target = Target::parse(Some(&root.path().to_string_lossy()), None).unwrap();
        let mut pages = open(&ctx(&[]), &target)
            .await
            .expect("an empty directory still lists");
        assert!(drain(pages.as_mut()).await.is_empty());
    }

    #[tokio::test]
    async fn a_named_plain_remote_lists_through_its_configuration() {
        // `dctl ls store:photos` — a configured remote, resolved from a real
        // file, scoped to a prefix. No vault, so no password anywhere.
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path().join("root");
        std::fs::create_dir_all(root.join("photos")).unwrap();
        std::fs::write(root.join("photos/a.jpg"), b"1").unwrap();
        std::fs::write(root.join("other.txt"), b"2").unwrap();

        let config = dir.path().join("config.toml");
        std::fs::write(
            &config,
            format!(
                "[remotes.store]\ntype = \"local\"\npath = {:?}\n",
                root.to_string_lossy()
            ),
        )
        .unwrap();

        let context = ctx(&["--config", &config.to_string_lossy()]);
        let target = Target::parse(Some("store:photos"), None).unwrap();
        let mut pages = open(&context, &target).await.expect("the remote lists");
        assert_eq!(drain(pages.as_mut()).await, vec!["photos/a.jpg"]);
    }

    #[tokio::test]
    async fn a_sealed_vault_lists_the_plaintext_paths_of_what_it_holds() {
        // The gap this whole abstraction exists to close: `dctl ls archive:`
        // used to answer "reading the object index is not implemented".
        //
        // Everything below is real — a sealed vault written through
        // `Vault::put_file`, a configuration file naming the pair `dctl init`
        // registers, and an unlock through the ordinary password ladder. What
        // comes back is the *plaintext* paths, which is the difference between
        // the sealed view and the store view of the same directory of bytes.
        use std::sync::Arc;

        use dctl_core::Vault;
        use dctl_store::{Backend, LocalFs};

        let dir = tempfile::TempDir::new().unwrap();
        let store = dir.path().join("store");
        std::fs::create_dir_all(&store).unwrap();
        let index = dir.path().join("index.redb");

        {
            let backend: Arc<dyn Backend> = Arc::new(LocalFs::new(&store));
            let vault = Vault::init(backend, &index, "pw").await.unwrap().vault;
            vault.put_file("photos/a.jpg", b"aaa").await.unwrap();
            vault.put_file("notes.txt", b"n").await.unwrap();
        }

        let config = dir.path().join("config.toml");
        std::fs::write(
            &config,
            format!(
                "[remotes.store]\ntype = \"local\"\npath = {:?}\nrequire_vault = true\n\n\
                 [remotes.archive]\ntype = \"vault\"\nbase = \"store\"\n",
                store.to_string_lossy()
            ),
        )
        .unwrap();

        let context = ctx(&[
            "--config",
            &config.to_string_lossy(),
            "--index",
            &index.to_string_lossy(),
            "--password",
            "pw",
        ]);

        let target = Target::parse(Some("archive:"), None).unwrap();
        let mut pages = open(&context, &target).await.expect("the vault lists");
        assert_eq!(
            drain(pages.as_mut()).await,
            vec!["notes.txt", "photos/a.jpg"]
        );

        // The same bytes through the store remote are opaque keys instead —
        // one rule, two honest views, and neither leaks the other's names.
        let store_target = Target::parse(Some("store:"), None).unwrap();
        let mut store_pages = open(&context, &store_target)
            .await
            .expect("the store lists");
        let keys = drain(store_pages.as_mut()).await;
        assert!(!keys.is_empty(), "the sealed objects are really there");
        assert!(
            !keys.iter().any(|key| key.contains("photos")),
            "a plaintext path leaked into the object view: {keys:?}"
        );
    }

    #[tokio::test]
    async fn an_unresolvable_remote_errors_rather_than_reporting_empty() {
        // `PLAN.md` §6: never report an outcome that did not happen. An empty
        // listing here would read as "the vault holds nothing".
        let target = Target::parse(Some("nosuchremote:photos"), None).unwrap();
        let error = open(&ctx(&["--no-ask-password"]), &target)
            .await
            .err()
            .expect("an unconfigured remote cannot be listed");
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.message().contains("nosuchremote"));
        assert!(error.hint().is_some());
    }
}
