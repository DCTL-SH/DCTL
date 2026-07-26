//! Where entries come from, one page at a time.
//!
//! The listing family is written against [`Pages`] and never against a `Vec`,
//! because `PLAN.md` §16.2 is explicit that the full file set is **never** held
//! in RAM: memory stays O(concurrency), not O(files). A renderer that took a
//! slice would work perfectly on a developer's ten-file test vault and fall over
//! on the ten-million-file dataset the tool is designed for, and the fix at that
//! point is a rewrite of all six commands rather than of one `impl`.
//!
//! ## Today's reality
//!
//! [`Vault::list`](dctl_core::Vault::list) materialises every record before
//! returning — it says so in its own documentation — so [`Pager`] pages over a
//! `Vec` that already exists. That is a smaller lie than it looks: the trait
//! boundary is where it belongs, the renderers cannot see past the current page,
//! and when the index grows a range cursor the change is confined to a new
//! `impl Pages` beside this one.
//!
//! ## The ordering contract
//!
//! **Every implementation must yield entries in ascending lexicographic order of
//! logical path, and must not repeat one.** [`super::dirs`] closes a directory
//! the instant the path leaves it and [`super::super::tree`] nests without a
//! second pass; both produce silently wrong output — not an error — if a source
//! interleaves subtrees. A B-tree range scan gives this for free, which is why
//! it is cheap to require.

use dctl_core::Record;

use crate::constants::{
    LIST_PAGE_SIZE, LISTING_ENGINE_HINT, LISTING_ENGINE_STAGE, LOCAL_LISTING_FEATURE,
    LOCAL_LISTING_HINT,
};
use crate::ctx::Ctx;
use crate::error::{CliError, Result};
use crate::platform::path;

use super::entry::Entry;
use super::target::Target;

/// A cursor over the objects under one listing root.
///
/// Implementors must honour the ordering contract in the module documentation.
pub trait Pages {
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
    fn next_page(&mut self) -> Result<Option<Vec<Entry>>>;
}

/// A cursor over records already in memory.
///
/// The adapter between what the vault hands back today and the paged interface
/// the renderers are written against.
pub struct Pager {
    /// Remaining records, reversed so that a page is a run of cheap pops rather
    /// than an O(n) drain from the front.
    remaining: Vec<Record>,
    root: String,
    page_size: usize,
}

impl Pager {
    /// Page over `records`, which must be sorted ascending by path, at the
    /// default page size.
    #[must_use]
    pub fn new(records: Vec<Record>, root: impl Into<String>) -> Self {
        Self::with_page_size(records, root, LIST_PAGE_SIZE)
    }

    /// Page over `records` at an explicit page size.
    ///
    /// Separate constructor rather than a parameter on [`Pager::new`] because
    /// the page size is a property of the *provider* — one page is one round
    /// trip — and only a test has a reason to choose it.
    #[must_use]
    pub fn with_page_size(
        mut records: Vec<Record>,
        root: impl Into<String>,
        page_size: usize,
    ) -> Self {
        records.reverse();
        Self {
            remaining: records,
            root: root.into(),
            // A zero page would make `next_page` return an empty page forever.
            page_size: page_size.max(1),
        }
    }
}

impl Pages for Pager {
    fn next_page(&mut self) -> Result<Option<Vec<Entry>>> {
        let mut page = Vec::new();

        while page.len() < self.page_size {
            let Some(record) = self.remaining.pop() else {
                break;
            };

            // The index matches a prefix by bytes, so a listing of `photos`
            // also sees `photos-backup`. Comparing whole components here is
            // what stops `dctl ls vault:photos` from reporting a neighbouring
            // tree as if it were inside the one that was asked for.
            if !path::is_under(&self.root, &record.path) {
                continue;
            }

            page.push(Entry::from_record(record, &self.root));
        }

        if page.is_empty() {
            Ok(None)
        } else {
            Ok(Some(page))
        }
    }
}

/// Open a paged view of the objects under `target`.
///
/// # Not implemented yet
///
/// This is the one step of the listing pipeline that cannot run. [`Ctx`] carries
/// the resolved flags, the output sink and the counters, but no vault handle —
/// unlocking one is the dispatcher's job and that wiring does not exist — so
/// there is nothing to ask for records. Everything either side of this call is
/// complete and tested: the spec grammar, the filters, the ordering contract,
/// the directory aggregation, the tree layout and all three output formats.
///
/// It returns an **error**, never an empty listing. Reporting "no objects" for
/// a vault that was never read is exactly the misreport `PLAN.md` §6 forbids,
/// and a script that branched on an empty listing would then delete a backup it
/// believed had already been superseded.
///
/// When `Ctx` grows a vault, [`index_records`] becomes a one-line call to
/// [`Vault::list`](dctl_core::Vault::list) and nothing else here changes.
///
/// # Errors
/// [`ExitCode::FatalError`](crate::exit::ExitCode::FatalError) while the engine
/// is unreachable, and for a local target, whose directory walk is a separate
/// unbuilt piece.
pub fn open(ctx: &Ctx, target: &Target) -> Result<Box<dyn Pages>> {
    if !target.is_remote() {
        return Err(CliError::unimplemented(LOCAL_LISTING_FEATURE).with_hint(LOCAL_LISTING_HINT));
    }

    let Some(records) = index_records(ctx, target)? else {
        return Err(CliError::unimplemented(format!(
            "{}: {LISTING_ENGINE_STAGE}",
            target.display()
        ))
        .with_hint(LISTING_ENGINE_HINT));
    };

    Ok(Box::new(Pager::new(records, target.prefix())))
}

/// Every index record under `target`, or `None` while no vault is reachable.
///
/// Separated from [`open`] so that the missing capability is a single named
/// function rather than a condition threaded through the caller: the whole of
/// the engine gap is this signature, and filling it is
/// `Ok(Some(ctx.vault()?.list(target.prefix())?))`.
fn index_records(_ctx: &Ctx, _target: &Target) -> Result<Option<Vec<Record>>> {
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::listing::tests_support::{ctx, record};
    use crate::exit::ExitCode;

    fn drain(pages: &mut dyn Pages) -> Vec<String> {
        let mut out = Vec::new();
        while let Some(page) = pages.next_page().expect("pager cannot fail") {
            assert!(!page.is_empty(), "a page must never be empty");
            out.extend(page.into_iter().map(|entry| entry.path().to_string()));
        }
        out
    }

    #[test]
    fn every_record_is_yielded_exactly_once_in_order() {
        let mut pager = Pager::new(
            vec![
                record("a.txt", 1, None),
                record("b/c.txt", 2, None),
                record("b/d.txt", 3, None),
            ],
            "",
        );
        assert_eq!(drain(&mut pager), vec!["a.txt", "b/c.txt", "b/d.txt"]);
    }

    #[test]
    fn paging_does_not_change_what_is_yielded() {
        // The property that lets a renderer ignore page boundaries entirely.
        let records: Vec<Record> = (0..25)
            .map(|n| record(&format!("f{n:02}.txt"), n, None))
            .collect();
        let whole = drain(&mut Pager::with_page_size(records.clone(), "", 1000));
        for page_size in [1, 2, 7, 25, 26] {
            let paged = drain(&mut Pager::with_page_size(records.clone(), "", page_size));
            assert_eq!(paged, whole, "page size {page_size}");
        }
    }

    #[test]
    fn a_zero_page_size_cannot_stall_the_listing() {
        let mut pager = Pager::with_page_size(vec![record("a", 1, None)], "", 0);
        assert_eq!(drain(&mut pager), vec!["a"]);
    }

    #[test]
    fn an_exhausted_pager_keeps_returning_none() {
        let mut pager = Pager::new(Vec::new(), "");
        assert!(pager.next_page().unwrap().is_none());
        assert!(pager.next_page().unwrap().is_none());
    }

    #[test]
    fn a_sibling_with_a_shared_prefix_is_not_inside_the_root() {
        // `photos` is not the parent of `photos-backup`. A byte-wise prefix
        // match — which is what the index does — would report both.
        let mut pager = Pager::new(
            vec![
                record("photos-backup/x.jpg", 1, None),
                record("photos/a.jpg", 2, None),
                record("photos", 3, None),
            ],
            "photos",
        );
        assert_eq!(drain(&mut pager), vec!["photos/a.jpg", "photos"]);
    }

    #[test]
    fn a_page_that_filters_down_to_nothing_ends_the_listing() {
        // Otherwise the caller's `while let Some(page)` loop spins forever.
        let mut pager = Pager::with_page_size(
            vec![record("other/a", 1, None), record("other/b", 2, None)],
            "photos",
            1,
        );
        assert!(pager.next_page().unwrap().is_none());
    }

    #[test]
    fn entries_are_rooted_at_the_listing_prefix() {
        let mut pager = Pager::new(vec![record("photos/2024/a.jpg", 1, None)], "photos");
        let page = pager.next_page().unwrap().expect("one page");
        assert_eq!(page[0].relative(), "2024/a.jpg");
    }

    #[test]
    fn a_listing_that_cannot_reach_the_index_errors_rather_than_reporting_empty() {
        // `PLAN.md` §6: never report an outcome that did not happen. An empty
        // listing here would read as "the vault holds nothing".
        let ctx = ctx(&[]);
        let target = Target::parse(Some("vault:photos"), None).unwrap();
        let error = open(&ctx, &target).err().expect("no engine yet");
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.message().contains(LISTING_ENGINE_STAGE));
        assert!(error.hint().is_some());
    }

    #[test]
    fn a_local_target_is_refused_with_its_own_message() {
        // Distinguishable from the engine gap, because the fix is different:
        // one is "wait for a release", the other is "write a remote spec".
        let ctx = ctx(&[]);
        let target = Target::parse(Some("./photos"), None).unwrap();
        let error = open(&ctx, &target).err().expect("no local walk yet");
        assert!(error.message().contains(LOCAL_LISTING_FEATURE));
    }
}
