//! A source and a filter, joined.
//!
//! The only thing a renderer sees. It hands out one [`Entry`] at a time and
//! holds exactly one page — never the listing — so the memory a `dctl ls` of a
//! ten-million-object vault uses is set by
//! [`LIST_PAGE_SIZE`](crate::constants::LIST_PAGE_SIZE), not by the size of the
//! vault (`PLAN.md` §16.2).
//!
//! ## Why a callback rather than `Iterator`
//!
//! Fetching a page can fail, so a real `Iterator` would have to yield
//! `Result<Entry>` and every renderer would carry the same `match` on every
//! element. Worse, the natural `for entry in stream` then *silently* skips the
//! rest of the listing when a page fails unless each renderer remembers to break
//! — a truncated listing that exits zero, which is the one outcome `PLAN.md` §6
//! forbids. [`Stream::try_for_each`] makes the failure the loop's own
//! short-circuit: it is not possible to write the renderer that ignores it.
//!
//! The counters move here too, for the same reason: every listing verb reports
//! the same "objects considered" figure because none of them is trusted to
//! increment it.

use crate::error::Result;
use crate::logging::fields;
use crate::source::Sizes;

use super::entry::Entry;
use super::filter::Filter;
use super::source::Pages;

/// A filtered listing, read one entry at a time.
pub struct Stream {
    pages: Box<dyn Pages>,
    filter: Filter,
    /// Entries that passed the filter, for the "did anything match" report.
    matched: u64,
    /// Entries the source produced, whether or not they passed.
    seen: u64,
}

impl Stream {
    /// Join a source and a filter.
    #[must_use]
    pub fn new(pages: Box<dyn Pages>, filter: Filter) -> Self {
        Self {
            pages,
            filter,
            matched: 0,
            seen: 0,
        }
    }

    /// The filter in force, so a renderer can word an empty result correctly.
    #[must_use]
    pub const fn filter(&self) -> &Filter {
        &self.filter
    }

    /// Entries that passed the filter so far.
    #[must_use]
    pub const fn matched(&self) -> u64 {
        self.matched
    }

    /// Entries the source produced so far, filtered or not.
    #[must_use]
    pub const fn seen(&self) -> u64 {
        self.seen
    }

    /// What the sizes on this stream's entries measure.
    ///
    /// Filtering changes which objects are counted, never the unit they are
    /// counted in, so this passes straight through from the source.
    #[must_use]
    pub fn sizes(&self) -> Sizes {
        self.pages.sizes()
    }

    /// What the walk behind this stream did about the symbolic links it met.
    ///
    /// Unfiltered on purpose. A link the walk passed over produced no entry, so
    /// no `--include` was ever asked about it; reporting only the links that
    /// "matched" would mean reporting none of them, which is the silence being
    /// removed. The filter decides what is listed, never what is disclosed.
    #[must_use]
    pub fn links(&self) -> dctl_store::LinkReport {
        self.pages.links()
    }

    /// What the walk behind this stream passed over that was neither a file, a
    /// directory nor a link.
    ///
    /// Unfiltered for the reason [`links`](Stream::links) is: a fifo the walk
    /// skipped produced no entry, so no `--include` was ever asked about it, and
    /// reporting only the ones that "matched" would mean reporting none.
    #[must_use]
    pub fn specials(&self) -> dctl_store::SpecialReport {
        self.pages.specials()
    }

    /// Call `visit` for every entry in scope, in path order.
    ///
    /// Stops at the first error from either the source or the visitor, and
    /// returns it. Nothing is buffered between pages, so a visitor that writes
    /// to stdout has already produced output for everything before the failure —
    /// which is correct: those lines were true.
    ///
    /// Fetching a page is asynchronous — it can be a provider round trip — but
    /// the visitor stays a plain `FnMut`, because every renderer in the family
    /// does exactly one thing with an entry: format it and write it to an
    /// already-open sink. Making it async would force each of them to box a
    /// future per row of a ten-million-row listing to buy nothing.
    ///
    /// # Errors
    /// Whatever the source or the visitor returned.
    pub async fn try_for_each<F>(&mut self, mut visit: F) -> Result<()>
    where
        F: FnMut(&Entry) -> Result<()>,
    {
        while let Some(page) = self.pages.next_page().await? {
            for entry in &page {
                self.seen += 1;
                if !self.filter.matches(entry) {
                    continue;
                }
                self.matched += 1;
                // One record per listed object, at trace (`PLAN.md` §7). Cheap
                // when the level is off — `tracing` checks it before evaluating
                // the fields — and the only way to answer "why did this listing
                // include that" without re-running with different flags. The
                // *absolute* path, unlike the rendered output, because a log
                // line has no listing root to be relative to.
                // The size is recorded through `Debug` rather than as a bare
                // integer: an unmeasured row has no byte count, and a trace
                // line that logged `0` for it would put the same misreport into
                // the record an operator reconstructs a run from.
                tracing::trace!(
                    { fields::PATH } = entry.path(),
                    { fields::BYTES } = tracing::field::debug(entry.size()),
                    "listed"
                );
                visit(entry)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::listing::tests_support::{ctx, pager};
    use crate::error::CliError;
    use crate::exit::ExitCode;

    fn stream(root: &str, paths: &[(&str, u64)], flags: &[&str]) -> Stream {
        let filter = Filter::from_globals(&ctx(flags).globals).expect("flags compile");
        Stream::new(Box::new(pager(root, paths)), filter)
    }

    async fn collect(stream: &mut Stream) -> Vec<String> {
        let mut seen = Vec::new();
        stream
            .try_for_each(|entry| {
                seen.push(entry.path().to_string());
                Ok(())
            })
            .await
            .expect("the pager cannot fail");
        seen
    }

    #[tokio::test]
    async fn every_entry_in_scope_is_visited_in_path_order() {
        let mut stream = stream("", &[("a.txt", 1), ("b/c.txt", 2), ("b/d.txt", 3)], &[]);
        assert_eq!(
            collect(&mut stream).await,
            vec!["a.txt", "b/c.txt", "b/d.txt"]
        );
        assert_eq!(stream.matched(), 3);
        assert_eq!(stream.seen(), 3);
    }

    #[tokio::test]
    async fn filtered_entries_are_counted_but_not_visited() {
        // The distinction that lets a command say "nothing matched your filters"
        // instead of "the directory is empty".
        let mut stream = stream(
            "",
            &[("a.jpg", 1), ("b.txt", 2), ("c.jpg", 3)],
            &["--include", "*.jpg"],
        );
        assert_eq!(collect(&mut stream).await, vec!["a.jpg", "c.jpg"]);
        assert_eq!(stream.matched(), 2);
        assert_eq!(stream.seen(), 3);
        assert!(stream.filter().is_restricting());
    }

    #[tokio::test]
    async fn a_visitor_error_stops_the_listing_and_propagates() {
        // A renderer whose stdout has gone away must not keep pulling pages.
        let mut stream = stream("", &[("a", 1), ("b", 2), ("c", 3)], &[]);
        let mut visited = 0;
        let error = stream
            .try_for_each(|_| {
                visited += 1;
                Err(CliError::new(ExitCode::Uncategorised, "stdout closed"))
            })
            .await
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::Uncategorised);
        assert_eq!(visited, 1, "the loop must stop at the first failure");
    }

    #[tokio::test]
    async fn an_empty_listing_visits_nothing_and_succeeds() {
        let mut stream = stream("", &[], &[]);
        assert!(collect(&mut stream).await.is_empty());
        assert_eq!(stream.matched(), 0);
        assert_eq!(stream.seen(), 0);
    }

    #[tokio::test]
    async fn page_boundaries_are_invisible_to_a_renderer() {
        let paths: Vec<(String, u64)> = (0u64..2500).map(|n| (format!("f{n:04}.bin"), n)).collect();
        let borrowed: Vec<(&str, u64)> = paths.iter().map(|(p, s)| (p.as_str(), *s)).collect();
        let mut stream = stream("", &borrowed, &[]);
        // More entries than one page holds, so this only passes if the stream
        // keeps pulling until the source is exhausted.
        assert!(paths.len() > crate::constants::LIST_PAGE_SIZE);
        assert_eq!(collect(&mut stream).await.len(), paths.len());
    }

    #[tokio::test]
    async fn filtering_changes_which_objects_are_counted_never_the_unit() {
        // `dctl size --include "*.jpg"` measures fewer files, not different
        // bytes, so the basis has to survive the filter untouched — otherwise
        // the label on the total would describe the source rather than the sum.
        let filter = Filter::from_globals(&ctx(&["--include", "*.jpg"]).globals).unwrap();
        let pages = pager("", &[("a.jpg", 1), ("b.txt", 2)]).with_sizes(Sizes::Plaintext);
        let mut stream = Stream::new(Box::new(pages), filter);

        assert_eq!(stream.sizes(), Sizes::Plaintext);
        assert_eq!(collect(&mut stream).await, vec!["a.jpg"]);
        assert_eq!(
            stream.sizes(),
            Sizes::Plaintext,
            "the basis must not drift as the listing is consumed"
        );
    }

    #[tokio::test]
    async fn the_root_scopes_the_listing() {
        let mut stream = stream(
            "photos",
            &[("photos/a.jpg", 1), ("photos-backup/b.jpg", 2)],
            &[],
        );
        assert_eq!(collect(&mut stream).await, vec!["photos/a.jpg"]);
    }
}
