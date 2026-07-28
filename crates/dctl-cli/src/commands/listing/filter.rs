//! Which entries a listing is allowed to show.
//!
//! Built once per invocation from the global filtering flags and then consulted
//! per entry, so that all six listing verbs agree about scope. The alternative —
//! each command interpreting `--exclude` for itself — produces a tool where
//! `dctl size` and `dctl ls` report different vaults and neither is wrong.
//!
//! ## This is an adapter, not an engine
//!
//! The rules themselves live in [`crate::filter`], which is the binary's single
//! implementation of `--include`, `--exclude`, `--filter-from`, `--files-from`,
//! `--min-size`, `--max-size` and `--max-depth`. The transfer family and the
//! recovery family already consult it; this file is how the listing family does,
//! and it is deliberately thin — a type conversion and four forwarding methods.
//!
//! It exists at all because the two layers speak about different things. The
//! engine decides about a [`Candidate`](crate::filter::Candidate): a
//! root-relative logical path, a size, and whether it is a directory. A listing
//! holds an [`Entry`], which knows its *absolute* path as well, carries a
//! content hash and a modification time for rendering, and remembers where the
//! listing root ended inside it. Converting once, here, is what stops six
//! renderers from each deciding for themselves which of an entry's two path
//! spellings a pattern is matched against — and matching an absolute path where
//! the transfer family matched a relative one is precisely how `ls` and the
//! `copy` that follows come to disagree.
//!
//! ## Why that agreement is the point
//!
//! A file that `dctl ls --exclude X` hides and `dctl copy --exclude X` then
//! transfers is a reporting bug. A file that `ls` *shows* and the copy omits is
//! worse: the listing is what a person reads before deciding what is safe to
//! delete from the source. And during a `sync`, a rule that means two things on
//! the two sides shows a file on one, hides it on the other, and deletes it for
//! being an extra. So there is one engine and the semantics are its, including
//! the parts that surprise people — most of all that using `--include` at all
//! appends an implicit `--exclude '**'`, so `--include '*.jpg' --exclude '*.png'`
//! means "the JPEGs only" and not "everything but the PNGs". That is rclone's
//! behaviour and [`crate::filter`] explains at length why DCTL matches it rather
//! than inventing a kinder rule.
//!
//! [`super::agreement`] holds the test that pins this: the same flags over the
//! same tree, through the listing family and through the transfer family, must
//! select the same files.
//!
//! ## `--files-from` narrows a listing without disabling its walk
//!
//! [`FilterSet::disables_traversal`] tells a *transfer* to look each named path
//! up directly instead of walking. A listing cannot do that and does not need
//! to: it is already reading a flat, ordered enumeration from an index or a
//! provider, so there is no directory recursion for a path list to prune. The
//! set of entries shown is identical either way — which is the property that
//! matters — and the cost of the walk is the cost of the listing that was asked
//! for regardless.

use crate::cli::globals::GlobalArgs;
use crate::error::Result;
use crate::filter::{Candidate, FilterSet};

use super::entry::Entry;

/// The scope of one listing.
#[derive(Clone, Debug, Default)]
pub struct Filter {
    set: FilterSet,
}

impl Filter {
    /// Build the filter from the global flags.
    ///
    /// # Errors
    /// [`ExitCode::Usage`](crate::exit::ExitCode::Usage) for a malformed
    /// pattern, size or depth, or for a `--filter-from`/`--files-from` file that
    /// cannot be read or understood. Every one of those names the flag and, for
    /// a file, the line — a rule that was quietly dropped would make a listing
    /// *look* complete, and listings are what people read before deciding what
    /// to delete.
    pub fn from_globals(globals: &GlobalArgs) -> Result<Self> {
        Ok(Self {
            set: FilterSet::from_globals(globals)?,
        })
    }

    /// Replace the depth limit.
    ///
    /// `lsd` and `tree` derive directories from the objects beneath them, so
    /// they must see objects the user's `--max-depth` would have hidden and
    /// apply the limit to the *directories* they synthesise instead. Without
    /// this, `dctl lsd --max-depth 1` would report a top-level directory as
    /// empty because every object in it sits at depth 2.
    #[must_use]
    pub fn with_depth_limit(self, depth: Option<usize>) -> Self {
        Self {
            set: self.set.with_depth_limit(depth),
        }
    }

    /// Whether `entry` is in scope.
    ///
    /// [`FilterSet::admits_enumerated`] rather than
    /// [`FilterSet::admits`](crate::filter::FilterSet::admits), because a
    /// listing has no walk to prune: it reads a flat, already complete set of
    /// paths out of an index or a provider, so the ancestor directories a
    /// walking caller would simply never have opened have to be asked about
    /// explicitly. `--exclude 'cache/'` hides everything under `cache` either
    /// way, which is the point.
    #[must_use]
    pub fn matches(&self, entry: &Entry) -> bool {
        self.set.admits_enumerated(&candidate(entry))
    }

    /// Why `entry` was admitted or refused, in one line.
    ///
    /// `cfg(test)` deliberately, in the same spirit as
    /// [`Target::is_remote`](super::Target): the engine can name the rule that
    /// decided a file's fate, and no listing verb prints it yet. Exposing it to
    /// production before something renders it would be a second, unreviewed
    /// wording of a decision the engine already words. What it is doing here is
    /// pinning that the adapter hands the engine an entry the engine can
    /// *explain* — which is the same conversion `matches` relies on, checked
    /// from the other side.
    #[cfg(test)]
    #[must_use]
    pub fn explain(&self, entry: &Entry) -> String {
        self.set.decide(&candidate(entry)).describe()
    }

    /// Whether any pattern, path list, size or depth restriction is in force.
    ///
    /// Used by the commands to word an empty result: "nothing here" and
    /// "nothing survived your filters" are different answers, and reporting the
    /// first when the second is true sends the user looking for missing data.
    #[must_use]
    pub fn is_restricting(&self) -> bool {
        self.set.is_restricting()
    }
}

/// The engine's view of one listing entry.
///
/// The **root-relative** path, always: `--max-depth 1` under
/// `dctl ls vault:photos` means one level below `photos`, and a pattern the user
/// wrote for the tree they are looking at must not have to know how deep inside
/// the vault that tree happens to sit. It is also the spelling the transfer
/// family offers the same engine, which is what makes the two agree.
///
/// A directory carries no size. Its size is the aggregate of everything beneath
/// it, and letting that number reach `--max-size` would hide every small file in
/// a large tree.
fn candidate(entry: &Entry) -> Candidate<'_> {
    match (entry.is_dir(), entry.size()) {
        (true, _) => Candidate::directory(entry.relative()),
        (false, Some(size)) => Candidate::file(entry.relative(), size).at(entry.modified_unix()),
        // A row from a rebuilt vault index. The engine is told the size is
        // unknown rather than handed a zero, because a zero would answer
        // `--min-size`/`--max-size` confidently and wrongly; see
        // [`Candidate::unmeasured_file`]. The same row has no time either, and
        // `--min-age`/`--max-age` are told so for the same reason.
        (false, None) => Candidate::unmeasured_file(entry.relative()).at(entry.modified_unix()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::listing::tests_support::{ctx, entry};
    use crate::exit::ExitCode;

    fn filter(args: &[&str]) -> Filter {
        Filter::from_globals(&ctx(args).globals).expect("flags should compile")
    }

    fn refuses(args: &[&str]) -> crate::error::CliError {
        Filter::from_globals(&ctx(args).globals).expect_err("flags should be refused")
    }

    fn shows(filter: &Filter, path: &str) -> bool {
        filter.matches(&entry("", path, 1024))
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("dctl-listing-filter-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temporary directory");
        dir
    }

    fn write(dir: &std::path::Path, name: &str, contents: &str) -> String {
        let path = dir.join(name);
        std::fs::write(&path, contents).expect("write the filter file");
        path.to_string_lossy().into_owned()
    }

    // ── The default ──────────────────────────────────────────────────────

    #[test]
    fn an_empty_filter_shows_everything() {
        let filter = filter(&[]);
        assert!(!filter.is_restricting());
        assert!(shows(&filter, "a/b/c.txt"));
        assert!(shows(&filter, "x.jpg"));
        assert!(Filter::default().matches(&entry("", "anything", u64::MAX)));
    }

    // ── Anchoring, which is the engine's and must not be re-derived here ──

    #[test]
    fn a_bare_pattern_matches_the_name_at_any_depth() {
        let filter = filter(&["--include", "*.jpg"]);
        assert!(shows(&filter, "a.jpg"));
        assert!(shows(&filter, "photos/2024/a.jpg"));
        assert!(!shows(&filter, "photos/2024/a.raw"));
    }

    #[test]
    fn a_leading_slash_anchors_at_the_listing_root() {
        let filter = filter(&["--include", "/tmp/*"]);
        assert!(shows(&filter, "tmp/a"));
        // Anchored: a `tmp` further down is a different directory.
        assert!(!shows(&filter, "photos/tmp/a"));
    }

    #[test]
    fn an_unanchored_path_pattern_matches_any_component_suffix() {
        let filter = filter(&["--exclude", "tmp/*"]);
        assert!(!shows(&filter, "tmp/a"));
        assert!(!shows(&filter, "photos/tmp/a"));
        assert!(shows(&filter, "photos/a"));
        // `*` does not cross a separator, so a deeper file survives the rule.
        assert!(shows(&filter, "tmp/a/b"));
        // And a suffix never starts mid-component: `photos-tmp/a` is not under a
        // directory called `tmp`.
        assert!(shows(&filter, "photos-tmp/a"));
    }

    // ── The asymmetry a listing must share with a transfer ────────────────

    #[test]
    fn an_include_drops_what_it_does_not_name() {
        // rclone's rule, and the engine's: using `--include` at all appends an
        // implicit `- **`. A listing that kept the unmentioned files while the
        // `copy` that follows dropped them would be the disagreement this whole
        // arrangement exists to prevent.
        let filter = filter(&["--include", "*.jpg", "--exclude", "*.png"]);
        assert!(shows(&filter, "a.jpg"));
        assert!(!shows(&filter, "a.png"));
        assert!(!shows(&filter, "a.txt"), "the unmentioned file goes too");
    }

    #[test]
    fn an_exclude_alone_keeps_everything_else() {
        let filter = filter(&["--exclude", "*.tmp"]);
        assert!(!shows(&filter, "a.tmp"));
        assert!(shows(&filter, "deep/tree/b.bin"));
    }

    #[test]
    fn several_includes_are_a_union() {
        let filter = filter(&["--include", "*.jpg", "--include", "*.raw"]);
        assert!(shows(&filter, "a.jpg"));
        assert!(shows(&filter, "a.raw"));
        assert!(!shows(&filter, "a.txt"));
    }

    #[test]
    fn inclusions_are_tried_before_exclusions_because_rclone_tries_them_first() {
        // Corrected against `fs/filter/rules.go:238`. rclone walks its flags by
        // kind — every include, then every exclude — so an inclusion that also
        // covers the excluded tree wins, and `private/a.jpg` is kept. DCTL led
        // with the exclusions and dropped it, which on a listing is a file the
        // operator is told is not stored.
        let mixed = filter(&["--include", "**", "--exclude", "private/**"]);
        assert!(shows(&mixed, "holiday/a.jpg"));
        assert!(shows(&mixed, "private/a.jpg"), "rclone keeps this one");

        // `--filter` is the flag whose order is written down, and it is how the
        // other reading is expressed. rclone's own diagnostics recommend it for
        // exactly this reason.
        let ordered = filter(&["--filter", "- private/**", "--filter", "+ **"]);
        assert!(shows(&ordered, "holiday/a.jpg"));
        assert!(!shows(&ordered, "private/a.jpg"));
    }

    // ── Size and depth ───────────────────────────────────────────────────

    #[test]
    fn size_limits_bound_both_ends() {
        let filter = filter(&["--min-size", "1K", "--max-size", "10K"]);
        assert!(filter.matches(&entry("", "a", 1024)));
        assert!(filter.matches(&entry("", "a", 10 * 1024)));
        assert!(!filter.matches(&entry("", "a", 1023)));
        assert!(!filter.matches(&entry("", "a", 10 * 1024 + 1)));
    }

    #[test]
    fn size_limits_do_not_apply_to_directories() {
        // A directory's size is the total beneath it; excluding it would hide
        // every small file inside a large tree.
        let filter = filter(&["--max-size", "1K"]);
        let dir = Entry::directory("big".into(), "", Some(1 << 30));
        assert!(filter.matches(&dir));
    }

    #[test]
    fn max_depth_counts_from_the_listing_root() {
        let filter = filter(&["--max-depth", "1"]);
        assert!(shows(&filter, "a.txt"));
        assert!(!shows(&filter, "a/b.txt"));
    }

    #[test]
    fn depth_is_measured_below_the_listing_root_and_not_inside_the_vault() {
        // `dctl ls vault:photos --max-depth 1` means one level below `photos`.
        // Matching the absolute path here would make the same flag mean
        // something different depending on how deep the tree happens to sit.
        let filter = filter(&["--max-depth", "1"]);
        assert!(filter.matches(&entry("photos", "photos/a.jpg", 1)));
        assert!(!filter.matches(&entry("photos", "photos/2024/a.jpg", 1)));
    }

    #[test]
    fn patterns_are_matched_against_the_root_relative_path() {
        // The other half of the same rule, and the one that keeps a listing and
        // a transfer in step: both offer the engine the relative spelling.
        let filter = filter(&["--include", "/2024/*"]);
        assert!(filter.matches(&entry("photos", "photos/2024/a.jpg", 1)));
        assert!(!filter.matches(&entry("photos", "photos/2025/a.jpg", 1)));
    }

    #[test]
    fn the_depth_limit_can_be_moved_to_the_directory_layer() {
        // `lsd` must still see deep objects in order to know the directory
        // exists at all.
        let filter = filter(&["--max-depth", "1"]).with_depth_limit(None);
        assert!(shows(&filter, "a/b/c.txt"));
        // And back again, so the dial is a real setter rather than a reset.
        assert!(!shows(
            &filter.clone().with_depth_limit(Some(1)),
            "a/b/c.txt"
        ));
    }

    // ── Rule files and path lists: honoured, not refused ──────────────────

    #[test]
    fn a_rule_file_shapes_a_listing_in_file_order() {
        // Previously refused outright. A listing that ignored `--filter-from`
        // would look complete while hiding nothing it was told to hide.
        let dir = scratch("rules");
        let path = write(
            &dir,
            "rules.txt",
            "# keep the sources, drop the build output\n\
             - /work/**/target/**\n\
             + /work/**\n\
             - **\n",
        );
        let filter = filter(&["--filter-from", &path]);

        assert!(shows(&filter, "work/src/main.rs"));
        assert!(!shows(&filter, "work/src/target/debug/x"));
        assert!(!shows(&filter, "notes.txt"));
        assert!(filter.is_restricting());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_files_from_list_narrows_a_listing_to_exactly_those_paths() {
        let dir = scratch("list");
        let path = write(&dir, "list.txt", "photos/2024/a.jpg\nnotes/todo.md\n");
        let filter = filter(&["--files-from", &path]);

        assert!(shows(&filter, "photos/2024/a.jpg"));
        assert!(shows(&filter, "notes/todo.md"));
        assert!(!shows(&filter, "photos/2024/b.jpg"));
        // No globbing: the list is a lookup, not a search.
        assert!(!shows(&filter, "photos/2024/a.jpg.bak"));
        // The containing directories stay in scope, so `lsd` and `tree` still
        // show the containers the listed files live in.
        assert!(filter.matches(&Entry::directory("photos/2024".into(), "", Some(1))));
        assert!(!filter.matches(&Entry::directory("music".into(), "", Some(1))));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_missing_rule_file_is_refused_rather_than_ignored() {
        // The failure mode the refusal exists for, kept now that the feature is
        // real: silently continuing would leave a listing believing a filter is
        // in force that is not.
        let error = refuses(&["--filter-from", "no/such/rules.txt"]);
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.message().contains("rules.txt"));
    }

    // ── Malformed input ──────────────────────────────────────────────────

    #[test]
    fn a_malformed_pattern_names_its_flag() {
        let error = refuses(&["--include", "[abc"]);
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.message().contains("--include"));
        assert!(error.hint().is_some());
    }

    #[test]
    fn a_malformed_size_names_its_flag() {
        let error = refuses(&["--max-size", "banana"]);
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.message().contains("--max-size"));
    }

    #[test]
    fn a_negative_depth_that_is_not_the_sentinel_is_refused() {
        // -1 means unlimited; anything else negative is an arithmetic slip in a
        // wrapper script, and both ways of clamping it are answers nobody asked
        // for.
        let error = refuses(&["--max-depth=-7"]);
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[test]
    fn off_disables_a_size_limit_rather_than_setting_it_to_zero() {
        let filter = filter(&["--max-size", "off"]);
        assert!(filter.matches(&entry("", "a", u64::MAX)));
        assert!(!filter.is_restricting());
    }

    // ── Reporting ────────────────────────────────────────────────────────

    #[test]
    fn restriction_is_reported_whenever_any_dial_is_turned() {
        assert!(filter(&["--include", "*.jpg"]).is_restricting());
        assert!(filter(&["--exclude", "*.tmp"]).is_restricting());
        assert!(filter(&["--min-size", "1K"]).is_restricting());
        assert!(filter(&["--max-depth", "2"]).is_restricting());
    }

    #[test]
    fn a_refused_entry_can_name_the_rule_that_refused_it() {
        let filter = filter(&["--exclude", "*.tmp"]);
        let text = filter.explain(&entry("", "a.tmp", 1));
        assert!(text.contains("excluded"), "got: {text}");
        assert!(text.contains("*.tmp"), "got: {text}");
        assert!(filter.explain(&entry("", "a.txt", 1)).contains("included"));
    }
}
