//! What a walk does when it meets a symbolic link, and how it says so.
//!
//! # The defect this exists to remove
//!
//! `/srv/data -> /mnt/bigdisk/data` is the canonical layout of every machine
//! with a small system disk and the data on a mounted volume. Pointing DCTL at
//! `/srv` used to produce an empty listing on `local:` and on `sftp:`, because
//! both walks asked the directory entry for its type and a symlink's type is
//! neither *file* nor *directory* — so the entry fell past both arms and was
//! dropped. `copy` then reported `Files: 0 / 0, Errors: 0` and exited 0, `sync`
//! read the same emptiness as permission to delete the destination, and the
//! operator found out on restore day. It is the only defect this project has
//! found that destroyed data without saying anything.
//!
//! The loss was not the skipping. It was the **silence**. Everything in this
//! module exists so that a walk which passes over a link says so, with a count
//! that is always exact and a sample of names that is bounded.
//!
//! # Why the default is to skip, loudly
//!
//! [`LinkPolicy::Skip`] is the default and following is opt-in, which is also
//! where rclone settled: its local backend ignores symlinks unless `-L`
//! (`--copy-links`) is given, and logs `Can't follow symlink without
//! -L/--copy-links` for each one it passes over. Three reasons decide it here.
//!
//! *Following changes what a backup contains, invisibly.* A single link named
//! `etc -> /etc` inside the tree pulls a machine's whole configuration into an
//! archive the operator believes holds photographs. The tree they audited with
//! `ls` is not the tree that gets stored, and no `--exclude` they wrote was
//! consulted about the target.
//!
//! *Following can duplicate without bound.* Two links to one directory store its
//! contents twice, under two names, at twice the egress. That is a cost
//! discovered on an invoice.
//!
//! *A default that deletes is worse than a default that omits.* `sync` removes
//! whatever the source does not have. If the default followed links, then a
//! later run on a machine whose links happened not to resolve — an unmounted
//! volume, a host where the target lives elsewhere — would see the source lose
//! those files and would delete them at the destination. Under `skip` the
//! entries were never there, so nothing is deleted for having gone away.
//!
//! What the default must not be is quiet, and it no longer is: every skipped
//! link is counted, a bounded sample of them is named, and the warning names the
//! flag that changes the answer.
//!
//! # The third policy, and the question it settles
//!
//! [`LinkPolicy::Follow`] follows a link wherever it points, because the
//! canonical case *is* out of tree — `/mnt/bigdisk/data` is not under `/srv` —
//! so a rule that refused to leave the tree would refuse exactly the layout this
//! work exists to support. An operator who wants the tighter rule asks for
//! [`LinkPolicy::InTree`], which follows a link only while its target stays
//! under the walk root and reports every one that would have left. Either way
//! the run says which links it followed and where they went; the thing that is
//! not on offer is doing it silently.
//!
//! # What is deliberately not here
//!
//! Storing the link *itself* — rclone's `-l/--links`, which writes the target
//! path into a `.rclonelink` file — is not implemented. A vault keyed by
//! logical path has no record type for "this path is a link to that one", so a
//! followed link restores as an ordinary **copy** of what it pointed at, and a
//! skipped one restores as nothing at all. That is stated in the restore
//! documentation and pinned by a drill rather than left for someone to
//! discover.

mod cycle;
mod report;

pub use cycle::{Ancestors, DirId, local_dir_id};
pub use report::{LINK_NOTE_SAMPLE, LinkNote, LinkReport};

use std::fmt;
use std::str::FromStr;

/// What a walk does with the symbolic links it finds inside a tree.
///
/// This decides links **found during a walk**, never the root the operator
/// typed. A root is always resolved: `dctl ls /srv/data` and `dctl backup
/// /var/log/current vault:` name a path a person chose, and refusing to look
/// through it produced an empty listing with `exists = true` — the shape that
/// let `sync --force` delete a destination. The two questions are separate and
/// answering them with one rule was itself a data-loss path.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum LinkPolicy {
    /// Pass over every link, counting it and naming a bounded sample.
    #[default]
    Skip,
    /// Follow every link to whatever it points at, anywhere the filesystem goes.
    Follow,
    /// Follow a link only while its target stays under the walk root; report the
    /// ones that would have left.
    InTree,
}

/// The spellings [`LinkPolicy::from_str`] accepts, in the order `--help` lists
/// them: the default first, then the two ways of saying "follow".
pub const LINK_POLICY_CHOICES: [&str; 3] = ["skip", "follow", "in-tree"];

impl LinkPolicy {
    /// Whether this policy ever looks through a link.
    ///
    /// The walks branch on this before they resolve anything, so the default
    /// costs no extra `stat` per entry: under [`Skip`](LinkPolicy::Skip) a link
    /// is counted from the directory entry alone and nothing behind it is
    /// touched.
    #[must_use]
    pub const fn follows(self) -> bool {
        matches!(self, Self::Follow | Self::InTree)
    }

    /// Whether a followed target must stay under the walk root.
    #[must_use]
    pub const fn confined(self) -> bool {
        matches!(self, Self::InTree)
    }

    /// The canonical spelling, which is also what [`LinkPolicy::from_str`] reads.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Skip => LINK_POLICY_CHOICES[0],
            Self::Follow => LINK_POLICY_CHOICES[1],
            Self::InTree => LINK_POLICY_CHOICES[2],
        }
    }
}

impl fmt::Display for LinkPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A spelling of `--links` this build does not know.
///
/// Carries the word that was typed so the caller can quote it back; the
/// alternatives come from [`LINK_POLICY_CHOICES`] rather than being repeated
/// here, because a fourth policy must not be able to appear in one list and not
/// the other.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("unknown link policy '{typed}' (expected one of: {})", LINK_POLICY_CHOICES.join(", "))]
pub struct UnknownLinkPolicy {
    /// The word the caller supplied, quoted back so the message names the input
    /// rather than only the rule.
    pub typed: String,
}

impl FromStr for LinkPolicy {
    type Err = UnknownLinkPolicy;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text {
            "skip" => Ok(Self::Skip),
            "follow" => Ok(Self::Follow),
            "in-tree" => Ok(Self::InTree),
            other => Err(UnknownLinkPolicy {
                typed: other.to_string(),
            }),
        }
    }
}

/// What was found behind a link, once a policy that follows went to look.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkTarget {
    /// Nobody looked. The state a link is in under [`LinkPolicy::Skip`], and a
    /// variant rather than an assumption because "the target is missing" and
    /// "the target was never resolved" are different facts and a walk that
    /// conflated them would report dangling links it had not checked for.
    Unread,
    /// Nothing is there — a dangling link, or one whose target is unreadable.
    Missing,
    /// The target resolves under the walk root.
    Inside,
    /// The target resolves outside the walk root.
    Outside,
}

/// What a walk did about one link, and why.
///
/// The *reason* rather than a bare yes/no, because the four ways of not
/// following are four different things for an operator to do next: change the
/// flag, fix a dangling link, widen the policy, or accept a cycle.
///
/// Serialised as its [`slug`](LinkVerdict::slug) — the same word `-v` prints and
/// the same word a script greps — so the human and machine renderings of a run
/// cannot come to disagree about what happened to a link.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LinkVerdict {
    /// The policy is `skip`. Nothing behind it was read.
    NotFollowed,
    /// Followed; the target's bytes (or tree) are in the listing.
    Followed,
    /// Followed, and there is nothing behind it.
    Broken,
    /// The policy is `in-tree` and the target lies outside the walk root.
    OutOfTree,
    /// The target directory is already an ancestor of this link: following it
    /// would walk forever.
    Cycle,
    /// Followed, and what is behind it is neither a file nor a directory — a
    /// socket, a fifo or a device, none of which has bytes a transfer carries.
    NotStorable,
}

impl LinkVerdict {
    /// Whether the walk read what was behind the link.
    #[must_use]
    pub const fn followed(self) -> bool {
        matches!(self, Self::Followed)
    }

    /// A stable, lower-case word for the reason, for logs and `--verbose` lines.
    ///
    /// Stable because scripts grep it: renaming one of these is a change to the
    /// tool's observable output, not a wording tweak.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::NotFollowed => "not-followed",
            Self::Followed => "followed",
            Self::Broken => "broken",
            Self::OutOfTree => "out-of-tree",
            Self::Cycle => "cycle",
            Self::NotStorable => "not-storable",
        }
    }

    /// What to tell an operator, in the form they can act on.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::NotFollowed => "not followed",
            Self::Followed => "followed",
            Self::Broken => "points at nothing",
            Self::OutOfTree => "points outside the tree",
            Self::Cycle => "points at a directory it is already inside",
            Self::NotStorable => "points at something that is not a file",
        }
    }
}

/// Decide one link, given the policy and what was found behind it.
///
/// Pure and total, so every combination is assertable without arranging a
/// filesystem for it — which is the half of this feature that is easy to get
/// subtly wrong and impossible to notice. The walks do the I/O and ask this;
/// they do not each carry their own version of the rule, because three walks
/// with three copies of it is how `local:`, `sftp:` and `backup` came to
/// disagree about what a link means in the first place.
///
/// A cycle is not decided here: it is a fact about where the walk has already
/// been rather than about the link, and it belongs to [`Ancestors`].
#[must_use]
pub const fn decide(policy: LinkPolicy, target: LinkTarget) -> LinkVerdict {
    match (policy, target) {
        // Nothing behind the link was read, so nothing about the target is
        // known — including whether it is there at all.
        (LinkPolicy::Skip, _) | (_, LinkTarget::Unread) => LinkVerdict::NotFollowed,
        (_, LinkTarget::Missing) => LinkVerdict::Broken,
        (LinkPolicy::Follow, _) | (LinkPolicy::InTree, LinkTarget::Inside) => LinkVerdict::Followed,
        (LinkPolicy::InTree, LinkTarget::Outside) => LinkVerdict::OutOfTree,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_is_to_skip() {
        // A default that followed would change what every existing backup
        // contains on the next run, and `sync` deletes on the difference.
        assert_eq!(LinkPolicy::default(), LinkPolicy::Skip);
        assert!(!LinkPolicy::default().follows());
    }

    #[test]
    fn every_choice_round_trips_through_its_own_spelling() {
        // The flag, the config value and the error message all read this list;
        // a variant that could not be spelled back would be unreachable from
        // the command line while still appearing in `--help`.
        for choice in LINK_POLICY_CHOICES {
            let policy: LinkPolicy = choice.parse().expect("a listed choice parses");
            assert_eq!(policy.as_str(), choice);
            assert_eq!(policy.to_string(), choice);
        }
    }

    #[test]
    fn an_unknown_spelling_is_refused_and_names_the_alternatives() {
        let error = "yes"
            .parse::<LinkPolicy>()
            .expect_err("yes is not a policy");
        let text = error.to_string();
        assert!(text.contains("yes"), "{text}");
        for choice in LINK_POLICY_CHOICES {
            assert!(text.contains(choice), "{text} omits {choice}");
        }
    }

    #[test]
    fn skipping_never_looks_behind_a_link() {
        // The property that keeps the default free: no extra `stat` per entry,
        // and no answer about a target nothing resolved.
        for target in [
            LinkTarget::Unread,
            LinkTarget::Missing,
            LinkTarget::Inside,
            LinkTarget::Outside,
        ] {
            assert_eq!(
                decide(LinkPolicy::Skip, target),
                LinkVerdict::NotFollowed,
                "{target:?}"
            );
        }
    }

    #[test]
    fn an_unresolved_target_is_never_called_broken() {
        // A skipped link may well be dangling; nothing looked, so nothing may
        // claim it is. Reporting a dangling link the walk never checked would
        // be a fabricated finding on a run that did no work.
        for policy in [LinkPolicy::Skip, LinkPolicy::Follow, LinkPolicy::InTree] {
            assert_eq!(
                decide(policy, LinkTarget::Unread),
                LinkVerdict::NotFollowed,
                "{policy}"
            );
        }
    }

    #[test]
    fn following_leaves_the_tree_and_in_tree_does_not() {
        // The canonical layout `/srv/data -> /mnt/bigdisk/data` is out of tree,
        // so a policy that refused to leave would refuse the case this whole
        // module exists for. Both answers are available; neither is silent.
        assert_eq!(
            decide(LinkPolicy::Follow, LinkTarget::Outside),
            LinkVerdict::Followed
        );
        assert_eq!(
            decide(LinkPolicy::InTree, LinkTarget::Outside),
            LinkVerdict::OutOfTree
        );
        assert_eq!(
            decide(LinkPolicy::InTree, LinkTarget::Inside),
            LinkVerdict::Followed
        );
    }

    #[test]
    fn a_dangling_link_is_broken_under_every_policy_that_looks() {
        // Never an abort: a run over a tree with one stale link must still
        // transfer the other 200 000 files and name the one it could not.
        assert_eq!(
            decide(LinkPolicy::Follow, LinkTarget::Missing),
            LinkVerdict::Broken
        );
        assert_eq!(
            decide(LinkPolicy::InTree, LinkTarget::Missing),
            LinkVerdict::Broken
        );
    }

    #[test]
    fn every_verdict_has_a_distinct_slug_and_a_reason() {
        let verdicts = [
            LinkVerdict::NotFollowed,
            LinkVerdict::Followed,
            LinkVerdict::Broken,
            LinkVerdict::OutOfTree,
            LinkVerdict::Cycle,
            LinkVerdict::NotStorable,
        ];
        for (index, verdict) in verdicts.iter().enumerate() {
            assert!(
                !verdicts[index + 1..]
                    .iter()
                    .any(|other| other.slug() == verdict.slug()),
                "'{}' twice",
                verdict.slug()
            );
            assert!(!verdict.reason().is_empty());
        }
        assert!(LinkVerdict::Followed.followed());
        assert!(!LinkVerdict::Cycle.followed());
    }

    #[test]
    fn a_verdict_serialises_as_the_word_it_prints() {
        // `dctl backup --format json` and `dctl backup -v` describe one run.
        // Two spellings of one verdict is two answers to "what happened to that
        // link", and the reader has no way to tell which is authoritative.
        for verdict in [
            LinkVerdict::NotFollowed,
            LinkVerdict::Followed,
            LinkVerdict::Broken,
            LinkVerdict::OutOfTree,
            LinkVerdict::Cycle,
            LinkVerdict::NotStorable,
        ] {
            let json = serde_json::to_string(&verdict).expect("a verdict serialises");
            assert_eq!(json, format!("\"{}\"", verdict.slug()));
        }
    }
}
