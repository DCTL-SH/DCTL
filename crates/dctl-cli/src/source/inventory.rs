//! Where a run's list of objects came from — and therefore whether an object
//! that is **gone** can be noticed at all.
//!
//! [`Assurance`](super::Assurance) answers *are these the bytes that were
//! written?*. It cannot answer *is everything that was written still here?*, and
//! the two are independent: a plain B2 remote records a per-object digest, so it
//! detects a changed byte, and its listing is still the only list of what it
//! holds, so it detects nothing at all about one that was deleted.
//!
//! ## Why a listing is not an expectation
//!
//! A check has two sides. `verify` on a sealed vault walks the **index** — a row
//! written when the object was stored, kept outside the remote — and asks the
//! remote for each row's object; a row with no object is
//! [`Verdict::Missing`](crate::commands::integrity::failure::Verdict::Missing)
//! and the run exits 4. `verify` on a plain remote walks the **remote's own
//! listing** and asks the remote for each key it just reported. Both sides of
//! that comparison are the same source, so of course they agree: a deleted
//! object is not *missing* there, it is simply not enumerated, and a run over a
//! store that has quietly lost half its objects reports the other half and exits
//! 0.
//!
//! Measured on the shipped binary, on a plain `local:` remote holding three
//! objects under `verify --allow-read-back`: one object deleted outright gave
//! `OK  2 objects examined` and **exit 0**. The `--help` of the flag that was
//! set said the check "is how a replica quietly losing objects is caught". A
//! deleted object is the one damage that claim names, and the one it does not
//! catch.
//!
//! ## Why there is no plain manifest, rather than a smaller one
//!
//! The obvious repair is to write DCTL's own record of what it put on a plain
//! remote and compare the listing against that. It was considered and rejected,
//! and the reasons are structural rather than budgetary:
//!
//! * **An expectation kept inside the thing it checks is not an expectation.**
//!   A sidecar object in the same bucket is lost by the same lifecycle rule, the
//!   same operator and the same failed replica that lost the object it
//!   describes — and it would appear in `ls`, in `check`, in `sync`'s
//!   comparison and in `restore`, in a namespace whose defining property is that
//!   the keys the provider reports **are** the paths DCTL hands back.
//! * **A plain remote is a shared namespace by design.** DCTL takes no lock and
//!   claims no ownership, and the migration story this product is sold with is
//!   *alongside* rclone rather than instead of it. A record that assumes sole
//!   authorship reports a false loss every time anything else writes or deletes
//!   there, and a monitor that cries wolf on Tuesday is switched off by
//!   Wednesday — after which it catches nothing at all, which is worse than the
//!   refusal it replaced.
//! * **It could not be rebuilt.** `index rebuild` reconstructs a vault's index
//!   from the backend alone because every sealed object carries its own
//!   authenticated header naming the path and hash inside it. A plain object
//!   carries nothing, so rebuilding a plain manifest could only re-read the
//!   listing — which is the circularity being escaped. A lost manifest would end
//!   the check permanently, and re-recording one from the current listing would
//!   silently adopt the very loss it was meant to report.
//!
//! **DCTL already ships the record this asks for, and it is called a vault.**
//! Every object gets an index row at write time, the row is kept outside the
//! remote, a recovery phrase survives the loss of the machine holding it, and a
//! row with no object exits 4. Building a second, unauthenticated, unrecoverable
//! copy of that for plain remotes would be shipping a worse version of the
//! product's core under the same word.
//!
//! So the honest answer for a plain remote is the one `PLAN.md` §6 requires:
//! say which claim cannot be made, refuse to make it, and name what does make it
//! — a vault, or `dctl check` against the tree the replica is a replica of,
//! which is the only independent record a replica has.

use crate::constants::{INVENTORY_RECORDED, INVENTORY_SELF_REPORTED};

/// Where the list of objects a run examines comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inventory {
    /// One row per object, written when the object was stored and kept outside
    /// the remote: a vault's index.
    ///
    /// This is what makes a loss detectable. The run walks the record and asks
    /// the remote for each entry, so an object the remote no longer has is a row
    /// with nothing behind it.
    Recorded,
    /// The remote's own listing, and nothing else.
    ///
    /// Every plain remote, whatever its provider records about the bytes of the
    /// objects it still has. The run enumerates the remote and then checks what
    /// the remote just told it about, so the two sides of the comparison are one
    /// source and an object that is gone leaves no trace to find.
    SelfReported,
}

impl Inventory {
    /// The stable slug used in `--json` output and in the coverage line.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Recorded => INVENTORY_RECORDED,
            Self::SelfReported => INVENTORY_SELF_REPORTED,
        }
    }

    /// One-line explanation, shown beside a verdict so the verdict cannot be
    /// read as covering objects the run never had a name for.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::Recorded => {
                "every object stored here has a row in an index kept outside the remote, so \
                 one that is gone is reported missing"
            }
            Self::SelfReported => {
                "the object list came from this remote's own listing, so a run covers what \
                 the remote still reports and an object deleted from it is not missing, it \
                 is simply not listed"
            }
        }
    }

    /// Whether a pass proves that nothing that was stored has since gone.
    ///
    /// The question a report has to answer before a count of objects can be read
    /// as a statement about a dataset.
    #[must_use]
    pub const fn detects_loss(self) -> bool {
        matches!(self, Self::Recorded)
    }

    /// Every level, strongest first — the single list the tests below share, so
    /// a level added later cannot be forgotten by one of them.
    ///
    /// Test-only, and said so rather than carried into the binary behind an
    /// `allow(dead_code)`: nothing shipped enumerates the levels, because every
    /// caller has one in hand and asks it a question.
    #[cfg(test)]
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[Self::Recorded, Self::SelfReported]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::Assurance;

    #[test]
    fn only_a_record_kept_outside_the_remote_can_detect_a_lost_object() {
        // The distinction the type exists for. A listing compared against
        // itself agrees by construction, however carefully every object it
        // still contains is read back.
        assert!(Inventory::Recorded.detects_loss());
        assert!(!Inventory::SelfReported.detects_loss());
    }

    #[test]
    fn a_digest_over_the_bytes_says_nothing_about_an_object_that_is_gone() {
        // The two axes are independent, and this is the pairing that proves it:
        // a plain B2 remote records a per-object digest and detects rot, and its
        // listing is still the only record of what it holds. A gate that read
        // only `detects_corruption` let exactly that remote through and reported
        // `ok` over a deleted object.
        assert!(Assurance::ProviderChecksum.detects_corruption());
        assert!(!Inventory::SelfReported.detects_loss());
    }

    #[test]
    fn each_level_has_a_distinct_slug_and_explains_itself() {
        let levels = Inventory::all();
        for (index, level) in levels.iter().enumerate() {
            assert!(!level.slug().is_empty());
            assert!(!level.describe().is_empty());
            for other in &levels[index + 1..] {
                assert_ne!(level.slug(), other.slug());
                assert_ne!(level.describe(), other.describe());
            }
        }
    }

    #[test]
    fn an_inventory_slug_is_never_an_assurance_slug() {
        // The two travel side by side in one JSON document and in one coverage
        // line. A slug that appeared in both columns would make the document
        // ambiguous to the consumer it exists for.
        for inventory in Inventory::all() {
            for assurance in Assurance::all() {
                assert_ne!(inventory.slug(), assurance.slug());
            }
        }
    }
}
