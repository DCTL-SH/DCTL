//! Everything a run against one source will be able to claim, in one value.
//!
//! There are two independent questions behind `dctl verify` and `dctl scrub`,
//! and answering only the first is what let a deleted object exit 0:
//!
//! | | question | answered by |
//! |---|---|---|
//! | the bytes | *are these the bytes that were written?* | [`Assurance`] |
//! | the set | *is everything that was written still here?* | [`Inventory`] |
//!
//! They do not move together. A sealed vault answers both. A plain B2 remote
//! answers the first — the provider recorded a digest at write time — and cannot
//! answer the second, because the only list of what it holds is the list it just
//! produced. A plain `local:` or `sftp:` remote answers neither.
//!
//! ## Why they travel as one value rather than as two arguments
//!
//! Because two arguments is the shape that has already gone wrong here twice.
//! `engine::verify` took a source and a prefix separately and the call site
//! passed the prefix of the *spec* instead of the prefix of the *resolver*, so
//! `dctl verify b2:DCTL001/photos` enumerated nothing and reported a clean tree.
//! The fix was to make the caller stop choosing.
//!
//! The same hazard is here and is worse, because both values are plain `Copy`
//! enums that type-check anywhere: a report could name the assurance of the
//! source in hand beside the inventory of some other one, and nothing would
//! complain. [`Claims::of`] is the only constructor outside tests, it takes the
//! source itself, and both the gate
//! ([`commands::integrity::assurance::require`](crate::commands::integrity::assurance::require))
//! and the report receive the same value — so the claim a run is *allowed* to
//! make and the claim it *publishes* cannot come from two different places.

use super::{Assurance, Inventory, Source};

/// What a successful run against one source proves — on both axes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Claims {
    /// What a clean read proves about the bytes that came back.
    pub assurance: Assurance,
    /// Where the list of objects came from, and therefore whether an object
    /// that is gone can be noticed.
    pub inventory: Inventory,
}

impl Claims {
    /// Read both claims off the source that will actually be walked.
    #[must_use]
    pub fn of(source: &dyn Source) -> Self {
        Self {
            assurance: source.assurance(),
            inventory: source.inventory(),
        }
    }

    /// Build a pair directly, for the tests that drive the gate and the reports
    /// without opening a remote.
    ///
    /// `#[cfg(test)]`, and no other constructor exists, which is the point: in
    /// the shipped binary the only way to obtain one of these is to hand over
    /// the source it describes.
    #[cfg(test)]
    #[must_use]
    pub const fn new(assurance: Assurance, inventory: Inventory) -> Self {
        Self {
            assurance,
            inventory,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::plain::PlainSource;
    use dctl_store::{Backend, LocalFs};
    use std::sync::Arc;

    #[test]
    fn the_pair_is_read_off_the_source_and_not_assembled_by_the_caller() {
        let dir = tempfile::TempDir::new().expect("a temporary directory");
        let backend: Arc<dyn Backend> = Arc::new(LocalFs::new(dir.path()));
        let source = PlainSource::new(backend);

        let claims = Claims::of(&source);
        assert_eq!(claims.assurance, source.assurance());
        assert_eq!(claims.inventory, source.inventory());
    }

    #[test]
    fn a_plain_filesystem_remote_can_answer_neither_question() {
        let dir = tempfile::TempDir::new().expect("a temporary directory");
        let backend: Arc<dyn Backend> = Arc::new(LocalFs::new(dir.path()));
        let claims = Claims::of(&PlainSource::new(backend));

        assert!(!claims.assurance.detects_corruption());
        assert!(!claims.inventory.detects_loss());
    }
}
