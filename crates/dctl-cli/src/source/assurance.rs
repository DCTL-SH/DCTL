//! What a successful [`Source::verify`](super::Source::verify) actually proves.
//!
//! Two sources can both answer "yes, that object read back cleanly" and mean
//! very different things by it, and the difference is the whole value of a
//! scrub:
//!
//! * a sealed vault checks every chunk's authentication tag and the object's own
//!   recorded content hash, so a pass means *these are the bytes that were
//!   written*;
//! * a plain object store records no hash of its own, so the strongest honest
//!   claim a pass supports is *the object is still there and every byte of it
//!   came back*. A provider that silently returned different bytes would not be
//!   caught, because there is nothing on that side to catch it with.
//!
//! Both are worth running on a schedule — the second is exactly the check that
//! notices a replica quietly losing objects — and neither is a substitute for
//! the other. So the claim travels with the result instead of being folded into
//! one word: `PLAN.md` §6 forbids reporting a guarantee that was not checked,
//! and "healthy" over a store that cannot detect corruption would be precisely
//! that.
//!
//! This is not the same axis as the `--verify` strength dial
//! ([`crate::commands::integrity::mode`]). Strength says *how much was read*;
//! assurance says *what the reading could prove*. A full read of a store with no
//! recorded hashes is still only a retrievability check.

use crate::constants::{ASSURANCE_AUTHENTICATED, ASSURANCE_READ_BACK};

/// The strongest claim a source can make about bytes it read back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Assurance {
    /// Checked against a hash recorded when the object was written.
    Authenticated,
    /// Read back in full, with nothing to check the bytes against.
    ReadBack,
}

impl Assurance {
    /// The stable slug used in `--json` output.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Authenticated => ASSURANCE_AUTHENTICATED,
            Self::ReadBack => ASSURANCE_READ_BACK,
        }
    }

    /// One-line explanation, shown beside a health grade so the grade cannot be
    /// read as a stronger claim than the one that was measured.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::Authenticated => {
                "every byte was re-read and authenticated against the hash recorded when \
                 it was written"
            }
            Self::ReadBack => {
                "every byte was re-read, but this remote records no hash of its own, so a \
                 pass proves the object is retrievable and not that it is unchanged"
            }
        }
    }

    /// Whether a pass proves the bytes are the bytes that were stored.
    ///
    /// The question a report has to answer before it prints "healthy".
    #[must_use]
    pub const fn detects_corruption(self) -> bool {
        matches!(self, Self::Authenticated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_authenticated_read_can_detect_corruption() {
        // The distinction the type exists for. A plain store returning altered
        // bytes reads back perfectly; nothing on that side can tell.
        assert!(Assurance::Authenticated.detects_corruption());
        assert!(!Assurance::ReadBack.detects_corruption());
    }

    #[test]
    fn each_level_has_a_distinct_slug_and_explains_itself() {
        assert_ne!(Assurance::Authenticated.slug(), Assurance::ReadBack.slug());
        for level in [Assurance::Authenticated, Assurance::ReadBack] {
            assert!(!level.slug().is_empty());
            assert!(!level.describe().is_empty());
        }
    }
}
