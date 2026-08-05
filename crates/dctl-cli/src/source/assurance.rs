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
//! Both are worth running on a schedule and neither is a substitute for the
//! other. So the claim travels with the result instead of being folded into one
//! word: [the plan](https://doc.dctl.sh/project/plan) §6 forbids reporting a guarantee that was not checked, and
//! "healthy" over a store that cannot detect corruption would be precisely that.
//!
//! This is not the same axis as the `--verify` strength dial
//! ([`crate::commands::integrity::mode`]). Strength says *how much was read*;
//! assurance says *what the reading could prove*. A full read of a store with no
//! recorded hashes is still only a retrievability check.
//!
//! **And it is not the same axis as [`Inventory`](super::Inventory) either.**
//! This one is about the objects a run *examined*; that one is about the objects
//! it should have examined and did not, because nothing told it they existed.
//! The strongest assurance available says nothing about an object that is gone,
//! and the two were conflated in the sentence this module's own documentation
//! used to carry — "the second is exactly the check that notices a replica
//! quietly losing objects", which was false of the only remotes it described.

use crate::constants::{ASSURANCE_AUTHENTICATED, ASSURANCE_PROVIDER_CHECKSUM, ASSURANCE_READ_BACK};

/// The strongest claim a source can make about bytes it read back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Assurance {
    /// Checked against a hash recorded when the object was written, under a key
    /// only the vault holds.
    Authenticated,
    /// Checked against the digest the **provider** recorded when the object was
    /// written.
    ///
    /// Between the other two, and it is the level that makes `dctl verify` mean
    /// something on a plain remote. The digest is not DCTL's and is not keyed,
    /// so it is not the vault's claim; but it was written down at write time and
    /// it lives in the provider's metadata rather than in the object, so a
    /// changed byte disagrees with it. That is precisely what a rot check needs.
    ProviderChecksum,
    /// Read back in full, with nothing to check the bytes against.
    ReadBack,
}

impl Assurance {
    /// The stable slug used in `--json` output.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Authenticated => ASSURANCE_AUTHENTICATED,
            Self::ProviderChecksum => ASSURANCE_PROVIDER_CHECKSUM,
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
            Self::ProviderChecksum => {
                "every byte was re-read and compared against the digest the provider \
                 recorded when the object was written"
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
        matches!(self, Self::Authenticated | Self::ProviderChecksum)
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
        &[Self::Authenticated, Self::ProviderChecksum, Self::ReadBack]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_read_with_something_to_compare_against_can_detect_corruption() {
        // The distinction the type exists for. A plain store that records
        // nothing returns altered bytes and reads back perfectly; nothing on
        // that side can tell. One that recorded a digest at write time can.
        assert!(Assurance::Authenticated.detects_corruption());
        assert!(Assurance::ProviderChecksum.detects_corruption());
        assert!(!Assurance::ReadBack.detects_corruption());
    }

    #[test]
    fn a_providers_digest_is_not_the_vaults_claim() {
        // Both detect rot and they are not the same statement: one is DCTL's
        // own hash under a key, the other is metadata the provider keeps beside
        // the bytes. A report that printed one word for both would let a plain
        // b2 remote read as a vault.
        assert_ne!(
            Assurance::ProviderChecksum.slug(),
            Assurance::Authenticated.slug()
        );
        assert_ne!(
            Assurance::ProviderChecksum.describe(),
            Assurance::Authenticated.describe()
        );
    }

    #[test]
    fn each_level_has_a_distinct_slug_and_explains_itself() {
        let levels = Assurance::all();
        for (index, level) in levels.iter().enumerate() {
            assert!(!level.slug().is_empty());
            assert!(!level.describe().is_empty());
            for other in &levels[index + 1..] {
                assert_ne!(level.slug(), other.slug());
                assert_ne!(level.describe(), other.describe());
            }
        }
    }
}
