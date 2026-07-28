//! What a store *is*, as far as its provider can tell one from another — and
//! how much that answer is worth.
//!
//! # The defect this exists to make impossible
//!
//! A `dctl copy` of 25 files into a vault, with the object store renamed away
//! three seconds in:
//!
//! ```text
//!  Transferred: 9.54 MiB / 9.54 MiB, 100%, 2.71 MiB/s
//!     Verified: 9.54 MiB checksum-matched
//!        Files: 25 / 25
//!       Errors: 0
//! ```
//!
//! Exit 0, and not one object in a vault. `create_dir_all` re-created the store
//! path, every write landed in the new empty directory, and the post-write
//! read-back passed because it re-read the same wrong place. That was fixed for
//! `local:` and for `local:` only, which `HANDOVER.md` §11.2 records: *"A deleted
//! bucket or a removed SFTP base mid-run is unguarded and untested."*
//!
//! It is reproducible on SFTP. Twenty-five files, the base renamed away at three
//! seconds: **seventeen objects landed in a directory the backend re-created**,
//! and the run reported `Files: 24 / 25` and `9.16 MiB checksum-matched`. One
//! file errored — the one in flight — which is the only reason the exit code was
//! not zero.
//!
//! # Why identity, and not existence
//!
//! Checking only that *something* is there passes in exactly the case that
//! matters: the write path puts one back. What has to be compared is whether it
//! is the **same** container. On a Unix filesystem that is `(st_dev, st_ino)`;
//! on B2 it is the bucket id, which a deleted-and-recreated bucket does not
//! keep.
//!
//! # Why the answer carries how strong it is
//!
//! Because two of the five providers cannot give a real one, and a guard that
//! quietly did its best would be the same silent partial answer it exists to
//! remove. SFTP version 3's `SSH_FXP_STAT` returns size, uid, gid, permissions
//! and two timestamps and **no inode**; S3 gives a bucket no id at all. Both can
//! answer *"is it still there"* and neither can answer *"is it the same one"*, so
//! [`Strength`] is part of the value and [`Guarded`](super::Guarded) reports it
//! in the log line an operator reads afterwards.
//!
//! The two [`Strength::ExistenceOnly`] providers are not left resting on the weak
//! half alone: the SFTP write path no longer creates the base directory it was
//! configured with (`sftp::path::ancestors_below`), so a base that has been
//! removed makes every write fail loudly instead of being silently re-created
//! underneath one. Existence is the guard; not re-creating it is what makes the
//! guard's answer stay true for the rest of the run.
//!
//! # Why a root that was absent at first use is not an error
//!
//! `dctl config create backup local path=/srv/new` names a directory that may
//! not exist yet, and the first write through it legitimately creates one. So an
//! *unrecorded* identity — nothing was there when the run started — admits the
//! write. Only a container that existed and has since been removed or replaced
//! is a failure. That rule has no false positives: it never refuses a write the
//! unguarded code would have performed correctly.

use crate::error::StoreError;

/// How much a comparison of two [`StoreIdentity`] values is worth.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Strength {
    /// The token changes when the container is replaced by a different one: an
    /// `(st_dev, st_ino)` pair, a bucket id.
    Distinguishing,
    /// The token only says the container is still there. A replacement created
    /// in the same place is indistinguishable from the original, and the
    /// provider's protocol offers nothing that would tell them apart.
    ExistenceOnly,
}

impl Strength {
    /// A short word for a log field.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Distinguishing => "distinguishing",
            Self::ExistenceOnly => "existence-only",
        }
    }
}

/// What a provider says its container is, right now.
///
/// The token is opaque: nothing outside a backend's own `store_identity`
/// constructs one, and nothing anywhere reads the string. Only two of them are
/// ever compared.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreIdentity {
    token: String,
    strength: Strength,
}

impl StoreIdentity {
    /// An identity that changes when the container is replaced.
    #[must_use]
    pub fn distinguishing(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
            strength: Strength::Distinguishing,
        }
    }

    /// An identity that only says the container is still there.
    ///
    /// The constructor takes no token because there is nothing to compare: every
    /// value it produces is equal to every other. Spelling that out here rather
    /// than letting a backend pass a constant string is what keeps a provider
    /// from *looking* like it distinguishes containers when it does not.
    #[must_use]
    pub fn existence_only() -> Self {
        Self {
            token: String::new(),
            strength: Strength::ExistenceOnly,
        }
    }

    /// How much comparing this against another is worth.
    #[must_use]
    pub const fn strength(&self) -> Strength {
        self.strength
    }
}

/// What became of the container between the run's first operation and now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Write. Either it is the container this run has been using, or there was
    /// none to record and creating it is the caller's ordinary first write.
    Proceed,
    /// It existed and is gone.
    Gone,
    /// It existed and a *different* one now stands in its place.
    Replaced,
}

/// Compare a recorded identity with a current one.
///
/// Pure, and that is what makes the rule assertable without arranging a
/// filesystem, an ssh host and a bucket for every case: the three outcomes are a
/// function of two `Option<StoreIdentity>`s and nothing else.
#[must_use]
pub fn verdict(recorded: Option<&StoreIdentity>, now: Option<&StoreIdentity>) -> Verdict {
    match (recorded, now) {
        // Nothing was there to be lost. A first write creates the container.
        (None, _) => Verdict::Proceed,
        (Some(_), None) => Verdict::Gone,
        (Some(before), Some(after)) => {
            if before.token == after.token {
                Verdict::Proceed
            } else {
                Verdict::Replaced
            }
        }
    }
}

/// The error a caller reports, naming the container and what happened to it.
///
/// Says what the run must not be allowed to believe — that the objects are where
/// they were asked to go — rather than only what the provider returned.
#[must_use]
pub fn refuse(container: &str, verdict: Verdict) -> StoreError {
    let what = match verdict {
        Verdict::Gone => "has been removed",
        Verdict::Replaced => "has been replaced by a different one",
        // Never constructed: a caller only reports a refusal.
        Verdict::Proceed => "changed",
    };
    StoreError::RootChanged {
        root: container.to_string(),
        detail: what,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(token: &str) -> StoreIdentity {
        StoreIdentity::distinguishing(token)
    }

    #[test]
    fn a_container_that_never_existed_admits_the_write_that_creates_it() {
        // `dctl config create backup local path=/srv/new` names a directory that
        // does not exist yet, and the first copy through it must still work. A
        // guard that refused here would break the ordinary case to catch the
        // rare one.
        assert_eq!(verdict(None, None), Verdict::Proceed);
        assert_eq!(verdict(None, Some(&id("7"))), Verdict::Proceed);
    }

    #[test]
    fn the_same_container_admits_the_write() {
        assert_eq!(verdict(Some(&id("7")), Some(&id("7"))), Verdict::Proceed);
    }

    #[test]
    fn a_container_that_was_there_and_is_not_is_refused() {
        assert_eq!(verdict(Some(&id("7")), None), Verdict::Gone);
    }

    #[test]
    fn a_container_replaced_by_a_different_one_is_refused() {
        // The case the write path's own `mkdir -p` creates, and the reason
        // existence is not enough: something *is* at the path, and it is not the
        // store.
        assert_eq!(verdict(Some(&id("7")), Some(&id("8"))), Verdict::Replaced);
    }

    #[test]
    fn an_existence_only_provider_cannot_see_a_replacement_and_does_not_pretend_to() {
        // Two `existence_only` identities are equal by construction, so a
        // replacement reads as `Proceed`. That is the honest answer for SFTP
        // version 3 and for S3, and it is stated here rather than left to be
        // discovered — the removal half is what those two really catch, and the
        // write paths no longer re-create the container underneath a run.
        let before = StoreIdentity::existence_only();
        let after = StoreIdentity::existence_only();
        assert_eq!(verdict(Some(&before), Some(&after)), Verdict::Proceed);
        assert_eq!(verdict(Some(&before), None), Verdict::Gone);
        assert_eq!(before.strength(), Strength::ExistenceOnly);
    }

    #[test]
    fn the_refusal_names_the_container_and_says_which_of_the_two_happened() {
        let gone = refuse("/srv/vault", Verdict::Gone);
        let text = gone.to_string();
        assert!(text.contains("/srv/vault"), "{text}");
        assert!(text.contains("removed"), "{text}");

        let replaced = refuse("b2:DCTL001", Verdict::Replaced);
        let text = replaced.to_string();
        assert!(text.contains("DCTL001"), "{text}");
        assert!(text.contains("replaced"), "{text}");
    }

    #[test]
    fn a_strength_has_a_word_for_the_log() {
        // The field an operator reads to know what the guard was actually able
        // to check on this provider. An empty one would make the disclosure
        // invisible, which is the shape of problem this whole module is about.
        for strength in [Strength::Distinguishing, Strength::ExistenceOnly] {
            assert!(!strength.label().is_empty());
        }
        assert_ne!(
            Strength::Distinguishing.label(),
            Strength::ExistenceOnly.label()
        );
    }
}
