//! One file in flight between the `read` stage and the `upload` stage.
//!
//! The stage trait takes `&self` and a file's bytes have to survive from the
//! stage that obtained them to the stage that stores them, so they are held
//! somewhere rather than in a local. What is worth a module is *what* is held.
//!
//! Bytes alone were not enough, and the gap was expensive. A transfer's job is to
//! make the destination hold what the source holds, and "what the source holds"
//! includes **when it was last modified** — the fact every incremental run
//! compares to decide whether a file needs sending at all. Reading only the bytes
//! left each destination free to invent one: a vault index stamped the moment of
//! the write, a local file got whatever the clock said when it was created, and
//! both are true statements about the copy rather than about the original. So
//! nothing ever matched its source, and `copy`, `sync` and `check` re-transferred
//! whole datasets on every run, forever.
//!
//! Pairing the two in one type is what stops that returning. A stage cannot take
//! the contents without also being handed the timestamp that belongs to them, and
//! a destination that quietly dropped it would have to do so visibly.
//!
//! The pairing is also the *only* correct way to obtain the two together: both
//! come from a single open handle wherever the platform allows it, so the
//! recorded time describes the bytes actually read. A separate `stat` afterwards
//! could describe a file that changed in between, and the destination would then
//! claim a modification time its contents never had — which is worse than no
//! timestamp, because the next run would believe it.

use dctl_core::Modified;
use zeroize::Zeroizing;

/// A file's plaintext, and the modification time that must travel with it.
pub struct Staged {
    /// The contents, wiped when this value is dropped.
    ///
    /// `Zeroizing` rather than a plain `Vec`, because this is plaintext in a
    /// crypto tool: it is the one thing in the pipeline that must not outlive its
    /// use in a core dump, a swap file or a formatted panic message.
    pub bytes: Zeroizing<Vec<u8>>,
    /// When the *source* last changed — never when this copy was made.
    pub modified: Modified,
}

impl Staged {
    /// Stage contents alongside the source time they belong to.
    #[must_use]
    pub const fn new(bytes: Zeroizing<Vec<u8>>, modified: Modified) -> Self {
        Self { bytes, modified }
    }

    /// How many bytes are in flight.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.bytes.len() as u64
    }
}

impl std::fmt::Debug for Staged {
    /// Written by hand so the plaintext cannot be rendered.
    ///
    /// A derived implementation would print the file's contents:
    /// `Zeroizing<Vec<u8>>` forwards `Debug` to the bytes it wraps, and wiping on
    /// drop does nothing about a copy already formatted into a log line. The
    /// length and the timestamp are what a diagnostic actually needs.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Staged")
            .field("bytes", &self.len())
            .field("modified", &self.modified)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staged_contents_are_never_rendered_by_debug() {
        // The assertion is about a leak, so it is made against the formatted
        // string rather than by reading the implementation: a future derive would
        // compile, pass every other test, and print plaintext into whatever log
        // the operator was tailing.
        let staged = Staged::new(
            Zeroizing::new(b"a passphrase in a file".to_vec()),
            Modified::At(1_700_000_000),
        );
        let rendered = format!("{staged:?}");
        assert!(!rendered.contains("passphrase"), "{rendered}");
        assert!(rendered.contains("22"), "the length is what is useful");
        assert!(rendered.contains("1700000000"), "{rendered}");
    }

    #[test]
    fn the_length_reported_is_the_length_stored() {
        assert_eq!(
            Staged::new(Zeroizing::new(vec![0_u8; 42]), Modified::Now).len(),
            42
        );
    }
}
