//! One file in flight between the `read` stage and the `upload` stage.
//!
//! The stage trait takes `&self` and a fact about a file has to survive from the
//! stage that established it to the stage that acts on it, so it is held
//! somewhere rather than in a local. What is worth a module is *what* is held.
//!
//! ## What this used to hold, and why it no longer can
//!
//! The file's entire contents. `read` pulled the whole plaintext into a
//! `Zeroizing<Vec<u8>>` and `upload` handed that buffer to the vault or the
//! store, which is the shape every buffered API in the stack wanted. It also
//! meant the peak memory of a transfer was the size of the largest file in it:
//! measured on the release binary, `copy` of a 1 GiB object into a vault peaked
//! at **3090 MiB** of resident memory and out of one at **2064 MiB**, both dead
//! straight in the object's size. A 10 GB video needed 20–30 GB of RAM, so the
//! engine carried a hard refusal above one gibibyte — a cloud backup tool that
//! could not store a film.
//!
//! Bytes therefore no longer pass through here at all. They are moved by the
//! `upload` stage in bounded windows, from the source straight to the
//! destination, and the largest thing this type has ever held since is a
//! timestamp.
//!
//! ## What is left, and why it is still a type
//!
//! A transfer's job is to make the destination hold what the source holds, and
//! "what the source holds" includes **when it was last modified** — the fact
//! every incremental run compares to decide whether a file needs sending at all.
//! Reading only the bytes left each destination free to invent one: a vault
//! index stamped the moment of the write, a local file got whatever the clock
//! said when it was created, and both are true statements about the copy rather
//! than about the original. So nothing ever matched its source, and `copy`,
//! `sync` and `check` re-transferred whole datasets on every run, forever.
//!
//! Pairing the time with the length in one type is what stops that returning. A
//! stage cannot claim to have moved a file without also being handed the
//! timestamp that belongs to it, and a destination that quietly dropped it would
//! have to do so visibly.

use dctl_core::Modified;

/// What the `read` stage established about one file, for the stage that moves it.
///
/// One field, and that is the point rather than an oversight. A length used to
/// travel here too, because `upload` reported it as the bytes written; the
/// number a completed transfer now reports is counted by the stream as the bytes
/// actually go past, which is the only one of the two that is true when a file
/// is being written to while it is read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Staged {
    /// When the *source* last changed — never when this copy was made.
    pub modified: Modified,
}

impl Staged {
    /// Record the time that belongs to a source's contents.
    #[must_use]
    pub const fn new(modified: Modified) -> Self {
        Self { modified }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_staged_file_carries_its_source_time_unchanged() {
        // The whole reason the type exists: a stage cannot claim to have moved a
        // file without being handed the time that belongs to it, so a
        // destination cannot be stamped with the moment of the copy by omission.
        let staged = Staged::new(Modified::At(1_700_000_000));
        assert_eq!(staged.modified, Modified::At(1_700_000_000));
    }

    #[test]
    fn nothing_in_flight_is_the_size_of_a_file() {
        // This type held every in-flight file's entire plaintext, and that was
        // the transfer engine's memory profile. The assertion is on the type's
        // own width so that re-growing a buffer here fails a test rather than a
        // machine: a `Vec` or a `Zeroizing<Vec<u8>>` field cannot be added
        // without tripping it.
        assert!(
            std::mem::size_of::<Staged>() <= 16,
            "Staged has grown: {} bytes",
            std::mem::size_of::<Staged>()
        );
    }
}
