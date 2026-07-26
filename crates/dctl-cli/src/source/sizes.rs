//! What a source's byte counts actually measure.
//!
//! Every [`Entry`](super::Entry) carries a `size`, and for the five listing
//! verbs that render one object per row it does not matter where that number
//! came from: the row names the file it belongs to, and a reader comparing it
//! against `cat | wc -c` gets the answer they expect either way.
//!
//! `dctl size` is the exception, and it is the reason this type exists. It
//! collapses a whole vault into a single figure that people then reconcile
//! against something external — a provider invoice, a quota alarm, a capacity
//! plan. A sealed vault reports the length of the files that were *written*,
//! because that is what [`Record::size`](dctl_core::Record) holds; the objects
//! the provider is actually storing and billing for are larger, by the envelope
//! and per-chunk AEAD overhead the format adds. The two numbers are both true
//! and they are not the same number, and a report that prints one of them
//! without saying which invites a user to conclude their provider is
//! overcharging them — or, worse, to size a migration against a figure that is
//! short.
//!
//! So the basis travels with the source rather than being inferred at the point
//! of printing. Inferring it would mean a command asking "is this a vault?",
//! which is exactly the branch [`super::open`] exists to prevent: a second
//! answer to that question is a second answer that can disagree with the first.
//!
//! ## This is not a way to tell the implementations apart
//!
//! A caller learns what its numbers *mean*; it does not learn what it is
//! holding, and there is nothing here to branch on to reach a different code
//! path. The distinction matters because the moment a command can ask "am I
//! reading a vault", it will eventually do something other than label a column
//! with the answer — and the sealed and plain views start diverging again.

use serde::{Serialize, Serializer};

use crate::constants::{SIZE_BASIS_PLAINTEXT, SIZE_BASIS_STORED};

/// The basis of the byte counts a source reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sizes {
    /// The length of the file as it was written, before it was sealed.
    ///
    /// What a sealed vault records and the only length it can cheaply know: the
    /// index stores the plaintext size, and the ciphertext length would have to
    /// be asked of the provider object by object.
    Plaintext,
    /// The length of the object exactly as the provider holds it.
    ///
    /// A plain store's own figure, so it is also the one that appears on a bill.
    Stored,
}

impl Sizes {
    /// The one-word name of this basis.
    ///
    /// Shared by the text report and the JSON field deliberately: two spellings
    /// of the same fact are two spellings that can drift, and a script keying on
    /// the JSON value should be reading the same word a person read on screen.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Plaintext => SIZE_BASIS_PLAINTEXT,
            Self::Stored => SIZE_BASIS_STORED,
        }
    }

    /// Whether the figure excludes encryption overhead, and therefore
    /// understates what a provider is storing.
    #[must_use]
    pub const fn understates_stored_bytes(self) -> bool {
        matches!(self, Self::Plaintext)
    }
}

impl Serialize for Sizes {
    /// Serialised through [`Sizes::label`] rather than derived, so the JSON
    /// value and the printed word cannot become two different vocabularies.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.label())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_basis_has_a_distinct_name() {
        // They are printed beside a number a user is about to act on; two bases
        // that rendered identically would be worse than not labelling at all.
        assert_ne!(Sizes::Plaintext.label(), Sizes::Stored.label());
        assert!(!Sizes::Plaintext.label().is_empty());
        assert!(!Sizes::Stored.label().is_empty());
    }

    #[test]
    fn only_the_plaintext_basis_understates_what_is_stored() {
        assert!(Sizes::Plaintext.understates_stored_bytes());
        assert!(!Sizes::Stored.understates_stored_bytes());
    }

    #[test]
    fn the_json_value_is_the_printed_word() {
        for basis in [Sizes::Plaintext, Sizes::Stored] {
            let encoded = serde_json::to_value(basis).expect("a basis encodes");
            assert_eq!(encoded, serde_json::Value::String(basis.label().into()));
        }
    }
}
