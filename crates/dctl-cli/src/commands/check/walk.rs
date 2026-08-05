//! Walking two ordered trees at once.
//!
//! Both sides yield keys in ascending order and never repeat one — that is the
//! contract [`Entries`](crate::source::Entries) states and both implementations
//! honour — which is what makes a comparison of two ten-million-object trees a
//! **merge** rather than a join. A merge holds one entry per side; a join would
//! hold one of the two trees in a map, and
//! [the plan](https://doc.dctl.sh/project/plan) §16.2 rules that out for
//! exactly the datasets `check` exists to compare.
//!
//! The merge is also what makes the three presence answers fall out for free.
//! When the smaller key belongs to the source, that path exists only at the
//! source and the destination has already passed it; the reverse for the
//! destination; equal keys are the same object seen twice. No lookups, no second
//! pass, and no possibility of reporting a path that neither side listed.
//!
//! ## Ordering is load-bearing, so it is checked
//!
//! A side that yielded keys out of order would silently produce wrong verdicts:
//! a file that arrived late would be reported `missing-on-dst` and its
//! counterpart `missing-on-src`, and a `--missing-on-dst` list fed to
//! `dctl copy --files-from` would re-upload files that were already there. That
//! is a misreport, not a crash, so the walk refuses to continue rather than
//! trusting a source that broke the contract.

use crate::error::{CliError, Result};
use crate::exit::ExitCode;

use super::side::{Found, Side};

/// One path, as each side described it.
///
/// At least one half is always present: the walk only produces a pair for a key
/// at least one side listed.
pub struct Pair {
    /// The object at the source, if it is there.
    pub source: Option<Found>,
    /// The object at the destination, if it is there.
    pub dest: Option<Found>,
}

impl Pair {
    /// The comparison key both halves share.
    ///
    /// Taken from whichever half exists; when both do they are equal by
    /// construction, because that is the condition under which the walk pairs
    /// them.
    #[must_use]
    pub fn key(&self) -> &str {
        self.source
            .as_ref()
            .or(self.dest.as_ref())
            .map_or("", Found::key)
    }
}

/// Advance both sides by one key.
///
/// Returns [`None`] once both are exhausted, which is the only way the walk
/// ends: a side that runs out first keeps producing the other side's remaining
/// paths as one-sided pairs, so nothing at the tail of the longer tree is
/// silently dropped.
///
/// # Errors
/// Whatever either side reported while reading, and
/// [`ExitCode::Uncategorised`] if a side yields a key that goes backwards —
/// see the module documentation for why that cannot be tolerated.
pub async fn next(source: &mut Side, dest: &mut Side) -> Result<Option<Pair>> {
    let left = source.peek().await?.map(|found| found.key().to_string());
    let right = dest.peek().await?.map(|found| found.key().to_string());

    let pair = match (left, right) {
        (None, None) => return Ok(None),
        (Some(_), None) => Pair {
            source: source.take(),
            dest: None,
        },
        (None, Some(_)) => Pair {
            source: None,
            dest: dest.take(),
        },
        (Some(left), Some(right)) => match left.cmp(&right) {
            std::cmp::Ordering::Less => Pair {
                source: source.take(),
                dest: None,
            },
            std::cmp::Ordering::Greater => Pair {
                source: None,
                dest: dest.take(),
            },
            std::cmp::Ordering::Equal => Pair {
                source: source.take(),
                dest: dest.take(),
            },
        },
    };
    Ok(Some(pair))
}

/// Refuse a key that did not advance.
///
/// Called by the caller after each pair with the key it just handled, because
/// the caller is the only place that sees the whole sequence. Split out so the
/// rule is stated once and reads the same on both sides.
///
/// # Errors
/// [`ExitCode::Uncategorised`] when `key` is not strictly greater than
/// `previous`, naming both so the broken source can be identified.
pub fn ordered(previous: Option<&str>, key: &str) -> Result<()> {
    let Some(previous) = previous else {
        return Ok(());
    };
    if previous < key {
        return Ok(());
    }
    Err(CliError::new(
        ExitCode::Uncategorised,
        format!("a listing yielded '{key}' after '{previous}', which is out of order"),
    )
    .with_hint(
        "A comparison of two out-of-order listings reports differences that do not \
         exist. Nothing was changed. Please report this: it is a defect in the \
         source that produced the listing, not in the data.",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_that_advances_is_accepted_and_one_that_does_not_is_refused() {
        assert!(ordered(None, "a").is_ok());
        assert!(ordered(Some("a"), "b").is_ok());
        // Equal is as wrong as backwards: a repeated key would be compared
        // twice and counted twice.
        assert_eq!(
            ordered(Some("b"), "b").unwrap_err().code(),
            ExitCode::Uncategorised
        );
        let error = ordered(Some("b"), "a").unwrap_err();
        assert!(error.message().contains('a') && error.message().contains('b'));
        assert!(error.hint().is_some());
    }
}
