//! What a snapshot may be called, and what it is called when nobody says.
//!
//! A snapshot name is not decoration. It becomes the handle an operator types
//! into `restore --snapshot` at three in the morning, and — once the engine
//! stores them — a path component, an object-key fragment and a URL segment. A
//! name that needs escaping in any of those three is a name that will one day be
//! escaped differently in two of them, so the accepted alphabet is the
//! intersection of what all three tolerate untouched.
//!
//! Validation lives here rather than in the argument parser because both
//! `backup` and `restore` name snapshots and must agree byte for byte on what a
//! name is: a `backup --snapshot-name` that accepted something
//! `restore --snapshot` rejected would create a snapshot nobody could ask for.

use std::fmt;

use serde::Serialize;

use crate::constants::{
    SNAPSHOT_AUTO_NAME_PREFIX, SNAPSHOT_NAME_EXTRA_CHARS, SNAPSHOT_NAME_MAX_LEN,
};
use crate::error::{CliError, Result};

use super::timespec::UnixSeconds;

/// A validated snapshot name.
///
/// Serialises as the bare string, so a plan document reads `"snapshot":
/// "nightly"` rather than wrapping it in an object that says nothing extra.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct SnapshotName(String);

impl SnapshotName {
    /// Validate a name typed by a user.
    ///
    /// # Errors
    /// [`crate::exit::ExitCode::Usage`] when the name is empty, longer than
    /// [`SNAPSHOT_NAME_MAX_LEN`], contains anything outside the accepted
    /// alphabet, or is one of the two names every filesystem reserves.
    pub fn parse(name: &str) -> Result<Self> {
        let name = name.trim();

        if name.is_empty() {
            return Err(CliError::usage("a snapshot name cannot be empty")
                .with_hint("Name it after what it is, for example 'nightly' or 'pre-upgrade'."));
        }

        if name.chars().count() > SNAPSHOT_NAME_MAX_LEN {
            return Err(CliError::usage(format!(
                "snapshot name '{name}' is longer than {SNAPSHOT_NAME_MAX_LEN} characters"
            ))
            .with_hint("A snapshot name has to fit in one path component on every platform."));
        }

        if let Some(bad) = name
            .chars()
            .find(|c| !c.is_ascii_alphanumeric() && !SNAPSHOT_NAME_EXTRA_CHARS.contains(c))
        {
            let allowed: String = SNAPSHOT_NAME_EXTRA_CHARS.iter().collect();
            return Err(
                CliError::usage(format!("snapshot name '{name}' contains '{bad}'")).with_hint(
                    format!(
                        "Snapshot names use ASCII letters, digits and {allowed} — the \
                         characters that survive a path, an object key and a URL unescaped."
                    ),
                ),
            );
        }

        // `.` and `..` are directory entries on every filesystem, and a leading
        // dot hides the snapshot from an operator listing the tree by eye.
        if name.starts_with('.') {
            return Err(
                CliError::usage(format!("snapshot name '{name}' starts with a dot")).with_hint(
                    "A leading dot names the current or parent directory, and hides \
                     the snapshot from an ordinary listing.",
                ),
            );
        }

        Ok(Self(name.to_string()))
    }

    /// The name a run gets when `--snapshot` is given without one.
    ///
    /// `snap-<unix seconds>`: it sorts chronologically as plain text, is
    /// unambiguous in every timezone, and cannot repeat itself the way a
    /// local-time spelling does for an hour every autumn.
    #[must_use]
    pub fn generated(at: UnixSeconds) -> Self {
        Self(format!("{SNAPSHOT_AUTO_NAME_PREFIX}{at}"))
    }

    /// Resolve the pair of flags a command carries: whether a snapshot was asked
    /// for, and what it should be called.
    ///
    /// # Errors
    /// Propagates [`SnapshotName::parse`].
    pub fn resolve(
        requested: bool,
        explicit: Option<&str>,
        at: UnixSeconds,
    ) -> Result<Option<Self>> {
        match (requested, explicit) {
            (_, Some(name)) => Self::parse(name).map(Some),
            (true, None) => Ok(Some(Self::generated(at))),
            (false, None) => Ok(None),
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SnapshotName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::exit::ExitCode;

    #[test]
    fn ordinary_names_are_accepted_and_trimmed() {
        assert_eq!(SnapshotName::parse("nightly").unwrap().as_str(), "nightly");
        assert_eq!(
            SnapshotName::parse("  pre-upgrade_2026.07  ")
                .unwrap()
                .as_str(),
            "pre-upgrade_2026.07"
        );
    }

    #[test]
    fn a_generated_name_sorts_chronologically() {
        // Text sorting has to agree with time ordering, or a listing of
        // snapshots is in an order nobody can use.
        let earlier = SnapshotName::generated(1_753_574_400);
        let later = SnapshotName::generated(1_784_937_600);
        assert!(earlier < later);
        assert!(earlier.as_str().starts_with(SNAPSHOT_AUTO_NAME_PREFIX));
    }

    #[test]
    fn a_generated_name_is_itself_a_legal_name() {
        // Otherwise `backup --snapshot` would create something
        // `restore --snapshot` could not accept.
        let generated = SnapshotName::generated(1_784_937_600);
        assert_eq!(SnapshotName::parse(generated.as_str()).unwrap(), generated);
    }

    #[test]
    fn characters_that_would_need_escaping_are_refused() {
        for name in [
            "back/up",   // a path separator
            "vault:one", // the remote separator
            "with space",
            "caf\u{e9}", // outside ASCII: encodes differently in a URL
            "star*",
            "back\\up",
        ] {
            let error = SnapshotName::parse(name).unwrap_err();
            assert_eq!(error.code(), ExitCode::Usage, "{name} should be refused");
            assert!(error.hint().is_some());
        }
    }

    #[test]
    fn the_names_every_filesystem_reserves_are_refused() {
        for name in [".", "..", ".hidden"] {
            assert_eq!(
                SnapshotName::parse(name).unwrap_err().code(),
                ExitCode::Usage
            );
        }
    }

    #[test]
    fn empty_and_overlong_names_are_refused() {
        assert!(SnapshotName::parse("").is_err());
        assert!(SnapshotName::parse("   ").is_err());
        let long = "a".repeat(SNAPSHOT_NAME_MAX_LEN + 1);
        assert!(SnapshotName::parse(&long).is_err());
        // The boundary itself is allowed.
        assert!(SnapshotName::parse(&"a".repeat(SNAPSHOT_NAME_MAX_LEN)).is_ok());
    }

    #[test]
    fn resolution_covers_the_three_states_of_the_flags() {
        // Not asked for.
        assert_eq!(SnapshotName::resolve(false, None, 1).unwrap(), None);
        // Asked for, unnamed: generated.
        let generated = SnapshotName::resolve(true, None, 1).unwrap().unwrap();
        assert_eq!(generated, SnapshotName::generated(1));
        // Named explicitly.
        let named = SnapshotName::resolve(true, Some("nightly"), 1)
            .unwrap()
            .unwrap();
        assert_eq!(named.as_str(), "nightly");
    }

    #[test]
    fn a_name_serialises_as_a_bare_string() {
        // A plan document should read "snapshot": "nightly", not an object.
        let json = serde_json::to_string(&SnapshotName::parse("nightly").unwrap()).unwrap();
        assert_eq!(json, "\"nightly\"");
    }
}
