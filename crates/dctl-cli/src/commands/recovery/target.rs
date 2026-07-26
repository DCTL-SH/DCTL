//! Turning a `REMOTE:PATH` argument into a vault location a recovery can name.
//!
//! `backup` writes into one of these and `restore` reads out of one, so a
//! mis-parse is not a cosmetic problem: a backup that silently resolves to the
//! wrong scope stores a tree nobody will look for, and a restore that does the
//! same writes the wrong data over a live directory. The parse therefore refuses
//! anything ambiguous rather than guessing, and it is the only place in the
//! family that interprets user path syntax.
//!
//! The disambiguation rules are the ones documented in [`crate::platform::path`]:
//! a single character before the colon is a Windows drive letter, a
//! `\\`-prefixed string is a UNC share, and both are *local* paths that neither
//! side of a recovery accepts as a vault. A remote name is therefore at least
//! [`MIN_REMOTE_NAME_LEN`] characters, which is what makes `C:\data`
//! unambiguous on every platform rather than only on Windows.

use std::fmt;

use serde::Serialize;

use crate::constants::{MIN_REMOTE_NAME_LEN, PATH_SEPARATOR, REMOTE_SEPARATOR};
use crate::error::{CliError, Result};
use crate::platform::path;

/// A resolved vault location: a named remote plus a canonical logical path.
///
/// The path is already cleaned and NFC-normalised, so two spellings of the same
/// name (`photos//2024/` and `photos/2024`, or a macOS-decomposed `café`)
/// resolve to one location. Anything that survives construction is safe to hand
/// to the engine unchanged.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Target {
    /// Name of the configured remote, without the separator.
    pub remote: String,
    /// Canonical logical path inside that remote. Empty means the vault root.
    pub path: String,
}

impl Target {
    /// Parse a `REMOTE:PATH` specification.
    ///
    /// # Errors
    /// [`crate::exit::ExitCode::Usage`] when the spec names a local path, omits
    /// the remote, uses a remote name short enough to be a drive letter, or
    /// tries to escape its root with `..`.
    pub fn parse(spec: &str) -> Result<Self> {
        let spec = spec.trim();
        if spec.is_empty() {
            return Err(CliError::usage("no vault given").with_hint(
                "Name the vault side as REMOTE:PATH, for example 'vault:photos/2024'.",
            ));
        }

        // Local paths are rejected before the colon split, because `C:\data`
        // *does* contain a colon and would otherwise parse as a remote called
        // `C` — which is how a backup ends up writing to a vault nobody named.
        if path::looks_like_unc(spec) || path::looks_like_windows_drive(spec) {
            return Err(
                CliError::usage(format!("'{spec}' is a local path, not a vault")).with_hint(
                    "A recovery has one local side and one vault side. The vault is \
                     written REMOTE:PATH; the local side is an ordinary path.",
                ),
            );
        }

        let Some((remote, rest)) = spec.split_once(REMOTE_SEPARATOR) else {
            return Err(
                CliError::usage(format!("'{spec}' is not a remote specification")).with_hint(
                    "Write the vault side as REMOTE:PATH, for example 'vault:photos/2024'.",
                ),
            );
        };

        if remote.len() < MIN_REMOTE_NAME_LEN {
            return Err(
                CliError::usage(format!("'{remote}' is too short to be a remote name")).with_hint(
                    format!(
                        "Remote names are at least {MIN_REMOTE_NAME_LEN} characters, so a \
                 one-letter prefix is always a Windows drive.",
                    ),
                ),
            );
        }

        if remote.contains(PATH_SEPARATOR) || remote.contains('\\') {
            return Err(
                CliError::usage(format!("'{remote}' is not a valid remote name")).with_hint(
                    "A remote name is a bare name from the config file; it contains \
                     no path separators.",
                ),
            );
        }

        let Some(path) = path::clean_logical(rest) else {
            return Err(
                CliError::usage(format!("'{rest}' escapes the remote with '..'")).with_hint(
                    "Vault paths are relative to the vault root and may not contain \
                     '..' components.",
                ),
            );
        };

        Ok(Self {
            remote: remote.to_string(),
            path,
        })
    }

    /// Whether this names the whole remote rather than a path inside it.
    ///
    /// A restore branches on it constantly: `restore vault: /tmp/out` is the
    /// entire dataset, which is worth saying out loud before it starts.
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.path.is_empty()
    }

    /// Whether `logical` lies within this target's scope.
    ///
    /// Whole-component comparison, so `photos/2024` does not capture
    /// `photos/2024-backup` — the same rule that keeps a `sync` from deleting
    /// the wrong tree.
    #[must_use]
    pub fn covers(&self, logical: &str) -> bool {
        path::is_under(&self.path, logical)
    }

    /// The logical path with this target's prefix removed, which is where the
    /// object lands beneath the local root of a restore.
    ///
    /// `restore vault:photos /tmp/out` writes `photos/2024/a.jpg` to
    /// `/tmp/out/2024/a.jpg`, not to `/tmp/out/photos/2024/a.jpg`: the operand
    /// names the tree, so repeating it under the destination would nest the
    /// result one level deeper than anyone asked for. This mirrors how `copy`
    /// treats a source directory.
    #[must_use]
    pub fn relative<'a>(&self, logical: &'a str) -> &'a str {
        if self.path.is_empty() {
            return logical;
        }
        logical
            .strip_prefix(self.path.as_str())
            .map_or(logical, |rest| rest.trim_start_matches(PATH_SEPARATOR))
    }
}

impl fmt::Display for Target {
    /// Renders back to the spelling the user typed, so a prompt, a log record
    /// and an error all quote the same string.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}{}", self.remote, REMOTE_SEPARATOR, self.path)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::exit::ExitCode;

    #[test]
    fn a_remote_and_a_path_are_split_at_the_first_colon() {
        let target = Target::parse("vault:photos/2024").unwrap();
        assert_eq!(target.remote, "vault");
        assert_eq!(target.path, "photos/2024");
        assert!(!target.is_root());
        assert_eq!(target.to_string(), "vault:photos/2024");
    }

    #[test]
    fn a_bare_remote_is_the_whole_vault() {
        let target = Target::parse("vault:").unwrap();
        assert!(target.is_root());
        assert_eq!(target.path, "");
        assert!(target.covers("anything/at/all"));
    }

    #[test]
    fn paths_are_canonicalised_before_anything_is_planned() {
        assert_eq!(
            Target::parse("vault:./photos//2024/").unwrap().path,
            "photos/2024"
        );
        assert_eq!(
            Target::parse(r"vault:photos\2024").unwrap().path,
            "photos/2024"
        );
    }

    #[test]
    fn unicode_spellings_converge_on_one_location() {
        // macOS hands back NFD. Without normalisation a restore typed on a Mac
        // would address a different object from the same name typed on Linux.
        let nfd = Target::parse("vault:cafe\u{301}/a.jpg").unwrap();
        let nfc = Target::parse("vault:caf\u{e9}/a.jpg").unwrap();
        assert_eq!(nfd, nfc);
    }

    #[test]
    fn a_drive_letter_is_never_a_remote() {
        for spec in [r"C:\data", "c:/data", r"\\server\share"] {
            let error = Target::parse(spec).unwrap_err();
            assert_eq!(error.code(), ExitCode::Usage);
            assert!(error.hint().is_some());
        }
    }

    #[test]
    fn a_missing_colon_is_a_usage_error() {
        assert_eq!(
            Target::parse("photos/2024").unwrap_err().code(),
            ExitCode::Usage
        );
        assert_eq!(Target::parse("   ").unwrap_err().code(), ExitCode::Usage);
    }

    #[test]
    fn parent_components_cannot_escape_the_vault() {
        // The attack this blocks: `vault:../../etc` resolving above the root.
        assert_eq!(
            Target::parse("vault:../../etc").unwrap_err().code(),
            ExitCode::Usage
        );
    }

    #[test]
    fn scope_comparison_uses_whole_components() {
        let target = Target::parse("vault:photos").unwrap();
        assert!(target.covers("photos/2024/a.jpg"));
        assert!(target.covers("photos"));
        // The bug this guards: restoring `photos-backup` into a directory the
        // user asked to fill from `photos`.
        assert!(!target.covers("photos-backup/a.jpg"));
    }

    #[test]
    fn the_named_tree_is_not_repeated_under_the_destination() {
        let target = Target::parse("vault:photos").unwrap();
        assert_eq!(target.relative("photos/2024/a.jpg"), "2024/a.jpg");
        assert_eq!(target.relative("photos"), "");

        // At the root there is no prefix to strip.
        let root = Target::parse("vault:").unwrap();
        assert_eq!(root.relative("photos/2024/a.jpg"), "photos/2024/a.jpg");
    }
}
