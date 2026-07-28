//! Turning a `REMOTE:PATH` argument into something a removal may act on.
//!
//! Every command in the removal family starts here, and none of them may skip
//! it: a typo that silently resolves to the wrong scope is the difference
//! between deleting `photos/2024` and deleting `photos`. The parse is therefore
//! deliberately strict — it refuses anything ambiguous rather than guessing —
//! and it is the only place in the family that interprets user path syntax.
//!
//! The disambiguation rules are [`crate::remote::spec`]'s, consulted rather than
//! re-derived: a single ASCII letter before the colon is a Windows drive letter
//! *on a platform that has drives*, a `\\`-prefixed string is a UNC share, and
//! both are *local* paths that no removal command accepts. Off Windows there is
//! no drive to be confused with, so `r:` there names the remote `r` — which is
//! rclone's rule and, since this module used to apply the drive test everywhere,
//! the one place a `purge` could refuse a remote the transfer verbs would use.

use std::fmt;

use serde::Serialize;

use crate::constants::REMOTE_SEPARATOR;
use crate::error::{CliError, Result};
use crate::platform::path;
use crate::remote::spec::{looks_local, names_a_remote, not_a_remote_name};

/// A resolved removal target: a named remote plus a canonical logical path.
///
/// The path is already cleaned and NFC-normalised, so two spellings of the same
/// name (`photos//2024/` and `photos/2024`, or a macOS decomposed `café`)
/// resolve to one target. Anything that survives construction is safe to hand
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
            return Err(CliError::usage("no target given")
                .with_hint("Name what to remove, for example 'vault:photos/2024'."));
        }

        // Local paths are rejected before the colon split, because `C:\data`
        // *does* contain a colon and would otherwise parse as a remote.
        if looks_local(spec) {
            return Err(
                CliError::usage(format!("'{spec}' is a local path, not a remote")).with_hint(
                    "The removal commands operate on a remote, written REMOTE:PATH. \
                 Use your operating system's own tools to remove local files.",
                ),
            );
        }

        let Some((remote, rest)) = spec.split_once(REMOTE_SEPARATOR) else {
            return Err(
                CliError::usage(format!("'{spec}' is not a remote specification"))
                    .with_hint("Write the target as REMOTE:PATH, for example 'vault:photos/2024'."),
            );
        };

        if !names_a_remote(remote) {
            let (reason, hint) = not_a_remote_name(remote);
            return Err(CliError::usage(reason).with_hint(hint));
        }

        let Some(path) = path::clean_logical(rest) else {
            return Err(
                CliError::usage(format!("'{rest}' escapes the remote with '..'")).with_hint(
                    "Removal targets are relative to the vault root and may not \
                     contain '..' components.",
                ),
            );
        };

        Ok(Self {
            remote: remote.to_string(),
            path,
        })
    }

    /// Whether this target is the whole remote rather than a path inside it.
    ///
    /// The removal family branches on this constantly: `rmdir vault:` has no
    /// directory to remove, and `purge vault:` is the entire dataset.
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.path.is_empty()
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
    use super::*;
    use crate::exit::ExitCode;

    fn parse(spec: &str) -> Result<Target> {
        Target::parse(spec)
    }

    #[test]
    fn a_remote_and_a_path_are_split_at_the_first_colon() {
        let target = parse("vault:photos/2024").unwrap();
        assert_eq!(target.remote, "vault");
        assert_eq!(target.path, "photos/2024");
        assert!(!target.is_root());
    }

    #[test]
    fn a_bare_remote_is_the_root() {
        let target = parse("vault:").unwrap();
        assert!(target.is_root());
        assert_eq!(target.path, "");
        assert_eq!(target.to_string(), "vault:");
    }

    #[test]
    fn paths_are_canonicalised_before_anything_is_removed() {
        // Noise in the spelling must not produce a second, different target:
        // `photos//2024/` and `photos/2024` are the same directory.
        assert_eq!(parse("vault:./photos//2024/").unwrap().path, "photos/2024");
        // Windows users type backslashes; the logical path is always '/'.
        assert_eq!(parse(r"vault:photos\2024").unwrap().path, "photos/2024");
    }

    #[test]
    fn unicode_spellings_converge_on_one_target() {
        // macOS hands back NFD. Without normalisation this would address a
        // different object from the same name typed on Linux — and a removal
        // would silently miss.
        let nfd = parse("vault:cafe\u{301}/a.jpg").unwrap();
        let nfc = parse("vault:caf\u{e9}/a.jpg").unwrap();
        assert_eq!(nfd, nfc);
    }

    #[test]
    fn local_paths_are_refused_rather_than_guessed_at() {
        for spec in [r"\\server\share\x", "/tmp/x"] {
            let error = parse(spec).unwrap_err();
            assert_eq!(error.code(), ExitCode::Usage, "accepted '{spec}'");
            assert!(error.hint().is_some(), "'{spec}' failed without advice");
        }
    }

    #[test]
    fn one_letter_specs_follow_the_same_platform_rule_the_transfer_verbs_use() {
        // A removal that refused `r:photos` on a machine where `dctl copy` had
        // just written to it is the worst version of this drift: the operator
        // cannot delete what they were able to store.
        let removal = parse("r:photos");
        match crate::remote::RemoteSpec::parse("r:photos").expect("classified") {
            crate::remote::RemoteSpec::Named { remote, path } => {
                let target = removal.expect("removal must agree that this is a remote");
                assert_eq!(target.remote, remote);
                assert_eq!(target.path, path);
            }
            crate::remote::RemoteSpec::Local(_) => {
                assert_eq!(removal.unwrap_err().code(), ExitCode::Usage);
            }
        }
        assert!(parse("xy:z").is_ok());
    }

    #[test]
    fn escaping_the_root_is_refused() {
        let error = parse("vault:photos/../../etc").unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[test]
    fn an_empty_target_is_a_usage_error_not_the_whole_vault() {
        // The dangerous default: an empty argument must never widen to "all".
        assert_eq!(parse("").unwrap_err().code(), ExitCode::Usage);
        assert_eq!(parse("   ").unwrap_err().code(), ExitCode::Usage);
    }

    #[test]
    fn a_remote_name_never_contains_a_separator() {
        assert_eq!(parse("a/b:c").unwrap_err().code(), ExitCode::Usage);
    }

    #[test]
    fn the_display_form_round_trips_through_the_parser() {
        let target = parse("vault:photos/2024").unwrap();
        assert_eq!(target.to_string(), "vault:photos/2024");
        assert_eq!(parse(&target.to_string()).unwrap(), target);
    }

    #[test]
    fn the_json_shape_is_remote_plus_path() {
        let target = parse("vault:photos").unwrap();
        let value = serde_json::to_value(&target).unwrap();
        assert_eq!(value["remote"], "vault");
        assert_eq!(value["path"], "photos");
    }
}
