//! Turning a `REMOTE:PATH` argument into something `mkdir` or `touch` may write.
//!
//! Both commands start here and neither may skip it: the path a user types is
//! the path that gets hashed into an object key, so it has to be canonical
//! before anything else looks at it. Two spellings of one directory would create
//! two directories, and on macOS — where the shell hands over decomposed
//! Unicode — that happens without the user typing anything unusual at all.
//!
//! The disambiguation rules are the ones documented in
//! [`crate::platform::path`]: a single character before the colon is a Windows
//! drive letter, a `\\`-prefixed string is a UNC share, and both are *local*
//! paths. Local paths are refused rather than guessed at, because the operating
//! system already has `mkdir(1)` and `touch(1)` and a DCTL that silently created
//! a local directory when the user meant a vault one would be worse than one
//! that says so.
//!
//! The family's own rule, on top of those: a target always names something
//! *inside* a remote. `vault:` is the root, the root always exists, and neither
//! creating it nor stamping a time on it means anything.

use std::fmt;

use serde::Serialize;

use crate::constants::{
    DIRECTORY_MARKER_NAME, MIN_REMOTE_NAME_LEN, PATH_SEPARATOR, REMOTE_SEPARATOR,
};
use crate::error::{CliError, Result};
use crate::platform::path;

/// A resolved directory-family target: a named remote plus a canonical logical
/// path that is guaranteed non-empty.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Target {
    /// Name of the configured remote, without the separator.
    pub remote: String,
    /// Canonical logical path inside that remote. Never empty.
    pub path: String,
}

impl Target {
    /// Parse a `REMOTE:PATH` specification.
    ///
    /// `noun` names what the caller is addressing ("directory", "object") and
    /// appears in the error messages, so `mkdir` and `touch` can share every
    /// rule below while still reading as though each wrote its own diagnostics.
    ///
    /// # Errors
    /// [`crate::exit::ExitCode::Usage`] when the spec names a local path, omits
    /// the remote, uses a remote name short enough to be a drive letter, tries
    /// to escape its root with `..`, or resolves to the remote's root.
    pub fn parse(spec: &str, noun: &str) -> Result<Self> {
        let spec = spec.trim();
        if spec.is_empty() {
            return Err(
                CliError::usage(format!("no {noun} given")).with_hint(format!(
                    "Name the {noun} as REMOTE:PATH, for example 'vault:photos/2024'."
                )),
            );
        }

        // Local paths are rejected before the colon split, because `C:\data`
        // *does* contain a colon and would otherwise parse as a remote.
        if path::looks_like_unc(spec) || path::looks_like_windows_drive(spec) {
            return Err(local_path_error(spec));
        }

        let Some((remote, rest)) = spec.split_once(REMOTE_SEPARATOR) else {
            return Err(local_path_error(spec));
        };

        if remote.chars().count() < MIN_REMOTE_NAME_LEN {
            return Err(
                CliError::usage(format!("'{remote}' is too short to be a remote name")).with_hint(
                    format!(
                        "Remote names are at least {MIN_REMOTE_NAME_LEN} characters, so a \
                         one-letter prefix is always a Windows drive."
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
                    "Targets are relative to the vault root and may not contain \
                     '..' components.",
                ),
            );
        };

        if path.is_empty() {
            return Err(
                CliError::usage(format!("'{spec}' is the root of '{remote}'")).with_hint(format!(
                    "The root of a remote always exists. Name the {noun} inside it, \
                     for example '{remote}{REMOTE_SEPARATOR}photos/2024'."
                )),
            );
        }

        Ok(Self {
            remote: remote.to_string(),
            path,
        })
    }

    /// The object key that represents this path as a directory.
    ///
    /// A backend has no directories, so an empty directory is an empty object at
    /// a well-known name beneath it — see
    /// [`DIRECTORY_MARKER_NAME`](crate::constants::DIRECTORY_MARKER_NAME).
    #[must_use]
    pub fn marker(&self) -> String {
        format!("{}{PATH_SEPARATOR}{DIRECTORY_MARKER_NAME}", self.path)
    }

    /// This target's parent, or `None` when it sits at the remote's root.
    ///
    /// Used by `mkdir --parents` to walk upwards, and by `touch` to name the
    /// directory an object would be created in.
    #[must_use]
    pub fn parent(&self) -> Option<Self> {
        let parent = path::parent(&self.path);
        if parent.is_empty() {
            return None;
        }
        Some(Self {
            remote: self.remote.clone(),
            path: parent.to_string(),
        })
    }
}

impl fmt::Display for Target {
    /// Renders back to the spelling the user typed, so a plan, a log record and
    /// an error all quote the same string.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}{}", self.remote, REMOTE_SEPARATOR, self.path)
    }
}

/// The refusal shared by every "that is a local path" branch.
///
/// One constructor so the advice cannot drift between the two ways a local path
/// arrives — with a drive letter, or with no colon at all.
fn local_path_error(spec: &str) -> CliError {
    CliError::usage(format!("'{spec}' is a local path, not a remote")).with_hint(
        "This command operates on a remote, written REMOTE:PATH. Your operating \
         system's own mkdir and touch already handle local paths.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exit::ExitCode;

    fn parse(spec: &str) -> Result<Target> {
        Target::parse(spec, "directory")
    }

    #[test]
    fn a_remote_and_a_path_are_split_at_the_first_colon() {
        let target = parse("vault:photos/2024").unwrap();
        assert_eq!(target.remote, "vault");
        assert_eq!(target.path, "photos/2024");
        assert_eq!(target.to_string(), "vault:photos/2024");
    }

    #[test]
    fn paths_are_canonicalised_before_anything_is_written() {
        // Noise in the spelling must not produce a second, different directory:
        // `photos//2024/` and `photos/2024` are the same place.
        assert_eq!(parse("vault:./photos//2024/").unwrap().path, "photos/2024");
        // Windows users type backslashes; the logical path is always '/'.
        assert_eq!(parse(r"vault:photos\2024").unwrap().path, "photos/2024");
    }

    #[test]
    fn unicode_spellings_converge_on_one_target() {
        // macOS hands back NFD. Without normalisation, `mkdir` on a Mac and
        // `mkdir` on Linux would create two directories with one visible name.
        let nfd = parse("vault:cafe\u{301}").unwrap();
        let nfc = parse("vault:caf\u{e9}").unwrap();
        assert_eq!(nfd, nfc);
    }

    #[test]
    fn local_paths_are_refused_rather_than_guessed_at() {
        for spec in [
            r"C:\Users\me",
            "c:/data",
            r"\\server\share\x",
            "/tmp/x",
            "x",
        ] {
            let error = parse(spec).unwrap_err();
            assert_eq!(error.code(), ExitCode::Usage, "accepted '{spec}'");
            assert!(error.hint().is_some(), "'{spec}' failed without advice");
        }
    }

    #[test]
    fn a_one_character_remote_is_always_a_drive_letter() {
        // The rule that keeps `C:\data` unambiguous on Linux too.
        assert_eq!(parse("x:y").unwrap_err().code(), ExitCode::Usage);
        assert!(parse("xy:z").is_ok());
    }

    #[test]
    fn the_root_of_a_remote_is_not_a_target() {
        // It always exists, so creating it or stamping a time on it is a typo,
        // not a request — and guessing which directory was meant would be worse.
        for spec in ["vault:", "vault:/", "vault:."] {
            let error = parse(spec).unwrap_err();
            assert_eq!(error.code(), ExitCode::Usage, "accepted '{spec}'");
        }
    }

    #[test]
    fn escaping_the_root_is_refused() {
        assert_eq!(
            parse("vault:photos/../../etc").unwrap_err().code(),
            ExitCode::Usage
        );
    }

    #[test]
    fn an_empty_target_is_a_usage_error() {
        assert_eq!(parse("").unwrap_err().code(), ExitCode::Usage);
        assert_eq!(parse("   ").unwrap_err().code(), ExitCode::Usage);
    }

    #[test]
    fn a_remote_name_never_contains_a_separator() {
        assert_eq!(parse("a/b:c").unwrap_err().code(), ExitCode::Usage);
    }

    #[test]
    fn the_noun_reaches_the_message() {
        // `touch` and `mkdir` share every rule but must not share their wording.
        let error = Target::parse("", "object").unwrap_err();
        assert!(error.message().contains("object"), "{}", error.message());
    }

    #[test]
    fn a_marker_names_an_object_beneath_the_directory() {
        let target = parse("vault:photos/2024").unwrap();
        assert_eq!(target.marker(), "photos/2024/.dctl-dir");
        assert!(target.marker().starts_with(&target.path));
    }

    #[test]
    fn parents_walk_upwards_and_stop_at_the_root() {
        let target = parse("vault:a/b/c").unwrap();
        let parent = target.parent().unwrap();
        assert_eq!(parent.path, "a/b");
        assert_eq!(parent.remote, "vault");
        let grandparent = parent.parent().unwrap();
        assert_eq!(grandparent.path, "a");
        // The root is not a target, so the walk ends rather than yielding it.
        assert_eq!(grandparent.parent(), None);
    }

    #[test]
    fn the_json_shape_is_remote_plus_path() {
        let target = parse("vault:photos").unwrap();
        let value = serde_json::to_value(&target).unwrap();
        assert_eq!(value["remote"], "vault");
        assert_eq!(value["path"], "photos");
    }

    #[test]
    fn the_display_form_round_trips_through_the_parser() {
        let target = parse("vault:photos/2024").unwrap();
        assert_eq!(parse(&target.to_string()).unwrap(), target);
    }
}
