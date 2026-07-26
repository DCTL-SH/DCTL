//! Turning the `REMOTE:` argument into what a mount would serve.
//!
//! `mount` reads a remote the same way every other command does — the rules live
//! in [`crate::platform::path`] — with one difference that is the whole point of
//! the command: an **empty path is the normal case**. `dctl mount vault: /mnt`
//! serves the whole vault, and a path narrows it to a subtree, exactly as
//! `rclone mount remote:path` does.
//!
//! A local path is refused rather than guessed at. Mounting a local directory
//! onto another local directory is `mount --bind`, not a job for an encrypted
//! object-store client, and silently accepting it would be a very confusing way
//! to find that out.

use std::fmt;

use crate::constants::{MIN_REMOTE_NAME_LEN, PATH_SEPARATOR, REMOTE_SEPARATOR};
use crate::error::{CliError, Result};
use crate::platform::path;

/// The remote, and optionally the subtree, a mount would serve.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Source {
    /// Name of the configured remote, without the separator.
    pub remote: String,
    /// Canonical logical path inside it. Empty means the whole remote.
    pub path: String,
}

impl Source {
    /// Parse a `REMOTE:` or `REMOTE:PATH` specification.
    ///
    /// # Errors
    /// [`crate::exit::ExitCode::Usage`] when the spec names a local path, omits
    /// the remote, uses a remote name short enough to be a drive letter, or
    /// tries to escape its root with `..`.
    pub fn parse(spec: &str) -> Result<Self> {
        let spec = spec.trim();
        if spec.is_empty() {
            return Err(CliError::usage("no remote given").with_hint(
                "Name what to mount as REMOTE:, for example 'dctl mount vault: /mnt/vault'.",
            ));
        }

        // Local paths are rejected before the colon split, because `C:\data`
        // *does* contain a colon and would otherwise parse as a remote.
        if path::looks_like_unc(spec) || path::looks_like_windows_drive(spec) {
            return Err(local_source_error(spec));
        }

        let Some((remote, rest)) = spec.split_once(REMOTE_SEPARATOR) else {
            return Err(local_source_error(spec));
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
                    "A mount source is relative to the vault root and may not contain \
                     '..' components.",
                ),
            );
        };

        Ok(Self {
            remote: remote.to_string(),
            path,
        })
    }
}

impl fmt::Display for Source {
    /// Renders back to the spelling the user typed, so a log record and an error
    /// quote the same string.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}{}", self.remote, REMOTE_SEPARATOR, self.path)
    }
}

/// The refusal shared by every "that is a local path" branch.
fn local_source_error(spec: &str) -> CliError {
    CliError::usage(format!("'{spec}' is a local path, not a remote")).with_hint(
        "mount serves a remote, written REMOTE:. Attaching one local directory to \
         another is a job for your operating system's own bind mount.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exit::ExitCode;

    #[test]
    fn a_bare_remote_mounts_the_whole_vault() {
        // The normal case, and the one the command's help text shows.
        let source = Source::parse("vault:").unwrap();
        assert_eq!(source.remote, "vault");
        assert!(source.path.is_empty(), "a bare remote mounts the root");
        assert_eq!(source.to_string(), "vault:");
    }

    #[test]
    fn a_path_narrows_the_mount_to_a_subtree() {
        let source = Source::parse("vault:photos/2024").unwrap();
        assert_eq!(source.path, "photos/2024");
    }

    #[test]
    fn paths_are_canonicalised_like_every_other_command() {
        assert_eq!(Source::parse("vault:./photos//").unwrap().path, "photos");
        assert_eq!(
            Source::parse(r"vault:photos\2024").unwrap().path,
            "photos/2024"
        );
    }

    #[test]
    fn local_paths_are_refused_rather_than_guessed_at() {
        for spec in [r"C:\Users\me", r"\\server\share", "/mnt/vault", "vault"] {
            let error = Source::parse(spec).unwrap_err();
            assert_eq!(error.code(), ExitCode::Usage, "accepted '{spec}'");
            assert!(error.hint().is_some(), "'{spec}' failed without advice");
        }
    }

    #[test]
    fn a_one_character_remote_is_always_a_drive_letter() {
        assert_eq!(Source::parse("x:").unwrap_err().code(), ExitCode::Usage);
        assert!(Source::parse("xy:").is_ok());
    }

    #[test]
    fn escaping_the_root_is_refused() {
        assert_eq!(
            Source::parse("vault:../etc").unwrap_err().code(),
            ExitCode::Usage
        );
    }

    #[test]
    fn an_empty_source_is_a_usage_error() {
        assert_eq!(Source::parse("").unwrap_err().code(), ExitCode::Usage);
        assert_eq!(Source::parse("  ").unwrap_err().code(), ExitCode::Usage);
    }

    #[test]
    fn the_display_form_round_trips_through_the_parser() {
        for spec in ["vault:", "vault:photos/2024"] {
            let source = Source::parse(spec).unwrap();
            assert_eq!(Source::parse(&source.to_string()).unwrap(), source);
        }
    }
}
