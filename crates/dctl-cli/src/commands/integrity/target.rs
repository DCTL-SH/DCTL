//! Parsing a `REMOTE:PATH` argument.
//!
//! Every integrity command takes at least one of these, and getting the split
//! wrong is not a cosmetic bug: `C:\data` parsed as a remote called `C` would
//! send a Windows user's local tree to a provider that does not exist, and a
//! path containing `..` would let a listing escape the prefix it was scoped to.
//! Both rules therefore live here, once, rather than in four command bodies.
//!
//! The disambiguation follows rclone's, because that is what a user porting a
//! script already has in their fingers:
//!
//! * anything that looks like a Windows drive (`C:`, `d:/data`) or a UNC path
//!   (`\\server\share`) is **local**, on every platform — a script written on
//!   Windows has to behave the same on a Linux build agent;
//! * otherwise, a colon before the first path separator introduces a remote,
//!   whose name must be at least [`MIN_REMOTE_NAME_LEN`] characters — which is
//!   precisely what makes the drive-letter rule unambiguous;
//! * everything else is a local path.
//!
//! The path half of a remote spec is canonicalised to a logical vault path
//! (`/`-separated, NFC, no `.` or `..`) by [`crate::platform::path`], so two
//! spellings of the same filename can never address two different objects.

// Some of what follows is not reachable from this build's `run` body: the engine
// has no entry point yet for the step that would call it (see the command's
// module documentation). It is written and unit-tested now, with the tests that
// pin its contract, rather than left until the engine lands — a machine-readable
// output format that first appears on the day it is needed is a format nobody
// reviewed.
#![allow(dead_code)]

use std::fmt;
use std::path::PathBuf;

use crate::constants::{MIN_REMOTE_NAME_LEN, PATH_SEPARATOR, REMOTE_SEPARATOR};
use crate::error::{CliError, Result};
use crate::platform::path as logical;

/// Windows' path separator, accepted in a spec typed by a Windows user.
const WINDOWS_SEPARATOR: char = '\\';

/// A parsed command-line location.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    /// `Some` for `REMOTE:PATH`; `None` when the spec names a local path.
    remote: Option<String>,
    /// The canonical logical path for a remote, or the path exactly as typed
    /// for a local spec — the local filesystem owns its own spelling, and
    /// rewriting it would break a symlinked or case-sensitive layout.
    path: String,
    /// Whether the spec named a *tree* rather than one object: `vault:`,
    /// `vault:photos/`. Trailing separators are stripped by canonicalisation, so
    /// the distinction has to be captured while it is still visible.
    tree: bool,
}

impl Target {
    /// Parse a `REMOTE:PATH` argument.
    ///
    /// # Errors
    /// [`CliError::usage`] when the spec is empty, when a remote name is too
    /// short to be distinguishable from a drive letter, or when the path tries
    /// to escape its root with `..`.
    pub fn parse(spec: &str) -> Result<Self> {
        if spec.is_empty() {
            return Err(CliError::usage("a path is required")
                .with_hint("Write a remote path as 'REMOTE:PATH', for example 'vault:photos'."));
        }

        // Local shapes that must never be read as a remote, on any platform.
        if logical::looks_like_windows_drive(spec) || logical::looks_like_unc(spec) {
            return Ok(Self::local(spec));
        }

        match split_remote(spec) {
            None => Ok(Self::local(spec)),
            Some((name, rest)) => {
                if name.chars().count() < MIN_REMOTE_NAME_LEN {
                    return Err(CliError::usage(format!(
                        "'{name}' is too short to be a remote name"
                    ))
                    .with_hint(
                        "Remote names are at least two characters, so that a single \
                         letter before a colon is always a Windows drive.",
                    ));
                }
                let tree = rest.is_empty() || ends_with_separator(rest);
                let path = logical::clean_logical(rest).ok_or_else(|| {
                    CliError::usage(format!("'{spec}' escapes its root with '..'")).with_hint(
                        "Vault paths are relative to the root of the remote and cannot \
                         contain '..'.",
                    )
                })?;
                Ok(Self {
                    remote: Some(name.to_string()),
                    path,
                    tree,
                })
            }
        }
    }

    /// A local target, kept verbatim.
    fn local(spec: &str) -> Self {
        Self {
            remote: None,
            path: spec.to_string(),
            tree: ends_with_separator(spec),
        }
    }

    /// The remote's name, or `None` when the target is a local path.
    #[must_use]
    pub fn remote(&self) -> Option<&str> {
        self.remote.as_deref()
    }

    /// The logical vault path, or the local path as typed.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Whether this target names a remote rather than a local path.
    #[must_use]
    pub const fn is_remote(&self) -> bool {
        self.remote.is_some()
    }

    /// Whether the spec named a tree (`vault:`, `vault:photos/`) rather than a
    /// single object.
    ///
    /// Commands use it to choose between "verify this one object" and "verify
    /// everything under this prefix" without guessing from the path's shape.
    #[must_use]
    pub const fn is_tree(&self) -> bool {
        self.tree
    }

    /// The local filesystem path, or `None` for a remote target.
    #[must_use]
    pub fn local_path(&self) -> Option<PathBuf> {
        self.remote.is_none().then(|| PathBuf::from(&self.path))
    }

    /// The remote name, or a usage error naming the command that requires one.
    ///
    /// The integrity commands work against recorded hashes held in the vault
    /// index, so a local path has nothing for them to compare against — better
    /// to say so up front than to run and report a vacuous "0 objects verified".
    ///
    /// # Errors
    /// [`CliError::usage`] when the target is a local path.
    pub fn require_remote(&self, command: &str) -> Result<&str> {
        self.remote.as_deref().ok_or_else(|| {
            CliError::usage(format!(
                "{command} needs a remote path, but '{self}' is local"
            ))
            .with_hint("Write the target as 'REMOTE:PATH', for example 'vault:photos'.")
        })
    }
}

impl fmt::Display for Target {
    /// Renders the canonical spelling, not the one that was typed: messages
    /// should show the path the command actually operated on, so a stripped
    /// `./` or a normalised Unicode spelling is visible rather than hidden.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.remote {
            Some(remote) => write!(f, "{remote}{REMOTE_SEPARATOR}{}", self.path),
            None => write!(f, "{}", self.path),
        }
    }
}

/// Split `spec` at the remote separator, if the colon really introduces one.
///
/// A colon that appears *after* a path separator belongs to the path
/// (`./notes/a:b`), so only the leading segment is considered.
fn split_remote(spec: &str) -> Option<(&str, &str)> {
    let colon = spec.find(REMOTE_SEPARATOR)?;
    let head = &spec[..colon];
    if head.contains(PATH_SEPARATOR) || head.contains(WINDOWS_SEPARATOR) {
        return None;
    }
    Some((head, &spec[colon + REMOTE_SEPARATOR.len_utf8()..]))
}

/// Whether a spec ends in a path separator, in either spelling.
fn ends_with_separator(spec: &str) -> bool {
    spec.ends_with(PATH_SEPARATOR) || spec.ends_with(WINDOWS_SEPARATOR)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exit::ExitCode;

    #[test]
    fn a_remote_spec_splits_into_name_and_logical_path() {
        let target = Target::parse("vault:photos/2024/a.jpg").unwrap();
        assert!(target.is_remote());
        assert_eq!(target.remote(), Some("vault"));
        assert_eq!(target.path(), "photos/2024/a.jpg");
        assert!(!target.is_tree());
        assert_eq!(target.to_string(), "vault:photos/2024/a.jpg");
    }

    #[test]
    fn a_bare_remote_names_the_whole_vault() {
        let target = Target::parse("vault:").unwrap();
        assert_eq!(target.remote(), Some("vault"));
        assert_eq!(target.path(), "");
        assert!(target.is_tree(), "'vault:' is the whole dataset");
    }

    #[test]
    fn a_trailing_separator_marks_a_tree() {
        // Canonicalisation strips the slash, so the flag has to be captured
        // before it disappears or `vault:photos/` and `vault:photos` would be
        // indistinguishable.
        let tree = Target::parse("vault:photos/").unwrap();
        assert!(tree.is_tree());
        assert_eq!(tree.path(), "photos");
        assert!(!Target::parse("vault:photos").unwrap().is_tree());
    }

    #[test]
    fn windows_drive_letters_stay_local() {
        for spec in [r"C:\Users\me", "c:", "d:/data"] {
            let target = Target::parse(spec).unwrap();
            assert!(!target.is_remote(), "{spec} was read as a remote");
            assert_eq!(target.local_path(), Some(PathBuf::from(spec)));
        }
    }

    #[test]
    fn unc_paths_stay_local() {
        let target = Target::parse(r"\\server\share\file").unwrap();
        assert!(!target.is_remote());
    }

    #[test]
    fn a_colon_inside_a_path_is_not_a_remote() {
        // `./notes/09:00.txt` is a perfectly ordinary local file on macOS and
        // Linux; only a colon in the leading segment introduces a remote.
        let target = Target::parse("./notes/09:00.txt").unwrap();
        assert!(!target.is_remote());
        assert_eq!(target.path(), "./notes/09:00.txt");
    }

    #[test]
    fn a_bare_path_is_local_and_kept_verbatim() {
        let target = Target::parse("./photos/../photos").unwrap();
        assert!(!target.is_remote());
        // Local paths are the filesystem's business; DCTL does not rewrite them.
        assert_eq!(target.path(), "./photos/../photos");
    }

    #[test]
    fn parent_components_are_rejected_inside_a_vault() {
        let error = Target::parse("vault:a/../../etc/passwd").unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.hint().is_some());
    }

    #[test]
    fn a_one_character_remote_name_that_is_not_a_drive_is_rejected() {
        // `1:x` cannot be a drive (drives are alphabetic) and cannot be a remote
        // (too short) — accepting it would make the rule unpredictable.
        let error = Target::parse("1:x").unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[test]
    fn an_empty_spec_is_a_usage_error() {
        let error = Target::parse("").unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(
            error.hint().is_some(),
            "a usage error must say what to type"
        );
    }

    #[test]
    fn logical_paths_are_canonicalised_once_here() {
        // Redundant separators, `.` components and Unicode spelling all converge,
        // so two ways of typing one path address one object.
        assert_eq!(
            Target::parse("vault:./a//b/./c").unwrap().path(),
            Target::parse("vault:a/b/c").unwrap().path()
        );
        assert_eq!(
            Target::parse("vault:cafe\u{301}/x").unwrap().path(),
            Target::parse("vault:caf\u{e9}/x").unwrap().path()
        );
    }

    #[test]
    fn backslashes_in_a_remote_path_are_accepted_as_separators() {
        // A Windows user typing a vault path natively must not create an object
        // whose name literally contains a backslash.
        assert_eq!(
            Target::parse(r"vault:photos\2024").unwrap().path(),
            "photos/2024"
        );
    }

    #[test]
    fn requiring_a_remote_names_the_command_that_needs_one() {
        let local = Target::parse("./photos").unwrap();
        let error = local.require_remote("dctl verify").unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.message().contains("dctl verify"));

        let remote = Target::parse("vault:photos").unwrap();
        assert_eq!(remote.require_remote("dctl verify").unwrap(), "vault");
    }
}
