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
//! * a UNC path (`\\server\share`) is **local** on every platform — nothing else
//!   begins `\\` — and a Windows drive (`C:`, `d:/data`) is local on a platform
//!   that has drives, which is where rclone draws the same line;
//! * otherwise, a colon before the first path separator introduces a remote, of
//!   any length from one character up, exactly as rclone's remote-name grammar
//!   does;
//! * everything else is a local path.
//!
//! All three are [`crate::remote::spec`]'s, called rather than re-implemented.
//! The copy that used to live here applied the drive test on every platform, so
//! `dctl check r:photos ./photos` refused on Linux a remote `dctl copy` accepted.
//!
//! The path half of a remote spec is canonicalised to a logical vault path
//! (`/`-separated, NFC, no `.` or `..`) by [`crate::platform::path`], so two
//! spellings of the same filename can never address two different objects.

// Three accessors below have no caller yet. `check`, `scrub` and
// `dctl index rebuild` all reach a real engine now and use `path`, `prefix`,
// `spec`, `is_tree` and `require_remote`; `remote`, `is_remote` and `local_path`
// are for `verify` and `hashsum`, which are still unwired. They are kept
// — with the tests that pin the drive-letter and `..` rules through them —
// because the grammar is the part of this file most worth testing exhaustively,
// and `C:\data` being read as a remote is the mistake that writes to the wrong
// side of a transfer.
#![allow(dead_code)]

use std::fmt;
use std::path::PathBuf;

use crate::constants::{PATH_SEPARATOR, REMOTE_SEPARATOR};
use crate::error::{CliError, Result};
use crate::platform::path as logical;
use crate::remote::RemoteSpec;
use crate::remote::spec::{looks_local, names_a_remote, not_a_remote_name};

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

        // Local shapes that must never be read as a remote here.
        if looks_local(spec) {
            return Ok(Self::local(spec));
        }

        match split_remote(spec) {
            None => Ok(Self::local(spec)),
            Some((name, rest)) => {
                if !names_a_remote(name) {
                    let (reason, hint) = not_a_remote_name(name);
                    return Err(CliError::usage(reason).with_hint(hint));
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

    /// The same target in the vocabulary [`crate::source::open`] speaks.
    ///
    /// The integrity verbs parse their own [`Target`] because they take one or
    /// two mandatory positional arguments and need the tree/object distinction;
    /// the listing verbs parse [`crate::commands::listing::Target`] because
    /// theirs is optional and falls back to `--remote`. Both apply the same
    /// rules — a drive letter is local on every platform, a logical path is NFC
    /// and `..`-free — and this is the one conversion out of this family's
    /// spelling into the source layer's.
    ///
    /// It is a method here rather than a `From` impl written at the call sites
    /// for the reason [`crate::source::open`] takes a parsed spec at all: a
    /// remote's name has no colon, so anything that re-parses one turns
    /// `archive:` into the *directory* `archive`, which lists empty and exits 0.
    #[must_use]
    pub fn spec(&self) -> RemoteSpec {
        match &self.remote {
            Some(remote) => RemoteSpec::Named {
                remote: remote.clone(),
                path: self.path.clone(),
            },
            // The local path is the source's root, so the whole of it goes into
            // the spec and none of it into the prefix. The prefix is not this
            // type's to state: `crate::source::open` produces it, from the
            // resolver, and hands it back joined to the source it scopes — see
            // `crate::source::open::Opened`.
            None => RemoteSpec::Local(PathBuf::from(&self.path)),
        }
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
    fn drive_letters_stay_local_exactly_where_drives_exist() {
        for spec in [r"C:\Users\me", "c:", "d:/data"] {
            let target = Target::parse(spec).unwrap();
            assert_eq!(
                target.is_remote(),
                !crate::constants::DRIVE_LETTERS_EXIST,
                "{spec} classified differently from the transfer verbs"
            );
            // Whatever it is, it is the same thing `dctl copy` would make of it.
            assert_eq!(target.spec(), RemoteSpec::parse(spec).unwrap());
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
    fn a_one_character_name_that_is_not_a_drive_is_a_remote_on_every_platform() {
        // Corrected against rclone: a drive letter is a single *ASCII letter*,
        // so `1:` names no drive anywhere and rclone reads it as the remote `1`.
        // Refusing it here made a legal rclone config unusable.
        let target = Target::parse("1:x").expect("a digit names no drive");
        assert_eq!(target.remote(), Some("1"));
        assert_eq!(target.path(), "x");
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
    fn a_target_converts_to_the_spec_the_source_layer_speaks() {
        // Both halves have to survive. A remote that lost its prefix would
        // scrub the whole vault when one directory was named, and a local path
        // that became a named remote would send the run hunting configuration
        // that does not exist.
        let remote = Target::parse("vault:photos/2024").unwrap();
        assert_eq!(
            remote.spec(),
            RemoteSpec::Named {
                remote: "vault".into(),
                path: "photos/2024".into(),
            }
        );
        let whole = Target::parse("vault:").unwrap();
        assert_eq!(
            whole.spec(),
            RemoteSpec::Named {
                remote: "vault".into(),
                path: String::new(),
            }
        );
    }

    #[test]
    fn a_local_target_carries_its_whole_path_into_the_spec() {
        // The whole path goes into the spec, so the source is pointed straight at
        // the directory. Scoping it a second time by prefix would look for
        // `./photos/./photos` and report an empty tree rather than the files
        // that are there — which is why the prefix a read is scoped by comes
        // from `crate::source::open` and not from here.
        let local = Target::parse("./photos").unwrap();
        assert_eq!(local.spec(), RemoteSpec::Local(PathBuf::from("./photos")));

        // The drive-letter rule survives the conversion, whichever way this
        // platform answers it — the two parsers must never disagree.
        assert_eq!(
            Target::parse(r"C:\data").unwrap().spec(),
            RemoteSpec::parse(r"C:\data").unwrap()
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
