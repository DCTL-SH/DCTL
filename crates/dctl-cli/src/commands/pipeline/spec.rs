//! Turning a `REMOTE:PATH` argument into an object the byte-stream family can
//! read from or write to.
//!
//! `cat` and `rcat` differ from the removal and integrity families in one
//! important way: a **local path is a legitimate argument**. `dctl cat report.pdf`
//! and `producer | dctl rcat out.bin` are exactly the shape the documented path
//! model promises — "a bare path, a Windows drive path such as `C:\data`, and a
//! UNC path are all treated as local" — and refusing them would make the two
//! most pipe-shaped commands in the tool the only ones that cannot appear in a
//! local pipeline.
//!
//! The disambiguation rules are the ones in [`crate::platform::path`], applied
//! the way [`crate::remote::RemoteSpec::classify`] applies them: a `\\`-prefixed
//! string is a UNC share, a single letter before the colon is a drive **on a
//! platform that has drives**, and a remote name is at least
//! [`MIN_REMOTE_NAME_LEN`] characters and contains no path separator. Anything
//! that fails those tests is a local path rather than an error, because for this
//! family "local" is a valid answer.
//!
//! The platform condition is the part that was missing, and it was not cosmetic.
//! This module tested the drive-letter *shape* unconditionally, so on Linux
//! `dctl cat r:notes.md` — a perfectly ordinary remote called `r` — was read as
//! a local file literally named `r:notes.md` and reported "No such file or
//! directory", while `dctl ls r:` listed the remote happily. `rcat` was worse: it
//! created its staging file beside the *local* path, so a stream written to a
//! configured remote failed on a directory the operator never named.
//! `HANDOVER.md` §18.1 recorded this drift as closed across five command
//! families; this one and the recovery family were not among them.
//!
//! The two halves are normalised differently, and that asymmetry is deliberate.
//! A **remote** path is a logical vault path, so it is cleaned and NFC-normalised
//! — the index key is a hash of those bytes, and macOS's decomposed spelling of
//! `café` would otherwise address a different object from the same name typed on
//! Linux. A **local** path is handed to the operating system verbatim: the
//! filesystem, not DCTL, decides what that name means, and normalising it here
//! would fail to open a file that genuinely exists in decomposed form.

use std::fmt;
use std::path::PathBuf;

use crate::constants::{
    DRIVE_LETTERS_EXIST, MIN_REMOTE_NAME_LEN, PATH_SEPARATOR, REMOTE_SEPARATOR,
};
use crate::error::{CliError, Result};
use crate::platform::path;

/// A parsed object specification: either an object in a named remote, or a path
/// on the local filesystem.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectSpec {
    /// Name of the configured remote, or `None` for a local path.
    remote: Option<String>,
    /// The logical vault path for a remote; the path exactly as typed for a
    /// local file. See the module docs for why the two are treated differently.
    path: String,
    /// The argument as the user wrote it, so every message quotes their spelling.
    display: String,
}

impl ObjectSpec {
    /// Parse a `REMOTE:PATH` specification, or a local path.
    ///
    /// # Errors
    /// [`crate::exit::ExitCode::Usage`] when the argument is empty, names a
    /// remote whose name contains a path separator, or tries to escape the vault
    /// root with `..`.
    pub fn parse(spec: &str) -> Result<Self> {
        Self::classify(spec, DRIVE_LETTERS_EXIST)
    }

    /// [`ObjectSpec::parse`] with the platform supplied.
    ///
    /// `drive_letters` is [`DRIVE_LETTERS_EXIST`] in production. It is a
    /// parameter for the same reason [`crate::remote::RemoteSpec::classify`]
    /// takes one: both answers have to be reachable from a test run on either
    /// kind of machine, or the platform-dependent half of the rule is asserted
    /// on exactly one platform and drifts on the other.
    ///
    /// # Errors
    /// As [`ObjectSpec::parse`].
    pub fn classify(spec: &str, drive_letters: bool) -> Result<Self> {
        if spec.trim().is_empty() {
            return Err(CliError::usage("no object given").with_hint(
                "Name the object, for example 'vault:notes/today.md' or a local path.",
            ));
        }

        // Checked before the colon split, because `C:\data` *does* contain a
        // colon and would otherwise parse as a remote named `C`. A UNC share is
        // local on every platform; a drive letter is local only where drives
        // exist, which off Windows is nowhere — so `r:notes.md` is the remote
        // `r` there, exactly as `dctl ls r:` already reads it.
        if path::looks_like_unc(spec) || (drive_letters && path::looks_like_windows_drive(spec)) {
            return Ok(Self::local(spec));
        }

        let Some((remote, rest)) = spec.split_once(REMOTE_SEPARATOR) else {
            return Ok(Self::local(spec));
        };

        // A name shorter than a remote name can be, or one carrying a separator
        // — a directory whose own name contains a colon. Both are local paths;
        // the colon told us nothing.
        if remote.chars().count() < MIN_REMOTE_NAME_LEN {
            return Ok(Self::local(spec));
        }
        if remote.contains(PATH_SEPARATOR) || remote.contains('\\') {
            return Ok(Self::local(spec));
        }

        let Some(path) = path::clean_logical(rest) else {
            return Err(
                CliError::usage(format!("'{rest}' escapes the remote with '..'")).with_hint(
                    "Object paths are relative to the vault root and may not contain \
                     '..' components.",
                ),
            );
        };

        Ok(Self {
            remote: Some(remote.to_string()),
            path,
            display: spec.to_string(),
        })
    }

    /// Build a local specification from a path as typed.
    fn local(spec: &str) -> Self {
        Self {
            remote: None,
            path: spec.to_string(),
            display: spec.to_string(),
        }
    }

    /// The remote's name, or `None` when this is a local path.
    #[must_use]
    pub fn remote(&self) -> Option<&str> {
        self.remote.as_deref()
    }

    /// Whether the object lives on the local filesystem.
    ///
    /// `cfg(test)` for the reason [`crate::remote::RemoteSpec::is_local`] spells
    /// out at length: a command that asks this and then reaches for the side it
    /// assumed is the shape of bug the two-sided type exists to prevent. The
    /// commands ask [`ObjectSpec::remote`] instead and let the `Option` decide
    /// the branch, so the local path and the remote name can never be taken from
    /// a specification that does not have one. The parser's own tests still have
    /// to be able to observe which side a specification landed on, which is what
    /// this is for.
    #[cfg(test)]
    #[must_use]
    pub const fn is_local(&self) -> bool {
        self.remote.is_none()
    }

    /// The logical vault path, or the local path as typed.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The argument exactly as the user wrote it.
    ///
    /// Used in every message, prompt and JSON record, so an operator can match a
    /// line of output back to the argument that produced it without mentally
    /// re-applying the normalisation rules.
    #[must_use]
    pub fn display(&self) -> &str {
        &self.display
    }

    /// The native filesystem path this specification names.
    ///
    /// Meaningful only when [`ObjectSpec::is_local`]; a remote object has no path
    /// on this machine, and callers check first.
    #[must_use]
    pub fn local_path(&self) -> PathBuf {
        PathBuf::from(&self.path)
    }

    /// Whether the specification named a remote but no object inside it.
    ///
    /// `vault:` addresses the whole vault, which is a listing target, not
    /// something that can be written to stdout or created from stdin.
    #[must_use]
    pub fn is_bare_remote(&self) -> bool {
        self.remote.is_some() && self.path.is_empty()
    }
}

impl fmt::Display for ObjectSpec {
    /// Renders the argument as typed, so a prompt, a log record and an error all
    /// quote the same string.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.display)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exit::ExitCode;

    #[test]
    fn a_remote_and_a_path_are_split_at_the_first_colon() {
        let spec = ObjectSpec::parse("vault:photos/2024/a.jpg").unwrap();
        assert_eq!(spec.remote(), Some("vault"));
        assert_eq!(spec.path(), "photos/2024/a.jpg");
        assert!(!spec.is_local());
        assert!(!spec.is_bare_remote());
    }

    #[test]
    fn remote_paths_are_canonicalised_but_local_paths_are_not() {
        // A vault path is hashed into an index key, so one spelling must win.
        assert_eq!(ObjectSpec::parse("vault:./a//b/").unwrap().path(), "a/b");
        // A local path is the operating system's to interpret; rewriting it
        // would fail to open a file that really is named that way.
        assert_eq!(ObjectSpec::parse("./a//b/").unwrap().path(), "./a//b/");
    }

    #[test]
    fn unicode_spellings_converge_for_a_remote_object() {
        // macOS hands back NFD. Without normalisation the same name typed on
        // Linux would address a different object.
        let nfd = ObjectSpec::parse("vault:cafe\u{301}/a.jpg").unwrap();
        let nfc = ObjectSpec::parse("vault:caf\u{e9}/a.jpg").unwrap();
        assert_eq!(nfd.path(), nfc.path());
    }

    #[test]
    fn local_paths_are_accepted_rather_than_refused() {
        // The documented path model: bare, drive-letter and UNC paths are local.
        // The drive-letter rows are asserted on a platform that has drives,
        // because that is the only place they are local — off Windows `c:/data`
        // names the remote `c`, exactly as `dctl ls c:` reads it.
        for spec in [
            "report.pdf",
            "/tmp/x",
            r"C:\Users\me",
            "c:/data",
            r"\\srv\s\f",
        ] {
            let parsed = ObjectSpec::classify(spec, true).unwrap();
            assert!(parsed.is_local(), "'{spec}' was not treated as local");
            assert_eq!(parsed.path(), spec);
            assert_eq!(parsed.remote(), None);
        }

        // The rows that are local on every platform stay local where drives do
        // not exist, so the change above did not quietly make an ordinary file
        // path into a remote.
        for spec in ["report.pdf", "/tmp/x", r"\\srv\s\f"] {
            assert!(
                ObjectSpec::classify(spec, false).unwrap().is_local(),
                "'{spec}' stopped being a local path off Windows"
            );
        }
    }

    #[test]
    fn a_one_character_prefix_is_a_drive_letter_only_where_drives_exist() {
        // This test used to be called `a_one_character_prefix_is_always_a_drive_
        // letter` and asserted exactly that, which is why the drift survived an
        // audit that claimed to have closed it: the defective rule had a passing
        // test standing over it. rclone settles the same ambiguity at
        // classification time (`fs/fspath/path.go:163` consults
        // `driveletter.IsDriveLetter`, a compiled-in `false` off Windows), and
        // `remote::spec` has agreed with that since §18.1. This family did not.
        assert!(ObjectSpec::classify("x:y", true).unwrap().is_local());
        assert_eq!(
            ObjectSpec::classify("x:y", false).unwrap().remote(),
            Some("x")
        );
        for drives in [false, true] {
            assert_eq!(
                ObjectSpec::classify("xy:z", drives).unwrap().remote(),
                Some("xy")
            );
        }
    }

    #[test]
    fn a_colon_inside_a_directory_name_stays_local() {
        // `./odd:name/f` splits at the colon too; the left half contains a
        // separator, which no remote name may, so the argument is a path.
        assert!(ObjectSpec::parse("./odd:name/f").unwrap().is_local());
        assert!(ObjectSpec::parse(r"dir\odd:name").unwrap().is_local());
    }

    #[test]
    fn escaping_the_vault_root_is_refused() {
        let error = ObjectSpec::parse("vault:a/../../etc/passwd").unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.hint().is_some(), "a refusal must say what to do next");
    }

    #[test]
    fn an_empty_argument_is_a_usage_error() {
        assert_eq!(ObjectSpec::parse("").unwrap_err().code(), ExitCode::Usage);
        assert_eq!(
            ObjectSpec::parse("   ").unwrap_err().code(),
            ExitCode::Usage
        );
    }

    #[test]
    fn a_bare_remote_names_no_object() {
        let spec = ObjectSpec::parse("vault:").unwrap();
        assert!(spec.is_bare_remote());
        assert_eq!(spec.path(), "");
    }

    #[test]
    fn the_display_form_is_the_argument_as_typed() {
        // Normalisation must never change what a message quotes back, or an
        // operator cannot match output to input.
        let spec = ObjectSpec::parse("vault:./photos//a.jpg").unwrap();
        assert_eq!(spec.to_string(), "vault:./photos//a.jpg");
        assert_eq!(spec.display(), "vault:./photos//a.jpg");
        assert_eq!(spec.path(), "photos/a.jpg");
    }

    #[test]
    fn a_local_specification_yields_a_native_path() {
        let spec = ObjectSpec::parse("dir/file.bin").unwrap();
        assert_eq!(spec.local_path(), PathBuf::from("dir/file.bin"));
    }

    #[test]
    fn a_one_character_remote_is_an_object_everywhere_a_drive_letter_cannot_exist() {
        // The byte-stream half of the same drift, and the worse half, because
        // this family's wrong answer is silent rather than a refusal. Measured
        // on the release binary before the fix, against a configured remote `r`:
        //
        //     $ dctl cat r:t/a.txt
        //     error: r:t/a.txt: No such file or directory (os error 2)
        //     $ echo hi | dctl rcat r:t/b.txt
        //     error: r:t/.dctl-staging.1762882.0: No such file or directory
        //
        // `cat` looked for a local file literally named `r:t/a.txt`, and `rcat`
        // tried to stage beside it — so a stream written to a remote failed on a
        // directory nobody named, while `dctl ls r:` listed that remote happily.
        //
        // Both platforms are asserted from either kind of machine, for the same
        // reason `Target::classify` takes the parameter.
        let remote = ObjectSpec::classify("r:notes/today.md", false).unwrap();
        assert_eq!(remote.remote(), Some("r"));
        assert_eq!(remote.path(), "notes/today.md");
        assert!(!remote.is_local());

        let bare = ObjectSpec::classify("r:", false).unwrap();
        assert_eq!(bare.remote(), Some("r"));
        assert!(bare.is_bare_remote());

        // On a platform with drives it is a drive, and a local path is a valid
        // answer for this family rather than an error.
        let drive = ObjectSpec::classify("r:notes/today.md", true).unwrap();
        assert!(drive.is_local());
        assert_eq!(drive.path(), "r:notes/today.md");

        // A UNC share is local wherever it is written.
        for drives in [false, true] {
            assert!(
                ObjectSpec::classify(r"\\server\share\f.bin", drives)
                    .unwrap()
                    .is_local()
            );
        }

        // Two characters never depended on the platform.
        for drives in [false, true] {
            assert_eq!(
                ObjectSpec::classify("rr:notes.md", drives)
                    .unwrap()
                    .remote(),
                Some("rr")
            );
        }
    }
}
