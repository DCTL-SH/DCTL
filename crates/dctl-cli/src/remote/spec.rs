//! Deciding whether an argument names a remote or a local path.
//!
//! Every transfer command takes arguments that may be either — `dctl copy
//! ./photos vault:photos/2024` mixes both on one line — so exactly one rule has
//! to say where `name:path` splits, and it lives here.
//!
//! ## Why this is the sharpest edge in the whole CLI
//!
//! The obvious implementation, `split_once(':')`, quietly destroys Windows
//! users: `C:\Users\me\photos` becomes a remote named `C` holding the path
//! `\Users\me\photos`. The best case is a baffling "unknown remote 'C'"; the
//! worst is a configured remote that really is called `C`, in which case a
//! backup silently reads from — or writes to — somewhere the user never named.
//! The same trap catches any relative path containing a colon, which POSIX
//! filesystems allow and photo tools produce: `photos/holiday:2024`.
//!
//! ## The rules, in order
//!
//! An argument is a **local path** when it:
//!
//! 1. is a UNC or extended-length path — `\\server\share`, `\\?\C:\...`;
//! 2. starts with a drive specifier — `C:`, `c:/x`, `C:\x`, and even the rare
//!    drive-relative `C:relative` — *on a platform that has drive letters*;
//! 3. contains no [`REMOTE_SEPARATOR`] at all;
//! 4. has a candidate name that is really a path component: containing a path
//!    separator, beginning with [`RELATIVE_PATH_MARKER`], or — again only where
//!    drive letters exist — a single character.
//!
//! Otherwise it names a remote, and everything after the *first* colon is a
//! logical path — so `vault:a:b` is the remote `vault` holding `a:b`, because a
//! colon is a legal filename character and only the first one is structural.
//!
//! ## The one platform-dependent rule, and why it is the safe arrangement
//!
//! Rules 2 and 4's single-character clause are the only classifications that
//! consult the platform, through [`DRIVE_LETTERS_EXIST`]. This module used to
//! apply them everywhere and argued the case at length: a script written on a
//! laptop should behave identically on a Linux build agent, and a `cfg`-gated
//! rule makes one string mean two things.
//!
//! That argument was measured against what it actually produced, and it lost.
//! `dctl copy /srv/data r:` on Linux created a **local directory named `r:`**
//! and exited 0 — a backup landing somewhere nobody named, silently, on the
//! platform DCTL is most likely to run on. rclone treats `r` as a remote
//! everywhere except Windows for exactly this reason.
//!
//! What makes the split safe rather than merely rclone-compatible is
//! [`MIN_REMOTE_NAME_LEN`]: a one-character remote cannot be *declared* in any
//! configuration, on any platform. So off Windows a single-character reference
//! parses as a remote, resolves to nothing, and fails by name — it can never
//! quietly address a remote the user did not mean. The two platforms differ in
//! which diagnosis they give, never in whether data goes somewhere unasked.
//!
//! [`classify`] therefore takes the platform as an argument instead of reading
//! the `cfg` itself, so both behaviours are asserted by the test suite whichever
//! machine runs it.
//!
//! ## Two path vocabularies, deliberately not mixed
//!
//! A [`RemoteSpec::Named`] path is a **logical vault path**: canonicalised
//! through [`clean_logical`], which strips redundant separators and applies
//! Unicode NFC, so the NFD spelling macOS hands back and the NFC spelling Linux
//! and Windows use collapse into one spec — and therefore one index key and one
//! stored object, rather than a silent duplicate no user could explain.
//!
//! A [`RemoteSpec::Local`] path is kept **byte-for-byte as typed**. It is
//! handed back to the operating system, which will look up exactly the bytes it
//! was given: normalising it would break opening an NFD-named file that really
//! exists on a Linux volume. Canonicalising the vault's namespace is required;
//! canonicalising someone else's namespace is corruption.

#[cfg(test)]
use std::borrow::Cow;
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use crate::constants::{
    DRIVE_LETTERS_EXIST, MIN_REMOTE_NAME_LEN, PATH_SEPARATOR, PROVIDER_LOCAL, RELATIVE_PATH_MARKER,
    REMOTE_SEPARATOR, WINDOWS_PATH_SEPARATOR,
};
use crate::error::{CliError, Result};
use crate::platform::path::{
    clean_logical, looks_like_unc, looks_like_windows_drive, normalize_unicode, parent_dir_refusal,
};

/// One command-line argument, classified.
///
/// An enum rather than a `(Option<String>, String)` pair so that the local case
/// cannot be handled by accident: a caller has to match, and the compiler makes
/// it say what happens when the user typed a filesystem path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RemoteSpec {
    /// A path on this machine: a bare path, a drive-letter path, a UNC path, or
    /// anything written with the explicit `local:` prefix.
    ///
    /// Stored as typed. See the module docs on why it is not normalised.
    Local(PathBuf),

    /// A configured remote and a logical path inside it — `vault:photos/2024`.
    Named {
        /// The remote's name, as the config file spells it.
        remote: String,
        /// The canonical logical path within that remote; `""` at its root.
        path: String,
    },
}

impl RemoteSpec {
    /// Classify one command-line argument.
    ///
    /// Fails only on input that cannot mean anything: an empty argument, or a
    /// logical path that climbs out of its remote with `..`. Everything else
    /// resolves to a local path rather than an error, because an argument that
    /// is not a remote is, by definition, a filename — and refusing to open a
    /// legally-named file would be the worse failure.
    pub fn parse(input: &str) -> Result<Self> {
        Self::classify(input, DRIVE_LETTERS_EXIST)
    }

    /// [`RemoteSpec::parse`], with the platform stated rather than compiled in.
    ///
    /// `drive_letters` is [`DRIVE_LETTERS_EXIST`] in production. It is a
    /// parameter so that a Linux test run can assert the Windows classification
    /// and vice versa: the whole risk of a platform-dependent rule is that only
    /// one half of it is ever exercised, and a `cfg` in the body would guarantee
    /// exactly that.
    ///
    /// # Errors
    /// As [`RemoteSpec::parse`].
    pub fn classify(input: &str, drive_letters: bool) -> Result<Self> {
        if input.is_empty() {
            return Err(CliError::usage("empty remote spec").with_hint(format!(
                "Give a path, or a configured remote as 'name{REMOTE_SEPARATOR}path'."
            )));
        }

        // Rules 1 and 2: Windows path shapes win before any colon is considered,
        // because both of them contain colons of their own. A UNC path is a
        // Windows path shape on any platform — nothing else begins `\\` — but a
        // drive specifier is only a drive where drives exist.
        if looks_like_unc(input) || (drive_letters && looks_like_windows_drive(input)) {
            return Ok(Self::Local(PathBuf::from(input)));
        }

        // Rule 3, and rule 4 via `is_remote_name`.
        let Some((candidate, rest)) = input.split_once(REMOTE_SEPARATOR) else {
            return Ok(Self::Local(PathBuf::from(input)));
        };
        if !is_remote_name(candidate, drive_letters) {
            return Ok(Self::Local(PathBuf::from(input)));
        }

        // `local:` is the escape hatch: it forces the remainder to be read as a
        // filesystem path, which is the only way to name a directory that would
        // otherwise parse as something else (`local:archive:2024`).
        if candidate == PROVIDER_LOCAL {
            return Ok(Self::Local(PathBuf::from(rest)));
        }

        let path = clean_logical(rest).ok_or_else(|| {
            let (reason, hint) = parent_dir_refusal(input, candidate, rest, REMOTE_SEPARATOR);
            CliError::usage(reason).with_hint(hint)
        })?;

        Ok(Self::Named {
            // Normalised for the same reason the path is: a remote whose name
            // carries an accent must be found by either spelling of it, or a
            // macOS user and a Linux user reading one config file disagree about
            // which remotes exist.
            remote: normalize_unicode(candidate),
            path,
        })
    }

    // The three accessors below are `cfg(test)`. They are not scaffolding: they
    // are how the parser is *observed*. Parsing is the one piece of this crate
    // that silently writes data to the wrong place when it is wrong — the
    // Windows drive-letter rule decides whether `C:\data` is a path or a remote
    // called `c` — so it carries an exhaustive test suite, and that suite has to
    // ask a parsed spec what it became.
    //
    // Production does not ask. A command that has a `RemoteSpec` matches on it,
    // because the two arms need genuinely different things (a native `Path` on
    // one side, a logical `/`-separated string on the other) and a `match` is
    // what makes the compiler insist both are handled. Answering `is_local()`
    // and then unwrapping the side you assumed is precisely the shape of the bug
    // the enum exists to prevent.

    /// Whether this spec addresses this machine's filesystem.
    #[cfg(test)]
    #[must_use]
    pub const fn is_local(&self) -> bool {
        matches!(self, Self::Local(_))
    }

    /// The remote's name, or `None` for a local path.
    ///
    /// Also the value of the `remote` log field (`PLAN.md` §7), which is why it
    /// is the *configured* name and not the provider type: an operator reading
    /// a log needs to know which of their three B2 remotes was involved.
    #[cfg(test)]
    #[must_use]
    pub fn remote_name(&self) -> Option<&str> {
        match self {
            Self::Local(_) => None,
            Self::Named { remote, .. } => Some(remote),
        }
    }

    /// The path portion: logical for a named remote, native for a local one.
    ///
    /// Returns [`Cow`] because a local path may hold bytes that are not valid
    /// UTF-8. Those are replaced for *display* rather than rejected — a lossy
    /// message about a file is far more useful than refusing to name it — so the
    /// result is safe to print but must not be fed back to the filesystem. Use
    /// [`RemoteSpec::local_path`] for that.
    #[cfg(test)]
    #[must_use]
    pub fn path(&self) -> Cow<'_, str> {
        match self {
            Self::Local(path) => path.to_string_lossy(),
            Self::Named { path, .. } => Cow::Borrowed(path),
        }
    }

    /// The native path, for a local spec only.
    ///
    /// The lossless counterpart of [`RemoteSpec::path`]: this is what gets
    /// opened, so it keeps whatever bytes the operating system gave us.
    #[must_use]
    pub fn local_path(&self) -> Option<&Path> {
        match self {
            Self::Local(path) => Some(path),
            Self::Named { .. } => None,
        }
    }
}

/// Whether `candidate` — the text before the first colon — really names a
/// remote, or is just the first component of a path that happens to contain one.
///
/// Each rejection is a real filename that would otherwise be misread:
/// `photos/x:y` (a directory), `./x:y` and `..:y` (relative-path markers), and —
/// where drives exist — `a:b`, whose leading `a` is a drive letter.
///
/// An **empty** candidate is never a name on either platform: `:leading-colon`
/// is a relative filename, and nothing can be configured under the empty name.
///
/// The minimum-length rule is `drive_letters`-conditional and the other two are
/// not, because only that one is about drives. Off Windows a single character is
/// an ordinary remote reference that no configuration can satisfy, which is the
/// arrangement the module docs set out.
fn is_remote_name(candidate: &str, drive_letters: bool) -> bool {
    // Length in characters, not bytes: a single non-ASCII character is still one
    // character, and a byte count would let `é:x` through as a two-byte "name"
    // on a platform that means to exclude one-character names.
    let length = candidate.chars().count();
    let minimum = if drive_letters {
        MIN_REMOTE_NAME_LEN
    } else {
        1
    };
    if length < minimum {
        return false;
    }
    if candidate.starts_with(RELATIVE_PATH_MARKER) {
        return false;
    }
    !candidate.contains([PATH_SEPARATOR, WINDOWS_PATH_SEPARATOR])
}

/// Renders back to something [`RemoteSpec::parse`] accepts.
///
/// Used in error messages and `--dry-run` lines, where showing the *resolved*
/// spec rather than the raw argument is what tells a user their `C:\...` was
/// understood as a path.
impl fmt::Display for RemoteSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local(path) => write!(f, "{}", path.display()),
            Self::Named { remote, path } => write!(f, "{remote}{REMOTE_SEPARATOR}{path}"),
        }
    }
}

/// Lets `clap` parse an argument straight into a spec via `value_parser`, so a
/// malformed spec is reported as a usage error before any command body runs.
impl FromStr for RemoteSpec {
    type Err = CliError;

    fn from_str(input: &str) -> Result<Self> {
        Self::parse(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Classification on a platform that has drive letters.
    const WINDOWS: bool = true;
    /// Classification on a platform that does not.
    const POSIX: bool = false;

    fn parse(input: &str) -> RemoteSpec {
        RemoteSpec::parse(input).unwrap()
    }

    fn local(input: &str) -> PathBuf {
        match RemoteSpec::parse(input).unwrap() {
            RemoteSpec::Local(path) => path,
            other => panic!("'{input}' should be a local path, got {other:?}"),
        }
    }

    fn named(input: &str) -> (String, String) {
        match RemoteSpec::parse(input).unwrap() {
            RemoteSpec::Named { remote, path } => (remote, path),
            other => panic!("'{input}' should be a named remote, got {other:?}"),
        }
    }

    /// The path a spec classifies to on a stated platform.
    fn local_on(input: &str, drive_letters: bool) -> PathBuf {
        match RemoteSpec::classify(input, drive_letters).unwrap() {
            RemoteSpec::Local(path) => path,
            other => panic!("'{input}' should be a local path, got {other:?}"),
        }
    }

    /// The remote name a spec classifies to on a stated platform.
    fn remote_on(input: &str, drive_letters: bool) -> String {
        match RemoteSpec::classify(input, drive_letters).unwrap() {
            RemoteSpec::Named { remote, .. } => remote,
            other => panic!("'{input}' should be a named remote, got {other:?}"),
        }
    }

    #[test]
    fn every_drive_letter_form_is_a_local_path_where_drives_exist() {
        // The bug this whole module exists to prevent. `C:relative` is the rare
        // drive-relative form: still a path, still never a remote called `C`.
        for spec in [
            "C:",
            "c:",
            "C:/",
            r"C:\",
            "c:/x",
            r"C:\Users\me",
            "C:relative",
        ] {
            assert_eq!(
                local_on(spec, WINDOWS),
                PathBuf::from(spec),
                "'{spec}' must be a path on Windows"
            );
            let parsed = RemoteSpec::classify(spec, WINDOWS).unwrap();
            assert!(parsed.is_local());
            assert_eq!(parsed.remote_name(), None);
        }
    }

    #[test]
    fn a_single_letter_reference_is_a_remote_where_drives_do_not() {
        // rclone's `IsDriveLetter` is false off Windows, so `r:` means the
        // remote `r` there. DCTL matched Windows everywhere and therefore made
        // `dctl copy /srv/data r:` create a directory literally named `r:` and
        // exit 0 — the backup went somewhere nobody named.
        assert_eq!(remote_on("r:", POSIX), "r");
        assert_eq!(remote_on("r:data", POSIX), "r");
        assert_eq!(remote_on(r"C:\Users\me", POSIX), "C");
        // And it is still a path where drives exist, on the same test run.
        assert_eq!(local_on("r:", WINDOWS), PathBuf::from("r:"));
    }

    #[test]
    fn a_single_letter_remote_can_never_be_configured_on_either_platform() {
        // This is what makes the platform split safe rather than merely
        // rclone-compatible: off Windows `r:` parses as a remote, and no config
        // file may declare a one-character name, so it resolves to nothing and
        // fails by name. It cannot silently address a remote the user did not
        // mean, which is the only outcome that would actually matter.
        const {
            assert!(
                MIN_REMOTE_NAME_LEN > 1,
                "a declarable one-character name would reopen the ambiguity"
            );
        }
    }

    #[test]
    fn unc_paths_are_local_on_every_platform() {
        // Unlike a drive specifier, nothing but a Windows path begins `\\`, so
        // this rule has no platform half to get wrong.
        for spec in [r"\\server\share", r"\\?\C:\very\long\path"] {
            assert_eq!(local_on(spec, WINDOWS), PathBuf::from(spec));
            assert_eq!(local_on(spec, POSIX), PathBuf::from(spec));
        }
    }

    #[test]
    fn a_two_character_name_is_a_remote_on_both_platforms() {
        // Everything a config file can actually declare classifies identically
        // wherever it runs, which is the property the old blanket rule was
        // protecting and the only one worth protecting.
        for spec in ["vault:photos", "b2:bucket", "local:/srv/data"] {
            assert_eq!(
                RemoteSpec::classify(spec, WINDOWS).unwrap(),
                RemoteSpec::classify(spec, POSIX).unwrap(),
                "'{spec}' must mean the same thing on both platforms"
            );
        }
    }

    #[test]
    fn unc_and_extended_length_paths_are_local() {
        for spec in [
            r"\\server\share",
            r"\\server\share\file.txt",
            r"\\?\C:\very\long\path",
            r"\\?\UNC\server\share",
        ] {
            assert_eq!(local(spec), PathBuf::from(spec), "'{spec}' must be a path");
        }
    }

    #[test]
    fn a_name_shorter_than_the_minimum_is_a_path_where_drives_exist() {
        // The rule that keeps drive letters unambiguous, applied to the
        // non-alphabetic cases the drive check does not catch. Off Windows all
        // three are one-character remote references that resolve to nothing.
        assert_eq!(local_on("1:file", WINDOWS), PathBuf::from("1:file"));
        // Counted in characters: one accented letter is one character.
        assert_eq!(local_on("é:x", WINDOWS), PathBuf::from("é:x"));
        assert_eq!(remote_on("1:file", POSIX), "1");
    }

    #[test]
    fn bare_posix_paths_are_local() {
        for spec in [
            "photos",
            "./photos",
            "../sibling",
            "photos/2024/a.jpg",
            "/absolute/path",
            "/",
            ".",
            "..",
        ] {
            assert_eq!(local(spec), PathBuf::from(spec), "'{spec}' must be a path");
        }
    }

    #[test]
    fn named_remotes_split_at_the_first_colon() {
        assert_eq!(
            named("vault:photos/2024"),
            ("vault".into(), "photos/2024".into())
        );
        assert_eq!(named("b2:my-bucket"), ("b2".into(), "my-bucket".into()));
    }

    #[test]
    fn a_remote_with_no_path_addresses_its_root() {
        // `dctl ls vault:` is the whole-remote listing, so an empty path is a
        // valid spec and must not be confused with a missing one.
        let (remote, path) = named("vault:");
        assert_eq!(remote, "vault");
        assert!(path.is_empty());
        assert_eq!(parse("vault:").to_string(), "vault:");
    }

    #[test]
    fn only_the_first_colon_is_structural() {
        // A colon is a legal filename character on POSIX, so everything after
        // the split belongs to the path — including more colons.
        assert_eq!(named("vault:a:b"), ("vault".into(), "a:b".into()));
        assert_eq!(
            named("vault:2024:07:26/notes"),
            ("vault".into(), "2024:07:26/notes".into())
        );
    }

    #[test]
    fn a_colon_inside_a_directory_name_does_not_create_a_remote() {
        // `photos/holiday:2024` is one relative path, not a remote called
        // `photos/holiday`. A path separator in the candidate settles it.
        for spec in [
            "photos/holiday:2024",
            r"photos\holiday:2024",
            "./a:b",
            "../a:b",
        ] {
            assert_eq!(local(spec), PathBuf::from(spec), "'{spec}' must be a path");
        }
    }

    #[test]
    fn an_empty_candidate_is_a_path_on_every_platform() {
        // `:leading-colon` is a relative filename. Nothing can be configured
        // under the empty name, so there is no platform on which it is a
        // reference to anything.
        assert_eq!(
            local_on(":leading-colon", WINDOWS),
            PathBuf::from(":leading-colon")
        );
        assert_eq!(
            local_on(":leading-colon", POSIX),
            PathBuf::from(":leading-colon")
        );
    }

    #[test]
    fn the_local_prefix_forces_a_filesystem_path() {
        // The escape hatch, and the reason it exists: an absolute path keeps its
        // leading slash, and a directory whose name contains a colon survives.
        assert_eq!(local("local:/srv/data"), PathBuf::from("/srv/data"));
        assert_eq!(local("local:archive:2024"), PathBuf::from("archive:2024"));
        assert_eq!(local(r"local:C:\Users\me"), PathBuf::from(r"C:\Users\me"));
        assert_eq!(local("local:"), PathBuf::from(""));
    }

    #[test]
    fn decomposed_and_composed_spellings_produce_one_spec() {
        // macOS hands back NFD, Linux and Windows NFC. Two spellings of one
        // filename would hash to two index keys and store two objects for one
        // file — a duplicate invisible to the user who created it.
        let nfd = "vault:cafe\u{301}/photo.jpg";
        let nfc = "vault:caf\u{e9}/photo.jpg";
        assert_ne!(nfd, nfc, "the inputs really are different byte sequences");
        assert_eq!(parse(nfd), parse(nfc));
        assert_eq!(parse(nfd).path(), parse(nfc).path());
    }

    #[test]
    fn a_decomposed_remote_name_converges_too() {
        // Same argument as the path: one config entry, found by either spelling.
        assert_eq!(
            parse("archive\u{301}:x").remote_name(),
            parse("archiv\u{e9}:x").remote_name()
        );
    }

    #[test]
    fn logical_paths_are_canonicalised_but_native_ones_are_not() {
        assert_eq!(named("vault:./a//b/./c/"), ("vault".into(), "a/b/c".into()));
        assert_eq!(named(r"vault:a\b"), ("vault".into(), "a/b".into()));
        // The local path keeps every byte: the OS will look up exactly these.
        assert_eq!(local("./a//b/"), PathBuf::from("./a//b/"));
    }

    #[test]
    fn climbing_out_of_a_remote_is_refused() {
        // `..` has nowhere to go above a remote's root, and silently clamping it
        // would address a different object than the user asked for.
        for spec in ["vault:../escape", "vault:a/../../b"] {
            let error = RemoteSpec::parse(spec).unwrap_err();
            assert_eq!(error.code(), crate::exit::ExitCode::Usage);
            assert!(error.hint().is_some(), "'{spec}' must explain itself");
        }
        // Interior `..` that stays inside is still a climb we refuse, but a
        // *local* `..` is an ordinary relative path and must survive.
        assert_eq!(local("../sibling"), PathBuf::from("../sibling"));
    }

    #[test]
    fn an_empty_argument_is_a_usage_error() {
        let error = RemoteSpec::parse("").unwrap_err();
        assert_eq!(error.code(), crate::exit::ExitCode::Usage);
        assert!(error.hint().is_some());
    }

    #[test]
    fn display_round_trips_through_the_parser() {
        for spec in [
            "vault:photos/2024",
            "vault:",
            "vault:a:b",
            "/absolute/path",
            "photos/2024",
            r"C:\Users\me",
        ] {
            let parsed = parse(spec);
            assert_eq!(
                RemoteSpec::parse(&parsed.to_string()).unwrap(),
                parsed,
                "'{spec}' did not survive a Display round trip"
            );
        }
    }

    #[test]
    fn the_lossless_path_is_available_only_for_local_specs() {
        assert_eq!(
            parse("/srv/data").local_path(),
            Some(Path::new("/srv/data"))
        );
        assert_eq!(parse("vault:x").local_path(), None);
        assert_eq!(parse("vault:x").path(), "x");
    }

    #[test]
    fn clap_can_parse_a_spec_directly() {
        // Registered as a value_parser, so a malformed spec is reported as a
        // usage error before the command body starts doing work.
        assert_eq!("vault:x".parse::<RemoteSpec>().unwrap(), parse("vault:x"));
        assert!("".parse::<RemoteSpec>().is_err());
    }
}
