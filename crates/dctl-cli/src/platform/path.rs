//! Conversion between OS paths and logical vault paths.
//!
//! A **logical path** is what DCTL stores and hashes: `/`-separated, UTF-8,
//! Unicode-NFC, no leading slash, no `.`/`..` components. It is identical on
//! every operating system, which is what makes a vault written on a Mac
//! readable — and *addressable* — from Linux or Windows.
//!
//! The NFC rule matters more than it looks. macOS hands back decomposed
//! filenames, so `café` arrives as `cafe\u{301}` (6 bytes, `e` + combining
//! acute) while the same file typed on Linux or Windows is `caf\u{e9}`
//! (5 bytes). Both display identically. Since the index key is
//! `BLAKE3_keyed(key, path.as_bytes())` and the object key is derived the same
//! way, two spellings would produce two different objects for one file — a
//! silent duplicate that no user could see or explain. Normalising once, here,
//! makes the hash input canonical.
//!
//! ## The backslash rule
//!
//! `\` is where the platforms genuinely disagree, and the disagreement cannot be
//! papered over. On Windows it separates components; on Unix it is an ordinary
//! character that a file may legally be named with. So the string `a\b.txt`
//! describes *one* file on Linux and *two* components on Windows, and both
//! readings are correct on their own platform.
//!
//! DCTL resolves it in one direction, here, and applies the same answer to both
//! ways a path can enter a vault:
//!
//! * A path a **person typed** — a spec, a `--files-from` line, an `ls` prefix —
//!   splits on `\` as well as `/` ([`clean_logical`]), on every platform, so a
//!   script written on Windows means the same thing on a Linux build agent.
//! * A path read from a **filesystem** ([`to_logical`],
//!   [`to_logical_component`]) may not contain `\` in a component at all. Such a
//!   name is refused, exactly as a non-UTF-8 name is.
//!
//! The alternative — storing the Unix reading as a single component — is what
//! makes the same file answer to two different index keys, because every spec
//! naming it takes the other reading. And it does not survive the trip back
//! out: [`from_logical`] on Windows would recreate `a\b.txt` as `b.txt` inside a
//! directory `a`, which is not the file that was backed up. Refusing costs the
//! user one clearly-reported file; accepting costs them a vault whose contents
//! depend on which machine reads it. That is the same trade
//! [`crate::platform::names`] already makes: report the name, never rewrite it.

use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

use unicode_normalization::UnicodeNormalization;

use crate::constants::{LOGICAL_PATH_SEPARATORS, PATH_SEPARATOR};

/// The logical path separator. Always `/`, on every platform.
pub const SEPARATOR: char = PATH_SEPARATOR;

/// Why a filesystem name has no logical spelling.
///
/// Carried rather than collapsed into a bare `None` so the walks can tell their
/// operator *which* rule refused a file. "Skipped 1 entry" is a shrug; "skipped
/// `photos/a\b.txt`: contains `\`" is something a person can rename and retry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unrepresentable {
    /// The name is not valid UTF-8, so it cannot be hashed into a key that any
    /// other platform could reproduce.
    NotUtf8,
    /// The name contains a character that separates path components somewhere
    /// (see the backslash rule above), so it has no single logical reading.
    Separator(char),
    /// The name contains `..`. Not a name at all — a filesystem walk that
    /// produced one would be reporting a directory entry that addresses its own
    /// parent rather than a file.
    ParentDir,
}

impl std::fmt::Display for Unrepresentable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotUtf8 => write!(
                f,
                "the name is not valid UTF-8, so it has no logical vault path"
            ),
            Self::Separator(c) => write!(
                f,
                "the name contains '{c}', which separates path components on other platforms, \
                 so it has no single logical vault path"
            ),
            Self::ParentDir => write!(
                f,
                "the name is '..', which addresses a directory rather \
                 than naming one"
            ),
        }
    }
}

/// Convert one filesystem name into a logical path component.
///
/// The single gate every name from a directory walk passes through: NFC applied,
/// and the two shapes that cannot round-trip refused. Callers get a reason they
/// can print rather than a silent skip.
///
/// # Errors
/// [`Unrepresentable::NotUtf8`] for a name that is not valid UTF-8, and
/// [`Unrepresentable::Separator`] for one containing `/` or `\`.
pub fn to_logical_component(name: &OsStr) -> Result<String, Unrepresentable> {
    let name = name.to_str().ok_or(Unrepresentable::NotUtf8)?;
    if let Some(found) = name.chars().find(|c| LOGICAL_PATH_SEPARATORS.contains(c)) {
        return Err(Unrepresentable::Separator(found));
    }
    Ok(normalize_unicode(name))
}

/// Append one component to a logical prefix.
///
/// Trivial, and shared anyway: a walk that formats its own separator is a walk
/// that can format a different one, and the whole point of a logical path is
/// that there is only ever one spelling.
#[must_use]
pub fn join(prefix: &str, component: &str) -> String {
    if prefix.is_empty() {
        component.to_string()
    } else {
        format!("{prefix}{SEPARATOR}{component}")
    }
}

/// Convert an OS path to a canonical logical vault path.
///
/// Applies, in order: separator normalisation (`\` → `/` on Windows), removal of
/// `.` components and any leading/trailing separators, then Unicode NFC.
///
/// The refusal carries its reason rather than collapsing to `None`: the callers
/// are directory walks, and a walk that drops a file must be able to say which
/// file and why.
///
/// # Errors
/// See [`to_logical_component`], plus [`Unrepresentable::ParentDir`] for a path
/// that climbs above its root.
pub fn to_logical(path: &Path) -> Result<String, Unrepresentable> {
    let mut parts: Vec<String> = Vec::new();

    for component in path.components() {
        match component {
            // Skip `/`, `C:\`, `\\?\`, and `\\server\share` prefixes: a logical
            // path is always relative to the transfer root.
            Component::RootDir | Component::Prefix(_) => {}
            Component::CurDir => {}
            Component::ParentDir => return Err(Unrepresentable::ParentDir),
            // On Windows `components()` has already split on `\`, so this only
            // ever fires on a Unix name that genuinely contains one — which is
            // exactly the name that has two readings and must be refused.
            Component::Normal(part) => parts.push(to_logical_component(part)?),
        }
    }

    Ok(parts.join(SEPARATOR.to_string().as_str()))
}

/// Convert a logical vault path back to a native OS path, relative to `root`.
///
/// On Windows this yields backslash separators via [`PathBuf`]'s own joining.
#[must_use]
pub fn from_logical(root: &Path, logical: &str) -> PathBuf {
    let mut out = root.to_path_buf();
    for part in logical.split(SEPARATOR).filter(|p| !p.is_empty()) {
        out.push(part);
    }
    out
}

/// Apply Unicode NFC to a logical path.
///
/// Exposed separately because paths that arrive as strings (from the command
/// line, a `--files-from` list, or a remote listing) need the same treatment as
/// paths that arrive from the filesystem.
#[must_use]
pub fn normalize_unicode(path: &str) -> String {
    // Fast path: ASCII is already NFC, and it is the overwhelming majority.
    if path.is_ascii() {
        return path.to_string();
    }
    path.nfc().collect()
}

/// Canonicalise a user-supplied logical path: normalise separators, drop `.`
/// components and redundant separators, and apply NFC.
///
/// Splits on `\` as well as `/`, on every platform — see the backslash rule in
/// the module documentation. This is the reading of `a\b.txt` that DCTL commits
/// to, which is why a *filename* containing `\` has no logical spelling at all.
///
/// Returns `None` if the path tries to escape its root with `..`.
#[must_use]
pub fn clean_logical(input: &str) -> Option<String> {
    let mut parts: Vec<&str> = Vec::new();
    for part in input.split(LOGICAL_PATH_SEPARATORS) {
        match part {
            "" | "." => {}
            ".." => return None,
            other => parts.push(other),
        }
    }
    Some(normalize_unicode(
        &parts.join(SEPARATOR.to_string().as_str()),
    ))
}

/// What the `..` components in a logical path actually do.
///
/// [`clean_logical`] refuses every `..`, which is the right policy — a logical
/// path is a key, not a filesystem path, and silently rewriting the argument a
/// user typed into a different one is how data gets written to the wrong place.
/// The *message* was another matter: `vault:x/../y` was refused with "climbs
/// above the root", which is not what `x/../y` does. It names `y`.
///
/// So the refusal now says which case it is, and for the harmless one it can
/// name the path the user meant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParentDirUse {
    /// The `..` components cancel out; the path names something inside the
    /// remote after all, spelled here without them. `""` is the remote's root.
    Inside(String),
    /// A `..` reaches past the root, so there is nothing for it to name.
    Escapes,
}

/// Classify the `..` components in `input`, or [`None`] if it has none.
///
/// Resolution is textual and that is correct here: a logical path has no
/// symlinks and no mount points, so `a/../b` and `b` address the same object by
/// construction. Nothing in this function decides whether to accept the path —
/// it only decides what to *say* about it.
#[must_use]
pub fn classify_parent_dir(input: &str) -> Option<ParentDirUse> {
    let mut resolved: Vec<&str> = Vec::new();
    let mut saw_parent = false;
    for part in input.split(LOGICAL_PATH_SEPARATORS) {
        match part {
            "" | "." => {}
            ".." => {
                saw_parent = true;
                if resolved.pop().is_none() {
                    return Some(ParentDirUse::Escapes);
                }
            }
            other => resolved.push(other),
        }
    }
    saw_parent.then(|| {
        ParentDirUse::Inside(normalize_unicode(
            &resolved.join(SEPARATOR.to_string().as_str()),
        ))
    })
}

/// The two halves of a refusal for a spec whose logical path contains `..`.
///
/// Returned as strings rather than as a built error so both the spec parser and
/// the listing parser can raise it in their own error type, and so the wording —
/// which is the entire point of this function — is written once.
///
/// The wording had to change because it was wrong. `vault:x/../y` was refused
/// with *"climbs above the root of 'vault'"*, and `x/../y` does not climb above
/// anything: it names `y`. A reader told their path escaped the root looks for
/// the escape, finds none, and concludes the tool is confused — which it was.
/// Now the message says what happened, and when the path resolves to somewhere
/// real it names the spelling that would have worked.
///
/// The refusal itself is unchanged. A logical path is a key, and resolving `..`
/// on the user's behalf means acting on a path they did not type; the value here
/// is telling them the one they meant, not typing it for them.
#[must_use]
pub fn parent_dir_refusal(
    spec: &str,
    remote: &str,
    path: &str,
    separator: char,
) -> (String, String) {
    match classify_parent_dir(path) {
        Some(ParentDirUse::Escapes) | None => (
            format!("'{spec}' climbs above the root of '{remote}'"),
            "A logical path is always relative to the remote's root, so a '..' that \
             reaches past it has nothing to name. Address the directory directly."
                .to_string(),
        ),
        Some(ParentDirUse::Inside(resolved)) => (
            format!("'{spec}' contains '..', which a logical path does not resolve"),
            format!(
                "'..' is refused wherever it appears, including where it cancels out: a \
                 logical path is a key rather than a filesystem path, and rewriting the \
                 one you typed into a different one is how data reaches the wrong place. \
                 Name it directly as '{remote}{separator}{resolved}'."
            ),
        ),
    }
}

/// Whether `child` lies under `prefix` in logical-path terms.
///
/// Compares whole components, so `photos/2024` is *not* considered a parent of
/// `photos/2024-backup` — a plain `starts_with` would get that wrong and delete
/// the wrong tree during a `sync`.
#[must_use]
pub fn is_under(prefix: &str, child: &str) -> bool {
    if prefix.is_empty() {
        return true;
    }
    let prefix = prefix.trim_end_matches(SEPARATOR);
    match child.strip_prefix(prefix) {
        Some("") => true,
        Some(rest) => rest.starts_with(SEPARATOR),
        None => false,
    }
}

/// The final component of a logical path.
#[must_use]
pub fn file_name(logical: &str) -> &str {
    logical.rsplit(SEPARATOR).next().unwrap_or(logical)
}

/// The parent portion of a logical path, or `""` at the root.
#[must_use]
pub fn parent(logical: &str) -> &str {
    match logical.rfind(SEPARATOR) {
        Some(index) => &logical[..index],
        None => "",
    }
}

/// Whether a string looks like a Windows drive specifier such as `C:` or `C:\`.
///
/// A shape test and nothing more: it answers "could this be a drive letter",
/// never "is it one here". Whether the shape *wins* is
/// [`crate::remote::spec`]'s decision, and it is the one rule in that module
/// that depends on the platform — see [`DRIVE_LETTERS_EXIST`].
#[must_use]
pub fn looks_like_windows_drive(spec: &str) -> bool {
    let mut chars = spec.chars();
    match (chars.next(), chars.next()) {
        (Some(letter), Some(':')) if letter.is_ascii_alphabetic() => {
            // `C:` alone, or `C:` followed by a separator, is a drive.
            // `C:relative` is also a (rare) legal Windows path.
            true
        }
        _ => false,
    }
}

/// Whether a path is a Windows UNC or extended-length path (`\\server\share`,
/// `\\?\C:\...`). These are always local paths, never remote specs.
#[must_use]
pub fn looks_like_unc(spec: &str) -> bool {
    spec.starts_with("\\\\")
}

/// Whether `name` — a bare remote **name**, with no colon and no path — has the
/// shape of a Windows drive letter.
///
/// rclone's `driveletter.IsDriveLetter` (`fs/driveletter/driveletter_windows.go:8`)
/// exactly: one character, and that character an ASCII letter. Digits are not
/// drives, so `1` is not one; `é` is not one either, which is why the test is on
/// bytes rather than on `char::is_alphabetic`.
///
/// Like [`looks_like_windows_drive`] this is a shape test and says nothing about
/// the platform. Whether the shape *matters* is the caller's decision, taken
/// through [`crate::constants::DRIVE_LETTERS_EXIST`], so that both answers are
/// reachable from a test run on either kind of machine.
#[must_use]
pub fn is_drive_letter(name: &str) -> bool {
    name.len() == 1 && name.as_bytes()[0].is_ascii_alphabetic()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logical_paths_use_forward_slashes() {
        let path = Path::new("photos").join("2024").join("a.jpg");
        assert_eq!(to_logical(&path).as_deref(), Ok("photos/2024/a.jpg"));
    }

    #[test]
    fn parent_dir_components_are_rejected() {
        assert_eq!(
            to_logical(Path::new("../escape")),
            Err(Unrepresentable::ParentDir)
        );
        assert_eq!(clean_logical("a/../../b"), None);
    }

    #[test]
    fn a_parent_dir_that_cancels_out_is_told_apart_from_one_that_escapes() {
        // The distinction the refusal message was getting wrong: `x/../y` names
        // `y` and does not climb above anything.
        assert_eq!(
            classify_parent_dir("x/../y"),
            Some(ParentDirUse::Inside("y".to_string()))
        );
        assert_eq!(
            classify_parent_dir("a/b/../c/d"),
            Some(ParentDirUse::Inside("a/c/d".to_string()))
        );
        // Cancelling back to the remote's own root is still inside it.
        assert_eq!(
            classify_parent_dir("a/b/../.."),
            Some(ParentDirUse::Inside(String::new()))
        );
        // These genuinely leave.
        assert_eq!(classify_parent_dir("../y"), Some(ParentDirUse::Escapes));
        assert_eq!(
            classify_parent_dir("a/../../b"),
            Some(ParentDirUse::Escapes)
        );
        // And a path with no `..` at all is not this function's business.
        assert_eq!(classify_parent_dir("a/b/c"), None);
        assert_eq!(classify_parent_dir("a/./b"), None);
    }

    #[test]
    fn the_refusal_says_what_the_path_actually_did() {
        // `vault:x/../y` was refused with "climbs above the root of 'vault'",
        // which is a statement about a path that does no such thing. A reader
        // told their path escaped goes looking for the escape, finds none, and
        // stops trusting the message.
        let (reason, hint) = parent_dir_refusal("vault:x/../y", "vault", "x/../y", ':');
        assert!(
            !reason.contains("climbs above"),
            "a path that resolves inside the root must not be told it left it: {reason}"
        );
        assert!(reason.contains("'..'"), "{reason}");
        // And the hint names the spelling that would have worked, which is the
        // whole practical value of telling the two cases apart.
        assert!(hint.contains("'vault:y'"), "{hint}");

        // The genuine escape keeps the words that were always true of it.
        let (reason, hint) = parent_dir_refusal("vault:../y", "vault", "../y", ':');
        assert!(
            reason.contains("climbs above the root of 'vault'"),
            "{reason}"
        );
        assert!(!hint.contains("Name it directly"), "{hint}");
    }

    #[test]
    fn a_path_that_cancels_back_to_the_root_is_pointed_at_the_root() {
        // The degenerate case the hint has to render sensibly rather than as
        // `'vault:'` followed by nothing meaningful — it *is* the remote's root,
        // and `vault:` is exactly how that is spelled.
        let (_, hint) = parent_dir_refusal("vault:a/..", "vault", "a/..", ':');
        assert!(hint.contains("'vault:'"), "{hint}");
    }

    #[test]
    fn a_component_may_not_contain_a_separator() {
        // The gate every filesystem name passes through. `/` is impossible on
        // any real filesystem; `\` is not, and is the whole point of the rule.
        assert_eq!(
            to_logical_component(OsStr::new(r"a\b.txt")),
            Err(Unrepresentable::Separator('\\'))
        );
        assert_eq!(
            to_logical_component(OsStr::new("a/b.txt")),
            Err(Unrepresentable::Separator('/'))
        );
        assert_eq!(
            to_logical_component(OsStr::new("photo.jpg")).as_deref(),
            Ok("photo.jpg")
        );
    }

    #[test]
    fn a_component_is_normalised_on_the_way_in() {
        // The same NFC guarantee `to_logical` gives, applied one name at a time
        // so a directory walk can build a path without re-normalising it.
        let nfd = to_logical_component(OsStr::new("cafe\u{301}"));
        let nfc = to_logical_component(OsStr::new("caf\u{e9}"));
        assert_eq!(nfd, nfc);
        assert_eq!(nfd.as_deref(), Ok("caf\u{e9}"));
    }

    #[cfg(unix)]
    #[test]
    fn a_component_that_is_not_utf8_is_refused_with_its_reason() {
        use std::os::unix::ffi::OsStrExt as _;
        let raw = OsStr::from_bytes(&[0x66, 0xff, 0x6f]);
        assert_eq!(to_logical_component(raw), Err(Unrepresentable::NotUtf8));
    }

    #[test]
    fn every_refusal_explains_itself() {
        // These strings reach an operator verbatim, in a scan problem or a
        // transfer warning. An empty or generic one is a file that vanished
        // without a reason anybody could act on.
        for issue in [
            Unrepresentable::NotUtf8,
            Unrepresentable::Separator('\\'),
            Unrepresentable::ParentDir,
        ] {
            let text = issue.to_string();
            assert!(text.len() > 20, "unhelpful reason: {text}");
        }
        assert!(Unrepresentable::Separator('\\').to_string().contains('\\'));
    }

    #[test]
    fn joining_uses_the_logical_separator_and_skips_an_empty_prefix() {
        assert_eq!(join("", "a.txt"), "a.txt");
        assert_eq!(join("photos", "a.txt"), "photos/a.txt");
        assert_eq!(join("photos/2024", "a.txt"), "photos/2024/a.txt");
    }

    #[test]
    fn cleaning_drops_noise_and_accepts_backslashes() {
        assert_eq!(clean_logical("./a//b/./c/").as_deref(), Some("a/b/c"));
        assert_eq!(clean_logical(r"a\b\c").as_deref(), Some("a/b/c"));
        assert_eq!(clean_logical("").as_deref(), Some(""));
    }

    #[test]
    fn a_name_never_has_two_logical_spellings() {
        // The walk (`to_logical`) and the spec parser (`clean_logical`) are the
        // two ways a path enters the vault, and the index key is a hash of the
        // result. If they disagree for any input, one file gets two keys — so
        // the walk must either agree with the parser or refuse the name.
        for raw in ["photos/a.jpg", r"a\b.txt", r"x\y/z", "plain.txt"] {
            let walked = to_logical(Path::new(raw)).ok();
            let typed = clean_logical(raw);
            assert!(
                walked.is_none() || walked == typed,
                "{raw}: the walk stores {walked:?} but a spec naming it means {typed:?}"
            );
        }
    }

    #[test]
    fn decomposed_and_composed_spellings_converge() {
        // macOS hands back NFD; Linux/Windows typically NFC. Both must produce
        // the same logical path, or one file becomes two objects.
        let nfd = "cafe\u{301}/photo.jpg";
        let nfc = "caf\u{e9}/photo.jpg";
        assert_ne!(nfd, nfc, "the inputs really are different byte sequences");
        assert_eq!(clean_logical(nfd), clean_logical(nfc));
        assert_eq!(normalize_unicode(nfd), normalize_unicode(nfc));
    }

    #[test]
    fn ascii_is_passed_through_unchanged() {
        assert_eq!(normalize_unicode("photos/2024/a.jpg"), "photos/2024/a.jpg");
    }

    #[test]
    fn containment_compares_whole_components() {
        assert!(is_under("photos", "photos/a.jpg"));
        assert!(is_under("photos", "photos"));
        assert!(is_under("", "anything"));
        // The bug this guards against: a naive starts_with would delete
        // `photos-backup/` when asked to sync `photos/`.
        assert!(!is_under("photos", "photos-backup/a.jpg"));
        assert!(!is_under("photos", "other/a.jpg"));
    }

    #[test]
    fn drive_letters_are_not_remote_names() {
        assert!(looks_like_windows_drive("C:"));
        assert!(looks_like_windows_drive(r"C:\Users\me"));
        assert!(looks_like_windows_drive("d:/data"));
        // Two or more characters before the colon is a remote.
        assert!(!looks_like_windows_drive("b2:bucket"));
        assert!(!looks_like_windows_drive("vault:photos"));
        assert!(!looks_like_windows_drive("/absolute/path"));
    }

    #[test]
    fn unc_paths_are_local() {
        assert!(looks_like_unc(r"\\server\share\file"));
        assert!(looks_like_unc(r"\\?\C:\very\long\path"));
        assert!(!looks_like_unc(r"C:\normal"));
    }

    #[test]
    fn a_drive_letter_is_one_ascii_letter_and_nothing_else() {
        // rclone's rule verbatim (`fs/driveletter/driveletter_windows.go:8`):
        // length one, ASCII letter. A digit names no drive, and a two-character
        // name is a remote everywhere.
        for name in ["c", "C", "z", "A"] {
            assert!(is_drive_letter(name), "'{name}' is a drive letter");
        }
        for name in ["", "1", "cd", "é", "_", "c:"] {
            assert!(!is_drive_letter(name), "'{name}' is not a drive letter");
        }
    }

    #[test]
    fn name_and_parent_split_correctly() {
        assert_eq!(file_name("a/b/c.txt"), "c.txt");
        assert_eq!(file_name("solo.txt"), "solo.txt");
        assert_eq!(parent("a/b/c.txt"), "a/b");
        assert_eq!(parent("solo.txt"), "");
    }

    #[test]
    fn round_trip_through_native_paths() {
        let root = Path::new("root");
        let native = from_logical(root, "a/b/c.txt");
        assert!(native.ends_with(Path::new("a").join("b").join("c.txt")));
    }
}
