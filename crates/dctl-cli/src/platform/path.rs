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
    /// The path climbs above its own root with `..`. Not a name at all, and a
    /// logical path that began with one would address something outside the
    /// vault entirely.
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
            Self::ParentDir => write!(f, "the path climbs above its root with '..'"),
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
/// This is the disambiguation rule for `remote:path` syntax. `C:\Users\me` is a
/// local path on Windows, not a remote named `C`; DCTL follows rclone and treats
/// **any single-character prefix** before the colon as a drive letter. Remote
/// names are therefore required to be two characters or longer (enforced when
/// the config is written).
///
/// The check is applied on every platform, not just Windows, so that a script
/// written on Windows behaves the same when it runs on a Linux build agent.
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
