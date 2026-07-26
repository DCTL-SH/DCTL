//! Filename legality across platforms.
//!
//! A tree that is perfectly legal on Linux can be impossible to write on
//! Windows: `aux.txt`, `report:final.pdf` and `data.` are all valid POSIX names
//! and all rejected by Win32. Discovering that halfway through a 4 TB restore is
//! the worst possible time, so these checks run during the pre-flight scan and
//! report every offending path up front.
//!
//! Nothing here rewrites a name. DCTL stores the original bytes and reports the
//! conflict; silently mangling a filename would break the promise that a restore
//! reproduces exactly what was backed up.

/// Characters Win32 rejects in a path component.
///
/// `/` and `\` are separators and handled before this check; the rest are
/// reserved by the API itself.
const WINDOWS_ILLEGAL_CHARS: &[char] = &['<', '>', ':', '"', '|', '?', '*'];

/// Device names reserved by Win32, matched case-insensitively and *ignoring any
/// extension* — `CON`, `con.txt` and `CON.tar.gz` are all refused.
const WINDOWS_RESERVED_STEMS: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", //
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", //
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Why a name cannot be written on some platform.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NameIssue {
    /// Contains a character Win32 forbids.
    WindowsIllegalChar(char),
    /// Matches a reserved Win32 device name.
    WindowsReservedName(String),
    /// Ends with `.` or a space — Win32 silently strips these, so the file would
    /// come back under a different name than it went in with.
    WindowsTrailingDotOrSpace,
    /// Contains a control character (0x00–0x1F). Illegal essentially everywhere
    /// and a common sign of a corrupt listing.
    ControlCharacter(u32),
}

impl std::fmt::Display for NameIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WindowsIllegalChar(c) => {
                write!(
                    f,
                    "contains '{c}', which Windows does not allow in a filename"
                )
            }
            Self::WindowsReservedName(name) => {
                write!(f, "'{name}' is a reserved Windows device name")
            }
            Self::WindowsTrailingDotOrSpace => {
                write!(f, "ends with a dot or space, which Windows silently strips")
            }
            Self::ControlCharacter(code) => {
                write!(f, "contains control character U+{code:04X}")
            }
        }
    }
}

/// Inspect one path component for portability problems.
///
/// Checks run on every platform, not only Windows: the point is to warn a Linux
/// user *before* they store a name that their own Windows restore will not be
/// able to reproduce.
#[must_use]
pub fn check_component(component: &str) -> Vec<NameIssue> {
    let mut issues = Vec::new();

    for c in component.chars() {
        if (c as u32) < 0x20 {
            issues.push(NameIssue::ControlCharacter(c as u32));
        } else if WINDOWS_ILLEGAL_CHARS.contains(&c) {
            issues.push(NameIssue::WindowsIllegalChar(c));
        }
    }

    if component.ends_with('.') || component.ends_with(' ') {
        issues.push(NameIssue::WindowsTrailingDotOrSpace);
    }

    // Reserved names are matched on the stem, before the first dot.
    let stem = component.split('.').next().unwrap_or(component);
    if WINDOWS_RESERVED_STEMS
        .iter()
        .any(|reserved| reserved.eq_ignore_ascii_case(stem))
    {
        issues.push(NameIssue::WindowsReservedName(stem.to_uppercase()));
    }

    issues
}

/// Inspect every component of a logical path.
///
/// Returns `(component, issue)` pairs so the caller can point at the exact part
/// of a long path that is a problem.
#[must_use]
pub fn check_logical_path(logical: &str) -> Vec<(String, NameIssue)> {
    let mut out = Vec::new();
    for component in logical.split('/').filter(|c| !c.is_empty()) {
        for issue in check_component(component) {
            out.push((component.to_string(), issue));
        }
    }
    out
}

/// Whether this issue stops the *current* platform creating the file.
///
/// The single statement of the rule. Every check in [`check_component`] runs on
/// every platform — a Linux user must be warned about a name their own Windows
/// restore could not reproduce — so something has to say which of those issues
/// are advisory *here* and which actually block the write. On Windows all of
/// them block; elsewhere only a control character does.
///
/// It lives beside the checks rather than beside either caller because it has
/// two: the recovery pre-flight report grades each finding with it, and that
/// report's tests check their own classification against it. Two copies of this
/// predicate would eventually disagree, and the disagreement reads as
/// "blocking" on a name that would have written fine — or, far worse, the
/// reverse.
#[must_use]
pub fn issue_blocks_here(issue: &NameIssue) -> bool {
    if cfg!(target_os = "windows") {
        true
    } else {
        matches!(issue, NameIssue::ControlCharacter(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_names_are_clean() {
        assert!(check_component("photo.jpg").is_empty());
        assert!(check_component("My Folder").is_empty());
        assert!(check_component("café.txt").is_empty());
        assert!(check_logical_path("photos/2024/a.jpg").is_empty());
    }

    #[test]
    fn windows_illegal_characters_are_flagged() {
        let issues = check_component("report:final.pdf");
        assert_eq!(issues, vec![NameIssue::WindowsIllegalChar(':')]);
        assert!(!check_component("what?.txt").is_empty());
        assert!(!check_component("a|b").is_empty());
    }

    #[test]
    fn reserved_device_names_are_flagged_with_any_extension() {
        assert_eq!(
            check_component("CON"),
            vec![NameIssue::WindowsReservedName("CON".into())]
        );
        assert_eq!(
            check_component("con.txt"),
            vec![NameIssue::WindowsReservedName("CON".into())]
        );
        assert_eq!(
            check_component("LPT1.tar.gz"),
            vec![NameIssue::WindowsReservedName("LPT1".into())]
        );
        // Not reserved: a longer name that merely starts with one.
        assert!(check_component("console.log").is_empty());
        assert!(check_component("COM10").is_empty());
    }

    #[test]
    fn trailing_dot_or_space_is_flagged() {
        assert!(check_component("data.").contains(&NameIssue::WindowsTrailingDotOrSpace));
        assert!(check_component("data ").contains(&NameIssue::WindowsTrailingDotOrSpace));
        assert!(!check_component("data").contains(&NameIssue::WindowsTrailingDotOrSpace));
    }

    #[test]
    fn control_characters_are_flagged_everywhere() {
        let issues = check_component("bad\u{7}name");
        assert_eq!(issues, vec![NameIssue::ControlCharacter(7)]);
    }

    #[test]
    fn issues_report_the_offending_component() {
        let found = check_logical_path("photos/report:final/a.jpg");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, "report:final");
    }
}
