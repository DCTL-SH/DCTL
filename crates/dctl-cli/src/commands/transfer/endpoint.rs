//! The two questions the transfer family asks of a [`RemoteSpec`] that no other
//! command needs answered.
//!
//! Classifying `SOURCE`/`DEST` is [`crate::remote::spec`]'s job and is not
//! repeated here: the Windows drive-letter rule is the sharpest edge in the CLI
//! and must have exactly one implementation. What this module adds is the split
//! `copyto` and `moveto` depend on — the object's **name** versus the container
//! it lands in.
//!
//! ```text
//!   vault:archive/2024.tar
//!   └────────┬──────┘ └─┬──┘
//!     parent()        leaf()
//! ```
//!
//! `copy` never needs that split, because `DEST` is always the container. The
//! exact-name verbs do, because for them `DEST` is the object — and reading the
//! same argument the wrong way round writes a file to a path nobody named.

use std::path::PathBuf;

use crate::platform::path as logical;
use crate::remote::RemoteSpec;

/// The final component of a spec — the name an exact-name transfer gives the
/// object.
///
/// Returns an empty string for a bare root (`vault:`, `/`), which the
/// exact-name commands treat as a usage error: a root supplies no name, and
/// inventing one would put the object somewhere the user never wrote.
///
/// The result is always a **logical** name, NFC-normalised even when it came
/// from a local path, because it is about to become a path inside a vault. That
/// is the same reason [`crate::platform::path`] normalises: `café` typed on a
/// Mac and on Linux must produce one object, not two.
#[must_use]
pub fn leaf(spec: &RemoteSpec) -> String {
    match spec {
        RemoteSpec::Local(path) => path
            .file_name()
            .and_then(|name| name.to_str())
            .map(logical::normalize_unicode)
            .unwrap_or_default(),
        RemoteSpec::Named { path, .. } => {
            if path.is_empty() {
                String::new()
            } else {
                logical::file_name(path).to_string()
            }
        }
    }
}

/// The spec one level up — the container an exact-name transfer writes into.
///
/// The counterpart of [`leaf`]: together they split `vault:a/b/c.txt` into the
/// root a listing is taken relative to and the name the object must end up with.
/// A local path with no parent becomes `.`, so the result is always something
/// that can be listed rather than an absence to special-case.
#[must_use]
pub fn parent(spec: &RemoteSpec) -> RemoteSpec {
    match spec {
        RemoteSpec::Local(path) => RemoteSpec::Local(
            path.parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .map_or_else(|| PathBuf::from("."), std::path::Path::to_path_buf),
        ),
        RemoteSpec::Named { remote, path } => RemoteSpec::Named {
            remote: remote.clone(),
            path: logical::parent(path).to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(input: &str) -> RemoteSpec {
        RemoteSpec::parse(input).unwrap()
    }

    #[test]
    fn a_remote_spec_splits_into_container_and_name() {
        let target = spec("vault:archive/2024.tar");
        assert_eq!(leaf(&target), "2024.tar");
        assert_eq!(parent(&target).to_string(), "vault:archive");
    }

    #[test]
    fn a_local_spec_splits_the_same_way() {
        let target = spec("/srv/out/final.mov");
        assert_eq!(leaf(&target), "final.mov");
        assert_eq!(
            parent(&target),
            RemoteSpec::Local(PathBuf::from("/srv/out"))
        );
    }

    #[test]
    fn a_root_supplies_no_name() {
        // `copyto x vault:` has no destination name, and inventing one would put
        // the object somewhere the user never wrote.
        assert_eq!(leaf(&spec("vault:")), "");
    }

    #[test]
    fn a_bare_filename_has_a_listable_parent() {
        // `.` rather than an empty path, so callers never special-case absence.
        assert_eq!(leaf(&spec("report.pdf")), "report.pdf");
        assert_eq!(
            parent(&spec("report.pdf")),
            RemoteSpec::Local(PathBuf::from("."))
        );
    }

    #[test]
    fn a_remote_object_at_the_root_has_the_remote_as_its_parent() {
        let target = spec("vault:solo.txt");
        assert_eq!(leaf(&target), "solo.txt");
        assert_eq!(parent(&target).to_string(), "vault:");
    }

    #[test]
    fn a_local_name_is_normalised_on_its_way_into_the_vault() {
        // macOS hands back NFD; the object key must be the NFC spelling, or the
        // same file stored from two machines becomes two objects.
        let nfd = RemoteSpec::Local(PathBuf::from("dir/cafe\u{301}.txt"));
        let nfc = RemoteSpec::Local(PathBuf::from("dir/caf\u{e9}.txt"));
        assert_eq!(leaf(&nfd), leaf(&nfc));
    }
}
