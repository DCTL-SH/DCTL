//! Pure, network-free path and chunk-planning logic for the SFTP backend.
//!
//! Everything here is deterministic and unit-tested without a connection: how an
//! [`ObjectKey`] maps to a remote path under `base`, how a leading `~` in `base`
//! collapses to a home-relative path, which ancestor directories a `mkdir -p` must
//! create, and how a byte total splits into bounded transfer chunks.

use std::path::{Component, Path};

use crate::error::{Result, StoreError};
use crate::model::{ObjectKey, ObjectMeta, Page};

/// Normalize a configured `base` into a remote path string with no trailing slash.
///
/// The openssh `sftp-server` resolves **relative** paths against its start
/// directory (the user's home), so a `base` of `~/foo`, `~foo`, or `./foo` all
/// collapse to the home-relative `foo`: SFTP itself never expands `~` (that needs
/// the optional `expand-path` extension), and sending a literal `~` would create a
/// directory *named* `~`. An **absolute** `base` (leading `/`) is kept verbatim.
/// Redundant slashes are collapsed and a trailing slash is trimmed.
#[must_use]
pub(crate) fn normalize_base(base: &str) -> String {
    let mut b = base.trim();
    // Strip a leading `~` (both `~/foo` and bare `~`) so the path becomes
    // home-relative; the server resolves relative paths against $HOME.
    if let Some(rest) = b.strip_prefix('~') {
        b = rest.trim_start_matches('/');
    } else if let Some(rest) = b.strip_prefix("./") {
        b = rest;
    }
    let absolute = b.starts_with('/');
    let joined = b
        .split('/')
        .filter(|seg| !seg.is_empty())
        .collect::<Vec<_>>()
        .join("/");
    if absolute {
        format!("/{joined}")
    } else {
        joined
    }
}

/// Validate an object key exactly like the local backend: reject empty keys, NUL
/// bytes, absolute paths, and any non-normal (`.`/`..`/root/prefix) component so a
/// key can never escape `base`. Returns the key as a clean forward-slash string.
fn validate_key(key: &ObjectKey) -> Result<String> {
    let raw = key.as_str();
    if raw.is_empty() {
        return Err(StoreError::InvalidKey("empty key".into()));
    }
    if raw.contains('\0') {
        return Err(StoreError::InvalidKey("key contains NUL byte".into()));
    }
    let relative = Path::new(raw);
    if relative.is_absolute() {
        return Err(StoreError::InvalidKey(format!(
            "absolute key not allowed: {raw}"
        )));
    }
    for component in relative.components() {
        if !matches!(component, Component::Normal(_)) {
            return Err(StoreError::InvalidKey(format!(
                "disallowed path component in key: {raw}"
            )));
        }
    }
    // Re-emit with forward slashes (the remote is always Unix), collapsing any
    // empty segments that a doubled slash would introduce.
    Ok(raw
        .split('/')
        .filter(|seg| !seg.is_empty())
        .collect::<Vec<_>>()
        .join("/"))
}

/// Map an object key to its full remote path `base/<key>`.
///
/// `base` is taken as already produced by [`normalize_base`]. The key is validated
/// (no traversal) before being appended.
pub(super) fn remote_path(base: &str, key: &ObjectKey) -> Result<String> {
    let key = validate_key(key)?;
    Ok(join(base, &key))
}

/// Join a normalized base with a relative sub-path using a single forward slash.
/// An empty `base` yields the sub-path unchanged (home-relative).
#[must_use]
pub(super) fn join(base: &str, rel: &str) -> String {
    match (base.is_empty(), rel.is_empty()) {
        (true, _) => rel.to_string(),
        (false, true) => base.to_string(),
        (false, false) => format!("{base}/{rel}"),
    }
}

/// The ancestor directories of a remote **file** path, shortest-first, so a caller
/// can `mkdir` each in order to realize `mkdir -p` on the parent.
///
/// The final component (the file itself) and the filesystem root are excluded. For
/// an absolute path the entries keep their leading `/`.
///
/// - `"a/b/c/obj"` → `["a", "a/b", "a/b/c"]`
/// - `"/home/u/x/obj"` → `["/home", "/home/u", "/home/u/x"]`
/// - `"obj"` → `[]`
#[must_use]
pub(super) fn ancestor_dirs(path: &str) -> Vec<String> {
    let absolute = path.starts_with('/');
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if segs.len() <= 1 {
        return Vec::new();
    }
    // All segments except the last (the file name) are directories to create.
    let dirs = &segs[..segs.len() - 1];
    let mut out = Vec::with_capacity(dirs.len());
    let mut acc = String::new();
    for seg in dirs {
        if acc.is_empty() {
            acc = if absolute {
                format!("/{seg}")
            } else {
                (*seg).to_string()
            };
        } else {
            acc = format!("{acc}/{seg}");
        }
        out.push(acc.clone());
    }
    out
}

/// A unique staging sibling for the atomic write, in the object's own directory.
///
/// The naming rule lives in [`crate::staging`] and is shared with the local
/// backend. It deliberately carries no trace of the object being staged: the old
/// spelling appended a suffix to the *filename*, so a 245-byte name exceeded
/// `NAME_MAX` as a staging file while being perfectly legal as a final one — and
/// the cutoff moved with the process id's digit count, so the same backup failed
/// on some nights and not others.
#[must_use]
pub(super) fn temp_path(final_path: &str) -> String {
    crate::staging::staging_sibling_remote(final_path)
}

/// A single bounded transfer span: a byte `offset` and `len`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ChunkSpan {
    pub offset: u64,
    pub len: u64,
}

/// Split a `total`-byte transfer into contiguous spans of at most `chunk` bytes.
///
/// Every span is exactly `chunk` bytes except the last, which carries the
/// remainder. A `total` of zero yields no spans; `chunk` is clamped to at least 1
/// so the function always terminates. This bounds both the streaming upload and
/// download to `O(chunk)` memory regardless of object size.
#[must_use]
pub(super) fn chunk_spans(total: u64, chunk: u64) -> Vec<ChunkSpan> {
    let chunk = chunk.max(1);
    let mut spans = Vec::new();
    let mut offset = 0u64;
    while offset < total {
        let len = chunk.min(total - offset);
        spans.push(ChunkSpan { offset, len });
        offset += len;
    }
    spans
}

/// The directory portion of a listing `prefix` — everything up to (not including)
/// the last `/`. Used to root the recursive walk at `base/<prefix-dir>` instead of
/// scanning the whole tree. `"p/00"` → `"p"`, `"p/"` → `"p"`, `"obj"` → `""`.
#[must_use]
pub(super) fn prefix_dir(prefix: &str) -> &str {
    match prefix.rfind('/') {
        Some(i) => &prefix[..i],
        None => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_base_strips_tilde_to_home_relative() {
        assert_eq!(normalize_base("~/dctl-sftp-livetest"), "dctl-sftp-livetest");
        assert_eq!(normalize_base("~"), "");
        assert_eq!(normalize_base("~/a/b/"), "a/b");
        assert_eq!(normalize_base("./scratch"), "scratch");
    }

    #[test]
    fn normalize_base_keeps_absolute_and_collapses_slashes() {
        assert_eq!(normalize_base("/srv//dctl/"), "/srv/dctl");
        assert_eq!(normalize_base("/mnt/data"), "/mnt/data");
        assert_eq!(normalize_base("rel//path//"), "rel/path");
    }

    #[test]
    fn remote_path_appends_key_under_base() {
        let base = normalize_base("~/store");
        assert_eq!(
            remote_path(&base, &ObjectKey::new("a/b/obj.bin")).unwrap(),
            "store/a/b/obj.bin"
        );
        let abs = normalize_base("/srv/store");
        assert_eq!(
            remote_path(&abs, &ObjectKey::new("obj")).unwrap(),
            "/srv/store/obj"
        );
    }

    #[test]
    fn remote_path_with_empty_base_is_home_relative() {
        let base = normalize_base("~");
        assert_eq!(remote_path(&base, &ObjectKey::new("x/y")).unwrap(), "x/y");
    }

    #[test]
    fn remote_path_rejects_traversal_and_bad_keys() {
        let base = normalize_base("/srv");
        assert!(matches!(
            remote_path(&base, &ObjectKey::new("../escape")),
            Err(StoreError::InvalidKey(_))
        ));
        assert!(matches!(
            remote_path(&base, &ObjectKey::new("/abs")),
            Err(StoreError::InvalidKey(_))
        ));
        assert!(matches!(
            remote_path(&base, &ObjectKey::new("")),
            Err(StoreError::InvalidKey(_))
        ));
        assert!(matches!(
            remote_path(&base, &ObjectKey::new("a/../b")),
            Err(StoreError::InvalidKey(_))
        ));
    }

    #[test]
    fn ancestor_dirs_relative() {
        assert_eq!(
            ancestor_dirs("a/b/c/obj"),
            vec!["a".to_string(), "a/b".to_string(), "a/b/c".to_string()]
        );
        assert!(ancestor_dirs("obj").is_empty());
        assert_eq!(ancestor_dirs("dir/obj"), vec!["dir".to_string()]);
    }

    #[test]
    fn ancestor_dirs_absolute_keeps_leading_slash() {
        assert_eq!(
            ancestor_dirs("/home/u/x/obj"),
            vec![
                "/home".to_string(),
                "/home/u".to_string(),
                "/home/u/x".to_string()
            ]
        );
    }

    #[test]
    fn chunk_spans_cover_total_exactly() {
        let spans = chunk_spans(250, 100);
        assert_eq!(
            spans,
            vec![
                ChunkSpan {
                    offset: 0,
                    len: 100
                },
                ChunkSpan {
                    offset: 100,
                    len: 100
                },
                ChunkSpan {
                    offset: 200,
                    len: 50
                },
            ]
        );
        // Contiguous, no gaps, sum to total.
        assert_eq!(spans.iter().map(|s| s.len).sum::<u64>(), 250);
    }

    #[test]
    fn chunk_spans_edge_cases() {
        assert!(chunk_spans(0, 100).is_empty());
        assert_eq!(
            chunk_spans(100, 100),
            vec![ChunkSpan {
                offset: 0,
                len: 100
            }]
        );
        // Degenerate chunk size is clamped, so the call still terminates.
        assert_eq!(chunk_spans(3, 0).len(), 3);
    }

    #[test]
    fn prefix_dir_extracts_directory_portion() {
        assert_eq!(prefix_dir("p/00"), "p");
        assert_eq!(prefix_dir("p/"), "p");
        assert_eq!(prefix_dir("p/a/b"), "p/a");
        assert_eq!(prefix_dir("obj"), "");
        assert_eq!(prefix_dir(""), "");
    }

    #[test]
    fn temp_path_is_unique_and_sibling() {
        let a = temp_path("dir/obj.bin");
        let b = temp_path("dir/obj.bin");
        assert_ne!(a, b, "temp paths must be unique per call");
        assert!(
            a.starts_with("dir/"),
            "the rename must stay in one directory"
        );
        // Recognised by the one shared rule, and carrying nothing of the object
        // it stages — which is what stops a long filename from being
        // un-storable and what stops a real `.tmp.` file from being hidden.
        assert!(crate::staging::is_staging_name(
            a.rsplit('/').next().unwrap_or_default()
        ));
        assert!(!a.contains("obj.bin"));
    }
}

/// Turn everything a recursive walk found into one page of a listing.
///
/// Split from the walk because this is where a listing goes quietly wrong.
/// The walk's failure modes are loud — a connection drops, a directory is
/// unreadable — while every mistake available here produces a **plausible page
/// that is missing objects**: an off-by-one at the cursor drops one object per
/// page, an inclusive partition repeats one, a `next_cursor` that is never `None`
/// loops forever and one that is always `None` lists the first page of a million.
/// A transfer then reports success over the subset it was shown.
///
/// The pieces:
///
/// * `found` is `(key, size, modified_unix)` for every file under the prefix's
///   *directory*, which is as narrowly as SFTP can be asked to walk.
/// * `prefix` filters exactly, because `p/00` and `p/000` share a directory.
/// * `cursor` is the last key of the previous page, so the next one starts
///   strictly after it — `partition_point` on `<=`, never on `<`.
/// * `next_cursor` is `Some` only when objects remain, which is what stops the
///   walk.
///
/// Sorted before paging: the cursor is a position in an order, and a walk that
/// returned directories in readdir order would give a different one each run.
#[must_use]
pub(super) fn page(
    mut found: Vec<(String, u64, Option<i64>)>,
    prefix: &str,
    cursor: Option<&str>,
    page_size: usize,
    links: crate::links::LinkReport,
) -> Page {
    found.retain(|(key, _, _)| key.starts_with(prefix));
    found.sort_by(|a, b| a.0.cmp(&b.0));

    let start = match cursor {
        Some(after) => found.partition_point(|(key, _, _)| key.as_str() <= after),
        None => 0,
    };
    let end = (start + page_size).min(found.len());
    let items = found[start..end]
        .iter()
        .map(|(key, size, modified_unix)| ObjectMeta {
            key: ObjectKey::new(key.clone()),
            size: *size,
            modified_unix: *modified_unix,
        })
        .collect();
    let next_cursor = if end < found.len() {
        found.get(end - 1).map(|(key, _, _)| key.clone())
    } else {
        None
    };
    Page {
        items,
        next_cursor,
        links,
    }
}

#[cfg(test)]
mod page_tests {
    use super::*;
    use crate::links::LinkReport;

    fn found(keys: &[&str]) -> Vec<(String, u64, Option<i64>)> {
        keys.iter()
            .enumerate()
            .map(|(n, key)| ((*key).to_string(), n as u64, Some(n as i64)))
            .collect()
    }

    fn keys(page: &Page) -> Vec<String> {
        page.items
            .iter()
            .map(|meta| meta.key.as_str().to_string())
            .collect()
    }

    /// Walking a listing to its end must see every object exactly once.
    ///
    /// The property the whole cursor exists for, and one that was only ever
    /// checked against a live `sshd` — `tests/sftp_live.rs`, which is `#[ignore]`d
    /// and needs `DCTL_SFTP_HOST`, so `cargo test --workspace` proved nothing
    /// about it. A page size of two over five objects is the smallest fixture
    /// that catches both an off-by-one that drops and one that repeats.
    #[test]
    fn paging_to_the_end_yields_every_object_once_and_in_order() {
        let all = ["a", "b", "c", "d", "e"];
        let mut seen = Vec::new();
        let mut cursor: Option<String> = None;
        let mut pages = 0;
        loop {
            let page = page(found(&all), "", cursor.as_deref(), 2, LinkReport::default());
            seen.extend(keys(&page));
            pages += 1;
            assert!(pages < 10, "the walk did not terminate: {seen:?}");
            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        assert_eq!(seen, all, "every object, once, in order");
        assert_eq!(pages, 3, "5 objects at 2 per page");
    }

    #[test]
    fn a_page_carries_the_size_and_time_the_walk_found() {
        // The listing is what a transfer compares against, so an entry that
        // dropped its modification time would make `sync` re-transfer that file
        // on every run.
        let page = page(found(&["a", "b"]), "", None, 10, LinkReport::default());
        assert_eq!(page.items[1].size, 1);
        assert_eq!(page.items[1].modified_unix, Some(1));
    }

    #[test]
    fn the_prefix_filters_exactly_rather_than_by_directory() {
        // `p/00` and `p/000` live in the same directory, so the walk brings back
        // both and only this can tell them apart.
        let page = page(
            found(&["p/00", "p/000", "p/01", "q/00"]),
            "p/00",
            None,
            10,
            LinkReport::default(),
        );
        assert_eq!(keys(&page), vec!["p/00", "p/000"]);
    }

    #[test]
    fn a_final_page_reports_no_cursor() {
        // A cursor that is always `Some` makes the caller loop forever; one that
        // is always `None` lists the first page of a million objects and reports
        // success over the rest.
        assert_eq!(
            page(found(&["a", "b"]), "", None, 2, LinkReport::default()).next_cursor,
            None
        );
        assert_eq!(
            page(found(&["a", "b", "c"]), "", None, 2, LinkReport::default()).next_cursor,
            Some("b".to_string())
        );
    }

    #[test]
    fn a_cursor_past_the_end_yields_an_empty_final_page() {
        let page = page(found(&["a", "b"]), "", Some("z"), 2, LinkReport::default());
        assert!(page.items.is_empty());
        assert_eq!(page.next_cursor, None);
    }

    #[test]
    fn an_empty_walk_is_an_empty_page() {
        let page = page(Vec::new(), "anything/", None, 10, LinkReport::default());
        assert!(page.items.is_empty());
        assert_eq!(page.next_cursor, None);
    }

    #[test]
    fn a_page_is_sorted_however_the_walk_found_things() {
        // The cursor is a position in an order; readdir has none.
        let page = page(found(&["c", "a", "b"]), "", None, 10, LinkReport::default());
        assert_eq!(keys(&page), vec!["a", "b", "c"]);
    }
}
