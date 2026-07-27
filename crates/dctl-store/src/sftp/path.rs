//! Pure, network-free path and chunk-planning logic for the SFTP backend.
//!
//! Everything here is deterministic and unit-tested without a connection: how an
//! [`ObjectKey`] maps to a remote path under `base`, how a leading `~` in `base`
//! collapses to a home-relative path, which ancestor directories a `mkdir -p` must
//! create, and how a byte total splits into bounded transfer chunks.

use std::path::{Component, Path};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::{Result, StoreError};
use crate::model::ObjectKey;

/// Monotonic counter making temp filenames unique across concurrent writers in
/// this process. Combined with the PID it is unique across processes too.
static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Normalize a configured `base` into a remote path string with no trailing slash.
///
/// The openssh `sftp-server` resolves **relative** paths against its start
/// directory (the user's home), so a `base` of `~/foo`, `~foo`, or `./foo` all
/// collapse to the home-relative `foo`: SFTP itself never expands `~` (that needs
/// the optional `expand-path` extension), and sending a literal `~` would create a
/// directory *named* `~`. An **absolute** `base` (leading `/`) is kept verbatim.
/// Redundant slashes are collapsed and a trailing slash is trimmed.
#[must_use]
pub(super) fn normalize_base(base: &str) -> String {
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

/// A unique temp sibling path for the atomic-write staging file: `<final>.tmp.<pid>.<seq>`.
#[must_use]
pub(super) fn temp_path(final_path: &str) -> String {
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    format!("{final_path}.tmp.{pid}.{seq}")
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
        assert!(a.starts_with("dir/obj.bin.tmp."));
        // The listing walk skips these staging files by this marker.
        assert!(a.contains(".tmp."));
    }
}
