//! The recursive `readdir` that turns an SFTP subtree into object keys, and the
//! entries it used to drop.
//!
//! SFTP has no recursive listing, so this walks. What it walks *over* is the
//! part that mattered: a `SSH_FXP_READDIR` entry carries the attributes of
//! `lstat`, so a link's type is neither *file* nor *directory*, and the arm that
//! matched those two let every link fall through to a `_ => {}` that said
//! nothing. `/srv/data -> /mnt/bigdisk/data` is the canonical layout on exactly
//! the kind of host this backend exists to reach, and pointing DCTL at `/srv`
//! listed an empty tree.
//!
//! The same `_ => {}` swallowed every fifo, socket and device node too, and that
//! half outlived the link fix by a full pass: `ls sftp:/var` reported the files
//! and said nothing whatever about the sockets. Both are now [`observe`]d, and
//! there is no arm left that ends in silence.
//!
//! # What each policy costs on the wire
//!
//! [`LinkPolicy::Skip`] costs nothing: the link is counted from the directory
//! entry that has already arrived, and no request is made. Following costs one
//! `SSH_FXP_STAT` per link to learn what is behind it, plus one
//! `SSH_FXP_REALPATH` per link that turns out to be a directory — needed for the
//! cycle guard, since SFTP version 3's attribute set carries no inode and a
//! canonical path is the only identity the protocol offers. `in-tree` costs one
//! further `REALPATH` per link, to answer where it landed.
//!
//! Ordinary subdirectories cost nothing extra under any policy. Their canonical
//! path is their parent's plus their own name — they are not links, so there is
//! nothing for the server to resolve — and computing it here rather than asking
//! keeps the walk's request count where it was. A special file costs nothing
//! either: the type bits it is classified from arrived with the directory entry.

use openssh_sftp_client::Sftp;
use tokio_stream::StreamExt as _;

use crate::error::Result;
use crate::links::{Ancestors, DirId, LinkPolicy, LinkReport, LinkTarget, LinkVerdict, decide};
use crate::specials::{SpecialKind, SpecialReport};
use crate::staging::Want;

use std::sync::Arc;

use super::map_sftp_err;

/// One walk's findings: `(key, size, modified_unix)` per object, plus what was
/// passed over.
#[derive(Debug, Default)]
pub(super) struct Walked {
    pub found: Vec<(String, u64, Option<i64>)>,
    pub links: LinkReport,
    pub specials: SpecialReport,
}

/// A directory waiting to be read.
struct Pending {
    /// The path to open on the wire.
    open: String,
    /// The same directory in key space, relative to the backend's base.
    key: String,
    /// The chain of directories above it, or [`None`] when nothing is followed.
    ancestors: Option<Arc<Ancestors>>,
}

/// Walk the subtree at `open_root` under `policy`, collecting what `want`
/// selects.
///
/// `key_root` is the same directory expressed as a key prefix, carried
/// separately because the two spellings diverge: the wire path is absolute or
/// home-relative and the key is neither.
///
/// # Errors
/// Whatever the server reported, except that a missing directory is an empty
/// listing — a prefix with no objects under it is the ordinary negative answer,
/// not a failure.
pub(super) async fn collect(
    sftp: &Sftp,
    open_root: String,
    key_root: String,
    policy: LinkPolicy,
    want: Want,
) -> Result<Walked> {
    let mut walked = Walked::default();
    let mut fs = sftp.fs();

    // One request, and only when something will actually ask. It anchors both
    // the cycle chain and the `in-tree` confinement, so a failure to resolve it
    // means neither question can be answered — and following blind is exactly
    // what the loop protection is here to prevent.
    let root_canonical = if policy.follows() {
        match fs.canonicalize(&open_root).await {
            Ok(path) => Some(path.to_string_lossy().into_owned()),
            Err(error) => match map_sftp_err(&open_root, error) {
                crate::error::StoreError::NotFound(_) => return Ok(walked),
                other => return Err(other),
            },
        }
    } else {
        None
    };

    let ancestors = root_canonical
        .as_ref()
        .map(|path| Ancestors::root(DirId::Path(path.clone())));

    let mut stack = vec![Pending {
        open: open_root,
        key: key_root,
        ancestors,
    }];

    while let Some(Pending {
        open: open_dir,
        key: key_dir,
        ancestors,
    }) = stack.pop()
    {
        let dir = match fs.open_dir(&open_dir).await {
            Ok(d) => d,
            Err(e) => match map_sftp_err(&open_dir, e) {
                // A missing directory (e.g. the prefix has no objects) is an
                // empty listing, not an error.
                crate::error::StoreError::NotFound(_) => continue,
                other => return Err(other),
            },
        };
        let mut rd = Box::pin(dir.read_dir());
        while let Some(item) = rd.next().await {
            let entry = item.map_err(|e| map_sftp_err(&open_dir, e))?;
            let name = entry.filename().to_string_lossy().into_owned();
            if name == "." || name == ".." {
                continue;
            }
            let open_child = join_wire(&open_dir, &name);
            let key_child = join_key(&key_dir, &name);

            match entry.file_type() {
                Some(ft) if ft.is_symlink() => {
                    let followed = follow(
                        &mut walked,
                        &mut fs,
                        policy,
                        root_canonical.as_deref(),
                        ancestors.as_ref(),
                        &open_child,
                        key_child,
                        want,
                    )
                    .await?;
                    if let Some(chain) = followed {
                        stack.push(Pending {
                            open: open_child,
                            key: chain.0,
                            ancestors: chain.1,
                        });
                    }
                }
                Some(ft) if ft.is_dir() => stack.push(Pending {
                    open: open_child,
                    key: key_child,
                    // Not a link, so its canonical path is its parent's plus its
                    // own name and the server has nothing to resolve.
                    ancestors: ancestors.as_ref().map(|chain| {
                        chain.child(DirId::Path(join_wire(&canonical_of(chain), &name)))
                    }),
                }),
                Some(ft) if ft.is_file() => {
                    let md = entry.metadata();
                    emit(
                        &mut walked,
                        key_child,
                        md.len().unwrap_or(0),
                        md.modified().map(|t| t.as_duration().as_secs() as i64),
                        want,
                    );
                }
                // A device, socket or fifo. Nothing a transfer can carry, and
                // nothing this walk may pass over in silence — the classification
                // is the one pure rule in `crate::specials`, fed the type bits
                // that already arrived with the directory entry.
                Some(ft) => walked.specials.observe(
                    key_child,
                    SpecialKind::from_posix_mode(ft.as_raw() as u32)
                        .unwrap_or(SpecialKind::Unknown),
                ),
                // The server sent no permissions attribute, which is legal in
                // version 3 of the protocol and leaves the type unknowable.
                // Something is there, it was not listed, and saying so is the
                // whole point.
                None => walked.specials.observe(key_child, SpecialKind::Unknown),
            }
        }
    }

    Ok(walked)
}

/// Decide one link; on a decision to descend, return the child's key and chain.
///
/// Returning the pieces rather than pushing the stack itself keeps the wire path
/// — which the caller still owns — out of this function's signature twice.
#[allow(clippy::too_many_arguments)]
async fn follow(
    walked: &mut Walked,
    fs: &mut openssh_sftp_client::fs::Fs,
    policy: LinkPolicy,
    root_canonical: Option<&str>,
    ancestors: Option<&Arc<Ancestors>>,
    open_child: &str,
    key_child: String,
    want: Want,
) -> Result<Option<(String, Option<Arc<Ancestors>>)>> {
    if !policy.follows() {
        walked
            .links
            .observe(key_child, decide(policy, LinkTarget::Unread));
        return Ok(None);
    }

    // `metadata` is `SSH_FXP_STAT`, which follows: the first and only look
    // behind the link, answering both "is anything there" and "is it a
    // directory".
    let Ok(target) = fs.metadata(open_child).await else {
        walked
            .links
            .observe(key_child, decide(policy, LinkTarget::Missing));
        return Ok(None);
    };

    let is_dir = target.file_type().is_some_and(|ft| ft.is_dir());
    let is_file = target.file_type().is_some_and(|ft| ft.is_file());

    // Where it landed. Needed for the confinement question under `in-tree`, and
    // for the cycle guard whenever the target is a directory.
    let resolved = if policy.confined() || is_dir {
        match fs.canonicalize(open_child).await {
            Ok(path) => Some(path.to_string_lossy().into_owned()),
            Err(_) => None,
        }
    } else {
        None
    };

    let landed = if policy.confined() {
        match (&resolved, root_canonical) {
            (Some(path), Some(base)) if under(path, base) => LinkTarget::Inside,
            (Some(_), Some(_)) => LinkTarget::Outside,
            // Nothing resolved it, so nothing can say it stayed in the tree.
            // Refusing is the conservative direction here: the alternative is
            // pulling in a path nobody could name.
            _ => LinkTarget::Missing,
        }
    } else {
        LinkTarget::Inside
    };

    let verdict = decide(policy, landed);
    if !verdict.followed() {
        walked.links.observe(key_child, verdict);
        return Ok(None);
    }

    if is_dir {
        let Some(canonical) = resolved else {
            // A directory whose identity the server would not give up cannot be
            // guarded against a cycle, and a walk that followed it anyway is the
            // one that never finishes.
            walked.links.observe(key_child, LinkVerdict::Broken);
            return Ok(None);
        };
        let id = DirId::Path(canonical);
        if ancestors.is_some_and(|chain| chain.contains(&id)) {
            walked.links.observe(key_child, LinkVerdict::Cycle);
            return Ok(None);
        }
        walked
            .links
            .observe(key_child.clone(), LinkVerdict::Followed);
        return Ok(Some((key_child, ancestors.map(|chain| chain.child(id)))));
    }

    if is_file {
        walked
            .links
            .observe(key_child.clone(), LinkVerdict::Followed);
        emit(
            walked,
            key_child,
            target.len().unwrap_or(0),
            target.modified().map(|t| t.as_duration().as_secs() as i64),
            want,
        );
    } else {
        // A link followed to a fifo, socket or device node. Reported as a link
        // verdict rather than as a special file, for the reason the local walk
        // gives: what the operator can act on is the link, which is in the tree
        // and has a name to exclude.
        walked.links.observe(key_child, LinkVerdict::NotStorable);
    }
    Ok(None)
}

/// Add one object, if it is the kind of file this walk was asked for.
///
/// One rule, one implementation, in [`crate::staging`]: a prefix test on the
/// file's own name, and the two selections are exact complements of it. The
/// substring test this replaced hid every object whose name contained `.tmp.`
/// from `ls`, `size`, `scrub`, `copy`, `sync` and `purge` alike — and the
/// listing that dropped staging files was the only listing `cleanup` had, so a
/// sweep of abandoned uploads searched a list they had already been removed
/// from and reported that there were none.
fn emit(walked: &mut Walked, key: String, size: u64, modified_unix: Option<i64>, want: Want) {
    if want.keeps(&key) {
        walked.found.push((key, size, modified_unix));
    }
}

/// The canonical path a chain node stands for, or `""` when it holds none.
///
/// Only ever called on a chain built from [`DirId::Path`] nodes, which is every
/// chain this backend builds — SFTP has no inode to offer.
fn canonical_of(chain: &Arc<Ancestors>) -> String {
    match chain.id() {
        DirId::Path(path) => path.clone(),
        DirId::Inode(_) => String::new(),
    }
}

/// Join a wire path and a child name, keeping a bare `.` from leaking into it.
fn join_wire(dir: &str, name: &str) -> String {
    if dir.is_empty() || dir == "." {
        name.to_string()
    } else {
        format!("{}/{name}", dir.trim_end_matches('/'))
    }
}

/// Join a key-space directory and a child name.
fn join_key(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_string()
    } else {
        format!("{dir}/{name}")
    }
}

/// Whether `path` lies at or under `base`, comparing **whole components**.
///
/// The byte-wise test would call `/srv-backup` a child of `/srv`, which is the
/// same mistake the prefix rule exists to prevent everywhere else in this
/// codebase — and here it would let a link out of the tree pass the confinement
/// check that was asked for precisely to stop it.
fn under(path: &str, base: &str) -> bool {
    let base = base.trim_end_matches('/');
    if base.is_empty() || base == "/" {
        return true;
    }
    path == base
        || path
            .strip_prefix(base)
            .is_some_and(|rest| rest.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wire_path_joins_without_a_leading_dot() {
        assert_eq!(join_wire(".", "a"), "a");
        assert_eq!(join_wire("", "a"), "a");
        assert_eq!(join_wire("/srv", "a"), "/srv/a");
        assert_eq!(join_wire("/srv/", "a"), "/srv/a");
    }

    #[test]
    fn a_key_joins_without_a_leading_separator() {
        assert_eq!(join_key("", "a"), "a");
        assert_eq!(join_key("p", "a"), "p/a");
    }

    #[test]
    fn confinement_compares_whole_components() {
        // `/srv-backup` is not inside `/srv`. A byte-wise `starts_with` would
        // say it is, and `in-tree` would admit exactly the link it was asked to
        // refuse.
        assert!(under("/srv/data", "/srv"));
        assert!(under("/srv", "/srv"));
        assert!(!under("/srv-backup/data", "/srv"));
        assert!(!under("/mnt/bigdisk", "/srv"));
    }

    #[test]
    fn everything_is_under_the_filesystem_root() {
        assert!(under("/anything", "/"));
    }

    #[test]
    fn an_in_flight_write_never_becomes_an_object() {
        let mut walked = Walked::default();
        emit(
            &mut walked,
            format!("d/{}42.1", crate::staging::STAGING_NAME_PREFIX),
            10,
            None,
            Want::Objects,
        );
        emit(&mut walked, "d/real.bin".into(), 10, None, Want::Objects);
        assert_eq!(walked.found.len(), 1);
        assert_eq!(walked.found[0].0, "d/real.bin");
    }

    #[test]
    fn the_staging_walk_returns_exactly_what_the_object_walk_omits() {
        // The two questions over one subtree, in the one place the sftp walk
        // decides them. A key in neither answer is what let `cleanup` report a
        // store clean while a killed upload's 12 MiB sat in it.
        let staged = format!("d/{}42.1", crate::staging::STAGING_NAME_PREFIX);
        let mut debris = Walked::default();
        emit(&mut debris, staged.clone(), 10, None, Want::Staging);
        emit(&mut debris, "d/real.bin".into(), 10, None, Want::Staging);
        assert_eq!(debris.found.len(), 1);
        assert_eq!(debris.found[0].0, staged);
    }
}
