//! Metadata, existence, and paginated tree listing.
//!
//! # Why `head` and `exists` resolve a link and the listing does not
//!
//! They are answering different questions. A key handed to [`head`] is a path
//! *somebody named*; a link met inside [`list_page`]'s walk is one the walk
//! found. DCTL applies that distinction everywhere — a root the operator typed
//! is always resolved, links discovered below it obey
//! [`LinkPolicy`](crate::links::LinkPolicy) — and conflating the two is how a
//! symlinked source root produced an empty listing with `exists = true`, which
//! `sync --force` read as permission to delete a destination.

use crate::error::{Result, StoreError};
use crate::links::LinkReport;
use crate::model::{ObjectKey, ObjectMeta, Page};

use super::LocalFs;

/// Objects returned per `list_page` call.
const PAGE_SIZE: usize = 1000;

pub(super) async fn head(fs: &LocalFs, key: &ObjectKey) -> Result<ObjectMeta> {
    let path = fs.resolve(key)?;
    match tokio::fs::metadata(&path).await {
        Ok(md) if md.is_file() => Ok(ObjectMeta {
            key: key.clone(),
            size: md.len(),
            modified_unix: modified_unix(&md),
        }),
        Ok(_) => Err(StoreError::NotFound(key.to_string())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(StoreError::NotFound(key.to_string()))
        }
        Err(e) => Err(e.into()),
    }
}

pub(super) async fn exists(fs: &LocalFs, key: &ObjectKey) -> Result<bool> {
    let path = fs.resolve(key)?;
    match tokio::fs::metadata(&path).await {
        Ok(md) => Ok(md.is_file()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

pub(super) async fn list_page(fs: &LocalFs, prefix: &str, cursor: Option<String>) -> Result<Page> {
    let walked = super::tree::collect(fs.root(), fs.links()).await?;
    let mut keys = walked.keys;
    keys.retain(|k| k.starts_with(prefix));
    keys.sort();

    // Items strictly after the cursor (the last key returned previously).
    let start = match &cursor {
        Some(c) => keys.partition_point(|k| k.as_str() <= c.as_str()),
        None => 0,
    };
    let end = (start + PAGE_SIZE).min(keys.len());

    let mut items = Vec::with_capacity(end - start);
    for key_str in &keys[start..end] {
        let md = tokio::fs::metadata(fs.root().join(key_str)).await?;
        items.push(ObjectMeta {
            key: ObjectKey::new(key_str.clone()),
            size: md.len(),
            modified_unix: modified_unix(&md),
        });
    }

    let next_cursor = if end < keys.len() {
        keys.get(end - 1).cloned()
    } else {
        None
    };

    // The report describes the *walk*, and this backend re-walks the whole tree
    // for every page (`HANDOVER.md` §9.3 item 10). Attaching it to each page
    // would therefore multiply one tree's links by the number of pages and tell
    // the operator a number that is simply wrong. It rides on the first page —
    // the one request every listing makes — and the continuations carry an empty
    // report, which merges into the total without changing it.
    let links = if cursor.is_none() {
        walked.links
    } else {
        LinkReport::default()
    };

    Ok(Page {
        items,
        next_cursor,
        links,
    })
}

fn modified_unix(md: &std::fs::Metadata) -> Option<i64> {
    md.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
}
