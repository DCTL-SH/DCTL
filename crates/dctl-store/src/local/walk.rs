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
//!
//! # Why the two listings share their paging and not their selection
//!
//! [`list_page`] answers "what is stored?" and [`list_staging_page`] answers
//! "what did we abandon?". They are complementary selections over one walk
//! ([`Want`](crate::staging::Want)) and identical in every other respect, so the
//! cursor arithmetic — the part where a listing goes quietly wrong, dropping one
//! object per page or looping forever — is written once. A second copy of it for
//! the sweep would be a second place for `cleanup` to under-report, which is the
//! failure this whole method exists to end.

use crate::error::{Result, StoreError};
use crate::links::LinkReport;
use crate::model::{ObjectKey, ObjectMeta, Page};
use crate::specials::SpecialReport;
use crate::staging::{StagingListing, StagingPage, Want};

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
    let walked = super::tree::collect(fs.root(), fs.links(), Want::Objects).await?;
    let (items, next_cursor) = paginate(fs, walked.keys, prefix, cursor.as_deref()).await?;

    // The report describes the *walk*, and this backend re-walks the whole tree
    // for every page (`HANDOVER.md` §9.3 item 10). Attaching it to each page
    // would therefore multiply one tree's links by the number of pages and tell
    // the operator a number that is simply wrong. It rides on the first page —
    // the one request every listing makes — and the continuations carry an empty
    // report, which merges into the total without changing it.
    let (links, specials) = if cursor.is_none() {
        (walked.links, walked.specials)
    } else {
        (LinkReport::default(), SpecialReport::default())
    };

    Ok(Page {
        items,
        next_cursor,
        links,
        specials,
    })
}

/// One page of the debris an interrupted write left in this store.
///
/// The walk this listing is built from is the same walk the object listing uses,
/// with the staging predicate the other way up — see
/// [`Want`](crate::staging::Want). Links are walked under
/// [`LinkPolicy::Skip`](crate::links::LinkPolicy::Skip) rather than the
/// backend's own policy, deliberately and for two reasons: DCTL writes its
/// staging files directly into the store, never through a link, so following one
/// could only ever *leave* the store; and a sweep that followed a link out of the
/// store and deleted what it found there would be doing the single worst thing
/// this command could do.
///
/// No link or special-file report rides along. The object listing already
/// describes the tree, and an operator running `cleanup` after `ls` must not be
/// told the same four links twice as though there were eight.
pub(super) async fn list_staging_page(
    fs: &LocalFs,
    prefix: &str,
    cursor: Option<String>,
) -> Result<StagingListing> {
    let walked =
        super::tree::collect(fs.root(), crate::links::LinkPolicy::Skip, Want::Staging).await?;
    let (items, next_cursor) = paginate(fs, walked.keys, prefix, cursor.as_deref()).await?;
    Ok(StagingListing::Page(StagingPage { items, next_cursor }))
}

/// Filter, sort and cut one page out of a walk's keys.
///
/// Written once and shared by both listings, because this is where a listing
/// goes quietly wrong: an off-by-one at the cursor drops one object per page, an
/// inclusive partition repeats one, a `next_cursor` that is never `None` loops
/// forever and one that is always `None` lists the first page of a million.
///
/// A key that has vanished between the walk and the `stat` is dropped rather
/// than failing the page: something else deleted it, which for the object
/// listing is an object that is genuinely gone and for the sweep is debris
/// somebody else already reclaimed. Neither is this call's failure to report.
async fn paginate(
    fs: &LocalFs,
    mut keys: Vec<String>,
    prefix: &str,
    cursor: Option<&str>,
) -> Result<(Vec<ObjectMeta>, Option<String>)> {
    keys.retain(|k| k.starts_with(prefix));
    keys.sort();

    // Items strictly after the cursor (the last key returned previously).
    let start = match cursor {
        Some(c) => keys.partition_point(|k| k.as_str() <= c),
        None => 0,
    };
    let end = (start + PAGE_SIZE).min(keys.len());

    let mut items = Vec::with_capacity(end - start);
    for key_str in &keys[start..end] {
        let md = match tokio::fs::metadata(fs.root().join(key_str)).await {
            Ok(md) => md,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
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
    Ok((items, next_cursor))
}

fn modified_unix(md: &std::fs::Metadata) -> Option<i64> {
    md.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
}
