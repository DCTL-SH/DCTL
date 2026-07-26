//! Metadata, existence, and paginated tree listing.

use std::path::Path;

use crate::error::{Result, StoreError};
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
    let mut keys = collect_keys(fs.root()).await?;
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
    Ok(Page { items, next_cursor })
}

/// Iteratively walk `root`, returning forward-slash-relative keys of regular
/// files (skipping in-flight temp files). Iterative (stack-based) to avoid async
/// recursion.
async fn collect_keys(root: &Path) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let mut entries = match tokio::fs::read_dir(&dir).await {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        while let Some(entry) = entries.next_entry().await? {
            let file_type = entry.file_type().await?;
            let path = entry.path();
            if file_type.is_dir() {
                stack.push(path);
            } else if file_type.is_file() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if name.contains(".tmp.") {
                        continue; // in-flight verified-write temp file
                    }
                }
                if let Ok(rel) = path.strip_prefix(root) {
                    out.push(rel.to_string_lossy().replace('\\', "/"));
                }
            }
        }
    }
    Ok(out)
}

fn modified_unix(md: &std::fs::Metadata) -> Option<i64> {
    md.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
}
