//! Map an object key to a safe path under the backend root, rejecting traversal.

use std::path::{Component, Path, PathBuf};

use crate::error::{Result, StoreError};
use crate::model::ObjectKey;

/// Resolve `key` to a path under `root`. Rejects empty keys, NUL bytes, absolute
/// paths, and any `..`/root components so a key can never escape `root`.
pub(super) fn resolve(root: &Path, key: &ObjectKey) -> Result<PathBuf> {
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

    Ok(root.join(relative))
}
