//! Platform-correct config/data/cache directories, derived from the identity.
//!
//! Uses OS conventions (XDG on Linux, Application Support on macOS, `%APPDATA%`
//! on Windows) via `directories`, with a local `./.<binary>` fallback for
//! headless or unusual environments so the tool always has somewhere to write.

use std::path::PathBuf;

use directories::ProjectDirs;

use crate::identity::BINARY_NAME;

/// Default config file name inside [`config_dir`].
pub const CONFIG_FILE_NAME: &str = "config.toml";

fn project_dirs() -> Option<ProjectDirs> {
    ProjectDirs::from("", "", BINARY_NAME)
}

fn fallback() -> PathBuf {
    PathBuf::from(format!(".{BINARY_NAME}"))
}

/// Config directory (e.g. `~/.config/dctl` on Linux).
#[must_use]
pub fn config_dir() -> PathBuf {
    project_dirs().map_or_else(fallback, |d| d.config_dir().to_path_buf())
}

/// Data directory (e.g. `~/.local/share/dctl` on Linux) — index, WAL, state.
#[must_use]
pub fn data_dir() -> PathBuf {
    project_dirs().map_or_else(fallback, |d| d.data_dir().to_path_buf())
}

/// Cache directory (e.g. `~/.cache/dctl` on Linux) — the encrypted VFS cache.
#[must_use]
pub fn cache_dir() -> PathBuf {
    project_dirs().map_or_else(fallback, |d| d.cache_dir().to_path_buf())
}

/// Default config file path: [`config_dir`]`/`[`CONFIG_FILE_NAME`].
#[must_use]
pub fn config_file() -> PathBuf {
    config_dir().join(CONFIG_FILE_NAME)
}
