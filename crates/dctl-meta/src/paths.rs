//! Every path DCTL writes to, rooted in one directory.
//!
//! `~/.dctl` holds the configuration, the encrypted indexes, the audit log and
//! the cache. One directory, identical on macOS, Linux and Windows.
//!
//! ## Why not the platform-native directories
//!
//! The obvious alternative — XDG on Linux, `Application Support` on macOS,
//! `%APPDATA%` on Windows — is what a *desktop application* should do, and it is
//! what this module used to do. It is wrong for this tool, for one reason that
//! outweighs convention:
//!
//! **What DCTL keeps here is recovery metadata.** The index maps logical paths
//! to opaque object keys; the config says which remote holds which vault; the
//! audit log is the record of what happened. A user backing up "the DCTL state"
//! before rebuilding a machine has to be able to find all of it, and scattering
//! it across `~/.config`, `~/.local/share` and `~/.cache` — three different
//! places on Linux, three *differently named* places on macOS, and different
//! ones again on Windows — turns that into research. A backup tool whose own
//! state is hard to back up has an obvious problem.
//!
//! The same argument makes the layout identical across platforms rather than
//! merely single-rooted: a runbook that says `~/.dctl/config.toml` is true
//! everywhere, and an operator moving between a Mac laptop and a Linux server
//! does not have to relearn where anything lives. `~/.ssh`, `~/.aws` and
//! `~/.docker` made the same trade for the same reason.
//!
//! Nothing here is secret. The configuration holds no credentials by design
//! (`PLAN.md` §14), the index is AEAD-encrypted, and the cache is encrypted at
//! rest. The directory is still created `0700` on Unix, because the *set* of
//! remote names and vault paths is reconnaissance even when the contents are not.
//!
//! ## Overriding it
//!
//! `DCTL_HOME` relocates the whole tree — one variable, so a test, a container
//! or a second isolated profile moves everything together and cannot end up
//! half in one place and half in another.

use std::path::PathBuf;

use crate::identity::{BINARY_NAME, env_var};

/// Name of the home directory, without the leading dot.
const HOME_DIR_STEM: &str = BINARY_NAME;

/// Environment variable that relocates the entire tree.
const HOME_ENV_SETTING: &str = "HOME";

/// Config file name inside [`home_dir`].
pub const CONFIG_FILE_NAME: &str = "config.toml";

/// Subdirectory holding the encrypted per-vault indexes.
const INDEX_SUBDIR: &str = "index";

/// Subdirectory holding the encrypted chunk cache.
const CACHE_SUBDIR: &str = "cache";

/// Subdirectory holding the tamper-evident audit logs.
const AUDIT_SUBDIR: &str = "audit";

/// Subdirectory holding log files written with `--log-file`.
const LOGS_SUBDIR: &str = "logs";

/// Permissions for the home directory on Unix.
///
/// Owner-only. The contents are encrypted or non-secret by design, but the
/// *names* — which remotes exist, which buckets they point at, which vaults a
/// machine can reach — are worth keeping to the owner.
#[cfg(unix)]
pub const HOME_DIR_MODE: u32 = 0o700;

/// The root of everything DCTL writes: `~/.dctl`, or `$DCTL_HOME`.
///
/// Falls back to `./.dctl` when there is no home directory at all — a container
/// with no `HOME`, or a daemon started with an empty environment. Writing into
/// the working directory is a poor default, but it is a *visible* one, and it
/// beats failing to start or silently writing to `/`.
#[must_use]
pub fn home_dir() -> PathBuf {
    resolve_home(
        std::env::var_os(env_var(HOME_ENV_SETTING)).map(PathBuf::from),
        std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(PathBuf::from),
    )
}

/// The home-resolution rule, with its inputs passed in.
///
/// Separated from the environment lookup so the precedence can be tested
/// exhaustively without mutating process-global state. `dctl-meta` carries
/// `#![forbid(unsafe_code)]`, and setting an environment variable in a test is
/// `unsafe` on this edition — which is the language pointing out, correctly,
/// that a test which mutates the environment is not isolated from whatever runs
/// beside it. Making the rule a pure function is the better answer than an
/// exemption.
fn resolve_home(override_home: Option<PathBuf>, user_home: Option<PathBuf>) -> PathBuf {
    let non_empty = |path: PathBuf| (!path.as_os_str().is_empty()).then_some(path);

    if let Some(explicit) = override_home.and_then(non_empty) {
        return explicit;
    }
    user_home.and_then(non_empty).map_or_else(
        || PathBuf::from(dotted_name()),
        |home| home.join(dotted_name()),
    )
}

/// `.dctl` — the directory name, derived from the binary name so a rebrand
/// moves it (`dctl-meta` owns branding; see [`crate::identity`]).
fn dotted_name() -> String {
    format!(".{HOME_DIR_STEM}")
}

/// Where the configuration file lives. The home directory itself, so
/// `~/.dctl/config.toml` is the whole answer to "where is my config".
#[must_use]
pub fn config_dir() -> PathBuf {
    home_dir()
}

/// The configuration file: `~/.dctl/config.toml`.
#[must_use]
pub fn config_file() -> PathBuf {
    home_dir().join(CONFIG_FILE_NAME)
}

/// Encrypted indexes: `~/.dctl/index`.
#[must_use]
pub fn data_dir() -> PathBuf {
    home_dir().join(INDEX_SUBDIR)
}

/// Encrypted chunk cache: `~/.dctl/cache`.
///
/// Separate from the index because it is the one directory here that is
/// genuinely disposable — deleting it costs a re-fetch and nothing else.
#[must_use]
pub fn cache_dir() -> PathBuf {
    home_dir().join(CACHE_SUBDIR)
}

/// Tamper-evident audit logs: `~/.dctl/audit`.
#[must_use]
pub fn audit_dir() -> PathBuf {
    home_dir().join(AUDIT_SUBDIR)
}

/// Log files written with `--log-file`: `~/.dctl/logs`.
#[must_use]
pub fn logs_dir() -> PathBuf {
    home_dir().join(LOGS_SUBDIR)
}

/// Every directory the tool expects to exist, relative to `root`.
///
/// Takes the root rather than reading the environment so a caller can ask
/// "where would this profile put things" without changing the process, and so
/// the set is testable directly.
#[must_use]
pub fn all_dirs_under(root: &std::path::Path) -> Vec<PathBuf> {
    vec![
        root.to_path_buf(),
        root.join(INDEX_SUBDIR),
        root.join(CACHE_SUBDIR),
        root.join(AUDIT_SUBDIR),
        root.join(LOGS_SUBDIR),
    ]
}

/// Every directory the tool expects to exist.
///
/// Returned rather than created: this crate is deliberately I/O-free, so path
/// resolution stays unit-testable and a `--dry-run` can print where things would
/// go without creating anything.
#[must_use]
pub fn all_dirs() -> Vec<PathBuf> {
    all_dirs_under(&home_dir())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> PathBuf {
        PathBuf::from(s)
    }

    #[test]
    fn the_override_wins_over_the_users_home() {
        // One variable moves everything, so a profile cannot end up half in one
        // place and half in another.
        let home = resolve_home(Some(p("/srv/profile")), Some(p("/Users/example")));
        assert_eq!(home, p("/srv/profile"));
    }

    #[test]
    fn without_an_override_it_is_a_dotted_directory_in_the_users_home() {
        let home = resolve_home(None, Some(p("/Users/example")));
        assert_eq!(home, p("/Users/example").join(format!(".{BINARY_NAME}")));
    }

    #[test]
    fn a_missing_home_still_yields_a_visible_path() {
        // A container with no HOME must not write to `/` or fail to start.
        assert_eq!(resolve_home(None, None), p(&format!(".{BINARY_NAME}")));
    }

    #[test]
    fn an_empty_value_is_not_a_home() {
        // `DCTL_HOME=` and `HOME=` are both "unset" for this purpose; treating
        // an empty string as a root would put the tree at the filesystem root.
        assert_eq!(
            resolve_home(Some(p("")), Some(p("/Users/example"))),
            p("/Users/example").join(format!(".{BINARY_NAME}"))
        );
        assert_eq!(
            resolve_home(Some(p("")), Some(p(""))),
            p(&format!(".{BINARY_NAME}"))
        );
    }

    #[test]
    fn everything_lives_under_one_root() {
        let root = p("/srv/profile");
        for path in all_dirs_under(&root) {
            assert!(
                path.starts_with(&root),
                "{} escaped the home directory",
                path.display()
            );
        }
    }

    #[test]
    fn the_layout_is_identical_on_every_platform() {
        // The point of the module: a runbook saying `~/.dctl/config.toml` is
        // true everywhere, so nothing here may be `#[cfg]`-dependent.
        let root = p("/srv/profile");
        let dirs = all_dirs_under(&root);
        assert!(dirs[1].ends_with("index"));
        assert!(dirs[2].ends_with("cache"));
        assert!(dirs[3].ends_with("audit"));
        assert!(dirs[4].ends_with("logs"));
        assert_eq!(CONFIG_FILE_NAME, "config.toml");
    }

    #[test]
    fn the_directories_are_distinct() {
        let mut dirs = all_dirs_under(&p("/srv/profile"));
        let before = dirs.len();
        dirs.sort();
        dirs.dedup();
        assert_eq!(before, dirs.len(), "two directories collided");
    }

    #[test]
    fn the_home_name_follows_the_binary_name() {
        // A rebrand must move the directory with it.
        assert_eq!(dotted_name(), format!(".{BINARY_NAME}"));
    }
}
