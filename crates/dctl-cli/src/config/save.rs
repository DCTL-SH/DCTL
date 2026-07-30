//! Writing `config.toml` without ever leaving it half-written.
//!
//! The configuration is the file that says *where a user's data lives*. Losing
//! it does not lose the data — objects are self-describing (`PLAN.md` §13.1) —
//! but truncating it during a power cut turns a working installation into a
//! puzzle, and `dctl config` is exactly the command someone runs on a laptop
//! that is about to lose battery. So the write follows the same discipline
//! `PLAN.md` §6 requires of a local-filesystem destination: stage, fsync,
//! rename, fsync the directory. At no instant does the path hold a partial file.
//!
//! Three further rules come from §14 rather than §6:
//!
//! * **Validate before writing.** An atomic write that faithfully persists a
//!   vault cycle has done its job and produced a config no later run can load.
//!   The rules are applied here, so nothing invalid reaches disk.
//! * **Owner-only, from the moment the file exists.** The staging file is
//!   created with [`CONFIG_FILE_MODE`] and its mode is then forced, because
//!   `open(2)` masks the requested mode through the umask and leaves an
//!   already-existing file's mode alone. The directory is hardened too: a `0600`
//!   file inside a world-writable directory can still be replaced wholesale.
//! * **A header that states the contract.** Every generated file opens with the
//!   comment block in [`CONFIG_FILE_HEADER`] — the one piece of documentation
//!   that is guaranteed to be in front of someone at the moment they consider
//!   pasting a credential in.

use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::constants::{
    CONFIG_FILE_HEADER, CONFIG_FILE_NAME, CONFIG_TEMP_NAME_SEPARATOR, CONFIG_TEMP_SUFFIX,
};
use crate::logging::fields;

use super::error::{ConfigError, Result};
use super::model::Config;
use super::validate;

/// Render a configuration exactly as it is written to disk.
///
/// Separated from [`save`] because it is the whole of the file's *content* and
/// none of its I/O, which makes the header, the ordering and the round trip
/// testable without touching a filesystem. `dctl config show` can use it too, so
/// what is displayed and what is stored cannot diverge.
///
/// # Errors
/// [`ConfigError::Serialize`] when a value cannot be represented in TOML — in
/// practice, a local remote whose path is not valid UTF-8.
pub fn render(config: &Config) -> Result<String> {
    let body = toml::to_string_pretty(config)?;
    Ok(format!("{CONFIG_FILE_HEADER}\n{body}"))
}

/// Write `config` to `path`, atomically and owner-only.
///
/// The sequence is: validate, render, create the directory, stage the bytes into
/// a sibling temp file, fsync it, rename it over the target, fsync the
/// directory. A failure at any step leaves the previous configuration exactly as
/// it was, and the staging file is removed rather than left behind.
///
/// The rename is the commit point, and it is only atomic within one filesystem —
/// which is why the staging file is a sibling of the target and not something in
/// the system temp directory.
///
/// # Errors
/// Any rule [`validate`](super::validate::validate) enforces (checked *before*
/// anything is written), [`ConfigError::Serialize`] from [`render`], and
/// [`ConfigError::Write`] for any filesystem failure along the way.
pub fn save(config: &Config, path: &Path) -> Result<()> {
    // Refusing here is the difference between "the file could not be written"
    // and "the file was written and no future run can load it".
    validate::validate(config)?;
    let body = render(config)?;

    if let Some(directory) = parent_of(path) {
        prepare_directory(directory)?;
    }

    let staging = staging_path(path);
    if let Err(error) = stage(&staging, body.as_bytes()) {
        // Best effort: the write already failed, and the reason for *that* is
        // the error worth reporting.
        let _ = std::fs::remove_file(&staging);
        return Err(error);
    }

    if let Err(source) = std::fs::rename(&staging, path) {
        let _ = std::fs::remove_file(&staging);
        return Err(ConfigError::Write {
            path: path.to_path_buf(),
            source,
        });
    }

    // The rename is durable only once the directory entry is. Without this a
    // crash immediately after `save` returns can leave the *old* file in place,
    // which is precisely the "reported success, did not happen" outcome the
    // project refuses to produce.
    if let Some(directory) = parent_of(path) {
        sync_directory(directory)?;
    }

    Ok(())
}

/// The directory a file lives in, or `None` for a bare relative filename.
///
/// `Path::parent` returns `Some("")` for `config.toml`, which is the current
/// directory — real, but not something to create or fsync.
fn parent_of(path: &Path) -> Option<&Path> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
}

/// Name of the staging file for `path`.
///
/// `config.toml.4711.tmp`, beside the target. The process id is in the name so
/// two DCTL processes saving at once stage to different files and the loser of
/// the rename race simply loses, instead of the two interleaving into one
/// corrupt file.
fn staging_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new(CONFIG_FILE_NAME))
        .to_os_string();
    name.push(format!(
        "{CONFIG_TEMP_NAME_SEPARATOR}{}{CONFIG_TEMP_SUFFIX}",
        std::process::id()
    ));
    path.with_file_name(name)
}

/// Create the configuration directory and close it to everyone but its owner.
fn prepare_directory(directory: &Path) -> Result<()> {
    std::fs::create_dir_all(directory).map_err(|source| ConfigError::Write {
        path: directory.to_path_buf(),
        source,
    })?;
    harden_directory(directory)
}

/// Enforce [`crate::constants::CONFIG_DIR_MODE`] on the configuration directory.
///
/// A no-op on Windows, where access is an ACL rather than a mode and the profile
/// directory the configuration lives under is already owner-only.
#[cfg(unix)]
fn harden_directory(directory: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    use crate::constants::CONFIG_DIR_MODE;

    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(CONFIG_DIR_MODE)).map_err(
        |source| ConfigError::Write {
            path: directory.to_path_buf(),
            source,
        },
    )
}

/// See the Unix definition.
#[cfg(not(unix))]
fn harden_directory(_directory: &Path) -> Result<()> {
    Ok(())
}

/// Write `bytes` into a fresh owner-only staging file and make them durable.
fn stage(staging: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = create_staging_file(staging)?;

    file.write_all(bytes).map_err(|source| ConfigError::Write {
        path: staging.to_path_buf(),
        source,
    })?;
    file.flush().map_err(|source| ConfigError::Write {
        path: staging.to_path_buf(),
        source,
    })?;
    // The whole point of staging: the bytes must be on the medium *before* the
    // rename publishes them, or a crash can publish an empty file.
    file.sync_all().map_err(|source| ConfigError::Write {
        path: staging.to_path_buf(),
        source,
    })?;
    Ok(())
}

/// Create the staging file, exclusively and owner-only.
///
/// `create_new` means the file cannot be a symlink somebody planted, and cannot
/// be an existing file whose looser mode `create` would have preserved. A stale
/// staging file left by a hard-killed run with the same process id is cleared
/// once and retried — the name is derived from our own pid, so it is ours to
/// remove — and a second failure is reported rather than looped on.
fn create_staging_file(staging: &Path) -> Result<File> {
    match open_exclusive(staging) {
        Ok(file) => Ok(file),
        Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
            std::fs::remove_file(staging).map_err(|source| ConfigError::Write {
                path: staging.to_path_buf(),
                source,
            })?;
            open_exclusive(staging).map_err(|source| ConfigError::Write {
                path: staging.to_path_buf(),
                source,
            })
        }
        Err(source) => Err(ConfigError::Write {
            path: staging.to_path_buf(),
            source,
        }),
    }
}

/// `open(2)` with `O_CREAT | O_EXCL`, requesting owner-only permissions.
fn open_exclusive(staging: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        use crate::constants::CONFIG_FILE_MODE;

        options.mode(CONFIG_FILE_MODE);
    }

    let file = options.open(staging)?;

    // `open` masks the requested mode through the umask, so the file may have
    // come out *more* closed than asked for — or, under an unusual umask,
    // unreadable to its own owner. Force it.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        use crate::constants::CONFIG_FILE_MODE;

        file.set_permissions(std::fs::Permissions::from_mode(CONFIG_FILE_MODE))?;
    }

    Ok(file)
}

/// Make a directory entry durable.
///
/// A failure to *open* the directory is tolerated with a warning: some
/// filesystems (and Windows, where a directory is not an openable file at all)
/// simply do not support this, and turning an unsupported operation into a
/// failed save would break DCTL on those systems for no gain. A failure of the
/// fsync itself is propagated, because there the platform does support the
/// operation and is telling us the write is not durable.
fn sync_directory(directory: &Path) -> Result<()> {
    let Ok(handle) = File::open(directory) else {
        tracing::debug!(
            { fields::PATH } = %directory.display(),
            "cannot open the configuration directory to flush it; \
             the rename is visible but its durability is the filesystem's business"
        );
        return Ok(());
    };

    handle.sync_all().map_err(|source| ConfigError::Write {
        path: directory.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::load;
    use crate::config::model::{B2Def, LocalDef, RemoteDef, VaultDef};
    use std::path::PathBuf;

    fn populated() -> Config {
        let mut config = Config::default();
        config.insert(
            "b2prod",
            RemoteDef::B2(B2Def {
                bucket: "photos".into(),
                endpoint: None,
                chunk_size: Some(64 * 1024 * 1024),
                verify: None,
                require_vault: false,
            }),
        );
        config.insert(
            "disk",
            RemoteDef::Local(LocalDef {
                path: PathBuf::from("/srv/data"),
                verify: None,
                require_vault: false,
            }),
        );
        config.insert(
            "vault",
            RemoteDef::Vault(VaultDef {
                base: "b2prod".into(),
                // Deliberately unset: `config::validate` refuses a vault
                // subdirectory, because no layer applies one. A fixture carrying
                // it asserted that an inert setting survives a save, which is
                // what it used to do.
                base_path: None,
                chunk_size: Some(4 * 1024 * 1024),
                verify: Some(crate::cli::VerifyMode::Strict),
            }),
        );
        config
    }

    #[test]
    fn the_rendered_file_opens_with_the_no_secrets_header() {
        let text = render(&populated()).expect("must render");
        assert!(text.starts_with(CONFIG_FILE_HEADER), "got: {text}");
        assert!(text.contains("NON-SECRET"));
    }

    #[test]
    fn the_header_is_a_comment_and_does_not_disturb_parsing() {
        let original = populated();
        let text = render(&original).expect("must render");
        let parsed = load::parse(&text, Path::new("config.toml")).expect("must parse back");
        assert_eq!(parsed, original);
    }

    #[test]
    fn an_empty_configuration_still_gets_its_header() {
        let text = render(&Config::default()).expect("must render");
        assert!(text.contains("NON-SECRET"));
        assert!(
            load::parse(&text, Path::new("config.toml"))
                .expect("must parse")
                .is_empty()
        );
    }

    #[test]
    fn a_saved_file_loads_back_identically() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        let original = populated();

        save(&original, &path).expect("must save");
        assert_eq!(load::load(&path).expect("must load"), original);
    }

    #[test]
    fn saving_creates_the_configuration_directory() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("deep").join("nested").join("config.toml");

        save(&populated(), &path).expect("must save");
        assert!(path.is_file());
    }

    #[test]
    fn saving_twice_replaces_rather_than_appends() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");

        save(&populated(), &path).expect("first save");
        let mut second = Config::default();
        second.insert(
            "disk",
            RemoteDef::Local(LocalDef {
                path: PathBuf::from("/srv"),
                verify: None,
                require_vault: false,
            }),
        );
        save(&second, &path).expect("second save");

        let loaded = load::load(&path).expect("must load");
        assert_eq!(loaded, second);
        assert_eq!(loaded.len(), 1, "the first save must not survive");
    }

    #[test]
    fn no_staging_file_is_left_behind() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        save(&populated(), &path).expect("must save");

        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(std::result::Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(CONFIG_TEMP_SUFFIX))
            .collect();
        assert!(leftovers.is_empty(), "left behind: {leftovers:?}");
    }

    #[test]
    fn the_staging_name_is_a_sibling_of_the_target() {
        // rename(2) is atomic only within one filesystem, so the staging file
        // must not be somewhere like /tmp.
        let path = Path::new("/etc/dctl/config.toml");
        let staging = staging_path(path);
        assert_eq!(staging.parent(), path.parent());
        assert_ne!(staging, path);
        assert!(
            staging
                .to_string_lossy()
                .ends_with(&format!("{}{CONFIG_TEMP_SUFFIX}", std::process::id()))
        );
    }

    #[test]
    fn a_staging_name_survives_a_path_with_no_file_name() {
        // `Path::file_name` is None for a path ending in `..`; the fallback must
        // still produce a usable sibling rather than panicking.
        let staging = staging_path(Path::new("/etc/dctl/.."));
        assert!(staging.to_string_lossy().contains(CONFIG_FILE_NAME));
    }

    #[test]
    fn an_invalid_configuration_is_never_written() {
        // Persisting a cycle faithfully would produce a file that no later run
        // can load. The rules are applied before the bytes are.
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");

        let mut broken = Config::default();
        broken.insert(
            "vault",
            RemoteDef::Vault(VaultDef {
                base: "vault".into(),
                base_path: None,
                chunk_size: None,
                verify: None,
            }),
        );

        assert!(matches!(
            save(&broken, &path),
            Err(ConfigError::VaultCycle { .. })
        ));
        assert!(
            !path.exists(),
            "nothing may be written for an invalid config"
        );
    }

    #[test]
    fn a_failed_save_leaves_the_previous_configuration_intact() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        let good = populated();
        save(&good, &path).expect("must save");

        let mut broken = Config::default();
        broken.insert(
            "vault",
            RemoteDef::Vault(VaultDef {
                base: "missing".into(),
                base_path: None,
                chunk_size: None,
                verify: None,
            }),
        );
        assert!(save(&broken, &path).is_err());

        assert_eq!(
            load::load(&path).expect("the old file must still be there"),
            good
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_saved_file_is_owner_only_whatever_the_umask() {
        use std::os::unix::fs::PermissionsExt;

        use crate::constants::{CONFIG_DIR_MODE, CONFIG_FILE_EXPOSED_MODE_MASK, CONFIG_FILE_MODE};

        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("nested").join("config.toml");
        save(&populated(), &path).expect("must save");

        let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, CONFIG_FILE_MODE, "file mode is {mode:o}");
        assert_eq!(mode & CONFIG_FILE_EXPOSED_MODE_MASK, 0);
        // A 0600 file inside a world-writable directory is still replaceable.
        let dir_mode = std::fs::metadata(path.parent().expect("has a parent"))
            .expect("stat")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, CONFIG_DIR_MODE, "directory mode is {dir_mode:o}");
    }

    #[cfg(unix)]
    #[test]
    fn saving_over_a_loosened_file_tightens_it_again() {
        use std::os::unix::fs::PermissionsExt;

        use crate::constants::CONFIG_FILE_MODE;

        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        save(&populated(), &path).expect("first save");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).expect("chmod");

        // The rename replaces the inode, so the new file carries the staging
        // file's mode rather than inheriting the loosened one.
        save(&populated(), &path).expect("second save");
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, CONFIG_FILE_MODE, "mode is {mode:o}");
    }

    #[test]
    fn a_stale_staging_file_does_not_block_a_save() {
        // A hard-killed run can leave one behind under this very process id.
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        std::fs::write(staging_path(&path), b"leftover garbage").expect("plant a stale file");

        save(&populated(), &path).expect("must save regardless");
        assert!(load::load(&path).is_ok());
    }
}
