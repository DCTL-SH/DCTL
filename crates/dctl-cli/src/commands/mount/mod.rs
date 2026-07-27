//! `dctl mount` — serve a vault as a read-only filesystem.
//!
//! The **verb**: it parses the command line, validates the mountpoint, unlocks
//! the vault, refuses the flags this engine cannot honour, and starts the
//! filesystem. The filesystem itself is [`crate::mount`], and the split is
//! deliberate — everything here is about the *command*, and nothing here knows
//! what an inode is.
//!
//! ## Read-only is the whole of v1
//!
//! `PLAN.md` §15 makes the mount read-first: a random-write encrypted mount means
//! re-chunking and journalled writes, and is a scoped phase of its own. So every
//! write, rename, delete and truncate through the mount is refused with `EROFS`,
//! `--read-only` is accepted as a statement of what is already true, and a user
//! who did *not* pass it is told on stderr rather than left to find out from an
//! error. What this command must never do is accept a write and drop it —
//! `PLAN.md` §6's rule against reporting work that did not happen, with a
//! filesystem's authority behind it.
//!
//! ## Per-platform backend (`PLAN.md` §15)
//!
//! | OS | Backend | State |
//! |----|---------|-------|
//! | Linux | **FUSE3** via `fuser` | Works. Pure-Rust mount path, so no `libfuse` at build time; `fusermount3` at run time. |
//! | macOS | **macFUSE** via `fuser` | Works. FSKit and fuse-t are §15's later kext-free options — neither has a Rust binding, so macFUSE is what this build can offer, and it says so rather than claiming the others. |
//! | Windows | **WinFSP** | Not built. WinFSP is not a FUSE binding and cannot be reached through `fuser`; the command refuses by name. |
//!
//! The preference order lives in [`backend`], the checks in [`mountpoint`], and
//! the flag decisions in [`plan`].
//!
//! ## One password, for as long as the mount is up
//!
//! The vault is unlocked once, here, and stays unlocked until the mount ends.
//! That is what makes a mount usable and it is a real security property — see
//! the security note in [`crate::mount`], which spells out what it means for a
//! machine left unattended with a mount attached.
//!
//! ## Output
//!
//! `mount` produces no structured result, so it has nothing to render in
//! `--format json`: it either runs a filesystem in the foreground or fails. The
//! resolved plan goes to **stderr**, where it belongs — stdout is reserved for
//! data, and a mount's data is the filesystem itself.

pub mod backend;
pub mod mountpoint;
pub mod options;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod plan;
pub mod source;

use std::path::PathBuf;
use std::time::Duration;

use clap::Args;

use crate::constants::{
    MOUNT_DEFAULT_ATTR_TIMEOUT, MOUNT_DEFAULT_BUFFER_SIZE, MOUNT_DEFAULT_DIR_CACHE_TIME,
    MOUNT_DEFAULT_VFS_READ_AHEAD,
};
use crate::ctx::Ctx;
use crate::error::Result;
use crate::logging::fields;
use crate::output::size;

use options::VfsCacheMode;
use source::Source;

/// Stable command name. Matches `Command::name()` in `cli/mod.rs`, because it is
/// the `op` field of every log record this command emits.
const VERB: &str = "mount";

/// Arguments for `dctl mount`.
///
/// Global flags — `--dry-run`, `--quiet`, `-v` — are not repeated here: they
/// live in [`crate::cli::GlobalArgs`] and reach the command through [`Ctx`].
#[derive(Args, Debug)]
pub struct MountArgs {
    /// Remote to serve, as REMOTE: for the whole vault or REMOTE:PATH for a
    /// subtree.
    #[arg(value_name = "REMOTE:")]
    pub remote: String,

    /// Existing empty directory to attach the filesystem to.
    ///
    /// On Windows this may instead be an unused drive letter, such as X:.
    #[arg(value_name = "MOUNTPOINT")]
    pub mountpoint: PathBuf,

    /// Serve the filesystem read-only.
    ///
    /// The safe default for a backup vault: nothing a stray process does can
    /// modify what is stored.
    #[arg(long)]
    pub read_only: bool,

    /// Let other users access the mount.
    ///
    /// Requires `user_allow_other` in /etc/fuse.conf on Linux. Has no meaning on
    /// Windows, where access is decided by the drive's ACL.
    #[arg(long)]
    pub allow_other: bool,

    /// Let root access the mount, without opening it to everyone.
    #[arg(long)]
    pub allow_root: bool,

    /// Detach and run in the background.
    ///
    /// Unavailable on Windows, where a service, not a fork, is how a filesystem
    /// stays up.
    #[arg(long)]
    pub daemon: bool,

    /// Name shown for the volume in the desktop file manager.
    #[arg(long, value_name = "NAME")]
    pub volname: Option<String>,

    /// How long a directory listing is cached before it is re-read.
    #[arg(
        long,
        value_name = "DURATION",
        default_value = MOUNT_DEFAULT_DIR_CACHE_TIME,
        value_parser = options::parse_duration
    )]
    pub dir_cache_time: Duration,

    /// How much of a file the VFS keeps on local disk.
    #[arg(
        long,
        value_enum,
        value_name = "MODE",
        default_value_t = VfsCacheMode::Off
    )]
    pub vfs_cache_mode: VfsCacheMode,

    /// Extra data to fetch past the end of a read, when the VFS cache is on.
    #[arg(
        long,
        value_name = "SIZE",
        default_value = MOUNT_DEFAULT_VFS_READ_AHEAD,
        value_parser = options::parse_buffer_size
    )]
    pub vfs_read_ahead: u64,

    /// In-memory read-ahead buffer held per open file.
    #[arg(
        long,
        value_name = "SIZE",
        default_value = MOUNT_DEFAULT_BUFFER_SIZE,
        value_parser = options::parse_buffer_size
    )]
    pub buffer_size: u64,

    /// How long the kernel may cache file attributes.
    #[arg(
        long,
        value_name = "DURATION",
        default_value = MOUNT_DEFAULT_ATTR_TIMEOUT,
        value_parser = options::parse_duration
    )]
    pub attr_timeout: Duration,

    /// Do not read modification times, reporting the mount time instead.
    ///
    /// One less index lookup per file; the trade is that anything comparing
    /// timestamps through the mount sees the wrong ones.
    #[arg(long)]
    pub no_modtime: bool,
}

/// Serve a vault as a read-only filesystem, until it is unmounted or the process
/// is asked to stop.
///
/// The order is the order it has to be: parse the source, check the mountpoint —
/// both of which fail cheaply and without a password — and only then reach the
/// engine, which resolves the flags and unlocks the vault. A user with a typo in
/// their mountpoint should not have to type their passphrase to find out.
///
/// # Errors
/// [`crate::exit::ExitCode::Usage`] for an unparseable remote, an unusable
/// mountpoint or a flag this build cannot honour;
/// [`crate::exit::ExitCode::DirNotFound`] for a mountpoint that does not exist;
/// [`crate::exit::ExitCode::VaultLocked`] when the vault will not unlock;
/// [`crate::exit::ExitCode::FatalError`] when the platform's FUSE layer refuses
/// the mount, and for the whole command on a platform that has none; and
/// [`crate::exit::ExitCode::Cancelled`] when a signal ends it — see
/// [`crate::mount::session`] for why an interrupted mount is not a success.
pub async fn run(ctx: &Ctx, args: &MountArgs) -> Result<()> {
    let source = Source::parse(&args.remote)?;
    mountpoint::validate(&args.mountpoint)?;

    // [`backend::attached`] is the authority on whether this build can attach a
    // filesystem at all, so it is asked once, here, rather than being inferred
    // from a `cfg` at each of the places that would care. On a platform with no
    // FUSE layer the run still reaches the two checks above first, because a bad
    // mountpoint should be reported as a bad mountpoint even where the command
    // was never going to succeed.
    if backend::attached().is_none() {
        advise(ctx, args);
        report(ctx, &source, args);
        tracing::debug!(
            { fields::REMOTE } = source.remote.as_str(),
            { fields::PATH } = source.path.as_str(),
            mountpoint = %args.mountpoint.display(),
            "mount validated; this platform has no FUSE layer"
        );
        return Err(no_filesystem_layer());
    }

    // `backend::attached` answers "was a FUSE layer compiled in"; this answers
    // "can this machine actually mount", which is a different question and the
    // one that was previously guessed at from an errno *after* the attempt.
    //
    // It runs BEFORE the vault is opened on purpose. A refusal here costs no
    // password prompt and unlocks no keys — and the previous ordering meant a
    // mount that could never succeed still asked for the vault password first,
    // holding an unlocked root key in memory to reach a failure that was
    // knowable beforehand.
    crate::mount::preflight().into_result()?;

    serve(ctx, args, &source).await
}

/// The refusal for a platform with no FUSE layer.
///
/// Windows attaches a userspace filesystem through **WinFSP**, which is not a
/// FUSE binding and cannot be reached from the crate that serves Linux and
/// macOS. Everything above the adapter — the flag surface, the mountpoint checks,
/// the filesystem itself — is finished and runs on the other two, so the refusal
/// names the one missing piece and the section that schedules it rather than
/// leaving a reader to wonder which part of their command was wrong.
fn no_filesystem_layer() -> crate::error::CliError {
    crate::error::CliError::unimplemented(format!(
        "{} {VERB}: {}",
        dctl_meta::BINARY_NAME,
        crate::constants::MOUNT_ADAPTER_FEATURE
    ))
    .with_hint(crate::constants::MOUNT_ENGINE_HINT)
}

/// Unlock the vault and run the filesystem.
///
/// Split from [`run`] so that everything a mount needs regardless of platform —
/// the source, the mountpoint, the refusal — is written once, and only the part
/// that genuinely needs a kernel interface is compiled per platform.
#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn serve(ctx: &Ctx, args: &MountArgs, source: &Source) -> Result<()> {
    use std::sync::Arc;

    let config = plan::resolve(ctx, args, source)?;

    report(ctx, source, args);

    // The password is asked for here and the vault stays unlocked for the life of
    // the mount. That is not an implementation detail — see the security note in
    // `crate::mount`, which says what it means for the machine this runs on.
    let spec = crate::remote::RemoteSpec::Named {
        remote: source.remote.clone(),
        path: String::new(),
    };
    let opened: Arc<dyn crate::source::Source> = Arc::from(crate::source::open(ctx, &spec).await?);

    let mounted = crate::mount::mount(
        opened,
        config,
        &args.mountpoint,
        tokio::runtime::Handle::current(),
    )?;

    tracing::info!(
        { fields::OP } = VERB,
        { fields::REMOTE } = source.remote.as_str(),
        { fields::PATH } = source.path.as_str(),
        mountpoint = %args.mountpoint.display(),
        backend = backend::attached().map_or("none", backend::MountBackend::slug),
        read_only = true,
        "mounted"
    );
    plan::announce(ctx, args, &args.mountpoint);

    mounted.run().await
}

/// The same, on a platform with no FUSE layer.
///
/// Never reached — [`run`] has already asked [`backend::attached`], which is the
/// authority — and written anyway rather than left to a `cfg` at the call site,
/// so that the platform question is answered in exactly one place. A second
/// answer is how the two come to disagree.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
async fn serve(_ctx: &Ctx, _args: &MountArgs, _source: &Source) -> Result<()> {
    Err(no_filesystem_layer())
}

/// Warn about combinations that parse but cannot do what they look like they do.
///
/// Only reached on a platform with no filesystem adapter, where a flag that
/// cannot be honoured is moot: the command is going to refuse anyway, and turning
/// each of these into its own refusal would report the *flag* as the problem when
/// the platform is. Where a mount really can be attached, the equivalent
/// decisions are refusals rather than warnings — see [`plan`], and the reasoning
/// there for why a warning is the wrong shape once something is at stake.
fn advise(ctx: &Ctx, args: &MountArgs) {
    use crate::constants::MOUNT_SIZE_DISABLED;

    if args.vfs_read_ahead > MOUNT_SIZE_DISABLED && args.vfs_cache_mode == VfsCacheMode::Off {
        ctx.out.warn(
            "--vfs-read-ahead does nothing with --vfs-cache-mode off: read-ahead \
             fills the on-disk cache, and there is none. Use --buffer-size for \
             in-memory read-ahead, or turn the cache on.",
        );
    }

    if args.allow_other || args.allow_root {
        ctx.out.warn(
            "--allow-other and --allow-root are POSIX permission concepts and have \
             no effect on Windows, where access follows the drive's ACL.",
        );
    }
    if args.daemon {
        ctx.out.warn(
            "--daemon has no effect on Windows: a filesystem stays up as a service \
             there, not as a detached process.",
        );
    }
}

/// Describe the mount on stderr at `-v`.
fn report(ctx: &Ctx, source: &Source, args: &MountArgs) {
    ctx.out.info(format!(
        "mounting {source} at {}",
        args.mountpoint.display()
    ));

    // The backend actually being used, never the one `PLAN.md` §15 prefers — see
    // [`backend::attached`] for why naming the preference here would tell a macOS
    // user the opposite of what they need to know.
    match backend::attached() {
        Some(attached) => match backend::shortfall() {
            Some(reason) => ctx
                .out
                .info(format!("backend: {} — {reason}", attached.describe())),
            None => ctx.out.info(format!("backend: {}", attached.describe())),
        },
        None => ctx
            .out
            .info("backend: none — this platform has no supported filesystem layer"),
    }

    let units = ctx.out.units();
    ctx.out.info(format!(
        "options: read-only=true, dir-cache={}, attr-timeout={}, buffer={}, modtime={}",
        size::duration(args.dir_cache_time.as_secs()),
        size::duration(args.attr_timeout.as_secs()),
        size::bytes(args.buffer_size, units),
        !args.no_modtime,
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::GlobalArgs;
    use crate::constants::MOUNT_SIZE_DISABLED;
    use crate::exit::ExitCode;
    use clap::Parser;

    /// Minimal parser that exposes `MountArgs` on its own.
    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        args: MountArgs,
    }

    /// Minimal parser that exposes the global block on its own.
    #[derive(Parser, Debug)]
    struct Globals {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn parse(argv: &[&str]) -> MountArgs {
        Harness::parse_from(std::iter::once("dctl").chain(argv.iter().copied())).args
    }

    fn mountpoint() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn both_positionals_are_required_in_order() {
        let dir = mountpoint();
        let path = dir.path().to_string_lossy().to_string();
        let args = parse(&["vault:", &path]);
        assert_eq!(args.remote, "vault:");
        assert_eq!(args.mountpoint, dir.path());

        assert!(Harness::try_parse_from(["dctl", "vault:"]).is_err());
        assert!(Harness::try_parse_from(["dctl"]).is_err());
    }

    #[test]
    fn the_defaults_are_the_documented_ones() {
        // These are published in --help and in the completions the moment this
        // ships; a default that moves later changes every script that relied on
        // it, so they are pinned by a test as well as by a constant.
        let args = parse(&["vault:", "/tmp"]);
        assert_eq!(args.dir_cache_time, Duration::from_secs(300));
        assert_eq!(args.attr_timeout, Duration::from_secs(1));
        assert_eq!(args.buffer_size, 16 * 1024 * 1024);
        assert_eq!(args.vfs_read_ahead, MOUNT_SIZE_DISABLED);
        assert_eq!(args.vfs_cache_mode, VfsCacheMode::Off);
        assert!(!args.read_only);
        assert!(!args.allow_other);
        assert!(!args.allow_root);
        assert!(!args.daemon);
        assert!(!args.no_modtime);
        assert_eq!(args.volname, None);
    }

    #[test]
    fn the_whole_flag_surface_parses() {
        // The point of shipping the surface early: every one of these has to
        // keep parsing, spelled exactly this way, once phase 2 lands.
        let args = parse(&[
            "vault:photos",
            "/mnt/vault",
            "--read-only",
            "--allow-other",
            "--allow-root",
            "--daemon",
            "--volname",
            "Vault",
            "--dir-cache-time",
            "10m",
            "--vfs-cache-mode",
            "full",
            "--vfs-read-ahead",
            "128M",
            "--buffer-size",
            "32M",
            "--attr-timeout",
            "500ms",
            "--no-modtime",
        ]);

        assert!(args.read_only);
        assert!(args.allow_other);
        assert!(args.allow_root);
        assert!(args.daemon);
        assert_eq!(args.volname.as_deref(), Some("Vault"));
        assert_eq!(args.dir_cache_time, Duration::from_secs(600));
        assert_eq!(args.vfs_cache_mode, VfsCacheMode::Full);
        assert_eq!(args.vfs_read_ahead, 128 * 1024 * 1024);
        assert_eq!(args.buffer_size, 32 * 1024 * 1024);
        assert_eq!(args.attr_timeout, Duration::from_millis(500));
        assert!(args.no_modtime);
    }

    #[test]
    fn every_cache_mode_is_reachable_from_the_command_line() {
        for (spelling, expected) in [
            ("off", VfsCacheMode::Off),
            ("minimal", VfsCacheMode::Minimal),
            ("writes", VfsCacheMode::Writes),
            ("full", VfsCacheMode::Full),
        ] {
            let args = parse(&["vault:", "/tmp", "--vfs-cache-mode", spelling]);
            assert_eq!(args.vfs_cache_mode, expected);
        }
        assert!(
            Harness::try_parse_from(["dctl", "vault:", "/tmp", "--vfs-cache-mode", "sometimes"])
                .is_err()
        );
    }

    #[test]
    fn malformed_durations_and_sizes_are_usage_errors_at_parse_time() {
        for flag in ["--dir-cache-time", "--attr-timeout"] {
            assert!(
                Harness::try_parse_from(["dctl", "vault:", "/tmp", flag, "soon"]).is_err(),
                "{flag} accepted a non-duration"
            );
        }
        for flag in ["--buffer-size", "--vfs-read-ahead"] {
            assert!(
                Harness::try_parse_from(["dctl", "vault:", "/tmp", flag, "banana"]).is_err(),
                "{flag} accepted a non-size"
            );
        }
    }

    /// A context with `--no-ask-password`, so a test that reaches the unlock
    /// fails on the missing remote instead of blocking on an invisible prompt.
    fn headless() -> Ctx {
        Ctx::new(Globals::parse_from(["dctl", "--quiet", "--no-ask-password"]).globals)
    }

    #[tokio::test]
    async fn the_mountpoint_is_checked_before_the_vault_is_unlocked() {
        // The order the command promises: a user with a typo in their mountpoint
        // must not have to type a passphrase to find out. A non-empty mountpoint
        // is a *usage* error, reported as such rather than as a failure to reach
        // the remote.
        let dir = mountpoint();
        std::fs::write(dir.path().join("occupied.txt"), b"x").unwrap();
        let path = dir.path().to_string_lossy().to_string();

        let error = run(&headless(), &parse(&["vault:", &path]))
            .await
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(
            error.message().contains("not empty"),
            "the mountpoint must be blamed for being non-empty: {}",
            error.message()
        );
    }

    #[tokio::test]
    async fn a_missing_mountpoint_is_its_own_exit_code() {
        // Distinct from a usage error so a wrapper can create it and retry
        // rather than parsing a message.
        let dir = mountpoint();
        let missing = dir.path().join("not-there");
        let path = missing.to_string_lossy().to_string();
        let error = run(&headless(), &parse(&["vault:", &path]))
            .await
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::DirNotFound);
    }

    #[tokio::test]
    async fn the_remote_is_parsed_before_the_mountpoint_is_touched() {
        // A local source is a usage error whatever the mountpoint looks like.
        let error = run(&headless(), &parse(&["/srv/data", "/mnt/nowhere-at-all"]))
            .await
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[tokio::test]
    async fn a_flag_this_engine_cannot_honour_is_refused_before_anything_is_unlocked() {
        // The rule `plan` exists for, checked through the command rather than
        // around it: a refusal has to happen before the password prompt, or the
        // user pays for a mount that was never going to start.
        let dir = mountpoint();
        let path = dir.path().to_string_lossy().to_string();
        for flags in [
            vec!["--daemon"],
            vec!["--vfs-cache-mode", "full"],
            vec!["--vfs-read-ahead", "128M"],
        ] {
            let mut argv = vec!["vault:", path.as_str()];
            argv.extend(flags.iter().copied());
            let error = run(&headless(), &parse(&argv)).await.unwrap_err();
            assert_eq!(error.code(), ExitCode::Usage, "{flags:?}");
            assert!(error.hint().is_some(), "{flags:?} refused without advice");
        }
    }

    #[tokio::test]
    async fn an_unconfigured_remote_fails_at_the_unlock_and_not_at_the_mount() {
        // Everything this command owns has passed by then, so the failure has to
        // name the remote rather than the filesystem.
        let dir = mountpoint();
        let path = dir.path().to_string_lossy().to_string();
        let error = run(&headless(), &parse(&["nosuchremote:", &path]))
            .await
            .unwrap_err();
        assert_ne!(error.code(), ExitCode::Success);
        assert!(
            error.message().contains("nosuchremote"),
            "the refusal must name the remote: {}",
            error.message()
        );
    }
}
