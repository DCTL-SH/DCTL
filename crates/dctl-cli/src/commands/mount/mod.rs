//! `dctl mount` — mount a remote as a filesystem.
//!
//! **This command cannot mount anything in this build.** It is `PLAN.md` phase 2
//! (§11), and every run ends in [`CliError::unimplemented`] — an error with a
//! real exit code, never a success message for work that did not happen
//! (`PLAN.md` §6). What it *does* do today is everything that can be done
//! without a filesystem adapter: parse and validate the full flag surface, check
//! the mountpoint, and name the backend it would attach through. A user who runs
//! it now learns about their non-empty mountpoint now, rather than on the day
//! the feature lands.
//!
//! ## Why the flags exist before the feature does
//!
//! A command-line surface is an interface, and interfaces are cheapest to get
//! right before anyone depends on them. `--help`, the generated shell
//! completions and the documentation are all built from these definitions the
//! moment this ships, so the spellings and defaults below are final: phase 2
//! wires an engine underneath them without renaming a flag or moving a default.
//! The defaults themselves are argued for in
//! [`crate::constants`], each with the `PLAN.md` §15 reasoning behind it.
//!
//! ## Per-platform backend (`PLAN.md` §15)
//!
//! | OS | Backend | Notes |
//! |----|---------|-------|
//! | Linux | **FUSE3** via `fuser` | writeback cache, large `max_read`/`max_write`, multithreaded, big readahead |
//! | macOS | **FSKit** (macOS 15+) → **fuse-t** → **macFUSE** | FSKit is Apple-sanctioned and needs no kernel extension, which is what makes it the 20-year-safe default (`PLAN.md` §13.1); fuse-t avoids a kext by tunnelling over NFS loopback; macFUSE is a kext — fastest, opt-in, and the one a macOS release can break |
//! | Windows | **WinFSP** | the mature FUSE-like layer; ProjFS is an option later for read-first streaming virtualisation |
//!
//! The order lives in [`backend`], and the checks in [`mountpoint`].
//!
//! ## Output
//!
//! `mount` produces no structured result, so it has nothing to render in
//! `--format json`: it either runs a filesystem in the foreground or fails.
//! The resolved plan is written to **stderr** at `-v`, where it belongs — stdout
//! is reserved for data, and a mount's data is the filesystem itself.

pub mod backend;
pub mod mountpoint;
pub mod options;
pub mod source;

use std::path::PathBuf;
use std::time::Duration;

use clap::Args;

use crate::constants::{
    MOUNT_ADAPTER_FEATURE, MOUNT_DEFAULT_ATTR_TIMEOUT, MOUNT_DEFAULT_BUFFER_SIZE,
    MOUNT_DEFAULT_DIR_CACHE_TIME, MOUNT_DEFAULT_VFS_READ_AHEAD, MOUNT_ENGINE_HINT,
    MOUNT_SIZE_DISABLED,
};
use crate::ctx::Ctx;
use crate::error::{CliError, Result};
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

/// Mount a remote as a filesystem.
///
/// Validates everything that can be validated, reports what it would do, and
/// then fails: see the module docs for why this is an error rather than a
/// no-op.
///
/// # Errors
/// [`crate::exit::ExitCode::Usage`] for an unparseable remote or an unusable
/// mountpoint, [`crate::exit::ExitCode::DirNotFound`] for a mountpoint that does
/// not exist, and [`crate::exit::ExitCode::FatalError`] from
/// [`CliError::unimplemented`] once everything else has passed.
pub async fn run(ctx: &Ctx, args: &MountArgs) -> Result<()> {
    let source = Source::parse(&args.remote)?;

    // The mountpoint is checked even though nothing can be mounted: it is the
    // problem the user has to fix before phase 2 is any use to them, and finding
    // out today costs one command.
    mountpoint::validate(&args.mountpoint)?;

    advise(ctx, args);
    report(ctx, &source, args);

    tracing::debug!(
        { fields::REMOTE } = source.remote.as_str(),
        { fields::PATH } = source.path.as_str(),
        mountpoint = %args.mountpoint.display(),
        backend = backend::first_choice().map_or("none", backend::MountBackend::slug),
        read_only = args.read_only,
        vfs_cache_mode = args.vfs_cache_mode.slug(),
        "mount validated; no filesystem adapter in this build"
    );

    // The message names the missing *capability* and the crate that would own
    // it, with the command in front so a reader can map it onto what they typed.
    // Naming only the command would be the one thing this refusal must not do:
    // everything `dctl mount` itself is responsible for has, by this line,
    // already run and passed.
    Err(CliError::unimplemented(format!(
        "{} {VERB}: {MOUNT_ADAPTER_FEATURE}",
        dctl_meta::BINARY_NAME
    ))
    .with_hint(MOUNT_ENGINE_HINT))
}

/// Warn about combinations that parse but cannot do what they look like they do.
///
/// Warnings rather than errors, and on stderr: every one of these is legal on
/// some platform or in some future mode, and refusing would break a script that
/// is correct elsewhere. Saying nothing, though, leaves a user tuning a dial
/// that is not connected.
fn advise(ctx: &Ctx, args: &MountArgs) {
    if args.vfs_read_ahead > MOUNT_SIZE_DISABLED && args.vfs_cache_mode == VfsCacheMode::Off {
        ctx.out.warn(
            "--vfs-read-ahead does nothing with --vfs-cache-mode off: read-ahead \
             fills the on-disk cache, and there is none. Use --buffer-size for \
             in-memory read-ahead, or turn the cache on.",
        );
    }

    if cfg!(target_os = "windows") {
        if args.allow_other || args.allow_root {
            ctx.out.warn(
                "--allow-other and --allow-root are POSIX permission concepts and \
                 have no effect on Windows, where access follows the drive's ACL.",
            );
        }
        if args.daemon {
            ctx.out.warn(
                "--daemon has no effect on Windows: a filesystem stays up as a \
                 service there, not as a detached process.",
            );
        }
    }
}

/// Describe the mount that would have been attached, on stderr at `-v`.
fn report(ctx: &Ctx, source: &Source, args: &MountArgs) {
    ctx.out.info(format!(
        "would mount {source} at {}",
        args.mountpoint.display()
    ));

    match backend::first_choice() {
        Some(first) => {
            let fallbacks: Vec<&str> = backend::preferred()
                .iter()
                .skip(1)
                .map(|candidate| candidate.describe())
                .collect();
            if fallbacks.is_empty() {
                ctx.out.info(format!("backend: {}", first.describe()));
            } else {
                ctx.out.info(format!(
                    "backend: {} (falling back to {})",
                    first.describe(),
                    fallbacks.join(", ")
                ));
            }
        }
        None => ctx
            .out
            .info("backend: none — this platform has no supported filesystem layer"),
    }

    let units = ctx.out.units();
    ctx.out.info(format!(
        "options: read-only={}, dir-cache={}, attr-timeout={}, vfs-cache={}, \
         buffer={}, read-ahead={}, modtime={}",
        args.read_only,
        size::duration(args.dir_cache_time.as_secs()),
        size::duration(args.attr_timeout.as_secs()),
        args.vfs_cache_mode.slug(),
        size::bytes(args.buffer_size, units),
        size::bytes(args.vfs_read_ahead, units),
        !args.no_modtime,
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::GlobalArgs;
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

    /// A context with the progress display and warnings silenced, so a test run
    /// from a terminal does not paint over the harness's output.
    fn ctx() -> Ctx {
        Ctx::new(Globals::parse_from(["dctl", "--quiet"]).globals)
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

    #[tokio::test]
    async fn a_valid_invocation_still_fails_because_nothing_can_mount_yet() {
        // PLAN.md §6: never report work that did not happen. There is no mode —
        // not even --dry-run — in which this build may exit 0.
        let dir = mountpoint();
        let path = dir.path().to_string_lossy().to_string();
        let error = run(&ctx(), &parse(&["vault:", &path])).await.unwrap_err();

        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(
            error.message().contains("mount"),
            "message must name the command: {}",
            error.message()
        );
        // …and the three things that turn a dead end into a roadmap entry. The
        // command name alone is what this test used to check, and it would have
        // passed on a message that told a reader nothing they could act on.
        assert!(
            error.message().contains(MOUNT_ADAPTER_FEATURE),
            "the missing capability must be named: {}",
            error.message()
        );
        assert!(
            error.message().contains("dctl-mount"),
            "and the layer that owes it: {}",
            error.message()
        );
        assert!(
            error.hint().is_some_and(|hint| hint.contains("phase 2")),
            "the refusal must say when it lands"
        );
    }

    #[tokio::test]
    async fn the_mountpoint_is_checked_before_the_engine_is_blamed() {
        // The whole reason the checks run in a build that cannot mount: a bad
        // mountpoint must be reported as a bad mountpoint, not as a missing
        // feature the user would then wait for.
        let dir = mountpoint();
        std::fs::write(dir.path().join("occupied.txt"), b"x").unwrap();
        let path = dir.path().to_string_lossy().to_string();

        let error = run(&ctx(), &parse(&["vault:", &path])).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert_ne!(error.code(), ExitCode::FatalError);
    }

    #[tokio::test]
    async fn a_missing_mountpoint_is_its_own_exit_code() {
        let dir = mountpoint();
        let missing = dir.path().join("not-there");
        let path = missing.to_string_lossy().to_string();
        let error = run(&ctx(), &parse(&["vault:", &path])).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::DirNotFound);
    }

    #[tokio::test]
    async fn the_remote_is_parsed_before_the_mountpoint_is_touched() {
        // A local source is a usage error whatever the mountpoint looks like.
        let error = run(&ctx(), &parse(&["/srv/data", "/mnt/nowhere-at-all"]))
            .await
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[tokio::test]
    async fn a_pointless_read_ahead_warns_but_does_not_fail_the_parse() {
        // The advice must never become a refusal: the same flags are correct in
        // a cache mode this run did not ask for.
        let dir = mountpoint();
        let path = dir.path().to_string_lossy().to_string();
        let args = parse(&["vault:", &path, "--vfs-read-ahead", "128M"]);
        let error = run(&ctx(), &args).await.unwrap_err();
        assert_eq!(
            error.code(),
            ExitCode::FatalError,
            "warning became a refusal"
        );
    }
}
