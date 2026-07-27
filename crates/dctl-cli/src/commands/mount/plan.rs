//! Turning the command line into something the engine can honour — or refusing
//! it by name.
//!
//! This is where `dctl mount`'s flags meet what the read-only v1 filesystem can
//! actually do, and the rule it applies is the one thing worth stating up front:
//! **a flag that cannot be honoured is refused, not ignored.** A mount that
//! accepted `--vfs-cache-mode full` and streamed everything anyway would leave
//! the user believing their seeks were being cached, tuning a dial that is not
//! connected, and — the part that matters — unable to tell that from a working
//! cache by looking at the mount. That is `PLAN.md` §6's rule about not reporting
//! work that did not happen, applied to configuration rather than to data.
//!
//! Refusals are `usage` errors, so a script gets exit 1 and a message naming the
//! flag. They are not warnings: a warning on stderr is invisible to the systemd
//! unit or the cron job that will be running the mount.
//!
//! ## What is honoured, and how
//!
//! | Flag | How |
//! |------|-----|
//! | `--read-only` | Always on. v1 is read-first (`PLAN.md` §15), so the mount is read-only whether the flag is given or not — and *says so* rather than letting the flag look decorative. |
//! | `--allow-other` / `--allow-root` | The FUSE session ACL. See the security note in [`crate::mount`] for what widening it means for an unlocked vault. |
//! | `--volname` | Passed to macFUSE as `volname=`. Refused elsewhere: Linux FUSE has no volume name, and pretending otherwise would be ignoring the flag. |
//! | `--dir-cache-time` | How long a decrypted directory listing is served before it is read again. |
//! | `--attr-timeout` | The TTL on every attribute reply, which is how long the kernel may believe a size or a timestamp. |
//! | `--buffer-size` | The read-ahead window: the mount warms the chunks covering the next this-many bytes after a read, and asks the kernel for the same window. |
//! | `--no-modtime` | Reports the mount time for every file instead of its recorded modification time. |
//!
//! ## What is refused, and why
//!
//! | Flag | Why |
//! |------|-----|
//! | `--daemon` | Detaching means `fork`, and this process holds a Tokio runtime, provider connections and an open SQLCipher database. Only async-signal-safe calls are legal between `fork` and `exec` in a threaded process, so a fork here is a deadlock waiting for the wrong moment. Backgrounding belongs to the shell, to `systemd` or to `launchd`, all of which do it correctly. |
//! | `--vfs-cache-mode` other than `off` | There is no on-disk cache in this build. The other three modes describe *writes*, and v1 has no write path at all. |
//! | `--vfs-read-ahead` | It fills the on-disk cache, which does not exist. `--buffer-size` is the in-memory read-ahead and is honoured. |
//! | `--volname` off macOS | No such concept on Linux FUSE. |
//! | `--include` / `--exclude` and the rest of the filter family | A mount serves what is there. A filtered mount would hide files that still exist, still count against a quota, and still appear to every other DCTL command — and the difference would look like data loss. |

use std::path::Path;

use fuser::SessionACL;

use crate::commands::listing::Filter;
use crate::ctx::Ctx;
use crate::error::{CliError, Result};
use crate::mount::MountConfig;

use super::MountArgs;
use super::options::VfsCacheMode;
use super::source::Source;

/// Build the engine's settings, refusing anything this build cannot honour.
///
/// # Errors
/// [`crate::exit::ExitCode::Usage`] naming the flag, for every refusal in the
/// table above.
pub fn resolve(ctx: &Ctx, args: &MountArgs, source: &Source) -> Result<MountConfig> {
    refuse_unhonourable(ctx, args)?;

    Ok(MountConfig {
        root: source.path.clone(),
        attr_ttl: args.attr_timeout,
        dir_ttl: args.dir_cache_time,
        read_ahead: args.buffer_size,
        acl: acl(args),
        volume_name: args.volname.clone(),
        no_modtime: args.no_modtime,
    })
}

/// Who the FUSE session accepts requests from.
///
/// `--allow-other` wins over `--allow-root` when both are given, because it is
/// the superset: a user who asked for both asked for the wider of the two, and
/// refusing the combination would be pedantry over an unambiguous request.
///
/// The default is the owning user, which is FUSE's own. It is also the only
/// default that keeps an unlocked vault to the account that unlocked it — see
/// the security note in [`crate::mount`].
fn acl(args: &MountArgs) -> SessionACL {
    if args.allow_other {
        SessionACL::All
    } else if args.allow_root {
        SessionACL::RootAndOwner
    } else {
        SessionACL::Owner
    }
}

/// Refuse every flag this build cannot act on, by name.
fn refuse_unhonourable(ctx: &Ctx, args: &MountArgs) -> Result<()> {
    if args.daemon {
        return Err(CliError::usage(
            "--daemon cannot be honoured: this process cannot safely detach itself",
        )
        .with_hint(
            "Detaching means fork(), and this process holds a thread pool, live \
             provider connections and an open encrypted database — only \
             async-signal-safe calls are legal in the child of a fork in a threaded \
             process, so the fork would be a deadlock waiting to happen. Background \
             the mount the way your system already does it: `dctl mount … &`, a \
             systemd unit, or a launchd job.",
        ));
    }

    if args.vfs_cache_mode != VfsCacheMode::Off {
        return Err(CliError::usage(format!(
            "--vfs-cache-mode {} cannot be honoured: this build has no on-disk cache",
            args.vfs_cache_mode.slug()
        ))
        .with_hint(
            "The read-only mount streams from the vault and keeps a bounded working \
             set of decrypted chunks in memory; nothing is written to local disk. \
             The other three modes describe caching writes, and PLAN.md §15 makes \
             the writable mount a later phase. Use --buffer-size for in-memory \
             read-ahead.",
        ));
    }

    if args.vfs_read_ahead > crate::constants::MOUNT_SIZE_DISABLED {
        return Err(CliError::usage(
            "--vfs-read-ahead cannot be honoured: it fills the on-disk cache, and \
             this build has none",
        )
        .with_hint(
            "--buffer-size is the in-memory read-ahead and is honoured: it sets how \
             far ahead of a read the mount fetches and authenticates chunks.",
        ));
    }

    if args.volname.is_some() && !cfg!(target_os = "macos") {
        return Err(CliError::usage(
            "--volname cannot be honoured on this platform: only macOS has a volume \
             name for a FUSE mount",
        )
        .with_hint(
            "On Linux the mount appears in the mount table under the filesystem's \
             own name; there is nothing a desktop file manager would show a volume \
             name in.",
        ));
    }

    // Read after the flags rather than beside them: a filter is assembled from
    // several globals at once, and the question that matters is whether the
    // *result* would hide anything.
    if Filter::from_globals(&ctx.globals)?.is_restricting() {
        return Err(CliError::usage(
            "the filter flags cannot be honoured by a mount: a mount serves what is \
             in the vault",
        )
        .with_hint(
            "A filtered mount would hide files that still exist, still cost storage \
             and are still listed by every other DCTL command — which looks exactly \
             like data loss. Filter at the point of use instead: `dctl ls`, `dctl \
             copy` and `dctl sync` all take the same flags and apply them.",
        ));
    }

    Ok(())
}

/// Say, on stderr, what the mount is doing that the flags did not ask for.
///
/// One line, and only when it is true. `--read-only` is the whole subject: the
/// mount is read-only in v1 whether or not the flag was given, so a user who did
/// not pass it is told — otherwise they would have to discover the difference
/// between "I asked for this" and "this is all there is" from an `EROFS` at the
/// worst moment.
pub fn announce(ctx: &Ctx, args: &MountArgs, mountpoint: &Path) {
    if !args.read_only {
        ctx.out.info(
            "the mount is read-only: PLAN.md §15 makes v1 read-first, so every write, \
             rename, delete and truncate through it is refused with EROFS. \
             --read-only is accepted and is the only mode there is.",
        );
    }

    ctx.out.info(format!(
        "mounted at {} — press Ctrl-C, or run 'umount' on the mountpoint, to detach",
        mountpoint.display()
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::GlobalArgs;
    use crate::exit::ExitCode;
    use clap::Parser;
    use std::time::Duration;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        args: MountArgs,
    }

    #[derive(Parser, Debug)]
    struct Globals {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn args(argv: &[&str]) -> MountArgs {
        Harness::parse_from(
            ["dctl", "vault:", "/mnt/vault"]
                .into_iter()
                .chain(argv.iter().copied()),
        )
        .args
    }

    fn ctx(argv: &[&str]) -> Ctx {
        Ctx::new(
            Globals::parse_from(["dctl", "--quiet"].into_iter().chain(argv.iter().copied()))
                .globals,
        )
    }

    fn source() -> Source {
        Source::parse("vault:").expect("a bare remote parses")
    }

    #[test]
    fn the_honoured_flags_reach_the_engine_unchanged() {
        let config = resolve(
            &ctx(&[]),
            &args(&[
                "--dir-cache-time",
                "10m",
                "--attr-timeout",
                "500ms",
                "--buffer-size",
                "32M",
                "--no-modtime",
            ]),
            &source(),
        )
        .expect("every one of these is honoured");

        assert_eq!(config.dir_ttl, Duration::from_secs(600));
        assert_eq!(config.attr_ttl, Duration::from_millis(500));
        assert_eq!(config.read_ahead, 32 * 1024 * 1024);
        assert!(config.no_modtime);
    }

    #[test]
    fn a_subtree_source_becomes_the_mount_root() {
        // Every path the filesystem builds is this prefix joined with what the
        // kernel asked for, which is what keeps a subtree mount inside itself.
        let source = Source::parse("vault:photos/2024").unwrap();
        let config = resolve(&ctx(&[]), &args(&[]), &source).unwrap();
        assert_eq!(config.root, "photos/2024");
    }

    #[test]
    fn read_only_is_accepted_and_changes_nothing_because_it_is_the_only_mode() {
        // Both spellings must produce the same mount; the difference is only in
        // what the user is told.
        let with = resolve(&ctx(&[]), &args(&["--read-only"]), &source()).unwrap();
        let without = resolve(&ctx(&[]), &args(&[]), &source()).unwrap();
        assert_eq!(with, without);
    }

    #[test]
    fn allow_other_widens_the_session_and_is_the_superset_of_allow_root() {
        assert_eq!(
            resolve(&ctx(&[]), &args(&[]), &source()).unwrap().acl,
            SessionACL::Owner
        );
        assert_eq!(
            resolve(&ctx(&[]), &args(&["--allow-root"]), &source())
                .unwrap()
                .acl,
            SessionACL::RootAndOwner
        );
        assert_eq!(
            resolve(&ctx(&[]), &args(&["--allow-other"]), &source())
                .unwrap()
                .acl,
            SessionACL::All
        );
        // Both given: the wider one, because that is unambiguously what was asked
        // for and refusing the combination would be pedantry.
        assert_eq!(
            resolve(
                &ctx(&[]),
                &args(&["--allow-other", "--allow-root"]),
                &source()
            )
            .unwrap()
            .acl,
            SessionACL::All
        );
    }

    #[test]
    fn daemon_is_refused_by_name_rather_than_ignored() {
        // The rule this module exists for. A flag that silently did nothing would
        // leave a user believing their mount had detached.
        let error = resolve(&ctx(&[]), &args(&["--daemon"]), &source()).unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.message().contains("--daemon"), "{}", error.message());
        // …and names what to do instead, or the refusal is a dead end.
        assert!(error.hint().is_some_and(|hint| hint.contains("systemd")));
    }

    #[test]
    fn every_cache_mode_but_off_is_refused_by_name() {
        for mode in ["minimal", "writes", "full"] {
            let error =
                resolve(&ctx(&[]), &args(&["--vfs-cache-mode", mode]), &source()).unwrap_err();
            assert_eq!(error.code(), ExitCode::Usage, "{mode}");
            assert!(
                error.message().contains("--vfs-cache-mode") && error.message().contains(mode),
                "the refusal must name the flag and the value: {}",
                error.message()
            );
        }
        // …and `off`, the default, is honoured.
        assert!(resolve(&ctx(&[]), &args(&["--vfs-cache-mode", "off"]), &source()).is_ok());
    }

    #[test]
    fn vfs_read_ahead_is_refused_and_points_at_the_flag_that_works() {
        // It used to be a warning, when nothing could mount. A refusal is right
        // now that something can: the user would otherwise be paying attention to
        // a dial with nothing behind it.
        let error =
            resolve(&ctx(&[]), &args(&["--vfs-read-ahead", "128M"]), &source()).unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(
            error
                .hint()
                .is_some_and(|hint| hint.contains("--buffer-size"))
        );
        // Zero — the default — is not a request and is not refused.
        assert!(resolve(&ctx(&[]), &args(&["--vfs-read-ahead", "0"]), &source()).is_ok());
    }

    #[test]
    fn a_volume_name_is_honoured_only_where_the_platform_has_one() {
        let resolved = resolve(&ctx(&[]), &args(&["--volname", "Archive"]), &source());
        if cfg!(target_os = "macos") {
            assert_eq!(
                resolved.unwrap().volume_name.as_deref(),
                Some("Archive"),
                "macOS has a volume name and must use it"
            );
        } else {
            let error = resolved.expect_err("no volume name off macOS");
            assert_eq!(error.code(), ExitCode::Usage);
            assert!(error.message().contains("--volname"));
        }
    }

    #[test]
    fn a_filtered_mount_is_refused_because_hiding_files_looks_like_losing_them() {
        let error = resolve(&ctx(&["--include", "*.jpg"]), &args(&[]), &source()).unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.hint().is_some_and(|hint| hint.contains("dctl ls")));
    }

    #[test]
    fn an_unfiltered_run_is_not_refused_by_the_filter_check() {
        // The check must not fire on the flags every command carries.
        assert!(resolve(&ctx(&[]), &args(&[]), &source()).is_ok());
    }

    #[test]
    fn no_refusal_is_silent() {
        // A refusal with no message would be indistinguishable from a crash, and
        // one with no hint is a dead end. Checked as a set rather than one at a
        // time, because that is how they decay.
        let refusals = [
            (ctx(&[]), args(&["--daemon"])),
            (ctx(&[]), args(&["--vfs-cache-mode", "full"])),
            (ctx(&[]), args(&["--vfs-read-ahead", "1M"])),
            (ctx(&["--include", "*.jpg"]), args(&[])),
        ];
        for (ctx, args) in refusals {
            let error = resolve(&ctx, &args, &source()).unwrap_err();
            assert!(!error.message().is_empty());
            assert!(error.hint().is_some(), "{}", error.message());
        }
    }
}
