//! Turning the session's mount options into the arguments macFUSE's helper reads.
//!
//! ## Why this is a translation and not a pass-through
//!
//! `fuser`'s [`MountOption`] vocabulary is Linux's. macFUSE's is its own, and the
//! two overlap without matching: `subtype=` becomes `fstypename=`, `auto_unmount`
//! has no equivalent at all, and `nosuid` is not a request macFUSE honours but a
//! flag it imposes. The obvious shortcut — render each option the way Linux
//! spells it and let the helper sort it out — is the one thing that must not be
//! done here, and the reason is measured rather than assumed:
//!
//! **macFUSE silently accepts an option it does not understand.** Passing
//! `subtype=dctl-vault-ro`, `auto_unmount` and an invented `no_such_option` each
//! produced a mount that came up cleanly and did not have the property asked for.
//! Only a few options are validated at all — `fstypename` is length-checked and
//! refused — so a wrong spelling does not fail, it *works incorrectly*. That is
//! `PLAN.md` §6's misreport arriving through a mount table: `dctl mount` would
//! report success, the mount would be up, and a property somebody is relying on
//! would quietly not be there.
//!
//! So the mapping below is **total and explicit**. Every variant is either given
//! macFUSE's own spelling, or stated to be macFUSE's default and mapped to
//! nothing, or refused by name. [`MountOption`] is not `#[non_exhaustive]`, so
//! the `match` is exhaustive and a new variant in a future `fuser` breaks this
//! build rather than being dropped on the floor.
//!
//! ## Compiled everywhere, on purpose
//!
//! Nothing here is a syscall — it is a decision about strings — and the decision
//! is what has to be right. [`super::helper`] and [`super::handover`] are macOS
//! only; this module is not, so the whole table and every refusal are compiled,
//! linted and tested by the Linux gates. That is the same rule
//! [`preflight`](crate::mount::preflight) states and for the same reason: a test
//! that can only run on one developer's laptop protects nothing.

use std::fmt;

use fuser::{MountOption, SessionACL};

use crate::constants::{
    MOUNT_MACFUSE_IOSIZE, MOUNT_MACFUSE_TYPE_NAME_MAX, mount_macfuse_daemon_timeout,
};

/// An option this platform cannot honour, and what to tell the reader.
///
/// Carried rather than logged, because every one of these is either a flag the
/// user passed or a defect in the option set this build assembles, and both are
/// worth failing the mount over. Silently dropping any of them is the failure
/// this module exists to prevent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unmappable {
    /// The option as it would have been spelled on Linux.
    pub option: String,
    /// Why macFUSE cannot be asked for it, in one line.
    pub reason: String,
}

impl fmt::Display for Unmappable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "'{}' {}", self.option, self.reason)
    }
}

impl Unmappable {
    fn new(option: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            option: option.into(),
            reason: reason.into(),
        }
    }
}

/// Every `-o` argument macFUSE's helper should be given, in order.
///
/// One element per argument rather than one comma-joined string, because the
/// helper accepts `-o` repeatedly and a comma inside a *value* would otherwise
/// end the option: `volname=Archive,2024` is read as `volname=Archive` plus an
/// unknown `2024`, which macFUSE ignores without a word. Values are still checked
/// for commas below — the helper's own parser splits on them whichever way the
/// arguments arrive — but keeping one option per argument means nothing else can
/// run together.
///
/// `idle_seconds` is the resolved `--timeout`; it decides macFUSE's watchdog, so
/// that DCTL's deadline is always the one that fires first. See
/// [`mount_macfuse_daemon_timeout`].
///
/// # Errors
/// [`Unmappable`] naming the first option macFUSE cannot be asked for.
pub fn translate(
    options: &[MountOption],
    acl: SessionACL,
    idle_seconds: u64,
) -> Result<Vec<String>, Unmappable> {
    let mut arguments = Vec::with_capacity(options.len() + 3);

    for option in options {
        if let Some(argument) = render(option)? {
            arguments.push(argument);
        }
    }

    // The ACL is not a `MountOption` — `fuser` carries it beside them — but it
    // is a kernel-enforced property of the mount and has to be asked for.
    //
    // `RootAndOwner` maps to macFUSE's own `allow_root` rather than to
    // `allow_other`. `fuser` uses `allow_other` for both on Linux, where there
    // is no kernel-level `allow_root`, and narrows it again in userspace by
    // dropping requests from other users. macFUSE *does* have `allow_root`, so
    // asking for it puts the same restriction in the kernel as well: two layers
    // instead of one, and the strictly tighter of the two spellings.
    if let Some(allow) = match acl {
        SessionACL::All => Some("allow_other"),
        SessionACL::RootAndOwner => Some("allow_root"),
        // FUSE's default and DCTL's: nothing to ask for.
        SessionACL::Owner => None,
    } {
        arguments.push(allow.to_string());
    }

    // macFUSE ignores the `max_write` negotiated in `FUSE_INIT` and uses this
    // instead, so leaving it out takes macFUSE's default rather than a value
    // chosen against the session loop's receive buffer.
    arguments.push(format!("iosize={MOUNT_MACFUSE_IOSIZE}"));

    // The watchdog that decides how long macFUSE waits for an answer before it
    // declares the volume dead. Set from DCTL's own deadline so that DCTL's
    // timeout is the one that fires and produces a diagnosed error, rather than
    // macFUSE killing the volume first and leaving a wedged mountpoint.
    arguments.push(format!(
        "daemon_timeout={}",
        mount_macfuse_daemon_timeout(idle_seconds)
    ));

    for argument in &arguments {
        check_value(argument)?;
    }

    Ok(arguments)
}

/// One option in macFUSE's spelling, or [`None`] where macFUSE already behaves
/// that way and there is nothing to ask for.
///
/// # Errors
/// [`Unmappable`] where macFUSE has no way to be asked at all.
fn render(option: &MountOption) -> Result<Option<String>, Unmappable> {
    Ok(match option {
        // ── Asked for, and verified in the mount table ──────────────────────
        //
        // Each of these was passed to the helper on this machine and read back
        // out of `mount(8)`: `dctl on … (macfuse_dctlro, nodev, noexec, nosuid,
        // read-only, synchronous, noatime, mounted by mx)`.
        MountOption::RO => Some("ro".to_string()),
        MountOption::NoExec => Some("noexec".to_string()),
        MountOption::NoSuid => Some("nosuid".to_string()),
        MountOption::NoDev => Some("nodev".to_string()),
        MountOption::NoAtime => Some("noatime".to_string()),
        MountOption::DefaultPermissions => Some("default_permissions".to_string()),
        MountOption::FSName(name) => Some(format!("fsname={name}")),

        // macFUSE's `subtype` is spelled `fstypename` and is length-limited; the
        // Linux spelling is accepted and ignored, which is why it is translated
        // rather than passed through. `mount(8)` renders it `macfuse_<name>`.
        MountOption::Subtype(name) => {
            if name.chars().count() > MOUNT_MACFUSE_TYPE_NAME_MAX {
                return Err(Unmappable::new(
                    format!("subtype={name}"),
                    format!(
                        "is longer than the {MOUNT_MACFUSE_TYPE_NAME_MAX} characters macFUSE \
                         allows in a filesystem type name, and macFUSE refuses the mount \
                         outright rather than shortening it"
                    ),
                ));
            }
            Some(format!("fstypename={name}"))
        }

        // ── Already how macFUSE behaves, so there is nothing to ask for ─────
        //
        // Verified by mounting without them and reading `mount(8)` back: a
        // macFUSE volume with no options is read-write, exec, atime and
        // synchronous. Mapping these to nothing is therefore honouring them, not
        // dropping them — and the distinction is exactly why they are listed
        // here by name instead of falling into a catch-all.
        MountOption::RW | MountOption::Exec | MountOption::Atime | MountOption::Sync => None,

        // ── No way to ask macFUSE for these ────────────────────────────────
        MountOption::Suid => {
            return Err(Unmappable::new(
                "suid",
                "cannot be honoured: macFUSE imposes nosuid on a mount made by an \
                 unprivileged user, and it appears in the mount table whether or not \
                 it was asked for",
            ));
        }
        MountOption::Dev => {
            return Err(Unmappable::new(
                "dev",
                "cannot be honoured: macFUSE imposes nodev on a mount made by an \
                 unprivileged user, and it appears in the mount table whether or not \
                 it was asked for",
            ));
        }
        MountOption::Async => {
            return Err(Unmappable::new(
                "async",
                "has no macFUSE equivalent: a macFUSE volume is synchronous, and the \
                 only option that changes it is one macFUSE's own help calls dangerous",
            ));
        }
        MountOption::DirSync => {
            return Err(Unmappable::new("dirsync", "has no macFUSE equivalent"));
        }
        MountOption::AutoUnmount => {
            return Err(Unmappable::new(
                "auto_unmount",
                "has no macFUSE equivalent: macFUSE accepts the option and does \
                 nothing with it, so asking for it would promise a cleanup after \
                 SIGKILL that would not happen",
            ));
        }

        // ── The user's own words ────────────────────────────────────────────
        //
        // `--volname` arrives here. Passed through because macFUSE's vocabulary
        // is wider than `MountOption` describes, and checked below for the comma
        // that would silently truncate it.
        MountOption::CUSTOM(value) => {
            if value.is_empty() {
                return Err(Unmappable::new(
                    "(empty)",
                    "is not an option: macFUSE would take the empty string as an \
                     option name and ignore it",
                ));
            }
            Some(value.clone())
        }
    })
}

/// Refuse an option macFUSE's parser would cut in half.
///
/// The helper splits an `-o` argument on commas, so `volname=Archive,2024`
/// becomes `volname=Archive` and an option called `2024` — which macFUSE ignores
/// in silence. The user would get a volume named `Archive` and no indication that
/// half their name had gone. Refusing is the only answer that does not involve
/// inventing a name they did not ask for.
///
/// Public because [`plan`](crate::commands::mount::plan) applies the same rule to
/// `--volname` *before* the vault is unlocked. Two call sites, one rule: the
/// early one exists so a refusal costs no password prompt, and this one is the
/// backstop that makes the property true of every option however it arrives.
pub fn check_value(argument: &str) -> Result<(), Unmappable> {
    if argument.contains(',') {
        return Err(Unmappable::new(
            argument,
            "contains a comma, and macFUSE reads a comma as the end of an option: \
             everything after it would be parsed as a separate option and ignored \
             without a word",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{
        DEADLINE_DISABLED, DEFAULT_TIMEOUT_SECS, MOUNT_FS_NAME, MOUNT_FS_SUBTYPE,
        MOUNT_MACFUSE_DAEMON_TIMEOUT_MAX, MOUNT_MACFUSE_TYPE_NAME,
    };

    fn translated(options: &[MountOption], acl: SessionACL) -> Vec<String> {
        translate(options, acl, DEFAULT_TIMEOUT_SECS).expect("the option set is mappable")
    }

    fn refusal(options: &[MountOption]) -> Unmappable {
        translate(options, SessionACL::Owner, DEFAULT_TIMEOUT_SECS)
            .expect_err("the option is not mappable")
    }

    #[test]
    fn the_read_only_mount_flags_reach_macfuse_in_its_own_spelling() {
        // The set `session::session_config` builds, translated. Every string
        // here was read back out of `mount(8)` on macFUSE 5.3.3.
        let arguments = translated(
            &[
                MountOption::RO,
                MountOption::NoExec,
                MountOption::NoSuid,
                MountOption::NoDev,
                MountOption::NoAtime,
            ],
            SessionACL::Owner,
        );
        for expected in ["ro", "noexec", "nosuid", "nodev", "noatime"] {
            assert!(
                arguments.iter().any(|argument| argument == expected),
                "{expected} did not survive translation: {arguments:?}"
            );
        }
    }

    #[test]
    fn the_linux_subtype_spelling_never_reaches_macfuse() {
        // The measured trap: macFUSE accepts `subtype=…` and does nothing with
        // it, so a pass-through would produce a mount that came up clean and
        // showed as a bare `macfuse` volume. The translation has to change the
        // word, not forward it.
        let arguments = translated(
            &[MountOption::Subtype(MOUNT_MACFUSE_TYPE_NAME.to_string())],
            SessionACL::Owner,
        );
        assert!(
            arguments
                .iter()
                .any(|argument| argument == &format!("fstypename={MOUNT_MACFUSE_TYPE_NAME}")),
            "{arguments:?}"
        );
        assert!(
            !arguments
                .iter()
                .any(|argument| argument.starts_with("subtype=")),
            "the Linux spelling reached macFUSE, where it does nothing: {arguments:?}"
        );
    }

    #[test]
    fn a_subtype_macfuse_would_refuse_is_refused_here_with_the_reason() {
        // `fstypename` is one of the few options macFUSE validates: over the
        // limit it refuses the mount outright. Catching it here means the
        // message names the option rather than quoting a helper that failed.
        let refused = refusal(&[MountOption::Subtype(MOUNT_FS_SUBTYPE.to_string())]);
        assert!(refused.option.contains(MOUNT_FS_SUBTYPE));
        assert!(
            refused
                .reason
                .contains(&MOUNT_MACFUSE_TYPE_NAME_MAX.to_string()),
            "{refused}"
        );
        // Counted in characters rather than bytes, so a multi-byte name is
        // measured the way macFUSE measures it rather than refused early.
        assert!(
            translate(
                &[MountOption::Subtype("dctlro".to_string())],
                SessionACL::Owner,
                DEFAULT_TIMEOUT_SECS
            )
            .is_ok()
        );
    }

    #[test]
    fn auto_unmount_is_refused_rather_than_promised() {
        // Measured: macFUSE takes the option and ignores it. Passing it would
        // tell a `--allow-other` user their mountpoint comes free after a
        // SIGKILL, which on macOS is the difference between a directory that
        // works and one that is unusable until the machine reboots.
        let refused = refusal(&[MountOption::AutoUnmount]);
        assert_eq!(refused.option, "auto_unmount");
        assert!(
            refused.reason.contains("SIGKILL"),
            "the refusal has to name what would silently not happen: {refused}"
        );
    }

    #[test]
    fn every_option_that_cannot_be_honoured_says_so_by_name() {
        // The whole point of the module: nothing is dropped in silence. Each of
        // these is a real `MountOption` that macFUSE has no way to be asked for.
        for option in [
            MountOption::Suid,
            MountOption::Dev,
            MountOption::Async,
            MountOption::DirSync,
            MountOption::AutoUnmount,
        ] {
            let refused = refusal(std::slice::from_ref(&option));
            assert!(
                !refused.option.is_empty() && !refused.reason.is_empty(),
                "{option:?} was refused without saying what or why"
            );
        }
    }

    #[test]
    fn an_option_macfuse_already_applies_is_honoured_by_asking_for_nothing() {
        // The other half of "nothing is dropped in silence": these are not
        // refusals, because a macFUSE volume with no options already behaves
        // this way. Verified by mounting without them and reading `mount(8)`.
        let arguments = translated(
            &[
                MountOption::RW,
                MountOption::Exec,
                MountOption::Atime,
                MountOption::Sync,
            ],
            SessionACL::Owner,
        );
        // Only the two macFUSE-specific settings this module always adds.
        assert!(
            arguments
                .iter()
                .all(|argument| argument.starts_with("iosize=")
                    || argument.starts_with("daemon_timeout=")),
            "{arguments:?}"
        );
    }

    #[test]
    fn the_acl_reaches_the_kernel_and_root_gets_the_tighter_word() {
        assert!(
            !translated(&[], SessionACL::Owner)
                .iter()
                .any(|argument| argument.starts_with("allow_")),
            "the default must widen nothing"
        );
        assert!(
            translated(&[], SessionACL::All)
                .iter()
                .any(|argument| argument == "allow_other")
        );
        // `--allow-root` becomes macFUSE's own `allow_root`, which is a kernel
        // restriction rather than `allow_other` plus a userspace filter.
        let root = translated(&[], SessionACL::RootAndOwner);
        assert!(
            root.iter().any(|argument| argument == "allow_root"),
            "{root:?}"
        );
        assert!(
            !root.iter().any(|argument| argument == "allow_other"),
            "allow_root must not be widened into allow_other: {root:?}"
        );
    }

    #[test]
    fn a_comma_in_a_value_is_refused_because_macfuse_would_eat_the_rest() {
        // `--volname 'Archive,2024'`: macFUSE reads `volname=Archive` and an
        // option called `2024`, which it ignores. The user would be given a
        // volume named `Archive` and told nothing.
        let refused = refusal(&[MountOption::CUSTOM("volname=Archive,2024".to_string())]);
        assert!(refused.option.contains("Archive,2024"));
        assert!(refused.reason.contains("comma"), "{refused}");

        // A space is fine and must not be swept up with it — verified against
        // the helper, which mounted `volname=My Archive` without complaint.
        assert!(
            translate(
                &[MountOption::CUSTOM("volname=My Archive".to_string())],
                SessionACL::Owner,
                DEFAULT_TIMEOUT_SECS
            )
            .is_ok()
        );
    }

    #[test]
    fn a_comma_is_caught_wherever_it_appears_and_not_only_in_custom_options() {
        // The filesystem name is a constant today, but the check belongs to the
        // arguments rather than to one branch of the match: a comma anywhere
        // truncates the option it is in.
        let refused = refusal(&[MountOption::FSName("dctl,vault".to_string())]);
        assert!(refused.option.contains("fsname=dctl,vault"), "{refused}");
    }

    #[test]
    fn the_kernel_is_told_how_large_a_request_may_be_and_how_long_it_may_take() {
        // macFUSE ignores the negotiated `max_write` and uses `iosize`, and its
        // default `daemon_timeout` is shorter than DCTL's own deadline — so both
        // are always sent, whatever else the caller asked for.
        let arguments = translated(&[], SessionACL::Owner);
        assert!(
            arguments
                .iter()
                .any(|argument| argument == &format!("iosize={MOUNT_MACFUSE_IOSIZE}"))
        );
        assert!(arguments.iter().any(|argument| argument
            == &format!(
                "daemon_timeout={}",
                mount_macfuse_daemon_timeout(DEFAULT_TIMEOUT_SECS)
            )));
    }

    #[test]
    fn a_disabled_deadline_still_bounds_macfuses_watchdog() {
        // `--timeout 0` turns DCTL's deadline off. macFUSE has no equivalent, so
        // the mount asks for the longest watchdog it will honour rather than
        // pretending the volume can wait forever.
        let arguments = translate(&[], SessionACL::Owner, DEADLINE_DISABLED)
            .expect("an empty option set is mappable");
        assert!(
            arguments.iter().any(|argument| argument
                == &format!("daemon_timeout={MOUNT_MACFUSE_DAEMON_TIMEOUT_MAX}")),
            "{arguments:?}"
        );
    }

    #[test]
    fn an_empty_custom_option_is_refused_rather_than_sent() {
        let refused = refusal(&[MountOption::CUSTOM(String::new())]);
        assert!(refused.reason.contains("ignore"), "{refused}");
    }

    #[test]
    fn the_filesystem_name_survives_translation_unchanged() {
        // What `mount(8)` and `df` print as the source of the mount. It is the
        // binary's name rather than the user's remote, and that property is
        // worth keeping through the one place that could rewrite it.
        let arguments = translated(
            &[MountOption::FSName(MOUNT_FS_NAME.to_string())],
            SessionACL::Owner,
        );
        assert!(
            arguments
                .iter()
                .any(|argument| argument == &format!("fsname={MOUNT_FS_NAME}"))
        );
    }
}
