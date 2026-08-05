//! What this platform can actually mount, checked before anything is attempted.
//!
//! A mount failure is diagnosed here, from the state of the machine, rather than
//! guessed at afterwards from an errno. That ordering is the whole point of the
//! module, and it exists because the guess-afterwards version did real harm: a
//! `fuser` mount on macOS fails with `ENOENT`, the old hint read that as "the
//! kernel extension was never approved", and it sent an operator through two
//! reboots and a Recovery-mode boot-security downgrade to approve an extension
//! that was already loaded and was never the problem.
//!
//! The rule that follows: **never infer a cause from an errno when the cause can
//! be observed directly.** `/dev/fuse` either exists or it does not. macFUSE
//! either has a loaded device node or it does not. Those are facts, and a
//! message built from facts cannot send someone to the wrong place.
//!
//! ## Observation and decision are separate, and only one of them is portable
//!
//! Looking at the machine is inherently platform-specific; deciding what the
//! answer *means* is not. So [`Machine`] and [`Macfuse`] are plain data — what
//! was found — and [`decide`] and [`decide_macos`] are pure functions over them,
//! compiled on **every** target.
//!
//! That split is not tidiness. The two regression tests that matter most here
//! were `#[cfg(target_os = "macos")]`, so `cargo test` on the Linux machine the
//! gates run on reported *zero matches* for both — and one of them returned
//! early when macFUSE was absent, so it could pass without asserting anything at
//! all on the only platform where it compiled. A test that cannot run in CI
//! protects nothing. The decision is now fed a described machine and asserted
//! everywhere, over states this host does not have and never will.
//!
//! ## The macOS situation, stated plainly
//!
//! This module used to refuse macOS outright, and the reason it gave was true of
//! the configuration it was written against: `fuser`'s build script excludes
//! macOS from its pure-Rust mount path by a hardcoded list of operating systems,
//! and what macOS fell through to was a `pkg-config` probe commented
//! `// for macFUSE 4.x` and a `fuse_mount_compat25` call that fails against
//! **macFUSE 5**. What the refusal *implied* — that mounting on macOS was not
//! possible — was never true. rclone mounts on the same machines, and the
//! dependency's configuration was ours to change.
//!
//! It has been changed. `fuser` is now built here with its `macos-no-mount`
//! feature, and [`macfuse`](super::macfuse) performs the mount itself through
//! macFUSE's own setuid helper. So the macOS question this module answers is no
//! longer "can this binding mount at all" but the same question it asks on Linux:
//! **is the kernel side present on this machine.** For macFUSE that is one
//! observation — a `/dev/macfuseN` device node, whose existence is proof the
//! kernel extension is loaded and approved — and one file, the helper that
//! performs the mount.
//!
//! [The plan](https://doc.dctl.sh/project/plan) §15 still ranks **fuse-t** (NFS
//! loopback) and **FSKit** above macFUSE, because both need no kernel extension
//! and Apple keeps narrowing what a kernel extension may do. That ordering is
//! unchanged and is reported by
//! [`backend::shortfall`](crate::commands::mount::backend::shortfall); what has
//! changed is that macFUSE now works rather than being a dead end.

use std::path::{Path, PathBuf};

use crate::constants::MOUNT_MACFUSE_HELPER;
use crate::error::{CliError, Result};
use crate::exit::ExitCode;

/// Whether this build can mount here, and why not when it cannot.
#[derive(Debug, PartialEq, Eq)]
pub enum Readiness {
    /// FUSE is present and this platform's mount path is supported.
    Ready,
    /// Mounting cannot work, for a reason observed rather than inferred.
    Unavailable {
        /// What is wrong, in one line.
        reason: String,
        /// What the reader should do next. Never a step that does not help.
        remedy: String,
    },
}

impl Readiness {
    /// Turn an unavailable verdict into the error the command returns.
    pub fn into_result(self) -> Result<()> {
        match self {
            Self::Ready => Ok(()),
            Self::Unavailable { reason, remedy } => {
                Err(CliError::new(ExitCode::FatalError, reason).with_hint(remedy))
            }
        }
    }
}

/// Inspect the machine and report whether a mount can succeed.
///
/// `cfg!` rather than `#[cfg]`, and deliberately: `cfg!` is an ordinary boolean,
/// so **both** arms are compiled on every target and only the taken one runs.
/// That is what keeps the macOS decision from being dead code on Linux — and
/// dead code is exactly what a `#[cfg]` here would make of it, which is the same
/// force that made the two macOS tests unrunnable in the first place. The
/// unreached arm costs a branch the optimiser removes; what it buys is that
/// `cargo clippy` and `cargo test` on the Linux gate machine compile, lint and
/// exercise the whole module rather than half of it.
#[must_use]
pub fn check() -> Readiness {
    if cfg!(target_os = "macos") {
        decide_macos(&Macfuse::observe())
    } else {
        decide(&Machine::observe())
    }
}

// ── Linux and the BSDs: the pure-Rust path, which genuinely works ───────────

/// The Linux FUSE character device.
const FUSE_DEVICE: &str = "/dev/fuse";

/// The setuid helper that performs the detach.
const UNMOUNT_HELPER: &str = "fusermount3";

/// What the FUSE decision needs to know about a machine.
///
/// Both fields are things `fuser`'s pure-Rust mount path actually uses — it
/// talks to `/dev/fuse` directly and shells out to `fusermount3` only to detach
/// — so both are observed rather than assumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Machine {
    /// Whether the FUSE character device exists.
    pub device: bool,
    /// Whether the setuid unmount helper is on `PATH`.
    pub unmount_helper: bool,
}

impl Machine {
    /// Look at the machine this process is running on.
    #[must_use]
    pub fn observe() -> Self {
        Self {
            device: Path::new(FUSE_DEVICE).exists(),
            unmount_helper: which(UNMOUNT_HELPER).is_some(),
        }
    }
}

/// Decide what a described Linux/BSD machine can do. Pure; no I/O.
#[must_use]
pub fn decide(machine: &Machine) -> Readiness {
    if !machine.device {
        return Readiness::Unavailable {
            reason: format!("{FUSE_DEVICE} does not exist, so no filesystem can be mounted"),
            remedy: "Install the FUSE kernel module and userspace package (`fuse3` on \
                     most distributions) and load the module with `modprobe fuse`. In a \
                     container, the device must also be passed through — \
                     `--device /dev/fuse` and, on many runtimes, `--cap-add SYS_ADMIN`."
                .to_string(),
        };
    }

    if !machine.unmount_helper {
        return Readiness::Unavailable {
            reason: format!("the `{UNMOUNT_HELPER}` helper is not installed"),
            remedy: format!(
                "{FUSE_DEVICE} exists, so the kernel side is ready, but detaching a \
                 mount needs the setuid `{UNMOUNT_HELPER}` helper from the `fuse3` \
                 package. Install it and try again."
            ),
        };
    }

    Readiness::Ready
}

/// Locate an executable on `PATH`.
fn which(program: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|dir| dir.join(program))
            .find(|candidate| candidate.is_file())
    })
}

// ── macOS: the same question, asked of macFUSE ─────────────────────────────

/// First macFUSE device node. Its presence proves the kernel extension is loaded
/// and approved, which is exactly the thing the old hint told people to go and
/// arrange while it was already true.
const MACFUSE_DEVICE: &str = "/dev/macfuse0";

/// Where macFUSE reports its version.
const MACFUSE_BUNDLE: &str = "/Library/Filesystems/macfuse.fs";

/// What the macOS decision needs to know about a machine.
///
/// The three fields are deliberately separate, and each of them names a
/// different remedy. "Not installed" is an install; "installed but no device
/// node" is a kernel extension waiting for approval; "installed, loaded, no
/// helper" is a broken installation. Conflating any two of them is precisely how
/// the message this module replaced misled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Macfuse {
    /// Whether the macFUSE bundle is present on disk.
    pub installed: bool,
    /// Whether a macFUSE device node exists — proof the kernel extension is
    /// loaded and approved.
    pub loaded: bool,
    /// Whether the setuid mount helper this build drives is present.
    ///
    /// The macOS counterpart of `fusermount3`: [`macfuse`](super::macfuse) runs
    /// it to perform the mount, because `mount(2)` on macOS is root-only. An
    /// installation without it cannot mount, and the reason is worth stating
    /// before a mount is attempted rather than after it fails.
    pub helper: bool,
    /// The version macFUSE reports, when it can be read.
    pub version: Option<String>,
}

impl Macfuse {
    /// Look at the machine this process is running on.
    ///
    /// Compiled on every platform, not only macOS: anywhere else the paths do
    /// not exist and it describes an uninstalled machine, which costs three
    /// `stat` calls nothing outside a test ever makes. The gain is that
    /// [`decide_macos`] and the plist scan below are ordinary code the Linux
    /// gates compile, lint and run.
    #[must_use]
    pub fn observe() -> Self {
        Self {
            installed: Path::new(MACFUSE_BUNDLE).exists(),
            loaded: Path::new(MACFUSE_DEVICE).exists(),
            helper: Path::new(MOUNT_MACFUSE_HELPER).exists(),
            version: installed_version(),
        }
    }
}

/// Decide what a described macOS machine can do. Pure; no I/O.
///
/// It **can** now return [`Readiness::Ready`], which it never used to, and the
/// change is the whole of this commit's macOS half: the refusal it replaced was
/// about a binding configuration, not about the machine. What it must never do is
/// blame something the observation shows is fine — see
/// [`a_loaded_extension_is_never_blamed`](tests::a_loaded_extension_is_never_blamed),
/// which is the regression the module was written for and is unchanged.
#[must_use]
pub fn decide_macos(macfuse: &Macfuse) -> Readiness {
    // Checked first, because its absence makes everything below irrelevant, and
    // reported on its own because "not installed" and "installed but not loaded"
    // call for completely different actions.
    if !macfuse.installed {
        return Readiness::Unavailable {
            reason: "macFUSE is not installed, and this build has no other macOS \
                     filesystem backend"
                .to_string(),
            remedy: MACOS_MISSING_REMEDY.to_string(),
        };
    }

    // The device node is the kernel side. Its absence is the one macOS case where
    // System Settings really is the answer — and saying so is only safe because
    // this branch is reached *only* when no device node exists.
    if !macfuse.loaded {
        return Readiness::Unavailable {
            reason: format!(
                "macFUSE is installed{} but its kernel extension is not loaded, so \
                 there is no device to mount through",
                macfuse
                    .version
                    .as_deref()
                    .map_or(String::new(), |version| format!(" ({version})"))
            ),
            remedy: "A macFUSE system extension has to be allowed once, in System \
                     Settings > General > Login Items & Extensions, and the machine \
                     restarted before it loads. Once it has, /dev/macfuse0 exists and \
                     this check passes."
                .to_string(),
        };
    }

    // Installed and loaded, but the program that performs the mount is missing.
    // A partial installation, and the only remedy is to put it back.
    if !macfuse.helper {
        return Readiness::Unavailable {
            reason: format!(
                "macFUSE's mount helper is missing from {MOUNT_MACFUSE_HELPER}, so \
                 nothing can attach a filesystem"
            ),
            remedy: "The kernel extension IS loaded — that half is fine — but the \
                     setuid helper that performs the mount is not where macFUSE \
                     installs it. Reinstall macFUSE to restore it. mount(2) is \
                     root-only on macOS, so there is no way around that program."
                .to_string(),
        };
    }

    Readiness::Ready
}

/// What a macOS user with no macFUSE should do.
///
/// Names the kext-free backends [the plan](https://doc.dctl.sh/project/plan)
/// §15 prefers as well as macFUSE, because somebody deciding whether to install
/// a kernel extension deserves to know that it is this build's only option
/// today and not its preferred one.
const MACOS_MISSING_REMEDY: &str = "Install macFUSE (https://macfuse.io) and allow its system extension when \
     macOS asks. It is a kernel extension, which is why `PLAN.md` §15 prefers \
     FSKit and fuse-t — neither has a Rust binding yet, so macFUSE is what this \
     build can attach through today.";

/// macFUSE's installed version, if it can be read.
fn installed_version() -> Option<String> {
    let plist = Path::new(MACFUSE_BUNDLE)
        .join("Contents")
        .join("Info.plist");
    bundle_version(&std::fs::read_to_string(&plist).ok()?)
}

/// The `CFBundleVersion` value out of an `Info.plist`'s text.
///
/// A minimal scan rather than a plist parser: this is one optional field used to
/// make a message more precise, and a whole dependency for it would be a poor
/// trade. Split from the file read so the scan itself is testable on a machine
/// with no macFUSE — which is every machine the gates run on.
fn bundle_version(text: &str) -> Option<String> {
    let key = text.find("<key>CFBundleVersion</key>")?;
    let open = text[key..].find("<string>")? + key + "<string>".len();
    let close = text[open..].find("</string>")? + open;
    Some(text[open..close].trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A described macFUSE installation, so each test states only what it varies.
    fn macfuse(installed: bool, loaded: bool, helper: bool, version: Option<&str>) -> Macfuse {
        Macfuse {
            installed,
            loaded,
            helper,
            version: version.map(str::to_string),
        }
    }

    /// A complete, working macFUSE — the machine this build now mounts on.
    fn working() -> Macfuse {
        macfuse(true, true, true, Some("5.3.3"))
    }

    /// The two halves of a refusal, or a failure naming the unexpected `Ready`.
    fn unavailable(readiness: Readiness) -> (String, String) {
        match readiness {
            Readiness::Ready => panic!("expected a refusal, got Ready"),
            Readiness::Unavailable { reason, remedy } => (reason, remedy),
        }
    }

    #[test]
    fn a_ready_verdict_is_not_an_error() {
        assert!(Readiness::Ready.into_result().is_ok());
    }

    #[test]
    fn an_unavailable_verdict_carries_both_halves() {
        let verdict = Readiness::Unavailable {
            reason: "no FUSE here".to_string(),
            remedy: "install it".to_string(),
        };
        let error = verdict.into_result().unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert_eq!(error.message(), "no FUSE here");
        assert_eq!(error.hint(), Some("install it"));
    }

    #[test]
    fn the_verdict_is_reached_without_attempting_a_mount() {
        // The property that matters: `check` observes the machine and returns.
        // If it ever mounts to find out, a failure would leave a half-attached
        // filesystem behind on the very path the user is being told about.
        let _ = check();
    }

    // ── The Linux/BSD decision, over machines this host may not be ──────────

    #[test]
    fn a_machine_with_both_halves_of_fuse_is_ready_and_one_without_is_not() {
        assert_eq!(
            decide(&Machine {
                device: true,
                unmount_helper: true
            }),
            Readiness::Ready
        );

        // The device is checked first, because its absence is the cause that
        // makes the helper's presence irrelevant.
        let (reason, remedy) = unavailable(decide(&Machine {
            device: false,
            unmount_helper: true,
        }));
        assert!(reason.contains(FUSE_DEVICE), "{reason}");
        assert!(remedy.contains("modprobe"), "{remedy}");

        // And the helper's absence must not be reported as a missing kernel
        // module: telling somebody to `modprobe fuse` on a machine that already
        // has `/dev/fuse` is the wrong-place advice this module exists to stop.
        let (reason, remedy) = unavailable(decide(&Machine {
            device: true,
            unmount_helper: false,
        }));
        assert!(reason.contains(UNMOUNT_HELPER), "{reason}");
        assert!(
            remedy.contains("the kernel side is ready"),
            "a present device must be acknowledged: {remedy}"
        );
    }

    #[test]
    fn the_observation_agrees_with_the_filesystem_it_looked_at() {
        // The observation half, on whatever this machine happens to be: it must
        // report what is there, never what a Linux box usually has.
        let observed = Machine::observe();
        assert_eq!(observed.device, Path::new(FUSE_DEVICE).exists());
        assert_eq!(observed.unmount_helper, which(UNMOUNT_HELPER).is_some());
        if !cfg!(target_os = "macos") {
            assert_eq!(check(), decide(&observed));
        }
    }

    #[test]
    fn the_macos_observation_agrees_with_the_filesystem_it_looked_at() {
        // The same rule for the macFUSE half: report what is there. On Linux
        // none of the three paths exists, which is a state worth exercising —
        // it is the one a container has, and it must describe an uninstalled
        // machine rather than fail.
        let observed = Macfuse::observe();
        assert_eq!(observed.installed, Path::new(MACFUSE_BUNDLE).exists());
        assert_eq!(observed.loaded, Path::new(MACFUSE_DEVICE).exists());
        assert_eq!(observed.helper, Path::new(MOUNT_MACFUSE_HELPER).exists());
        if cfg!(target_os = "macos") {
            assert_eq!(check(), decide_macos(&observed));
        }
    }

    // ── The macOS decision, on every platform ───────────────────────────────

    #[test]
    fn a_working_macfuse_is_ready_and_the_change_from_never_is_deliberate() {
        // This test replaces `macos_never_claims_to_be_ready`, which existed so
        // that the day macOS became mountable the change would have to be made
        // on purpose. This is that change, made on purpose: `fuser` is built
        // with `macos-no-mount` and `super::macfuse` performs the mount through
        // macFUSE's own setuid helper, so a machine with the extension loaded
        // and the helper present really can mount.
        //
        // Whole machine states are enumerated rather than the one this host
        // happens to be, which is strictly more than a macOS runner could offer.
        assert_eq!(decide_macos(&working()), Readiness::Ready);
        // Ready is earned by all three, and by nothing less. Any missing piece
        // is a refusal, whatever the other two say.
        for installed in [false, true] {
            for loaded in [false, true] {
                for helper in [false, true] {
                    let described = macfuse(installed, loaded, helper, Some("5.3.3"));
                    assert_eq!(
                        decide_macos(&described) == Readiness::Ready,
                        installed && loaded && helper,
                        "the verdict does not match the machine: {described:?}"
                    );
                }
            }
        }
        // The version is a label on a message, never a gate. A macFUSE that does
        // not say what it is still mounts, and refusing over an unreadable plist
        // would be inventing a problem out of a missing string.
        for version in [None, Some("4.5.0"), Some("not-a-version")] {
            let mut described = working();
            described.version = version.map(str::to_string);
            assert_eq!(decide_macos(&described), Readiness::Ready, "{described:?}");
        }
    }

    #[test]
    fn a_loaded_extension_is_never_blamed() {
        // The regression this module was written for, and it survives the macOS
        // backend becoming real. When the kernel extension is loaded, no message
        // may send the reader to System Settings — that advice cost an operator
        // two reboots and a boot-security downgrade for a problem it could not
        // have fixed.
        //
        // The machine that is loaded *and still cannot mount* is now the one
        // whose helper is missing, so that is the state described here. It is
        // also asserted across every remaining refusal, so the rule cannot be
        // reintroduced through a branch added later.
        for version in [None, Some("4.5.0"), Some("5.3.3")] {
            let (_, remedy) = unavailable(decide_macos(&macfuse(true, true, false, version)));
            assert!(
                remedy.contains("IS loaded"),
                "a loaded extension must be acknowledged: {remedy}"
            );
            assert!(
                !remedy.contains("System Settings"),
                "must not send the reader to approve something already approved: {remedy}"
            );
        }

        for installed in [false, true] {
            for helper in [false, true] {
                let described = macfuse(installed, true, helper, Some("5.3.3"));
                if let Readiness::Unavailable { remedy, .. } = decide_macos(&described) {
                    assert!(
                        !remedy.contains("System Settings"),
                        "a loaded extension was blamed for {described:?}: {remedy}"
                    );
                }
            }
        }
    }

    #[test]
    fn an_unloaded_extension_is_not_told_that_it_is_loaded() {
        // The inverse: where the extension genuinely is not loaded, the remedy
        // must not open by insisting that it is — and this is the one macOS case
        // where System Settings really is the answer, which is only safe to say
        // because the branch is reached solely when no device node exists.
        let (reason, remedy) =
            unavailable(decide_macos(&macfuse(true, false, true, Some("5.3.3"))));
        assert!(!remedy.contains("IS loaded"), "{remedy}");
        assert!(reason.contains("5.3.3"), "{reason}");
        assert!(
            remedy.contains("System Settings"),
            "an extension that really is unapproved needs the one step that helps: {remedy}"
        );
    }

    #[test]
    fn an_absent_macfuse_is_reported_as_absent_rather_than_as_unapproved() {
        // The two states call for different actions — install it, versus approve
        // what is installed — and the message that conflated them is what sent
        // an operator to re-approve a kernel extension they did not have.
        let (reason, remedy) = unavailable(decide_macos(&macfuse(false, false, false, None)));
        assert!(reason.contains("not installed"), "{reason}");
        assert!(
            !remedy.contains("System Settings"),
            "nothing to approve on a machine with no macFUSE: {remedy}"
        );
        assert!(remedy.contains("macfuse.io"), "{remedy}");
    }

    #[test]
    fn a_missing_mount_helper_is_named_rather_than_left_to_an_errno() {
        // The macOS counterpart of the missing `fusermount3` case. mount(2) is
        // root-only here, so the setuid helper is not an optimisation — without
        // it nothing can attach, and finding that out from a spawn failure would
        // be the guess-afterwards this module exists to stop.
        let (reason, remedy) =
            unavailable(decide_macos(&macfuse(true, true, false, Some("5.3.3"))));
        assert!(reason.contains(MOUNT_MACFUSE_HELPER), "{reason}");
        assert!(remedy.contains("Reinstall macFUSE"), "{remedy}");
    }

    // ── The plist scan, which is just string work ───────────────────────────

    #[test]
    fn the_version_scan_reads_the_field_it_is_looking_for() {
        let plist = "<?xml version=\"1.0\"?>\n<plist><dict>\
             <key>CFBundleName</key><string>macFUSE</string>\
             <key>CFBundleVersion</key><string> 5.0.3 </string>\
             </dict></plist>";
        assert_eq!(bundle_version(plist).as_deref(), Some("5.0.3"));
    }

    #[test]
    fn the_version_scan_yields_nothing_rather_than_a_wrong_answer() {
        // Every degenerate shape returns `None`, which makes the message less
        // specific and nothing worse. A scan that guessed would put a version
        // number the machine does not have into a refusal somebody acts on.
        for text in [
            "",
            "<plist><dict></dict></plist>",
            "<key>CFBundleVersion</key>",
            "<key>CFBundleVersion</key><string>5.0.3",
            "<string>5.0.3</string><key>CFBundleVersion</key>",
        ] {
            assert_eq!(bundle_version(text), None, "{text:?}");
        }
    }

    #[test]
    fn the_version_scan_survives_a_missing_or_odd_plist_on_disk() {
        // Returns None rather than failing; the message degrades, nothing else.
        // Runs everywhere now, where it used to be macOS-only — which is to say
        // it used to run nowhere.
        let _ = installed_version();
    }
}
