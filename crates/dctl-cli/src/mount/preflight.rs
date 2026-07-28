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
//! `fuser` — the only maintained Rust FUSE binding, at its latest release —
//! probes for macFUSE with `pkg-config … probe("fuse") // for macFUSE 4.x` and
//! mounts through libfuse's `fuse_mount_compat25`. Against **macFUSE 5.x** that
//! call fails even for a filesystem with no options at all: a minimal `fuser`
//! program that mounts an empty struct fails identically, with no DCTL code
//! involved. rclone mounts on the same machine because it links no libfuse at
//! all and drives macFUSE through its own bindings.
//!
//! So macOS is refused, by name, with the real reason. `PLAN.md` §15 already
//! ranks **fuse-t** (NFS loopback, no kernel extension) and **FSKit** above
//! macFUSE for macOS, and this is the concrete argument for finishing that work
//! rather than chasing a binding that cannot reach the installed macFUSE.

use std::path::{Path, PathBuf};

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

// ── macOS: refused, with the real reason ───────────────────────────────────

/// First macFUSE device node. Its presence proves the kernel extension loaded,
/// which is exactly the thing the old hint told people to go and arrange.
const MACFUSE_DEVICE: &str = "/dev/macfuse0";

/// Where macFUSE reports its version.
const MACFUSE_BUNDLE: &str = "/Library/Filesystems/macfuse.fs";

/// The macFUSE generation `fuser`'s mount path targets.
///
/// Its build script probes with the comment `// for macFUSE 4.x`, and its
/// `fuse_mount_compat25` call fails against 5.x.
const FUSER_SUPPORTED_MACFUSE_MAJOR: u32 = 4;

/// What the macOS decision needs to know about a machine.
///
/// `installed` and `loaded` are deliberately separate. "Not installed" and
/// "installed but unreachable" call for completely different actions, and
/// conflating them is precisely how the message this module replaced misled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Macfuse {
    /// Whether the macFUSE bundle is present on disk.
    pub installed: bool,
    /// Whether a macFUSE device node exists — proof the kernel extension is
    /// loaded and approved.
    pub loaded: bool,
    /// The version macFUSE reports, when it can be read.
    pub version: Option<String>,
}

impl Macfuse {
    /// Look at the machine this process is running on.
    ///
    /// Compiled on every platform, not only macOS: anywhere else the paths do
    /// not exist and it describes an uninstalled machine, which costs two `stat`
    /// calls nothing outside a test ever makes. The gain is that
    /// [`decide_macos`] and the plist scan below are ordinary code the Linux
    /// gates compile, lint and run.
    #[must_use]
    pub fn observe() -> Self {
        Self {
            installed: Path::new(MACFUSE_BUNDLE).exists(),
            loaded: Path::new(MACFUSE_DEVICE).exists(),
            version: installed_version(),
        }
    }
}

/// Decide what a described macOS machine can do. Pure; no I/O.
///
/// Never returns [`Readiness::Ready`], and that is the point rather than an
/// oversight: no macOS configuration this build can reach is mountable. The
/// property is asserted directly, over every machine state — including the ones
/// the machine running the tests does not have.
#[must_use]
pub fn decide_macos(macfuse: &Macfuse) -> Readiness {
    // Reported separately from the incompatibility below, because "not
    // installed" and "installed but unreachable" call for completely different
    // actions, and conflating them is how the previous message misled.
    if !macfuse.installed {
        return Readiness::Unavailable {
            reason: "macFUSE is not installed, and this build has no other macOS \
                     filesystem backend"
                .to_string(),
            remedy: MACOS_UNSUPPORTED_REMEDY.to_string(),
        };
    }

    let major = macfuse
        .version
        .as_deref()
        .and_then(|v| v.split('.').next())
        .and_then(|major| major.parse::<u32>().ok());

    // Everything below is a refusal. It is stated as one rather than attempted,
    // because attempting it produces an errno that cannot be told apart from a
    // genuine misconfiguration — which is the trap this module exists to close.
    Readiness::Unavailable {
        reason: match (&macfuse.version, major) {
            (Some(v), Some(major)) if major > FUSER_SUPPORTED_MACFUSE_MAJOR => format!(
                "mounting on macOS is not supported by this build: macFUSE {v} is \
                 installed, and the Rust FUSE binding this build uses mounts only \
                 against macFUSE {FUSER_SUPPORTED_MACFUSE_MAJOR}.x"
            ),
            (Some(v), _) => format!(
                "mounting on macOS is not supported by this build (macFUSE {v} \
                 installed{})",
                if macfuse.loaded {
                    ", kernel extension loaded"
                } else {
                    ", kernel extension not loaded"
                }
            ),
            _ => "mounting on macOS is not supported by this build".to_string(),
        },
        remedy: format!(
            "{}{MACOS_UNSUPPORTED_REMEDY}",
            if macfuse.loaded {
                "The macFUSE kernel extension IS loaded and approved — that is not the \
                 problem, and no amount of re-approving it will help. The binding \
                 cannot drive this macFUSE generation: a filesystem with no options \
                 at all fails the same way. "
            } else {
                ""
            }
        ),
    }
}

/// What a macOS user should actually do. Named because it is repeated.
const MACOS_UNSUPPORTED_REMEDY: &str = "Mount on Linux, where the FUSE path this build uses works natively and needs \
     no kernel extension. macOS support is tracked as `PLAN.md` §15's kext-free \
     backends — fuse-t (NFS loopback) and FSKit — which are the right target \
     precisely because Apple keeps narrowing what a kernel extension may do.";

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
    fn macfuse(installed: bool, loaded: bool, version: Option<&str>) -> Macfuse {
        Macfuse {
            installed,
            loaded,
            version: version.map(str::to_string),
        }
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

    // ── The macOS decision, on every platform ───────────────────────────────

    #[test]
    fn macos_never_claims_to_be_ready() {
        // Stated as a test rather than a comment because the day this changes —
        // a fuse-t backend, or a fuser release that reaches macFUSE 5 — the
        // change must be deliberate, and this test is what makes it so.
        //
        // It used to be `#[cfg(target_os = "macos")]`, so it never ran where the
        // gates run. Every machine state is enumerated here instead, which is
        // strictly more than the single state a macOS runner could have offered.
        for installed in [false, true] {
            for loaded in [false, true] {
                for version in [None, Some("4.5.0"), Some("5.0.3"), Some("not-a-version")] {
                    let described = macfuse(installed, loaded, version);
                    assert_ne!(
                        decide_macos(&described),
                        Readiness::Ready,
                        "macOS must not report Ready for {described:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_loaded_extension_is_never_blamed() {
        // The regression this module was written for. When the kernel extension
        // is loaded, the message must say so and must not send the reader to
        // System Settings — that advice cost an operator two reboots and a
        // boot-security downgrade for a problem it could not have fixed.
        //
        // This test used to be `#[cfg(target_os = "macos")]` *and* to return
        // early when `/dev/macfuse0` was absent, so on the one platform where it
        // compiled it could still pass having asserted nothing. The loaded
        // machine is now described rather than required.
        for version in [None, Some("4.5.0"), Some("5.0.3")] {
            let (_, remedy) = unavailable(decide_macos(&macfuse(true, true, version)));
            assert!(
                remedy.contains("IS loaded"),
                "a loaded extension must be acknowledged: {remedy}"
            );
            assert!(
                !remedy.contains("System Settings"),
                "must not send the reader to approve something already approved: {remedy}"
            );
        }
    }

    #[test]
    fn an_unloaded_extension_is_not_told_that_it_is_loaded() {
        // The inverse, which the old test could not reach at all: where the
        // extension is genuinely not loaded, the remedy must not open by
        // insisting that it is.
        let (reason, remedy) = unavailable(decide_macos(&macfuse(true, false, Some("5.0.3"))));
        assert!(!remedy.contains("IS loaded"), "{remedy}");
        assert!(reason.contains("5.0.3"), "{reason}");
    }

    #[test]
    fn an_absent_macfuse_is_reported_as_absent_rather_than_as_incompatible() {
        // The two states call for different actions — install it, versus stop
        // trying on this platform — and the message that conflated them is what
        // sent an operator to re-approve a kernel extension they did not have.
        let (reason, _) = unavailable(decide_macos(&macfuse(false, false, None)));
        assert!(reason.contains("not installed"), "{reason}");
        assert!(!reason.contains("binding"), "{reason}");
    }

    #[test]
    fn a_macfuse_the_binding_cannot_drive_says_which_generation_it_can() {
        // A 5.x install is refused by *version*, and the supported major is
        // named so the reader can tell what would work.
        let (reason, _) = unavailable(decide_macos(&macfuse(true, true, Some("5.0.3"))));
        assert!(reason.contains("macFUSE 5.0.3"), "{reason}");
        assert!(
            reason.contains(&FUSER_SUPPORTED_MACFUSE_MAJOR.to_string()),
            "{reason}"
        );

        // A version this build cannot parse must not be presented as though the
        // major had been compared: it falls back to the general refusal.
        let (reason, _) = unavailable(decide_macos(&macfuse(true, false, Some("weird"))));
        assert!(reason.contains("macFUSE weird"), "{reason}");
        assert!(!reason.contains("mounts only"), "{reason}");
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
