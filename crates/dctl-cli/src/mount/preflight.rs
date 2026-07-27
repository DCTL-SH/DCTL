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

use std::path::Path;

use crate::error::{CliError, Result};
use crate::exit::ExitCode;

/// Whether this build can mount here, and why not when it cannot.
#[derive(Debug, PartialEq, Eq)]
pub enum Readiness {
    /// FUSE is present and this platform's mount path is supported.
    ///
    /// Never constructed on macOS, which is the point rather than an oversight:
    /// no macOS configuration this build can reach is mountable, and
    /// `macos_never_claims_to_be_ready` fails if that ever silently changes. The
    /// allow is scoped to the variant and to macOS, so the same variant staying
    /// unconstructed on Linux — where it is the normal outcome — would still be
    /// caught.
    #[cfg_attr(target_os = "macos", allow(dead_code))]
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
#[must_use]
pub fn check() -> Readiness {
    platform_check()
}

// ── Linux and the BSDs: the pure-Rust path, which genuinely works ───────────

#[cfg(not(target_os = "macos"))]
fn platform_check() -> Readiness {
    // `fuser` builds its pure-Rust mount path here, which talks to `/dev/fuse`
    // directly and shells out to `fusermount3` only to detach. Both are
    // observable, so both are checked rather than assumed.
    if !Path::new(FUSE_DEVICE).exists() {
        return Readiness::Unavailable {
            reason: format!("{FUSE_DEVICE} does not exist, so no filesystem can be mounted"),
            remedy: "Install the FUSE kernel module and userspace package (`fuse3` on \
                     most distributions) and load the module with `modprobe fuse`. In a \
                     container, the device must also be passed through — \
                     `--device /dev/fuse` and, on many runtimes, `--cap-add SYS_ADMIN`."
                .to_string(),
        };
    }

    if which(UNMOUNT_HELPER).is_none() {
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

/// The Linux FUSE character device.
#[cfg(not(target_os = "macos"))]
const FUSE_DEVICE: &str = "/dev/fuse";

/// The setuid helper that performs the detach.
#[cfg(not(target_os = "macos"))]
const UNMOUNT_HELPER: &str = "fusermount3";

/// Locate an executable on `PATH`.
#[cfg(not(target_os = "macos"))]
fn which(program: &str) -> Option<std::path::PathBuf> {
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|dir| dir.join(program))
            .find(|candidate| candidate.is_file())
    })
}

// ── macOS: refused, with the real reason ───────────────────────────────────

/// First macFUSE device node. Its presence proves the kernel extension loaded,
/// which is exactly the thing the old hint told people to go and arrange.
#[cfg(target_os = "macos")]
const MACFUSE_DEVICE: &str = "/dev/macfuse0";

/// Where macFUSE reports its version.
#[cfg(target_os = "macos")]
const MACFUSE_BUNDLE: &str = "/Library/Filesystems/macfuse.fs";

/// The macFUSE generation `fuser`'s mount path targets.
///
/// Its build script probes with the comment `// for macFUSE 4.x`, and its
/// `fuse_mount_compat25` call fails against 5.x.
#[cfg(target_os = "macos")]
const FUSER_SUPPORTED_MACFUSE_MAJOR: u32 = 4;

#[cfg(target_os = "macos")]
fn platform_check() -> Readiness {
    let installed = Path::new(MACFUSE_BUNDLE).exists();
    let loaded = Path::new(MACFUSE_DEVICE).exists();

    // Reported separately from the incompatibility below, because "not
    // installed" and "installed but unreachable" call for completely different
    // actions, and conflating them is how the previous message misled.
    if !installed {
        return Readiness::Unavailable {
            reason: "macFUSE is not installed, and this build has no other macOS \
                     filesystem backend"
                .to_string(),
            remedy: MACOS_UNSUPPORTED_REMEDY.to_string(),
        };
    }

    let version = macfuse_version();
    let major = version
        .as_deref()
        .and_then(|v| v.split('.').next())
        .and_then(|major| major.parse::<u32>().ok());

    // Everything below is a refusal. It is stated as one rather than attempted,
    // because attempting it produces an errno that cannot be told apart from a
    // genuine misconfiguration — which is the trap this module exists to close.
    Readiness::Unavailable {
        reason: match (&version, major) {
            (Some(v), Some(major)) if major > FUSER_SUPPORTED_MACFUSE_MAJOR => format!(
                "mounting on macOS is not supported by this build: macFUSE {v} is \
                 installed, and the Rust FUSE binding this build uses mounts only \
                 against macFUSE {FUSER_SUPPORTED_MACFUSE_MAJOR}.x"
            ),
            (Some(v), _) => format!(
                "mounting on macOS is not supported by this build (macFUSE {v} \
                 installed{})",
                if loaded {
                    ", kernel extension loaded"
                } else {
                    ", kernel extension not loaded"
                }
            ),
            _ => "mounting on macOS is not supported by this build".to_string(),
        },
        remedy: format!(
            "{}{MACOS_UNSUPPORTED_REMEDY}",
            if loaded {
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
#[cfg(target_os = "macos")]
const MACOS_UNSUPPORTED_REMEDY: &str = "Mount on Linux, where the FUSE path this build uses works natively and needs \
     no kernel extension. macOS support is tracked as `PLAN.md` §15's kext-free \
     backends — fuse-t (NFS loopback) and FSKit — which are the right target \
     precisely because Apple keeps narrowing what a kernel extension may do.";

/// macFUSE's installed version, if it can be read.
#[cfg(target_os = "macos")]
fn macfuse_version() -> Option<String> {
    let plist = Path::new(MACFUSE_BUNDLE)
        .join("Contents")
        .join("Info.plist");
    let text = std::fs::read_to_string(&plist).ok()?;

    // A minimal scan rather than a plist parser: this is one optional field used
    // to make a message more precise, and a whole dependency for it would be a
    // poor trade. Failure simply yields a less specific message.
    let key = text.find("<key>CFBundleVersion</key>")?;
    let open = text[key..].find("<string>")? + key + "<string>".len();
    let close = text[open..].find("</string>")? + open;
    Some(text[open..close].trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_never_claims_to_be_ready() {
        // Stated as a test rather than a comment because the day this changes —
        // a fuse-t backend, or a fuser release that reaches macFUSE 5 — the
        // change must be deliberate, and this test is what makes it so.
        assert_ne!(check(), Readiness::Ready);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_loaded_extension_is_never_blamed() {
        // The regression this module was written for. When the kernel extension
        // is loaded, the message must say so and must not send the reader to
        // System Settings — that advice cost an operator two reboots and a
        // boot-security downgrade for a problem it could not have fixed.
        if !std::path::Path::new(MACFUSE_DEVICE).exists() {
            return; // extension not loaded here; nothing to assert
        }
        let Readiness::Unavailable { remedy, .. } = check() else {
            panic!("macOS must not report Ready");
        };
        assert!(
            remedy.contains("IS loaded"),
            "a loaded extension must be acknowledged: {remedy}"
        );
        assert!(
            !remedy.contains("System Settings"),
            "must not send the reader to approve something already approved: {remedy}"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_version_scan_survives_a_missing_or_odd_plist() {
        // Returns None rather than panicking; the message degrades, nothing else.
        let _ = macfuse_version();
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn linux_readiness_tracks_the_device_that_is_really_there() {
        // Whatever this machine has, the verdict must agree with the filesystem
        // — never with an assumption about what a Linux box usually has.
        let verdict = check();
        if std::path::Path::new(FUSE_DEVICE).exists() && which(UNMOUNT_HELPER).is_some() {
            assert_eq!(verdict, Readiness::Ready);
        } else {
            assert_ne!(verdict, Readiness::Ready);
        }
    }
}
