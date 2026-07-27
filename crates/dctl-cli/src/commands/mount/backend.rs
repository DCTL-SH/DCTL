//! Which filesystem layer a mount would attach through, per platform.
//!
//! Straight out of `PLAN.md` §15, and recorded in code rather than only in prose
//! because the choice is the first thing a user needs to know: a mount fails on
//! a machine with no filesystem layer installed, and "install macFUSE" is a very
//! different answer from "your mountpoint is not empty".
//!
//! | OS      | Backend, in preference order      | Why that order |
//! |---------|-----------------------------------|----------------|
//! | Linux   | FUSE3 (`fuser`)                   | The only real option, and a good one: writeback cache, large `max_read`/`max_write`, multithreaded, big readahead. |
//! | macOS   | FSKit (15+) → fuse-t → macFUSE    | FSKit is Apple-sanctioned and needs no kernel extension, which is what makes it the 20-year-safe choice (`PLAN.md` §13.1). fuse-t also avoids a kext by tunnelling over NFS loopback. macFUSE is a kext: highest throughput, but it must be opt-in because a kext can be broken by any macOS release. |
//! | Windows | WinFSP                            | The mature FUSE-like layer. ProjFS is an option later for read-first streaming virtualisation. |
//!
//! The order is a *preference*, not a detection result: it is what `PLAN.md` §15
//! argues DCTL should reach for, in what order, and it is the roadmap rather
//! than the build.
//!
//! **What this build actually attaches through is a different question, and
//! [`attached`] is the one that answers it.** The two are not the same on macOS
//! and saying they were would be the kind of misreport `PLAN.md` §6 forbids: the
//! preference names FSKit first, and this build mounts through macFUSE, because
//! FSKit and fuse-t have no Rust binding and the crate DCTL uses (`fuser`) speaks
//! FUSE. A user reading "backend: FSKit" while a kernel extension was doing the
//! work would be told the opposite of what they need to know — FSKit needs no
//! kext, macFUSE is one, and that difference is the entire reason §15 ranks them
//! the way it does.
//!
//! So: [`preferred`] is where DCTL is going, [`attached`] is where it is, and
//! anything user-facing reports the second.

/// A filesystem layer DCTL can attach a mount through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MountBackend {
    /// Linux FUSE3, via the `fuser` crate.
    Fuse3,
    /// macOS FSKit, available from macOS 15.
    FsKit,
    /// macOS fuse-t: FUSE without a kernel extension, over NFS loopback.
    FuseT,
    /// macOS macFUSE: a kernel extension. Fastest, and the least future-proof.
    MacFuse,
    /// Windows WinFSP.
    WinFsp,
}

impl MountBackend {
    /// Stable slug for log records and machine-readable output.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Fuse3 => "fuse3",
            Self::FsKit => "fskit",
            Self::FuseT => "fuse-t",
            Self::MacFuse => "macfuse",
            Self::WinFsp => "winfsp",
        }
    }

    /// One line naming the backend as a human would say it.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::Fuse3 => "Linux FUSE3 (fuser)",
            Self::FsKit => "macOS FSKit (macOS 15+, no kernel extension)",
            Self::FuseT => "fuse-t (no kernel extension, NFS loopback)",
            Self::MacFuse => "macFUSE (kernel extension; opt-in, highest throughput)",
            Self::WinFsp => "WinFSP",
        }
    }
}

/// The backends DCTL would try on the platform it was built for, best first.
///
/// Empty on a platform DCTL has no mount story for, which is a fact worth
/// stating early rather than a case worth pretending about: on such a machine
/// the command can never succeed, whatever else is configured.
#[must_use]
pub fn preferred() -> &'static [MountBackend] {
    if cfg!(target_os = "linux") {
        &[MountBackend::Fuse3]
    } else if cfg!(target_os = "macos") {
        // FSKit first: Apple-sanctioned, no kext, and therefore the option most
        // likely to still work in twenty years (`PLAN.md` §13.1).
        &[
            MountBackend::FsKit,
            MountBackend::FuseT,
            MountBackend::MacFuse,
        ]
    } else if cfg!(target_os = "windows") {
        &[MountBackend::WinFsp]
    } else {
        &[]
    }
}

/// The backend DCTL *would* attach through first, if this platform has one.
///
/// The head of [`preferred`], and therefore a statement about the roadmap. Use
/// [`attached`] for what a mount on this machine really uses.
#[must_use]
pub fn first_choice() -> Option<MountBackend> {
    preferred().first().copied()
}

/// The backend this build actually attaches a mount through.
///
/// [`None`] on a platform with no FUSE layer, where `dctl mount` refuses by name
/// rather than pretending.
///
/// macOS answers [`MountBackend::MacFuse`] and not [`MountBackend::FsKit`], which
/// is the whole reason this function exists beside [`first_choice`]. FSKit is
/// §15's preference and is Apple-sanctioned and kext-free; it has no Rust
/// binding, and neither does fuse-t, so what this build can link against is
/// macFUSE — a kernel extension. Reporting the preference as though it were the
/// implementation would tell a user their mount needs no kext when it needs one,
/// which is exactly backwards for anybody deciding whether to install it.
#[must_use]
pub fn attached() -> Option<MountBackend> {
    if cfg!(target_os = "linux") {
        Some(MountBackend::Fuse3)
    } else if cfg!(target_os = "macos") {
        Some(MountBackend::MacFuse)
    } else {
        None
    }
}

/// Why this build does not use the backend `PLAN.md` §15 prefers, if it does not.
///
/// [`None`] when preference and implementation agree, which is the case on Linux
/// and the case DCTL is working towards everywhere. A `Some` is printed beside
/// the backend so the gap is visible at the moment it matters — a user installing
/// a kernel extension deserves to know it is a stopgap and why.
#[must_use]
pub fn shortfall() -> Option<&'static str> {
    match (first_choice(), attached()) {
        (Some(preferred), Some(attached)) if preferred != attached => Some(
            "PLAN.md §15 prefers FSKit, which needs no kernel extension; neither it \
             nor fuse-t has a Rust binding, so this build attaches through macFUSE",
        ),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_platform_this_build_targets_has_a_mount_story() {
        // DCTL ships for these three; a build for one of them that offered no
        // backend would be a packaging mistake worth failing a test over.
        if cfg!(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "windows"
        )) {
            assert!(first_choice().is_some());
        }
    }

    #[test]
    fn macos_prefers_the_backend_that_needs_no_kernel_extension() {
        // The ordering PLAN.md §15 argues for: a kext is the fastest option and
        // the one most likely to be broken by a future macOS release, so it is
        // last rather than first.
        if cfg!(target_os = "macos") {
            assert_eq!(first_choice(), Some(MountBackend::FsKit));
            assert_eq!(preferred().last(), Some(&MountBackend::MacFuse));
            assert_eq!(preferred().len(), 3);
        }
    }

    #[test]
    fn each_platform_offers_only_its_own_backends() {
        if cfg!(target_os = "linux") {
            assert_eq!(preferred(), &[MountBackend::Fuse3][..]);
        }
        if cfg!(target_os = "windows") {
            assert_eq!(preferred(), &[MountBackend::WinFsp][..]);
        }
    }

    #[test]
    fn what_this_build_attaches_through_is_reported_and_not_the_preference() {
        // The misreport this pair exists to prevent: FSKit needs no kernel
        // extension and macFUSE is one, so naming the preference where the
        // implementation belongs tells a macOS user the opposite of what they
        // need in order to decide whether to install it.
        if cfg!(target_os = "macos") {
            assert_eq!(attached(), Some(MountBackend::MacFuse));
            assert_ne!(attached(), first_choice());
            assert!(
                shortfall().is_some_and(|reason| reason.contains("FSKit")),
                "the gap between preference and implementation must be stated"
            );
        }
        if cfg!(target_os = "linux") {
            assert_eq!(attached(), Some(MountBackend::Fuse3));
            assert_eq!(attached(), first_choice());
            assert_eq!(shortfall(), None, "there is no gap on Linux");
        }
        if cfg!(target_os = "windows") {
            assert_eq!(attached(), None, "no FUSE layer exists on Windows");
            assert_eq!(shortfall(), None);
        }
    }

    #[test]
    fn every_backend_has_a_distinct_slug_and_a_description() {
        let all = [
            MountBackend::Fuse3,
            MountBackend::FsKit,
            MountBackend::FuseT,
            MountBackend::MacFuse,
            MountBackend::WinFsp,
        ];
        let mut slugs: Vec<&str> = all.iter().map(|backend| backend.slug()).collect();
        slugs.sort_unstable();
        slugs.dedup();
        assert_eq!(slugs.len(), all.len(), "slugs must be unique");

        for backend in all {
            assert!(!backend.describe().is_empty());
            // Slugs go into log queries, so they stay machine-shaped.
            assert!(
                backend
                    .slug()
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
                "{} is not a slug",
                backend.slug()
            );
        }
    }
}
