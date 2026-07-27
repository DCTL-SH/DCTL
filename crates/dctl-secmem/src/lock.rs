//! Pin / unpin a memory region so the OS cannot page it to swap, and keep it out
//! of core dumps where the platform allows.
//!
//! ## The dump exclusion did not work, on any Linux host, ever
//!
//! `madvise(MADV_DONTDUMP)` requires a **page-aligned** address and returns
//! `EINVAL` otherwise. `mlock` does not: Linux rounds its address down to the
//! enclosing page. So a 32-byte heap allocation — which is what every
//! [`LockedSecret`](crate::LockedSecret) was, a `Box<[u8]>` at 8- or 16-byte
//! alignment — satisfied `mlock` and could never satisfy `madvise`.
//!
//! The failure was real and it was disclosed at `debug!`, three levels below
//! where anyone would see it, described in the code as "benign". It was not
//! benign and it was not environmental: measured on the reporting host,
//! `malloc(32)` gave `0x10d242b0`, `mlock` returned `0`, `madvise(MADV_DONTDUMP)`
//! returned `-1 EINVAL`, and the identical call over the page-rounded region
//! returned `0`. `ulimit -c` was `unlimited` and `/proc/sys/kernel/core_pattern`
//! piped to `systemd-coredump`, so a crash of `dctl` on that machine would have
//! written the 32-byte vault root key to disk.
//!
//! The fix is in the allocation, not here: [`LockedSecret`](crate::LockedSecret)
//! now owns whole pages of its own, so this module's calls are exact and cover
//! nothing but the secret. What is here is the second half — the failure is
//! reported at `warn!` alongside its `errno`, at the same level as an `mlock`
//! failure, because a key in a core dump and a key in swap are the same
//! compromise reached by two routes.

/// What the platform actually did for a region, as opposed to what was asked.
///
/// Returned rather than logged-and-forgotten, because "best effort" is only an
/// honest description if somebody can find out what the effort achieved. A
/// caller can ask a [`LockedSecret`](crate::LockedSecret) and a test can assert
/// on it, which is what stops a call that cannot succeed from sitting in the
/// tree looking like protection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Protection {
    /// Whether the primary page lock (`mlock` / `VirtualLock`) succeeded. `false`
    /// means the bytes may be written to swap, where they outlive the process.
    pub locked: bool,
    /// Whether the pages were kept out of core dumps.
    pub dumps: DumpExclusion,
}

/// Whether a region is excluded from core dumps, and whether this platform can
/// even express the question.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DumpExclusion {
    /// The pages are excluded (`madvise(MADV_DONTDUMP)` succeeded).
    Excluded,
    /// The platform offers no per-page exclusion, so dump policy is process-wide
    /// and this crate cannot narrow it. Not a failure: nothing was attempted,
    /// because there is nothing to attempt.
    Unavailable,
    /// The platform offers it and the call failed. The key can reach a core dump.
    Failed,
}

/// Pin a memory region in RAM (prevent swap paging) and, where the platform
/// supports it, exclude it from core dumps.
///
/// Applies, best-effort:
/// 1. `mlock` / `VirtualLock` — prevents swap paging (forensic recovery from disk).
/// 2. `madvise(MADV_DONTDUMP)` on Linux/Android — omits the pages from core dumps.
/// 3. `madvise(VM_BEHAVIOR_ZERO_WIRED_PAGES)` on Darwin — zero the wired pages on free.
///
/// **`ptr` must be page-aligned and `len` a whole number of pages** for step 2 to
/// succeed; see the module documentation for what happens otherwise, and
/// [`crate::page`] for the rounding. A caller that cannot arrange that still gets
/// step 1, and gets [`DumpExclusion::Failed`] rather than a quiet `debug!`.
///
/// Neither failure is fatal: the caller's `zeroize`-on-drop protection applies
/// regardless.
#[must_use]
pub fn lock_memory(ptr: *const u8, len: usize) -> Protection {
    if len == 0 || ptr.is_null() {
        return Protection {
            locked: false,
            dumps: DumpExclusion::Unavailable,
        };
    }

    #[cfg(unix)]
    {
        let addr = ptr as *const libc::c_void;

        // SAFETY: caller guarantees `ptr` points to `len` valid, owned bytes (checked
        // non-null / non-zero above); `mlock` only pins those pages and never writes.
        let locked = unsafe { libc::mlock(addr, len) } == 0;
        if !locked {
            // WARN, not DEBUG: an mlock failure means key bytes can reach swap and be
            // recovered from a stolen disk — an operational signal worth surfacing so
            // ops can raise RLIMIT_MEMLOCK on the affected platform.
            tracing::warn!(
                bytes = len,
                error = %std::io::Error::last_os_error(),
                "mlock failed — key material may be paged to swap; raise RLIMIT_MEMLOCK"
            );
        }

        Protection {
            locked,
            dumps: exclude_from_dumps(ptr, len),
        }
    }

    #[cfg(windows)]
    {
        // Rust 2024 requires `unsafe extern`; per-call safety is re-asserted below.
        unsafe extern "system" {
            fn VirtualLock(lpAddress: *const u8, dwSize: usize) -> i32;
        }
        // SAFETY: caller guarantees `ptr`..`ptr+len` is a valid owned region; VirtualLock
        // only pins it in the working set and does not modify its contents.
        let locked = unsafe { VirtualLock(ptr, len) } != 0;
        if !locked {
            tracing::warn!(
                bytes = len,
                "VirtualLock failed — key material may be paged to swap"
            );
        }
        Protection {
            locked,
            // Windows dump policy is per-process (`MiniDumpWriteDump` filters,
            // `WerRegisterExcludedMemoryBlock`), not per-page through this call.
            dumps: DumpExclusion::Unavailable,
        }
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = (ptr, len);
        tracing::debug!("memory locking unavailable on this platform");
        Protection {
            locked: false,
            dumps: DumpExclusion::Unavailable,
        }
    }
}

/// Keep `ptr`..`ptr+len` out of core dumps, where the platform can express that.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn exclude_from_dumps(ptr: *const u8, len: usize) -> DumpExclusion {
    /// `MADV_DONTDUMP` (`asm-generic/mman-common.h`). Not exposed by every `libc`
    /// release, so it is named here rather than assumed present.
    const MADV_DONTDUMP: libc::c_int = 16;

    // The kernel refuses a non-page-aligned address outright, and checking first
    // is what lets the log line name the actual reason instead of leaving a bare
    // `EINVAL` for somebody else to diagnose. This is the branch that used to be
    // taken by every secret in the process.
    if (ptr as usize) % crate::page::size() != 0 {
        tracing::warn!(
            bytes = len,
            "madvise(MADV_DONTDUMP) skipped: the region is not page-aligned, so the \
             kernel would refuse it — key material can reach a core dump"
        );
        return DumpExclusion::Failed;
    }

    // SAFETY: the region is the caller's, checked non-null and non-zero above;
    // `madvise` only sets a kernel hint on these pages and does not read or write
    // their contents.
    if unsafe { libc::madvise(ptr as *mut libc::c_void, len, MADV_DONTDUMP) } == 0 {
        return DumpExclusion::Excluded;
    }
    // WARN, not DEBUG. This used to be a `debug!` calling the failure benign, and
    // it was neither benign nor rare: it was every secret on every host.
    tracing::warn!(
        bytes = len,
        error = %std::io::Error::last_os_error(),
        "madvise(MADV_DONTDUMP) failed — key material can reach a core dump"
    );
    DumpExclusion::Failed
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn exclude_from_dumps(ptr: *const u8, len: usize) -> DumpExclusion {
    // VM_BEHAVIOR_ZERO_WIRED_PAGES = 6 (Darwin sys/mman.h): wired pages are zeroed
    // on free, so keys don't survive in freelist memory after Drop. Darwin has no
    // per-page dump exclusion at all, so this reports `Unavailable` however it
    // goes — it is a different property, and reporting it as `Excluded` would be
    // the same overstatement this module was rewritten to remove. Apple's dump
    // protection is `apple_harden_crash_reporter`, which is process-wide.
    const VM_BEHAVIOR_ZERO_WIRED_PAGES: libc::c_int = 6;
    // SAFETY: the region is the caller's, checked non-null and non-zero above;
    // `madvise` only sets a kernel behavior hint and does not touch the bytes.
    let advised =
        unsafe { libc::madvise(ptr as *mut libc::c_void, len, VM_BEHAVIOR_ZERO_WIRED_PAGES) } == 0;
    if !advised {
        tracing::debug!(bytes = len, "madvise(ZERO_WIRED_PAGES) failed on Darwin");
    }
    DumpExclusion::Unavailable
}

#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios"
    ))
))]
fn exclude_from_dumps(ptr: *const u8, len: usize) -> DumpExclusion {
    let _ = (ptr, len);
    DumpExclusion::Unavailable
}

/// Unpin a region previously pinned by [`lock_memory`], allowing paging again.
///
/// Call after the buffer has been zeroized, before its memory is freed. Optional —
/// the OS unlocks every page on process exit.
pub fn unlock_memory(ptr: *const u8, len: usize) {
    if len == 0 || ptr.is_null() {
        return;
    }

    #[cfg(unix)]
    {
        // SAFETY: `ptr`..`ptr+len` was previously locked by the caller via lock_memory;
        // munlock only clears the pin and never touches the bytes.
        unsafe {
            libc::munlock(ptr as *const libc::c_void, len);
        }
    }

    #[cfg(windows)]
    {
        unsafe extern "system" {
            fn VirtualUnlock(lpAddress: *const u8, dwSize: usize) -> i32;
        }
        // SAFETY: region was previously locked via VirtualLock; VirtualUnlock only clears
        // the pin and does not modify the bytes.
        unsafe {
            VirtualUnlock(ptr, len);
        }
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = (ptr, len);
    }
}
