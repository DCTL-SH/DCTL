//! Pin / unpin a memory region so the OS cannot page it to swap.

/// Pin a memory region in RAM (prevent swap paging) and, where the platform
/// supports it, exclude it from core dumps.
///
/// Applies, best-effort:
/// 1. `mlock` / `VirtualLock` — prevents swap paging (forensic recovery from disk).
/// 2. `madvise(MADV_DONTDUMP)` on Linux/Android — omits the pages from core dumps.
/// 3. `madvise(VM_BEHAVIOR_ZERO_WIRED_PAGES)` on Darwin — zero the wired pages on free.
///
/// Returns `true` iff the primary lock (`mlock`/`VirtualLock`) succeeded. A `false`
/// return is non-fatal: the caller's `zeroize`-on-drop protection still applies.
#[must_use]
pub fn lock_memory(ptr: *const u8, len: usize) -> bool {
    if len == 0 || ptr.is_null() {
        return false;
    }

    #[cfg(unix)]
    {
        let addr = ptr as *const libc::c_void;

        // SAFETY: caller guarantees `ptr` points to `len` valid, owned bytes (checked
        // non-null / non-zero above); `mlock` only pins those pages and never writes.
        let mlock_ok = unsafe { libc::mlock(addr, len) } == 0;
        if !mlock_ok {
            // WARN, not DEBUG: an mlock failure means key bytes can reach swap and be
            // recovered from a stolen disk — an operational signal worth surfacing so
            // ops can raise RLIMIT_MEMLOCK on the affected platform.
            tracing::warn!(
                bytes = len,
                error = %std::io::Error::last_os_error(),
                "mlock failed — key material may be paged to swap; raise RLIMIT_MEMLOCK"
            );
        }

        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            const MADV_DONTDUMP: libc::c_int = 16;
            // SAFETY: same region as above; `madvise` only sets a kernel hint on these
            // pages and does not read or write their contents.
            let advise_ok =
                unsafe { libc::madvise(addr as *mut libc::c_void, len, MADV_DONTDUMP) } == 0;
            if !advise_ok {
                tracing::debug!(
                    bytes = len,
                    "madvise(MADV_DONTDUMP) failed — key may appear in core dumps"
                );
            }
        }

        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            // VM_BEHAVIOR_ZERO_WIRED_PAGES = 6 (Darwin sys/mman.h): wired pages are zeroed
            // on free, so keys don't survive in freelist memory after Drop. Darwin has no
            // per-page MADV_DONTDUMP; some sandbox profiles deny this — failure is benign.
            const VM_BEHAVIOR_ZERO_WIRED_PAGES: libc::c_int = 6;
            // SAFETY: same region as above; `madvise` only sets a kernel behavior hint.
            let advise_ok = unsafe {
                libc::madvise(addr as *mut libc::c_void, len, VM_BEHAVIOR_ZERO_WIRED_PAGES)
            } == 0;
            if !advise_ok {
                tracing::debug!(bytes = len, "madvise(ZERO_WIRED_PAGES) failed on Darwin");
            }
        }

        mlock_ok
    }

    #[cfg(windows)]
    {
        // Rust 2024 requires `unsafe extern`; per-call safety is re-asserted below.
        unsafe extern "system" {
            fn VirtualLock(lpAddress: *const u8, dwSize: usize) -> i32;
        }
        // SAFETY: caller guarantees `ptr`..`ptr+len` is a valid owned region; VirtualLock
        // only pins it in the working set and does not modify its contents.
        let ok = unsafe { VirtualLock(ptr, len) } != 0;
        if !ok {
            tracing::debug!(
                bytes = len,
                "VirtualLock failed — key material may be paged to swap"
            );
        }
        ok
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = (ptr, len);
        tracing::debug!("memory locking unavailable on this platform");
        false
    }
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
