//! The platform's memory page, and rounding to it.
//!
//! Both syscalls this crate makes are page-scoped, and they do not agree about
//! what to do when the caller is careless. Linux's `mlock` rounds the address
//! **down** to the enclosing page and locks whole pages; `madvise` refuses,
//! `EINVAL`, unless the address is already page-aligned. A 32-byte `malloc`
//! satisfies neither by accident: a heap allocation is aligned to 8 or 16 bytes,
//! never to 4096.
//!
//! That single difference is why [`crate::lock_memory`]'s `mlock` succeeded on
//! every Linux host while its `madvise(MADV_DONTDUMP)` failed on every Linux
//! host — for every secret, in every build, since the call was written. Measured
//! on the machine that reported it: `malloc(32)` at `0x10d242b0`, `mlock -> 0`,
//! `madvise(MADV_DONTDUMP) -> -1 EINVAL`, and the same `madvise` over the
//! page-rounded region `-> 0`. Nothing about the host was unusual; `ulimit -c` was
//! `unlimited` and `core_pattern` piped to `systemd-coredump`, so the root key
//! genuinely could reach a core file.
//!
//! So this crate rounds instead of hoping. Secrets are allocated on their own
//! whole pages ([`crate::LockedSecret`]), which is what makes both calls exact:
//! `madvise` gets an address it accepts, and neither `mlock` nor `MADV_DONTDUMP`
//! spills onto a neighbouring allocation that never asked to be pinned or hidden.

use std::sync::OnceLock;

/// Assumed page size when the platform will not say.
///
/// 4 KiB is the page size of every target this crate builds for. It is a
/// fallback and not a constant to compute with — [`size`] asks the OS first —
/// but a wrong guess here degrades to over-allocating or under-covering a
/// region, so it is the most common value rather than the smallest.
const ASSUMED_PAGE_SIZE: usize = 4096;

/// The platform's page size, asked once and remembered.
///
/// Cached because it cannot change while a process runs, and because this is on
/// the path of every secret allocation.
#[must_use]
pub fn size() -> usize {
    static SIZE: OnceLock<usize> = OnceLock::new();
    *SIZE.get_or_init(|| {
        let probed = probe();
        // A page size must be a non-zero power of two for the rounding below to
        // be correct; anything else is a platform lying, and the assumption is
        // safer than arithmetic built on it.
        if probed.is_power_of_two() {
            probed
        } else {
            tracing::warn!(
                probed,
                "the platform reported an implausible page size; assuming {ASSUMED_PAGE_SIZE}"
            );
            ASSUMED_PAGE_SIZE
        }
    })
}

#[cfg(unix)]
fn probe() -> usize {
    // SAFETY: `sysconf` reads a static platform parameter and touches no caller
    // memory. A negative return means "no limit / unknown", handled below.
    let reported = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    usize::try_from(reported).unwrap_or(ASSUMED_PAGE_SIZE)
}

#[cfg(windows)]
fn probe() -> usize {
    #[repr(C)]
    struct SystemInfo {
        oem_id: u32,
        page_size: u32,
        minimum_application_address: *mut core::ffi::c_void,
        maximum_application_address: *mut core::ffi::c_void,
        active_processor_mask: usize,
        number_of_processors: u32,
        processor_type: u32,
        allocation_granularity: u32,
        processor_level: u16,
        processor_revision: u16,
    }
    unsafe extern "system" {
        fn GetSystemInfo(info: *mut SystemInfo);
    }
    let mut info = core::mem::MaybeUninit::<SystemInfo>::uninit();
    // SAFETY: `GetSystemInfo` fully initializes the struct it is given and reads
    // nothing from it; the pointer is to correctly-sized, correctly-aligned
    // stack storage owned here.
    let page_size = unsafe {
        GetSystemInfo(info.as_mut_ptr());
        info.assume_init().page_size
    };
    usize::try_from(page_size).unwrap_or(ASSUMED_PAGE_SIZE)
}

#[cfg(not(any(unix, windows)))]
const fn probe() -> usize {
    ASSUMED_PAGE_SIZE
}

/// `len` rounded up to a whole number of pages, and never zero.
///
/// Never zero because a zero-length allocation has no address to lock, advise or
/// wipe, and every caller here would then have to carry a branch for a secret
/// that holds nothing. One page costs 4 KiB and removes the branch.
///
/// Saturating rather than wrapping: a length within one page of `usize::MAX`
/// cannot be allocated on any machine, and the allocator refusing a huge request
/// is a better failure than arithmetic that quietly produces a small one.
#[must_use]
pub fn whole_pages(len: usize) -> usize {
    let page = size();
    let wanted = len.max(1);
    match wanted.checked_add(page - 1) {
        Some(padded) => (padded / page) * page,
        None => wanted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_page_size_is_a_plausible_power_of_two() {
        let page = size();
        assert!(
            page.is_power_of_two(),
            "page size {page} is not a power of two"
        );
        assert!(
            (512..=1 << 20).contains(&page),
            "implausible page size {page}"
        );
    }

    #[test]
    fn a_rounded_length_covers_the_request_and_lands_on_a_page_boundary() {
        let page = size();
        for len in [1, 2, 31, 32, page - 1, page, page + 1, 3 * page + 7] {
            let rounded = whole_pages(len);
            assert!(rounded >= len, "{len} rounded down to {rounded}");
            assert_eq!(
                rounded % page,
                0,
                "{len} rounded to {rounded}, not a whole page"
            );
            assert!(
                rounded - len < page,
                "{len} rounded to {rounded}, wasting a whole extra page"
            );
        }
    }

    #[test]
    fn a_secret_of_no_bytes_still_gets_a_page() {
        // There is no address to lock, advise or wipe in a zero-length
        // allocation, and every caller would need a branch for it. One page is
        // cheaper than the branch.
        assert_eq!(whole_pages(0), size());
    }
}
