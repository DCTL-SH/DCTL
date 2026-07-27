//! Behavioral tests for the secure-memory primitives. Locking is best-effort, so
//! these assert on observable behavior (contents, lengths, redaction, syscall safety)
//! rather than on whether a given environment grants `mlock`.

use dctl_secmem::{
    DumpExclusion, LockedSecret, apple_harden_crash_reporter, lock_memory,
    opportunistic_chunk_lock_enabled, page, rlimit_memlock_budget, unlock_memory,
};

#[test]
fn locked_secret_fill_and_read() {
    let mut s = LockedSecret::zeroed(32);
    assert_eq!(s.len(), 32);
    assert!(!s.is_empty());
    assert_eq!(s.as_slice(), &[0u8; 32]);
    s.as_mut_slice().copy_from_slice(&[7u8; 32]);
    assert_eq!(s.as_slice(), &[7u8; 32]);
}

#[test]
fn from_slice_copies_exactly() {
    let src = [1u8, 2, 3, 4, 5];
    let s = LockedSecret::from_slice(&src);
    assert_eq!(s.as_slice(), &src);
    assert_eq!(s.len(), 5);
}

#[test]
fn empty_secret_is_valid() {
    let s = LockedSecret::zeroed(0);
    assert!(s.is_empty());
    assert_eq!(s.as_slice(), &[] as &[u8]);
    // Drop of an empty (unlocked) buffer must not fault.
    drop(s);
}

#[test]
fn debug_redacts_contents() {
    let s = LockedSecret::from_slice(b"super-secret-key-material");
    let rendered = format!("{s:?}");
    assert!(
        !rendered.contains("super-secret"),
        "debug leaked secret bytes: {rendered}"
    );
    assert!(rendered.contains("len"));
}

#[test]
fn lock_memory_rejects_null_and_zero() {
    assert!(!lock_memory(std::ptr::null(), 0).locked);
    assert!(!lock_memory(std::ptr::null(), 16).locked);
    let buf = [0u8; 16];
    assert!(!lock_memory(buf.as_ptr(), 0).locked);
}

#[test]
fn lock_unlock_real_region_is_non_fatal() {
    let buf = [0u8; 4096];
    // May succeed or fail depending on RLIMIT_MEMLOCK / platform — must never panic.
    let _locked = lock_memory(buf.as_ptr(), buf.len());
    unlock_memory(buf.as_ptr(), buf.len());
}

#[test]
fn a_secret_sits_on_its_own_pages() {
    // The property the whole fix rests on. `madvise(MADV_DONTDUMP)` refuses any
    // address that is not page-aligned, and a `Box<[u8]>` — which this used to be
    // — is aligned to 8 or 16 bytes. So the exclusion could never succeed, for
    // any secret, on any Linux host, and reported that at `debug!` as benign.
    let secret = LockedSecret::zeroed(32);
    let address = secret.as_slice().as_ptr() as usize;
    assert_eq!(
        address % page::size(),
        0,
        "a secret at {address:#x} is not page-aligned, so the dump exclusion cannot work"
    );
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn a_secret_is_kept_out_of_core_dumps_on_a_platform_that_can_do_it() {
    // Linux can express per-page dump exclusion, so "best effort" here means it
    // succeeded — not that it was attempted. This is the assertion that was
    // missing: the call failed on every run and nothing could tell.
    //
    // Deliberately not conditioned on `is_locked()`. `mlock` needs
    // RLIMIT_MEMLOCK budget and can legitimately fail in a container;
    // `MADV_DONTDUMP` needs nothing but a page-aligned address, so there is no
    // environment in which failing it is acceptable.
    let secret = LockedSecret::zeroed(32);
    assert_eq!(
        secret.dump_exclusion(),
        DumpExclusion::Excluded,
        "the root key can reach a core dump: {secret:?}"
    );
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
#[test]
fn a_platform_without_per_page_exclusion_says_so_rather_than_claiming_success() {
    // The honest answer where the mechanism does not exist. `Unavailable` is not
    // `Excluded`: nobody reading this may conclude the pages are hidden.
    let secret = LockedSecret::zeroed(32);
    assert_eq!(secret.dump_exclusion(), DumpExclusion::Unavailable);
}

#[test]
fn a_non_page_aligned_region_is_reported_as_failed_rather_than_excluded() {
    // The old state, asserted directly: hand `lock_memory` the shape a
    // `Box<[u8]>` had and it must report the exclusion as failed. A platform with
    // no per-page mechanism reports `Unavailable` for the same call, and the two
    // must never be confused — one is "we could not", the other "there is no we".
    let buf = vec![0u8; page::size() * 2];
    // SAFETY: one byte into a two-page allocation is inside it, so the pointer is
    // valid; nothing is read or written through it here.
    let misaligned = unsafe { buf.as_ptr().add(1) };
    let protection = lock_memory(misaligned, 64);
    unlock_memory(misaligned, 64);

    if cfg!(any(target_os = "linux", target_os = "android")) {
        assert_eq!(protection.dumps, DumpExclusion::Failed);
    } else {
        assert_eq!(protection.dumps, DumpExclusion::Unavailable);
    }
}

#[test]
fn a_secret_holds_its_bytes_across_the_whole_page_it_owns() {
    // Rounding the allocation up to a page must not change what the secret *is*:
    // the length is what was asked for, the contents are what was written, and
    // the padding is never visible.
    let mut secret = LockedSecret::zeroed(page::size() + 7);
    assert_eq!(secret.len(), page::size() + 7);
    secret.as_mut_slice().fill(0xAB);
    assert!(secret.as_slice().iter().all(|byte| *byte == 0xAB));
    assert_eq!(secret.as_slice().len(), page::size() + 7);
}

#[test]
fn os_probes_are_safe() {
    let _ = rlimit_memlock_budget();
    let _ = opportunistic_chunk_lock_enabled();
    // No-op in debug / non-Apple; must link and not panic.
    apple_harden_crash_reporter();
}
