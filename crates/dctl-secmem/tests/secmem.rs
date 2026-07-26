//! Behavioral tests for the secure-memory primitives. Locking is best-effort, so
//! these assert on observable behavior (contents, lengths, redaction, syscall safety)
//! rather than on whether a given environment grants `mlock`.

use dctl_secmem::{
    LockedSecret, apple_harden_crash_reporter, lock_memory, opportunistic_chunk_lock_enabled,
    rlimit_memlock_budget, unlock_memory,
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
    assert!(!lock_memory(std::ptr::null(), 0));
    assert!(!lock_memory(std::ptr::null(), 16));
    let buf = [0u8; 16];
    assert!(!lock_memory(buf.as_ptr(), 0));
}

#[test]
fn lock_unlock_real_region_is_non_fatal() {
    let buf = [0u8; 4096];
    // May succeed or fail depending on RLIMIT_MEMLOCK / platform — must never panic.
    let _locked = lock_memory(buf.as_ptr(), buf.len());
    unlock_memory(buf.as_ptr(), buf.len());
}

#[test]
fn os_probes_are_safe() {
    let _ = rlimit_memlock_budget();
    let _ = opportunistic_chunk_lock_enabled();
    // No-op in debug / non-Apple; must link and not panic.
    apple_harden_crash_reporter();
}
