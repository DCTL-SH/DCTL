//! A heap secret buffer, on pages of its own, locked in RAM and zeroized on drop.

use core::fmt;
use core::ptr::NonNull;
use core::slice;
use std::alloc::{Layout, alloc_zeroed, dealloc, handle_alloc_error};

use zeroize::Zeroize;

use crate::lock::{DumpExclusion, Protection, lock_memory, unlock_memory};
use crate::page;

/// A fixed-size byte buffer on **whole pages of its own**, `mlock`-pinned and
/// excluded from core dumps on construction, unlocked and zeroized on drop.
///
/// Holds long-lived key material (root key, sub-keys, DEKs, KEK). Never `Clone` —
/// duplicating a secret must be an explicit, auditable act.
///
/// ## Why it owns pages instead of a `Box<[u8]>`
///
/// It was a `vec![0u8; len].into_boxed_slice()`, which the allocator hands back
/// at 8- or 16-byte alignment. `mlock` tolerates that — Linux rounds the address
/// down to the enclosing page — but `madvise(MADV_DONTDUMP)` does not: it returns
/// `EINVAL` for any address that is not page-aligned. So the core-dump exclusion
/// **failed for every secret, on every Linux host, in every build**, and said so
/// only at `debug!`, in a line describing the failure as benign. On a host with
/// core dumps enabled — `ulimit -c unlimited` with a `systemd-coredump` handler
/// is the distribution default — a crash wrote the vault root key to disk.
///
/// A page-aligned, whole-page allocation is what makes both syscalls exact. It
/// also makes them *narrow*: rounding the address of a shared heap page instead
/// would pin and hide whatever else the allocator had placed on it, quietly
/// removing unrelated data from every core dump the process ever produced.
///
/// The cost is one page per secret. A vault holds three — the root key and the
/// two name-layer sub-keys — so 12 KiB, and `mlock` was already pinning a page
/// apiece, because a page is the unit the kernel locks in.
pub struct LockedSecret {
    /// Start of the allocation. Page-aligned, and the whole of `layout`.
    ptr: NonNull<u8>,
    /// Bytes the caller asked for; never more than `layout.size()`.
    len: usize,
    /// What was actually allocated — whole pages — kept for `dealloc`, which
    /// requires the same layout the allocation was made with.
    layout: Layout,
    /// What the platform did for these pages, as opposed to what was asked.
    protection: Protection,
}

// SAFETY: `LockedSecret` uniquely owns its allocation — the pointer is created
// here, never handed out, never copied, and freed exactly once in `Drop`. Shared
// access (`&self`) yields only `&[u8]`; the sole mutable path takes `&mut self`,
// so Rust's own borrow rules already exclude a data race. This is the same
// reasoning that makes the `Box<[u8]>` it replaces `Send + Sync`, which
// `dctl-core` relies on to hold a `&Vault` across an `.await`.
unsafe impl Send for LockedSecret {}
// SAFETY: see the `Send` impl above.
unsafe impl Sync for LockedSecret {}

impl LockedSecret {
    /// Allocate `len` zeroed, locked bytes on pages of their own; fill via
    /// [`Self::as_mut_slice`].
    ///
    /// Aborts on allocation failure, exactly as the `vec![0u8; len]` this
    /// replaces did. An abort is what Rust's allocator does with an
    /// out-of-memory condition, and a fallible constructor here would thread a
    /// `Result` through every key derivation to describe a state in which the
    /// process cannot continue anyway.
    #[must_use]
    pub fn zeroed(len: usize) -> Self {
        let bytes = page::whole_pages(len);
        // `page::size()` is a screened power of two and `whole_pages` returns a
        // non-zero multiple of it, so this layout is always constructible. The
        // fallback exists because `from_size_align` cannot know that, and it
        // aborts through the allocator's own path rather than through an
        // `unwrap` this crate forbids.
        let layout = Layout::from_size_align(bytes, page::size())
            .unwrap_or_else(|_| handle_alloc_error(Layout::new::<u8>()));

        // SAFETY: `layout` has a non-zero size (`whole_pages` never returns 0),
        // which is `alloc_zeroed`'s only precondition.
        let raw = unsafe { alloc_zeroed(layout) };
        let Some(ptr) = NonNull::new(raw) else {
            handle_alloc_error(layout)
        };

        // Locked over the *whole* allocation, which is what makes the region
        // page-aligned and page-sized — the two things `madvise(MADV_DONTDUMP)`
        // requires and a `Box<[u8]>` could never provide.
        let protection = lock_memory(ptr.as_ptr(), bytes);
        Self {
            ptr,
            len,
            layout,
            protection,
        }
    }

    /// Copy `src` into a freshly locked buffer.
    #[must_use]
    pub fn from_slice(src: &[u8]) -> Self {
        let mut s = Self::zeroed(src.len());
        s.as_mut_slice().copy_from_slice(src);
        s
    }

    /// Whether the primary page lock (`mlock`/`VirtualLock`) succeeded. `false` means
    /// only the zeroize-on-drop protection is active (see crate docs).
    #[must_use]
    pub const fn is_locked(&self) -> bool {
        self.protection.locked
    }

    /// Whether these pages are kept out of core dumps, and whether the platform
    /// can express the question at all.
    ///
    /// Exposed so the claim is checkable rather than merely made. A syscall that
    /// cannot succeed looks exactly like one that does until something can ask.
    #[must_use]
    pub const fn dump_exclusion(&self) -> DumpExclusion {
        self.protection.dumps
    }

    /// Length in bytes — what the caller asked for, not what was allocated.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the buffer is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Read the secret bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: `ptr` is a live allocation of `layout.size() >= len` initialized
        // bytes owned by this value, and `&self` borrows it for the returned
        // slice's lifetime, so no `&mut` can coexist.
        unsafe { slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    /// Mutable access, e.g. to fill a freshly-[`zeroed`](Self::zeroed) buffer.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: as `as_slice`, and `&mut self` guarantees this is the only
        // outstanding reference to the allocation.
        unsafe { slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
}

impl Drop for LockedSecret {
    fn drop(&mut self) {
        // Wipe the whole allocation rather than the requested length. The tail is
        // zero today because `alloc_zeroed` made it so, but the invariant worth
        // holding is "no byte of this allocation survives the drop", and that one
        // is still true after somebody writes past `len`.
        //
        // SAFETY: `ptr` is a live allocation of `layout.size()` bytes owned by
        // this value, and `&mut self` in `drop` makes this the only reference.
        unsafe { slice::from_raw_parts_mut(self.ptr.as_ptr(), self.layout.size()) }.zeroize();

        if self.protection.locked {
            unlock_memory(self.ptr.as_ptr(), self.layout.size());
        }

        // SAFETY: `ptr` came from `alloc_zeroed` with exactly this `layout` and
        // has not been freed; `Drop` runs once.
        unsafe { dealloc(self.ptr.as_ptr(), self.layout) };
    }
}

// Never expose secret contents through formatting.
impl fmt::Debug for LockedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LockedSecret")
            .field("len", &self.len)
            .field("locked", &self.protection.locked)
            .field("dumps", &self.protection.dumps)
            .finish_non_exhaustive()
    }
}
