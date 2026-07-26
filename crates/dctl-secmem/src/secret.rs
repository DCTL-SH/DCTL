//! A heap secret buffer, locked in RAM and zeroized on drop.

use core::fmt;

use zeroize::Zeroize;

use crate::lock::{lock_memory, unlock_memory};

/// A fixed-size heap byte buffer that is `mlock`-pinned on construction and
/// unlocked + zeroized on drop.
///
/// Heap allocation (not the stack) gives the pages a stable address to lock, and the
/// boxed slice never reallocates, so the lock stays valid for the buffer's lifetime.
/// Holds long-lived key material (root key, sub-keys, DEKs, KEK). Never `Clone` —
/// duplicating a secret must be an explicit, auditable act.
pub struct LockedSecret {
    buf: Box<[u8]>,
    locked: bool,
}

impl LockedSecret {
    /// Allocate `len` zeroed, locked bytes; fill via [`Self::as_mut_slice`].
    #[must_use]
    pub fn zeroed(len: usize) -> Self {
        let buf = vec![0u8; len].into_boxed_slice();
        let locked = lock_memory(buf.as_ptr(), buf.len());
        Self { buf, locked }
    }

    /// Copy `src` into a freshly locked buffer.
    #[must_use]
    pub fn from_slice(src: &[u8]) -> Self {
        let mut s = Self::zeroed(src.len());
        s.buf.copy_from_slice(src);
        s
    }

    /// Whether the primary page lock (`mlock`/`VirtualLock`) succeeded. `false` means
    /// only the zeroize-on-drop protection is active (see crate docs).
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Read the secret bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    /// Mutable access, e.g. to fill a freshly-[`zeroed`](Self::zeroed) buffer.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buf
    }
}

impl Drop for LockedSecret {
    fn drop(&mut self) {
        self.buf.zeroize();
        if self.locked {
            unlock_memory(self.buf.as_ptr(), self.buf.len());
        }
    }
}

// Never expose secret contents through formatting.
impl fmt::Debug for LockedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LockedSecret")
            .field("len", &self.buf.len())
            .field("locked", &self.locked)
            .finish_non_exhaustive()
    }
}
