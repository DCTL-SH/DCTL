//! Query the OS memory-locking budget (`RLIMIT_MEMLOCK`).

/// Maximum bytes this process may pin via `mlock`, or `None` if unknown.
///
/// On Unix, queries the soft `RLIMIT_MEMLOCK` (`RLIM_INFINITY` → `u64::MAX`).
/// Unprivileged Linux typically defaults to 64 KiB; macOS/iOS/Android budgets are
/// effectively unbounded. On Windows the limit is working-set-quota driven, so this
/// returns `None` and callers skip opportunistic locking by default.
#[must_use]
pub fn rlimit_memlock_budget() -> Option<u64> {
    #[cfg(unix)]
    {
        let mut rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `getrlimit` writes only into the fully-initialized `rlim` we pass by
        // pointer; the resource id is a valid libc constant.
        let ok = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut rlim) } == 0;
        if !ok {
            return None;
        }
        if rlim.rlim_cur == libc::RLIM_INFINITY {
            Some(u64::MAX)
        } else {
            // `rlim_t` is u64 on most targets (where this cast is a no-op) but its width
            // is platform-defined, so the cast is kept for portability.
            #[allow(clippy::unnecessary_cast)]
            Some(rlim.rlim_cur as u64)
        }
    }
    #[cfg(not(unix))]
    {
        None
    }
}

/// One-shot (cached) decision on whether per-chunk opportunistic locking is worth it.
///
/// Enabled only when the budget is ≥ 16 MiB; below that the streaming path would
/// exhaust the `mlock` budget and then noisily fail every subsequent call. Long-lived
/// key material is locked regardless of this gate.
#[must_use]
pub fn opportunistic_chunk_lock_enabled() -> bool {
    use std::sync::OnceLock;
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        let Some(budget) = rlimit_memlock_budget() else {
            tracing::info!("RLIMIT_MEMLOCK budget unknown — opportunistic chunk lock disabled");
            return false;
        };
        let enabled = budget >= 16 * 1024 * 1024;
        tracing::info!(
            budget,
            enabled,
            "RLIMIT_MEMLOCK budget probed for opportunistic chunk locking"
        );
        enabled
    })
}
