//! Apple process hardening: deny debugger attachment in release builds.

/// On Apple release builds, install `PT_DENY_ATTACH` so a forensic actor with
/// physical access to an unlocked device cannot attach `lldb` and dump key memory
/// at runtime. Idempotent; a no-op on other platforms and in debug builds.
///
/// Trade-off: the process becomes non-debuggable in release. Call once at startup,
/// before any debugger could attach. Teams targeting the App Store may prefer the
/// exception-port redirect instead (requires CoreFoundation linkage).
pub fn apple_harden_crash_reporter() {
    #[cfg(all(any(target_os = "macos", target_os = "ios"), not(debug_assertions)))]
    {
        // PT_DENY_ATTACH = 31 (Darwin sys/ptrace.h).
        const PT_DENY_ATTACH: libc::c_int = 31;
        // ptrace(int request, pid_t pid, caddr_t addr, int data)
        unsafe extern "C" {
            fn ptrace(
                request: libc::c_int,
                pid: libc::pid_t,
                addr: *mut libc::c_char,
                data: libc::c_int,
            ) -> libc::c_int;
        }
        // SAFETY: PT_DENY_ATTACH takes no address/data operands; passing a null addr and
        // 0 data is the documented invocation and touches no caller memory.
        let result = unsafe { ptrace(PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) };
        if result != 0 {
            tracing::debug!(
                result,
                error = %std::io::Error::last_os_error(),
                "PT_DENY_ATTACH failed — debugger-attach protection may not be enforced"
            );
        } else {
            tracing::info!("PT_DENY_ATTACH installed — debugger attach will trap the process");
        }
    }
    #[cfg(not(all(any(target_os = "macos", target_os = "ios"), not(debug_assertions))))]
    {
        // compiled out on non-Apple targets and in debug builds
    }
}
