//! Turning a DCTL failure into the number a system call can return.
//!
//! A filesystem has one channel for failure and it is three bits wide by the
//! standards of this codebase: an `errno`. Everything DCTL knows how to say about
//! a failure — the classified [`ExitCode`], the message, the remediation hint —
//! collapses to a single integer by the time `read(2)` returns, and a program
//! reading through the mount sees only that integer.
//!
//! So the mapping is made once, here, rather than at each of the eight callbacks.
//! Two properties matter and neither survives being decided ad hoc:
//!
//! * **An integrity failure must not look like an ordinary I/O error to the
//!   *log*.** The errno has to be `EIO` — there is no "these bytes were forged"
//!   errno, and inventing one would make readers fail in ways they do not handle
//!   — but the record written beside it says exactly which it was. That is the
//!   only place the distinction can survive, so [`from_error`] logs before it
//!   converts, and the caller does not have to remember to.
//! * **"Not there" must never become `EIO`.** A missing object is `ENOENT`, which
//!   is what every caller in the world handles correctly; reporting it as a
//!   device error turns a `ls` of a file that was deleted on another machine into
//!   an apparent hardware fault.
//!
//! ## Why `ENOSYS` appears nowhere here
//!
//! `ENOSYS` from a FUSE callback tells the *kernel* the filesystem does not
//! implement that operation, and the kernel remembers: it stops sending that
//! operation for the life of the mount. That is right for an optional feature and
//! wrong for a refusal — see [`super::refuse`], which answers `EROFS` precisely
//! so that every write attempt is refused individually and visibly rather than
//! being answered once and then silently absorbed by the kernel.

use fuser::Errno;

use crate::error::CliError;
use crate::exit::ExitCode;
use crate::logging::fields;

/// The errno a failed filesystem operation reports, with the reason logged.
///
/// `operation` and `path` name what was being attempted, because an errno on its
/// own is unactionable: `EIO` on a read tells an operator that something went
/// wrong somewhere in a vault, and the log record tells them it was chunk
/// authentication on one named file.
pub fn from_error(operation: &str, path: &str, error: &CliError) -> Errno {
    let errno = for_code(error.code());

    // Integrity is the one class that gets its own level. Everything else a mount
    // meets — a missing object, a provider timeout — is ordinary operational
    // noise on a network filesystem and would drown the case that matters if it
    // were logged as loudly.
    if error.code() == ExitCode::IntegrityFailure {
        tracing::error!(
            { fields::OP } = operation,
            { fields::PATH } = path,
            { fields::ERROR_CODE } = error.code().slug(),
            errno = errno_number(errno),
            "{}",
            error.message()
        );
    } else {
        tracing::debug!(
            { fields::OP } = operation,
            { fields::PATH } = path,
            { fields::ERROR_CODE } = error.code().slug(),
            errno = errno_number(errno),
            "{}",
            error.message()
        );
    }

    errno
}

/// The errno one classified exit code maps to.
///
/// Split out and pure so the table can be read — and tested — without building a
/// failure to carry it.
#[must_use]
pub const fn for_code(code: ExitCode) -> Errno {
    match code {
        // The object is not there. The one mapping that has to be exact: every
        // caller handles ENOENT, and none of them handles a device error for a
        // file that was simply deleted somewhere else.
        ExitCode::FileNotFound | ExitCode::DirNotFound => Errno::ENOENT,

        // The bytes came back wrong, or would not authenticate. There is no
        // errno for "forged", and EIO is what a POSIX filesystem returns when
        // the storage under it did not give back what it was given — which is
        // exactly the claim. The log record beside it keeps the distinction.
        ExitCode::IntegrityFailure | ExitCode::ChecksumMismatch => Errno::EIO,

        // The provider did not answer inside its retry budget. EAGAIN says
        // "this might work if you ask again", which is the truth about a network
        // that is merely down, and is distinguishable from EIO by a caller that
        // wants to retry.
        ExitCode::TemporaryError => Errno::EAGAIN,

        // The vault will not unlock, or the index cannot be read. Both mean the
        // mount can no longer answer for this path with any authority; EACCES is
        // the honest "you may not have this", and is not retryable.
        ExitCode::VaultLocked | ExitCode::IndexError => Errno::EACCES,

        // Something asked for was malformed — a name this filesystem cannot
        // represent, an offset that cannot be expressed.
        ExitCode::Usage => Errno::EINVAL,

        // Everything else. A read-only filesystem that cannot explain a failure
        // reports a device error rather than inventing a more specific one it
        // cannot stand behind.
        _ => Errno::EIO,
    }
}

/// The numeric value of an errno, for a log record.
///
/// A one-line wrapper so the log fields below read as `errno = errno_number(..)`
/// rather than reaching into `fuser`'s accessor at three call sites; the number
/// rather than the name because a log query filters on integers.
fn errno_number(errno: Errno) -> i32 {
    errno.code()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_object_is_enoent_and_never_a_device_error() {
        // The mapping a stale listing depends on: a file deleted from another
        // machine must read as absent, not as broken hardware.
        assert_eq!(for_code(ExitCode::FileNotFound), Errno::ENOENT);
        assert_eq!(for_code(ExitCode::DirNotFound), Errno::ENOENT);
        assert_ne!(for_code(ExitCode::FileNotFound), Errno::EIO);
    }

    #[test]
    fn bytes_that_failed_authentication_are_reported_as_io_errors() {
        // There is no errno for "forged". EIO is the closest true statement, and
        // the reason the log record beside it exists.
        assert_eq!(for_code(ExitCode::IntegrityFailure), Errno::EIO);
        assert_eq!(for_code(ExitCode::ChecksumMismatch), Errno::EIO);
    }

    #[test]
    fn a_provider_that_did_not_answer_is_retryable() {
        // Distinguishable from EIO on purpose: one of these is worth asking
        // again, and the other means the data is wrong.
        assert_eq!(for_code(ExitCode::TemporaryError), Errno::EAGAIN);
        assert_ne!(
            for_code(ExitCode::TemporaryError),
            for_code(ExitCode::IntegrityFailure)
        );
    }

    #[test]
    fn no_failure_maps_to_enosys() {
        // ENOSYS is remembered by the kernel for the life of the mount, which
        // would turn one failure into a permanently disabled operation.
        for code in [
            ExitCode::Success,
            ExitCode::Usage,
            ExitCode::Uncategorised,
            ExitCode::DirNotFound,
            ExitCode::FileNotFound,
            ExitCode::TemporaryError,
            ExitCode::PartialFailure,
            ExitCode::FatalError,
            ExitCode::ChecksumMismatch,
            ExitCode::IntegrityFailure,
            ExitCode::VaultLocked,
            ExitCode::IndexError,
            ExitCode::AuditChainBroken,
            ExitCode::Cancelled,
        ] {
            assert_ne!(for_code(code), Errno::ENOSYS, "{code:?}");
        }
    }

    #[test]
    fn an_unclassifiable_failure_still_produces_a_usable_errno() {
        // The `_` arm is reachable and must not be a hole: a caller has to get
        // *some* answer, or the operation hangs.
        assert_eq!(for_code(ExitCode::Uncategorised), Errno::EIO);
        assert_eq!(for_code(ExitCode::FatalError), Errno::EIO);
    }

    #[test]
    fn converting_a_real_error_logs_it_and_yields_its_errno() {
        let error = CliError::new(ExitCode::FileNotFound, "no such object");
        assert_eq!(from_error("read", "photos/a.jpg", &error), Errno::ENOENT);

        let integrity = CliError::new(ExitCode::IntegrityFailure, "chunk 3 failed to authenticate");
        assert_eq!(from_error("read", "photos/a.jpg", &integrity), Errno::EIO);
    }

    #[test]
    fn every_errno_renders_as_a_positive_number_for_the_log() {
        // The field is what a log query filters on; a zero would silently make
        // every failure look the same.
        for code in [
            ExitCode::FileNotFound,
            ExitCode::IntegrityFailure,
            ExitCode::TemporaryError,
            ExitCode::VaultLocked,
            ExitCode::Usage,
            ExitCode::Uncategorised,
        ] {
            assert!(errno_number(for_code(code)) > 0, "{code:?}");
        }
    }
}
