//! What one failed attempt saw, read off the error's *shape* and never off its
//! words.
//!
//! # Why not just match on the message
//!
//! Because it works, right up until somebody improves the wording. A rule
//! spelled `message.contains("503")` passes every test written the same day and
//! then stops firing the moment a message gains a prefix — silently, and in the
//! direction of not retrying, which is the direction nobody notices. So the
//! backends record what they observed in the error *type*
//! ([`StoreError::Provider`], [`StoreError::Transport`], [`StoreError::Io`]) and
//! this module reads it back.
//!
//! # The three things worth knowing
//!
//! * **Did anything answer at all?** A request that never got a response may
//!   never have reached the provider, which is the case retrying exists for.
//! * **What did it answer with?** A status, and the provider's own error code
//!   when the body carried one.
//! * **Did it ask us to wait?** A `Retry-After` the server actually sent always
//!   beats the client's schedule.
//!
//! Everything else — which key, which bucket, what the message said — belongs in
//! the report to the operator and not in this decision.

use std::time::Duration;

use crate::error::StoreError;

/// What one attempt observed when it failed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Observed {
    /// The HTTP status the provider answered with, or [`None`] when nothing
    /// answered.
    pub status: Option<u16>,
    /// The provider's own error code from the response body, when it sent one.
    pub code: Option<String>,
    /// The server's `Retry-After`, already parsed, when it sent one.
    pub retry_after: Option<Duration>,
    /// Whether the failure is one that another attempt could plausibly survive,
    /// independently of any status: a reset connection, a timed-out read, a
    /// filesystem that answered `EAGAIN`.
    pub transient: bool,
    /// How many attempts a *lower* layer has already made at this operation.
    ///
    /// [`None`] when nothing below has tried. B2's request-level driver fills
    /// this in, and it is what stops a six-attempt inner budget under a
    /// six-attempt outer one from becoming thirty-six — rclone marks the same
    /// idea on the error itself (`fs/fserrors/error.go:218`,
    /// `NoLowLevelRetryError`).
    pub already_attempted: Option<u32>,
}

impl Observed {
    /// A failure where nothing answered — a connect that never completed, a
    /// timeout, a connection reset mid-body.
    #[must_use]
    pub const fn transport() -> Self {
        Self {
            status: None,
            code: None,
            retry_after: None,
            transient: true,
            already_attempted: None,
        }
    }

    /// A provider that answered with `status`.
    #[must_use]
    pub const fn status(status: u16) -> Self {
        Self {
            status: Some(status),
            code: None,
            retry_after: None,
            transient: false,
            already_attempted: None,
        }
    }

    /// A failure nothing about which suggests another attempt would differ.
    #[must_use]
    pub const fn terminal() -> Self {
        Self {
            status: None,
            code: None,
            retry_after: None,
            transient: false,
            already_attempted: None,
        }
    }

    /// Read the observation back off an error.
    ///
    /// The one place the mapping from "what DCTL reports" to "what the retry
    /// layer decides" lives, so a new [`StoreError`] variant has to be given an
    /// answer here rather than silently defaulting to whatever the wildcard arm
    /// happened to be. Every arm is written out for that reason.
    #[must_use]
    pub fn of(error: &StoreError) -> Self {
        match error {
            StoreError::Provider {
                status,
                code,
                retry_after_secs,
                ..
            } => Self {
                status: Some(*status),
                code: Some(code.clone()),
                retry_after: retry_after_secs.map(Duration::from_secs),
                transient: false,
                already_attempted: None,
            },

            StoreError::Transport { .. } => Self::transport(),

            // The errno decides, and the list is rclone's
            // (`fs/fserrors/retriable_errors.go`) plus the two `io` sentinels it
            // adds in `error.go:395`. A local filesystem rarely produces any of
            // them; a network mount produces them exactly when retrying helps.
            StoreError::Io(source) => Self {
                transient: is_transient_io(source),
                ..Self::terminal()
            },

            // Already tried. The count travels so the outer layer can decline to
            // spend a second budget on it and the operator is told the real
            // number.
            StoreError::Retried { attempts, source } => Self {
                already_attempted: Some(*attempts),
                ..Self::of(source)
            },

            // Everything below is a statement about the request, the key or the
            // data, and every one of them will be exactly as true next time.
            StoreError::NotFound(_)
            | StoreError::ChecksumMismatch { .. }
            | StoreError::ShortWrite { .. }
            | StoreError::InvalidKey(_)
            | StoreError::RangeOutOfBounds { .. }
            | StoreError::RootChanged { .. }
            // An unclassified backend failure is treated as permanent on
            // purpose. Guessing "temporary" for something nobody has classified
            // turns a clear failure into a slow one, and the remedy is to
            // classify it at the site that raised it — which is why the two
            // structured variants above exist.
            | StoreError::Backend(_) => Self::terminal(),
        }
    }
}

/// Whether an I/O error is one another attempt could survive.
///
/// The list is rclone's, cited rather than invented: `syscall.EPIPE`,
/// `ETIMEDOUT`, `ECONNREFUSED`, `EHOSTDOWN`, `EHOSTUNREACH`, `ECONNABORTED`,
/// `EAGAIN`, `EWOULDBLOCK`, `ECONNRESET`
/// (`fs/fserrors/retriable_errors.go:9-19`), plus `io.EOF` and
/// `io.ErrUnexpectedEOF` (`fs/fserrors/error.go:395-398`).
///
/// Matched on [`std::io::ErrorKind`] where the standard library names the
/// condition, and on the raw errno where it does not — `EAGAIN` has no stable
/// `ErrorKind` and is precisely the one a wedged network mount returns.
fn is_transient_io(error: &std::io::Error) -> bool {
    use std::io::ErrorKind;

    if matches!(
        error.kind(),
        ErrorKind::BrokenPipe
            | ErrorKind::TimedOut
            | ErrorKind::ConnectionRefused
            | ErrorKind::ConnectionAborted
            | ErrorKind::ConnectionReset
            | ErrorKind::HostUnreachable
            | ErrorKind::NetworkUnreachable
            | ErrorKind::NetworkDown
            | ErrorKind::WouldBlock
            | ErrorKind::Interrupted
            | ErrorKind::UnexpectedEof
    ) {
        return true;
    }

    // `EAGAIN` and `EWOULDBLOCK` are the same number on Linux and different on
    // some other Unixes, so both are named. `libc` is deliberately not a
    // dependency of this crate's library half — the numbers are ABI-stable and
    // naming them here costs one constant each.
    #[cfg(unix)]
    {
        // `EAGAIN` and `EWOULDBLOCK` are the same number on Linux, which is why
        // only one constant is named: writing both would be an unreachable arm
        // rather than extra coverage, and the compiler says so. On a platform
        // where they differ this is the one a wedged mount returns.
        const EAGAIN: i32 = 11;
        matches!(error.raw_os_error(), Some(EAGAIN))
    }
    #[cfg(not(unix))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_provider_answer_carries_its_status_code_and_wait() {
        let observed = Observed::of(&StoreError::Provider {
            backend: "s3",
            status: 503,
            code: "SlowDown".to_string(),
            retry_after_secs: Some(7),
        });
        assert_eq!(observed.status, Some(503));
        assert_eq!(observed.code.as_deref(), Some("SlowDown"));
        assert_eq!(observed.retry_after, Some(Duration::from_secs(7)));
    }

    #[test]
    fn nothing_answering_is_the_transport_case() {
        let observed = Observed::of(&StoreError::Transport {
            backend: "b2",
            detail: "connection reset".to_string(),
        });
        assert_eq!(observed.status, None);
        assert!(observed.transient);
    }

    #[test]
    fn the_errno_list_is_rclones_and_the_rest_are_permanent() {
        use std::io::{Error, ErrorKind};

        for kind in [
            ErrorKind::BrokenPipe,
            ErrorKind::TimedOut,
            ErrorKind::ConnectionRefused,
            ErrorKind::ConnectionAborted,
            ErrorKind::ConnectionReset,
            ErrorKind::UnexpectedEof,
            ErrorKind::Interrupted,
        ] {
            assert!(
                Observed::of(&StoreError::Io(Error::from(kind))).transient,
                "{kind:?} should be retryable"
            );
        }

        // The ones that must never be retried, and the reason each matters: a
        // full disk stays full, a missing file stays missing, and a permission
        // denial is not a wait.
        for kind in [
            ErrorKind::NotFound,
            ErrorKind::PermissionDenied,
            ErrorKind::InvalidInput,
            ErrorKind::AlreadyExists,
        ] {
            assert!(
                !Observed::of(&StoreError::Io(Error::from(kind))).transient,
                "{kind:?} must not be retried"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn eagain_is_retryable_even_though_it_has_no_error_kind() {
        // The case a `matches!` on `ErrorKind` alone silently drops, and the one
        // a wedged NFS mount actually produces.
        let again = std::io::Error::from_raw_os_error(11);
        assert!(Observed::of(&StoreError::Io(again)).transient);

        // ENOSPC is the counter-example that has to stay permanent: a full
        // filesystem is not a wait, and `HANDOVER.md` §16.1 is about the last
        // time DCTL mis-described it.
        let no_space = std::io::Error::from_raw_os_error(28);
        assert!(!Observed::of(&StoreError::Io(no_space)).transient);
    }

    #[test]
    fn an_unclassified_backend_failure_is_permanent() {
        // Deliberate. Guessing "temporary" for something nobody classified is
        // how a wrong credential became a run that backed off forever.
        assert!(!Observed::of(&StoreError::Backend("mystery".into())).transient);
        assert_eq!(
            Observed::of(&StoreError::Backend("mystery".into())).status,
            None
        );
    }

    #[test]
    fn a_record_of_earlier_attempts_travels_with_the_error_it_wraps() {
        let inner = StoreError::Provider {
            backend: "b2",
            status: 503,
            code: "service_unavailable".to_string(),
            retry_after_secs: None,
        };
        let observed = Observed::of(&StoreError::Retried {
            attempts: 6,
            source: Box::new(inner),
        });
        assert_eq!(observed.already_attempted, Some(6));
        // …and the observation underneath is still readable, so a second layer
        // can see *what* was already tried and not merely that something was.
        assert_eq!(observed.status, Some(503));
    }

    #[test]
    fn every_data_and_key_failure_is_permanent() {
        for error in [
            StoreError::NotFound("k".into()),
            StoreError::ChecksumMismatch {
                expected: "a".into(),
                actual: "b".into(),
            },
            StoreError::ShortWrite {
                expected: 10,
                actual: 4,
            },
            StoreError::InvalidKey("../x".into()),
            StoreError::RangeOutOfBounds { size: 4 },
            StoreError::RootChanged {
                root: "/srv".into(),
                detail: "has been removed",
            },
        ] {
            let observed = Observed::of(&error);
            assert!(!observed.transient, "{error}");
            assert_eq!(observed.status, None, "{error}");
        }
    }
}
