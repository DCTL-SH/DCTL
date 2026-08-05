//! Typed storage errors, and enough structure for the retry layer to classify
//! them without reading their words.
//!
//! Three of the variants below exist for [`crate::retry`] and are worth a line
//! each. [`StoreError::Provider`] is "the provider answered, and refused" and
//! carries the status, the provider's own error code and any `Retry-After`;
//! [`StoreError::Transport`] is "nothing answered", which is the case retrying
//! exists for; [`StoreError::Retried`] records that a layer already tried again,
//! and how many times, so the message an operator finally reads describes work
//! that really happened.
//!
//! [`StoreError::Backend`] stays for everything nobody has classified, and it is
//! deliberately treated as **permanent**: guessing "temporary" for an unknown
//! failure turns a clear error into a slow one. Anything worth retrying should
//! be raised as one of the two structured variants at the site that knows what
//! it saw.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum StoreError {
    /// The requested object does not exist.
    #[error("object not found: {0}")]
    NotFound(String),

    /// The named bucket is not listed by this account's credentials.
    ///
    /// Deliberately not [`StoreError::NotFound`], and the separation is the
    /// fix for a measured defect: a bucket-level miss minted as `NotFound`
    /// rode the object-absence rails — `init --force` against an existing
    /// empty bucket died "object not found: bucket X" exit 4, and the
    /// envelope probe's `NotFound → Absent` arm could read an *unlistable*
    /// store as an *empty* one, which is the exact "absence is a claim"
    /// violation that module documents. A bucket that cannot be listed is a
    /// fact about credentials and configuration, answered by the provider,
    /// never retried and never conflated with a missing object.
    #[error(
        "bucket {bucket} is not listed by this account's credentials; \
         nothing was read or written"
    )]
    BucketNotFound { bucket: String },

    /// The stored bytes did not match the expected content hash — a verified
    /// write refused to (or a verified read refused to accept) commit corruption.
    #[error("checksum mismatch: expected {expected}, got {actual}")]
    ChecksumMismatch { expected: String, actual: String },

    /// Fewer bytes reached the destination than were written to it.
    ///
    /// Kept apart from [`StoreError::ChecksumMismatch`] because the two send an
    /// operator to opposite places. A hash that differs over the *same* number
    /// of bytes is corruption: something changed the content. A file that is
    /// simply shorter than what was written is a write that stopped — a full
    /// filesystem, an exhausted quota, a device that went away — and the remedy
    /// is `df`, not a hunt for bit-rot.
    ///
    /// This is the backstop, not the diagnosis. The write path surfaces the real
    /// errno first ([`crate::durable`]); this fires only when the destination
    /// accepted every byte without complaint and then did not have them, which
    /// is a lying filesystem or a concurrent truncation. Reporting *that* as a
    /// checksum mismatch is the misdiagnosis this variant exists to prevent.
    #[error("short write: {expected} bytes were written, {actual} landed")]
    ShortWrite { expected: u64, actual: u64 },

    /// The object key is malformed or unsafe (e.g. path traversal).
    #[error("invalid object key: {0}")]
    InvalidKey(String),

    /// A requested read range starts beyond the object's size.
    #[error("range offset out of bounds for object of size {size}")]
    RangeOutOfBounds { size: u64 },

    /// Underlying I/O failure.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Backend-specific failure (network, auth, quota, provider error).
    #[error("backend error: {0}")]
    Backend(String),

    /// The store's root directory is not the one this backend was opened on.
    ///
    /// Its own variant rather than an [`StoreError::Io`], because the errno is
    /// not what the operator needs to know and there may not be one: the
    /// characteristic case is a root that a write *re-created*, so the write
    /// itself reports nothing at all. See [`crate::local::root`] for the run
    /// this exists to stop reporting as a success.
    #[error("the store root {root} {detail}; nothing was written into it")]
    RootChanged { root: String, detail: &'static str },

    /// The provider answered the request, and refused it.
    ///
    /// Its own variant rather than a formatted [`StoreError::Backend`] because
    /// the retry layer has to decide from *what happened*. A rule spelled
    /// `message.contains("503")` works until somebody rewords the message, and
    /// then stops firing silently and in the direction of not retrying. The
    /// rendering is unchanged — `s3 error 503: SlowDown` — so an operator reads
    /// exactly what they read before.
    #[error("{backend} error {status}: {code}")]
    Provider {
        /// The backend that made the request, as [`crate::Backend::name`] spells it.
        backend: &'static str,
        /// The HTTP status the provider answered with.
        status: u16,
        /// The provider's own error code from the response body, or `?` when it
        /// sent none.
        code: String,
        /// The `Retry-After` the server sent, in whole seconds, when it sent one.
        retry_after_secs: Option<u64>,
    },

    /// Nothing answered: the request may never have reached the provider.
    ///
    /// A connect that did not complete, a read that timed out, a connection
    /// reset mid-body. Distinct from [`StoreError::Provider`] because the two
    /// send an operator to opposite places — one is the network path, the other
    /// is the account — and because only one of them is a request the provider
    /// has certainly seen.
    #[error("{backend}: {detail}")]
    Transport {
        /// The backend that made the request.
        backend: &'static str,
        /// What the transport reported.
        detail: String,
    },

    /// The server answered, refused the request, and named no cause.
    ///
    /// Its own variant rather than a formatted [`StoreError::Backend`] for the
    /// same reason [`StoreError::Provider`] has one: a later layer has to be
    /// able to act on **what happened**, and a rule spelled
    /// `message.contains("Failure")` stops firing the moment somebody rewords
    /// the sentence.
    ///
    /// What acts on it is [`crate::sftp`]'s write path, which asks the far end
    /// how much room is left and upgrades this to a named
    /// [`std::io::ErrorKind::StorageFull`] when the filesystem turns out to be
    /// full. That decision cannot be made from the status code: SFTP version 3
    /// answers `ENOSPC`, `EDQUOT`, `EROFS` and a non-empty `rmdir` with one
    /// catch-all carrying no errno, which is the measurement in
    /// `crate::sftp::status`.
    ///
    /// Distinct from [`StoreError::Transport`], which means *nothing answered*.
    /// Something answered here, and said no.
    #[error("{backend} refused '{path}': {detail}")]
    Refused {
        /// The backend whose server refused, as [`crate::Backend::name`] spells
        /// it.
        backend: &'static str,
        /// What was being written or removed when the refusal arrived.
        path: String,
        /// The reason, where the server gave one, and otherwise the sentence
        /// saying the protocol carries none.
        detail: String,
    },

    /// The run reached the deadline the operator gave it with `--max-duration`.
    ///
    /// **Not** a [`StoreError::Transport`], and the distinction is the whole
    /// point of the variant. A transport failure means *nothing answered*, which
    /// is the case another attempt exists for; this means *the window you gave
    /// me is over*, which no number of attempts can undo. Reporting a deadline
    /// as something retryable has been measured here: the flag fires at exactly
    /// its number and the run continues for another 943.6 s, because every
    /// layer above reads "worth another attempt" and spends its whole schedule.
    ///
    /// It is a *store* error rather than a CLI one because the layer that
    /// notices is the one holding the request. The CLI maps it to exit **10**.
    #[error("the run reached its own deadline (--max-duration {}s)", limit.as_secs())]
    RunDeadline {
        /// The window the operator asked for, so the report quotes their number.
        limit: std::time::Duration,
    },

    /// The run stopped asking a link that never answered.
    ///
    /// **Not** a [`StoreError::Transport`], and for the same reason
    /// [`StoreError::RunDeadline`] beside it is not. A transport failure means
    /// *nothing answered this time*, which is the case another attempt exists
    /// for; this means *nothing has answered for a whole schedule of attempts,
    /// and the run has stopped asking*. Another attempt is not merely useless —
    /// classifying it as worth one is what let `--timeout × attempts` grow into
    /// `--timeout × attempts × distinct requests`, measured at 288.7 s under
    /// `--timeout 30`.
    ///
    /// The message multiplies out to the number an operator can check against
    /// the flag they set. The CLI maps it to exit **5**, the same code a link
    /// that died produces without this bound, because the *cause* is unchanged
    /// — a scheduler should still come back later. What changed is only how long
    /// the run spends establishing it.
    /// # No backend is named, and that is the accurate report
    ///
    /// Every other variant here names the backend that failed, because a
    /// backend failed. This one is counted **across the run** — every request
    /// it made, to either end of a copy — so naming one remote would be a claim
    /// about where the silence was that the counter does not hold. What the
    /// message carries instead is the arithmetic: the attempts, and the
    /// operator's own `--timeout` they were each bounded by. The failure that
    /// caused the *first* silence is reported by the backend that saw it, in
    /// the ordinary way, and is what an operator reads above this line.
    #[error("gave up after {attempts} attempts that got no answer (--timeout {}s)", idle.as_secs())]
    Stalled {
        /// Consecutive attempts that got nothing back.
        attempts: u32,
        /// The operator's own `--timeout`, so the report quotes their number.
        idle: std::time::Duration,
    },

    /// A failure a retry layer already tried again, and how many times.
    ///
    /// Wraps rather than replaces, so the exit code, the message and the type an
    /// operator acts on stay the provider's own. Attached **only** when more
    /// than one attempt was really made — see [`crate::retry::driver`]. This is
    /// what makes the CLI's hint a report rather than a claim: every backend
    /// failure used to arrive saying *"Retries were exhausted"* over a run that
    /// had made exactly one attempt.
    #[error("{source}")]
    Retried {
        /// Attempts made, the first one included.
        attempts: u32,
        /// What failed.
        source: Box<StoreError>,
    },
}

impl StoreError {
    /// Stable, FFI-safe numeric error code for this variant.
    ///
    /// Codes are **FROZEN** (`docs/ERROR_CODES.md`): a number is never
    /// renumbered or reused, and new variants only ever take new, unused
    /// numbers — a one-way door like `docs/FORMAT.md` §8. The `2xxx` range is
    /// reserved for the store layer. `0` is reserved for success/none and is
    /// never returned here.
    pub fn code(&self) -> u32 {
        match self {
            StoreError::NotFound(_) => 2001,
            StoreError::ChecksumMismatch { .. } => 2002,
            StoreError::InvalidKey(_) => 2003,
            StoreError::RangeOutOfBounds { .. } => 2004,
            StoreError::Io(_) => 2005,
            StoreError::Backend(_) => 2006,
            StoreError::ShortWrite { .. } => 2007,
            StoreError::RootChanged { .. } => 2008,
            StoreError::Provider { .. } => 2009,
            StoreError::Transport { .. } => 2010,
            StoreError::RunDeadline { .. } => 2011,
            StoreError::Refused { .. } => 2012,
            StoreError::Stalled { .. } => 2013,
            StoreError::BucketNotFound { .. } => 2014,
            // Delegated, never its own number. A retry record describes how
            // often something was attempted, not what went wrong, and a script
            // branching on the exit code must see the same number whether or not
            // the failure happened to be retried.
            StoreError::Retried { source, .. } => source.code(),
        }
    }

    /// How many attempts a retry layer made, when one made any.
    ///
    /// [`None`] means *no retry layer reported anything*, which is not the same
    /// as one attempt and must not be worded as though it were. The CLI's hint
    /// reads this: with a number it says how many attempts were made, and
    /// without one it says nothing about retrying at all.
    #[must_use]
    pub const fn attempts(&self) -> Option<u32> {
        match self {
            Self::Retried { attempts, .. } => Some(*attempts),
            _ => None,
        }
    }

    /// The failure itself, with any retry record peeled off.
    ///
    /// So a caller classifying an error — the CLI's exit-code mapping, a
    /// `matches!` in a test — sees the provider's own variant whether or not the
    /// operation happened to be retried.
    #[must_use]
    pub fn cause(&self) -> &Self {
        match self {
            Self::Retried { source, .. } => source.cause(),
            other => other,
        }
    }

    /// [`StoreError::cause`], taking ownership.
    #[must_use]
    pub fn into_cause(self) -> Self {
        match self {
            Self::Retried { source, .. } => source.into_cause(),
            other => other,
        }
    }
}

pub type Result<T> = std::result::Result<T, StoreError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn representative_codes_are_frozen() {
        assert_eq!(StoreError::NotFound(String::new()).code(), 2001);
        assert_eq!(
            StoreError::ChecksumMismatch {
                expected: String::new(),
                actual: String::new(),
            }
            .code(),
            2002
        );
        assert_eq!(StoreError::Backend(String::new()).code(), 2006);
        assert_eq!(
            StoreError::RunDeadline {
                limit: std::time::Duration::from_secs(30)
            }
            .code(),
            2011
        );
        assert_eq!(
            StoreError::ShortWrite {
                expected: 0,
                actual: 0
            }
            .code(),
            2007
        );
        assert_eq!(
            StoreError::Stalled {
                attempts: 6,
                idle: std::time::Duration::from_secs(30),
            }
            .code(),
            2013
        );
    }

    #[test]
    fn a_short_write_says_how_short_rather_than_naming_two_hashes() {
        // The whole reason the variant exists. An operator reading this has to
        // be able to tell "the disk is full" from "the bytes came back wrong",
        // and the numbers are what does it.
        let message = StoreError::ShortWrite {
            expected: 200_000,
            actual: 4_096,
        }
        .to_string();
        assert!(message.contains("200000"), "{message}");
        assert!(message.contains("4096"), "{message}");
        assert!(
            !message.contains("checksum"),
            "a short write is not a checksum failure: {message}"
        );
    }

    #[test]
    fn a_retry_record_reports_the_wrapped_failures_code_and_not_its_own() {
        // A script branching on the exit code must see the same number whether
        // or not the operation was retried: how often DCTL asked is not what
        // went wrong.
        let inner = StoreError::Provider {
            backend: "s3",
            status: 503,
            code: "SlowDown".to_string(),
            retry_after_secs: None,
        };
        let wrapped = StoreError::Retried {
            attempts: 6,
            source: Box::new(inner),
        };
        assert_eq!(wrapped.code(), 2009);
        assert_eq!(wrapped.attempts(), Some(6));
        assert!(matches!(wrapped.cause(), StoreError::Provider { .. }));
        // And the message is the provider's, unchanged, so the sentence an
        // operator reads is the one the provider sent.
        assert_eq!(wrapped.to_string(), "s3 error 503: SlowDown");
    }

    #[test]
    fn an_unretried_failure_makes_no_claim_about_retrying() {
        // The defect this whole field exists for: the hint said "Retries were
        // exhausted" over a run that made one attempt. `None` is how the CLI
        // knows to say nothing.
        assert_eq!(StoreError::Backend("x".into()).attempts(), None);
        assert_eq!(StoreError::NotFound("k".into()).attempts(), None);
    }

    #[test]
    fn a_provider_failure_reads_the_way_it_always_did() {
        // The rendering is a contract: `tests/s3_mock.rs` asserts on it, and an
        // operator greps for it.
        let error = StoreError::Provider {
            backend: "s3",
            status: 403,
            code: "InvalidAccessKeyId".to_string(),
            retry_after_secs: None,
        };
        assert_eq!(error.to_string(), "s3 error 403: InvalidAccessKeyId");
    }

    #[test]
    fn codes_are_unique_and_in_domain() {
        let codes = [
            StoreError::NotFound(String::new()).code(),
            StoreError::ChecksumMismatch {
                expected: String::new(),
                actual: String::new(),
            }
            .code(),
            StoreError::InvalidKey(String::new()).code(),
            StoreError::RangeOutOfBounds { size: 0 }.code(),
            StoreError::Io(std::io::Error::other("x")).code(),
            StoreError::Backend(String::new()).code(),
            StoreError::ShortWrite {
                expected: 0,
                actual: 0,
            }
            .code(),
            StoreError::RootChanged {
                root: String::new(),
                detail: "changed",
            }
            .code(),
            StoreError::Provider {
                backend: "s3",
                status: 500,
                code: String::new(),
                retry_after_secs: None,
            }
            .code(),
            StoreError::Transport {
                backend: "s3",
                detail: String::new(),
            }
            .code(),
            StoreError::RunDeadline {
                limit: std::time::Duration::from_secs(1),
            }
            .code(),
            StoreError::Stalled {
                attempts: 6,
                idle: std::time::Duration::from_secs(30),
            }
            .code(),
        ];
        // Every store code lives in the 2xxx domain and is never 0 (success).
        assert!(codes.iter().all(|c| (2001..3000).contains(c)));
        // Unique within the crate.
        let mut sorted = codes;
        sorted.sort_unstable();
        let unique = sorted.windows(2).all(|w| w[0] != w[1]);
        assert!(unique, "duplicate store error codes: {sorted:?}");
    }
}
