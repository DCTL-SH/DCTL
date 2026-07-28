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
    /// checksum mismatch is what `docs/HANDOVER.md` §16.1 is about.
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
            StoreError::ShortWrite {
                expected: 0,
                actual: 0
            }
            .code(),
            2007
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
        // The rendering is a contract: `HANDOVER.md` quotes it, `tests/s3_mock.rs`
        // asserts on it, and an operator greps for it.
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
