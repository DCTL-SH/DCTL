//! Typed CLI errors and their mapping onto stable exit codes.
//!
//! `PLAN.md` §7 forbids silent failures and requires every error to carry a
//! stable code plus a remediation hint. This module is the single place where a
//! failure from any layer is classified — so a `checksum-mismatch` deep in the
//! storage layer always surfaces as exit code 20 with the same message,
//! regardless of which command produced it.

use std::fmt;

use dctl_core::CoreError;
use dctl_store::StoreError;

use crate::exit::ExitCode;

/// A classified command failure.
#[derive(Debug)]
pub struct CliError {
    code: ExitCode,
    message: String,
    /// Actionable next step shown to the user. Never contains secrets.
    hint: Option<String>,
}

impl CliError {
    /// Build an error with an explicit code.
    pub fn new(code: ExitCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            hint: None,
        }
    }

    /// Attach a remediation hint.
    #[must_use]
    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    /// A usage//syntax error (exit 1).
    pub fn usage(message: impl Into<String>) -> Self {
        Self::new(ExitCode::Usage, message)
    }

    /// A fatal configuration error (exit 7).
    pub fn fatal(message: impl Into<String>) -> Self {
        Self::new(ExitCode::FatalError, message)
    }

    /// A feature accepted by the parser but not yet wired to an engine.
    ///
    /// Deliberately an *error*, never a silent success: reporting work as done
    /// when it did not happen is the one thing `PLAN.md` §6 forbids outright.
    pub fn unimplemented(what: impl fmt::Display) -> Self {
        Self::new(
            ExitCode::FatalError,
            format!("{what} is not implemented in this build"),
        )
        .with_hint("See PLAN.md §11 for the phase that delivers this command.")
    }

    #[must_use]
    pub const fn code(&self) -> ExitCode {
        self.code
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    #[must_use]
    pub fn hint(&self) -> Option<&str> {
        self.hint.as_deref()
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)?;
        if let Some(hint) = &self.hint {
            write!(f, "\n  hint: {hint}")?;
        }
        Ok(())
    }
}

impl std::error::Error for CliError {}

/// Classify a storage-layer failure.
///
/// The mapping is deliberately conservative: anything that could mean "the data
/// might not be intact" gets its own loud code rather than the generic bucket.
impl From<StoreError> for CliError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::NotFound(ref key) => Self::new(ExitCode::FileNotFound, error.to_string())
                .with_hint(format!("No object stored under '{key}'.")),

            StoreError::ChecksumMismatch { .. } => {
                Self::new(ExitCode::ChecksumMismatch, error.to_string()).with_hint(
                    "The destination did not store the bytes we sent. Nothing was \
                     committed and the source is untouched. Retry; if it persists, \
                     the provider or the network path is corrupting data.",
                )
            }

            StoreError::InvalidKey(_) => Self::new(ExitCode::Usage, error.to_string())
                .with_hint("Object keys must be relative, NUL-free, and free of '..' components."),

            StoreError::RangeOutOfBounds { .. } => Self::new(ExitCode::Usage, error.to_string())
                .with_hint("The requested offset is past the end of the object."),

            StoreError::Io(_) => Self::new(ExitCode::Uncategorised, error.to_string()),

            // Network/provider failures are the retryable class; by the time one
            // reaches here the retry budget is already spent.
            StoreError::Backend(_) => Self::new(ExitCode::TemporaryError, error.to_string())
                .with_hint("Retries were exhausted. Check connectivity and provider status."),
        }
    }
}

/// Classify a core/vault failure.
impl From<CoreError> for CliError {
    fn from(error: CoreError) -> Self {
        match error {
            // Deliberately does not mention `--key-file`. This build cannot mix
            // a second factor into the KEK at all — `crate::session::factor`
            // refuses the flag before an unlock is even attempted — so naming it
            // here would send the reader hunting a keyfile problem that cannot
            // exist, and would imply a protection the vault does not have.
            // `--password-file` is named because it really is a password source
            // and really can be the culprit (a trailing byte, the wrong line).
            CoreError::Unlock => Self::new(ExitCode::VaultLocked, error.to_string()).with_hint(
                "Check the password, including how it reached DCTL — a \
                 --password-file or --password-command that emits a stray \
                 character produces a different secret than the one you typed. \
                 If the password is right, the envelope may be damaged — recover \
                 with `dctl vault recover` using your BIP39 phrase.",
            ),

            CoreError::NotFound(ref path) => Self::new(ExitCode::FileNotFound, error.to_string())
                .with_hint(format!("'{path}' is not in the vault index. Try `dctl ls`.")),

            CoreError::Integrity(_) => Self::new(ExitCode::IntegrityFailure, error.to_string())
                .with_hint(
                    "Stored data failed authentication — it was NOT returned. The \
                     object is corrupt or was tampered with. Restore it from another \
                     copy, then run `dctl scrub` to check the rest of the dataset.",
                ),

            CoreError::Crypto(inner) => Self::new(ExitCode::IntegrityFailure, inner.to_string()),
            CoreError::Store(inner) => Self::from(inner),
            CoreError::Index(inner) => Self::new(ExitCode::IndexError, inner.to_string())
                .with_hint("The index is a rebuildable cache: `dctl index rebuild` rescans object headers."),
        }
    }
}

/// Fallback for errors that arrive as `anyhow` context chains from helper code.
impl From<anyhow::Error> for CliError {
    fn from(error: anyhow::Error) -> Self {
        // Preserve a typed classification if one is buried in the chain.
        if let Some(store) = error.downcast_ref::<StoreError>() {
            return Self::new(Self::from_store_code(store), format!("{error:#}"));
        }
        Self::new(ExitCode::Uncategorised, format!("{error:#}"))
    }
}

impl From<std::io::Error> for CliError {
    fn from(error: std::io::Error) -> Self {
        let code = match error.kind() {
            std::io::ErrorKind::NotFound => ExitCode::FileNotFound,
            std::io::ErrorKind::PermissionDenied => ExitCode::FatalError,
            _ => ExitCode::Uncategorised,
        };
        Self::new(code, error.to_string())
    }
}

impl CliError {
    /// Exit code for a borrowed `StoreError` (used when downcasting a chain).
    fn from_store_code(error: &StoreError) -> ExitCode {
        match error {
            StoreError::NotFound(_) => ExitCode::FileNotFound,
            StoreError::ChecksumMismatch { .. } => ExitCode::ChecksumMismatch,
            StoreError::InvalidKey(_) | StoreError::RangeOutOfBounds { .. } => ExitCode::Usage,
            StoreError::Backend(_) => ExitCode::TemporaryError,
            StoreError::Io(_) => ExitCode::Uncategorised,
        }
    }
}

/// Result alias used throughout the CLI.
pub type Result<T> = std::result::Result<T, CliError>;

#[cfg(test)]
mod tests {
    use super::{CliError, ExitCode};
    use dctl_store::StoreError;

    #[test]
    fn checksum_mismatch_gets_its_own_loud_code() {
        let err = CliError::from(StoreError::ChecksumMismatch {
            expected: "aa".into(),
            actual: "bb".into(),
        });
        assert_eq!(err.code(), ExitCode::ChecksumMismatch);
        assert!(err.hint().is_some(), "a mismatch must explain itself");
    }

    #[test]
    fn missing_object_is_file_not_found() {
        let err = CliError::from(StoreError::NotFound("k".into()));
        assert_eq!(err.code(), ExitCode::FileNotFound);
    }

    #[test]
    fn backend_failure_is_classified_temporary() {
        let err = CliError::from(StoreError::Backend("503".into()));
        assert_eq!(err.code(), ExitCode::TemporaryError);
    }

    #[test]
    fn the_unlock_hint_never_names_a_factor_this_build_cannot_apply() {
        // The hint used to send the reader off to check "any --password-file /
        // --key-file second factor". Naming a factor that is never mixed into
        // the KEK sends someone hunting a keyfile problem that cannot exist,
        // and implies a protection the build does not provide.
        let err = CliError::from(dctl_core::CoreError::Unlock);
        let hint = err.hint().expect("an unlock failure must explain itself");
        assert!(
            !hint.contains("--key-file"),
            "the unlock hint must not imply --key-file was applied: {hint}"
        );
    }

    #[test]
    fn unimplemented_is_an_error_never_a_success() {
        let err = CliError::unimplemented("dctl mount");
        assert_ne!(err.code(), ExitCode::Success);
    }
}
