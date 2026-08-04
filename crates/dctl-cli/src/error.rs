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

use crate::constants::VAULT_ENVELOPE_OBJECT_KEY;
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
        // How many attempts a retry layer really made, before the record is
        // peeled off so every arm below classifies the provider's own failure
        // rather than the wrapper around it. See `dctl_store::StoreError::cause`.
        let attempts = error.attempts();
        let error = error.into_cause();
        match error {
            StoreError::NotFound(ref key) => Self::new(ExitCode::FileNotFound, error.to_string())
                .with_hint(format!("No object stored under '{key}'.")),

            // A configuration/credential fact, not a missing object: exit 4's
            // "file not found" sent an operator hunting for a lost object when
            // the store itself could not be reached by name. Fatal, with the
            // three causes worth checking in one hint.
            StoreError::BucketNotFound { ref bucket } => {
                Self::new(ExitCode::FatalError, error.to_string()).with_hint(format!(
                    "The bucket '{bucket}' must exist in the account this \
                     application key belongs to, spelled as the account spells \
                     it. A bucket-restricted key can only reach its own \
                     bucket; a key without listBuckets cannot resolve any."
                ))
            }

            StoreError::ChecksumMismatch { .. } => {
                Self::new(ExitCode::ChecksumMismatch, error.to_string()).with_hint(
                    "The destination did not store the bytes we sent. Nothing was \
                     committed and the source is untouched. Retry; if it persists, \
                     the provider or the network path is corrupting data.",
                )
            }

            // Distinct from a mismatch on purpose, with a distinct remedy. The
            // bytes are not in question: fewer of them arrived than were sent,
            // which is a destination that ran out of room or went away, not one
            // that changed the content. See `dctl_store::StoreError::ShortWrite`.
            StoreError::ShortWrite { .. } => Self::new(ExitCode::FatalError, error.to_string())
                .with_hint(
                    "The destination accepted the write and then did not have all \
                     the bytes. Nothing was committed and the source is untouched. \
                     Check free space and quota on the destination filesystem \
                     (`df -h`, `quota`) before suspecting the data.",
                ),

            StoreError::InvalidKey(_) => Self::new(ExitCode::Usage, error.to_string())
                .with_hint("Object keys must be relative, NUL-free, and free of '..' components."),

            StoreError::RangeOutOfBounds { .. } => Self::new(ExitCode::Usage, error.to_string())
                .with_hint("The requested offset is past the end of the object."),

            // A full filesystem is exit 7 — the code whose published definition
            // already names "disk full" — and it stops the run, because
            // `transfer::pipeline::is_fatal` is right that every remaining file
            // will fail identically. It reached here as exit 2 "uncategorised"
            // for as long as nothing read the errno, so a run against a full
            // disk ground through ten thousand files to produce ten thousand
            // copies of the same line.
            StoreError::Io(ref source) if dctl_store::durable::is_out_of_space(source) => {
                Self::new(ExitCode::FatalError, error.to_string()).with_hint(
                    "The destination has no room for the object: the filesystem is \
                     full, a quota is exhausted, or it is mounted read-only. Nothing \
                     was committed and the source is untouched. `df -h` on the \
                     destination is the first thing to look at.",
                )
            }

            StoreError::Io(_) => Self::new(ExitCode::Uncategorised, error.to_string()),

            // Network and provider failures. The hint is worded from what the
            // retry layer actually did, and this is the sentence that made it
            // necessary: every one of these used to arrive saying "Retries were
            // exhausted" over a run that had attempted the request exactly once
            // — a message describing work that did not happen, which is the
            // class `PLAN.md` §6 forbids and the worse kind of false, because it
            // tells an operator the tool already did the thing they would
            // otherwise go and do. See `dctl_store::retry`.
            StoreError::Backend(_) | StoreError::Provider { .. } | StoreError::Transport { .. } => {
                Self::new(ExitCode::TemporaryError, error.to_string())
                    .with_hint(retry_hint(attempts))
            }

            // A server that answered and said no. **Not** `TemporaryError`: the
            // request was received and refused, so "try again shortly" is
            // advice that spends a backup window to arrive at the same answer.
            // The message already carries whatever could be established about
            // the cause — including, where the far end could be asked, that the
            // filesystem is *not* out of space, which is the fact that sends an
            // operator to the quota instead of to `df`.
            StoreError::Refused { .. } => Self::new(ExitCode::FatalError, error.to_string())
                .with_hint(
                    "The server received the request and refused it. SFTP's status \
                     packet carries no errno, so where the cause is not named above \
                     it could not be established from the protocol alone. Check the \
                     destination for a quota, a read-only mount, and the permissions \
                     on the directory itself.",
                ),

            // The run's own `--max-duration`, and its own exit code. Reporting
            // it as a temporary error — which is what `Transport` would have
            // made it — would tell a scheduler to back off and try again, about
            // a run that did exactly what it was told to do. `HANDOVER.md`
            // §32.9 is the measurement behind the flag; exit 10 is how a
            // wrapper tells "my window ran out" from "the network broke".
            StoreError::RunDeadline { .. } => {
                Self::new(ExitCode::DurationLimitExceeded, error.to_string())
                    .with_hint(crate::constants::MAX_DURATION_HINT)
            }

            // The run stopped asking. Its own code, for the argument
            // `ExitCode::LinkSilent` carries: 5 means "retries exhausted",
            // which is nearly the opposite of what happened, and 5 is repeated
            // by `--retries` and does not stop the walk — so a stalled run
            // wearing it would fail every remaining file in microseconds and
            // report retries over requests that were never made.
            StoreError::Stalled { .. } => Self::new(ExitCode::LinkSilent, error.to_string())
                .with_hint(crate::constants::STALLED_HINT),

            // Fatal, and fatal is the point: every remaining file would be
            // written into the same wrong place, and the run that this replaced
            // reported all of them as stored. See `dctl_store::local::root`.
            StoreError::RootChanged { .. } => Self::new(ExitCode::FatalError, error.to_string())
                .with_hint(
                    "The store moved or was removed while the run was using it, so \
                     anything written after that point would have gone into a \
                     different directory. Put the store back where the \
                     configuration says it is — check that the volume holding it is \
                     still mounted — and run the command again; it will resume from \
                     what is genuinely there.",
                ),

            // `into_cause` above removes this variant before the match, so it is
            // unreachable in practice. It is written out rather than swallowed by
            // a wildcard because a wildcard here is how the next variant added to
            // `StoreError` would silently inherit somebody else's exit code.
            StoreError::Retried { .. } => Self::new(ExitCode::TemporaryError, error.to_string())
                .with_hint(retry_hint(attempts)),
        }
    }
}

/// What to tell an operator about retrying, given what was actually attempted.
///
/// Three states, and the distinction between the last two is the whole reason
/// this function exists rather than a constant:
///
/// * **More than one attempt** — say how many, and that they are spent. That is
///   a report.
/// * **Exactly one** — say that the failure was classified as one another
///   attempt could not change. That is also a report, and it is the sentence
///   that used to be a lie.
/// * **No record at all** — say nothing about retrying. An error that never
///   passed through the retry layer has no attempt count, and inventing one
///   would be the same misreport in a quieter voice.
fn retry_hint(attempts: Option<u32>) -> String {
    let preamble = match attempts {
        Some(made) if made > 1 => format!("{made} attempts were made and the failure persisted. "),
        Some(_) => "This failure was classified as one another attempt could not \
                    change, so it was attempted once. "
            .to_string(),
        None => String::new(),
    };
    format!(
        "{preamble}Check connectivity and provider status, then run the command \
         again; it will resume from what is genuinely there."
    )
}

/// Classify a core/vault failure.
impl From<CoreError> for CliError {
    fn from(error: CoreError) -> Self {
        match error {
            // This is the most frightening message the tool produces: it is read
            // by somebody who believes their vault may be lost, and it will be
            // acted on literally. So every remedy named here has to be one this
            // build actually provides.
            //
            // Deliberately does not mention `--key-file`. This build cannot mix
            // a second factor into the KEK at all — `crate::session::factor`
            // refuses the flag before an unlock is even attempted — so naming it
            // here would send the reader hunting a keyfile problem that cannot
            // exist, and would imply a protection the vault does not have.
            // `--password-file` is named because it really is a password source
            // and really can be the culprit (a trailing byte, the wrong line).
            //
            // This hint has named a nonexistent command twice, and the history
            // is why the wording below is so specific. It used to send the
            // reader to a `dctl vault recover` subcommand with "your BIP39
            // phrase" when neither existed; that was replaced with the honest
            // statement that a password was the only way in, and this is the
            // third and — the point — *true* version: `dctl init` now writes a
            // mnemonic slot beside the password slot and prints the phrase
            // once, `--recovery-phrase` is a global on every command, and
            // `dctl vault recover` exists. `crate::cli::mentions` fails the
            // build if any of those spellings stops naming a real command.
            //
            // Both remedies are ordered by what the reader most likely has. The
            // phrase comes first because somebody reading this has already
            // tried the password. The envelope repair comes last because it is
            // the answer when the secret is not the problem.
            //
            // Deliberately still does not mention `--key-file`. This build
            // cannot mix a second factor into the KEK at all —
            // `crate::session::factor` refuses the flag before an unlock is
            // attempted — so naming it would send the reader hunting a keyfile
            // problem that cannot exist. `--password-file` is named because it
            // really is a password source and really can be the culprit.
            CoreError::Unlock => Self::new(ExitCode::VaultLocked, error.to_string()).with_hint(
                format!(
                    "Check the password, including how it reached DCTL — a \
                     --password-file or --password-command that emits a stray \
                     character produces a different secret than the one you \
                     typed. If the password is gone, use the recovery phrase \
                     printed when the vault was created: `dctl vault recover \
                     REMOTE:` opens the vault with it and sets a new password, \
                     and --recovery-phrase works on any command. A password \
                     change never invalidates that phrase, so an old sheet of \
                     paper is still current. If neither secret is the problem, \
                     the envelope itself may be damaged; it is stored as \
                     '{VAULT_ENVELOPE_OBJECT_KEY}' in the object store, and \
                     restoring that one object from a replica of the store \
                     (`dctl replicate` copies it) is the repair.",
                ),
            ),

            // The message the previous arm must never be allowed to give.
            //
            // A plain remote has no envelope, because a plain remote is not a
            // vault; nothing DCTL can do to it will produce one, and no password
            // opens it. Reporting the *unlock* wording here sent an operator to
            // check a secret that was never involved and to restore a file that
            // cannot exist at that address — a diagnosis that costs more than
            // none, because it is confident and wrong.
            //
            // Exit 7 rather than 22: the vault is not locked, and a script that
            // branches on 22 to re-prompt for a password would loop forever on a
            // location where no password can help.
            CoreError::NoVault(ref key) => Self::new(ExitCode::FatalError, error.to_string())
                .with_hint(format!(
                    "A vault keeps its key envelope at '{key}', and this is a plain \
                     object store with no such object in it — so no password is \
                     involved and none will help. If you meant a vault that does \
                     exist, `dctl config list` shows the configured remotes. If a \
                     vault really was here, the envelope is the one object nothing \
                     else can rebuild: restore it from a replica of the store \
                     (`dctl replicate` copies it) before writing anything to this \
                     location.",
                )),

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
    ///
    /// Must agree with the owning `From<StoreError>` above, arm for arm — the
    /// same failure reaching the operator by two routes with two codes is the
    /// misreport this module exists to prevent. `agrees_with_the_owning_mapping`
    /// asserts it over every variant.
    fn from_store_code(error: &StoreError) -> ExitCode {
        match error {
            StoreError::NotFound(_) => ExitCode::FileNotFound,
            StoreError::BucketNotFound { .. } => ExitCode::FatalError,
            StoreError::ChecksumMismatch { .. } => ExitCode::ChecksumMismatch,
            StoreError::ShortWrite { .. } => ExitCode::FatalError,
            StoreError::InvalidKey(_) | StoreError::RangeOutOfBounds { .. } => ExitCode::Usage,
            StoreError::Backend(_) | StoreError::Provider { .. } | StoreError::Transport { .. } => {
                ExitCode::TemporaryError
            }
            StoreError::Refused { .. } => ExitCode::FatalError,
            StoreError::RootChanged { .. } => ExitCode::FatalError,
            StoreError::RunDeadline { .. } => ExitCode::DurationLimitExceeded,
            StoreError::Stalled { .. } => ExitCode::LinkSilent,
            StoreError::Io(source) if dctl_store::durable::is_out_of_space(source) => {
                ExitCode::FatalError
            }
            StoreError::Io(_) => ExitCode::Uncategorised,
            // The wrapped failure decides, exactly as it does in the owning
            // mapping: a retried write that ran out of space is still exit 7.
            StoreError::Retried { source, .. } => Self::from_store_code(source),
        }
    }
}

/// Result alias used throughout the CLI.
pub type Result<T> = std::result::Result<T, CliError>;

#[cfg(test)]
mod tests {
    use super::{CliError, ExitCode, VAULT_ENVELOPE_OBJECT_KEY};
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

    /// Every `StoreError` shape, so the two mappings below can be held to each
    /// other without either of them growing a variant the other has not seen.
    fn every_store_error() -> Vec<StoreError> {
        vec![
            StoreError::NotFound("k".into()),
            StoreError::ChecksumMismatch {
                expected: "aa".into(),
                actual: "bb".into(),
            },
            StoreError::ShortWrite {
                expected: 10,
                actual: 4,
            },
            StoreError::InvalidKey("k".into()),
            StoreError::RangeOutOfBounds { size: 1 },
            StoreError::Io(std::io::Error::from(std::io::ErrorKind::StorageFull)),
            StoreError::Io(std::io::Error::from(std::io::ErrorKind::QuotaExceeded)),
            StoreError::Io(std::io::Error::from(std::io::ErrorKind::ReadOnlyFilesystem)),
            StoreError::Io(std::io::Error::other("device")),
            StoreError::Backend("503".into()),
            StoreError::RootChanged {
                root: "/srv/vault".into(),
                detail: "has been removed",
            },
            StoreError::Provider {
                backend: "s3",
                status: 503,
                code: "SlowDown".into(),
                retry_after_secs: Some(3),
            },
            StoreError::Transport {
                backend: "sftp",
                detail: "connection reset".into(),
            },
            StoreError::RunDeadline {
                limit: std::time::Duration::from_secs(30),
            },
            StoreError::Stalled {
                attempts: 6,
                idle: std::time::Duration::from_secs(30),
            },
            // A retry record over a failure whose code is *not* the temporary
            // one, so a mapping that answered from the wrapper instead of from
            // what it wraps is caught rather than accidentally right.
            StoreError::Retried {
                attempts: 6,
                source: Box::new(StoreError::Io(std::io::Error::from(
                    std::io::ErrorKind::StorageFull,
                ))),
            },
        ]
    }

    #[test]
    fn a_run_that_ran_out_of_time_is_not_reported_as_a_network_problem() {
        // Exit 10, not exit 5, and the distinction is what a scheduler branches
        // on. `--max-duration` doing what it was told is not a temporary error,
        // and telling a wrapper to back off and retry would turn a working flag
        // into a job that runs twice.
        let err = CliError::from(StoreError::RunDeadline {
            limit: std::time::Duration::from_secs(30),
        });
        assert_eq!(err.code(), ExitCode::DurationLimitExceeded);
        assert!(
            err.message().contains("--max-duration"),
            "{}",
            err.message()
        );
        let hint = err.hint().unwrap_or_default();
        assert!(
            !hint.to_lowercase().contains("exhaust"),
            "a deadline is not exhausted retries: {hint}"
        );
        assert!(
            hint.contains("cleanup"),
            "a hard cutoff leaves debris and must say how to reclaim it: {hint}"
        );
    }

    #[test]
    fn a_run_that_stopped_asking_gets_its_own_code_and_not_the_retry_one() {
        // Exit **28**, not 5. `EXIT_CODES.md`'s own rule is that a code's
        // meaning never changes and a new condition gets a new number, and 5
        // already stands for "temporary error; retries exhausted" — which is
        // nearly the opposite of what happened here: the retries were **not**
        // exhausted, the run stopped early because a link that answers nothing
        // cannot be persuaded by asking again. The two also want opposite
        // handling inside the run; see `pipeline::is_fatal` and
        // `retry::is_worth_repeating`.
        let err = CliError::from(StoreError::Stalled {
            attempts: 6,
            idle: std::time::Duration::from_secs(30),
        });
        assert_eq!(err.code(), ExitCode::LinkSilent);

        // The message is where an operator checks the arithmetic against the
        // number they set, so both halves of the product are in it.
        let message = err.message();
        assert!(message.contains("--timeout 30s"), "{message}");
        assert!(message.contains('6'), "{message}");

        // It must not read as a run that was told to stop. `--max-duration` is
        // the operator's own instruction and exits 10; this is the link being
        // gone, and confusing the two sends somebody to the wrong flag.
        assert!(
            !message.contains("--max-duration"),
            "a dead link is not a closed window: {message}"
        );

        let hint = err.hint().unwrap_or_default();
        // The false claim, named rather than banned by keyword. The first
        // spelling of this forbade the substring "exhaust", which failed on a
        // hint that *denies* the claim — the assertion was about a word where
        // it should have been about a sentence.
        assert!(
            !hint.to_lowercase().contains("retries were exhausted"),
            "the hint must not borrow the retry wording PLAN.md §6 forbids, \
             over a run whose retries were not exhausted: {hint}"
        );
        assert!(
            hint.contains("NOT exhausted"),
            "and it must say so out loud, because exit 5 is the code that means \
             the other thing and an operator knows 5: {hint}"
        );
        assert!(
            hint.contains("--timeout 0"),
            "an operator who really will wait forever needs to be told how to \
             say so: {hint}"
        );
    }

    #[test]
    fn a_failure_that_was_never_retried_makes_no_claim_about_retrying() {
        // The defect, in one assertion. `HANDOVER.md` §11.2: "the hint still
        // says *Retries were exhausted* on an sftp connection failure where none
        // were attempted" — a message describing work that did not happen, which
        // is the class `PLAN.md` §6 forbids outright.
        let err = CliError::from(StoreError::Transport {
            backend: "sftp",
            detail: "connection reset by peer".into(),
        });
        let hint = err.hint().unwrap_or_default();
        assert!(
            !hint.to_lowercase().contains("exhaust"),
            "an unretried failure claimed exhausted retries: {hint}"
        );
        assert!(
            !hint.contains("attempts were made"),
            "an unretried failure claimed attempts: {hint}"
        );
        // It still has to say something useful, or the fix would be silence.
        assert!(hint.contains("connectivity"), "{hint}");
    }

    #[test]
    fn a_failure_that_was_retried_says_how_many_times() {
        let err = CliError::from(StoreError::Retried {
            attempts: 6,
            source: Box::new(StoreError::Provider {
                backend: "b2",
                status: 503,
                code: "service_unavailable".into(),
                retry_after_secs: None,
            }),
        });
        let hint = err.hint().unwrap_or_default();
        assert!(
            hint.contains('6'),
            "the count must reach the operator: {hint}"
        );
        assert!(hint.contains("attempts were made"), "{hint}");
        // The message stays the provider's own: how often DCTL asked is not what
        // went wrong.
        assert_eq!(err.message(), "b2 error 503: service_unavailable");
        assert_eq!(err.code(), ExitCode::TemporaryError);
    }

    #[test]
    fn a_failure_attempted_exactly_once_says_so_rather_than_nothing() {
        // The middle state, and the one a single boolean would have collapsed:
        // "the retry layer looked at this and decided another attempt could not
        // help" is a different fact from "no retry layer ever saw it", and an
        // operator deciding whether to re-run needs the difference.
        let err = CliError::from(StoreError::Retried {
            attempts: 1,
            source: Box::new(StoreError::Provider {
                backend: "s3",
                status: 403,
                code: "AccessDenied".into(),
                retry_after_secs: None,
            }),
        });
        let hint = err.hint().unwrap_or_default();
        assert!(hint.contains("attempted once"), "{hint}");
        assert!(!hint.contains("attempts were made"), "{hint}");
    }

    #[test]
    fn a_retried_failure_keeps_the_exit_code_of_what_it_wraps() {
        // A script branching on the exit code must see the same number whether
        // or not the operation happened to be retried. A full disk is exit 7
        // either way.
        let full = StoreError::Io(std::io::Error::from(std::io::ErrorKind::StorageFull));
        let plain = CliError::from(StoreError::Io(std::io::Error::from(
            std::io::ErrorKind::StorageFull,
        )))
        .code();
        let retried = CliError::from(StoreError::Retried {
            attempts: 3,
            source: Box::new(full),
        })
        .code();
        assert_eq!(plain, retried);
        assert_eq!(retried, ExitCode::FatalError);
    }

    #[test]
    fn a_full_filesystem_is_the_disk_full_code_and_sends_the_operator_to_df() {
        // §16.1. A full disk used to arrive as exit 2, "an error not otherwise
        // categorised", with no hint — while exit 7's published definition
        // already read "Fatal error — the run cannot continue (bad config, disk
        // full)" and `transfer::pipeline::is_fatal` already said a full disk
        // should stop the run. Nothing read the errno, so neither happened.
        for kind in [
            std::io::ErrorKind::StorageFull,
            std::io::ErrorKind::QuotaExceeded,
            std::io::ErrorKind::FileTooLarge,
            std::io::ErrorKind::ReadOnlyFilesystem,
        ] {
            let err = CliError::from(StoreError::Io(std::io::Error::from(kind)));
            assert_eq!(err.code(), ExitCode::FatalError, "{kind:?}");
            let hint = err.hint().unwrap_or_default();
            assert!(hint.contains("df"), "{kind:?}: {hint}");
            assert!(
                !hint.to_lowercase().contains("corrupt"),
                "a full disk must not be described as corruption: {hint}"
            );
        }
    }

    #[test]
    fn a_device_error_is_still_uncategorised_rather_than_blamed_on_free_space() {
        // The other half of the same rule: `df` is the wrong advice for an EIO,
        // and a hint that gave it would waste the same hour in the other
        // direction.
        let err = CliError::from(StoreError::Io(std::io::Error::other("device failure")));
        assert_eq!(err.code(), ExitCode::Uncategorised);
    }

    #[test]
    fn a_short_write_is_never_reported_as_a_checksum_mismatch() {
        // The defect in one assertion: a destination that took the bytes and did
        // not keep them is a write that stopped, and telling the operator their
        // checksums disagree sends them hunting bit-rot in good data.
        let err = CliError::from(StoreError::ShortWrite {
            expected: 200_000,
            actual: 4_096,
        });
        assert_ne!(err.code(), ExitCode::ChecksumMismatch);
        assert_eq!(err.code(), ExitCode::FatalError);
        assert!(!err.message().contains("checksum"), "{}", err.message());
        let hint = err.hint().unwrap_or_default();
        assert!(hint.contains("df"), "{hint}");
        assert!(
            !hint.contains("corrupting data"),
            "the provider is not the suspect here: {hint}"
        );
    }

    #[test]
    fn the_two_store_mappings_agree_on_every_variant() {
        for error in every_store_error() {
            let borrowed = CliError::from_store_code(&error);
            let owned = CliError::from(error).code();
            assert_eq!(borrowed, owned, "the two routes disagree");
        }
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
    fn the_unlock_hint_offers_the_recovery_route_this_build_now_has() {
        // Defect D6, and its resolution. The hint once told the reader to run a
        // `vault recover` subcommand with "your BIP39 phrase" when neither
        // existed, so the one instruction a frightened operator would follow
        // was spent on `unrecognized subcommand`. It was then rewritten to say
        // plainly that a password was the only way in — true at the time, and
        // the worst possible truth.
        //
        // Both halves are now real: `dctl init` writes a mnemonic slot beside
        // the password slot and prints the phrase once, and `dctl vault
        // recover` opens a vault with it. So the hint offers it again, and this
        // test exists to keep the *promise* honest rather than to forbid it —
        // an offer of recovery is what makes an operator stop hunting for their
        // password, so it must never again describe something absent.
        //
        // The command spelling is enforced separately and mechanically by
        // `crate::cli::mentions`, which parses every `dctl …` this crate writes
        // down. That is deliberate duplication of concern: this test would pass
        // for a hint that named a plausible-sounding sibling verb, and that one
        // would not — it asks the argument parser rather than a human.
        let err = CliError::from(dctl_core::CoreError::Unlock);
        let hint = err.hint().expect("an unlock failure must explain itself");

        assert!(
            hint.contains("dctl vault recover"),
            "the hint must name the command that performs a recovery: {hint}"
        );
        assert!(
            hint.contains("--recovery-phrase"),
            "and the flag that opens every other command with the phrase: {hint}"
        );
        assert!(
            hint.contains("never invalidates"),
            "someone who has changed their password since `init` must be told \
             their old phrase is still current, or they will not try it: {hint}"
        );
        // And it must still name the repair that does not involve a secret at
        // all, verified by hand: `dctl replicate` copies the envelope object
        // byte-for-byte into a second store.
        assert!(
            hint.contains(VAULT_ENVELOPE_OBJECT_KEY),
            "the hint must name the object that would have to be restored: {hint}"
        );
    }

    #[test]
    fn the_unlock_hint_never_claims_the_password_is_the_only_way_in() {
        // The previous wording, kept as a negative because it was correct once
        // and is now the most damaging sentence the tool could print: somebody
        // holding a valid recovery phrase, told there is no second way in,
        // stops looking. A stale message survives the feature that made it
        // false unless something fails when it does.
        let err = CliError::from(dctl_core::CoreError::Unlock);
        let hint = err.hint().expect("an unlock failure must explain itself");
        for absent in [
            "no second way in",
            "issues no recovery phrase",
            "password and nothing else",
        ] {
            assert!(
                !hint.contains(absent),
                "the unlock hint still denies the recovery path ('{absent}'): {hint}"
            );
        }
    }

    #[test]
    fn unimplemented_is_an_error_never_a_success() {
        let err = CliError::unimplemented("dctl mount");
        assert_ne!(err.code(), ExitCode::Success);
    }
}
