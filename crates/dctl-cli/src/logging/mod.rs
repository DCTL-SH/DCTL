//! Structured logging, diagnostics and secret redaction (`PLAN.md` §7).
//!
//! Three guarantees this module is responsible for:
//!
//! 1. **Structure.** Records carry typed fields, not interpolated prose, so a
//!    log pipeline can query `bytes > 1e9` or `error_code = checksum_mismatch`
//!    without regex-scraping.
//! 2. **Redaction is mandatory, not optional.** Secrets are wrapped in
//!    [`redact::Secret`], whose `Debug`/`Display` reveal nothing, and appear in
//!    logs only as BLAKE3 fingerprints. A `--dump headers` capture is safe to
//!    attach to a support ticket.
//! 3. **stdout stays clean.** Every record goes to stderr or to a log file, so
//!    `dctl cat` can stream a file through a pipe while logging is at trace.
//!
//! ## Span conventions
//!
//! Operations open a span so every record inside inherits the context. The
//! field names below are a contract that log queries depend on:
//!
//! | Field        | Meaning                                          |
//! |--------------|--------------------------------------------------|
//! | `op`         | Command name (`copy`, `sync`, `verify`)          |
//! | `path`       | Logical vault path                               |
//! | `remote`     | Remote name from the config                      |
//! | `stage`      | Verified-write stage (`PLAN.md` §6)              |
//! | `bytes`      | Byte count for this record                       |
//! | `dek_fp`     | DEK fingerprint — never the key                  |
//! | `error_code` | Stable slug from [`crate::exit::ExitCode`]       |

mod format;
mod init;
pub mod redact;

mod level;

pub use format::LogFormat;
pub use init::{LogConfig, LogInitError, init};
pub use level::LogLevel;
pub use redact::Secret;

/// Field names used in spans and records.
///
/// Constants rather than string literals at each call site, so a rename is one
/// edit and a typo is a compile error instead of a silently unqueryable field.
pub mod fields {
    /// Command name.
    pub const OP: &str = "op";
    /// Logical vault path.
    pub const PATH: &str = "path";
    /// Configured remote name.
    pub const REMOTE: &str = "remote";
    /// Verified-write pipeline stage.
    pub const STAGE: &str = "stage";
    /// Byte count.
    pub const BYTES: &str = "bytes";
    /// DEK fingerprint (never the key itself).
    ///
    /// Declared but not yet emitted: a DEK never crosses into this crate — the
    /// vault derives and holds it, and `dctl-core` is where a record carrying
    /// this field will be written. The name lives here anyway because it is the
    /// column a log query selects on, and a field whose spelling is decided
    /// twice is a field that ends up spelled two ways.
    #[allow(dead_code)]
    pub const DEK_FINGERPRINT: &str = "dek_fp";
    /// Stable error slug.
    pub const ERROR_CODE: &str = "error_code";
    /// Attempt number for a retried operation.
    ///
    /// Declared but not yet emitted: `--retries` and `--low-level-retries` are
    /// accepted, and nothing loops on them yet. The first retry loop written
    /// must tag its records with this rather than inventing a second name for
    /// the same number.
    #[allow(dead_code)]
    pub const ATTEMPT: &str = "attempt";
    /// Duration of an operation, in milliseconds.
    pub const DURATION_MS: &str = "duration_ms";
}

#[cfg(test)]
mod tests {
    use super::{LogFormat, LogLevel, fields};

    #[test]
    fn field_names_are_stable_and_distinct() {
        let names = [
            fields::OP,
            fields::PATH,
            fields::REMOTE,
            fields::STAGE,
            fields::BYTES,
            fields::DEK_FINGERPRINT,
            fields::ERROR_CODE,
            fields::ATTEMPT,
            fields::DURATION_MS,
        ];
        let mut sorted = names.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len(), "field names must be unique");
        assert!(names.iter().all(|n| !n.is_empty()));
    }

    #[test]
    fn the_key_field_is_named_as_a_fingerprint() {
        // Guards against someone adding a `dek` field carrying the real key.
        assert!(fields::DEK_FINGERPRINT.ends_with("_fp"));
    }

    #[test]
    fn defaults_are_conservative() {
        assert_eq!(LogLevel::default(), LogLevel::Warn);
        assert_eq!(LogFormat::default(), LogFormat::Human);
    }
}
