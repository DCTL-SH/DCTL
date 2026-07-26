//! Subscriber installation.
//!
//! Builds the `tracing` subscriber from the resolved flags: a console layer on
//! stderr, optionally a second layer appending to a log file, with the format
//! and level each chosen independently.
//!
//! Logs go to **stderr**, never stdout. `dctl cat` streams file contents on
//! stdout, so a log record on the same stream would corrupt the data.

use std::fs::OpenOptions;
use std::path::Path;

use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use super::format::LogFormat;
use super::level::LogLevel;

/// Environment variable that overrides the computed filter entirely, for
/// targeted debugging such as `DCTL_LOG=dctl_store::b2=trace`.
const FILTER_ENV: &str = "DCTL_LOG";

/// Settings for the logging subsystem.
#[derive(Clone, Debug)]
pub struct LogConfig {
    pub level: LogLevel,
    pub format: LogFormat,
    pub file: Option<std::path::PathBuf>,
    /// Include source file and line in every record.
    pub show_source: bool,
    /// Whether the console layer may emit ANSI styling.
    pub color: bool,
}

impl LogConfig {
    /// Build the `EnvFilter` for this configuration.
    ///
    /// `DCTL_LOG` wins if set, so an operator can dial one module up to trace
    /// without drowning in everything else.
    fn filter(&self) -> EnvFilter {
        if let Ok(directive) = std::env::var(FILTER_ENV) {
            if let Ok(filter) = EnvFilter::try_new(&directive) {
                return filter;
            }
        }
        EnvFilter::new(self.level.as_str())
    }
}

/// Errors that can prevent logging from starting.
///
/// Failing to open a log file is fatal: continuing without the audit trail the
/// user explicitly asked for would be a silent downgrade of their guarantees.
#[derive(Debug, thiserror::Error)]
pub enum LogInitError {
    #[error("cannot open log file {path}: {source}")]
    OpenFile {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

/// Install the global subscriber.
///
/// Idempotent: a second call is a no-op rather than a panic, which matters
/// because integration tests may run several commands in one process.
pub fn init(config: &LogConfig) -> Result<(), LogInitError> {
    let filter = config.filter();

    // The file layer, if requested. Opened before anything is installed so a
    // permissions problem surfaces as a clean error, not a half-configured
    // subscriber.
    let file_writer = match &config.file {
        Some(path) => Some(open_log_file(path)?),
        None => None,
    };

    let console_is_json = config.format.is_structured();
    let console_color = config.color && config.format.is_colored();

    // `tracing_subscriber` layers are statically typed, so each combination is
    // built explicitly rather than pushed into a Vec.
    match (console_is_json, file_writer) {
        (true, None) => {
            let _ = tracing_subscriber::registry()
                .with(filter)
                .with(
                    tracing_subscriber::fmt::layer()
                        .json()
                        .with_current_span(true)
                        .with_writer(std::io::stderr)
                        .with_file(config.show_source)
                        .with_line_number(config.show_source),
                )
                .try_init();
        }
        (false, None) => {
            let _ = tracing_subscriber::registry()
                .with(filter)
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_ansi(console_color)
                        .with_target(false)
                        .with_writer(std::io::stderr)
                        .with_file(config.show_source)
                        .with_line_number(config.show_source),
                )
                .try_init();
        }
        (true, Some(file)) => {
            let _ = tracing_subscriber::registry()
                .with(filter)
                .with(
                    tracing_subscriber::fmt::layer()
                        .json()
                        .with_current_span(true)
                        .with_writer(std::io::stderr),
                )
                .with(
                    tracing_subscriber::fmt::layer()
                        .json()
                        .with_current_span(true)
                        .with_writer(file),
                )
                .try_init();
        }
        (false, Some(file)) => {
            let _ = tracing_subscriber::registry()
                .with(filter)
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_ansi(console_color)
                        .with_target(false)
                        .with_writer(std::io::stderr),
                )
                .with(
                    // A file never gets ANSI escapes.
                    tracing_subscriber::fmt::layer()
                        .with_ansi(false)
                        .with_target(false)
                        .with_writer(file),
                )
                .try_init();
        }
    }

    Ok(())
}

/// Open a log file for appending, creating parent directories as needed.
fn open_log_file(path: &Path) -> Result<std::fs::File, LogInitError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|source| LogInitError::OpenFile {
                path: parent.display().to_string(),
                source,
            })?;
        }
    }
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|source| LogInitError::OpenFile {
            path: path.display().to_string(),
            source,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> LogConfig {
        LogConfig {
            level: LogLevel::Warn,
            format: LogFormat::Plain,
            file: None,
            show_source: false,
            color: false,
        }
    }

    #[test]
    fn a_log_file_and_its_parents_are_created() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("nested").join("dctl.log");
        assert!(open_log_file(&path).is_ok());
        assert!(path.exists());
    }

    #[test]
    fn opening_an_impossible_path_is_a_typed_error() {
        // A path whose parent is an existing *file* cannot be created.
        let dir = tempfile::TempDir::new().unwrap();
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, b"x").unwrap();
        let path = blocker.join("child.log");

        let error = open_log_file(&path).unwrap_err();
        let LogInitError::OpenFile { .. } = error;
        assert!(error.to_string().contains("cannot open log file"));
    }

    #[test]
    fn log_files_are_appended_not_truncated() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("dctl.log");
        std::fs::write(&path, b"existing\n").unwrap();

        drop(open_log_file(&path).unwrap());

        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(
            contents.starts_with("existing"),
            "opening the log must never discard earlier records"
        );
    }

    #[test]
    fn init_is_idempotent() {
        // Installing twice must not panic — integration tests run several
        // commands inside one process.
        let config = config();
        assert!(init(&config).is_ok());
        assert!(init(&config).is_ok());
    }

    #[test]
    fn filter_falls_back_to_the_level_when_the_env_is_unset() {
        // Guard against a DCTL_LOG in the developer's own environment.
        if std::env::var(FILTER_ENV).is_err() {
            let mut config = config();
            config.level = LogLevel::Debug;
            assert_eq!(config.filter().to_string(), "debug");
        }
    }
}
