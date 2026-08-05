//! Log severity levels and their mapping onto verbosity flags.

use clap::ValueEnum;

/// Severity threshold for emitted log records.
///
/// Named rather than numeric so `--log-level` is self-documenting in a script
/// and in a config file.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
#[value(rename_all = "lower")]
pub enum LogLevel {
    /// Failures only. What `--quiet` leaves visible: a silent failure is the one
    /// outcome <https://doc.dctl.sh/project/plan> §7 forbids outright.
    Error,
    /// Failures plus anything the user should look at. The default.
    #[default]
    Warn,
    /// Per-operation progress: one record per file transferred.
    Info,
    /// Per-stage detail inside an operation, plus retry decisions.
    Debug,
    /// Everything, including per-chunk activity. Extremely verbose on large
    /// files — a 50 GB transfer at 4 MiB chunks emits ~12,800 records.
    Trace,
}

impl LogLevel {
    /// Map a `-v` repetition count onto a level.
    #[must_use]
    pub const fn from_verbosity(count: u8) -> Self {
        match count {
            0 => Self::Warn,
            1 => Self::Info,
            2 => Self::Debug,
            _ => Self::Trace,
        }
    }

    /// The lowercase name used in `EnvFilter` directives and JSON records.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::LogLevel;

    #[test]
    fn verbosity_saturates_at_trace() {
        assert_eq!(LogLevel::from_verbosity(0), LogLevel::Warn);
        assert_eq!(LogLevel::from_verbosity(1), LogLevel::Info);
        assert_eq!(LogLevel::from_verbosity(2), LogLevel::Debug);
        assert_eq!(LogLevel::from_verbosity(3), LogLevel::Trace);
        assert_eq!(LogLevel::from_verbosity(200), LogLevel::Trace);
    }

    #[test]
    fn ordering_runs_from_quiet_to_loud() {
        assert!(LogLevel::Error < LogLevel::Warn);
        assert!(LogLevel::Warn < LogLevel::Info);
        assert!(LogLevel::Trace > LogLevel::Debug);
    }

    #[test]
    fn names_are_filter_directive_compatible() {
        for level in [
            LogLevel::Error,
            LogLevel::Warn,
            LogLevel::Info,
            LogLevel::Debug,
            LogLevel::Trace,
        ] {
            assert_eq!(level.as_str(), level.as_str().to_lowercase());
            assert!(!level.as_str().is_empty());
        }
    }

    #[test]
    fn default_is_warnings_only() {
        assert_eq!(LogLevel::default(), LogLevel::Warn);
    }
}
