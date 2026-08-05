//! Log record formats.

use clap::ValueEnum;

/// How log records are rendered.
///
/// [The plan](https://doc.dctl.sh/project/plan) §7 requires both a human sink
/// and a JSON sink: an operator reading a terminal and a log pipeline ingesting
/// records have opposite needs, and making one serve both badly is a false
/// economy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lower")]
pub enum LogFormat {
    /// Aligned, colourised, one line per record. For a person at a terminal.
    #[default]
    Human,
    /// Newline-delimited JSON objects with structured fields preserved. For
    /// ingestion by a log pipeline.
    Json,
    /// Human layout with no ANSI styling — for a log file or a CI transcript
    /// where escape sequences are noise.
    Plain,
}

impl LogFormat {
    /// Whether records should carry ANSI styling.
    #[must_use]
    pub const fn is_colored(self) -> bool {
        matches!(self, Self::Human)
    }

    /// Whether records are machine-structured.
    #[must_use]
    pub const fn is_structured(self) -> bool {
        matches!(self, Self::Json)
    }
}

#[cfg(test)]
mod tests {
    use super::LogFormat;

    #[test]
    fn only_the_human_format_is_coloured() {
        assert!(LogFormat::Human.is_colored());
        assert!(!LogFormat::Plain.is_colored());
        assert!(!LogFormat::Json.is_colored());
    }

    #[test]
    fn only_json_is_structured() {
        assert!(LogFormat::Json.is_structured());
        assert!(!LogFormat::Human.is_structured());
    }

    #[test]
    fn default_is_human() {
        assert_eq!(LogFormat::default(), LogFormat::Human);
    }
}
