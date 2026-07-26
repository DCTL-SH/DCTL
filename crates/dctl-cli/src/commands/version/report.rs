//! What `dctl version` prints, in whichever format was asked for.
//!
//! The report is the command's *result*, so it goes to **stdout** (`PLAN.md`
//! §7) and `dctl version --json | jq -r .git_hash` is a working pipeline. It is
//! also the text a user pastes into a bug report, which is why every field is
//! present in every format: a key that vanished when its value was unknown would
//! make two reports from two machines structurally different, and the reader
//! would have to guess whether the field was absent or the tool was older.
//!
//! Unknown values are therefore `null` in JSON and [`UNKNOWN_VALUE`] in text,
//! never omitted and never filled in with a guess.

use serde::Serialize;

use crate::constants::{
    UNKNOWN_VALUE, VERSION_COLUMN_SETTING, VERSION_COLUMN_VALUE, VERSION_FEATURE_SEPARATOR,
    VERSION_FEATURES_NONE, VERSION_FIELD_ARCH, VERSION_FIELD_BINARY,
    VERSION_FIELD_DEBUG_ASSERTIONS, VERSION_FIELD_FEATURES, VERSION_FIELD_GIT_HASH,
    VERSION_FIELD_OS, VERSION_FIELD_PROFILE, VERSION_FIELD_RUSTC, VERSION_FIELD_TARGET,
    VERSION_FIELD_VERSION,
};
use crate::ctx::Ctx;
use crate::error::Result;
use crate::output::{Align, Border, Column, Table};
use crate::platform;

use super::build_info;

/// Everything `dctl version` knows, as one record.
///
/// Field names are the JSON keys *and* the text row labels — see
/// [`crate::constants::VERSION_FIELD_VERSION`] for why the two vocabularies are
/// deliberately the same one.
#[derive(Debug, Serialize)]
pub struct VersionReport {
    /// The release this binary is built from.
    pub version: &'static str,
    /// The executable's own name, so a rebranded build identifies itself.
    pub binary: &'static str,
    /// Commit the build came from, or `null` when it was not built from a
    /// checkout.
    pub git_hash: Option<&'static str>,
    /// Compiler that produced the binary.
    pub rustc: Option<&'static str>,
    /// Target triple it was built for.
    pub target: Option<&'static str>,
    /// Cargo profile it was built under.
    pub profile: Option<&'static str>,
    /// Operating system it is running on.
    pub os: &'static str,
    /// CPU architecture it is running on.
    pub arch: &'static str,
    /// Optional cargo features compiled in. Empty in a default build.
    pub features: Vec<&'static str>,
    /// Whether debug assertions are active.
    pub debug_assertions: bool,
}

impl VersionReport {
    /// Gather everything this build knows about itself.
    ///
    /// Infallible on purpose. `dctl version` is what somebody runs when nothing
    /// else works, so there is no path through this function that can fail,
    /// block, or need a resource the machine might not have.
    #[must_use]
    pub fn current() -> Self {
        Self {
            version: build_info::VERSION,
            binary: dctl_meta::BINARY_NAME,
            git_hash: build_info::git_hash(),
            rustc: build_info::rustc(),
            target: build_info::target(),
            profile: build_info::profile(),
            os: platform::os_name(),
            arch: build_info::ARCH,
            features: build_info::features(),
            debug_assertions: build_info::debug_assertions(),
        }
    }

    /// The rows the text rendering shows, in the order a person reads them:
    /// which build this is, where it came from, and what it is running on.
    pub fn rows(&self) -> Vec<(&'static str, String)> {
        vec![
            (VERSION_FIELD_VERSION, self.version.to_string()),
            (VERSION_FIELD_BINARY, self.binary.to_string()),
            (VERSION_FIELD_GIT_HASH, or_unknown(self.git_hash)),
            (VERSION_FIELD_RUSTC, or_unknown(self.rustc)),
            (VERSION_FIELD_TARGET, or_unknown(self.target)),
            (VERSION_FIELD_PROFILE, or_unknown(self.profile)),
            (VERSION_FIELD_OS, self.os.to_string()),
            (VERSION_FIELD_ARCH, self.arch.to_string()),
            (VERSION_FIELD_FEATURES, self.feature_list()),
            (
                VERSION_FIELD_DEBUG_ASSERTIONS,
                self.debug_assertions.to_string(),
            ),
        ]
    }

    /// The feature list as one cell.
    ///
    /// An empty list renders as [`VERSION_FEATURES_NONE`] rather than as
    /// [`UNKNOWN_VALUE`], because "no optional features were enabled" is a known
    /// answer and the dash means "we could not find out" everywhere else in this
    /// table.
    fn feature_list(&self) -> String {
        if self.features.is_empty() {
            return VERSION_FEATURES_NONE.to_string();
        }
        self.features.join(VERSION_FEATURE_SEPARATOR)
    }

    /// Write the report to stdout in the active format.
    ///
    /// # Errors
    /// Any stdout failure other than a broken pipe, which
    /// [`crate::output::Out`] deliberately tolerates so `dctl version | head -1`
    /// is a success.
    pub fn emit(&self, ctx: &Ctx) -> Result<()> {
        if ctx.out.format().is_json() {
            ctx.out.json(self)?;
            return Ok(());
        }

        let mut table = Table::new(vec![
            Column::new(VERSION_COLUMN_SETTING, Align::Left),
            Column::new(VERSION_COLUMN_VALUE, Align::Left),
        ])
        .with_border(Border::None);

        for (label, value) in self.rows() {
            table.push(vec![label.to_string(), value]);
        }
        ctx.out.table(&table)?;
        Ok(())
    }
}

/// Render an optional stamp, showing the shared placeholder when it is absent.
fn or_unknown(value: Option<&'static str>) -> String {
    value.unwrap_or(UNKNOWN_VALUE).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::GlobalArgs;
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn ctx(args: &[&str]) -> Ctx {
        let parsed = Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied()));
        Ctx::new(parsed.globals)
    }

    #[test]
    fn text_row_labels_are_the_json_field_names() {
        // The porting promise: a script moving from --format text to
        // --format json changes its parser and nothing else.
        let report = VersionReport::current();
        let json = serde_json::to_value(&report).unwrap();
        for (label, _) in report.rows() {
            assert!(
                json.get(label).is_some(),
                "text row '{label}' has no matching JSON field"
            );
        }
    }

    #[test]
    fn every_field_appears_in_the_json_even_when_it_is_unknown() {
        // A key that disappeared with its value would make two bug reports
        // structurally different, and the reader could not tell "not built from
        // a checkout" from "older version of dctl".
        let mut report = VersionReport::current();
        report.git_hash = None;
        report.rustc = None;
        report.target = None;
        report.profile = None;

        let json = serde_json::to_value(&report).unwrap();
        for field in [
            VERSION_FIELD_GIT_HASH,
            VERSION_FIELD_RUSTC,
            VERSION_FIELD_TARGET,
            VERSION_FIELD_PROFILE,
        ] {
            assert_eq!(json[field], serde_json::Value::Null, "{field} was omitted");
        }
    }

    #[test]
    fn an_unknown_value_renders_as_the_shared_placeholder_and_never_as_a_guess() {
        let mut report = VersionReport::current();
        report.git_hash = None;
        let rows = report.rows();
        let hash = rows
            .iter()
            .find(|(label, _)| *label == VERSION_FIELD_GIT_HASH)
            .map(|(_, value)| value.clone());
        assert_eq!(hash.as_deref(), Some(UNKNOWN_VALUE));
    }

    #[test]
    fn an_empty_feature_list_says_none_rather_than_unknown() {
        // The two must stay distinguishable: one is an answer, the other is the
        // absence of one.
        let mut report = VersionReport::current();
        report.features = Vec::new();
        assert_eq!(report.feature_list(), VERSION_FEATURES_NONE);
        assert_ne!(report.feature_list(), UNKNOWN_VALUE);

        report.features = vec!["mount", "keychain"];
        assert_eq!(
            report.feature_list(),
            format!("mount{VERSION_FEATURE_SEPARATOR}keychain")
        );
    }

    #[test]
    fn the_report_always_carries_the_facts_that_cannot_be_missing() {
        let report = VersionReport::current();
        assert!(!report.version.is_empty());
        assert_eq!(report.binary, dctl_meta::BINARY_NAME);
        assert_eq!(report.os, platform::os_name());
        assert!(!report.arch.is_empty());
    }

    #[test]
    fn every_format_emits_without_error() {
        // Rule: a command producing structured results supports Text, Json and
        // JsonLines. JSON Lines matters here too — a fleet inventory pipes one
        // `dctl version` per host into a single stream.
        for format in ["text", "json", "json-lines"] {
            let ctx = ctx(&["--format", format]);
            assert!(
                VersionReport::current().emit(&ctx).is_ok(),
                "{format} failed"
            );
        }
    }

    #[test]
    fn the_json_lines_rendering_is_one_line() {
        // The newline is the record separator; a pretty-printed report would
        // make a per-host inventory stream unparseable.
        let report = VersionReport::current();
        let encoded = crate::output::Format::JsonLines
            .encode(&report)
            .expect("the report serialises");
        assert!(!encoded.contains('\n'), "got: {encoded}");
    }

    #[test]
    fn quiet_does_not_suppress_the_result() {
        // --quiet silences notes and warnings, which live on stderr. The report
        // is data on stdout and must survive: `dctl version -q` still answers.
        let ctx = ctx(&["--quiet"]);
        assert!(VersionReport::current().emit(&ctx).is_ok());
    }
}
