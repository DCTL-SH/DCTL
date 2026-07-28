//! What a replication tells the caller it did.
//!
//! The record is the *result*, so it goes to **stdout** in whichever `--format`
//! was asked for (`PLAN.md` §7); the commentary, the warnings and the end-of-run
//! summary stay on stderr, where they cannot corrupt a pipeline. An offsite job
//! is scheduled software, and `dctl replicate archive-store: offsite-store:
//! --json | jq '.summary.failed'` is how it reports to a monitoring system.
//!
//! ## Two fields that must never be collapsed
//!
//! [`Report::dry_run`] and [`Summary::replicated`](super::plan::Summary) are
//! separate, and a dry run sets the first and reports the second as what *would*
//! move. A single "ok" would have the report claim work that did not happen,
//! which `PLAN.md` §6 forbids outright — and this is the command where that lie
//! would be most expensive, because the thing being claimed is the existence of
//! a second copy.
//!
//! [`Report::verify_mode`] is carried for the same reason every integrity report
//! carries it: "1 204 objects replicated" means something very different under
//! `checksum` (the destination stored what we sent) and under `strict` (every
//! object was read back and its BLAKE3 compared), and a report that does not say
//! which is incomplete.
//!
//! ## Which rows appear
//!
//! Only objects that *did something*. A store with ten million already-replicated
//! objects and fifty new ones is fifty rows, not ten million and fifty; the
//! skipped count is in the summary, so nothing is hidden — only summarised. That
//! is the transfer family's rule, followed here so a reader porting between
//! `dctl sync --dry-run` and `dctl replicate --dry-run` is reading the same
//! report in the same shape.

use serde::Serialize;

use crate::constants::{PLAN_COLUMN_ACTION, PLAN_COLUMN_PATH, PLAN_COLUMN_SIZE};
use crate::error::{CliError, Result};
use crate::exit::ExitCode;
use crate::output::{Align, Border, Column, Format, Out, Table, size};

use super::plan::{Item, Summary};

/// The result of one `dctl replicate` invocation.
#[derive(Debug, Serialize)]
pub struct Report {
    /// The verb, so a record lifted out of a log says which command produced it.
    ///
    /// A compliance reviewer reading an audit trail needs to see `replicate`
    /// here and not `copy`: the two differ in whether a decryption key was held,
    /// which is the fact the whole separation-of-duties argument rests on.
    pub command: &'static str,
    /// The source store, as it was typed.
    pub source: String,
    /// How the source earned its place — `declared` or `demonstrated`.
    pub source_standing: &'static str,
    /// The destination store, as it was typed.
    pub destination: String,
    /// How the destination earned its place.
    pub destination_standing: &'static str,
    /// Which `--verify` strength the objects were moved under.
    pub verify_mode: String,
    /// Whether this run was forbidden from changing anything.
    pub dry_run: bool,
    /// Aggregate counts.
    pub summary: Summary,
    /// One record per object that did something. Skips are counted, not listed.
    pub objects: Vec<Item>,
}

impl Report {
    /// Assemble the record for a run, planned or performed.
    #[must_use]
    pub fn new(
        command: &'static str,
        source: &super::target::Store,
        destination: &super::target::Store,
        verify_mode: String,
        dry_run: bool,
        summary: Summary,
        items: &[Item],
    ) -> Self {
        Self {
            command,
            source: source.spec.clone(),
            source_standing: source.standing.slug(),
            destination: destination.spec.clone(),
            destination_standing: destination.standing.slug(),
            verify_mode,
            dry_run,
            summary,
            objects: items
                .iter()
                .filter(|item| item.action.is_action())
                .cloned()
                .collect(),
        }
    }

    /// Render exactly the bytes stdout should receive.
    ///
    /// # Errors
    /// Only if serialisation fails, which is reported rather than swallowed.
    pub fn render(&self, out: &Out) -> Result<String> {
        match out.format() {
            Format::Text => Ok(self.render_text(out)),
            Format::Json => encode(Format::Json, self).map(|json| format!("{json}\n")),
            Format::JsonLines => {
                let mut rendered = String::new();
                for object in &self.objects {
                    rendered.push_str(&encode(Format::JsonLines, object)?);
                    rendered.push('\n');
                }
                Ok(rendered)
            }
        }
    }

    /// Write the record to stdout.
    ///
    /// # Errors
    /// Propagates a stdout write failure other than a broken pipe, which
    /// [`Out`] deliberately tolerates so `dctl replicate --dry-run | head` is a
    /// success.
    pub fn emit(&self, out: &Out) -> Result<()> {
        out.write(self.render(out)?)?;
        Ok(())
    }

    /// The human view: an aligned table of objects, and nothing else on stdout.
    ///
    /// A run with nothing to do prints **nothing**, rather than a bare header. A
    /// header with no rows under it reads as output in a pipe, and an offsite
    /// job whose whole point is to be boring should produce no stdout on the
    /// nights it has nothing to move.
    fn render_text(&self, out: &Out) -> String {
        if self.objects.is_empty() {
            return String::new();
        }

        let mut table = Table::new(vec![
            Column::new(PLAN_COLUMN_ACTION, Align::Left),
            Column::new(PLAN_COLUMN_SIZE, Align::Right).with_style(out.palette().number()),
            Column::new(PLAN_COLUMN_PATH, Align::Left).with_style(out.palette().path()),
        ])
        .with_border(Border::Header);

        for object in &self.objects {
            table.push(vec![
                object.action.slug().to_string(),
                size::bytes(object.size, out.units()),
                object.key.clone(),
            ]);
        }
        table.render(out.palette())
    }
}

/// Serialise a value, turning a serde failure into a classified CLI error.
fn encode<T: Serialize>(format: Format, value: &T) -> Result<String> {
    format.encode(value).map_err(|error| {
        CliError::new(
            ExitCode::Uncategorised,
            format!("cannot serialise the replication report: {error}"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::replicate::plan::Action;
    use crate::commands::replicate::target::{Side, open};
    use crate::config::{Config, LocalDef, RemoteDef};
    use crate::output::{ColorChoice, Units};
    use std::path::Path;

    fn out(format: Format) -> Out {
        Out::new(format, ColorChoice::Never, Units::Binary, false, 0)
    }

    fn declared(config: &mut Config, name: &str, path: &Path) {
        config.insert(
            name,
            RemoteDef::Local(LocalDef {
                path: path.to_path_buf(),
                verify: None,
                require_vault: true,
            }),
        );
    }

    /// A report over two declared stores, so no envelope fixture is needed.
    async fn report(items: Vec<Item>, summary: Summary, dry_run: bool) -> Report {
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        declared(&mut config, "primary-store", &dir.path().join("a"));
        declared(&mut config, "offsite-store", &dir.path().join("b"));

        let source = open(
            &config,
            "primary-store:",
            Side::Source,
            dctl_store::LinkPolicy::default(),
        )
        .await
        .unwrap();
        let destination = open(
            &config,
            "offsite-store:",
            Side::Destination,
            dctl_store::LinkPolicy::default(),
        )
        .await
        .unwrap();

        Report::new(
            "replicate",
            &source,
            &destination,
            "strict".to_string(),
            dry_run,
            summary,
            &items,
        )
    }

    fn items() -> Vec<Item> {
        vec![
            Item {
                action: Action::Replicate,
                key: "data/aa".into(),
                size: 1024,
                reason: "missing-at-destination",
            },
            Item {
                action: Action::Skip,
                key: "data/bb".into(),
                size: 2048,
                reason: "exists",
            },
            Item {
                action: Action::Failed,
                key: "data/cc".into(),
                size: 16,
                reason: "source-unreadable",
            },
        ]
    }

    #[tokio::test]
    async fn json_carries_both_ends_the_mode_and_the_counts() {
        let summary = Summary {
            objects: 3,
            replicated: 1,
            skipped: 1,
            failed: 1,
            bytes: 1024,
            extra: 2,
            ..Summary::default()
        };
        let report = report(items(), summary, false).await;
        let rendered = report.render(&out(Format::Json)).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&rendered).unwrap();

        assert_eq!(parsed["command"], "replicate");
        assert_eq!(parsed["source"], "primary-store:");
        assert_eq!(parsed["destination"], "offsite-store:");
        assert_eq!(parsed["source_standing"], "declared");
        assert_eq!(parsed["verify_mode"], "strict");
        assert_eq!(parsed["dry_run"], false);
        assert_eq!(parsed["summary"]["failed"], 1);
        assert_eq!(parsed["summary"]["extra"], 2);
        // Skips are counted, never listed.
        assert_eq!(parsed["objects"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn a_dry_run_says_so_and_never_claims_a_copy_exists() {
        // The field a monitoring system trusts to mean "there is a second copy".
        let report = report(
            items(),
            Summary {
                replicated: 1,
                ..Summary::default()
            },
            true,
        )
        .await;
        let parsed: serde_json::Value =
            serde_json::from_str(&report.render(&out(Format::Json)).unwrap()).unwrap();
        assert_eq!(parsed["dry_run"], true);
    }

    #[tokio::test]
    async fn json_lines_emits_one_object_per_line_and_no_summary() {
        let report = report(items(), Summary::default(), false).await;
        let rendered = report.render(&out(Format::JsonLines)).unwrap();
        assert_eq!(rendered.lines().count(), 2);
        for line in rendered.lines() {
            let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
            assert!(parsed.get("key").is_some());
            assert!(parsed.get("summary").is_none());
        }
    }

    #[tokio::test]
    async fn the_text_table_lists_the_actions_and_counts_the_rest() {
        let report = report(items(), Summary::default(), false).await;
        let rendered = report.render(&Out::plain()).unwrap();
        assert!(rendered.contains("replicate"));
        assert!(rendered.contains("data/aa"));
        assert!(rendered.contains("failed"));
        assert!(
            !rendered.contains("data/bb"),
            "skipped objects are counted, not listed"
        );
    }

    #[tokio::test]
    async fn a_night_with_nothing_to_move_prints_nothing_at_all() {
        let report = report(
            vec![Item {
                action: Action::Skip,
                key: "data/aa".into(),
                size: 1,
                reason: "exists",
            }],
            Summary {
                objects: 1,
                skipped: 1,
                ..Summary::default()
            },
            false,
        )
        .await;
        assert_eq!(report.render(&Out::plain()).unwrap(), "");
        assert_eq!(report.render(&out(Format::JsonLines)).unwrap(), "");
        // The JSON document still exists: a consumer needs the zero.
        assert!(!report.render(&out(Format::Json)).unwrap().is_empty());
    }

    #[tokio::test]
    async fn every_format_emits_without_error() {
        for format in [Format::Text, Format::Json, Format::JsonLines] {
            let report = report(items(), Summary::default(), false).await;
            assert!(report.emit(&out(format)).is_ok(), "{format:?} failed");
        }
    }
}
