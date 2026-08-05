//! What `dctl init` tells the caller it did.
//!
//! The record is the *result*, so it goes to **stdout**
//! ([the plan](https://doc.dctl.sh/project/plan) §7): the congratulations go to
//! stderr via [`crate::output::Out::success`], and
//! `dctl init --name archive --base local:/v --json | jq -r .vault_remote` stays
//! a working pipeline.
//!
//! One record type serves all three formats, and it carries **two** booleans
//! rather than one. [`InitReport::created`] is true only after `Vault::init` has
//! returned; [`InitReport::registered`] is true only after the configuration
//! naming both remotes has been saved. They can genuinely differ — a vault that
//! exists on its store but whose addressing could not be written is a real
//! outcome, and a recoverable one (`dctl config import`) — so collapsing them
//! into a single "ok" would have the report claim work that did not happen,
//! which is the one thing [the plan](https://doc.dctl.sh/project/plan) §6
//! forbids outright.
//!
//! ## What is deliberately absent
//!
//! The recovery phrase. [`InitReport::recovery_phrase_issued`] is a boolean and
//! will stay one: `dctl init --json | tee provisioning.log` is an ordinary thing
//! to run, and a phrase in a log file is a compromised vault — permanently,
//! because unlike a password it cannot be rotated away. The words go to stderr
//! once, from [`super::phrase`]; this field is how a script confirms they were
//! produced without ever being able to hold them. A test below asserts the
//! absence rather than trusting the struct definition to stay this shape.

use serde::Serialize;

use super::password::Source;
use super::plan::InitPlan;
use crate::constants;
use crate::ctx::Ctx;
use crate::error::Result;
use crate::output::{Align, Border, Column, Table};

/// The outcome of one `dctl init` invocation.
#[derive(Debug, Serialize)]
pub struct InitReport {
    /// The sealed view's name: everything written through it is encrypted.
    pub vault_remote: String,
    /// The object view's name: opaque ciphertext, and no password needed to
    /// replicate it.
    pub store_remote: String,
    /// The location the objects are stored at, as it was typed.
    pub base: String,
    /// Local encrypted index this vault uses.
    pub index: String,
    /// Whether a vault now exists that did not before.
    pub created: bool,
    /// Whether the configuration now names both remotes.
    pub registered: bool,
    /// Which mechanism supplied the password. Absent when none was read —
    /// a dry run never asks for one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_source: Option<Source>,
    /// Whether this run was forbidden from changing anything.
    pub dry_run: bool,
    /// Whether a recovery phrase was generated and shown.
    ///
    /// Never the phrase itself — see the module documentation. A `false` here on
    /// a run that reports `created: true` would mean a vault with one way in,
    /// which is the state this whole feature exists to make impossible.
    pub recovery_phrase_issued: bool,
}

impl InitReport {
    /// Build the record for a plan that was carried out, or not.
    #[must_use]
    pub fn new(
        plan: &InitPlan,
        created: bool,
        registered: bool,
        password_source: Option<Source>,
        dry_run: bool,
        recovery_phrase_issued: bool,
    ) -> Self {
        Self {
            vault_remote: plan.vault_name.clone(),
            store_remote: plan.store_name.clone(),
            base: plan.base.clone(),
            index: plan.index.display().to_string(),
            created,
            registered,
            password_source,
            dry_run,
            recovery_phrase_issued,
        }
    }

    /// The rows the text rendering shows, in a deliberate order: the two names
    /// the user will type from now on, where the bytes live, where the index is,
    /// and then what actually happened.
    ///
    /// Labels are the JSON field names verbatim — see
    /// [`constants::INIT_FIELD_VAULT_REMOTE`].
    fn rows(&self) -> Vec<(&'static str, String)> {
        let mut rows = vec![
            (
                constants::INIT_FIELD_VAULT_REMOTE,
                self.vault_remote.clone(),
            ),
            (
                constants::INIT_FIELD_STORE_REMOTE,
                self.store_remote.clone(),
            ),
            (constants::INIT_FIELD_BASE, self.base.clone()),
            (constants::INIT_FIELD_INDEX, self.index.clone()),
            (constants::INIT_FIELD_CREATED, self.created.to_string()),
            (
                constants::INIT_FIELD_REGISTERED,
                self.registered.to_string(),
            ),
            (
                constants::INIT_FIELD_RECOVERY_PHRASE_ISSUED,
                self.recovery_phrase_issued.to_string(),
            ),
        ];
        if let Some(source) = self.password_source {
            rows.push((
                constants::INIT_FIELD_PASSWORD_SOURCE,
                source.describe().to_string(),
            ));
        }
        rows
    }

    /// Write the record to stdout in whichever format was requested.
    ///
    /// # Errors
    /// Any stdout failure other than a broken pipe, which
    /// [`crate::output::Out`] deliberately tolerates.
    pub fn emit(&self, ctx: &Ctx) -> Result<()> {
        if ctx.out.format().is_json() {
            ctx.out.json(self)?;
            return Ok(());
        }

        let mut table = Table::new(vec![
            Column::new(constants::INIT_COLUMN_SETTING, Align::Left),
            Column::new(constants::INIT_COLUMN_VALUE, Align::Left),
        ])
        .with_border(Border::None);

        for (label, value) in self.rows() {
            table.push(vec![label.to_string(), value]);
        }
        ctx.out.table(&table)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::GlobalArgs;
    use crate::commands::init::InitArgs;
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

    fn plan(ctx: &Ctx) -> InitPlan {
        InitPlan::resolve(
            ctx,
            &InitArgs {
                legacy_location: None,
                name: Some("archive".into()),
                base: Some("local:/srv/vault".into()),
                store_name: None,
            },
        )
        .expect("a legal plan")
    }

    #[test]
    fn a_dry_run_never_claims_a_vault_was_created_or_registered() {
        // The two fields a script trusts. A dry run must set neither.
        let ctx = ctx(&["--dry-run", "--index", "/tmp/x.redb"]);
        let report = InitReport::new(&plan(&ctx), false, false, None, true, false);
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["created"], false);
        assert_eq!(json["registered"], false);
        assert_eq!(json["dry_run"], true);
    }

    #[test]
    fn a_vault_that_exists_but_could_not_be_addressed_says_so() {
        // The outcome that makes two booleans necessary rather than tidy: the
        // envelope is on the store and the configuration is not written. One
        // combined field would have to lie in one direction or the other.
        let ctx = ctx(&["--index", "/tmp/x.redb"]);
        let report = InitReport::new(&plan(&ctx), true, false, Some(Source::Prompt), false, true);
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["created"], true);
        assert_eq!(json["registered"], false);
    }

    #[test]
    fn a_completed_run_names_both_remotes_and_no_password() {
        let ctx = ctx(&["--index", "/tmp/x.redb"]);
        let report = InitReport::new(&plan(&ctx), true, true, Some(Source::Prompt), false, true);
        let encoded = serde_json::to_string(&report).unwrap();
        assert!(
            encoded.contains("\"vault_remote\":\"archive\""),
            "{encoded}"
        );
        assert!(
            encoded.contains("\"store_remote\":\"archive-store\""),
            "{encoded}"
        );
        assert!(encoded.contains("prompt"), "got: {encoded}");
        // Nothing password-shaped may appear beyond the mechanism's name.
        assert!(!encoded.contains("password\":\""), "got: {encoded}");
    }

    #[test]
    fn the_recovery_phrase_is_reported_as_issued_and_never_carried() {
        // The report is what `--json` writes to stdout, and stdout is what ends
        // up in `| tee provisioning.log`. A phrase there is a compromised vault
        // that stays compromised, because changing the password does not revoke
        // it. Asserted on the encoded document rather than on the struct, so a
        // field added later with a plausible name is caught too.
        let ctx = ctx(&["--index", "/tmp/x.redb"]);
        let report = InitReport::new(&plan(&ctx), true, true, Some(Source::Flag), false, true);
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["recovery_phrase_issued"], true);

        let object = json.as_object().expect("a JSON object");
        for (field, value) in object {
            let rendered = value.to_string();
            assert!(
                !rendered.split_whitespace().count().eq(&24),
                "'{field}' looks like a 24-word phrase: {rendered}"
            );
        }
        // And the only phrase-shaped field is the boolean.
        let phrase_fields: Vec<&String> = object
            .keys()
            .filter(|key| key.contains("phrase") || key.contains("mnemonic"))
            .collect();
        assert_eq!(phrase_fields, ["recovery_phrase_issued"]);
        assert!(json["recovery_phrase_issued"].is_boolean());
    }

    #[test]
    fn a_dry_run_reports_no_phrase_because_it_created_no_vault() {
        // The pairing that matters: `created` and `recovery_phrase_issued` are
        // true together or false together, because a vault is never created
        // without a second key and a phrase is never issued without a vault.
        let ctx = ctx(&["--dry-run", "--index", "/tmp/x.redb"]);
        let report = InitReport::new(&plan(&ctx), false, false, None, true, false);
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["created"], json["recovery_phrase_issued"]);
    }

    #[test]
    fn the_password_source_is_omitted_when_none_was_read() {
        let ctx = ctx(&["--index", "/tmp/x.redb"]);
        let report = InitReport::new(&plan(&ctx), false, false, None, true, false);
        let json = serde_json::to_value(&report).unwrap();
        assert!(json.get("password_source").is_none());
    }

    #[test]
    fn text_row_labels_are_the_json_field_names() {
        // The porting promise: a user moving a script from --format text to
        // --format json must not have to learn a second vocabulary.
        let ctx = ctx(&["--index", "/tmp/x.redb"]);
        let report = InitReport::new(&plan(&ctx), true, true, Some(Source::Flag), false, true);
        let json = serde_json::to_value(&report).unwrap();
        for (label, _) in report.rows() {
            assert!(
                json.get(label).is_some(),
                "text row '{label}' has no matching JSON field"
            );
        }
    }

    #[test]
    fn the_text_rendering_carries_every_resolved_value() {
        let ctx = ctx(&["--index", "/tmp/x.redb"]);
        let report = InitReport::new(&plan(&ctx), true, true, None, false, true);
        let rendered: Vec<String> = report.rows().into_iter().map(|(_, v)| v).collect();
        assert!(rendered.contains(&"archive".to_string()));
        assert!(rendered.contains(&"archive-store".to_string()));
        assert!(rendered.contains(&"local:/srv/vault".to_string()));
        assert!(rendered.contains(&"/tmp/x.redb".to_string()));
    }

    #[test]
    fn every_format_emits_without_error() {
        // Rule: a command that produces structured results supports Text, Json
        // and JsonLines. Exercising all three catches a format that was never
        // wired up rather than one that merely looks wrong.
        for format in ["text", "json", "json-lines"] {
            let ctx = ctx(&["--format", format, "--index", "/tmp/x.redb"]);
            let report = InitReport::new(&plan(&ctx), true, true, Some(Source::File), false, true);
            assert!(report.emit(&ctx).is_ok(), "{format} failed");
        }
    }
}
