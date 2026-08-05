//! What `dctl vault recover` reports.
//!
//! Two booleans rather than one, for the same reason `dctl init`'s report carries
//! two: they can genuinely differ, and collapsing them would make the record
//! claim work that did not happen ([the plan](https://doc.dctl.sh/project/plan)
//! §6).
//!
//! * [`Report::unlocked`] — the recovery phrase opened the vault.
//! * [`Report::password_changed`] — a new password slot is now in force.
//!
//! A `--dry-run` sets neither, and `--keep-password` sets only the first. A
//! script that read one combined "ok" would believe a password it cannot use is
//! now working, which is the failure the whole command exists to end.
//!
//! Nothing here carries a secret. The phrase that was used is not reported —
//! not in `--json`, not in the table — because this record goes to **stdout**,
//! and a phrase on stdout ends up in whatever the operator piped the command
//! into. Even naming which source supplied it is deliberately omitted: the `-v`
//! note from [`crate::session::secret`] already says that, on stderr, where a
//! pipeline does not collect it.

use serde::Serialize;

use crate::constants::{
    VAULT_COLUMN_SETTING, VAULT_COLUMN_VALUE, VAULT_FIELD_PASSWORD_CHANGED, VAULT_FIELD_REMOTE,
    VAULT_FIELD_UNLOCKED,
};
use crate::ctx::Ctx;
use crate::error::Result;
use crate::output::{Align, Border, Column, Table};

/// The result of one `dctl vault recover`.
#[derive(Clone, Debug, Serialize)]
pub struct Report {
    /// The remote that was recovered, as the user spelled it.
    pub remote: String,
    /// Whether the recovery phrase opened the vault.
    pub unlocked: bool,
    /// Whether a new password slot was written.
    pub password_changed: bool,
}

impl Report {
    #[must_use]
    pub fn new(remote: impl Into<String>, unlocked: bool, password_changed: bool) -> Self {
        Self {
            remote: remote.into(),
            unlocked,
            password_changed,
        }
    }

    /// The rows the text rendering shows. Labels are the JSON field names
    /// verbatim, so a script ported between formats changes its parser only.
    fn rows(&self) -> Vec<(&'static str, String)> {
        vec![
            (VAULT_FIELD_REMOTE, self.remote.clone()),
            (VAULT_FIELD_UNLOCKED, self.unlocked.to_string()),
            (
                VAULT_FIELD_PASSWORD_CHANGED,
                self.password_changed.to_string(),
            ),
        ]
    }

    /// Write the record to stdout in whichever format was requested.
    ///
    /// # Errors
    /// Any stdout failure other than a broken pipe.
    pub fn emit(&self, ctx: &Ctx) -> Result<()> {
        if ctx.out.format().is_json() {
            ctx.out.json(self)?;
            return Ok(());
        }

        let mut table = Table::new(vec![
            Column::new(VAULT_COLUMN_SETTING, Align::Left),
            Column::new(VAULT_COLUMN_VALUE, Align::Left),
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
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn ctx(args: &[&str]) -> Ctx {
        Ctx::new(Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied())).globals)
    }

    #[test]
    fn an_unlock_that_changed_no_password_says_so() {
        // The combination that makes two booleans necessary: the phrase worked
        // and the vault still has the password it had. One field would have to
        // lie in one direction or the other.
        let json = serde_json::to_value(Report::new("archive:", true, false)).unwrap();
        assert_eq!(json["unlocked"], true);
        assert_eq!(json["password_changed"], false);
    }

    #[test]
    fn a_dry_run_claims_neither() {
        let json = serde_json::to_value(Report::new("archive:", false, false)).unwrap();
        assert_eq!(json["unlocked"], false);
        assert_eq!(json["password_changed"], false);
    }

    #[test]
    fn nothing_secret_reaches_stdout() {
        // This record is what `--json` writes to stdout, which is what a
        // pipeline collects. Neither the phrase nor a password may be in it, in
        // any field, under any name.
        let json = serde_json::to_value(Report::new("archive:", true, true)).unwrap();
        let object = json.as_object().expect("a JSON object");
        for key in object.keys() {
            assert!(
                !key.contains("phrase") && !key.contains("password_source"),
                "'{key}' would put a secret's provenance on stdout"
            );
        }
        assert!(object["password_changed"].is_boolean());
    }

    #[test]
    fn text_row_labels_are_the_json_field_names() {
        let report = Report::new("archive:", true, true);
        let json = serde_json::to_value(&report).unwrap();
        for (label, _) in report.rows() {
            assert!(
                json.get(label).is_some(),
                "text row '{label}' has no matching JSON field"
            );
        }
    }

    #[test]
    fn every_format_emits_without_error() {
        for format in ["text", "json", "json-lines"] {
            let ctx = ctx(&["--format", format]);
            assert!(
                Report::new("archive:", true, true).emit(&ctx).is_ok(),
                "{format} failed"
            );
        }
    }
}
