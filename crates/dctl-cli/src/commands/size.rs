//! `dctl size` — how many objects, and how many bytes.
//!
//! The cheapest question in the family and the one most often asked from a
//! script: two numbers, over the same scope every other listing verb uses, so
//! `dctl size --include "*.raw"` and `dctl ls --include "*.raw" | wc -l` agree by
//! construction.
//!
//! ## Two renderings of the same number
//!
//! The text report prints the rounded human figure *and* the exact byte count:
//!
//! ```text
//! Total objects: 1,234
//! Total size (plaintext): 1.44 GiB (1546188226 bytes)
//! ```
//!
//! Both, because they answer different questions. `1.44 GiB` is what a person
//! reads; `1546188226` is what gets subtracted from a quota, and a rounded
//! figure quietly loses up to five per cent of it. The JSON shape carries only
//! the exact values — a machine has no use for a rounded one and every use for a
//! stable one.
//!
//! ## Which bytes were counted, said out loud
//!
//! `(plaintext)` is not decoration. A sealed vault's index records the length of
//! each file as it was *written*; the objects the provider stores and bills for
//! are larger, by the envelope and the per-chunk AEAD tags. Both figures are
//! true and they are not equal, and this is the one command that reduces a whole
//! vault to a single number people then compare against an invoice or a quota.
//! An unlabelled total is a number two readers read two ways — one concludes the
//! provider is overcharging, the other sizes a migration short — so the basis
//! comes from [`Sizes`], travels with the source that produced the entries, and
//! is printed on the line itself rather than buried in a note nobody reads.
//!
//! A plain remote or a local directory reports `(stored)`: those bytes are the
//! provider's own figure, so there is nothing to reconcile. The same vault
//! measured through its store remote — `dctl size archive-store:` — gives the
//! sealed total, which is what makes the two views reconcilable rather than
//! merely different.
//!
//! ## Memory
//!
//! Two `u64`s, whatever the vault holds. This is the command that proves the
//! streaming pipeline is real: counting ten million objects must not need ten
//! million anything (`PLAN.md` §16.2).
//!
//! ## Where the objects come from
//!
//! [`listing::source::open`] — one call that reaches a sealed vault, a plain
//! object store or a local directory through [`crate::source`], so this command
//! never learns which it was given.

use clap::Args;
use serde::Serialize;

use crate::constants::{
    SIZE_PLAINTEXT_NOTE, SIZE_REPORT_EXACT_UNIT, SIZE_REPORT_LABEL_BYTES, SIZE_REPORT_LABEL_OBJECTS,
};
use crate::ctx::Ctx;
use crate::error::Result;
use crate::output::Units;
use crate::output::size::{bytes, count};
use crate::source::Sizes;

use super::listing::{self, Filter, Target};

/// Arguments for `dctl size`.
#[derive(Args, Debug)]
pub struct SizeArgs {
    /// Remote and path to measure, as REMOTE:PATH. Defaults to --remote.
    #[arg(value_name = "REMOTE:PATH")]
    pub path: Option<String>,
}

/// The totals, as a machine reads them.
///
/// Field names are rclone's `size --json` shape, lower case, so a script that
/// already reads `.count` and `.bytes` keeps working. Both are exact: rounding
/// belongs in the text rendering and nowhere else.
///
/// `sizes` is DCTL's addition and has no rclone counterpart, because rclone has
/// no vault and therefore never has two defensible answers for "how many bytes".
/// It is a field rather than an inference so that a capacity script comparing
/// this figure against a provider's own is not left to guess which of the two it
/// was handed — the guess being wrong is silent, and the number is the input to
/// a decision about buying storage.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Totals {
    /// Objects in scope.
    pub count: u64,
    /// Sum of their sizes, in bytes, on the basis named by `sizes`.
    pub bytes: u64,
    /// What `bytes` counted: plaintext lengths, or objects as stored.
    pub sizes: Sizes,
}

/// Measure everything under the given path.
///
/// # Errors
/// A malformed spec or filter is a usage error; an unreachable index is fatal.
pub async fn run(ctx: &Ctx, args: &SizeArgs) -> Result<()> {
    let target = Target::parse(args.path.as_deref(), ctx.globals.remote.as_deref())?;
    let filter = Filter::from_globals(&ctx.globals)?;
    let mut stream = listing::open(ctx, &target, filter).await?;

    let mut totals = Totals {
        count: 0,
        bytes: 0,
        // Taken from the stream rather than decided here: this command must not
        // be a second place that works out what a remote is.
        sizes: stream.sizes(),
    };
    stream
        .try_for_each(|entry| {
            totals.count = totals.count.saturating_add(1);
            // Saturating rather than wrapping: a vault whose total overflows u64
            // is not something DCTL will meet, and reporting u64::MAX would at
            // least be visibly wrong where a wrapped value would look plausible.
            totals.bytes = totals.bytes.saturating_add(entry.size());
            Ok(())
        })
        .await?;

    if ctx.out.is_json() {
        ctx.out.json(&totals)?;
    } else {
        for line in report(&totals, ctx.out.units()) {
            ctx.out.line(line)?;
        }
    }

    // The elaboration, on stderr in both formats so it never lands inside the
    // data. The label on the total already carries the fact; this says what to
    // do about it, and only when there is something to do — a stored total is
    // the provider's own number and needs no caveat.
    if totals.sizes.understates_stored_bytes() {
        ctx.out.info(SIZE_PLAINTEXT_NOTE);
    }

    Ok(())
}

/// The two text lines of the report.
///
/// Returned rather than printed so the exact wording is testable without a
/// terminal — this is the output people paste into capacity spreadsheets.
///
/// The basis is part of the byte line rather than a third one, because a reader
/// who takes only the number takes the qualifier with it, and a reader piping to
/// `tail -1` still gets a labelled figure.
fn report(totals: &Totals, units: Units) -> [String; 2] {
    [
        format!("{SIZE_REPORT_LABEL_OBJECTS} {}", count(totals.count)),
        format!(
            "{SIZE_REPORT_LABEL_BYTES} ({}): {} ({} {SIZE_REPORT_EXACT_UNIT})",
            totals.sizes.label(),
            bytes(totals.bytes, units),
            totals.bytes
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Cli;
    use crate::commands::listing::tests_support::ctx;
    use crate::exit::ExitCode;
    use clap::Parser;
    use serde_json::json;

    #[test]
    fn the_command_parses_with_and_without_a_path() {
        assert!(Cli::try_parse_from(["dctl", "size"]).is_ok());
        let cli = Cli::try_parse_from(["dctl", "size", "vault:photos"]).unwrap();
        assert_eq!(cli.command.name(), "size");
    }

    /// Totals on the stored basis, which is what a plain remote produces.
    fn totals(count: u64, bytes: u64) -> Totals {
        Totals {
            count,
            bytes,
            sizes: Sizes::Stored,
        }
    }

    #[test]
    fn the_report_carries_the_rounded_and_the_exact_figure() {
        let report = report(&totals(1_234, 1_546_188_226), Units::Binary);
        assert_eq!(report[0], "Total objects: 1,234");
        assert_eq!(
            report[1],
            "Total size (stored): 1.44 GiB (1546188226 bytes)"
        );
    }

    #[test]
    fn a_sealed_total_says_it_is_plaintext() {
        // The whole point of the label: this figure is smaller than what the
        // provider is holding, and a user reconciling it against an invoice has
        // to be able to see that from the line itself.
        let report = report(
            &Totals {
                count: 5,
                bytes: 14_352,
                sizes: Sizes::Plaintext,
            },
            Units::Binary,
        );
        assert_eq!(report[1], "Total size (plaintext): 14.0 KiB (14352 bytes)");
    }

    #[test]
    fn the_two_bases_are_distinguishable_at_a_glance() {
        // Same numbers, different meaning. If these rendered identically the
        // label would be worse than useless: it would look like a disclosure.
        let stored = report(&totals(1, 1024), Units::Binary);
        let sealed = report(
            &Totals {
                count: 1,
                bytes: 1024,
                sizes: Sizes::Plaintext,
            },
            Units::Binary,
        );
        assert_ne!(stored[1], sealed[1]);
        // And the figure itself is untouched by the labelling.
        assert!(stored[1].contains("(1024 bytes)"));
        assert!(sealed[1].contains("(1024 bytes)"));
    }

    #[test]
    fn the_exact_figure_is_never_rounded_or_separated() {
        // It is there to be pasted into arithmetic, so no thousands separators
        // and no unit ladder.
        let report = report(&totals(0, 1_000_000), Units::Decimal);
        assert!(report[1].contains("(1000000 bytes)"), "{}", report[1]);
    }

    #[test]
    fn the_unit_convention_reaches_the_rounded_figure() {
        let totals = totals(1, 1_000_000_000_000);
        assert!(report(&totals, Units::Binary)[1].contains("931.3 GiB"));
        assert!(report(&totals, Units::Decimal)[1].contains("1.00 TB"));
    }

    #[test]
    fn an_empty_vault_reports_zeroes_rather_than_nothing() {
        // "Zero objects" is an answer; silence is not.
        let report = report(&totals(0, 0), Units::Binary);
        assert_eq!(report[0], "Total objects: 0");
        assert!(report[1].starts_with("Total size (stored): 0 B"));
    }

    #[test]
    fn the_json_shape_is_exact_and_stable() {
        let value = serde_json::to_value(totals(7, 1_546_188_226)).unwrap();
        assert_eq!(
            value,
            json!({ "count": 7, "bytes": 1_546_188_226u64, "sizes": "stored" })
        );
    }

    #[test]
    fn the_json_shape_names_the_basis_a_sealed_total_used() {
        // A capacity script must not have to infer this from the remote name.
        let value = serde_json::to_value(Totals {
            count: 7,
            bytes: 1_546_188_226,
            sizes: Sizes::Plaintext,
        })
        .unwrap();
        assert_eq!(value["sizes"], "plaintext");
        // rclone's two fields are untouched, so an existing consumer keeps
        // working and simply ignores the third.
        assert_eq!(value["count"], 7);
        assert_eq!(value["bytes"], 1_546_188_226u64);
    }

    #[tokio::test]
    async fn an_unreachable_index_is_an_error_not_a_zero() {
        // A reported zero would be indistinguishable from an empty vault, and
        // "the backup is empty" is a conclusion people act on.
        for flags in [vec![], vec!["--json"], vec!["--format", "json-lines"]] {
            let ctx = ctx(&flags);
            let error = run(
                &ctx,
                &SizeArgs {
                    path: Some("vault:".into()),
                },
            )
            .await
            .unwrap_err();
            assert_eq!(error.code(), ExitCode::FatalError, "{flags:?}");
        }
    }

    #[tokio::test]
    async fn filters_are_validated_before_the_engine_is_reached() {
        let ctx = ctx(&["--min-size", "not-a-size"]);
        let error = run(
            &ctx,
            &SizeArgs {
                path: Some("vault:".into()),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[tokio::test]
    async fn a_missing_target_is_a_usage_error() {
        let error = run(&ctx(&[]), &SizeArgs { path: None }).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[tokio::test]
    async fn a_vault_totals_plaintext_and_its_store_totals_more_than_that() {
        // The reason the basis is printed at all, demonstrated against a real
        // sealed vault rather than asserted: the same five files measured
        // through the two views give two different totals, the sealed one is
        // larger by the encryption overhead, and only the label says which
        // number a reader is holding.
        use std::sync::Arc;

        use crate::commands::listing::{self, Filter, Target};
        use dctl_core::Vault;
        use dctl_store::{Backend, LocalFs};

        let dir = tempfile::TempDir::new().expect("a temporary directory");
        let store = dir.path().join("store");
        std::fs::create_dir_all(&store).expect("the store directory");
        let index = dir.path().join("index.redb");

        let plaintext_bytes: u64 = {
            let backend: Arc<dyn Backend> = Arc::new(LocalFs::new(&store));
            let vault = Vault::init(backend, &index, "correct horse battery")
                .await
                .expect("a fresh vault initialises");
            let mut written = 0u64;
            for (path, bytes) in [
                ("photos/2024/a.jpg", vec![7u8; 4096]),
                ("photos/2024/b.jpg", vec![9u8; 2048]),
                ("docs/notes.txt", b"notes\n".to_vec()),
            ] {
                written += bytes.len() as u64;
                vault
                    .put_file(path, &bytes)
                    .await
                    .expect("a verified write");
            }
            written
        };

        let config = dir.path().join("config.toml");
        std::fs::write(
            &config,
            format!(
                "[remotes.archive-store]\ntype = \"local\"\npath = {:?}\nrequire_vault = true\n\n\
                 [remotes.archive]\ntype = \"vault\"\nbase = \"archive-store\"\n",
                store.to_string_lossy()
            ),
        )
        .expect("the configuration writes");

        let context = ctx(&[
            "--config",
            &config.to_string_lossy(),
            "--index",
            &index.to_string_lossy(),
            "--password",
            "correct horse battery",
        ]);

        /// Total one remote the way `run` does, without a terminal to write to.
        async fn measure(context: &Ctx, spec: &str) -> Totals {
            let target = Target::parse(Some(spec), None).expect("a valid spec");
            let filter = Filter::from_globals(&context.globals).expect("no filters");
            let mut stream = listing::open(context, &target, filter)
                .await
                .expect("the remote lists");
            let mut totals = Totals {
                count: 0,
                bytes: 0,
                sizes: stream.sizes(),
            };
            stream
                .try_for_each(|entry| {
                    totals.count += 1;
                    totals.bytes += entry.size();
                    Ok(())
                })
                .await
                .expect("the listing completes");
            totals
        }

        let sealed = measure(&context, "archive:").await;
        assert_eq!(sealed.sizes, Sizes::Plaintext);
        assert_eq!(sealed.count, 3);
        assert_eq!(
            sealed.bytes, plaintext_bytes,
            "a vault totals the bytes that were written"
        );

        let stored = measure(&context, "archive-store:").await;
        assert_eq!(stored.sizes, Sizes::Stored);
        assert!(
            stored.bytes > sealed.bytes,
            "the sealed objects must cost more than their plaintext: \
             {} stored vs {} plaintext",
            stored.bytes,
            sealed.bytes
        );

        // And the difference is visible in the output, not just in the struct.
        assert!(report(&sealed, Units::Binary)[1].contains("(plaintext)"));
        assert!(report(&stored, Units::Binary)[1].contains("(stored)"));
    }
}
