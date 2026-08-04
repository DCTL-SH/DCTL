//! `dctl verify REMOTE:PATH` — prove that stored objects still decrypt and
//! still match the hashes recorded when they were written.
//!
//! This is the read-side half of the verified-write contract (`PLAN.md` §6). A
//! write refuses to commit unless the destination's checksum matches ours; a
//! `verify` asks the same question again later, on demand.
//!
//! **Failure is loud.** An object whose bytes fail authentication ends the
//! process with [`ExitCode::IntegrityFailure`](crate::exit::ExitCode::IntegrityFailure)
//! (21) and a message saying, in words, that the data was **not** returned. It
//! is never rolled up into a generic error, and a run that found damage never
//! exits zero.
//!
//! ## What the default tells you, and what `--fail-fast` gives up
//!
//! By default every selected object is examined and the report says *how much*
//! is damaged. That number is the whole point: one corrupt object out of 40,000
//! is a restore of one file, and 12,000 is a lost dataset. `--fail-fast` stops
//! at the first failure for the runs where the only question is yes-or-no, and
//! the report then carries `stopped_early` so nobody reads the count as the full
//! extent of the damage.
//!
//! ## The `--verify` dial, and why this build cannot honour a cheaper one
//!
//! `--verify` is documented as a cost/assurance dial:
//!
//! * `checksum` — compare the provider's stored checksum with ours. No egress.
//! * `sample` — additionally range-read and decrypt `--verify-samples` chunks.
//! * `strict` — read every object back in full and confirm its whole-file
//!   BLAKE3.
//!
//! **Every selected object is read back in full here, whatever `--verify`
//! says**, and the run warns when a cheaper strength was asked for. One of the
//! cheaper two cannot be performed at all with the primitives that exist; the
//! other has not been designed. Performing something else while reporting the
//! requested name would be the misreport `PLAN.md` §6 forbids:
//!
//! * `checksum` would need the provider's own checksum of the *stored object*
//!   compared against one DCTL holds. `dctl_core::Vault` exposes no such value —
//!   the index records a hash of the **plaintext**, and the object key the
//!   ciphertext lives under is deliberately not reachable from a
//!   [`Source`](crate::source::Source) — so there is nothing to compare and a
//!   `checksum` run would read nothing and then print a wall of `ok`. Since
//!   `checksum` is the *default*, that would make the bare `dctl verify
//!   archive:` a command that proves nothing while looking like it proved
//!   everything. It is the single worst outcome available here.
//! * `sample` now *could* be built — [`Source::read_range`](crate::source::Source::read_range)
//!   on a vault is a genuine ranged authenticated read, so spot-checking a few
//!   windows of a huge object costs O(window) rather than O(object). It is still
//!   not built, and the difference between "impossible" and "not yet written" is
//!   exactly the sort of thing this project may not blur: what a `sample` would
//!   have to decide — which windows, how many, and what a pass over 1% of a file
//!   licenses anybody to say — is a design question, not a plumbing one, and
//!   answering it badly produces a check that reads cheap and proves nothing.
//!
//! So the report records the strength that actually *ran* rather than the one
//! that was requested, exactly as [`super::scrub`] does and for the same reason.
//! The day `dctl-core` exposes a stored-object checksum, and `sample` is
//! designed rather than merely enabled, this becomes a real dial and the warning
//! disappears.
//!
//! ## What a pass proves depends on the remote
//!
//! A sealed vault authenticates every chunk against a key and compares the
//! object's own recorded content hash, so `ok` means *these are the bytes that
//! were written*. A plain remote — including the object store a vault's
//! ciphertext lives in — records no hash of its own, so the strongest honest
//! claim about an object it served is *it was still there and every byte came
//! back*. See [`Assurance`](crate::source::Assurance).
//!
//! **And there is a second axis, which is about the objects the run never had a
//! name for.** A vault is verified by walking its index — a row per object, kept
//! outside the remote — so an object the backend no longer has is reported
//! missing and the run exits 4. A plain remote is verified by walking the
//! remote's own listing and then re-reading the keys it just reported, so both
//! sides of that comparison are one source: a deleted object is not missing
//! there, it is simply not enumerated, and `OK  2 objects examined` over a store
//! that used to hold three is exit 0. Measured, on the shipped binary, under the
//! flag whose `--help` said this was exactly what it caught
//! (`HANDOVER.md` §36). Both axes are refused by default now and both are
//! published in the report. See [`Inventory`](crate::source::Inventory).
//!
//! **The report says which one it is**, and that is newer than it looks. The
//! value was computed here and spent on a single stderr warning — one that fires
//! only when the remote *cannot* detect corruption, so a vault's run never
//! stated its assurance at all, and no run stated it anywhere a machine could
//! read. Measured: an 8 MiB object on a plain `local:` remote, truncated to zero
//! bytes on disk, produced `ok` in the table, exit 0, and a JSON document
//! carrying `"status": "ok"`, `"verified": 1`, `"failed": 0` and `"verify_mode":
//! "strict"` with no field to say the pass could not have noticed.
//!
//! Two things follow from that, and both are now here rather than in a warning:
//! `assurance` is a field of the report in every format, and a text-mode run
//! ends with one line naming what it covered and what covering it proved. Both
//! are what [`super::scrub`] has done since it was written — the two commands
//! share `Verdict`, share their failure wording and share their exit codes, and
//! a claim only one of them published was a claim nobody could rely on.

pub mod engine;
pub mod report;

use clap::Args;

use crate::cli::VerifyMode;
use crate::commands::integrity::assurance::{self, AssuranceArgs};
use crate::commands::integrity::{Target, command_name, mode};
use crate::commands::listing::Filter;
use crate::ctx::Ctx;
use crate::error::Result;
use crate::source::Claims;

use report::Report;

/// The verb this module implements, used in messages that name the command.
const VERB: &str = "verify";

/// Arguments to `dctl verify`.
///
/// Deliberately small: strength, sampling depth and path filtering are all
/// global flags already, and duplicating them here would create two spellings of
/// one setting.
#[derive(Args, Debug)]
pub struct VerifyArgs {
    /// Object or prefix to verify.
    #[arg(value_name = "REMOTE:PATH")]
    pub target: String,

    /// Stop at the first object that fails instead of checking the rest.
    ///
    /// Off by default: the most useful thing a verify run can tell you is *how
    /// much* is damaged, and stopping at the first bad object hides that.
    #[arg(long)]
    pub fail_fast: bool,

    /// What this run will accept as proof. See
    /// [`assurance`](crate::commands::integrity::assurance).
    #[command(flatten)]
    pub assurance: AssuranceArgs,
}

/// Verify stored objects against their recorded hashes.
///
/// # Errors
/// [`CliError::usage`](crate::error::CliError::usage) for a malformed or local
/// target or an unusable filter; whatever opening the remote reported; and the
/// integrity family's classified failure when objects do not verify —
/// [`ExitCode::IntegrityFailure`](crate::exit::ExitCode::IntegrityFailure) for
/// objects that did not authenticate, and the availability codes for objects
/// that were missing or unreachable.
pub async fn run(ctx: &Ctx, args: &VerifyArgs) -> Result<()> {
    let command = command_name(VERB);
    let target = Target::parse(&args.target)?;
    // Verification compares stored bytes against the hash the vault recorded for
    // them. A local path has no such record, so there is nothing to compare and
    // saying so now beats reporting "0 objects verified" after doing nothing.
    target.require_remote(&command)?;

    // Compiled before the remote opens, so a malformed `--include` fails before
    // a password is asked for.
    let filter = Filter::from_globals(&ctx.globals)?;
    let opened = crate::source::open(ctx, &target.spec()).await?;
    let claims = Claims::of(opened.source());

    // Every object is read back in full, so the strength that ran is `strict`
    // whatever was asked for. Reporting the requested one instead would name a
    // check that did not happen — see the module documentation.
    let performed = VerifyMode::Strict;
    ctx.out.info(format!(
        "{command}: {target} at --verify={} — {}",
        mode::slug(performed),
        mode::describe(performed)
    ));

    // The target's own policy, not the flag alone. See
    // `crate::remote::resolve::verify_policy`.
    let requested = ctx.verify_mode_for(&target.spec())?;
    if !mode::proves_whole_plaintext(requested) {
        ctx.out.warn(format!(
            "--verify={} asks for a cheaper check than `{command}` can perform in this \
             build: dctl-core exposes no stored-object checksum, and no sampling \
             strategy is defined, so every selected object is read back in full",
            mode::slug(requested)
        ));
    }
    // Before anything is read, so a remote that cannot be certified costs
    // nothing to find out about rather than an hour of egress and a caveat. This
    // was a `warn` and the run went on to print `ok` for every object and exit
    // 0 — over a store holding a flipped byte and a truncated object.
    assurance::require(&command, &target.to_string(), claims, &args.assurance)?;
    if !claims.assurance.detects_corruption() {
        // Reached only when the operator asked for this with `--allow-read-back`.
        ctx.out.warn(format!(
            "'{target}' records no hash of its own — {}",
            claims.assurance.describe()
        ));
    }
    if !claims.inventory.detects_loss() {
        // Reached only when the operator asked for this with
        // `--allow-listing-as-inventory`. Said out loud beside the other one,
        // because the count this run is about to print is a count of what the
        // remote still admits to holding and will be read as a count of the
        // dataset.
        ctx.out.warn(format!(
            "'{target}' keeps no record of what it should hold — {}",
            claims.inventory.describe()
        ));
    }
    if mode::reads_object_bytes(performed) && target.is_tree() {
        // The one surprise worth a warning: verifying a whole vault downloads
        // the whole vault, and the bill arrives later than the run. Conditioned
        // on the strength that actually ran rather than stated flatly, so that
        // the day a genuinely cheaper mode exists this line stops appearing for
        // runs that do not cost anything.
        ctx.out.warn(format!(
            "verifying the tree '{target}' reads every object it contains"
        ));
    }
    if args.fail_fast {
        ctx.out.warn(
            "--fail-fast stops at the first failure, so the report will not say how \
             widespread any damage is",
        );
    }

    // `verify` mutates nothing, so --dry-run has nothing to suppress. It must
    // still not be treated as permission to claim the work was done, which is
    // why there is no dry-run branch here at all: the command simply runs.
    let mut report = Report::new(target.to_string(), mode::slug(performed), claims);
    report.filters_restricted(filter.is_restricting());
    // A non-tree target names one object, and an empty walk under that exact
    // name proves it absent — which must exit as a missing object, not as an
    // empty run. See `Report::outcome`.
    report.named_object(!target.is_tree());
    engine::verify(ctx, &opened, &filter, args.fail_fast, &mut report).await?;

    report.emit(&ctx.out)?;
    // Text mode only, exactly as `scrub` does it: the JSON document already
    // carries `assurance` and the whole `summary` object, and a second, prose
    // rendering of the same numbers would be one more thing that can disagree
    // with the data. In text mode there is no such document and the coverage
    // would otherwise be invisible, which was half the defect.
    if !ctx.out.is_json() {
        report.announce(&ctx.out);
    }
    report.outcome().map_or(Ok(()), Err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Cli, Command};
    use crate::exit::ExitCode;
    use clap::Parser;

    /// Parse a full command line and hand back the context plus the arguments.
    fn parse(args: &[&str]) -> (Ctx, VerifyArgs) {
        let cli = Cli::try_parse_from(std::iter::once("dctl").chain(args.iter().copied()))
            .expect("arguments should parse");
        let Command::Verify(verify) = cli.command else {
            panic!("expected the verify subcommand");
        };
        (Ctx::new(cli.globals), verify)
    }

    /// A configured plain remote over a temporary directory, plus the `--config`
    /// argument that points DCTL at the file naming it.
    fn plain_remote(files: &[(&str, &[u8])]) -> (tempfile::TempDir, String) {
        let dir = tempfile::TempDir::new().expect("a temporary directory");
        let root = dir.path().join("root");
        std::fs::create_dir_all(&root).expect("the root exists even when empty");
        for (relative, bytes) in files {
            let path = root.join(relative);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("the parent directory is created");
            }
            std::fs::write(&path, bytes).expect("the fixture file is written");
        }

        let config = dir.path().join("config.toml");
        std::fs::write(
            &config,
            format!(
                "[remotes.store]\ntype = \"local\"\npath = {:?}\n",
                root.to_string_lossy()
            ),
        )
        .expect("the configuration is written");
        let path = config.to_string_lossy().into_owned();
        (dir, path)
    }

    #[tokio::test]
    async fn a_target_is_required() {
        assert!(Cli::try_parse_from(["dctl", "verify"]).is_err());
    }

    #[tokio::test]
    async fn the_target_and_fail_fast_flag_parse() {
        let (_, args) = parse(&["verify", "vault:photos"]);
        assert_eq!(args.target, "vault:photos");
        assert!(!args.fail_fast);

        let (_, args) = parse(&["verify", "vault:photos", "--fail-fast"]);
        assert!(args.fail_fast);
    }

    #[tokio::test]
    async fn the_global_verify_mode_is_reachable_without_a_local_flag() {
        // Strength is a global dial; a per-command copy would be a second
        // spelling of one setting. Asked about the target, because the remote
        // states a policy the flag overrides.
        let (ctx, _) = parse(&["verify", "vault:x", "--verify", "strict"]);
        let spec = crate::remote::RemoteSpec::parse("vault:x").expect("a well-formed spec");
        assert_eq!(
            ctx.verify_mode_for(&spec).expect("the mode resolves"),
            crate::cli::VerifyMode::Strict
        );
    }

    #[tokio::test]
    async fn a_local_target_is_a_usage_error() {
        let (ctx, args) = parse(&["verify", "./photos"]);
        let error = run(&ctx, &args).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.message().contains(VERB));
    }

    #[tokio::test]
    async fn an_escaping_path_is_rejected_before_any_work() {
        let (ctx, args) = parse(&["verify", "vault:../../etc"]);
        let error = run(&ctx, &args).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[tokio::test]
    async fn an_unresolvable_remote_is_an_error_rather_than_a_clean_bill_of_health() {
        // Printing "0 failed" for a target nothing read would be the exact lie
        // this command exists to prevent.
        let (ctx, args) = parse(&["verify", "nosuchremote:", "--no-ask-password"]);
        let error = run(&ctx, &args).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.message().contains("nosuchremote"));
    }

    #[tokio::test]
    async fn a_malformed_pattern_fails_before_the_remote_is_opened() {
        let (ctx, args) = parse(&["verify", "nosuchremote:", "--include", "[abc"]);
        assert_eq!(run(&ctx, &args).await.unwrap_err().code(), ExitCode::Usage);
    }

    #[tokio::test]
    async fn an_intact_remote_verifies_and_exits_zero() {
        // `local:` records no digest, so the run has to say which check it is
        // asking for. With that said, an intact store passes it.
        let (_dir, config) = plain_remote(&[("a.txt", b"1"), ("sub/b.txt", b"22")]);
        let (ctx, args) = parse(&[
            "verify",
            "store:",
            "--config",
            &config,
            "--allow-read-back",
            "--allow-listing-as-inventory",
        ]);
        run(&ctx, &args)
            .await
            .expect("an intact remote must not fail the run");
    }

    #[tokio::test]
    async fn a_plain_remote_is_refused_rather_than_reported_ok() {
        // The defect, at the level an operator meets it. A nightly
        // `dctl verify store:` over a plain `local:` remote read every byte,
        // printed `ok` for every object and exited **0** — over a store that
        // could be holding a flipped byte and a truncated object, because a
        // filesystem records no digest a re-read could disagree with.
        //
        // Exit 27 and not 0, and not 21: nothing here has been shown to be
        // damaged. What is being reported is that the question was not answered.
        let (_dir, config) = plain_remote(&[("a.txt", b"1"), ("sub/b.txt", b"22")]);
        let (ctx, args) = parse(&["verify", "store:", "--config", &config]);

        let error = run(&ctx, &args)
            .await
            .expect_err("a remote that cannot detect rot must not report a clean bill of health");
        assert_eq!(error.code(), ExitCode::VerificationNotPossible);
        assert_eq!(error.code().as_i32(), 27);
        assert_ne!(error.code(), ExitCode::IntegrityFailure);
        assert!(
            error.hint().is_some(),
            "an operator refused a check needs the next action: {}",
            error.message()
        );
    }

    #[tokio::test]
    async fn a_deleted_object_is_not_reported_ok_on_a_plain_remote() {
        // The measured defect, at the level an operator meets it, and with the
        // flag whose `--help` said this was the damage it caught. Three objects
        // are stored, one is deleted outright from the store, and the run
        // reported `OK  2 objects examined` and exit **0** — because the only
        // list of what should be there is the listing that no longer mentions
        // it, so both sides of the comparison agreed.
        //
        // Not 0, and not 4: nothing here has been shown to be missing, because
        // nothing here knows what to look for. What is reported is that the
        // question cannot be answered — which is why the same deletion inside a
        // vault *is* exit 4 and this is exit 27.
        let (dir, config) =
            plain_remote(&[("a.bin", b"111"), ("b.bin", b"222"), ("c.bin", b"333")]);
        let gone = dir.path().join("root").join("b.bin");
        std::fs::remove_file(&gone).expect("the object is deleted from the store");
        assert!(!gone.exists(), "the damage must have landed");

        let (ctx, args) = parse(&["verify", "store:", "--config", &config, "--allow-read-back"]);
        let error = run(&ctx, &args)
            .await
            .expect_err("a store that has lost an object must not report a clean bill of health");
        assert_eq!(error.code(), ExitCode::VerificationNotPossible);
        assert_eq!(error.code().as_i32(), 27);
        assert!(
            error.message().contains("--allow-listing-as-inventory"),
            "the refusal must name the limit and the flag that accepts it: {}",
            error.message()
        );
    }

    #[tokio::test]
    async fn a_truncated_object_is_not_reported_ok_on_a_plain_remote() {
        // The second measured damage. Truncation is invisible to a read-back by
        // construction — shortening a file moves its length too, so `head` and
        // the bytes agree and every byte the object claims does come back — and
        // the run reported `ok  244.1 KiB  mid.bin` at exit 0 over an object
        // that had been 488.3 KiB.
        let (dir, config) = plain_remote(&[("a.bin", &[7u8; 4096]), ("b.bin", b"22")]);
        let target = dir.path().join("root").join("a.bin");
        let before = std::fs::metadata(&target).expect("the object exists").len();
        std::fs::File::options()
            .write(true)
            .open(&target)
            .expect("the object is writable")
            .set_len(before / 2)
            .expect("the object is truncated");
        let after = std::fs::metadata(&target).expect("the object exists").len();
        assert!(
            after < before,
            "the damage must have landed: {before} -> {after}"
        );

        let (ctx, args) = parse(&["verify", "store:", "--config", &config, "--allow-read-back"]);
        assert_eq!(
            run(&ctx, &args)
                .await
                .expect_err("a truncated object must not be reported ok")
                .code(),
            ExitCode::VerificationNotPossible,
        );
    }

    #[tokio::test]
    async fn an_undamaged_plain_remote_still_passes_once_both_limits_are_accepted() {
        // The self-test without which the two above prove nothing: the same
        // command over an *undamaged* store, with both limits accepted by name,
        // has to succeed. A gate that refused everything would pass both tests
        // above and would have made the command useless.
        let (_dir, config) = plain_remote(&[("a.bin", b"111"), ("b.bin", b"222")]);
        let (ctx, args) = parse(&[
            "verify",
            "store:",
            "--config",
            &config,
            "--allow-read-back",
            "--allow-listing-as-inventory",
        ]);
        run(&ctx, &args)
            .await
            .expect("an undamaged remote must pass once the operator has accepted the limits");
    }

    #[tokio::test]
    async fn the_refusal_lands_before_the_walk_rather_than_after_it() {
        // A refusal that arrived after an hour of egress would be a caveat
        // rather than a gate, and the difference is observable without timing
        // anything: this target selects **no objects**, which is its own error
        // (exit 9, and the assertion of
        // `a_target_holding_nothing_does_not_report_a_clean_bill_of_health`).
        //
        // Exit 9 can only be reached by walking the remote and finding nothing.
        // So 27 here proves the gate closed first, and 9 would prove it did not
        // — with no permission bits, which is worth stating because these tests
        // run as root, where mode 000 stops nothing.
        let (_dir, config) = plain_remote(&[("kept.txt", b"payload")]);
        let (ctx, args) = parse(&["verify", "store:nowhere", "--config", &config]);

        let error = run(&ctx, &args).await.expect_err("refused");
        assert_eq!(
            error.code(),
            ExitCode::VerificationNotPossible,
            "the gate must close before the walk starts, not after it: {}",
            error.message()
        );

        // The control, and the reason the assertion above means anything: with
        // the weaker check asked for, the same target reaches the walk and
        // reports what the walk found. Tree spelling, so the empty walk stays
        // "nothing verified" rather than "named object missing".
        let (ctx, args) = parse(&[
            "verify",
            "store:nowhere/",
            "--config",
            &config,
            "--allow-read-back",
            "--allow-listing-as-inventory",
        ]);
        assert_eq!(
            run(&ctx, &args)
                .await
                .expect_err("nothing verified is still not a pass")
                .code(),
            ExitCode::NoFilesTransferred,
        );
    }

    #[tokio::test]
    async fn every_verify_mode_is_accepted_and_none_of_them_weakens_the_run() {
        // The cheaper strengths are warned about, not refused: refusing would
        // break every script that sets `--verify` globally, and honouring them
        // literally would prove less than the report claims.
        let (_dir, config) = plain_remote(&[("a.txt", b"1")]);
        for strength in ["checksum", "sample", "strict"] {
            let (ctx, args) = parse(&[
                "verify",
                "store:",
                "--config",
                &config,
                "--verify",
                strength,
                "--allow-read-back",
                "--allow-listing-as-inventory",
            ]);
            run(&ctx, &args)
                .await
                .unwrap_or_else(|error| panic!("--verify={strength} failed: {error}"));
        }
    }

    #[tokio::test]
    async fn dry_run_does_not_turn_the_check_into_a_no_op() {
        // --dry-run suppresses mutations; verify has none, and it must never be
        // read as permission to skip the work and report success.
        let (_dir, config) = plain_remote(&[("a.txt", b"1")]);
        let (ctx, args) = parse(&[
            "verify",
            "store:",
            "--config",
            &config,
            "--dry-run",
            "--allow-read-back",
            "--allow-listing-as-inventory",
        ]);
        assert!(ctx.is_dry_run());
        run(&ctx, &args).await.expect("a dry run still verifies");
    }

    #[tokio::test]
    async fn every_output_format_is_accepted() {
        let (_dir, config) = plain_remote(&[("a.txt", b"1")]);
        for format in [&["--json"][..], &["--format", "json-lines"][..], &[][..]] {
            let mut argv = vec![
                "verify",
                "store:",
                "--config",
                config.as_str(),
                "--allow-read-back",
                "--allow-listing-as-inventory",
            ];
            argv.extend_from_slice(format);
            let (ctx, args) = parse(&argv);
            run(&ctx, &args)
                .await
                .expect("the format must not change the outcome");
        }
    }

    #[tokio::test]
    async fn a_target_holding_nothing_does_not_report_a_clean_bill_of_health() {
        // `dctl verify archive:` over a real dataset and `dctl verify
        // archive:typo` over nothing were the same silent exit zero — and at the
        // default verbosity the second printed *nothing at all* on either stream,
        // because the notice explaining it was an `info`. A cron entry could
        // verify nothing every night and stay green for years. `dctl scrub`
        // already exits 9 for exactly this; the two integrity verbs must not
        // disagree about what "nothing was read" means.
        let (_dir, config) = plain_remote(&[("kept.txt", b"payload")]);
        let (ctx, args) = parse(&[
            "verify",
            "store:nowhere/",
            "--config",
            &config,
            "--allow-read-back",
            "--allow-listing-as-inventory",
        ]);

        let error = run(&ctx, &args)
            .await
            .expect_err("verifying nothing is not a pass");
        assert_eq!(error.code(), ExitCode::NoFilesTransferred);
        assert_eq!(error.code().as_i32(), 9);
        assert!(
            error.message().contains("nothing was verified"),
            "the message must say no verification happened: {}",
            error.message()
        );
    }

    #[tokio::test]
    async fn a_named_object_that_is_absent_is_missing_rather_than_nothing_verified() {
        // `verify store:gone.bin` names ONE object, and an empty walk under
        // that exact name proves it absent. Exit 9's "the run did no work"
        // told a cron job nothing about a run that discovered a loss; the
        // published missing-object code is 4, and this is a missing object.
        let (_dir, config) = plain_remote(&[("kept.txt", b"payload")]);
        let (ctx, args) = parse(&[
            "verify",
            "store:gone.bin",
            "--config",
            &config,
            "--allow-read-back",
            "--allow-listing-as-inventory",
        ]);

        let error = run(&ctx, &args)
            .await
            .expect_err("a named absence is not a pass");
        assert_eq!(error.code(), ExitCode::FileNotFound);
        assert_eq!(error.code().as_i32(), 4);
        assert!(
            error.message().contains("gone.bin"),
            "the missing object must be named: {}",
            error.message()
        );
        assert!(
            error.hint().is_some(),
            "the trailing-slash misreading deserves its hint"
        );
    }

    #[tokio::test]
    async fn filters_that_admit_nothing_are_named_rather_than_read_as_success() {
        // The same exit code, a different next action: the prefix is fine and the
        // operator's own `--include` is what emptied the run. Reporting one cause
        // for both would send somebody hunting a missing dataset that is there.
        let (_dir, config) = plain_remote(&[("kept.txt", b"payload")]);
        let (ctx, args) = parse(&[
            "verify",
            "store:",
            "--config",
            &config,
            "--include",
            "*.nothing",
            "--allow-read-back",
            "--allow-listing-as-inventory",
        ]);

        let error = run(&ctx, &args)
            .await
            .expect_err("filters that admit nothing verify nothing");
        assert_eq!(error.code(), ExitCode::NoFilesTransferred);
        assert!(
            error.message().contains("filter"),
            "the cause must name the filters: {}",
            error.message()
        );
    }

    #[tokio::test]
    async fn a_sealed_vault_verifies_end_to_end_and_a_flipped_byte_exits_twenty_one() {
        // The whole command, wired: configuration, vault chain, unlock, index
        // walk, authenticated read-back, exit code.
        use std::sync::Arc;

        use dctl_core::Vault;
        use dctl_store::{Backend, LocalFs};

        let dir = tempfile::TempDir::new().unwrap();
        let store = dir.path().join("store");
        std::fs::create_dir_all(&store).unwrap();
        let index = dir.path().join("index.redb");

        {
            let backend: Arc<dyn Backend> = Arc::new(LocalFs::new(&store));
            let vault = Vault::init(backend, &index, "pw").await.unwrap().vault;
            vault
                .put_file("photos/a.jpg", b"aaa", dctl_core::Modified::Now)
                .await
                .unwrap();
            vault
                .put_file("notes.txt", b"n", dctl_core::Modified::Now)
                .await
                .unwrap();
        }

        let config = dir.path().join("config.toml");
        std::fs::write(
            &config,
            format!(
                "[remotes.store]\ntype = \"local\"\npath = {:?}\nrequire_vault = true\n\n\
                 [remotes.archive]\ntype = \"vault\"\nbase = \"store\"\n",
                store.to_string_lossy()
            ),
        )
        .unwrap();

        let config = config.to_string_lossy().into_owned();
        let index_arg = index.to_string_lossy().into_owned();
        let argv = [
            "verify",
            "archive:",
            "--config",
            &config,
            "--index",
            &index_arg,
            "--password",
            "pw",
        ];

        let (ctx, args) = parse(&argv);
        run(&ctx, &args).await.expect("an intact vault verifies");

        // Flip exactly one byte in one stored object, reaching past DCTL
        // entirely, and confirm the same command notices.
        let object = std::fs::read_dir(store.join("o"))
            .unwrap()
            .filter_map(std::result::Result::ok)
            .map(|entry| entry.path())
            .find(|path| path.is_file())
            .expect("the vault stored at least one object");
        let mut bytes = std::fs::read(&object).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        std::fs::write(&object, &bytes).unwrap();

        let (ctx, args) = parse(&argv);
        let error = run(&ctx, &args)
            .await
            .expect_err("a flipped byte must fail the run");
        assert_eq!(error.code(), ExitCode::IntegrityFailure);
        assert_eq!(error.code().as_i32(), 21);
        assert!(
            error.message().contains("NOT served"),
            "the message must say the data was not returned: {}",
            error.message()
        );
    }
}
