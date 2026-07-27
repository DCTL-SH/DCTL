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
//! claim is *the object was still there and every byte came back*. The run says
//! which one it is on stderr before it starts; see
//! [`Assurance`](crate::source::Assurance).

pub mod engine;
pub mod report;

use clap::Args;

use crate::cli::VerifyMode;
use crate::commands::integrity::{Target, command_name, mode};
use crate::commands::listing::Filter;
use crate::ctx::Ctx;
use crate::error::Result;

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
    let source = crate::source::open(ctx, &target.spec()).await?;
    let assurance = source.assurance();

    // Every object is read back in full, so the strength that ran is `strict`
    // whatever was asked for. Reporting the requested one instead would name a
    // check that did not happen — see the module documentation.
    let performed = VerifyMode::Strict;
    ctx.out.info(format!(
        "{command}: {target} at --verify={} — {}",
        mode::slug(performed),
        mode::describe(performed)
    ));

    let requested = ctx.verify_mode();
    if !mode::proves_whole_plaintext(requested) {
        ctx.out.warn(format!(
            "--verify={} asks for a cheaper check than `{command}` can perform in this \
             build: dctl-core exposes no stored-object checksum, and no sampling \
             strategy is defined, so every selected object is read back in full",
            mode::slug(requested)
        ));
    }
    if !assurance.detects_corruption() {
        // Otherwise "verified" would be read as a statement about the bytes, and
        // this remote cannot make one.
        ctx.out.warn(format!(
            "'{target}' records no hash of its own — {}",
            assurance.describe()
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
    let mut report = Report::new(target.to_string(), mode::slug(performed));
    engine::verify(
        ctx,
        source.as_ref(),
        target.prefix(),
        &filter,
        args.fail_fast,
        &mut report,
    )
    .await?;

    if report.summary.examined == 0 {
        empty_notice(ctx, &target, &filter);
    }

    report.emit(&ctx.out)?;
    report.outcome().map_or(Ok(()), Err)
}

/// Say on stderr why nothing was examined.
///
/// "Nothing is there" and "nothing survived your filters" both produce a run
/// that verified zero objects and exited zero, and they call for completely
/// different actions — so a `verify` that could not tell them apart would be an
/// integrity command that reports a clean bill of health for a target it never
/// looked at.
fn empty_notice(ctx: &Ctx, target: &Target, filter: &Filter) {
    if filter.is_restricting() {
        ctx.out.info(format!(
            "no objects under '{target}' matched the active filters, so nothing was verified"
        ));
    } else {
        ctx.out
            .info(format!("no objects under '{target}' to verify"));
    }
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
        // spelling of one setting.
        let (ctx, _) = parse(&["verify", "vault:x", "--verify", "strict"]);
        assert_eq!(ctx.verify_mode(), crate::cli::VerifyMode::Strict);
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
        let (_dir, config) = plain_remote(&[("a.txt", b"1"), ("sub/b.txt", b"22")]);
        let (ctx, args) = parse(&["verify", "store:", "--config", &config]);
        run(&ctx, &args)
            .await
            .expect("an intact remote must not fail the run");
    }

    #[tokio::test]
    async fn every_verify_mode_is_accepted_and_none_of_them_weakens_the_run() {
        // The cheaper strengths are warned about, not refused: refusing would
        // break every script that sets `--verify` globally, and honouring them
        // literally would prove less than the report claims.
        let (_dir, config) = plain_remote(&[("a.txt", b"1")]);
        for strength in ["checksum", "sample", "strict"] {
            let (ctx, args) = parse(&[
                "verify", "store:", "--config", &config, "--verify", strength,
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
        let (ctx, args) = parse(&["verify", "store:", "--config", &config, "--dry-run"]);
        assert!(ctx.is_dry_run());
        run(&ctx, &args).await.expect("a dry run still verifies");
    }

    #[tokio::test]
    async fn every_output_format_is_accepted() {
        let (_dir, config) = plain_remote(&[("a.txt", b"1")]);
        for format in [&["--json"][..], &["--format", "json-lines"][..], &[][..]] {
            let mut argv = vec!["verify", "store:", "--config", config.as_str()];
            argv.extend_from_slice(format);
            let (ctx, args) = parse(&argv);
            run(&ctx, &args)
                .await
                .expect("the format must not change the outcome");
        }
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
