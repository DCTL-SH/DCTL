//! `dctl rcat` — read standard input and store it as one object.
//!
//! The mirror image of `cat`, and a pipeline citizen for the same reason:
//! **stdin is the payload**, so nothing on stdout may compete with it and every
//! report goes to stderr unless a machine format was asked for.
//!
//! Three properties define the command:
//!
//! * **The length is never required in advance.** `pg_dump | dctl rcat
//!   vault:db.sql` cannot say how large the dump will be, and buffering it to
//!   find out would hold an arbitrary amount of the user's data in memory. The
//!   pump in [`stream`] reads until EOF and counts as it goes.
//! * **It refuses before it reads.** A pipe cannot be rewound. If the
//!   destination cannot be written — because it names a remote the engine cannot
//!   yet reach, because `--immutable` forbids replacing what is there, or because
//!   the operator declined — the command fails *before* the first read, leaving
//!   the producer's output intact. Consuming a stream and then failing would
//!   destroy data that was never stored anywhere.
//! * **The commit is the last step.** For a local destination the bytes are
//!   staged, fsynced and renamed into place ([`local`]), so a reader sees the old
//!   object or the whole new one and never a truncated middle. That is
//!   `PLAN.md` §6's rule expressed on a filesystem.
//!
//! A terminal on stdin is a usage error rather than an invitation to type: the
//! command would otherwise sit there looking like a hang, which is the most
//! confusing way for a byte-stream tool to fail.
//!
//! **Engine reality.** A local destination is fully implemented. Storing into a
//! remote needs the verified-write engine to accept an upload of unknown length,
//! which `dctl-core` does not expose yet; that invocation is refused with a real
//! exit code — including under `--dry-run`, because rehearsing an operation this
//! build cannot perform would be a promise the tool cannot keep.

mod local;
mod stream;

use std::io::{self, IsTerminal};
use std::path::PathBuf;

use clap::Args;
use serde::Serialize;

use crate::commands::pipeline::{ObjectSpec, command_name};
use crate::constants::{
    RCAT_OUTCOME_DECLINED, RCAT_OUTCOME_PLANNED, RCAT_OUTCOME_STORED, RCAT_TERMINAL_STDIN_HINT,
    STREAM_WRITE_FEATURE, STREAM_WRITE_HINT,
};
use crate::ctx::Ctx;
use crate::error::{CliError, Result};
use crate::exit::ExitCode;
use crate::output::size;

/// Arguments to `dctl rcat`.
#[derive(Args, Debug)]
pub struct RcatArgs {
    /// Object to create from standard input.
    #[arg(value_name = "REMOTE:PATH")]
    pub dest: String,
}

/// Store everything on standard input as a single object.
pub async fn run(ctx: &Ctx, args: &RcatArgs) -> Result<()> {
    let spec = ObjectSpec::parse(&args.dest)?;

    match resolve(ctx, &spec, io::stdin().is_terminal())? {
        Action::Store(destination) => {
            let bytes = local::store(ctx, &destination, &mut io::stdin().lock())?;
            ctx.stats.file_done();
            report(ctx, &spec, RCAT_OUTCOME_STORED, Some(bytes))
        }
        Action::Plan => {
            ctx.dry_run_notice("store standard input as", spec.display());
            report(ctx, &spec, RCAT_OUTCOME_PLANNED, None)
        }
        Action::Decline => {
            ctx.out.warn(format!(
                "{spec}: not replaced — nothing was read from standard input"
            ));
            report(ctx, &spec, RCAT_OUTCOME_DECLINED, None)
        }
    }
}

/// What this invocation will do, decided before a single byte is read.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Action {
    /// Stream stdin into this local path.
    Store(PathBuf),
    /// Report what a real run would do, and read nothing (`--dry-run`).
    Plan,
    /// The operator refused the replacement; read nothing.
    Decline,
}

/// Decide the action, or fail with the reason nothing can happen.
///
/// `stdin_is_terminal` is a parameter rather than a probe so the decision table
/// is testable: under `cargo test` the harness inherits whatever stdin the
/// developer's shell had, and a rule this important must not be verified only on
/// machines where that happens to be a pipe.
///
/// The order of the checks is the order in which a user can act on them: what
/// they typed, then what they piped, then what this build can do, and only then
/// the state of the destination.
fn resolve(ctx: &Ctx, spec: &ObjectSpec, stdin_is_terminal: bool) -> Result<Action> {
    if spec.is_bare_remote() || spec.path().is_empty() {
        return Err(
            CliError::usage(format!("'{spec}' names no object to create"))
                .with_hint("Name the object, for example 'dctl rcat vault:backups/today.sql'."),
        );
    }

    if stdin_is_terminal {
        return Err(CliError::usage("nothing to read from standard input")
            .with_hint(RCAT_TERMINAL_STDIN_HINT));
    }

    // Before the dry-run branch on purpose. A dry run rehearses a real run, so
    // announcing "would store" for an operation this build cannot perform would
    // be a promise the tool cannot keep — the same reasoning `cat` applies to a
    // remote read.
    if !spec.is_local() {
        return Err(CliError::unimplemented(format!(
            "{STREAM_WRITE_FEATURE} ({})",
            command_name("rcat")
        ))
        .with_hint(STREAM_WRITE_HINT));
    }

    if ctx.is_dry_run() {
        return Ok(Action::Plan);
    }

    let destination = spec.local_path();

    // `rcat` reaches the filesystem by a completely different route from the
    // transfer family, so the addressing rule has to be asked here too. It was
    // not, and `echo secret | dctl rcat ./vault/z.txt` wrote plaintext straight
    // into a vault directory and exited 0 — the exact failure the transfer-side
    // guard exists to prevent, through the one door nobody had checked. Both
    // ask [`crate::addressing`], so neither can be fixed without the other.
    crate::addressing::refuse_plain_write_to_path(ctx, &destination)?;

    if destination.exists() {
        if ctx.globals.immutable {
            return Err(CliError::new(
                ExitCode::Usage,
                format!("'{spec}' already exists and --immutable was given"),
            )
            .with_hint("--immutable refuses to modify anything that already exists."));
        }

        // Replacing an object is destructive, so `--interactive` gets to ask.
        if !ctx.confirm_destructive("replace", spec.display())? {
            return Ok(Action::Decline);
        }
    }

    Ok(Action::Store(destination))
}

/// Report the outcome: structured on stdout, human on stderr.
fn report(ctx: &Ctx, spec: &ObjectSpec, outcome: &'static str, bytes: Option<u64>) -> Result<()> {
    let record = Record {
        dest: spec.display(),
        remote: spec.remote(),
        path: spec.path(),
        bytes,
        outcome,
    };

    if ctx.out.format().is_json() {
        // One object in, one document out — the same shape in `json` and
        // `json-lines`, which differ only in whether it is indented.
        ctx.out.json(&record)?;
        return Ok(());
    }

    if let Some(bytes) = bytes {
        // On stderr, never stdout: `dctl rcat` may itself sit inside a pipeline
        // whose stdout belongs to something else entirely.
        ctx.out.success(format!(
            "stored {} from standard input as {spec}",
            size::bytes(bytes, ctx.out.units())
        ));
    }

    Ok(())
}

/// The result of the run, in machine-readable form.
#[derive(Debug, Serialize)]
struct Record<'a> {
    /// The destination exactly as typed.
    dest: &'a str,
    /// Remote name, or `null` for a local path.
    remote: Option<&'a str>,
    /// Logical vault path, or the local path as typed.
    path: &'a str,
    /// Bytes read from standard input and durably stored.
    ///
    /// `null` whenever nothing was read, which is the only honest answer for a
    /// stream: its length cannot be known without consuming it, and a run that
    /// consumed nothing has no number to report.
    bytes: Option<u64>,
    /// Stable slug: stored, planned, or declined.
    outcome: &'a str,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::GlobalArgs;
    use clap::Parser;
    use std::fs;
    use tempfile::tempdir;

    /// Mirrors the real command tree, so the tests exercise the same parse the
    /// binary does — including globals given *after* the verb.
    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
        #[command(subcommand)]
        verb: Verb,
    }

    #[derive(clap::Subcommand, Debug)]
    enum Verb {
        Rcat(RcatArgs),
    }

    /// Parse an argument vector with the configuration pinned.
    ///
    /// `--config` is forced on because [`resolve`] now asks
    /// [`crate::addressing`] whether the destination belongs to a vault, and
    /// that reads the configuration file. Without this the suite would read the
    /// developer's own `config.toml` and pass or fail depending on the machine.
    /// It is prepended, so a test that pins its own configuration still wins.
    fn try_parse(argv: &[&str]) -> std::result::Result<Harness, clap::Error> {
        let absent = crate::config::absent_path().to_string_lossy().into_owned();
        let pinned = ["dctl".to_string(), "--config".to_string(), absent];
        Harness::try_parse_from(
            pinned
                .into_iter()
                .chain(argv.iter().map(|arg| (*arg).to_string())),
        )
    }

    fn parse(argv: &[&str]) -> Harness {
        match try_parse(argv) {
            Ok(harness) => harness,
            Err(error) => unreachable!("{argv:?} did not parse: {error}"),
        }
    }

    fn ctx_for(harness: &Harness) -> Ctx {
        Ctx::new(harness.globals.clone())
    }

    fn spec(text: &str) -> ObjectSpec {
        ObjectSpec::parse(text).unwrap()
    }

    #[test]
    fn a_destination_is_required() {
        assert!(try_parse(&["rcat"]).is_err());
        assert!(try_parse(&["rcat", "vault:a"]).is_ok());
    }

    #[test]
    fn a_terminal_on_stdin_is_a_usage_error_not_a_hang() {
        let parsed = parse(&["rcat", "vault:a.bin"]);
        let error = resolve(&ctx_for(&parsed), &spec("vault:a.bin"), true).unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.hint().is_some(), "the fix must be spelled out");
    }

    #[test]
    fn a_remote_destination_is_refused_before_stdin_is_touched() {
        // PLAN.md §6: never report work that did not happen — and never consume
        // a pipe that cannot be rewound in order to find that out.
        let parsed = parse(&["rcat", "vault:a.bin"]);
        let error = resolve(&ctx_for(&parsed), &spec("vault:a.bin"), false).unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.hint().is_some());
    }

    #[test]
    fn a_dry_run_of_a_remote_is_refused_rather_than_rehearsed() {
        // Announcing "would store" for something this build cannot do would be
        // a promise the tool cannot keep.
        let parsed = parse(&["rcat", "vault:a.bin", "--dry-run"]);
        assert!(resolve(&ctx_for(&parsed), &spec("vault:a.bin"), false).is_err());
    }

    #[test]
    fn a_dry_run_of_a_local_destination_reads_nothing() {
        let dir = tempdir().unwrap();
        let destination = dir.path().join("out.bin");
        let name = destination.to_string_lossy().into_owned();
        let parsed = parse(&["rcat", &name, "--dry-run"]);

        let action = resolve(&ctx_for(&parsed), &spec(&name), false).unwrap();
        assert_eq!(action, Action::Plan);
        assert!(!destination.exists(), "a dry run must create nothing");
    }

    #[test]
    fn a_bare_remote_names_no_object() {
        let parsed = parse(&["rcat", "vault:"]);
        let error = resolve(&ctx_for(&parsed), &spec("vault:"), false).unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[test]
    fn immutable_refuses_to_replace_an_existing_object() {
        let dir = tempdir().unwrap();
        let destination = dir.path().join("out.bin");
        fs::write(&destination, b"original").unwrap();
        let name = destination.to_string_lossy().into_owned();

        let parsed = parse(&["rcat", &name, "--immutable"]);
        let error = resolve(&ctx_for(&parsed), &spec(&name), false).unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert_eq!(
            fs::read(&destination).unwrap(),
            b"original",
            "the refusal must not have touched anything"
        );
    }

    #[test]
    fn a_new_local_destination_is_accepted() {
        let dir = tempdir().unwrap();
        let name = dir.path().join("out.bin").to_string_lossy().into_owned();
        let parsed = parse(&["rcat", &name]);

        let action = resolve(&ctx_for(&parsed), &spec(&name), false).unwrap();
        assert_eq!(action, Action::Store(PathBuf::from(&name)));
    }

    #[tokio::test]
    async fn a_local_stream_is_stored_and_counted() {
        // The end-to-end local path: stdin is not involved, but `store` is the
        // same call `run` makes once the destination has been resolved.
        let dir = tempdir().unwrap();
        let destination = dir.path().join("out.bin");
        let parsed = parse(&["rcat", "ignored.bin"]);
        let ctx = ctx_for(&parsed);

        let bytes = local::store(&ctx, &destination, &mut b"hello world".as_slice()).unwrap();

        assert_eq!(bytes, 11);
        assert_eq!(fs::read(&destination).unwrap(), b"hello world");
        assert_eq!(ctx.stats.snapshot().bytes_transferred, 11);
    }

    #[test]
    fn the_json_record_separates_stored_from_planned() {
        let stored = serde_json::to_value(Record {
            dest: "out.bin",
            remote: None,
            path: "out.bin",
            bytes: Some(11),
            outcome: RCAT_OUTCOME_STORED,
        })
        .unwrap();
        assert_eq!(stored["bytes"], 11);
        assert_eq!(stored["outcome"], RCAT_OUTCOME_STORED);
        assert_eq!(stored["remote"], serde_json::Value::Null);

        // A plan has no byte count, because a stream's length cannot be known
        // without consuming it — and a plan consumes nothing.
        let planned = serde_json::to_value(Record {
            dest: "vault:a",
            remote: Some("vault"),
            path: "a",
            bytes: None,
            outcome: RCAT_OUTCOME_PLANNED,
        })
        .unwrap();
        assert_eq!(planned["bytes"], serde_json::Value::Null);
        assert_eq!(planned["outcome"], RCAT_OUTCOME_PLANNED);
        assert_eq!(planned["remote"], "vault");
    }

    #[test]
    fn the_outcome_slugs_are_distinct() {
        // A consumer branches on them, so a collision would make two different
        // results indistinguishable.
        let slugs = [
            RCAT_OUTCOME_STORED,
            RCAT_OUTCOME_PLANNED,
            RCAT_OUTCOME_DECLINED,
        ];
        for (index, slug) in slugs.iter().enumerate() {
            assert!(!slug.is_empty());
            assert!(!slugs[index + 1..].contains(slug), "'{slug}' listed twice");
        }
    }
}
