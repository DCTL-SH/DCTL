//! `dctl rcat` — read standard input and store it as one object.
//!
//! The mirror image of `cat`, and a pipeline citizen for the same reason:
//! **stdin is the payload**, so nothing on stdout may compete with it and every
//! report goes to stderr unless a machine format was asked for.
//!
//! Three properties define the command:
//!
//! * **The length is never required in advance.** `pg_dump | dctl rcat
//!   archive:db.sql` cannot say how large the dump will be, and holding it in
//!   memory to find out would put an arbitrary amount of the user's data in RAM.
//!   A local destination is written straight through ([`local`]); a vault
//!   destination is spooled to a temporary file and sealed from there
//!   ([`spool`]), which is what keeps memory at one chunk and leaves `rcat`
//!   without the size limit the transfer engine still has.
//! * **It refuses before it reads.** A pipe cannot be rewound. If the
//!   destination cannot be written — because the remote is one this build has no
//!   write path to, because `--immutable` forbids replacing what is there, or
//!   because the operator declined — the command fails *before* the first read,
//!   leaving the producer's output intact. Consuming a stream and then failing
//!   would destroy data that was never stored anywhere.
//! * **The commit is the last step.** For a local destination the bytes are
//!   staged, fsynced and renamed into place ([`local`]), so a reader sees the old
//!   object or the whole new one and never a truncated middle. For a vault the
//!   seal, the verified write and the index commit are one operation in
//!   `dctl-core`, which is stronger: there is no window in which bytes are
//!   stored but uncommitted.
//!
//! A terminal on stdin is a usage error rather than an invitation to type: the
//! command would otherwise sit there looking like a hang, which is the most
//! confusing way for a byte-stream tool to fail.
//!
//! ## Where a stream may go, and where it may not
//!
//! * A **local path** — written durably, exactly as before.
//! * A **vault remote** — sealed. See [`sealed`], and [`spool`] for the one
//!   consequence worth knowing: the plaintext transits a temporary file on the
//!   local disk, owner-only and unlinked when the run ends.
//! * A **plain local remote** — an ordinary file inside that remote's root.
//! * A **plain object store** — refused, and refused by *this command's* own
//!   gap rather than by a missing store capability. `dctl copy ./src b2:bucket`
//!   writes plain objects into a bucket today; `rcat` has a filesystem arm and a
//!   vault arm and no third one, so it says exactly that
//!   ([`refuse_object_store`]) instead of claiming the store cannot take them.
//!
//! ## The vault-plaintext guard has not moved
//!
//! Piping into a directory that holds a vault is still refused, by the same
//! [`crate::addressing`] rule the transfer engine asks — and now the named form
//! is refused too, so `producer | dctl rcat archive-store:x` cannot put foreign
//! plaintext among a vault's objects either. A guard that protects one spelling
//! of an address is not a guard.

mod local;
mod sealed;
mod spool;
mod stream;

use std::io::{self, IsTerminal};
use std::path::PathBuf;

use clap::Args;
use serde::Serialize;

use crate::audit::record::Entry as AuditEntry;
use crate::audit::sink;
use crate::commands::directory::Target;
use crate::commands::pipeline::{ObjectSpec, command_name};
use crate::constants::{
    RCAT_OBJECT_STORE_FEATURE, RCAT_OBJECT_STORE_HINT, RCAT_OUTCOME_DECLINED, RCAT_OUTCOME_PLANNED,
    RCAT_OUTCOME_STORED, RCAT_TERMINAL_STDIN_HINT,
};
use crate::ctx::Ctx;
use crate::error::{CliError, Result};
use crate::output::size;
use crate::platform::path as logical;
use crate::remote::Place;

/// Stable command name, used where a message has to name the verb the user
/// typed rather than the module it landed in.
const VERB: &str = "rcat";

/// What this command calls the thing it addresses, in its diagnostics.
const NOUN: &str = "object";

/// Arguments to `dctl rcat`.
#[derive(Args, Debug)]
pub struct RcatArgs {
    /// Object to create from standard input.
    #[arg(value_name = "REMOTE:PATH")]
    pub dest: String,
}

/// Store everything on standard input as a single object.
///
/// # Errors
/// Every failure in [`resolve`], plus whatever the spool, the seal, the
/// provider or the filesystem reported.
pub async fn run(ctx: &Ctx, args: &RcatArgs) -> Result<()> {
    let spec = ObjectSpec::parse(&args.dest)?;

    match resolve(ctx, &spec, io::stdin().is_terminal())? {
        Action::Store(destination) => {
            let stored = local::store(ctx, &destination, &mut io::stdin().lock());
            audit(ctx, &spec, &stored)?;
            let bytes = stored?;
            ctx.stats.file_done();
            report(ctx, &spec, RCAT_OUTCOME_STORED, Some(bytes))
        }
        Action::Seal(target) => {
            match sealed::store(ctx, &spec, &target, &mut io::stdin().lock()).await {
                // The operator declined the replacement, so nothing was read and
                // nothing was written. There is no event to attest to, and a
                // record for one would be a record of something that did not
                // happen.
                Ok(None) => {
                    ctx.out.warn(format!(
                        "{spec}: not replaced — nothing was read from standard input"
                    ));
                    report(ctx, &spec, RCAT_OUTCOME_DECLINED, None)
                }
                outcome => {
                    let stored = outcome.map(Option::unwrap_or_default);
                    audit(ctx, &spec, &stored)?;
                    let bytes = stored?;
                    report(ctx, &spec, RCAT_OUTCOME_STORED, Some(bytes))
                }
            }
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

/// Append the chained record for a stream that was actually consumed.
///
/// Called after the store returns and before its error is raised, so a failed
/// `rcat` is recorded too — which matters more here than almost anywhere else in
/// DCTL. A pipe cannot be rewound: when `pg_dump | dctl rcat archive:db.sql`
/// fails, the dump is gone, and "was the 03:00 backup written?" is a question
/// only the log can answer afterwards.
///
/// No plaintext hash. The bytes are streamed to their destination and never held
/// whole, which is the property that lets `rcat` take a dump larger than memory;
/// buying a digest by keeping them would trade that away, and neither `local`
/// nor `sealed` computes one today. An empty field is what the format defines
/// for "no plaintext hash", and it is honest — a wrong one would not be.
///
/// # Errors
/// Whatever [`crate::audit::sink::Sink::record`] refused: the operation is then
/// unrecorded and the command fails rather than reporting an unaudited write.
fn audit(ctx: &Ctx, spec: &ObjectSpec, stored: &Result<u64>) -> Result<()> {
    ctx.audit.record(
        &AuditEntry::new(VERB, sink::outcome(stored))
            .path(spec.path())
            .size(stored.as_ref().copied().unwrap_or_default())
            .remote(spec.remote().unwrap_or_default()),
    )
}

/// What this invocation will do, decided before a single byte is read.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Action {
    /// Stream stdin into this local path.
    Store(PathBuf),
    /// Seal stdin into this vault target.
    Seal(Target),
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
/// they typed, then what they piped, then where the destination *is*, then
/// whether this build can write there — and only then the state it is in. The
/// last boundary is the one that matters: everything above it is true of a dry
/// run as well, and everything below it is about bytes that already exist and
/// would be replaced.
///
/// A sealed destination's state is deliberately *not* inspected here. Doing so
/// would mean unlocking the vault during a `--dry-run`, which is a password
/// prompt for a run that will not write; the existence question is asked in
/// [`sealed::decide`] instead, still before the stream is read.
///
/// # Errors
/// [`ExitCode::Usage`](crate::exit::ExitCode::Usage) for a destination that
/// names no object, a terminal on stdin, or an `--immutable` conflict on a local
/// path; [`ExitCode::FatalError`](crate::exit::ExitCode::FatalError) for an
/// unknown remote, a plain object store, or an address the vault-plaintext rule
/// refuses.
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

    let Some(remote) = spec.remote() else {
        return local_action(ctx, spec);
    };

    // A named destination is classified from the configuration — which is also
    // what turns an unknown remote into a typo report rather than a directory of
    // that name in the working directory.
    let target = Target::parse(&format!("{remote}:{}", spec.path()), NOUN)?;
    let place = Place::of(ctx, &target.spec())?;

    // Before the dry-run branch on purpose. A dry run rehearses a real run, so
    // announcing "would store" for an operation this build cannot perform would
    // be a promise the tool cannot keep.
    //
    // Ahead of the addressing rule as well, and that ordering is deliberate
    // rather than incidental: a bucket that is also a vault's object store would
    // otherwise be diagnosed as an addressing violation, when the reason
    // standing between the user and their pipe is that `rcat` has no
    // object-store arm at all. Both refusals are true; this is the one that
    // stays true after the address is fixed.
    refuse_object_store(&place)?;

    // The addressing rule, in its named form: `archive-store:` is a vault's
    // object tree, and foreign plaintext among those objects is both unencrypted
    // and unreadable to the vault that owns them. Asked from the configuration,
    // so the answer never depends on what the store currently holds (invariant
    // I4) and a dry run reaches the same one.
    crate::addressing::refuse_plain_write_to_remote(ctx, remote)?;

    match place {
        Place::Sealed => {
            if ctx.is_dry_run() {
                return Ok(Action::Plan);
            }
            Ok(Action::Seal(target))
        }
        // A plain local remote is an ordinary directory, so it takes the local
        // path exactly as a bare path does — including the durable staging
        // write and the vault-plaintext check below it.
        Place::Filesystem { root, path } => local_at(ctx, &logical::from_logical(&root, &path)),
        // Refused above; the arm asks the same question again rather than
        // inventing a second wording for it, so a place added later is a compile
        // error here rather than a silent fall-through.
        Place::ObjectStore { .. } => refuse_object_store(&place).map(|()| Action::Plan),
    }
}

/// Refuse a bucket, naming the gap that is actually `rcat`'s.
///
/// The only refusal left in this family that names `dctl-cli` as the layer, and
/// it is worth being precise about why. `dctl_store::Backend::put_from_path`
/// would store the spooled stream under the key with the same verified write a
/// transfer gets — the store is ready, the transfer family already uses it, and
/// what is missing is the third arm in [`resolve`] beside the filesystem and the
/// vault. Saying "this build cannot write a plain object" would be false now
/// that `dctl copy ./src b2:mybucket` does exactly that, and a reader who
/// believed it would spool their dump for nothing.
///
/// # Errors
/// [`ExitCode::FatalError`](crate::exit::ExitCode::FatalError) with
/// [`RCAT_OBJECT_STORE_FEATURE`] when `place` is an object store. Standard input
/// has not been read at that point, which is the fact the hint leads with.
fn refuse_object_store(place: &Place) -> Result<()> {
    let Place::ObjectStore { provider } = place else {
        return Ok(());
    };
    Err(CliError::unimplemented(format!(
        "{RCAT_OBJECT_STORE_FEATURE} ({provider}, {})",
        command_name(VERB)
    ))
    .with_hint(RCAT_OBJECT_STORE_HINT))
}

/// The local branch for a destination the user typed as a path.
fn local_action(ctx: &Ctx, spec: &ObjectSpec) -> Result<Action> {
    local_at(ctx, &spec.local_path())
}

/// Decide a filesystem destination, wherever its path came from.
///
/// Shared by the bare-path and plain-local-remote spellings, because they are
/// one destination written two ways and a rule applied to only one of them is a
/// rule with a hole in it.
fn local_at(ctx: &Ctx, destination: &std::path::Path) -> Result<Action> {
    // `rcat` reaches the filesystem by a completely different route from the
    // transfer family, so the addressing rule has to be asked here too. It was
    // not, and `echo secret | dctl rcat ./vault/z.txt` wrote plaintext straight
    // into a vault directory and exited 0 — the exact failure the transfer-side
    // guard exists to prevent, through the one door nobody had checked. Both
    // ask [`crate::addressing`], so neither can be fixed without the other.
    //
    // Ahead of the dry-run branch, alongside the other "this cannot happen at
    // all" checks and for the same reason: a rehearsal that omits a refusal the
    // real run will make is a promise the tool cannot keep. It is safe to ask
    // this early because the answer never depends on the destination's contents
    // (invariant I4) — a dry run and a real run are asking one question with one
    // answer.
    crate::addressing::refuse_plain_write_to_path(ctx, destination)?;

    if ctx.is_dry_run() {
        return Ok(Action::Plan);
    }

    if destination.exists() {
        if ctx.globals.immutable {
            return Err(CliError::new(
                crate::exit::ExitCode::Usage,
                format!(
                    "'{}' already exists and --immutable was given",
                    destination.display()
                ),
            )
            .with_hint("--immutable refuses to modify anything that already exists."));
        }

        // Replacing an object is destructive, so `--interactive` gets to ask.
        if !ctx.confirm_destructive("replace", &destination.display().to_string())? {
            return Ok(Action::Decline);
        }
    }

    Ok(Action::Store(destination.to_path_buf()))
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
    use crate::exit::ExitCode;
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
    /// `--config` is forced on because [`resolve`] asks [`crate::addressing`]
    /// and [`Place`] about the destination, and both read the configuration
    /// file. Without this the suite would read the developer's own `config.toml`
    /// and pass or fail depending on the machine. It is prepended, so a test that
    /// pins its own configuration still wins.
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

    /// A context pointed at a configuration written for this test.
    fn ctx_with_config(body: &str, extra: &[&str]) -> (tempfile::TempDir, Ctx) {
        let dir = tempdir().expect("a temporary directory");
        let path = dir.path().join("config.toml");
        fs::write(&path, body).expect("the fixture is writable");

        let mut flags = vec![
            "dctl".to_string(),
            "--config".to_string(),
            path.to_string_lossy().into_owned(),
            "--quiet".to_string(),
        ];
        flags.extend(extra.iter().map(|flag| (*flag).to_string()));

        #[derive(Parser, Debug)]
        struct Globals {
            #[command(flatten)]
            globals: GlobalArgs,
        }
        (dir, Ctx::new(Globals::parse_from(flags).globals))
    }

    /// The pair `dctl init --name archive --base local:<root>` registers.
    fn vault_pair(root: &std::path::Path) -> String {
        format!(
            "[remotes.archive-store]\ntype = \"local\"\npath = {:?}\nrequire_vault = true\n\n\
             [remotes.archive]\ntype = \"vault\"\nbase = \"archive-store\"\n",
            root.to_string_lossy()
        )
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
    fn a_vault_destination_is_accepted_and_carries_the_canonical_path() {
        // The refusal this command used to make. What replaced it must address
        // the object the user named, canonicalised the way an index key is.
        let store = tempdir().expect("a temporary directory");
        let (_dir, ctx) = ctx_with_config(&vault_pair(store.path()), &[]);

        let action = resolve(&ctx, &spec("archive:./backups//today.sql"), false)
            .expect("a vault is a legitimate destination");

        match action {
            Action::Seal(target) => {
                assert_eq!(target.remote, "archive");
                assert_eq!(target.path, "backups/today.sql");
            }
            other => unreachable!("expected a sealed action, got {other:?}"),
        }
    }

    #[test]
    fn a_dry_run_of_a_vault_reads_nothing_and_asks_for_no_password() {
        // A rehearsal must not unlock: that would put a password prompt in front
        // of a run that will not write.
        let store = tempdir().expect("a temporary directory");
        let (_dir, ctx) = ctx_with_config(&vault_pair(store.path()), &["--dry-run"]);

        assert_eq!(
            resolve(&ctx, &spec("archive:a.bin"), false).unwrap(),
            Action::Plan
        );
    }

    #[test]
    fn a_vaults_object_store_is_refused_by_name() {
        // Foreign plaintext among a vault's objects, through the named spelling.
        // The path spelling is covered below; both have to be closed.
        let store = tempdir().expect("a temporary directory");
        let (_dir, ctx) = ctx_with_config(&vault_pair(store.path()), &[]);

        let error = resolve(&ctx, &spec("archive-store:z.txt"), false)
            .expect_err("a plain write into a vault's store is refused");
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.hint().is_some_and(|hint| hint.contains("archive:")));
    }

    #[test]
    fn a_plain_write_into_a_vault_directory_is_still_refused() {
        // The regression that made this guard exist: `echo secret | dctl rcat
        // ./vault/z.txt` wrote plaintext next to the envelope and exited 0.
        let vault = tempdir().expect("a temporary directory");
        fs::create_dir_all(vault.path().join("system")).expect("the system directory");
        fs::write(vault.path().join("system/envelope.bin"), b"DKE1").expect("an envelope");

        let inside = vault.path().join("z.txt");
        let name = inside.to_string_lossy().into_owned();
        let parsed = parse(&["rcat", &name]);

        let error = resolve(&ctx_for(&parsed), &spec(&name), false)
            .expect_err("plaintext into a vault directory is refused");
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(!inside.exists(), "nothing may be written by the refusal");
    }

    #[test]
    fn a_plain_object_store_is_refused_before_stdin_is_touched() {
        // PLAN.md §6: never report work that did not happen — and never consume
        // a pipe that cannot be rewound in order to find that out.
        let parsed = parse(&["rcat", "b2:bucket/a.bin"]);
        let error = resolve(&ctx_for(&parsed), &spec("b2:bucket/a.bin"), false).unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.hint().is_some());
    }

    #[test]
    fn the_object_store_refusal_names_this_command_as_the_layer_that_is_missing_it() {
        // The assertion the test above cannot make, and the one that went stale
        // silently: "nothing in this build writes a plain object" stopped being
        // true the day `dctl copy ./src b2:bucket` started working, and a
        // refusal that still said it would have a `pg_dump` operator waiting for
        // a store capability that shipped. The gap is a branch in *this* file,
        // so the message says dctl-cli and the hint says which phase.
        let parsed = parse(&["rcat", "b2:bucket/a.bin"]);
        let error = resolve(&ctx_for(&parsed), &spec("b2:bucket/a.bin"), false).unwrap_err();

        assert!(
            error.message().contains(RCAT_OBJECT_STORE_FEATURE),
            "the refusal must name the missing capability: {}",
            error.message()
        );
        assert!(
            error.message().contains("dctl-cli"),
            "and the layer that owes it: {}",
            error.message()
        );
        assert!(
            error.message().contains(crate::constants::PROVIDER_B2),
            "and the provider addressed: {}",
            error.message()
        );
        let hint = error.hint().expect("a refusal must say what to do");
        assert!(
            hint.contains("phase 1"),
            "and the phase that closes it: {hint}"
        );
        assert!(
            hint.contains("Nothing was read from standard input"),
            "a pipe that cannot be rewound makes this the first fact: {hint}"
        );
    }

    #[test]
    fn a_dry_run_of_an_object_store_is_refused_rather_than_rehearsed() {
        // Announcing "would store" for something this build cannot do would be
        // a promise the tool cannot keep.
        let parsed = parse(&["rcat", "b2:bucket/a.bin", "--dry-run"]);
        assert!(resolve(&ctx_for(&parsed), &spec("b2:bucket/a.bin"), false).is_err());
    }

    #[test]
    fn an_unknown_remote_is_named_rather_than_written_to() {
        let parsed = parse(&["rcat", "nosuchremote:a.bin"]);
        let error = resolve(&ctx_for(&parsed), &spec("nosuchremote:a.bin"), false).unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.message().contains("nosuchremote"));
    }

    #[test]
    fn a_plain_local_remote_takes_the_ordinary_filesystem_path() {
        let root = tempdir().expect("a temporary directory");
        let (_dir, ctx) = ctx_with_config(
            &format!(
                "[remotes.scratch]\ntype = \"local\"\npath = {:?}\n",
                root.path().to_string_lossy()
            ),
            &[],
        );

        let action = resolve(&ctx, &spec("scratch:notes/today.md"), false).unwrap();
        assert_eq!(
            action,
            Action::Store(root.path().join("notes").join("today.md"))
        );
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
