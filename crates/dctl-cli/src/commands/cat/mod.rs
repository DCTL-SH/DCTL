//! `dctl cat` — write object contents to standard output.
//!
//! `cat` is a pipeline citizen: **stdout carries object bytes and nothing else,
//! ever.** Progress, warnings, the dry-run plan and the discard report all go to
//! stderr, which is what makes `dctl cat vault:film.mkv | ffplay -` work while a
//! progress bar is still animating on the terminal.
//!
//! Four behaviours are deliberate rather than incidental:
//!
//! * **A closed pipe is success.** `dctl cat big.mkv | head -c 1M` exits 0. The
//!   reasoning lives in [`sink`], which owns that rule.
//! * **Ranges are ranges, not read-and-discard.** `--offset`/`--count` resolve to
//!   a byte window ([`range`]) that becomes a `seek` on a local file and, once
//!   the engine exposes it, a ranged read of exactly the stored chunks covering
//!   the window. Seeking 40 GB into a film costs one request, not 40 GB.
//! * **Every argument is pre-flighted before any byte is written.** A run that
//!   emitted half a stream and then failed would leave a redirected file that
//!   looks complete and is not — the false success `PLAN.md` §6 forbids.
//! * **`--json` requires `--discard`.** stdout cannot carry both raw bytes and a
//!   JSON document. Rather than silently corrupting one with the other, the
//!   combination is refused and `--discard` turns `cat` into a
//!   read-and-report — which is also how you verify that an object can be read
//!   end to end without spooling it anywhere.
//!
//! **Engine reality.** Local paths are fully implemented, including every range
//! flag: a bare path is part of the documented path model, and a local file is
//! seekable. Remote objects need an unlocked vault and a ranged read, which
//! `dctl-core` does not expose yet; those invocations parse, validate, resolve
//! their range and then fail with a real exit code rather than printing anything.

mod range;
mod sink;
mod source;

use std::io::{self, Write};

use clap::Args;
use serde::Serialize;

use crate::commands::pipeline::ObjectSpec;
use crate::constants::{CAT_JSON_STREAM_HINT, STREAM_CHUNK_BYTES};
use crate::ctx::Ctx;
use crate::error::{CliError, Result};
use crate::output::{Format, Units, size};

use range::Span;
use sink::{Flow, Sink};
use source::Source;

/// Arguments to `dctl cat`.
#[derive(Args, Debug)]
pub struct CatArgs {
    /// Objects to write, in the order given.
    #[arg(value_name = "REMOTE:PATH", required = true)]
    pub paths: Vec<String>,

    /// Write only the first N bytes of each object.
    #[arg(
        long,
        value_name = "N",
        value_parser = range::byte_count,
        conflicts_with_all = ["tail", "offset", "count"]
    )]
    pub head: Option<u64>,

    /// Write only the last N bytes of each object.
    #[arg(
        long,
        value_name = "N",
        value_parser = range::byte_count,
        conflicts_with_all = ["offset", "count"]
    )]
    pub tail: Option<u64>,

    /// Start reading at this byte offset. Negative counts back from the end.
    #[arg(
        long,
        value_name = "N",
        allow_hyphen_values = true,
        value_parser = range::byte_offset
    )]
    pub offset: Option<i64>,

    /// Write at most this many bytes from each object.
    #[arg(long, value_name = "N", value_parser = range::byte_count)]
    pub count: Option<u64>,

    /// Read the objects but write nothing: proves they can be read end to end.
    #[arg(long)]
    pub discard: bool,
}

/// Write the requested objects, or the requested slice of each, to stdout.
pub async fn run(ctx: &Ctx, args: &CatArgs) -> Result<()> {
    let span = Span::from_flags(args.head, args.tail, args.offset, args.count)?;

    if ctx.out.format().is_json() && !args.discard {
        return Err(
            CliError::usage("--json cannot share stdout with an object's bytes")
                .with_hint(CAT_JSON_STREAM_HINT),
        );
    }

    // Locate and measure everything first. Nothing is written until every
    // argument has been proven readable.
    let mut sources = Vec::with_capacity(args.paths.len());
    for path in &args.paths {
        sources.push(Source::preflight(ObjectSpec::parse(path)?, span)?);
    }

    ctx.stats.add_total_files(sources.len() as u64);
    ctx.stats
        .add_total_bytes(sources.iter().map(|source| source.slice().length).sum());

    if ctx.is_dry_run() {
        return report_plan(ctx, &sources);
    }

    // One copy loop, two destinations. `--discard` reads exactly the same bytes
    // through exactly the same path and drops them at the last step, so what it
    // proves about an object is what a real read would find.
    if args.discard {
        stream(ctx, args, &sources, &mut Sink::writing(io::sink()))
    } else {
        stream(ctx, args, &sources, &mut Sink::writing(io::stdout().lock()))
    }
}

/// Copy every source into `sink`, reporting as the active format requires.
fn stream<W: Write>(
    ctx: &Ctx,
    args: &CatArgs,
    sources: &[Source],
    sink: &mut Sink<W>,
) -> Result<()> {
    // One buffer for the whole invocation: memory stays O(1), never O(objects)
    // and never O(file size).
    let mut buffer = vec![0_u8; STREAM_CHUNK_BYTES];
    let mut records = Vec::new();

    for source in sources {
        let before = sink.written();

        // A zero-length request — `--head 0`, or an offset past the end — needs
        // no file handle at all. Pre-flight already proved the object exists, so
        // opening it here would buy nothing but a syscall.
        let flow = if source.slice().is_empty() {
            Flow::Continue
        } else {
            let mut reader = source.open()?;
            sink.drain(&mut reader, &mut buffer)?
        };

        let bytes = sink.written() - before;

        ctx.stats.add_bytes(bytes);
        ctx.stats.file_done();
        ctx.out.info(format!(
            "{}: {}",
            source.spec(),
            size::bytes(bytes, ctx.out.units())
        ));
        emit(ctx, Record::of(source, bytes, false), &mut records)?;

        if flow == Flow::Stop {
            // Not an error: the consumer got what it wanted and went away.
            ctx.out.info("output stream closed — stopping");
            break;
        }
    }

    let total = sink.finish()?;

    if matches!(ctx.out.format(), Format::Json) {
        ctx.out.json(&records)?;
    } else if args.discard {
        ctx.out.success(format!(
            "{} read and discarded from {} objects",
            size::bytes(total, ctx.out.units()),
            size::count(sources.len() as u64)
        ));
    }

    Ok(())
}

/// Report what a real run would read, without reading it.
///
/// A dry run writes nothing to stdout even though `cat` destroys nothing: the
/// bytes *are* this command's effect, and a run advertised as effect-free must
/// not dump a 50 GB film into the caller's pipe.
fn report_plan(ctx: &Ctx, sources: &[Source]) -> Result<()> {
    let mut records = Vec::new();

    for source in sources {
        ctx.dry_run_notice("read", &describe(source, ctx.out.units()));
        emit(ctx, Record::of(source, 0, true), &mut records)?;
    }

    if matches!(ctx.out.format(), Format::Json) {
        ctx.out.json(&records)?;
    }
    Ok(())
}

/// Emit one record now, or hold it for the closing document.
///
/// [`Format::JsonLines`] streams — a consumer reads, parses and drops one line at
/// a time, so a listing far larger than memory still works. [`Format::Json`] must
/// be a single well-formed document, so its records are collected and written
/// once as an array. [`Format::Text`] has already said everything it has to say:
/// its output is the bytes themselves.
fn emit<'a>(ctx: &Ctx, record: Record<'a>, collected: &mut Vec<Record<'a>>) -> Result<()> {
    match ctx.out.format() {
        Format::JsonLines => ctx.out.json(&record)?,
        Format::Json => collected.push(record),
        Format::Text => {}
    }
    Ok(())
}

/// A human description of one planned read.
fn describe(source: &Source, units: Units) -> String {
    let slice = source.slice();
    if slice.start == 0 && slice.length == source.size() {
        return format!("{} ({})", source.spec(), size::bytes(source.size(), units));
    }
    format!(
        "{} (bytes {}..{} of {})",
        source.spec(),
        slice.start,
        slice.end(),
        size::bytes(source.size(), units)
    )
}

/// One object's contribution to the run, in machine-readable form.
#[derive(Debug, Serialize)]
struct Record<'a> {
    /// The argument exactly as typed, so a record can be matched to its input.
    spec: &'a str,
    /// Remote name, or `null` for a local path.
    remote: Option<&'a str>,
    /// Logical vault path, or the local path as typed.
    path: &'a str,
    /// The object's full size in bytes.
    size: u64,
    /// First byte of the range that was read.
    offset: u64,
    /// Length of that range.
    length: u64,
    /// Bytes actually written or discarded — the only field that reports work
    /// that really happened.
    bytes: u64,
    /// True when nothing was read. Present on every record, not just dry-run
    /// ones, so a consumer can never mistake a plan for a result by omission.
    dry_run: bool,
}

impl<'a> Record<'a> {
    fn of(source: &'a Source, bytes: u64, dry_run: bool) -> Self {
        let slice = source.slice();
        Self {
            spec: source.spec().display(),
            remote: source.spec().remote(),
            path: source.spec().path(),
            size: source.size(),
            offset: slice.start,
            length: slice.length,
            bytes,
            dry_run,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::GlobalArgs;
    use crate::exit::ExitCode;
    use clap::Parser;
    use std::fs;
    use std::path::Path;
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
        Cat(CatArgs),
    }

    impl Harness {
        fn args(&self) -> &CatArgs {
            let Verb::Cat(args) = &self.verb;
            args
        }
    }

    fn parse(argv: &[&str]) -> Harness {
        match try_parse(argv) {
            Ok(harness) => harness,
            Err(error) => unreachable!("{argv:?} did not parse: {error}"),
        }
    }

    fn try_parse(argv: &[&str]) -> std::result::Result<Harness, clap::Error> {
        Harness::try_parse_from(std::iter::once("dctl").chain(argv.iter().copied()))
    }

    fn ctx_for(harness: &Harness) -> Ctx {
        Ctx::new(harness.globals.clone())
    }

    fn seed(dir: &Path, name: &str, bytes: &[u8]) -> String {
        let path = dir.join(name);
        fs::write(&path, bytes).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn at_least_one_object_is_required() {
        assert!(try_parse(&["cat"]).is_err());
        assert!(try_parse(&["cat", "vault:a"]).is_ok());
    }

    #[test]
    fn range_flags_accept_size_suffixes() {
        let parsed = parse(&["cat", "vault:a", "--head", "1M"]);
        assert_eq!(parsed.args().head, Some(1024 * 1024));
        let parsed = parse(&["cat", "vault:a", "--offset", "-4K", "--count", "512"]);
        assert_eq!(parsed.args().offset, Some(-4096));
        assert_eq!(parsed.args().count, Some(512));
    }

    #[test]
    fn contradictory_range_flags_are_rejected_by_the_parser() {
        // clap enforces it, and `Span::from_flags` enforces it again — a flag
        // added later without the matching `conflicts_with` must not slip past.
        assert!(try_parse(&["cat", "vault:a", "--head", "1", "--tail", "1"]).is_err());
        assert!(try_parse(&["cat", "vault:a", "--head", "1", "--offset", "1"]).is_err());
        assert!(try_parse(&["cat", "vault:a", "--tail", "1", "--count", "1"]).is_err());
    }

    #[tokio::test]
    async fn json_without_discard_is_a_usage_error() {
        // The two cannot share stdout, and silently corrupting either would be
        // worse than refusing.
        let parsed = parse(&["cat", "vault:a", "--json"]);
        let error = run(&ctx_for(&parsed), parsed.args()).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.hint().is_some());
    }

    #[tokio::test]
    async fn a_remote_object_is_refused_before_anything_is_written() {
        // PLAN.md §6: never report work that did not happen. The engine cannot
        // range-read a vault yet, so this must be a loud failure.
        let parsed = parse(&["cat", "vault:film.mkv"]);
        let error = run(&ctx_for(&parsed), parsed.args()).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.hint().is_some());
    }

    #[tokio::test]
    async fn one_bad_argument_stops_the_whole_run_before_any_output() {
        // Pre-flight: a readable first object must not be streamed when a later
        // argument is unreadable, or the redirected file looks complete.
        let dir = tempdir().unwrap();
        let good = seed(dir.path(), "a.bin", b"hello");
        let parsed = parse(&["cat", &good, "vault:b.bin", "--discard"]);
        let ctx = ctx_for(&parsed);

        assert!(run(&ctx, parsed.args()).await.is_err());
        assert_eq!(
            ctx.stats.snapshot().bytes_transferred,
            0,
            "nothing may be read once any argument has failed pre-flight"
        );
    }

    #[tokio::test]
    async fn discard_reads_every_byte_and_writes_none() {
        let dir = tempdir().unwrap();
        let a = seed(dir.path(), "a.bin", &[1_u8; 100]);
        let b = seed(dir.path(), "b.bin", &[2_u8; 50]);
        let parsed = parse(&["cat", &a, &b, "--discard"]);
        let ctx = ctx_for(&parsed);

        run(&ctx, parsed.args()).await.unwrap();

        let snapshot = ctx.stats.snapshot();
        assert_eq!(snapshot.bytes_transferred, 150);
        assert_eq!(snapshot.files_done, 2);
        assert_eq!(snapshot.errors, 0);
    }

    #[tokio::test]
    async fn a_range_reads_only_its_own_bytes() {
        let dir = tempdir().unwrap();
        let path = seed(dir.path(), "a.bin", &[0_u8; 1000]);
        let parsed = parse(&["cat", &path, "--tail", "40", "--discard"]);
        let ctx = ctx_for(&parsed);

        run(&ctx, parsed.args()).await.unwrap();
        assert_eq!(ctx.stats.snapshot().bytes_transferred, 40);
    }

    #[tokio::test]
    async fn a_dry_run_reads_nothing_at_all() {
        let dir = tempdir().unwrap();
        let path = seed(dir.path(), "a.bin", &[0_u8; 1000]);
        let parsed = parse(&["cat", &path, "--dry-run"]);
        let ctx = ctx_for(&parsed);

        run(&ctx, parsed.args()).await.unwrap();
        let snapshot = ctx.stats.snapshot();
        assert_eq!(snapshot.bytes_transferred, 0);
        assert_eq!(snapshot.files_done, 0);
        // The plan still counted what a real run would move.
        assert_eq!(snapshot.bytes_total, 1000);
    }

    #[tokio::test]
    async fn a_dry_run_still_validates_its_arguments() {
        // A dry run that accepted a nonexistent file would be worthless as a
        // rehearsal.
        let dir = tempdir().unwrap();
        let missing = dir.path().join("nope.bin");
        let parsed = parse(&["cat", &missing.to_string_lossy(), "--dry-run"]);
        let error = run(&ctx_for(&parsed), parsed.args()).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::FileNotFound);
    }

    #[tokio::test]
    async fn json_lines_and_json_both_survive_a_discarding_run() {
        let dir = tempdir().unwrap();
        let path = seed(dir.path(), "a.bin", &[0_u8; 10]);
        for format in ["json", "json-lines"] {
            let parsed = parse(&["cat", &path, "--discard", "--format", format]);
            let ctx = ctx_for(&parsed);
            run(&ctx, parsed.args()).await.unwrap();
            assert_eq!(ctx.stats.snapshot().bytes_transferred, 10);
        }
    }

    #[test]
    fn the_json_record_names_what_happened_and_what_did_not() {
        let dir = tempdir().unwrap();
        let path = seed(dir.path(), "a.bin", &[0_u8; 10]);
        let spec = ObjectSpec::parse(&path).unwrap();
        let source = Source::preflight(spec, Span::WHOLE).unwrap();

        let value = serde_json::to_value(Record::of(&source, 10, false)).unwrap();
        assert_eq!(value["size"], 10);
        assert_eq!(value["offset"], 0);
        assert_eq!(value["length"], 10);
        assert_eq!(value["bytes"], 10);
        assert_eq!(value["dry_run"], false);
        assert_eq!(value["remote"], serde_json::Value::Null);

        // A plan reports zero bytes and says so twice, so neither a human nor a
        // consumer can read it as completed work.
        let planned = serde_json::to_value(Record::of(&source, 0, true)).unwrap();
        assert_eq!(planned["bytes"], 0);
        assert_eq!(planned["dry_run"], true);
    }

    #[test]
    fn the_plan_description_names_the_window_only_when_there_is_one() {
        let dir = tempdir().unwrap();
        let path = seed(dir.path(), "a.bin", &[0_u8; 10]);
        let spec = ObjectSpec::parse(&path).unwrap();

        let whole = Source::preflight(spec.clone(), Span::WHOLE).unwrap();
        assert!(!describe(&whole, Units::Binary).contains("bytes"));

        let span = Span::from_flags(Some(4), None, None, None).unwrap();
        let part = Source::preflight(spec, span).unwrap();
        assert!(describe(&part, Units::Binary).contains("bytes 0..4"));
    }
}
