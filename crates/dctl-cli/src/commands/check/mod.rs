//! `dctl check SOURCE DEST` — compare two trees without transferring anything.
//!
//! `PLAN.md` §13.6 is blunt about why this exists: a backup nobody ever compared
//! against its source is a hope, not a backup. `check` is the command that turns
//! the hope into a measurement, and it is also the safest command in the tool —
//! it reads, it never writes to either side, and it cannot be talked into
//! copying something "while it is there".
//!
//! Every path lands in exactly one of five buckets:
//!
//! | verdict          | meaning                                    |
//! |------------------|--------------------------------------------|
//! | `match`          | on both sides and the same                 |
//! | `differ`         | on both sides, contents disagree           |
//! | `missing-on-dst` | only at the source                         |
//! | `missing-on-src` | only at the destination                    |
//! | `error`          | could not be compared — never a silent pass |
//!
//! *What* "the same" means is the global comparison dial: size and modification
//! time by default, `--size-only`, or `--checksum` — the only one that proves
//! the contents match. The report always names which one ran, because "0
//! differences" is a very different claim under each.
//!
//! The `--combined`, `--differ`, `--match` and `--missing-on-*` flags write the
//! verdicts to files. A per-verdict file carries bare paths, so
//! `dctl check src: dst: --missing-on-dst todo.txt` followed by
//! `dctl copy src: dst: --files-from todo.txt` is the whole repair loop.
//!
//! ## How a run is performed
//!
//! Both arguments are opened through [`crate::source::open`], so a sealed vault,
//! a plain object store and a local directory are all just *sides*
//! ([`side`]) and neither argument is privileged — `dctl check archive: ./photos`
//! and `dctl check ./photos archive:` are the same walk with the labels swapped.
//! Each side reports its objects keyed relative to its own root, which is what
//! lets a remote rooted at `photos` and a local directory called `photos`
//! describe the same file with the same name.
//!
//! The two sides are then **merged** ([`walk`]) rather than joined: both yield
//! keys in ascending order, so one entry per side is enough and memory stays
//! O(1) in the size of the trees. Comparing two ten-million-object datasets is
//! the case this command exists for, and a map of one side would put the ceiling
//! back where the tool could not ship with it (`PLAN.md` §16.2).
//!
//! Nothing is read from either object unless `--checksum` asks for a hash the
//! source did not record — see [`side::Side::hash`] for what that costs and why
//! computing it is the only way that flag can mean anything against a plain
//! store.

pub mod difference;
pub mod report;
pub mod side;
pub mod sinks;
pub mod walk;

use std::path::PathBuf;

use clap::Args;

use crate::commands::integrity::{Target, command_name};
use crate::commands::listing::Filter;
use crate::ctx::Ctx;
use crate::error::Result;

use difference::{Comparison, Difference, Entry, classify};
use report::{Record, Report};
use side::{Found, Side};
use sinks::{Destinations, Sinks};

/// The verb this module implements, used in messages that name the command.
const VERB: &str = "check";

/// Arguments to `dctl check`.
#[derive(Args, Debug)]
pub struct CheckArgs {
    /// Tree to compare from.
    #[arg(value_name = "SOURCE")]
    pub source: String,

    /// Tree to compare against.
    #[arg(value_name = "DEST")]
    pub dest: String,

    /// Ignore paths that exist only at the destination.
    ///
    /// Asks "is everything from the source present and correct at the
    /// destination?", which is the right question after a `copy` — extra files
    /// at the destination are what `copy` leaves behind by design.
    #[arg(long)]
    pub one_way: bool,

    /// Write every path with its one-character verdict mark to FILE.
    #[arg(long, value_name = "FILE")]
    pub combined: Option<PathBuf>,

    /// Write paths that exist only at the destination to FILE.
    #[arg(long, value_name = "FILE")]
    pub missing_on_src: Option<PathBuf>,

    /// Write paths that exist only at the source to FILE.
    #[arg(long, value_name = "FILE")]
    pub missing_on_dst: Option<PathBuf>,

    /// Write paths that exist on both sides but differ to FILE.
    #[arg(long, value_name = "FILE")]
    pub differ: Option<PathBuf>,

    /// Write paths that matched to FILE.
    // Named explicitly because `match` is a Rust keyword; the flag a user types
    // must still be `--match`.
    #[arg(long = "match", value_name = "FILE")]
    pub matched: Option<PathBuf>,
}

impl CheckArgs {
    /// The verdict files this run was asked to produce.
    #[must_use]
    pub fn destinations(&self) -> Destinations {
        Destinations {
            combined: self.combined.clone(),
            missing_on_src: self.missing_on_src.clone(),
            missing_on_dst: self.missing_on_dst.clone(),
            differ: self.differ.clone(),
            matched: self.matched.clone(),
        }
    }
}

/// Compare two trees and report their differences.
///
/// # Errors
/// [`CliError::usage`](crate::error::CliError::usage) for a malformed path or an
/// unusable output file; whatever opening either side reported (an unresolvable
/// remote, a vault that will not unlock); and
/// [`ExitCode::PartialFailure`](crate::exit::ExitCode::PartialFailure) when the
/// two sides disagree.
///
/// A path that could not be compared is [`Difference::Error`] for that path and
/// does not end the run: the most useful thing this command reports is *how
/// much* of one tree matches the other, and stopping at the first unreadable
/// object hides everything after it.
pub async fn run(ctx: &Ctx, args: &CheckArgs) -> Result<()> {
    let command = command_name(VERB);
    let source_target = Target::parse(&args.source)?;
    let dest_target = Target::parse(&args.dest)?;

    // Check the output files before comparing anything: the mistake is almost
    // always a typo, and finding it after a multi-hour walk helps nobody. This
    // deliberately creates nothing — see `sinks`.
    let destinations = args.destinations();
    destinations.validate()?;

    // Compiled before either side is opened, so a malformed `--include` fails
    // before a password is asked for rather than after.
    let filter = Filter::from_globals(&ctx.globals)?;

    let comparison = Comparison::from_globals(&ctx.globals)?;
    ctx.out.info(format!(
        "{command}: '{source_target}' against '{dest_target}'{}",
        if args.one_way {
            ", ignoring paths that exist only at the destination"
        } else {
            ""
        }
    ));
    if !comparison.proves_contents() {
        // A warning rather than an info, deliberately: a metadata comparison
        // can call two files equal when their contents are not, someone using
        // `check` to validate a backup usually wants the stronger claim, and
        // an info line vanishes at the default verbosity — which left the
        // caveat unread by exactly the cron log that needed it.
        ctx.out.warn(
            "comparing metadata only — contents are not verified; pass \
             --checksum to prove them",
        );
    }

    // Writing the verdict files is this command's only mutation, so it is the
    // only thing --dry-run has to suppress. The comparison itself still runs:
    // it reads and changes nothing, and a dry run that skipped it would print no
    // report at all, which is not what "show me what would happen" means.
    if ctx.is_dry_run() && !destinations.is_empty() {
        for path in [
            args.combined.as_ref(),
            args.missing_on_src.as_ref(),
            args.missing_on_dst.as_ref(),
            args.differ.as_ref(),
            args.matched.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            ctx.dry_run_notice("write", &path.display().to_string());
        }
    }

    let mut source = Side::open(ctx, &source_target, filter.clone()).await?;
    let mut dest = Side::open(ctx, &dest_target, filter).await?;

    // Created only once both sides have opened, so a run that fails on an
    // unresolvable remote leaves no empty files a later script could mistake for
    // "no differences found".
    let mut sinks = if ctx.is_dry_run() || destinations.is_empty() {
        None
    } else {
        Some(Sinks::create(&destinations)?)
    };

    let mut report = Report::new(
        source_target.to_string(),
        dest_target.to_string(),
        comparison,
        args.one_way,
    );

    let mut previous: Option<String> = None;
    while let Some(pair) = walk::next(&mut source, &mut dest).await? {
        let key = pair.key().to_string();
        walk::ordered(previous.as_deref(), &key)?;

        let verdict = compare(ctx, &source, &dest, &pair, comparison).await;
        previous = Some(key.clone());

        // Suppressed before the sinks as well as before the tally: a path
        // `--one-way` does not count is not a finding, and writing it to
        // `--missing-on-src` would hand a script a list the report says is
        // empty.
        if args.one_way && verdict.suppressed_by_one_way() {
            continue;
        }

        report.push(Record::new(key.clone(), verdict));
        if let Some(sinks) = sinks.as_mut() {
            sinks.record(verdict, &key)?;
        }
    }

    if let Some(sinks) = sinks.as_mut() {
        // Explicit, because a buffered write that fails during a drop has
        // nowhere to report the failure — and a truncated verdict file nobody
        // was told about is the silent partial success `PLAN.md` §6 forbids.
        sinks.finish()?;
    }

    report.emit(&ctx.out)?;
    match report.outcome() {
        Some(error) => Err(error),
        None => {
            // A clean run used to print nothing at all, on either stream. That
            // makes a health gate indistinguishable from a health gate that did
            // nothing — a typo'd prefix matching no objects, a filter that
            // excluded the whole dataset, a side that listed empty — and all
            // three exited 0 in silence. The confirmation goes to stderr, so
            // `dctl check … > findings.txt` still writes only findings and
            // stdout stays the channel where a difference would appear.
            ctx.out.success(report.confirmation());
            Ok(())
        }
    }
}

/// The verdict for one path, resolving hashes if `--checksum` needs them.
///
/// Split out because the checksum case is the only one that can *fail while
/// deciding*: reading an object to hash it can hit a damaged vault object or a
/// provider outage. That is [`Difference::Error`] for this path and a warning on
/// stderr, never a match and never the end of the run — "I could not tell" is a
/// third answer, and rolling it into either of the other two is the misreport
/// this command exists to prevent.
async fn compare(
    ctx: &Ctx,
    source: &Side,
    dest: &Side,
    pair: &walk::Pair,
    comparison: Comparison,
) -> Difference {
    // A recorded listing can hold a ghost: a path whose stored object was
    // deleted behind the tool's back, still wearing the size, mtime and hash
    // of bytes that are gone. Every comparison mode — including --checksum,
    // whose vault-side digest is the same index row — would call that a
    // Match, which is BENCHMARKS §7.2's "all match" over a lost object.
    // Confirm each recorded half against the store first, so a loss
    // classifies as missing. Costs one existence probe per entry on recorded
    // sides only; a self-reported listing already is the store's answer.
    let source_found = match confirmed(ctx, source, pair.source.as_ref()).await {
        Ok(found) => found,
        Err(()) => return Difference::Error,
    };
    let dest_found = match confirmed(ctx, dest, pair.dest.as_ref()).await {
        Ok(found) => found,
        Err(()) => return Difference::Error,
    };

    match (source_found, dest_found) {
        (Some(found_source), Some(found_dest)) if comparison.proves_contents() => {
            match (
                hashed(ctx, source, found_source).await,
                hashed(ctx, dest, found_dest).await,
            ) {
                (Some(left), Some(right)) => classify(Some(&left), Some(&right), comparison),
                _ => Difference::Error,
            }
        }
        (source_found, dest_found) => classify(
            source_found.map(|found| &found.entry),
            dest_found.map(|found| &found.entry),
            comparison,
        ),
    }
}

/// One half of a pair, with a recorded side's ghost rows resolved to absences.
///
/// `Err(())` means the probe itself failed — "could not ask" is a third
/// answer, reported on stderr and classified as an error for the path, never
/// rolled into either verdict.
async fn confirmed<'pair>(
    ctx: &Ctx,
    side: &Side,
    found: Option<&'pair Found>,
) -> std::result::Result<Option<&'pair Found>, ()> {
    let Some(present) = found else {
        return Ok(None);
    };
    if !side.recorded() {
        return Ok(Some(present));
    }
    match side.confirm(present).await {
        Ok(true) => Ok(Some(present)),
        Ok(false) => {
            ctx.out.warn(format!(
                "the index records '{}' but the store no longer holds its \
                 object — counted as missing; `dctl verify` reports the full \
                 damage",
                present.path()
            ));
            Ok(None)
        }
        Err(error) => {
            ctx.out.warn(format!(
                "could not confirm '{}' against the store: {error}",
                present.path()
            ));
            Err(())
        }
    }
}

/// One side's entry with its content hash filled in, or [`None`] if it could not
/// be obtained.
///
/// The failure is reported on stderr rather than swallowed, because the report
/// itself can only say `error` — it has no field for *why* — and "this object
/// would not read" is exactly what the operator needs in order to act.
async fn hashed(ctx: &Ctx, side: &Side, found: &Found) -> Option<Entry> {
    match side.hash(found).await {
        Ok(digest) => Some(found.entry.clone().hashed(digest)),
        Err(error) => {
            ctx.out.warn(format!(
                "cannot compare '{}': {}",
                found.key(),
                error.message()
            ));
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Cli, Command};
    use crate::exit::ExitCode;
    use clap::Parser;

    fn parse(args: &[&str]) -> (Ctx, CheckArgs) {
        let cli = Cli::try_parse_from(std::iter::once("dctl").chain(args.iter().copied()))
            .expect("arguments should parse");
        let Command::Check(check) = cli.command else {
            panic!("expected the check subcommand");
        };
        (Ctx::new(cli.globals), check)
    }

    #[tokio::test]
    async fn both_sides_are_required() {
        assert!(Cli::try_parse_from(["dctl", "check", "vault:"]).is_err());
        assert!(Cli::try_parse_from(["dctl", "check"]).is_err());
    }

    #[tokio::test]
    async fn the_verdict_files_parse_under_their_flag_names() {
        // `--match` is spelled with a keyword; the field behind it is not.
        let (_, args) = parse(&[
            "check",
            "vault:photos",
            "./photos",
            "--combined",
            "all.txt",
            "--missing-on-src",
            "src.txt",
            "--missing-on-dst",
            "dst.txt",
            "--differ",
            "differ.txt",
            "--match",
            "same.txt",
            "--one-way",
        ]);
        assert!(args.one_way);
        let destinations = args.destinations();
        assert!(!destinations.is_empty());
        assert_eq!(destinations.combined, Some(PathBuf::from("all.txt")));
        assert_eq!(destinations.matched, Some(PathBuf::from("same.txt")));
        assert_eq!(destinations.differ, Some(PathBuf::from("differ.txt")));
    }

    #[tokio::test]
    async fn no_flags_means_no_output_files() {
        let (_, args) = parse(&["check", "src:", "dst:"]);
        assert!(args.destinations().is_empty());
        assert!(!args.one_way);
    }

    #[tokio::test]
    async fn a_malformed_path_is_a_usage_error() {
        let (ctx, args) = parse(&["check", "vault:../escape", "./photos"]);
        assert_eq!(run(&ctx, &args).await.unwrap_err().code(), ExitCode::Usage);
    }

    #[tokio::test]
    async fn two_flags_aimed_at_one_file_are_rejected_before_any_work() {
        let (ctx, args) = parse(&[
            "check", "src:", "dst:", "--differ", "out.txt", "--match", "out.txt",
        ]);
        let error = run(&ctx, &args).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.hint().is_some());
    }

    #[tokio::test]
    async fn a_missing_output_directory_is_reported_up_front() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope").join("out.txt");
        let path = missing.to_string_lossy().into_owned();
        let (ctx, args) = parse(&["check", "src:", "dst:", "--combined", &path]);
        assert_eq!(
            run(&ctx, &args).await.unwrap_err().code(),
            ExitCode::DirNotFound
        );
    }

    #[tokio::test]
    async fn a_dry_run_creates_no_verdict_files() {
        // The command's only mutation is writing these files, so --dry-run must
        // leave the directory exactly as it found it.
        let dir = tempfile::tempdir().unwrap();
        let combined = dir.path().join("all.txt");
        let path = combined.to_string_lossy().into_owned();
        let (ctx, args) = parse(&["check", "src:", "dst:", "--combined", &path, "--dry-run"]);
        assert!(ctx.is_dry_run());
        assert!(run(&ctx, &args).await.is_err());
        assert!(!combined.exists(), "--dry-run must write nothing");
    }

    #[tokio::test]
    async fn a_failed_run_leaves_no_empty_files_behind() {
        // Creating the files up front and then failing would leave artefacts a
        // later script could mistake for "no differences found".
        let dir = tempfile::tempdir().unwrap();
        let differ = dir.path().join("differ.txt");
        let path = differ.to_string_lossy().into_owned();
        let (ctx, args) = parse(&["check", "src:", "dst:", "--differ", &path]);
        assert!(run(&ctx, &args).await.is_err());
        assert!(!differ.exists());
    }

    #[tokio::test]
    async fn an_unresolvable_side_is_an_error_rather_than_an_empty_comparison() {
        // `PLAN.md` §6: never report an outcome that did not happen. A tree that
        // was never read must not come back as "everything is missing", which
        // would invite someone to "repair" it by copying a whole dataset over a
        // destination that was fine.
        let (ctx, args) = parse(&["check", "nosuchremote:photos", "./photos"]);
        let error = run(&ctx, &args).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.message().contains("nosuchremote"));
    }

    #[tokio::test]
    async fn the_comparison_follows_the_global_flags() {
        let (ctx, _) = parse(&["check", "src:", "dst:", "--checksum"]);
        assert_eq!(
            Comparison::from_globals(&ctx.globals).unwrap(),
            Comparison::Checksum
        );
        let (ctx, _) = parse(&["check", "src:", "dst:", "--size-only"]);
        assert_eq!(
            Comparison::from_globals(&ctx.globals).unwrap(),
            Comparison::SizeOnly
        );
    }

    /// A directory tree on disk, which both `check` arguments can address.
    fn tree(files: &[(&str, &[u8])]) -> tempfile::TempDir {
        let root = tempfile::TempDir::new().expect("a temporary directory");
        for (relative, bytes) in files {
            let path = root.path().join(relative);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("the parent directory is created");
            }
            std::fs::write(&path, bytes).expect("the fixture file is written");
        }
        root
    }

    /// Run `check` over two real trees, with `flags` appended.
    async fn check(
        left: &tempfile::TempDir,
        right: &tempfile::TempDir,
        flags: &[&str],
    ) -> Result<()> {
        let left = left.path().to_string_lossy().into_owned();
        let right = right.path().to_string_lossy().into_owned();
        let mut argv = vec!["check", left.as_str(), right.as_str()];
        argv.extend_from_slice(flags);
        let (ctx, args) = parse(&argv);
        run(&ctx, &args).await
    }

    #[tokio::test]
    async fn two_identical_trees_agree_and_the_run_exits_zero() {
        let left = tree(&[("a.txt", b"1"), ("sub/b.txt", b"22")]);
        let right = tree(&[("a.txt", b"1"), ("sub/b.txt", b"22")]);
        check(&left, &right, &["--size-only"])
            .await
            .expect("identical trees must not be reported as differing");
    }

    #[tokio::test]
    async fn a_difference_is_a_partial_failure_and_not_an_integrity_failure() {
        // Two trees disagreeing is not damage: nothing failed to authenticate,
        // and conflating the two would send someone hunting for corruption.
        let left = tree(&[("a.txt", b"1")]);
        let right = tree(&[("a.txt", b"different")]);
        let error = check(&left, &right, &["--size-only"])
            .await
            .expect_err("a size difference must be reported");
        assert_eq!(error.code(), ExitCode::PartialFailure);
        assert_ne!(error.code(), ExitCode::IntegrityFailure);
    }

    #[tokio::test]
    async fn presence_is_named_from_the_side_that_lacks_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let missing_on_dst = dir.path().join("dst.txt");
        let missing_on_src = dir.path().join("src.txt");

        let left = tree(&[("only-at-source.txt", b"1"), ("both.txt", b"x")]);
        let right = tree(&[("only-at-dest.txt", b"1"), ("both.txt", b"x")]);
        let error = check(
            &left,
            &right,
            &[
                "--size-only",
                "--missing-on-dst",
                &missing_on_dst.to_string_lossy(),
                "--missing-on-src",
                &missing_on_src.to_string_lossy(),
            ],
        )
        .await
        .expect_err("two paths differ");
        assert_eq!(error.code(), ExitCode::PartialFailure);

        // A per-verdict file carries bare paths, so it feeds straight into
        // `dctl copy --files-from`.
        assert_eq!(
            std::fs::read_to_string(&missing_on_dst).unwrap(),
            "only-at-source.txt\n"
        );
        assert_eq!(
            std::fs::read_to_string(&missing_on_src).unwrap(),
            "only-at-dest.txt\n"
        );
    }

    #[tokio::test]
    async fn one_way_ignores_extra_files_at_the_destination() {
        // The state a `copy` leaves behind by design, so it is not a finding and
        // must not change the exit code or reach a verdict file.
        let dir = tempfile::tempdir().unwrap();
        let missing_on_src = dir.path().join("src.txt");

        let left = tree(&[("a.txt", b"1")]);
        let right = tree(&[("a.txt", b"1"), ("extra.txt", b"2")]);

        check(
            &left,
            &right,
            &[
                "--size-only",
                "--one-way",
                "--missing-on-src",
                &missing_on_src.to_string_lossy(),
            ],
        )
        .await
        .expect("an extra file at the destination is not a one-way finding");
        assert_eq!(std::fs::read_to_string(&missing_on_src).unwrap(), "");

        // Without --one-way the same pair of trees does differ.
        assert!(check(&left, &right, &["--size-only"]).await.is_err());
    }

    #[tokio::test]
    async fn only_checksum_notices_two_files_of_the_same_size() {
        // The whole reason `--checksum` exists, and the reason the hash is
        // computed rather than refused: neither of these plain trees records
        // one, so a comparison that would not read the bytes could never tell
        // these two files apart.
        let left = tree(&[("a.txt", b"aaaa")]);
        let right = tree(&[("a.txt", b"bbbb")]);

        check(&left, &right, &["--size-only"])
            .await
            .expect("equal sizes match under --size-only");

        let error = check(&left, &right, &["--checksum"])
            .await
            .expect_err("different contents must differ under --checksum");
        assert_eq!(error.code(), ExitCode::PartialFailure);
    }

    #[tokio::test]
    async fn filters_apply_to_both_sides_alike() {
        // Filtering only one side would manufacture a finding: every excluded
        // file would be reported as missing from the side that filtered it.
        let left = tree(&[("keep.jpg", b"1"), ("drop.txt", b"22")]);
        let right = tree(&[("keep.jpg", b"1")]);
        check(&left, &right, &["--size-only", "--include", "*.jpg"])
            .await
            .expect("the excluded file must not become a difference");
    }

    #[tokio::test]
    async fn a_dry_run_compares_but_writes_no_verdict_files() {
        let dir = tempfile::tempdir().unwrap();
        let combined = dir.path().join("all.txt");
        let left = tree(&[("a.txt", b"1")]);
        let right = tree(&[("a.txt", b"1")]);

        check(
            &left,
            &right,
            &[
                "--size-only",
                "--dry-run",
                "--combined",
                &combined.to_string_lossy(),
            ],
        )
        .await
        .expect("the comparison itself changes nothing and still runs");
        assert!(!combined.exists(), "--dry-run must write nothing");
    }

    #[tokio::test]
    async fn every_output_format_is_accepted() {
        let left = tree(&[("a.txt", b"1")]);
        let right = tree(&[("a.txt", b"1")]);
        for format in [&["--json"][..], &["--format", "json-lines"][..], &[][..]] {
            let mut flags = vec!["--size-only"];
            flags.extend_from_slice(format);
            check(&left, &right, &flags)
                .await
                .expect("the format must not change the outcome");
        }
    }

    #[tokio::test]
    async fn a_ghost_index_row_is_reported_missing_never_matched() {
        // BENCHMARKS §7.2 / §12 defect 2, High: delete one stored object
        // behind the tool's back and `check` said "all match" and exited 0 —
        // the vault side listed the index row, whose size, mtime and recorded
        // hash all still described the lost bytes, so every mode matched it,
        // --checksum included. The confirmation probe makes the same run
        // report the loss. Everything below is real: a sealed vault, a config
        // naming the init pair, the ordinary unlock ladder.
        use std::sync::Arc;

        let dir = tempfile::TempDir::new().unwrap();
        let store = dir.path().join("store");
        std::fs::create_dir_all(&store).unwrap();
        let index = dir.path().join("index.redb");
        let tree = dir.path().join("tree");
        std::fs::create_dir_all(&tree).unwrap();

        {
            let backend: Arc<dyn dctl_store::Backend> = Arc::new(dctl_store::LocalFs::new(&store));
            let vault = dctl_core::Vault::init(backend, &index, "correct horse battery")
                .await
                .unwrap()
                .vault;
            for (name, bytes) in [
                ("a.txt", &b"alpha"[..]),
                ("b.txt", &b"bravo"[..]),
                ("c.txt", &b"charlie"[..]),
            ] {
                std::fs::write(tree.join(name), bytes).unwrap();
                let modified = std::fs::metadata(tree.join(name))
                    .unwrap()
                    .modified()
                    .unwrap()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;
                vault
                    .put_file(name, bytes, dctl_core::Modified::At(modified))
                    .await
                    .unwrap();
            }
        }

        let config = dir.path().join("config.toml");
        std::fs::write(
            &config,
            format!(
                "[remotes.archive-store]\ntype = \"local\"\npath = {:?}\nrequire_vault = true\n\n\
                 [remotes.archive]\ntype = \"vault\"\nbase = \"archive-store\"\n",
                store.to_string_lossy()
            ),
        )
        .unwrap();

        let tree_arg = tree.to_string_lossy().into_owned();
        let config_arg = config.to_string_lossy().into_owned();
        let index_arg = index.to_string_lossy().into_owned();
        let run_check = |extra: &'static [&'static str]| {
            let mut argv = vec![
                "check",
                &tree_arg,
                "archive:",
                "--config",
                &config_arg,
                "--index",
                &index_arg,
                "--password",
                "correct horse battery",
            ];
            argv.extend_from_slice(extra);
            let (ctx, args) = parse(&argv);
            async move { run(&ctx, &args).await }
        };

        // The control: before any damage, a clean pair is clean — proving the
        // probe manufactures no findings.
        run_check(&[])
            .await
            .expect("an undamaged pair compares clean");

        // The damage, exactly as benchmarked.
        let mut objects: Vec<_> = std::fs::read_dir(store.join("o"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        objects.sort();
        std::fs::remove_file(&objects[0]).unwrap();

        // The default comparison must find the loss…
        let error = run_check(&[])
            .await
            .expect_err("a lost object is never a match");
        assert_eq!(error.code(), ExitCode::PartialFailure);

        // …and so must --checksum, whose vault-side digest is the same index
        // row that outlived the object.
        let error = run_check(&["--checksum"])
            .await
            .expect_err("a recorded hash must not vouch for a lost object");
        assert_eq!(error.code(), ExitCode::PartialFailure);
    }
}
