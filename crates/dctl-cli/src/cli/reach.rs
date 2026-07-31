//! Every global flag, and what it reaches.
//!
//! ## The defect this module exists to make impossible
//!
//! Eleven global flags parsed, appeared in `dctl --help`, printed nothing and
//! changed nothing. `--bwlimit 1k` moved 10 MiB at 32.9 MiB/s — roughly 34 000×
//! the requested rate. `--max-transfer 1M` moved the whole 10 MiB and exited
//! **0**, so exit 8 was unreachable. `--timeout` published a five-minute idle
//! timeout no backend applies. Two more — `--transfers` and `--retries` — had
//! been *reported working* by a previous audit, on the strength of a `--help`
//! entry and a plausible-looking constant; nothing read either field.
//!
//! A flag in this state is worse than one that does not exist. An unknown flag
//! is a usage error the operator sees immediately. An accepted one that does
//! nothing is a belief: they think they capped their egress bill, and the
//! invoice is the first thing that disagrees.
//!
//! ## Two outcomes, never a third
//!
//! Every flag below is either [`Reach::Honoured`] — some command reads the field
//! and behaves differently — or [`Reach::Refused`], which fails the run before
//! anything is read or written and says which layer owes the capability.
//! `--key-file` is the precedent ([`crate::session::factor`]) and this follows
//! it exactly, including the chokepoint in `main.rs` that no command can bypass.
//!
//! Refusing is a perfectly good answer and several flags get it. A silent no-op
//! never is.
//!
//! ## Why the table is exhaustive, and what enforces that
//!
//! [`FLAGS`] is checked against clap's own argument list, so a flag added to
//! [`GlobalArgs`] without a row here fails the build's test suite with an
//! instruction rather than shipping. That is the difference between fixing
//! eleven flags and fixing the reason there were eleven.
//!
//! The two halves are enforced differently, because they can be:
//!
//! * A **refused** flag is proved: the guard builds a command line that sets it
//!   and asserts the refusal actually fires and names the flag. A row claiming a
//!   refusal that does not happen fails.
//! * An **honoured** flag is *scanned*: the guard reads this crate's own source
//!   and requires the struct field to be read somewhere outside
//!   [`super::globals`]. That is a weaker claim than "it works" — a test per
//!   flag is what proves that, and those live beside each implementation — but
//!   it is exactly the check that was missing. Every one of the eleven would
//!   have failed it, including the two an audit had cleared by eye.
//!
//! A scan can be fooled by a field that is read into a variable nobody uses.
//! It cannot be fooled by the failure that actually happened eleven times,
//! which is a field nothing mentions at all.

use crate::constants::{
    CHECKERS_PERFORMED, CHECKERS_UNSUPPORTED_REASON, DUMP_UNSUPPORTED_REASON,
    KEY_FILE_UNSUPPORTED_REASON, LOW_LEVEL_RETRIES_UNSUPPORTED_REASON, TRANSFERS_PERFORMED,
    TRANSFERS_UNSUPPORTED_REASON, VERIFY_SAMPLES_UNSUPPORTED_REASON,
};

use super::GlobalArgs;

/// What a global flag actually reaches in this build.
#[derive(Clone, Copy)]
pub enum Reach {
    /// A command reads the field and behaves differently because of it.
    ///
    /// The claim the guard checks is deliberately narrow — that *something*
    /// outside [`super::globals`] reads it — because a stronger claim cannot be
    /// made mechanically and a weaker one is what let eleven flags through.
    Honoured,

    /// This build cannot do what the flag asks, and says so before it starts.
    Refused {
        /// Why, naming the layer that owes the capability. Never "not
        /// implemented" on its own: the operator's next question is what the
        /// tool does instead, and the sentence answers it.
        reason: &'static str,

        /// Whether this run asked for something [`Reach::Refused::reason`]
        /// forbids.
        ///
        /// A predicate rather than a bare "was it present", because two of these
        /// flags have one honest value. `--transfers 1` is a true statement
        /// about this executor, so it is accepted; `--transfers 8` is not, so it
        /// is refused. Refusing a request for the behaviour you already have
        /// teaches nobody anything.
        asked: fn(&GlobalArgs) -> bool,
    },
}

/// One global flag's row.
pub struct Flag {
    /// The spelling the user types, with its leading dashes.
    pub long: &'static str,

    /// The [`GlobalArgs`] field, for the source scan in
    /// [`tests::every_honoured_flag_is_read_by_something`].
    ///
    /// Held separately from [`Flag::long`] rather than derived by replacing `-`
    /// with `_`, because the derivation would be right for every flag today and
    /// silently wrong for the first one clap renames.
    ///
    /// Read only by that guard, hence the allow: it is the *input* to the check
    /// rather than something the binary consults, and deriving it at test time
    /// from the flag name is precisely the shortcut the previous sentence
    /// rejects.
    #[allow(dead_code)]
    pub field: &'static str,

    /// What it reaches.
    pub reach: Reach,
}

impl Flag {
    /// A flag some command reads.
    const fn honoured(long: &'static str, field: &'static str) -> Self {
        Self {
            long,
            field,
            reach: Reach::Honoured,
        }
    }

    /// A flag this build refuses, with the reason and the predicate that fires.
    const fn refused(
        long: &'static str,
        field: &'static str,
        reason: &'static str,
        asked: fn(&GlobalArgs) -> bool,
    ) -> Self {
        Self {
            long,
            field,
            reach: Reach::Refused { reason, asked },
        }
    }
}

/// Every global flag, in the order [`GlobalArgs`] declares them.
///
/// Kept in declaration order so that a diff adding a flag and a diff adding its
/// row land next to each other, which is the smallest thing that makes the pair
/// obvious to a reviewer.
pub const FLAGS: &[Flag] = &[
    // ── Configuration ────────────────────────────────────────────────────
    Flag::honoured("--config", "config"),
    Flag::honoured("--remote", "remote"),
    Flag::honoured("--index", "index"),
    // ── Authentication ───────────────────────────────────────────────────
    Flag::honoured("--password", "password"),
    Flag::honoured("--password-command", "password_command"),
    Flag::honoured("--password-file", "password_file"),
    Flag::honoured("--recovery-phrase", "recovery_phrase"),
    Flag::honoured("--recovery-phrase-file", "recovery_phrase_file"),
    // The precedent. `session::factor` owns the message and its tests — the
    // second factor is a security property, not a tuning knob — but the row
    // belongs here so the table is exhaustive and so the guard proves this
    // refusal through the same chokepoint as every other one.
    Flag::refused(
        "--key-file",
        "key_file",
        KEY_FILE_UNSUPPORTED_REASON,
        |globals| globals.key_file.is_some(),
    ),
    Flag::honoured("--no-ask-password", "no_ask_password"),
    // ── Durability ───────────────────────────────────────────────────────
    Flag::honoured("--verify", "verify"),
    Flag::refused(
        "--verify-samples",
        "verify_samples",
        VERIFY_SAMPLES_UNSUPPORTED_REASON,
        |globals| globals.verify_samples.is_some(),
    ),
    Flag::honoured("--checksum", "checksum"),
    Flag::honoured("--size-only", "size_only"),
    Flag::honoured("--modify-window", "modify_window"),
    Flag::honoured("--immutable", "immutable"),
    // ── Transfer ─────────────────────────────────────────────────────────
    Flag::refused(
        "--transfers",
        "transfers",
        TRANSFERS_UNSUPPORTED_REASON,
        |globals| globals.transfers != TRANSFERS_PERFORMED,
    ),
    Flag::refused(
        "--checkers",
        "checkers",
        CHECKERS_UNSUPPORTED_REASON,
        |globals| globals.checkers != CHECKERS_PERFORMED,
    ),
    Flag::honoured("--bwlimit", "bwlimit"),
    Flag::honoured("--retries", "retries"),
    Flag::refused(
        "--low-level-retries",
        "low_level_retries",
        LOW_LEVEL_RETRIES_UNSUPPORTED_REASON,
        |globals| globals.low_level_retries.is_some(),
    ),
    Flag::honoured("--timeout", "timeout"),
    Flag::honoured("--contimeout", "contimeout"),
    Flag::honoured("--max-transfer", "max_transfer"),
    Flag::honoured("--max-duration", "max_duration"),
    // ── Filtering ────────────────────────────────────────────────────────
    Flag::honoured("--include", "include"),
    Flag::honoured("--exclude", "exclude"),
    Flag::honoured("--include-from", "include_from"),
    Flag::honoured("--exclude-from", "exclude_from"),
    Flag::honoured("--filter", "filter"),
    Flag::honoured("--filter-from", "filter_from"),
    Flag::honoured("--files-from", "files_from"),
    Flag::honoured("--min-size", "min_size"),
    Flag::honoured("--max-size", "max_size"),
    Flag::honoured("--min-age", "min_age"),
    Flag::honoured("--max-age", "max_age"),
    Flag::honoured("--max-depth", "max_depth"),
    // ── Traversal ────────────────────────────────────────────────────────
    Flag::honoured("--links", "links"),
    // ── Output ───────────────────────────────────────────────────────────
    Flag::honoured("--format", "format"),
    Flag::honoured("--json", "json"),
    Flag::honoured("--units", "units"),
    Flag::honoured("--color", "color"),
    Flag::honoured("--ascii", "ascii"),
    Flag::honoured("--progress", "progress"),
    Flag::honoured("--stats", "stats"),
    Flag::honoured("--stats-one-line", "stats_one_line"),
    Flag::honoured("--quiet", "quiet"),
    // ── Logging & debugging ──────────────────────────────────────────────
    Flag::honoured("--verbose", "verbose"),
    Flag::honoured("--log-level", "log_level"),
    Flag::honoured("--log-format", "log_format"),
    Flag::honoured("--log-file", "log_file"),
    Flag::refused("--dump", "dump", DUMP_UNSUPPORTED_REASON, |globals| {
        !globals.dump.is_empty()
    }),
    Flag::honoured("--log-source", "log_source"),
    // ── Safety ───────────────────────────────────────────────────────────
    Flag::honoured("--dry-run", "dry_run"),
    Flag::honoured("--interactive", "interactive"),
    Flag::honoured("--force", "force"),
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Cli;
    use crate::exit::ExitCode;
    use clap::{CommandFactory as _, Parser};
    use std::collections::BTreeSet;
    use std::path::Path;

    /// Fields read through a method on [`GlobalArgs`] rather than at a call
    /// site, so the source scan below would not find them by name.
    ///
    /// Both are genuinely honoured — `--log-level` and `--json` decide the
    /// values `main.rs` and `Ctx::new` install — and both are read inside
    /// [`super::super::globals`] by an accessor the scan deliberately skips.
    /// Naming the accessor is what keeps this from becoming a way to wave a flag
    /// past the guard: the entry has to say *where* the field is consumed, and a
    /// reviewer can check that one line.
    const READ_THROUGH_AN_ACCESSOR: &[(&str, &str)] = &[
        ("log_level", "effective_log_level()"),
        ("json", "effective_format()"),
    ];

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn globals(args: &[&str]) -> GlobalArgs {
        Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied())).globals
    }

    /// Every long flag clap knows about on the top-level command.
    ///
    /// Taken from the parser rather than from a list, so this is the same set
    /// `dctl --help` prints. `help` and `version` are clap built-ins rather than
    /// members of the global block and are excluded by name.
    fn declared_flags() -> BTreeSet<String> {
        Cli::command()
            .get_arguments()
            .filter_map(|arg| arg.get_long())
            .filter(|long| *long != "help" && *long != "version")
            .map(|long| format!("--{long}"))
            .collect()
    }

    fn tabled_flags() -> BTreeSet<String> {
        FLAGS.iter().map(|flag| flag.long.to_string()).collect()
    }

    #[test]
    fn every_declared_flag_is_classified_and_every_row_is_a_real_flag() {
        let declared = declared_flags();
        let tabled = tabled_flags();

        let unclassified: Vec<_> = declared.difference(&tabled).collect();
        assert!(
            unclassified.is_empty(),
            "these flags parse but this table does not say what they reach: {unclassified:?}\n\
             Add a row to cli::reach::FLAGS. A new global flag must either be read \
             by a command (Reach::Honoured) or refused before the run starts \
             (Reach::Refused) — a flag that parses and does neither is the defect \
             this table exists to prevent."
        );

        let phantom: Vec<_> = tabled.difference(&declared).collect();
        assert!(
            phantom.is_empty(),
            "these rows name flags the parser does not have: {phantom:?}"
        );
    }

    #[test]
    fn the_table_is_in_declaration_order() {
        // Not cosmetic: the pair "add a flag, add its row" is only obvious to a
        // reviewer when the two hunks are adjacent. Compared against clap's own
        // ordering, which follows the struct.
        let declared: Vec<String> = Cli::command()
            .get_arguments()
            .filter_map(|arg| arg.get_long())
            .filter(|long| *long != "help" && *long != "version")
            .map(|long| format!("--{long}"))
            .collect();
        let tabled: Vec<String> = FLAGS.iter().map(|flag| flag.long.to_string()).collect();
        assert_eq!(declared, tabled);
    }

    #[test]
    fn every_refused_flag_actually_refuses() {
        // The strong half of the guard. A row may not merely *claim* a refusal:
        // the run is put through the same chokepoint `main.rs` uses, and the
        // error has to arrive, name the flag, and carry the reason.
        for flag in FLAGS {
            let Reach::Refused { reason, asked } = flag.reach else {
                continue;
            };

            let value = sample_value(flag.long);
            let mut argv = vec![flag.long];
            if let Some(value) = value {
                argv.push(value);
            }
            let parsed = globals(&argv);
            assert!(
                asked(&parsed),
                "{} {:?} must trip its own predicate, or the refusal is unreachable",
                flag.long,
                value
            );

            let error = super::super::refuse::refuse_if_present(&parsed, "dctl copy", "Nothing.")
                .expect_err(flag.long);
            assert_eq!(error.code(), ExitCode::FatalError, "{}", flag.long);
            assert!(
                error.message().contains(flag.long),
                "the refusal must name the flag the user typed: {}",
                error.message()
            );
            let hint = error.hint().unwrap_or_default();
            assert!(
                hint.contains(reason),
                "and carry the reason that says what the tool does instead: {hint}"
            );
        }
    }

    #[test]
    fn a_run_that_asks_for_nothing_unsupported_is_untouched() {
        super::super::refuse::refuse_if_present(&globals(&[]), "dctl copy", "Nothing.").unwrap();
        // Including the two values that *are* honest statements about this
        // build. Refusing a request for the behaviour you already have would be
        // a worse tool, not a more honest one.
        super::super::refuse::refuse_if_present(
            &globals(&["--transfers", "1", "--checkers", "1"]),
            "dctl copy",
            "Nothing.",
        )
        .unwrap();
    }

    /// Every `.rs` file in this crate except the two that declare the flags.
    ///
    /// The declaration sites are skipped because `pub bwlimit: Option<ByteLimit>`
    /// is not somebody *reading* the field, and counting it would make every
    /// flag pass forever — which is the exact shape of the defect this file
    /// exists to prevent, reproduced inside its own guard.
    fn crate_corpus() -> String {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let sources = crate::cli::mentions::rust_files(&root);
        assert!(
            sources.len() > 50,
            "the scan must actually reach the crate: found {} files",
            sources.len()
        );

        let mut corpus = String::new();
        for file in &sources {
            if file.ends_with("globals.rs") || file.ends_with("reach.rs") {
                continue;
            }
            if let Ok(text) = std::fs::read_to_string(file) {
                corpus.push_str(&text);
            }
        }
        corpus
    }

    /// Whether anything outside the declaration reads `GlobalArgs::<field>`.
    ///
    /// The leading dot is the whole predicate, and it is not incidental: every
    /// one of these field names also appears as an ordinary English word in this
    /// crate's prose (`timeout`, `progress`, `force`, `index`). Matching the
    /// bare word would pass every flag ever written, silently, forever — so
    /// [`tests::the_scan_tells_a_field_that_is_read_from_a_word_that_appears`]
    /// pins the distinction rather than trusting it.
    fn reads_field(corpus: &str, field: &str) -> bool {
        corpus.contains(&format!(".{field}"))
    }

    #[test]
    fn every_honoured_flag_is_read_by_something() {
        // The check nobody had. Every one of the eleven inert flags would fail
        // here, including `--transfers` and `--retries`, which a previous
        // adversarial pass cleared by reading `--help`.
        let corpus = crate_corpus();

        for flag in FLAGS {
            if !matches!(flag.reach, Reach::Honoured) {
                continue;
            }
            if let Some((_, accessor)) = READ_THROUGH_AN_ACCESSOR
                .iter()
                .find(|(field, _)| *field == flag.field)
            {
                assert!(
                    corpus.contains(accessor),
                    "{} claims to be read through {accessor}, which nothing calls",
                    flag.long
                );
                continue;
            }
            assert!(
                reads_field(&corpus, flag.field),
                "{} is declared honoured, but nothing outside globals.rs reads \
                 GlobalArgs::{}. Either wire it to an implementation, or move it \
                 to Reach::Refused with the reason it cannot be.",
                flag.long,
                flag.field
            );
        }
    }

    #[test]
    fn the_scan_tells_a_field_that_is_read_from_a_word_that_appears() {
        // The guard's own guard, and it has teeth because it is written against
        // the *same predicate* the guard uses rather than against a copy of it.
        // Dropping the leading dot — the one plausible "simplification" here —
        // makes every assertion below fail, which is the point: a scan loosened
        // that far would clear every inert flag in silence.
        let corpus = crate_corpus();

        assert!(
            reads_field(&corpus, "dry_run"),
            "a genuinely honoured field must be found"
        );
        assert!(
            !reads_field(&corpus, "no_such_global_flag_field"),
            "and an absent one must not"
        );

        // The fixture that makes the loosening detectable. It has to be a word
        // this crate writes often *and* a field nothing reads, or it proves
        // nothing about the predicate.
        //
        // It used to be `timeout`, which stopped qualifying the moment
        // `--timeout` was honoured — a fixture going stale is the good failure
        // mode here, because it fails loudly at the assertion below rather than
        // quietly weakening the guard. `dump` replaces it: the word appears in
        // eighteen files of this crate, and `.dump` appears in none of them
        // outside the two the scan already skips.
        assert!(
            corpus.contains("dump"),
            "the fixture must appear in the corpus as a word"
        );
        assert!(
            !reads_field(&corpus, "dump"),
            "…but appearing as a word is not being read, and a scan that \
             conflated the two would pass every flag on this list"
        );
    }

    /// A value for a flag that takes one, or `None` for a switch.
    ///
    /// Written as a match on the flag rather than read off clap's metadata
    /// because two of these need a value the predicate will actually reject:
    /// `--transfers 1` is accepted, so the guard has to ask for `2`.
    fn sample_value(long: &str) -> Option<&'static str> {
        match long {
            "--transfers" | "--checkers" => Some("2"),
            "--verify-samples" | "--low-level-retries" => Some("4"),
            "--dump" => Some("headers"),
            "--key-file" => Some("/dev/null"),
            _ => None,
        }
    }
}
