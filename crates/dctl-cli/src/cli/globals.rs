//! Global flags — available on every subcommand.
//!
//! Grouped by `help_heading` so `dctl --help` reads as a set of related dials
//! rather than one 60-line wall. The groups mirror the structure of `PLAN.md`:
//! durability (§6), observability (§7), scale (§16.2), and safety.
//!
//! Every flag has an environment-variable equivalent so DCTL runs headless on a
//! server with no interactive configuration step (`PLAN.md` §14).

use std::path::PathBuf;

use clap::Args;

use crate::constants;
use crate::limits::ByteLimit;
use crate::logging::{LogFormat, LogLevel};
use crate::output::{ColorChoice, Format, Units};

/// Strength of the post-transfer verification (`PLAN.md` §6 step 5).
///
/// The cost/assurance dial the plan requires to be explicit: full read-back on a
/// 50 GB video doubles egress, so the default is the provider-checksum
/// comparison — still strong, because a mismatch hard-aborts and commits
/// nothing — and the deeper modes are opt-in.
///
/// Derives serde as well as [`clap::ValueEnum`] because `PLAN.md` §14 makes the
/// verification strength a **per-remote** setting in `config.toml` as well as a
/// flag: the trade-off belongs to the destination (a read-back is free against a
/// local disk and doubles egress against a bucket). Both spellings are lower
/// case so `--verify strict` and `verify = "strict"` are the same word, and a
/// test in `crate::config::model` holds the two renames together.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    clap::ValueEnum,
    serde::Serialize,
    serde::Deserialize,
)]
#[value(rename_all = "lower")]
#[serde(rename_all = "lowercase")]
pub enum VerifyMode {
    /// Compare the provider's stored checksum against ours. No extra egress.
    #[default]
    Checksum,
    /// Additionally Range-read and decrypt a sample of chunks.
    Sample,
    /// Full read-back and decrypt; confirm the whole-file BLAKE3.
    Strict,
}

/// What to dump for protocol-level debugging.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum DumpTarget {
    /// HTTP request and response headers. Authorization is always redacted.
    Headers,
    /// Request and response bodies. Never includes plaintext file content.
    Bodies,
    /// One line per HTTP request: method, URL, status, duration.
    Requests,
    /// Every retry decision, with the classification that drove it.
    Retries,
    /// Filter evaluation: which rule included or excluded each path.
    Filters,
    /// The resolved configuration, with all secrets redacted.
    Config,
}

/// Flags shared by every subcommand.
#[derive(Args, Clone, Debug)]
pub struct GlobalArgs {
    // ── Configuration ────────────────────────────────────────────────────
    /// Path to the configuration file.
    #[arg(
        long,
        global = true,
        value_name = "PATH",
        env = "DCTL_CONFIG",
        help_heading = "Configuration"
    )]
    pub config: Option<PathBuf>,

    /// Remote spec to operate on when a command takes no explicit path.
    #[arg(
        long,
        global = true,
        value_name = "SPEC",
        env = "DCTL_REMOTE",
        help_heading = "Configuration"
    )]
    pub remote: Option<String>,

    /// Path to the local encrypted index database.
    #[arg(
        long,
        global = true,
        value_name = "PATH",
        env = "DCTL_INDEX",
        help_heading = "Configuration"
    )]
    pub index: Option<PathBuf>,

    // ── Authentication ───────────────────────────────────────────────────
    /// Vault password. Prefer --password-command or the environment: an
    /// argument is visible to every other process on the machine.
    #[arg(
        long,
        global = true,
        value_name = "PASSWORD",
        env = "DCTL_PASSWORD",
        hide_env_values = true,
        help_heading = "Authentication"
    )]
    pub password: Option<String>,

    /// Command whose stdout is the vault password.
    #[arg(
        long,
        global = true,
        value_name = "COMMAND",
        env = "DCTL_PASSWORD_COMMAND",
        help_heading = "Authentication"
    )]
    pub password_command: Option<String>,

    /// File whose first line is the vault password.
    #[arg(
        long,
        global = true,
        value_name = "PATH",
        help_heading = "Authentication"
    )]
    pub password_file: Option<PathBuf>,

    /// Unlock with the BIP-39 recovery phrase issued at 'dctl init' instead of
    /// the password. Prefer --recovery-phrase-file or the environment.
    ///
    /// Global rather than a flag on one command, and that is the whole point of
    /// the recovery story: a phrase has to be able to run `ls`, `cat`, `copy`
    /// and `restore`, because "prove the phrase works" is not what somebody who
    /// has lost their password needs — getting their data back is. A
    /// `vault recover` verb that only reported success would be a demonstration,
    /// not a recovery.
    ///
    /// Carries the same warning as `--password`: an argument is visible to every
    /// other process on the machine, and this one cannot be rotated by changing
    /// the password.
    #[arg(
        long,
        global = true,
        value_name = "PHRASE",
        env = "DCTL_RECOVERY_PHRASE",
        hide_env_values = true,
        help_heading = "Authentication"
    )]
    pub recovery_phrase: Option<String>,

    /// File holding the vault's recovery phrase. Line breaks are ignored.
    ///
    /// The transcription case, and why this is not `--password-file`'s
    /// first-line rule: 24 words come off a sheet of paper, and somebody typing
    /// them into a file will break the lines where the paper breaks them.
    /// Reading only the first line would reject a correct phrase, which is the
    /// cruellest possible failure at the moment it is used — so the whole file
    /// is read and BIP-39's own whitespace rules apply.
    #[arg(
        long,
        global = true,
        value_name = "PATH",
        help_heading = "Authentication"
    )]
    pub recovery_phrase_file: Option<PathBuf>,

    /// Second-factor keyfile (PLAN.md §8): 'know' plus 'have'. REFUSED in this
    /// build — the engine derives the key from the password alone, so a run
    /// that passes this fails rather than silently using one factor.
    #[arg(
        long,
        global = true,
        value_name = "PATH",
        help_heading = "Authentication"
    )]
    pub key_file: Option<PathBuf>,

    /// Never prompt for a password; fail instead. For unattended runs.
    #[arg(long, global = true, help_heading = "Authentication")]
    pub no_ask_password: bool,

    // ── Durability ───────────────────────────────────────────────────────
    /// Verification strength applied after every write.
    #[arg(
        long,
        global = true,
        value_enum,
        default_value_t = VerifyMode::Checksum,
        value_name = "MODE",
        help_heading = "Durability"
    )]
    pub verify: VerifyMode,

    /// Chunks to sample when --verify=sample. REFUSED in this build — sample
    /// mode reads every chunk, so a depth would describe nothing.
    ///
    /// `Option` rather than a defaulted number, and the difference is the whole
    /// point: a default would make `dctl --help` publish a sampling depth this
    /// build has never applied, and would leave no way to tell "the user asked
    /// for eight" from "nobody asked for anything". See [`crate::cli::reach`].
    #[arg(long, global = true, value_name = "N", help_heading = "Durability")]
    pub verify_samples: Option<u32>,

    /// Compare by checksum rather than size and modification time.
    #[arg(long, global = true, help_heading = "Durability")]
    pub checksum: bool,

    /// Compare by size only, ignoring modification time.
    #[arg(
        long,
        global = true,
        conflicts_with = "checksum",
        help_heading = "Durability"
    )]
    pub size_only: bool,

    /// Treat modification times within this many seconds as equal.
    ///
    /// Not validated here, and deliberately: clap can only say "not a number",
    /// and the interesting refusal — a window smaller than the whole second DCTL
    /// records — needs a sentence of explanation that belongs with the rule it
    /// enforces. See [`crate::cli::window`].
    #[arg(
        long,
        global = true,
        default_value_t = constants::DEFAULT_MODIFY_WINDOW_SECS,
        value_name = "SECONDS",
        help_heading = "Durability"
    )]
    pub modify_window: u64,

    /// Refuse to modify or delete anything that already exists.
    #[arg(long, global = true, help_heading = "Durability")]
    pub immutable: bool,

    // ── Transfer ─────────────────────────────────────────────────────────
    /// Files transferred at once. Only 1 is accepted: this build's executor is
    /// sequential, and a larger value is refused rather than ignored.
    ///
    /// The default is the *measurement*, not an aspiration, which is why there
    /// is no `Option` here as there is on the flags below: `1` is a true
    /// statement about what happens, so `--help` may publish it and a run that
    /// asks for it has asked for what it will get.
    #[arg(
        long,
        global = true,
        default_value_t = constants::TRANSFERS_PERFORMED,
        value_name = "N",
        help_heading = "Transfer"
    )]
    pub transfers: usize,

    /// Metadata checks run at once. Only 1 is accepted; see --transfers.
    #[arg(
        long,
        global = true,
        default_value_t = constants::CHECKERS_PERFORMED,
        value_name = "N",
        help_heading = "Transfer"
    )]
    pub checkers: usize,

    /// Bandwidth limit per second, e.g. 10M. 'off' for unlimited. Paced per
    /// file: one large object is not split, so the run's average rate is what
    /// is capped.
    #[arg(long, global = true, value_name = "RATE", help_heading = "Transfer")]
    pub bwlimit: Option<ByteLimit>,

    /// Retries of a whole failed file.
    #[arg(
        long,
        global = true,
        default_value_t = constants::DEFAULT_RETRIES,
        value_name = "N",
        help_heading = "Transfer"
    )]
    pub retries: u32,

    /// Retries of an individual network request. REFUSED in this build — the
    /// request-level retry layer exists for B2 alone.
    #[arg(long, global = true, value_name = "N", help_heading = "Transfer")]
    pub low_level_retries: Option<u32>,

    /// Inactivity timeout on a transfer, in seconds. REFUSED in this build —
    /// no backend applies one.
    #[arg(long, global = true, value_name = "SECONDS", help_heading = "Transfer")]
    pub timeout: Option<u64>,

    /// Connection timeout, in seconds. REFUSED in this build — no backend
    /// applies one.
    #[arg(long, global = true, value_name = "SECONDS", help_heading = "Transfer")]
    pub contimeout: Option<u64>,

    /// Stop after transferring this much, e.g. 100G. Exits 8 at the limit,
    /// without starting a file that would exceed it.
    #[arg(long, global = true, value_name = "SIZE", help_heading = "Transfer")]
    pub max_transfer: Option<ByteLimit>,

    // ── Filtering ────────────────────────────────────────────────────────
    /// Include only paths matching this glob. Repeatable.
    #[arg(
        long,
        global = true,
        value_name = "PATTERN",
        help_heading = "Filtering"
    )]
    pub include: Vec<String>,

    /// Exclude paths matching this glob. Repeatable.
    #[arg(
        long,
        global = true,
        value_name = "PATTERN",
        help_heading = "Filtering"
    )]
    pub exclude: Vec<String>,

    /// Read include/exclude rules from a file. Repeatable.
    #[arg(long, global = true, value_name = "PATH", help_heading = "Filtering")]
    pub filter_from: Vec<PathBuf>,

    /// Transfer only the paths listed in this file.
    #[arg(long, global = true, value_name = "PATH", help_heading = "Filtering")]
    pub files_from: Vec<PathBuf>,

    /// Skip files smaller than this.
    #[arg(long, global = true, value_name = "SIZE", help_heading = "Filtering")]
    pub min_size: Option<String>,

    /// Skip files larger than this.
    #[arg(long, global = true, value_name = "SIZE", help_heading = "Filtering")]
    pub max_size: Option<String>,

    /// Recursion depth limit; -1 for unlimited.
    #[arg(
        long,
        global = true,
        default_value_t = constants::MAX_DEPTH_UNLIMITED,
        value_name = "N",
        help_heading = "Filtering"
    )]
    pub max_depth: i32,

    // ── Output ───────────────────────────────────────────────────────────
    /// Output format for structured results.
    #[arg(
        long,
        global = true,
        value_enum,
        default_value_t = Format::Text,
        value_name = "FORMAT",
        help_heading = "Output"
    )]
    pub format: Format,

    /// Shorthand for --format=json.
    #[arg(
        long,
        global = true,
        conflicts_with = "format",
        help_heading = "Output"
    )]
    pub json: bool,

    /// Byte-size convention: binary (KiB, matches the OS) or decimal (kB,
    /// matches provider billing).
    #[arg(
        long,
        global = true,
        value_enum,
        default_value_t = Units::Binary,
        value_name = "UNITS",
        help_heading = "Output"
    )]
    pub units: Units,

    /// When to colourise output.
    #[arg(
        long,
        global = true,
        value_enum,
        default_value_t = ColorChoice::Auto,
        value_name = "WHEN",
        help_heading = "Output"
    )]
    pub color: ColorChoice,

    /// Use ASCII-only glyphs for bars and spinners.
    #[arg(long, global = true, help_heading = "Output")]
    pub ascii: bool,

    /// Watch this run: a status record every second instead of every --stats
    /// seconds, and progress kept on under --json. Bars need a terminal;
    /// redirected, progress is the periodic record rather than bars.
    ///
    /// Two effects, both observable, because a flag that changes nothing is a
    /// belief rather than a setting. `--stats 0` still wins — it is an
    /// instruction about this exact output — and `--quiet` beats everything.
    /// See [`crate::output::ProgressMode`] and
    /// [`ticker::interval`](crate::output::progress::ticker::interval).
    ///
    /// An earlier wording promised "live progress bars, even when output is
    /// redirected" and the opposite happened: forcing bars off a terminal drew
    /// nothing and stopped the periodic line as well, so `-P` was the only way
    /// to make a redirected run quieter.
    #[arg(short = 'P', long, global = true, help_heading = "Output")]
    pub progress: bool,

    /// Emit a status record every N seconds. 0 disables. -P shortens it.
    #[arg(
        long,
        global = true,
        default_value_t = constants::DEFAULT_STATS_INTERVAL_SECS,
        value_name = "SECONDS",
        help_heading = "Output"
    )]
    pub stats: u64,

    /// Condense periodic statistics onto a single line.
    #[arg(long, global = true, help_heading = "Output")]
    pub stats_one_line: bool,

    /// Suppress all non-error output.
    #[arg(short, long, global = true, help_heading = "Output")]
    pub quiet: bool,

    // ── Logging & debugging ──────────────────────────────────────────────
    /// Increase verbosity. -v for info, -vv for debug, -vvv for trace.
    #[arg(
        short,
        long,
        global = true,
        action = clap::ArgAction::Count,
        help_heading = "Logging & debugging"
    )]
    pub verbose: u8,

    /// Explicit log level, overriding -v.
    #[arg(
        long,
        global = true,
        value_enum,
        value_name = "LEVEL",
        env = "DCTL_LOG_LEVEL",
        help_heading = "Logging & debugging"
    )]
    pub log_level: Option<LogLevel>,

    /// Log record format. JSON is structured for ingestion by a log pipeline.
    #[arg(
        long,
        global = true,
        value_enum,
        default_value_t = LogFormat::Human,
        value_name = "FORMAT",
        env = "DCTL_LOG_FORMAT",
        help_heading = "Logging & debugging"
    )]
    pub log_format: LogFormat,

    /// Append logs to this file in addition to stderr.
    #[arg(
        long,
        global = true,
        value_name = "PATH",
        help_heading = "Logging & debugging"
    )]
    pub log_file: Option<PathBuf>,

    /// Dump protocol detail for debugging. REFUSED in this build — the tracing
    /// layer these select from is not installed, so every target is silence.
    #[arg(
        long,
        global = true,
        value_enum,
        value_name = "TARGET",
        help_heading = "Logging & debugging"
    )]
    pub dump: Vec<DumpTarget>,

    /// Include source file and line in every log record.
    #[arg(long, global = true, help_heading = "Logging & debugging")]
    pub log_source: bool,

    // ── Safety ───────────────────────────────────────────────────────────
    /// Report what would happen without changing anything.
    #[arg(short = 'n', long, global = true, help_heading = "Safety")]
    pub dry_run: bool,

    /// Prompt before each destructive action.
    #[arg(
        short,
        long,
        global = true,
        conflicts_with = "force",
        help_heading = "Safety"
    )]
    pub interactive: bool,

    /// Skip confirmation prompts for destructive actions.
    #[arg(long, global = true, help_heading = "Safety")]
    pub force: bool,
}

impl GlobalArgs {
    /// The effective output format, folding in the `--json` shorthand.
    #[must_use]
    pub const fn effective_format(&self) -> Format {
        if self.json { Format::Json } else { self.format }
    }

    /// The effective log level: an explicit `--log-level` wins, otherwise the
    /// `-v` count, otherwise warnings only.
    #[must_use]
    pub fn effective_log_level(&self) -> LogLevel {
        if let Some(level) = self.log_level {
            return level;
        }
        if self.quiet {
            return LogLevel::Error;
        }
        LogLevel::from_verbosity(self.verbose)
    }

    /// Whether a given dump target was requested.
    ///
    /// No caller in this build, because the protocol tracing layer it feeds is
    /// not written and [`crate::cli::reach`] therefore refuses `--dump` outright
    /// rather than accepting it into silence. Kept, rather than deleted and
    /// re-derived later, so that the layer reads the flag through one predicate
    /// instead of each capture site testing `dump.contains(…)` for itself —
    /// which is how `--dump headers` ends up honoured by one call site and
    /// ignored by the next. Its safe renderer is already in place too; see
    /// [`crate::logging::redact::redact_header`].
    #[allow(dead_code)]
    #[must_use]
    pub fn dumping(&self, target: DumpTarget) -> bool {
        self.dump.contains(&target)
    }

    /// Whether this run was told to unlock with the recovery phrase.
    ///
    /// Answers "was a phrase *offered*", not "is one usable": a
    /// `--recovery-phrase-file` naming a missing file is still an instruction to
    /// use the recovery path, and must fail as one rather than falling back to
    /// the password. Silently reverting to a password after a phrase source
    /// failed would make a restore drill pass while proving nothing.
    #[must_use]
    pub const fn wants_recovery_phrase(&self) -> bool {
        self.recovery_phrase.is_some() || self.recovery_phrase_file.is_some()
    }

    /// Whether *any* password source was named on this run.
    ///
    /// Answers only "was a source given", never "is it usable" — the file may
    /// not exist, the command may fail, the value may be too short. Reading a
    /// password stays the job of [`crate::session::password`] and
    /// [`crate::commands::init::password`], and this must never grow into a
    /// second implementation of their fallback chains.
    ///
    /// It exists so a command can fail *early* when it can see that a password
    /// it will need later cannot possibly arrive: `dctl vault recover` asks for
    /// the recovery phrase before it asks for a new password, and discovering
    /// only afterwards that `--no-ask-password` forbids the prompt wastes the
    /// operator's most expensive step. Because the predicate is strictly less
    /// permissive than the acquirers — it can only be true when one of the
    /// three fields is set — a disagreement degrades to the old behaviour (the
    /// run continues and fails later), never to a refused valid run.
    #[must_use]
    pub const fn has_password_source(&self) -> bool {
        self.password.is_some() || self.password_command.is_some() || self.password_file.is_some()
    }

    /// Whether any dump target is active — used to decide whether to install
    /// the (non-free) protocol tracing layer at all.
    ///
    /// Uncalled for the same reason as [`GlobalArgs::dumping`]: the layer this
    /// question gates does not exist yet.
    #[allow(dead_code)]
    #[must_use]
    pub fn any_dump(&self) -> bool {
        !self.dump.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// Minimal harness so the global block can be parsed in isolation.
    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn parse(args: &[&str]) -> GlobalArgs {
        Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied())).globals
    }

    #[test]
    fn defaults_match_the_constants_module() {
        let g = parse(&[]);
        assert_eq!(g.transfers, constants::TRANSFERS_PERFORMED);
        assert_eq!(g.checkers, constants::CHECKERS_PERFORMED);
        assert_eq!(g.retries, constants::DEFAULT_RETRIES);
        assert_eq!(g.max_depth, constants::MAX_DEPTH_UNLIMITED);
        assert_eq!(g.verify, VerifyMode::Checksum);
    }

    #[test]
    fn the_flags_this_build_cannot_honour_carry_no_default() {
        // A default is a published claim. `--timeout` printing `[default: 300]`
        // said this build applies a five-minute idle timeout, which it does
        // not, and left no way to tell a user who asked from one who did not.
        let g = parse(&[]);
        assert_eq!(g.verify_samples, None);
        assert_eq!(g.low_level_retries, None);
        assert_eq!(g.timeout, None);
        assert_eq!(g.contimeout, None);
        assert!(g.dump.is_empty());
    }

    #[test]
    fn json_shorthand_overrides_the_format() {
        assert_eq!(parse(&[]).effective_format(), Format::Text);
        assert_eq!(parse(&["--json"]).effective_format(), Format::Json);
        assert_eq!(
            parse(&["--format", "json-lines"]).effective_format(),
            Format::JsonLines
        );
    }

    #[test]
    fn verbosity_maps_onto_log_levels() {
        assert_eq!(parse(&[]).effective_log_level(), LogLevel::Warn);
        assert_eq!(parse(&["-v"]).effective_log_level(), LogLevel::Info);
        assert_eq!(parse(&["-vv"]).effective_log_level(), LogLevel::Debug);
        assert_eq!(parse(&["-vvv"]).effective_log_level(), LogLevel::Trace);
    }

    #[test]
    fn explicit_log_level_beats_verbosity_count() {
        let g = parse(&["-vvv", "--log-level", "error"]);
        assert_eq!(g.effective_log_level(), LogLevel::Error);
    }

    #[test]
    fn quiet_silences_logging_below_errors() {
        assert_eq!(parse(&["--quiet"]).effective_log_level(), LogLevel::Error);
    }

    #[test]
    fn dump_targets_are_repeatable_and_queryable() {
        let g = parse(&["--dump", "headers", "--dump", "retries"]);
        assert!(g.any_dump());
        assert!(g.dumping(DumpTarget::Headers));
        assert!(g.dumping(DumpTarget::Retries));
        assert!(!g.dumping(DumpTarget::Bodies));
        assert!(!parse(&[]).any_dump());
    }

    #[test]
    fn a_recovery_phrase_source_is_recognised_from_either_flag() {
        assert!(!parse(&[]).wants_recovery_phrase());
        assert!(parse(&["--recovery-phrase", "abandon abandon"]).wants_recovery_phrase());
        assert!(parse(&["--recovery-phrase-file", "/tmp/p"]).wants_recovery_phrase());
        // A password alongside it does not cancel the request: the phrase is
        // what was asked for, and a stale DCTL_PASSWORD in the shell must not
        // quietly turn a recovery run back into an ordinary one.
        assert!(
            parse(&["--recovery-phrase", "abandon", "--password", "hunter2"])
                .wants_recovery_phrase()
        );
    }

    #[test]
    fn a_password_source_is_recognised_from_any_of_the_three_flags() {
        assert!(!parse(&[]).has_password_source());
        assert!(parse(&["--password", "hunter2"]).has_password_source());
        assert!(parse(&["--password-command", "true"]).has_password_source());
        assert!(parse(&["--password-file", "/tmp/pw"]).has_password_source());
        // A source that will certainly fail is still a source: this answers
        // "was one named", and whether it works is the acquirer's question.
        assert!(parse(&["--password-file", "/nonexistent"]).has_password_source());
    }

    #[test]
    fn mutually_exclusive_flags_are_rejected() {
        // --checksum and --size-only ask for contradictory comparisons.
        assert!(Harness::try_parse_from(["dctl", "--checksum", "--size-only"]).is_err());
        // --interactive and --force contradict each other.
        assert!(Harness::try_parse_from(["dctl", "--interactive", "--force"]).is_err());
        // --json and --format both set the format.
        assert!(Harness::try_parse_from(["dctl", "--json", "--format", "text"]).is_err());
    }

    #[test]
    fn repeatable_filters_accumulate() {
        let g = parse(&[
            "--include",
            "*.jpg",
            "--include",
            "*.raw",
            "--exclude",
            "tmp/**",
        ]);
        assert_eq!(g.include, vec!["*.jpg", "*.raw"]);
        assert_eq!(g.exclude, vec!["tmp/**"]);
    }

    #[test]
    fn verify_modes_parse_from_their_lowercase_names() {
        assert_eq!(parse(&["--verify", "strict"]).verify, VerifyMode::Strict);
        assert_eq!(parse(&["--verify", "sample"]).verify, VerifyMode::Sample);
        assert!(Harness::try_parse_from(["dctl", "--verify", "nonsense"]).is_err());
    }
}
