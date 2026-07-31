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
use clap::builder::TypedValueParser as _;
use dctl_store::{LINK_POLICY_CHOICES, LinkPolicy};

use crate::constants;
use crate::limits::{ByteLimit, TimeLimit};
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
    /// Verification strength applied after every write. Overrides the
    /// destination remote's `verify` setting. [default: checksum]
    ///
    /// `Option` rather than a defaulted value, and the difference is the whole
    /// reason a per-remote `verify` can exist: with `default_value_t` there is
    /// no way to tell "the operator asked for checksum" from "the operator
    /// asked for nothing", so a remote configured `strict` would be overridden
    /// by a value nobody typed — and the setting would stay exactly as inert as
    /// it was before it was wired. See
    /// [`crate::remote::resolve::verify_policy`], and
    /// [`GlobalArgs::verify_samples`] for the same argument made first.
    ///
    /// The default is stated in the help text rather than published by clap
    /// for the same reason `--timeout`'s was: what a run actually applies is
    /// this, then the remote's, then [`DEFAULT_VERIFY_MODE`], and printing only
    /// the last of the three as `[default: …]` would be a claim about the
    /// destination that this flag cannot make.
    #[arg(
        long,
        global = true,
        value_enum,
        value_name = "MODE",
        help_heading = "Durability"
    )]
    pub verify: Option<VerifyMode>,

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

    /// Bandwidth limit per second, e.g. 10M. 'off' for unlimited.
    ///
    /// Paced INSIDE a file, not merely between files: every window of bytes is
    /// charged as it crosses the wire, so one enormous object is capped for its
    /// whole duration and so is the last file of a run. 8 MiB as a single object
    /// at --bwlimit 1M takes ~8.5 s, which is the arithmetic.
    ///
    /// It said the opposite until the streaming engine landed, and the gap was
    /// the whole width of the flag: the debt was charged once per finished file,
    /// so the same 8 MiB as one object took 47 ms and only a tree of small files
    /// was paced at all. Both uses of the flag — capping a metered link's bill,
    /// and keeping the uplink usable while a backup runs — are served now.
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

    /// Give up on ONE attempt that has moved no data for this long, in seconds.
    /// 0 waits forever.
    ///
    /// An INACTIVITY deadline, not a deadline on the operation: every frame that
    /// moves resets it, so a 4 GiB restore over a slow link runs for hours and
    /// never approaches it. That is rclone's meaning of the same flag.
    ///
    /// It bounds one ATTEMPT, and it does NOT bound the run. A copy makes
    /// several distinct requests, each request is retried on a schedule, and
    /// --retries repeats the file over all of it — so the time a dead network
    /// can cost is a product this flag does not know. Use --max-duration to
    /// bound the run.
    // ── the history, which is not the operator's business ────────────────
    //
    // Everything above is help text: clap renders this doc comment into
    // `dctl --help`, and `HANDOVER.md` §32.9 is a finding about what it used to
    // say there. It ended with *"the whole-run bound is the product — which is
    // stated here because an operator sizing a backup window needs the product
    // and not the factor"* and then stated no product: no number, and no
    // mention that the schedule runs once per distinct request. A claim to have
    // said something, in the place an operator reads, which is the same class
    // of false report as a transfer that did not happen.
    //
    // The measurement behind the correction, against live B2 with the route
    // black-holed and `--retries 1`: the first failure at **30 s**, to the
    // second, and the run **not ended 943.6 s after the cut**. On `sftp:`, not
    // ended after 601 s. The product is not stated now because it is not a
    // number this flag knows — and `--max-duration`, which is the honest
    // answer, is named instead.
    //
    // The semantics are deliberately unchanged. rclone's `--timeout` is
    // `Help: "IO idle timeout"` with a five-minute default (`fs/config.go:122`)
    // and DCTL matches it. An inactivity deadline made to behave like a
    // stopwatch would destroy exactly the transfers it exists to protect, which
    // would be a worse defect than the one being fixed.
    #[arg(
        long,
        global = true,
        default_value_t = constants::DEFAULT_TIMEOUT_SECS,
        value_name = "SECONDS",
        help_heading = "Transfer"
    )]
    pub timeout: u64,

    /// Give up on ONE attempt to reach a host after this long, in seconds.
    /// 0 waits forever.
    ///
    /// Separate from --timeout because the two bound different failures.
    /// Nothing is at risk while a connection is being established, so giving up
    /// on one costs a round of backoff and nothing else — which is why this is
    /// far more impatient than the deadline on a transfer already carrying data.
    ///
    /// Like --timeout it bounds one ATTEMPT and does NOT bound the run.
    // On `sftp:` it is applied twice over: handed to `ssh` as
    // `-o ConnectTimeout`, so the whole `ProxyCommand` chain is bounded from
    // the inside — which is where rclone puts the same number
    // (`backend/sftp/sftp.go:946`) — and applied again around the dial, because
    // `ConnectTimeout` covers the TCP connect and stops watching after it.
    //
    // The second one closes a measured hole. §32.9's `sftp:` arm dropped port 22
    // six seconds into a copy: the deadline fired at exactly 30 s, the dead
    // session was discarded correctly, a replacement was dialled — and the
    // replacement hung, with the run still alive when the harness killed it at
    // 601 s. Everything above the dial was working.
    #[arg(
        long,
        global = true,
        default_value_t = constants::DEFAULT_CONTIMEOUT_SECS,
        value_name = "SECONDS",
        help_heading = "Transfer"
    )]
    pub contimeout: u64,

    /// Stop after transferring this much, e.g. 100G. Exits 8 at the limit,
    /// without starting a file that would exceed it.
    #[arg(long, global = true, value_name = "SIZE", help_heading = "Transfer")]
    pub max_transfer: Option<ByteLimit>,

    /// Stop the whole run after this long, e.g. 4h. Exits 10. 'off' for no
    /// limit, which is the default.
    ///
    /// The flag that bounds a backup window, and the only one that does:
    /// --timeout and --contimeout each bound one attempt, while this bounds the
    /// invocation from the moment it starts.
    ///
    /// A HARD cutoff. When the window closes the request in flight is
    /// cancelled, the retry loop is not re-entered, no further file is started,
    /// and the counters report what really completed.
    ///
    /// Nothing is left half-written by it: a verified write commits only when
    /// the stored bytes match, so an abandoned object was never an object. What
    /// a cut transfer does leave is a staging file or an unfinished upload, and
    /// 'dctl cleanup' reclaims both. Re-running the same command continues from
    /// what landed.
    ///
    /// Written as 30s, 90m, 4h or 7d; a bare number is seconds. rclone accepts
    /// a compound duration here (1h30m) and this does not — write 90m.
    // Hard rather than cautious, and the choice is not the one `--max-transfer`
    // made. There is no honest way to predict how long a file will take, so
    // "do not start what will not fit" has no meaning here; and a flag that only
    // stopped *between* files would not stop a run whose last object is a
    // terabyte. rclone's default for the same flag is `--cutoff-mode hard`,
    // implemented by giving the transfer context a deadline
    // (`fs/sync/sync.go:203-205`), and this is the same act in the Rust idiom.
    //
    // `HANDOVER.md` §11.3 item 2 is the entry it closes and §32.9 is the
    // measurement that opened it.
    #[arg(
        long,
        global = true,
        value_name = "DURATION",
        help_heading = "Transfer"
    )]
    pub max_duration: Option<TimeLimit>,

    // ── Filtering ────────────────────────────────────────────────────────
    /// Include only paths matching this glob. Repeatable.
    ///
    /// `allow_hyphen_values` because a pattern may legitimately begin with `-`
    /// (`--exclude '-old*'`), and because rclone's parser consumes the next
    /// argument as the value whatever it starts with. Without it a pattern a
    /// migrating script already contains is reported as an unknown flag.
    #[arg(
        long,
        global = true,
        allow_hyphen_values = true,
        value_name = "PATTERN",
        help_heading = "Filtering"
    )]
    pub include: Vec<String>,

    /// Exclude paths matching this glob. Repeatable.
    #[arg(
        long,
        global = true,
        allow_hyphen_values = true,
        value_name = "PATTERN",
        help_heading = "Filtering"
    )]
    pub exclude: Vec<String>,

    /// Read include patterns from a file, one per line. Repeatable.
    #[arg(long, global = true, value_name = "PATH", help_heading = "Filtering")]
    pub include_from: Vec<PathBuf>,

    /// Read exclude patterns from a file, one per line. Repeatable.
    #[arg(long, global = true, value_name = "PATH", help_heading = "Filtering")]
    pub exclude_from: Vec<PathBuf>,

    /// One rule, written '+ pattern', '- pattern' or '!'. Repeatable.
    ///
    /// The flag whose order is written down rather than reconstructed; prefer it
    /// to mixing --include and --exclude.
    ///
    /// `allow_hyphen_values` is not optional here: every exclusion rule begins
    /// with `-`, so without it the flag could only ever express inclusions.
    #[arg(
        short = 'f',
        long,
        global = true,
        allow_hyphen_values = true,
        value_name = "RULE",
        help_heading = "Filtering"
    )]
    pub filter: Vec<String>,

    /// Read '+'/'-' rules from a file. Repeatable.
    #[arg(long, global = true, value_name = "PATH", help_heading = "Filtering")]
    pub filter_from: Vec<PathBuf>,

    /// Transfer only the paths listed in this file.
    #[arg(long, global = true, value_name = "PATH", help_heading = "Filtering")]
    pub files_from: Vec<PathBuf>,

    /// Skip files smaller than this. A unit is required, e.g. 100K.
    #[arg(long, global = true, value_name = "SIZE", help_heading = "Filtering")]
    pub min_size: Option<String>,

    /// Skip files larger than this. A unit is required, e.g. 100K.
    #[arg(long, global = true, value_name = "SIZE", help_heading = "Filtering")]
    pub max_size: Option<String>,

    /// Only files at least this old, e.g. 7d. A bare number is seconds.
    #[arg(long, global = true, value_name = "AGE", help_heading = "Filtering")]
    pub min_age: Option<String>,

    /// Only files modified within this long, e.g. 7d.
    #[arg(long, global = true, value_name = "AGE", help_heading = "Filtering")]
    pub max_age: Option<String>,

    /// Recursion depth limit; -1 for unlimited.
    #[arg(
        long,
        global = true,
        default_value_t = constants::MAX_DEPTH_UNLIMITED,
        value_name = "N",
        help_heading = "Filtering"
    )]
    pub max_depth: i32,

    // ── Traversal ────────────────────────────────────────────────────────
    /// What to do with symbolic links found inside a tree.
    ///
    /// Never followed by default, and never passed over in silence: the count is
    /// always reported and `-v` names each one. The root a command is pointed at
    /// is a different question and is always resolved.
    //
    // Everything below is for a reader of this file rather than of `--help`, so
    // it is a comment and not part of the doc string.
    //
    // The possible values come from the storage layer's own list rather than
    // being restated here, so a fourth policy cannot appear in `--help` and be
    // unparseable, or parse and be undocumented.
    //
    // Its own heading, and not "Filtering". A filter selects among the things a
    // walk found; this decides what the walk finds at all. The distinction is
    // load-bearing rather than tidy: `dctl replicate` refuses every flag under
    // "Filtering" — a filtered replica is a vault with dangling references — and
    // it *honours* this one, because a store on `local:` or `sftp:` is walked by
    // the same code as any other tree.
    #[arg(
        long,
        global = true,
        value_name = "MODE",
        default_value_t = LinkPolicy::default(),
        value_parser = clap::builder::PossibleValuesParser::new(LINK_POLICY_CHOICES)
            .try_map(|choice| choice.parse::<LinkPolicy>()),
        help_heading = "Traversal"
    )]
    pub links: LinkPolicy,

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
        // `--verify` carries no clap default, deliberately: the run's strength
        // is the flag, then the destination remote's `verify` setting, then
        // `DEFAULT_VERIFY_MODE`, and a default here would silently win over the
        // middle one. See `crate::remote::resolve::verify_policy`.
        assert_eq!(g.verify, None);
        assert_eq!(constants::DEFAULT_VERIFY_MODE, VerifyMode::Checksum);
    }

    #[test]
    fn the_flags_this_build_cannot_honour_carry_no_default() {
        // A default is a published claim, and a flag that cannot be honoured has
        // nothing to claim. `--timeout` used to be on this list, printing
        // `[default: 300]` for a five-minute idle timeout no backend applied;
        // it left below because something now applies it, which is the only
        // reason a flag may leave.
        let g = parse(&[]);
        assert_eq!(g.verify_samples, None);
        assert_eq!(g.low_level_retries, None);
        assert!(g.dump.is_empty());
    }

    #[test]
    fn the_two_deadlines_publish_the_defaults_the_backends_apply() {
        // The other half of the same rule. These do carry a default, so the
        // number `--help` prints has to be the number `dctl_store` uses — not a
        // copy of it that can drift, which is why both constants are derived
        // from that crate rather than restated here.
        let g = parse(&[]);
        assert_eq!(g.timeout, constants::DEFAULT_TIMEOUT_SECS);
        assert_eq!(g.contimeout, constants::DEFAULT_CONTIMEOUT_SECS);
        assert_eq!(
            dctl_store::Deadlines::from_seconds(g.contimeout, g.timeout),
            dctl_store::Deadlines::default(),
            "a run that names neither flag must get the storage layer's own defaults"
        );

        // And zero really reaches the "wait forever" answer rather than being
        // read as a very short deadline.
        let g = parse(&["--timeout", "0", "--contimeout", "0"]);
        assert_eq!(
            dctl_store::Deadlines::from_seconds(g.contimeout, g.timeout),
            dctl_store::Deadlines::none()
        );
    }

    #[test]
    fn the_run_has_no_deadline_unless_one_is_asked_for() {
        // The default rclone ships for the same flag (`fs/config.go:361`,
        // `max_duration`, `Default: time.Duration(0)`). A window invented here
        // would end somebody's first ten-terabyte sync at whatever number this
        // file happened to pick.
        assert_eq!(parse(&[]).max_duration, None);
        assert_eq!(
            parse(&["--max-duration", "off"]).max_duration,
            Some(TimeLimit::none())
        );
        assert_eq!(
            parse(&["--max-duration", "0"]).max_duration,
            Some(TimeLimit::none())
        );
    }

    #[test]
    fn the_window_is_read_in_the_dialect_the_help_text_names() {
        assert_eq!(
            parse(&["--max-duration", "4h"]).max_duration,
            Some(TimeLimit::of(std::time::Duration::from_secs(4 * 3600)))
        );
        assert_eq!(
            parse(&["--max-duration", "90m"]).max_duration,
            Some(TimeLimit::of(std::time::Duration::from_secs(90 * 60)))
        );
        // Refused at the parser rather than silently leaving the run unbounded.
        // A `--max-duration` that is accepted and then ignored is a backup
        // window removed without anybody being told.
        assert!(Harness::try_parse_from(["dctl", "--max-duration", "4hrs"]).is_err());
    }

    #[test]
    fn the_help_no_longer_claims_a_bound_it_does_not_deliver() {
        // §32.9's finding about `--help` itself. It said the whole-run bound
        // "is the product — which is stated here because an operator sizing a
        // backup window needs the product and not the factor", and then stated
        // no product: no number, and no mention that the schedule runs once per
        // distinct request. A claim to have said something, in the place an
        // operator reads.
        //
        // Asserted against the whole rendered page rather than against a
        // paragraph sliced out of it, and that is not laziness: the first
        // spelling of this test cut each entry at the next blank line, which
        // silently reduced it to the two lines clap puts first — so it passed
        // and failed on where a sentence happened to wrap rather than on
        // whether the sentence was there.
        let help = help_text();

        assert!(
            !help.contains("is the product"),
            "the sentence that promised a product and gave none is back:\n{help}"
        );
        // Both attempt-scoped deadlines have to disclaim the run, or the
        // correction is half-made and the half that is missing is the one an
        // operator reads first.
        assert_eq!(
            help.matches("does NOT bound the run").count(),
            2,
            "--timeout and --contimeout must each say what they do not bound:\n{help}"
        );
        // …and the flag that does bound a run has to be on the same page, or
        // the correction sends the reader nowhere.
        assert!(help.contains("--max-duration"), "{help}");
        assert!(
            help.contains("Stop the whole run after this long"),
            "the run-level flag must say so in its own first line:\n{help}"
        );
    }

    /// `dctl --help` as a user sees it, with every run of whitespace collapsed
    /// to one space.
    ///
    /// Long help, because that is what `--help` renders and what §32.9 quoted:
    /// clap puts the first line of a doc comment in `-h` and the whole of it in
    /// `--help`, so every paragraph written above a flag is user-facing text.
    ///
    /// Collapsed because clap re-wraps that text to the terminal width, so any
    /// sentence an assertion names can be split across two lines by a change to
    /// a flag's *name*. A test that broke for that reason would be a test
    /// nobody trusts, and one that was written to avoid it by matching only
    /// single words would assert nothing.
    fn help_text() -> String {
        use clap::CommandFactory as _;
        Harness::command()
            .render_long_help()
            .to_string()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
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
        assert_eq!(
            parse(&["--verify", "strict"]).verify,
            Some(VerifyMode::Strict)
        );
        assert_eq!(
            parse(&["--verify", "sample"]).verify,
            Some(VerifyMode::Sample)
        );
        assert!(Harness::try_parse_from(["dctl", "--verify", "nonsense"]).is_err());
    }
}
