//! Single source of truth for every tunable in the CLI — no literal is
//! duplicated across the crate.
//!
//! Mirrors the convention established by `dctl-crypto::constants`. Values are
//! grouped by concern, and each carries the reasoning behind its default so a
//! future change is an informed one rather than a guess.
//!
//! Nothing here is part of the on-disk format. These are *presentation and
//! policy* defaults: every one of them is overridable by a flag, an environment
//! variable, or the config file, and changing one can never make stored data
//! unreadable.

// ─────────────────────────────────────────────────────────────────────────────
// Concurrency & transfer policy
// ─────────────────────────────────────────────────────────────────────────────

/// Parallel file transfers (`--transfers`).
///
/// Four keeps a single large-file stream near line rate on a home connection
/// without starving interactive use. Raising it helps many-small-files runs and
/// hurts nothing but provider rate limits.
pub const DEFAULT_TRANSFERS: usize = 4;

/// Parallel metadata checkers (`--checkers`).
///
/// Higher than [`DEFAULT_TRANSFERS`] because a check is one cheap round trip,
/// so the pipeline should stay ahead of the transfers it feeds.
pub const DEFAULT_CHECKERS: usize = 8;

/// High-level retries of a whole failed file (`--retries`).
pub const DEFAULT_RETRIES: u32 = 3;

/// Retries of an individual HTTP request (`--low-level-retries`).
///
/// Higher than [`DEFAULT_RETRIES`] because most failures are a single transient
/// 5xx or reset that succeeds immediately on repeat.
pub const DEFAULT_LOW_LEVEL_RETRIES: u32 = 10;

/// Inactivity timeout on a transfer (`--timeout`).
pub const DEFAULT_TIMEOUT_SECS: u64 = 300;

/// Connection establishment timeout (`--contimeout`).
pub const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 60;

// ─────────────────────────────────────────────────────────────────────────────
// Listing & pagination
// ─────────────────────────────────────────────────────────────────────────────

/// Objects requested per listing page. Matches the page size B2 and S3 both
/// return by default, so a page maps to exactly one provider round trip.
pub const LIST_PAGE_SIZE: usize = 1000;

/// Depth meaning "no limit" for `--max-depth`.
pub const MAX_DEPTH_UNLIMITED: i32 = -1;

/// Default recursion depth for the directory-only listings (`lsd`), which show
/// one level unless asked to recurse.
pub const LSD_DEFAULT_DEPTH: i32 = 1;

// ─────────────────────────────────────────────────────────────────────────────
// Listing output (`ls`, `lsd`, `lsl`, `lsjson`, `tree`, `size`)
// ─────────────────────────────────────────────────────────────────────────────
//
// The listing family shares one line grammar — fixed-width measured columns on
// the left, the path last and unpadded — so that `ls`, `lsl` and `lsd` output
// can be read down a screen as if they were one table, and so that the path (the
// only field whose width is unbounded) never has trailing whitespace in a pipe.

/// Width of the right-aligned size column in the text listings.
///
/// Ten characters is the widest rendering [`crate::output::size::bytes`] can
/// produce for a plausible object (`1023.99 GiB`), so the path column starts in
/// the same screen position on every row. It matches
/// [`FILE_BYTES_COLUMN_WIDTH`] deliberately: a listing and a progress bar shown
/// in the same terminal should not disagree about how wide a size is.
pub const LISTING_SIZE_COLUMN_WIDTH: usize = 10;

/// Width of the right-aligned object-count column in `lsd`.
///
/// Nine characters holds `9,999,999` with its thousands separators, which is
/// past the point where a single directory is browsable by a human at all.
pub const LISTING_COUNT_COLUMN_WIDTH: usize = 9;

/// Width of the modification-time column in `lsl`.
///
/// Exactly the length of an RFC 3339 timestamp at whole-second resolution
/// (`2024-05-31T16:24:29Z`), so the column never pads and never truncates. A
/// row whose time is unknown fills the same width with [`UNKNOWN_VALUE`].
pub const LISTING_MODTIME_COLUMN_WIDTH: usize = 20;

/// Separator between fields on one listing line.
///
/// A single space, never a tab: a tab's rendered width depends on the terminal's
/// tab stops, and the columns either side of it are already width-aligned.
pub const LISTING_FIELD_SEPARATOR: &str = " ";

/// Appended to a directory name in the text listings.
///
/// `lsd` and `tree` both print names that could otherwise be mistaken for
/// files. rclone prints the bare name; DCTL adds the slash because a listing
/// that mixes the two vocabularies (`lsd` here, `ls` one command later) is
/// ambiguous without it. The JSON shape carries `IsDir` instead and never
/// applies this suffix — a machine consumer must not have to strip it.
pub const LISTING_DIR_SUFFIX: char = '/';

/// Name under which a plaintext content hash is reported in `lsjson`'s
/// `Hashes` map.
///
/// BLAKE3 is the only digest the index records (`PLAN.md` §6 step 1). The map
/// shape — rather than a bare string — is what lets a second algorithm be added
/// later without breaking a consumer that reads `Hashes.blake3`.
pub const LISTING_HASH_ALGORITHM: &str = "blake3";

/// Stage named in the "not implemented" error the listing family returns while
/// the engine is unreachable.
///
/// Spelled as the *missing step* rather than as the command, because everything
/// either side of it — argument parsing, filtering, ordering, rendering — does
/// work, and a user who is told "`dctl ls` is not implemented" would reasonably
/// stop reading there.
pub const LISTING_ENGINE_STAGE: &str = "reading the object index";

/// Remediation hint attached to that error.
pub const LISTING_ENGINE_HINT: &str = "The listing pipeline is complete; what is missing is the vault handle, \
     which Ctx does not carry yet. See PLAN.md §11.";

/// Feature name reported when a listing is pointed at a local directory.
///
/// A bare path is a legal spec — `PLAN.md` treats local storage as a remote like
/// any other — but the walk that would enumerate it does not exist yet, and a
/// listing that silently produced nothing would read as "the directory is
/// empty".
pub const LOCAL_LISTING_FEATURE: &str = "listing a local directory";

/// Remediation hint attached to [`LOCAL_LISTING_FEATURE`].
pub const LOCAL_LISTING_HINT: &str =
    "Give a remote spec such as 'vault:photos' instead of a filesystem path.";

/// Hint shown when a listing command was given neither a path nor a remote.
pub const LISTING_TARGET_HINT: &str = "Name the remote in the command ('dctl ls vault:photos'), or set a default \
     with --remote / DCTL_REMOTE.";

/// Feature name reported when rules are requested from a file.
///
/// Refused rather than ignored for the same reason as every other filter: a
/// listing whose `--filter-from` was dropped shows objects the user believes
/// are excluded, and that answer then gets used to decide what to delete.
pub const RULE_FILE_FEATURE: &str = "reading filter rules from a file";

/// Remediation hint attached to [`RULE_FILE_FEATURE`].
pub const RULE_FILE_HINT: &str = "Pass the rules directly with --include/--exclude, which are honoured in \
     full by the listing commands.";

/// Lower-case hexadecimal digits, indexed by nibble value.
///
/// Hand-indexed rather than formatted per byte: a content hash is rendered once
/// per object, and `lsjson` over ten million objects should not spend its time
/// in the formatting machinery.
pub const HEX_DIGITS: &[u8] = b"0123456789abcdef";

// ─────────────────────────────────────────────────────────────────────────────
// `size` report
// ─────────────────────────────────────────────────────────────────────────────

/// Label on the object-count row of `dctl size`.
pub const SIZE_REPORT_LABEL_OBJECTS: &str = "Total objects:";

/// Label on the byte-total row of `dctl size`.
pub const SIZE_REPORT_LABEL_BYTES: &str = "Total size:";

/// Unit named beside the exact byte total.
///
/// `dctl size` prints the rounded human figure *and* the exact count, because
/// the first is what a person wants and the second is what a quota calculation
/// needs. Lower case, so it cannot be mistaken for one of the suffixes in
/// [`BINARY_UNIT_SUFFIXES`].
pub const SIZE_REPORT_EXACT_UNIT: &str = "bytes";

// ─────────────────────────────────────────────────────────────────────────────
// Tree glyphs
// ─────────────────────────────────────────────────────────────────────────────
//
// Four slots, in the order the renderer uses them: a branch to a node that has
// later siblings, a branch to the last node, the vertical continuation drawn
// under a branch that had later siblings, and the blank continuation drawn
// under the last one. Every slot in both sets is exactly four columns wide, so
// the two are interchangeable and an indent is always a multiple of four.

/// Branch to a node with later siblings, UTF-8 terminal.
pub const TREE_BRANCH_UNICODE: &str = "├── ";
/// Branch to the last node in a directory, UTF-8 terminal.
pub const TREE_LAST_BRANCH_UNICODE: &str = "└── ";
/// Continuation under a non-final branch, UTF-8 terminal.
pub const TREE_VERTICAL_UNICODE: &str = "│   ";

/// Branch to a node with later siblings, ASCII fallback.
pub const TREE_BRANCH_ASCII: &str = "|-- ";
/// Branch to the last node in a directory, ASCII fallback.
pub const TREE_LAST_BRANCH_ASCII: &str = "`-- ";
/// Continuation under a non-final branch, ASCII fallback.
pub const TREE_VERTICAL_ASCII: &str = "|   ";

/// Continuation under the last branch. Shared by both sets — blank is blank.
pub const TREE_INDENT: &str = "    ";

/// Root label used when `tree` is given no path, i.e. the vault root.
///
/// A bare `.` rather than `/`, matching `tree(1)`: the listing is relative to
/// wherever the command was pointed, not to an absolute filesystem root.
pub const TREE_ROOT_LABEL: &str = ".";

/// Noun used in the `tree` footer for directories.
pub const TREE_SUMMARY_DIRECTORIES: &str = "directories";

/// Noun used in the `tree` footer for files.
pub const TREE_SUMMARY_FILES: &str = "files";

// ─────────────────────────────────────────────────────────────────────────────
// Streamed JSON documents
// ─────────────────────────────────────────────────────────────────────────────
//
// A listing of ten million objects must not be serialised into one `Vec` before
// the first byte reaches the pipe (`PLAN.md` §16.2), so the array brackets and
// separators are written by hand around individually-encoded elements rather
// than delegating the whole document to `serde_json`.

/// Opening bracket of a streamed JSON array.
pub const JSON_ARRAY_OPEN: &str = "[";
/// Closing bracket of a streamed JSON array.
pub const JSON_ARRAY_CLOSE: &str = "]";
/// Separator written between two elements of a streamed JSON array.
pub const JSON_ARRAY_SEPARATOR: &str = ",";
/// Indent applied to each element of a streamed JSON array, matching the two
/// spaces `serde_json`'s pretty printer uses so the result is indistinguishable
/// from a document it produced whole.
pub const JSON_INDENT: &str = "  ";
/// Rendering of a streamed array that turned out to have no elements.
pub const JSON_EMPTY_ARRAY: &str = "[]";

// ─────────────────────────────────────────────────────────────────────────────
// Glob syntax
// ─────────────────────────────────────────────────────────────────────────────
//
// The metacharacters `--include`/`--exclude` accept. Named rather than inlined
// so the matcher, its error messages and its documentation cannot drift apart.
// This is rclone's dialect, because the patterns users bring are rclone's.

/// Matches any run of characters *within* one path component.
pub const GLOB_ANY_SEQUENCE: char = '*';
/// Doubled [`GLOB_ANY_SEQUENCE`]: matches any run of characters, crossing
/// [`PATH_SEPARATOR`].
pub const GLOB_RECURSIVE_SEQUENCE: &str = "**";
/// Matches exactly one character, never [`PATH_SEPARATOR`].
pub const GLOB_ANY_CHAR: char = '?';
/// Opens a character class.
pub const GLOB_CLASS_OPEN: char = '[';
/// Closes a character class.
pub const GLOB_CLASS_CLOSE: char = ']';
/// Either character, as the first in a class, negates it.
pub const GLOB_CLASS_NEGATE: &[char] = &['!', '^'];
/// Separates the ends of a range inside a character class.
pub const GLOB_CLASS_RANGE: char = '-';
/// Removes any special meaning from the character that follows it.
pub const GLOB_ESCAPE: char = '\\';

// ─────────────────────────────────────────────────────────────────────────────
// RFC 3339 timestamps
// ─────────────────────────────────────────────────────────────────────────────
//
// Timestamps in machine output are always RFC 3339 in **UTC**. A local-time
// rendering would make the same vault produce different bytes on two machines,
// which breaks the one thing structured output exists for: comparing two runs.

/// Separator between the fields of the date part.
pub const RFC3339_DATE_SEPARATOR: char = '-';
/// Separator between the fields of the time part.
pub const RFC3339_TIME_SEPARATOR: char = ':';
/// Separator between the date and the time.
pub const RFC3339_DATE_TIME_SEPARATOR: char = 'T';
/// Zone designator. Always `Z`: see the note above.
pub const RFC3339_UTC_DESIGNATOR: char = 'Z';
/// Zero-padded width of the year field.
pub const RFC3339_YEAR_WIDTH: usize = 4;
/// Zero-padded width of every field other than the year.
pub const RFC3339_FIELD_WIDTH: usize = 2;

// ─────────────────────────────────────────────────────────────────────────────
// Progress rendering
// ─────────────────────────────────────────────────────────────────────────────

/// Bar redraw frequency (Hz). Fast enough to read as live motion, slow enough
/// that a saturated link spends no measurable CPU on drawing.
pub const PROGRESS_REDRAW_HZ: u8 = 12;

/// Spinner animation interval.
pub const PROGRESS_TICK_INTERVAL_MS: u64 = 120;

/// Width, in characters, of the aggregate progress bar.
pub const AGGREGATE_BAR_WIDTH: usize = 32;

/// Width, in characters, of a per-file progress bar.
pub const FILE_BAR_WIDTH: usize = 20;

/// Width reserved for the filename column on a per-file bar.
pub const FILE_LABEL_WIDTH: usize = 36;

/// How often the periodic status line is emitted when bars are unavailable
/// (`--stats`).
pub const DEFAULT_STATS_INTERVAL_SECS: u64 = 60;

/// Field width for a percentage, on the bars and in the one-line status alike.
///
/// Three digits so `7%`, `70%` and `100%` all occupy the same columns, and the
/// [`UNKNOWN_VALUE`] placeholder lines up with them. A status line that shifts
/// sideways as the number grows is unreadable in a scrolling log, and a bar
/// whose tail jumps a column at 100% looks like a redraw glitch.
pub const PERCENT_FIELD_WIDTH: usize = 3;

/// Width of each byte-count column on a per-file bar.
///
/// Ten characters fits the common `123.45 MiB` rendering, so the transferred
/// and total counts sit symmetrically either side of their separator. A wider
/// value such as `1023.99 GiB` pushes the column instead of being cut —
/// `indicatif` treats the width as a minimum, and a truncated byte count would
/// be far worse than a shifted one.
pub const FILE_BYTES_COLUMN_WIDTH: usize = 10;

/// Bar glyphs for a terminal that can be trusted with UTF-8, in the order
/// `indicatif` expects: filled body, leading edge, unfilled remainder.
///
/// The heavy box-drawing run reads as a continuous bar at any width, and the
/// half-width edge glyph gives sub-character resolution on the moving end.
pub const PROGRESS_CHARS_UNICODE: &str = "━╸━";

/// ASCII bar glyphs, in the same filled/edge/unfilled order.
///
/// Kept the same length as [`PROGRESS_CHARS_UNICODE`] so the two are drop-in
/// interchangeable. On a legacy Windows console or a non-UTF-8 locale the
/// Unicode set degrades into mojibake, and a bar drawn from `=`, `>` and `-`
/// still reads as a bar.
pub const PROGRESS_CHARS_ASCII: &str = "=>-";

/// Spinner frames for a UTF-8 terminal.
///
/// The braille cycle animates smoothly at [`PROGRESS_TICK_INTERVAL_MS`] without
/// the width jitter a rotating-slash spinner has. The trailing check mark is the
/// frame `indicatif` parks on when the bar finishes, so a completed row reads as
/// done rather than as frozen mid-spin.
pub const SPINNER_TICKS_UNICODE: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏", "✔"];

/// ASCII spinner frames, under the same contract: a rotation followed by one
/// final completion frame.
pub const SPINNER_TICKS_ASCII: &[&str] = &["|", "/", "-", "\\", "*"];

/// Fraction of a truncated label given to the tail. The filename identifies the
/// row, so it gets two thirds and the leading directories get the rest.
pub const TRUNCATE_TAIL_NUMERATOR: usize = 2;
pub const TRUNCATE_TAIL_DENOMINATOR: usize = 3;

/// Marker inserted where a label was cut.
///
/// Its own display width is subtracted from the budget before the head/tail
/// split, so a truncated label occupies exactly the requested number of columns.
pub const TRUNCATION_ELLIPSIS: &str = "…";

/// Narrowest label that can still carry a head, an ellipsis and a tail.
///
/// At or below three columns there is nothing informative left to keep — one
/// leading character and one trailing character say less than nothing about
/// which file a row is — so the label degrades to ellipses alone rather than to
/// a misleading fragment.
pub const TRUNCATE_MIN_WIDTH: usize = 3;

// ─────────────────────────────────────────────────────────────────────────────
// Terminal & formatting
// ─────────────────────────────────────────────────────────────────────────────

/// Environment variable that marks a modern Windows Terminal session.
///
/// It is the documented signal for the one Windows console host that renders
/// multi-byte glyphs reliably; the legacy `conhost.exe` never sets it. Probing
/// this variable is how the CLI decides whether Windows gets the Unicode or the
/// ASCII glyph set.
pub const WINDOWS_TERMINAL_ENV: &str = "WT_SESSION";

/// Locale variables consulted for a UTF-8 signal, in POSIX precedence order:
/// `LC_ALL` overrides everything, `LC_CTYPE` governs character classification
/// specifically, and `LANG` is the fallback default.
///
/// Any one of them naming UTF-8 is taken as a positive signal. The check is
/// deliberately permissive rather than strictly hierarchical: guessing "yes" on
/// a half-configured environment costs at worst some mojibake in a spinner,
/// while guessing "no" would downgrade every correctly configured terminal that
/// happens to set only `LANG`.
pub const LOCALE_ENV_VARS: &[&str] = &["LC_ALL", "LC_CTYPE", "LANG"];

/// Spellings of UTF-8 that appear inside a locale value (`en_US.UTF-8`,
/// `C.utf8`). Matched against the upper-cased value, so only the upper-case
/// forms need listing here.
pub const UTF8_LOCALE_MARKERS: &[&str] = &["UTF-8", "UTF8"];

/// Gap between table columns, in spaces.
pub const TABLE_COLUMN_GAP: &str = "  ";

/// Character repeated to draw a header rule.
pub const TABLE_RULE_CHAR: char = '-';

/// Character used to pad a cell out to its column width.
///
/// A plain space, never a tab: a tab's rendered width depends on the terminal's
/// tab stops, which would destroy the character-exact alignment the renderer
/// computes.
pub const TABLE_PAD_CHAR: char = ' ';

/// Digits per thousands group when formatting counts.
pub const THOUSANDS_GROUP_SIZE: usize = 3;

/// Separator inserted between thousands groups.
///
/// Fixed rather than locale-derived on purpose: DCTL's text output is parsed by
/// scripts, so `1,234` must be `1,234` on a German desktop too — a locale-aware
/// separator would silently change the bytes a pipeline sees.
pub const THOUSANDS_SEPARATOR: char = ',';

/// Below this value a size is shown with two decimals; at or above it, one.
/// Keeps columns narrow without losing meaningful precision.
pub const SIZE_HIGH_PRECISION_CUTOFF: f64 = 10.0;

/// Decimals shown below [`SIZE_HIGH_PRECISION_CUTOFF`]. Two digits on a
/// single-digit mantissa keeps three significant figures (`1.44 GiB`).
pub const SIZE_DECIMALS_BELOW_CUTOFF: usize = 2;

/// Decimals shown at or above [`SIZE_HIGH_PRECISION_CUTOFF`]. One digit is
/// enough for three significant figures once the mantissa has two (`50.0 KiB`).
pub const SIZE_DECIMALS_ABOVE_CUTOFF: usize = 1;

/// Binary (IEC) divisor: 1 KiB = 1024 B. What the operating system reports.
pub const BINARY_DIVISOR: f64 = 1024.0;

/// Decimal (SI) divisor: 1 kB = 1000 B. What providers bill in.
pub const DECIMAL_DIVISOR: f64 = 1000.0;

/// Binary unit suffixes, ascending.
pub const BINARY_UNIT_SUFFIXES: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];

/// Decimal unit suffixes, ascending.
pub const DECIMAL_UNIT_SUFFIXES: &[&str] = &["B", "kB", "MB", "GB", "TB", "PB", "EB"];

/// Placeholder shown where a value cannot be computed (an ETA with no rate).
pub const UNKNOWN_VALUE: &str = "-";

/// Appended to a formatted size to turn it into a rate (`12.4 MiB/s`).
///
/// Per-second is the only rate DCTL quotes: it is the unit every other transfer
/// tool prints, so a user comparing DCTL against `rclone` or `scp` is comparing
/// like with like.
pub const RATE_SUFFIX: &str = "/s";

// ─────────────────────────────────────────────────────────────────────────────
// Size-suffix parsing
// ─────────────────────────────────────────────────────────────────────────────
//
// The inverse of the formatting constants above: these turn what a user *writes*
// (`10G`, `1.5MiB`, `900kB`, `off`) back into a byte count. The ladder is derived
// from [`BINARY_DIVISOR`] and [`DECIMAL_DIVISOR`] rather than spelled out, so
// parsing can never drift from formatting.

/// Multiplier for a bare number or an explicit `B` suffix.
pub const BYTES_PER_BYTE: f64 = 1.0;

/// One kibibyte, 2^10 bytes.
pub const BYTES_PER_KIB: f64 = BINARY_DIVISOR;
/// One mebibyte, 2^20 bytes.
pub const BYTES_PER_MIB: f64 = BYTES_PER_KIB * BINARY_DIVISOR;
/// One gibibyte, 2^30 bytes.
pub const BYTES_PER_GIB: f64 = BYTES_PER_MIB * BINARY_DIVISOR;
/// One tebibyte, 2^40 bytes.
pub const BYTES_PER_TIB: f64 = BYTES_PER_GIB * BINARY_DIVISOR;
/// One pebibyte, 2^50 bytes. The top of the ladder: a `--max-size` beyond this
/// is indistinguishable from no limit at all, which already has a spelling
/// ([`SIZE_LIMIT_OFF`]).
pub const BYTES_PER_PIB: f64 = BYTES_PER_TIB * BINARY_DIVISOR;

/// One kilobyte, 10^3 bytes.
pub const BYTES_PER_KB: f64 = DECIMAL_DIVISOR;
/// One megabyte, 10^6 bytes.
pub const BYTES_PER_MB: f64 = BYTES_PER_KB * DECIMAL_DIVISOR;
/// One gigabyte, 10^9 bytes.
pub const BYTES_PER_GB: f64 = BYTES_PER_MB * DECIMAL_DIVISOR;
/// One terabyte, 10^12 bytes.
pub const BYTES_PER_TB: f64 = BYTES_PER_GB * DECIMAL_DIVISOR;
/// One petabyte, 10^15 bytes.
pub const BYTES_PER_PB: f64 = BYTES_PER_TB * DECIMAL_DIVISOR;

/// Every size suffix DCTL accepts, paired with its byte multiplier.
///
/// Lookup is an exact match on the ASCII-lower-cased suffix, so the rows carry no
/// ordering requirement; they are listed smallest-first because that is how a
/// reader checks the table for gaps.
///
/// The split between the two conventions is the interesting part. A bare letter
/// or an IEC spelling (`10G`, `10Gi`, `10GiB`) is **binary**, matching rclone and
/// therefore matching every script a user is porting. An explicit SI spelling
/// (`10GB`) is **decimal**, because that is the unit a provider's invoice and
/// quota page are quoted in — someone writing `--max-size 5TB` from a bill means
/// the bill's terabyte, not 10% more than it. Both spellings of the ambiguous
/// case are therefore deliberate, not an oversight.
pub const SIZE_SUFFIX_MULTIPLIERS: &[(&str, f64)] = &[
    ("", BYTES_PER_BYTE),
    ("b", BYTES_PER_BYTE),
    ("k", BYTES_PER_KIB),
    ("ki", BYTES_PER_KIB),
    ("kib", BYTES_PER_KIB),
    ("kb", BYTES_PER_KB),
    ("m", BYTES_PER_MIB),
    ("mi", BYTES_PER_MIB),
    ("mib", BYTES_PER_MIB),
    ("mb", BYTES_PER_MB),
    ("g", BYTES_PER_GIB),
    ("gi", BYTES_PER_GIB),
    ("gib", BYTES_PER_GIB),
    ("gb", BYTES_PER_GB),
    ("t", BYTES_PER_TIB),
    ("ti", BYTES_PER_TIB),
    ("tib", BYTES_PER_TIB),
    ("tb", BYTES_PER_TB),
    ("p", BYTES_PER_PIB),
    ("pi", BYTES_PER_PIB),
    ("pib", BYTES_PER_PIB),
    ("pb", BYTES_PER_PB),
];

/// Word that disables a size limit (`--max-size off`).
///
/// Matched case-insensitively. A word rather than a sentinel number because
/// "unlimited" is a different *kind* of answer from a size, and spelling it as
/// one keeps `--max-size 0` from silently meaning "transfer nothing".
pub const SIZE_LIMIT_OFF: &str = "off";

/// The numeric spelling of "no limit", accepted for rclone compatibility.
pub const SIZE_LIMIT_ZERO: &str = "0";

/// Hint appended to a size-parsing failure, showing one example of each accepted
/// shape so the fix is visible without opening the manual.
pub const SIZE_PARSE_EXAMPLES: &str = "10G, 1.5MiB, or off";

// ─────────────────────────────────────────────────────────────────────────────
// Status marks & stderr message prefixes
// ─────────────────────────────────────────────────────────────────────────────
//
// Everything in this block is written to **stderr**, never stdout: stdout is
// reserved for data so a pipeline stays parseable while these are on screen.

/// Mark prefixed to a success message when styling is enabled.
///
/// A styled sink has already proven it is talking to a terminal that accepted
/// ANSI, which in practice is also a terminal that renders U+2713 — so the glyph
/// is safe exactly when colour is.
pub const SUCCESS_MARK: &str = "✓";

/// Success mark used when styling is disabled — a pipe, a CI log, a legacy
/// Windows console, or a non-UTF-8 locale, where the glyph would arrive as
/// mojibake. Two ASCII letters survive all of them.
pub const SUCCESS_MARK_ASCII: &str = "OK";

/// Prefix on a warning. Lower-case and colon-terminated to match the
/// `program: message` convention every other Unix tool uses, so log scrapers
/// that already grep for `warning:` keep working.
pub const WARNING_PREFIX: &str = "warning:";

/// Prefix on an error, following the same convention as [`WARNING_PREFIX`].
pub const ERROR_PREFIX: &str = "error:";

// ─────────────────────────────────────────────────────────────────────────────
// End-of-run summary
// ─────────────────────────────────────────────────────────────────────────────
//
// The labels are part of what a user reads after every transfer, and the row
// vocabulary deliberately mirrors `PLAN.md` §6: *transferred* and *verified* are
// separate rows because bytes that are uploaded but not yet checksum-confirmed
// are not yet durable, and conflating the two would be the misreporting the
// verified-write contract exists to prevent.

/// Width of the right-aligned label column in the summary.
///
/// Sized to the longest label ([`SUMMARY_LABEL_TRANSFERRED`], 11 characters)
/// plus one space of breathing room, so every value starts in the same column
/// and the report reads as a table without needing one.
pub const SUMMARY_LABEL_WIDTH: usize = 12;

/// Decimals on the completion percentage in the summary.
///
/// None: the summary is a final figure, not a live gauge, and `99.7%` invites
/// the question "which files were the missing 0.3%?" that the *Files* and
/// *Errors* rows answer properly.
pub const SUMMARY_PERCENT_DECIMALS: usize = 0;

/// Bytes moved over the wire. Not a durability claim on its own.
pub const SUMMARY_LABEL_TRANSFERRED: &str = "Transferred";

/// Bytes whose stored checksum matched ours — the durable subset of
/// [`SUMMARY_LABEL_TRANSFERRED`].
pub const SUMMARY_LABEL_VERIFIED: &str = "Verified";

/// Files committed to the index versus files considered.
pub const SUMMARY_LABEL_FILES: &str = "Files";

/// Metadata comparisons performed by the checker pipeline.
pub const SUMMARY_LABEL_CHECKS: &str = "Checks";

/// Files the checker proved were already identical at the destination.
pub const SUMMARY_LABEL_SKIPPED: &str = "Skipped";

/// Files removed at the destination by a `sync`.
pub const SUMMARY_LABEL_DELETED: &str = "Deleted";

/// Transfer attempts that failed and were retried.
pub const SUMMARY_LABEL_RETRIES: &str = "Retries";

/// Verified writes refused because the stored checksum disagreed with ours.
pub const SUMMARY_LABEL_MISMATCHES: &str = "Mismatches";

/// Total failures. Always shown, including as `0`, so its absence can never be
/// mistaken for "no errors happened".
pub const SUMMARY_LABEL_ERRORS: &str = "Errors";

/// Wall-clock duration of the run.
pub const SUMMARY_LABEL_ELAPSED: &str = "Elapsed";

/// Qualifier on the verified row, stating *which* guarantee those bytes carry.
pub const SUMMARY_VERIFIED_NOTE: &str = "checksum-matched";

/// Qualifier on the skipped row: skipped means "proven identical", not
/// "ignored".
pub const SUMMARY_SKIPPED_NOTE: &str = "(unchanged)";

/// Qualifier on the mismatch row. The reassurance is the point: a mismatch
/// aborts before the index commit, so nothing was recorded as stored and no
/// source file was touched (`PLAN.md` §6 step 4).
pub const SUMMARY_MISMATCH_NOTE: &str = "(nothing committed)";

// ─────────────────────────────────────────────────────────────────────────────
// Time
// ─────────────────────────────────────────────────────────────────────────────

pub const SECONDS_PER_MINUTE: u64 = 60;
pub const SECONDS_PER_HOUR: u64 = 60 * SECONDS_PER_MINUTE;
pub const SECONDS_PER_DAY: u64 = 24 * SECONDS_PER_HOUR;

/// Unit letters used by the compact duration format (`45s`, `1m20s`, `2h05m`,
/// `3d04h`).
///
/// Single ASCII letters, not words: a duration sits inside a progress line whose
/// total width is fixed, and `1m20s` costs five columns where `1 min 20 sec`
/// costs twelve. They are also the spellings `date`, `sleep` and every other Unix
/// tool already uses, so they need no legend.
pub const DURATION_SECOND_SUFFIX: char = 's';
/// See [`DURATION_SECOND_SUFFIX`].
pub const DURATION_MINUTE_SUFFIX: char = 'm';
/// See [`DURATION_SECOND_SUFFIX`].
pub const DURATION_HOUR_SUFFIX: char = 'h';
/// See [`DURATION_SECOND_SUFFIX`].
pub const DURATION_DAY_SUFFIX: char = 'd';

/// Zero-padded width of the trailing field in a two-part duration.
///
/// Two digits so `2h05m` and `2h45m` occupy the same columns: an ETA that
/// changes width as it counts down makes the whole progress line jitter.
pub const DURATION_FIELD_WIDTH: usize = 2;

// ─────────────────────────────────────────────────────────────────────────────
// Configuration & paths
// ─────────────────────────────────────────────────────────────────────────────

/// Config filename inside the platform config directory.
pub const CONFIG_FILE_NAME: &str = "config.toml";

/// Filename of the local encrypted index inside the platform data directory.
pub const INDEX_FILE_NAME: &str = "vault.redb";

/// POSIX permission bits enforced on the config file. Group and world get
/// nothing: the file names buckets and endpoints, which is reconnaissance.
#[cfg(unix)]
pub const CONFIG_FILE_MODE: u32 = 0o600;

/// Minimum length of a remote name.
///
/// Two, not one, so a name can never be mistaken for a Windows drive letter:
/// `c:\data` must always parse as a path, never as a remote called `c`.
pub const MIN_REMOTE_NAME_LEN: usize = 2;

/// Separator between a remote name and its path in a spec (`vault:photos/a`).
pub const REMOTE_SEPARATOR: char = ':';

/// Logical path separator. Always `/`, on every platform.
pub const PATH_SEPARATOR: char = '/';

// ─────────────────────────────────────────────────────────────────────────────
// Environment variable settings
// ─────────────────────────────────────────────────────────────────────────────
//
// Names are suffixes: `dctl_meta::env_var` prefixes each with `DCTL_`, so a
// rebrand renames every variable automatically.
//
// Only the variables this crate reads *itself* appear here. The rest —
// `DCTL_PASSWORD_COMMAND`, `DCTL_INDEX`, `DCTL_LOG_LEVEL`, `DCTL_LOG_FORMAT` —
// are read by clap on the flag that owns them, and clap's `env` attribute needs
// a `'static` name it can bake into the command definition, so a value computed
// by `dctl_meta::env_var` cannot be handed to it. Declaring them twice would be
// worse than declaring them once in the place that consumes them: two spellings
// of one variable name is exactly how a rename half-lands.

pub const ENV_CONFIG: &str = "CONFIG";
pub const ENV_REMOTE: &str = "REMOTE";
pub const ENV_PASSWORD: &str = "PASSWORD";

// ─────────────────────────────────────────────────────────────────────────────
// Interactive prompts
// ─────────────────────────────────────────────────────────────────────────────

/// Prompt shown when reading the vault password from a terminal.
pub const PASSWORD_PROMPT: &str = "Vault password: ";

/// Prompt shown when a new password must be typed twice.
pub const PASSWORD_CONFIRM_PROMPT: &str = "Confirm vault password: ";

/// Word a user must type to confirm a destructive operation without `--force`.
pub const DESTRUCTIVE_CONFIRMATION: &str = "yes";

/// Marker opening the confirmation prompt for a destructive action.
///
/// Visually distinct from [`WARNING_PREFIX`] and [`ERROR_PREFIX`] because it is
/// not a report of something that happened — it is a question that blocks until
/// answered, and the operator needs to recognise that difference instantly.
pub const CONFIRM_PROMPT_PREFIX: &str = "confirm:";

// ─────────────────────────────────────────────────────────────────────────────
// Second-factor keyfile (`--key-file`)
// ─────────────────────────────────────────────────────────────────────────────

/// Why `--key-file` is refused by every command that can be handed one.
///
/// `PLAN.md` §8 specifies the second factor as `KDF_input = password ‖ H(factor)`,
/// but `dctl_core::Vault::init` and `::unlock` take a password and nothing else
/// in this build: there is no parameter through which the CLI could mix a factor
/// into the key-encryption key. Accepting the flag anyway would create — or
/// open — a vault protected by one factor while the command line says two, which
/// is the "reported as done when it did not happen" failure `PLAN.md` §6
/// forbids, made worse by being a *security* guarantee rather than a cosmetic
/// one.
///
/// Kept here rather than written out at each call site because `init` and every
/// unlock must give the identical reason. Two commands that disagree about
/// whether a factor is applied would leave the operator unable to determine what
/// actually protects their data, which is worse than either answer alone.
///
/// Delete this, and the refusals that quote it, on the day the engine grows a
/// factor parameter — not before.
pub const KEY_FILE_UNSUPPORTED_REASON: &str = "This build derives the key-encryption key from the password alone, so the \
     file named by --key-file is never read and the second factor cannot be \
     applied.";

// ─────────────────────────────────────────────────────────────────────────────
// Vault initialisation (`dctl init`)
// ─────────────────────────────────────────────────────────────────────────────

/// Shortest password accepted for a **new** vault.
///
/// The root key is 256 bits of CSPRNG output, so the password is the only part
/// of the envelope worth attacking. Argon2id makes each guess expensive, but no
/// KDF rescues a four-character password from an offline attacker who has the
/// envelope. Eight is the floor NIST SP 800-63B sets for a memorised secret.
///
/// Enforced only when a vault is *created*. Unlocking never re-applies today's
/// policy to yesterday's password — a rule change must never lock someone out of
/// data they already own.
pub const MIN_VAULT_PASSWORD_LEN: usize = 8;

/// Interpreter used to run `--password-command`.
///
/// A shell rather than a bare `exec`, because the flag exists to defer to an
/// existing secret manager and those invocations are pipelines
/// (`pass show vault | head -1`) far more often than they are single programs.
#[cfg(not(windows))]
pub const PASSWORD_COMMAND_SHELL: &str = "/bin/sh";
/// See the non-Windows definition.
#[cfg(windows)]
pub const PASSWORD_COMMAND_SHELL: &str = "cmd";

/// Flag that makes [`PASSWORD_COMMAND_SHELL`] read its command from the next
/// argument rather than from a script file.
#[cfg(not(windows))]
pub const PASSWORD_COMMAND_SHELL_FLAG: &str = "-c";
/// See the non-Windows definition.
#[cfg(windows)]
pub const PASSWORD_COMMAND_SHELL_FLAG: &str = "/C";

/// Column headers for the `dctl init` result table.
pub const INIT_COLUMN_SETTING: &str = "Setting";
/// See [`INIT_COLUMN_SETTING`].
pub const INIT_COLUMN_VALUE: &str = "Value";

/// Row labels in the `dctl init` result.
///
/// Spelled exactly as the JSON field names, in `snake_case`, so a script can be
/// ported between `--format text` and `--format json` by changing the parser and
/// nothing else. A test in the command module holds the two spellings together.
///
/// The first two are the whole point of the command: a vault has a sealed view
/// and an object view, and a run that reported only one of them would leave the
/// operator unable to address the half that needs no password.
pub const INIT_FIELD_VAULT_REMOTE: &str = "vault_remote";
/// See [`INIT_FIELD_VAULT_REMOTE`]. The object view's remote name.
pub const INIT_FIELD_STORE_REMOTE: &str = "store_remote";
/// See [`INIT_FIELD_VAULT_REMOTE`]. The location the objects are stored at.
pub const INIT_FIELD_BASE: &str = "base";
/// See [`INIT_FIELD_VAULT_REMOTE`].
pub const INIT_FIELD_INDEX: &str = "index";
/// See [`INIT_FIELD_VAULT_REMOTE`].
pub const INIT_FIELD_CREATED: &str = "created";
/// See [`INIT_FIELD_VAULT_REMOTE`].
pub const INIT_FIELD_PASSWORD_SOURCE: &str = "password_source";
/// See [`INIT_FIELD_VAULT_REMOTE`]. Whether the configuration now names the vault.
///
/// Separate from [`INIT_FIELD_CREATED`] because the two can genuinely differ: a
/// vault that exists on its store but whose addressing could not be written is
/// recoverable with `dctl config import`, and a run that reported one boolean
/// for both would leave a script unable to tell which half is missing.
pub const INIT_FIELD_REGISTERED: &str = "registered";

/// Suffix appended to `--name` to name the base store remote `dctl init`
/// registers alongside the vault.
///
/// The base gets a **name** because that is what makes separation of duties
/// structural rather than procedural: an offsite replication job addressed at
/// `archive-store:` moves ciphertext objects and needs no vault password at all,
/// so a backup operator can satisfy 3-2-1 without ever holding decryption
/// capability. A nameless base would force every such job to re-describe the
/// location, and a location typed twice is a location that eventually differs.
///
/// A hyphen rather than an underscore or a dot because it reads as one phrase in
/// a shell — `archive-store:` — and because it is already legal inside a remote
/// name ([`REMOTE_NAME_EXTRA_CHARS`]); a suffix that had to be quoted would make
/// the derived name worse than one the user picked.
pub const INIT_STORE_NAME_SUFFIX: &str = "-store";

// ─────────────────────────────────────────────────────────────────────────────
// `dctl config`
// ─────────────────────────────────────────────────────────────────────────────

/// Separator in a `key=value` setting typed on the command line.
///
/// Only the **first** occurrence splits, so a value may itself contain `=`
/// (an endpoint carrying a query string, a base64 blob) without quoting games.
pub const CONFIG_ASSIGNMENT_SEPARATOR: char = '=';

/// Key naming a remote's provider type inside its config section.
///
/// The one key every remote must have: it selects which backend
/// `crate::remote` builds, so a section without it is not a remote at all.
pub const CONFIG_REMOTE_TYPE_KEY: &str = "type";

/// Suffix of the temporary file a config rewrite is staged through.
///
/// The config file is replaced by `write temp → rename`, never by truncating
/// the original: a crash or a full disk halfway through a direct write would
/// leave a half-written TOML file, and the next run would report every remote as
/// missing rather than reporting a damaged file.
pub const CONFIG_TEMP_SUFFIX: &str = ".tmp";

/// Comment written at the top of a configuration file DCTL creates.
///
/// Stating the no-secrets rule *in the file* is the only version of it a user
/// reliably reads. Someone about to paste an application key into a section is
/// looking at this line at that exact moment (`PLAN.md` §14).
pub const CONFIG_FILE_HEADER: &str = "\
# DCTL configuration.
#
# This file holds NON-SECRET settings only: remote names, types, endpoints,
# buckets, regions and policy defaults. It is deliberately human-editable and
# safe to keep in version control.
#
# Credentials do NOT belong here. Provider keys live in the OS keychain, and the
# vault password is never stored at all — it is prompted for, or supplied by
# --password-command. Anything secret-shaped found in this file is printed as
# <redacted> by `dctl config show`, which hides the mistake but does not undo it.
";

/// Column headers for the `dctl config` tables.
///
/// Named constants rather than inline strings so the text output and the
/// generated documentation cannot drift apart.
pub const CONFIG_COLUMN_NAME: &str = "Name";
/// See [`CONFIG_COLUMN_NAME`].
pub const CONFIG_COLUMN_TYPE: &str = "Type";
/// See [`CONFIG_COLUMN_NAME`].
pub const CONFIG_COLUMN_KEY: &str = "Key";
/// See [`CONFIG_COLUMN_NAME`].
pub const CONFIG_COLUMN_VALUE: &str = "Value";
/// See [`CONFIG_COLUMN_NAME`].
pub const CONFIG_COLUMN_DESCRIPTION: &str = "Description";
/// See [`CONFIG_COLUMN_NAME`]. Whether a remote seals what passes through it.
pub const CONFIG_COLUMN_MODE: &str = "Mode";
/// See [`CONFIG_COLUMN_NAME`]. The remote at the end of a vault chain.
pub const CONFIG_COLUMN_STORE: &str = "Store";
/// See [`CONFIG_COLUMN_NAME`]. What `dctl config verify` found, per remote.
pub const CONFIG_COLUMN_STATUS: &str = "Status";

/// The two words `dctl config verify` uses for a remote's encryption behaviour.
///
/// The whole of invariant I4 in one column: what a remote does to the bytes
/// passing through it is a property of the **name typed**, fixed when the remote
/// was defined, and never a function of what the destination happens to contain
/// today. So the report can state it from the configuration alone — no data
/// access, no key, no network — which is exactly what makes it a compliance
/// pre-flight rather than an audit.
///
/// `sealed` and not `encrypted` because the word has to survive being read next
/// to a plain remote that is itself server-side encrypted at rest by its
/// provider. What DCTL promises is narrower and stronger: the bytes were sealed
/// before they left this machine.
pub const CONFIG_MODE_SEALED: &str = "sealed";
/// See [`CONFIG_MODE_SEALED`].
pub const CONFIG_MODE_PLAIN: &str = "plain";

/// Verdict `dctl config verify` prints for a remote with nothing wrong.
///
/// Spelled as a slug rather than a sentence because it lands in `--json` and in
/// a column a script greps.
pub const CONFIG_VERIFY_STATUS_OK: &str = "ok";

/// Findings `dctl config verify` reports, as stable slugs.
///
/// Each names a way a configuration can be *internally* wrong — reachable
/// without touching a byte of stored data — so a consumer can branch on the
/// kind of fault rather than on the wording of a message.
pub const CONFIG_FINDING_UNKNOWN_BASE: &str = "unknown-base";
/// See [`CONFIG_FINDING_UNKNOWN_BASE`].
pub const CONFIG_FINDING_CHAIN_CYCLE: &str = "chain-cycle";
/// See [`CONFIG_FINDING_UNKNOWN_BASE`].
pub const CONFIG_FINDING_CHAIN_TOO_DEEP: &str = "chain-too-deep";
/// See [`CONFIG_FINDING_UNKNOWN_BASE`].
pub const CONFIG_FINDING_ILLEGAL_NAME: &str = "illegal-name";
/// See [`CONFIG_FINDING_UNKNOWN_BASE`].
pub const CONFIG_FINDING_CASE_COLLISION: &str = "case-collision";
/// See [`CONFIG_FINDING_UNKNOWN_BASE`].
pub const CONFIG_FINDING_INCOMPLETE_SETTINGS: &str = "incomplete-settings";
/// See [`CONFIG_FINDING_UNKNOWN_BASE`].
pub const CONFIG_FINDING_PLAIN_AT_VAULT_LOCATION: &str = "plain-at-vault-location";

/// Separator between the fields of a rendered store [`location`].
///
/// A location is `provider:field|field`, and the fields are the settings that
/// decide *which physical place* a remote addresses — a bucket and its endpoint,
/// or a directory. The separator only has to be absent from those fields often
/// enough that two different places never render identically; a false match
/// costs a refusal a user can explain and undo, never a silent write to the
/// wrong place, so the safe direction is the one it errs in.
///
/// [`location`]: crate::config::Location
pub const LOCATION_FIELD_SEPARATOR: char = '|';

// ── Secret-shaped values ─────────────────────────────────────────────────────
//
// `PLAN.md` §14 puts no credentials in the config file at all, so in a correct
// installation none of the rules below ever fire. They exist because a *wrong*
// installation is exactly the one whose config gets pasted into a bug report:
// someone adds `secret_key = …` by hand, and `dctl config show` must not be the
// thing that publishes it. The rules therefore err towards over-redaction — a
// bucket name printed as `<redacted>` is an annoyance, a printed key is an
// incident.

/// Length at or above which an opaque token is treated as a secret.
///
/// Twenty-four characters is longer than every provider identifier DCTL prints
/// (a region, an endpoint host, a bucket) and shorter than every credential it
/// might meet: an AWS secret key is 40, a B2 application key 31, an OAuth
/// refresh token far more.
pub const SECRET_VALUE_MIN_LEN: usize = 24;

/// Non-alphanumeric characters that still count as part of an opaque token.
///
/// The union of the base64, base64url and hex alphabets' padding and separator
/// characters. A value containing anything *else* — a dot, a slash, a space, a
/// colon — is structured text such as a hostname or a path, not a raw token.
pub const SECRET_VALUE_EXTRA_CHARS: &[char] = &['+', '/', '=', '_', '-'];

/// Substrings that mark a value as a credential whatever its shape.
///
/// Matched case-sensitively, because each is a fixed protocol or vendor prefix:
/// PEM armour, an HTTP bearer scheme, and the two AWS access-key-id prefixes.
pub const SECRET_VALUE_MARKERS: &[&str] = &["-----BEGIN ", "Bearer ", "AKIA", "ASIA"];

/// Separator between a URL's scheme and its authority.
pub const URL_SCHEME_SEPARATOR: &str = "://";

/// Character separating a URL's userinfo from its host.
///
/// `https://user:password@host/path` carries a credential in plain sight, so a
/// value whose authority contains one is redacted whole rather than partially.
pub const URL_USERINFO_SEPARATOR: char = '@';

/// Environment variables consulted, in order, for the editor `dctl config edit`
/// launches. `VISUAL` wins because POSIX gives it precedence for full-screen
/// editors, which is what a human editing TOML wants.
pub const EDITOR_ENV_VARS: &[&str] = &["VISUAL", "EDITOR"];

/// Editor used when none of [`EDITOR_ENV_VARS`] is set.
///
/// `vi` is the only editor POSIX requires to exist; on Windows `notepad` is the
/// equivalent guaranteed presence.
#[cfg(not(windows))]
pub const DEFAULT_EDITOR: &str = "vi";
/// See the non-Windows definition.
#[cfg(windows)]
pub const DEFAULT_EDITOR: &str = "notepad";

/// Provider type naming a directory on this machine's filesystem.
///
/// Doubles as a *spec prefix*: `local:/srv/data` is the explicit escape hatch
/// that forces the rest of the argument to be read as a filesystem path, which
/// is the only way to name a directory whose own name would otherwise parse as
/// a remote (`local:archive:2024`, `local:C:\Users\me`).
pub const PROVIDER_LOCAL: &str = "local";

/// Provider type for a Backblaze B2 bucket, spoken over B2's native API.
pub const PROVIDER_B2: &str = "b2";

/// Provider type for Amazon S3 or any S3-compatible endpoint.
pub const PROVIDER_S3: &str = "s3";

/// Provider type for a Cloudflare R2 bucket.
///
/// Distinct from [`PROVIDER_S3`] even though R2 speaks the S3 protocol: R2
/// derives its endpoint from an account id and pins the SigV4 region, so the two
/// need different settings from the user.
pub const PROVIDER_R2: &str = "r2";

/// Remote provider types this build understands, each paired with the one-line
/// description `dctl config providers` prints.
///
/// The spelling in the first column is what a config section's
/// [`CONFIG_REMOTE_TYPE_KEY`] must contain. This table is *presentation and
/// validation only* — the backend registry in `crate::remote` decides what each
/// type actually builds. A type listed here with no arm there fails loudly at
/// connect time, which is the right failure: a wrong list can never cause a
/// silent fallback to the wrong provider.
pub const REMOTE_PROVIDER_TYPES: &[(&str, &str)] = &[
    (PROVIDER_LOCAL, "A directory on this machine's filesystem"),
    (PROVIDER_B2, "Backblaze B2 bucket"),
    (PROVIDER_S3, "Amazon S3, or any S3-compatible endpoint"),
    (PROVIDER_R2, "Cloudflare R2 bucket"),
];

/// POSIX permission bits that mean "readable by someone other than the owner".
///
/// `PLAN.md` §14 requires a warning when the config file is group- or
/// world-readable: it names buckets, endpoints and regions, which is free
/// reconnaissance for anyone who can read it.
#[cfg(unix)]
pub const CONFIG_FILE_EXPOSED_MODE_MASK: u32 = 0o077;

// ─────────────────────────────────────────────────────────────────────────────
// `config.toml` — the file itself (`crate::config`)
// ─────────────────────────────────────────────────────────────────────────────
//
// The block above governs how the file is *displayed*; this one governs how it
// is spelled, named, validated and written. `PLAN.md` §14 is the whole reason
// the file has rules at all: it is deliberately a *non-secret* artefact that a
// user is encouraged to hand-edit and even commit to version control, which
// only works if what may appear in it is defined narrowly enough to be
// enforced on load.

/// Provider type naming a **vault wrapper** rather than a place to put bytes.
///
/// Deliberately absent from [`REMOTE_PROVIDER_TYPES`]: a vault remote stores
/// nothing itself, it wraps a base remote and encrypts on the way through
/// (`PLAN.md` §14), so `dctl config providers` must not offer it as a
/// destination and `crate::remote` has no backend arm for it. It is still a
/// legal value of [`CONFIG_REMOTE_TYPE_KEY`], which is why it is named here
/// beside the four real providers instead of inside the table with them.
///
/// Spelled `vault` and not rclone's `crypt` because the two are not the same
/// kind of thing. rclone's crypt is a stateless transformation applied over a
/// base remote: give it the same password and it produces the same ciphertext,
/// and there is nothing else to it. This is an object with identity — a
/// `vault_id` in the DKE2 envelope, key slots that can be added and revoked
/// (password, mnemonic, later Shamir and Secure Enclave), a root key that never
/// changes, an encrypted index and a hash-chained audit log. Calling that
/// "crypt" would describe a fraction of it and invite the assumption that two
/// remotes with the same password are interchangeable, which they are not.
///
/// No `crypt` alias is accepted. In a tool whose ethos is that ambiguity never
/// resolves silently, one spelling of rclone muscle memory is not worth two
/// permanent names for one concept.
pub const PROVIDER_VAULT: &str = "vault";

// ── The file-format vocabulary ───────────────────────────────────────────────
//
// Four of the keys below are spelled nowhere else in the running binary, and
// that is the point rather than an oversight. `serde` derives a remote's TOML
// keys from the field names on `RemoteDef`, and a `#[serde(rename = …)]` takes
// a literal, not a constant — so the schema cannot be *made* to read from here.
// What these do instead is give the schema a second, independent statement of
// itself that the tests at the bottom of this file check the whole set against
// (TOML-safe spelling, lower case, no duplicates) and that `config/model.rs`'s
// round-trip tests pin the serialiser to. Deleting one would not remove a key
// from the file format; it would remove the only thing that notices when a
// field rename silently changes the format under a user's existing config.
//
// `#[allow(dead_code)]` is therefore load-bearing on exactly these four, and
// must not be widened to the section: `CONFIG_KEY_BASE` and the provider keys
// beside them are read by `remote::resolve`, and if one of *those* ever stops
// being read, that is a resolver that quietly ignores a setting — a warning
// worth keeping.

/// Top-level table holding every named remote.
///
/// The config file has exactly one top-level key today. Naming it keeps the
/// TOML spelling and the `Config` field from drifting apart, and a test asserts
/// the serialiser really emits this word.
#[allow(dead_code)]
pub const CONFIG_KEY_REMOTES: &str = "remotes";

/// Setting naming the remote a vault remote wraps.
///
/// The value is a bare remote **name**, never a `name:path` spec. Allowing a
/// spec here would reintroduce exactly the ambiguity [`MIN_REMOTE_NAME_LEN`]
/// exists to prevent — `base = "c:/data"` would be unreadable as either — so the
/// subdirectory is a separate setting ([`CONFIG_KEY_BASE_PATH`]) and this one
/// has one unambiguous meaning.
pub const CONFIG_KEY_BASE: &str = "base";

/// Setting naming the subdirectory of the base remote a vault remote occupies.
///
/// Optional, and a *logical* path (`/`-separated, no `..`) rather than a native
/// one, because the same config must resolve identically on every platform.
#[allow(dead_code)]
pub const CONFIG_KEY_BASE_PATH: &str = "base_path";

/// Setting naming a remote's chunk size, in bytes.
///
/// Its meaning is per-provider, which is why it is one key rather than several:
/// on a cloud remote it is the multipart part size, on a vault remote it is the
/// AEAD chunk size that decides seek granularity (`PLAN.md` §3). Absent means
/// "use the profile default", so a config written today does not freeze a
/// tuning decision that a later release improves.
#[allow(dead_code)]
pub const CONFIG_KEY_CHUNK_SIZE: &str = "chunk_size";

/// Setting naming a remote's default verification strength.
///
/// Per-remote because the cost/assurance trade-off in `PLAN.md` §6 step 5 is a
/// property of the destination: a full read-back is cheap against a local disk
/// and doubles egress against a cloud bucket. `--verify` on the command line
/// still overrides it.
#[allow(dead_code)]
pub const CONFIG_KEY_VERIFY: &str = "verify";

/// Setting marking a store remote's location as **vault-only**.
///
/// Set on the `<name>-store` remote `dctl init` creates, and the config-level
/// half of invariant I2: foreign plaintext is never written into a vault's
/// object store. The flag says one thing — *no plain remote may address this
/// location* — and it is enforced by [`crate::config::validate`], which is to
/// say at the earliest possible moment: when a configuration naming a second,
/// plain remote at the same place is written or read, not hours later when a
/// transfer reaches it.
///
/// A declaration rather than a lock. Nothing stops an operator from clearing it
/// with `dctl config update`, and nothing should: it protects against the
/// accident of pointing a plain remote at a store, not against an administrator
/// who has decided otherwise. The invariant that has no override is the one
/// enforced on the write path — a vault remote always seals.
///
/// `#[allow(dead_code)]` for the same reason as the four keys above it: `serde`
/// derives the TOML spelling from the field name on `RemoteDef` and cannot be
/// made to read it from here, so this is the second, independent statement of
/// the schema that the tests check the set against.
#[allow(dead_code)]
pub const CONFIG_KEY_REQUIRE_VAULT: &str = "require_vault";

/// Longest accepted remote name.
///
/// A remote name is typed on every command line and printed in every table, so
/// the ceiling is an ergonomic one rather than a technical limit. Sixty-four
/// characters is longer than any name anybody types deliberately and short
/// enough that a name can never be the reason a listing wraps — while still
/// bounding what a hand-edited (or hostile) config can force the CLI to render.
pub const MAX_REMOTE_NAME_LEN: usize = 64;

/// Longest chain of remotes a vault remote may resolve through, counting itself
/// and the plain remote it ultimately lands on.
///
/// Vault-over-vault is legal — a second wrap costs a second AEAD pass and is a
/// defensible thing to ask for — but a chain this long is a mistake rather than
/// a design, and the bound turns "the config is subtly wrong" into a precise
/// error instead of a deep recursion. Cycles are caught separately and exactly,
/// by the visited set; this is the guard against the merely absurd.
pub const MAX_VAULT_CHAIN_DEPTH: usize = 8;

/// Separator between links when a vault chain or a cycle is printed.
///
/// An ASCII arrow, not `→`: this text lands in error messages that are read on
/// legacy Windows consoles and scraped out of CI logs, where a multi-byte glyph
/// becomes mojibake.
pub const CONFIG_CHAIN_ARROW: &str = " -> ";

/// Separator between the levels of a dotted TOML key path (`remotes.vault.base`).
///
/// TOML's own key separator, used when a validation error has to say *where* in
/// the file the offending key was.
pub const CONFIG_KEY_PATH_SEPARATOR: char = '.';

/// Separator between the config file's name and the writing process's id in the
/// staging file's name.
///
/// The process id is in the name so two DCTL processes saving at once stage to
/// different files and the loser of the rename race simply loses, rather than
/// the two interleaving into one corrupt file.
pub const CONFIG_TEMP_NAME_SEPARATOR: char = '.';

/// POSIX permission bits enforced on the directory holding the config.
///
/// Owner-only, matching [`CONFIG_FILE_MODE`]: a `0600` file inside a
/// world-writable directory can still be replaced wholesale by anyone who can
/// write the directory, so hardening the file alone would be theatre.
#[cfg(unix)]
pub const CONFIG_DIR_MODE: u32 = 0o700;

// ─────────────────────────────────────────────────────────────────────────────
// Remote specs & the backend registry (`crate::remote`)
// ─────────────────────────────────────────────────────────────────────────────
//
// Two vocabularies meet here. The *spec* vocabulary decides where `name:path`
// splits — and, critically, when it must not split at all, because
// `C:\Users\me` is a path and not a remote called `C`. The *settings*
// vocabulary is the set of keys a remote's config section may carry and the
// environment variables its credentials arrive in.
//
// The split between those last two is `PLAN.md` §14 in one line: a bucket, an
// endpoint, a region and an account id are non-secret and belong in the config
// file, while an access key belongs only in the environment (or, later, the OS
// keychain). Nothing that reads a secret from the config file is listed here,
// because there is no such key.

/// Native path separator on Windows.
///
/// Used alongside [`PATH_SEPARATOR`] wherever a *user-typed* string is examined:
/// a candidate remote name containing either separator is really a relative
/// path that happens to contain a colon (`photos/holiday:2024`), and splitting
/// it would invent a remote out of a directory name.
pub const WINDOWS_PATH_SEPARATOR: char = '\\';

/// Every character that can separate the components of a path a person typed.
///
/// The same list on every platform, and deliberately so. A logical path is the
/// hash input behind an index key, so the two directions must agree exactly: a
/// spec splits on all of these ([`crate::platform::path::clean_logical`]), and a
/// filename containing any of them therefore has no logical spelling at all
/// ([`crate::platform::path::to_logical_component`] refuses it). Were the list
/// platform-dependent, `a\b.txt` would be one key on Linux and two on Windows —
/// one file, two objects, and a vault that stops round-tripping the moment it
/// crosses machines.
pub const LOGICAL_PATH_SEPARATORS: &[char] = &[PATH_SEPARATOR, WINDOWS_PATH_SEPARATOR];

/// Leading character that marks an argument as a relative path.
///
/// `.` and `..` are paths on every platform, so a candidate remote name that
/// starts with one is never a remote — without this rule `..:backup` would
/// resolve as a remote literally named `..`.
pub const RELATIVE_PATH_MARKER: char = '.';

/// Setting naming the bucket a cloud remote stores objects in.
///
/// Non-secret by design: a bucket name is not a credential, and keeping it in
/// the config file is what makes a remote reproducible from a version-controlled
/// `config.toml`.
pub const CONFIG_KEY_BUCKET: &str = "bucket";

/// Setting naming an S3-compatible endpoint URL.
///
/// Required for every S3 deployment that is not AWS — Wasabi, MinIO, B2's S3
/// gateway — and therefore a per-remote setting rather than a compiled-in
/// default that would quietly point somebody's data at the wrong provider.
pub const CONFIG_KEY_ENDPOINT: &str = "endpoint";

/// Setting naming the SigV4 region an S3 remote signs requests for.
pub const CONFIG_KEY_REGION: &str = "region";

/// Setting naming the Cloudflare account id an R2 remote belongs to.
///
/// R2 derives its endpoint from this rather than being given one, so it is R2's
/// equivalent of [`CONFIG_KEY_ENDPOINT`] and not an extra credential.
pub const CONFIG_KEY_ACCOUNT: &str = "account";

/// Setting naming the root directory of a `local` remote.
///
/// A directory, never a file: the value is the root that logical vault paths are
/// resolved beneath, exactly as the bucket is for a cloud remote.
pub const CONFIG_KEY_PATH: &str = "path";

/// Environment settings carrying provider credentials, never read from the
/// config file (`PLAN.md` §14 — rclone's reversibly-obscured secrets are the
/// specific mistake being avoided).
///
/// Spelled as suffixes because `dctl_meta::env_var` prefixes each with the
/// product's environment prefix, so a rebrand renames every variable at once.
pub const ENV_B2_KEY_ID: &str = "B2_KEY_ID";
/// See [`ENV_B2_KEY_ID`].
pub const ENV_B2_APP_KEY: &str = "B2_APP_KEY";
/// See [`ENV_B2_KEY_ID`].
pub const ENV_S3_ENDPOINT: &str = "S3_ENDPOINT";
/// See [`ENV_B2_KEY_ID`].
pub const ENV_S3_REGION: &str = "S3_REGION";
/// See [`ENV_B2_KEY_ID`].
pub const ENV_S3_ACCESS_KEY: &str = "S3_ACCESS_KEY";
/// See [`ENV_B2_KEY_ID`].
pub const ENV_S3_SECRET_KEY: &str = "S3_SECRET_KEY";
/// See [`ENV_B2_KEY_ID`].
pub const ENV_R2_ACCOUNT_ID: &str = "R2_ACCOUNT_ID";
/// See [`ENV_B2_KEY_ID`].
pub const ENV_R2_ACCESS_KEY: &str = "R2_ACCESS_KEY";
/// See [`ENV_B2_KEY_ID`].
pub const ENV_R2_SECRET_KEY: &str = "R2_SECRET_KEY";

// ─────────────────────────────────────────────────────────────────────────────
// Integrity family — `verify`, `check`, `scrub`, `hashsum`
// ─────────────────────────────────────────────────────────────────────────────
//
// These four commands are what DCTL has and a plain copier does not
// (`PLAN.md` §6, §13.4), and the strings below are the part of them that *other
// software* reads: verdict slugs land in `--json`, the combined-file marks land
// in a diff someone greps, and the `hashsum` separator has to satisfy
// `sha256sum -c` byte for byte. They are a compatibility surface, not
// decoration — which is why each is named once here rather than typed inline at
// the two or three places it is used.

/// Sentence appended to every integrity-failure message.
///
/// The wording is the whole point of exit code 21. When AEAD authentication
/// fails DCTL does not hand back best-effort bytes, it hands back nothing, and
/// the person reading the error has to know that without consulting a manual —
/// the natural assumption on seeing a read error is that *some* of the data got
/// through, and here none of it did.
pub const INTEGRITY_NOT_SERVED_NOTICE: &str = "the data was NOT served";

/// Remediation hint attached to an integrity failure.
///
/// Names the two actions that actually help: restore the object from another
/// copy of the 3-2-1 set (`PLAN.md` §13.3), then scrub, because bit rot and a
/// failing provider are rarely confined to the one object you happened to read
/// (§13.4).
pub const INTEGRITY_FAILURE_HINT: &str = "Restore the affected objects from another copy, then run `dctl scrub` to \
     check the rest of the dataset — corruption is seldom limited to one object.";

/// Per-object verdict slugs shared by `verify` and `scrub`.
///
/// Four words rather than a bare pass/fail, because the operator's next action
/// differs for each: `corrupt` means restore from redundancy, `missing` means
/// the index and the provider disagree and the index may need a rebuild, and
/// `unreadable` means the provider never answered, so a retry may be all that is
/// needed.
pub const VERDICT_OK: &str = "ok";
/// See [`VERDICT_OK`]. Stored bytes failed authentication — real damage.
pub const VERDICT_CORRUPT: &str = "corrupt";
/// See [`VERDICT_OK`]. Indexed, but the object is not at the provider.
pub const VERDICT_MISSING: &str = "missing";
/// See [`VERDICT_OK`]. The provider could not serve the object at all.
pub const VERDICT_UNREADABLE: &str = "unreadable";

/// `check` verdict slugs, one per way two sides can disagree.
///
/// Spelled exactly like the flags that capture them (`--missing-on-src`), so a
/// reader of the JSON never has to translate between two vocabularies.
pub const DIFFERENCE_MATCH: &str = "match";
/// See [`DIFFERENCE_MATCH`]. On both sides, contents disagree.
pub const DIFFERENCE_DIFFER: &str = "differ";
/// See [`DIFFERENCE_MATCH`]. Only at the destination.
pub const DIFFERENCE_MISSING_ON_SRC: &str = "missing-on-src";
/// See [`DIFFERENCE_MATCH`]. Only at the source.
pub const DIFFERENCE_MISSING_ON_DST: &str = "missing-on-dst";
/// See [`DIFFERENCE_MATCH`]. One side could not be read, so no verdict is
/// possible — never silently folded into "match".
pub const DIFFERENCE_ERROR: &str = "error";

/// Names of the field sets `check` can compare two sides by, as they appear in
/// `--json` output.
///
/// Spelled after the flags that select them (`--size-only`, `--checksum`) so the
/// report names the setting the user typed. The default has no flag of its own,
/// and is named for what it looks at rather than for being the default — a
/// report that said `"comparison": "default"` would age badly the first time the
/// default changed.
pub const COMPARISON_SIZE_AND_MODTIME: &str = "size-and-modtime";
/// See [`COMPARISON_SIZE_AND_MODTIME`].
pub const COMPARISON_SIZE_ONLY: &str = "size-only";
/// See [`COMPARISON_SIZE_AND_MODTIME`]. The only one that proves the contents
/// match rather than that the metadata agrees.
pub const COMPARISON_CHECKSUM: &str = "checksum";

/// One-character marks written by `check --combined`.
///
/// Identical to rclone's, because the combined file is precisely the artefact
/// people already have `awk` one-liners for: `=` same, `-` only at the
/// destination, `+` only at the source, `*` different, `!` could not compare.
pub const COMBINED_MARK_MATCH: char = '=';
/// See [`COMBINED_MARK_MATCH`].
pub const COMBINED_MARK_MISSING_ON_SRC: char = '-';
/// See [`COMBINED_MARK_MATCH`].
pub const COMBINED_MARK_MISSING_ON_DST: char = '+';
/// See [`COMBINED_MARK_MATCH`].
pub const COMBINED_MARK_DIFFER: char = '*';
/// See [`COMBINED_MARK_MATCH`].
pub const COMBINED_MARK_ERROR: char = '!';

/// Separator between a combined-file mark and the path it describes.
pub const COMBINED_MARK_SEPARATOR: char = ' ';

/// Separator between a hash and its path in `hashsum` output.
///
/// **Exactly two spaces.** GNU coreutils writes `<hash>␠<mode><path>`, where the
/// mode character is a space for text and `*` for binary; two spaces is
/// therefore the text-mode spelling, and it is what `sha256sum -c` parses. This
/// constant is what makes
/// `dctl hashsum sha256 vault: > SUMS && sha256sum -c SUMS` work, so it is a
/// wire format rather than a formatting preference.
pub const HASHSUM_FIELD_SEPARATOR: &str = "  ";

/// The coreutils *binary* mode marker, written in place of the second space of
/// [`HASHSUM_FIELD_SEPARATOR`] when `--binary` is passed.
pub const HASHSUM_BINARY_MARKER: char = '*';

/// Hex digest widths, one per algorithm `hashsum` accepts.
///
/// Properties of the algorithms rather than choices — BLAKE3's default 32-byte
/// output, SHA-1's 20 and SHA-256's 32, each doubled for hex. Named here so the
/// place that validates a checksum file and the place that sizes a column agree,
/// and so a fourth algorithm arrives as one new row instead of a hunt through
/// the command.
pub const HASH_HEX_LEN_BLAKE3: usize = 64;
/// See [`HASH_HEX_LEN_BLAKE3`].
pub const HASH_HEX_LEN_SHA1: usize = 40;
/// See [`HASH_HEX_LEN_BLAKE3`].
pub const HASH_HEX_LEN_SHA256: usize = 64;

/// `--sample-percent` value meaning "read every object": a full scrub.
///
/// The default, because a scrub that silently skipped most of the dataset would
/// report health it never measured — exactly the failure §13.4 exists to
/// prevent. Sampling is an explicit choice made to bound egress cost on a vault
/// too large to read in one night, never something DCTL decides for you.
pub const SCRUB_FULL_SAMPLE_PERCENT: u8 = 100;

/// Smallest accepted `--sample-percent`.
///
/// One, not zero: a zero-percent scrub reads nothing and could therefore only
/// ever report "healthy" without evidence. Asking for no work is spelled by not
/// running the command.
pub const SCRUB_MIN_SAMPLE_PERCENT: u8 = 1;

/// Basis the sampling decision is taken modulo.
///
/// Percent, matching the flag's units, so the number a user types and the
/// arithmetic that selects objects cannot drift apart.
pub const SCRUB_SAMPLE_BASIS: u64 = 100;

/// Domain-separation label for the keyed hash that selects sampled objects.
///
/// Keyed rather than plain BLAKE3 so two different runs cover two different
/// slices: with a plain hash, `--sample-percent 10` would read the same tenth
/// forever and the other ninety percent would never be scrubbed at all.
pub const SCRUB_SAMPLE_KEY_CONTEXT: &str = "dctl scrub sample selector v1";

/// `--max-errors` value meaning "no limit": keep scrubbing to the end.
///
/// The default. A scrub's job is to survey the whole dataset, and stopping at
/// the first damaged object would hide *how widespread* the damage is — which is
/// the most important thing the report has to say.
pub const SCRUB_MAX_ERRORS_UNLIMITED: u64 = 0;

/// Health grades reported by `scrub`, in worsening order.
///
/// Three grades, not two, because "damage was found and repaired from
/// redundancy" is a materially different situation from "damage was found and
/// could not be repaired". The first is the system working as designed; the
/// second is a countdown to data loss, and collapsing them into one word would
/// hide the difference at the exact moment it matters.
pub const HEALTH_HEALTHY: &str = "healthy";
/// See [`HEALTH_HEALTHY`]. Damage found, all of it repaired.
pub const HEALTH_DEGRADED: &str = "degraded";
/// See [`HEALTH_HEALTHY`]. Damage found that could not be repaired.
pub const HEALTH_DAMAGED: &str = "damaged";

/// Column headers for the integrity family's text reports.
///
/// Prefixed rather than generic (`INTEGRITY_COLUMN_PATH`, not `COLUMN_PATH`) so
/// these four commands can change their report layout without dragging every
/// listing command's columns along with them, following the same convention as
/// [`CONFIG_COLUMN_NAME`].
pub const INTEGRITY_COLUMN_STATUS: &str = "Status";
/// See [`INTEGRITY_COLUMN_STATUS`].
pub const INTEGRITY_COLUMN_SIZE: &str = "Size";
/// See [`INTEGRITY_COLUMN_STATUS`].
pub const INTEGRITY_COLUMN_PATH: &str = "Path";
/// See [`INTEGRITY_COLUMN_STATUS`]. Carries the reason behind a non-`ok`
/// verdict; empty for the rows that passed.
pub const INTEGRITY_COLUMN_DETAIL: &str = "Detail";

// ─────────────────────────────────────────────────────────────────────────────
// Transfer family — `copy`, `move`, `sync`, `copyto`, `moveto`
// ─────────────────────────────────────────────────────────────────────────────
//
// Everything the transfer family needs in order to decide *what* it would do,
// before a single byte moves. The plan is what makes `--dry-run` trustworthy: it
// comes out of the same code the executor consumes, so what a dry run prints is
// exactly what a real run would perform.

/// Characters other than letters and digits that may appear in a remote name.
///
/// Deliberately tiny. A remote name is the left half of `name:path`, so anything
/// that can also appear in a path — `/`, `\`, a second `:` — would make a spec
/// ambiguous. Hyphen, underscore and dot are the separators people already use
/// in `b2-prod`, `s3_backup`, `vault.old`, and none can be mistaken for a path
/// component.
pub const REMOTE_NAME_EXTRA_CHARS: &[char] = &['-', '_', '.'];

/// Tolerance, in seconds, when comparing two modification times.
///
/// One second, not zero, because timestamp resolution is the least portable
/// thing about a filesystem: FAT stores two-second granularity, S3 and B2 return
/// whole seconds, and an SMB share can round differently from the disk beneath
/// it. With a zero window, a round trip through any of them makes every file
/// look modified and a `sync` re-uploads the entire dataset on every run.
///
/// Mirrors rclone's `--modify-window`, so a user porting a script sees the same
/// set of files treated as unchanged.
pub const DEFAULT_MODIFY_WINDOW_SECS: u64 = 1;

/// Whether a local directory walk follows symbolic links.
///
/// It does not. A link pointing at one of its own ancestors turns a walk into an
/// infinite loop, and a link pointing outside the transfer root would copy data
/// the user never named — silently, and past whatever `--exclude` they wrote.
/// Links are counted and reported rather than followed, so their presence is
/// never hidden.
pub const WALK_FOLLOW_SYMLINKS: bool = false;

/// Column headers of the transfer plan table.
///
/// Prefixed rather than generic, following [`INTEGRITY_COLUMN_STATUS`]'s
/// convention: the transfer family can change its report layout without
/// disturbing any other command's columns.
pub const PLAN_COLUMN_ACTION: &str = "Action";
/// See [`PLAN_COLUMN_ACTION`].
pub const PLAN_COLUMN_SIZE: &str = "Size";
/// See [`PLAN_COLUMN_ACTION`].
pub const PLAN_COLUMN_PATH: &str = "Path";

/// Action slugs.
///
/// A machine contract twice over: each is the `action` field of the JSON plan
/// *and* the first column of the text plan, so `dctl sync --dry-run | grep
/// '^delete'` and `… --json | jq 'select(.action=="delete")'` select the same
/// rows. One constant per action is what keeps the two renderings from drifting.
pub const PLAN_ACTION_COPY: &str = "copy";
/// See [`PLAN_ACTION_COPY`]. The destination exists but differs.
pub const PLAN_ACTION_UPDATE: &str = "update";
/// See [`PLAN_ACTION_COPY`]. Present at the destination, absent at the source.
pub const PLAN_ACTION_DELETE: &str = "delete";
/// See [`PLAN_ACTION_COPY`]. Proven identical, or excluded by a flag.
pub const PLAN_ACTION_SKIP: &str = "skip";
/// See [`PLAN_ACTION_COPY`]. An empty source directory to recreate.
pub const PLAN_ACTION_MKDIR: &str = "mkdir";

/// Separator drawn between a source path and a differing destination path.
///
/// ASCII, not `→`: the plan goes to stdout and therefore into pipes, where a
/// non-UTF-8 consumer must still be able to read it.
pub const PLAN_PATH_ARROW: &str = " -> ";

/// Why an entry carries the action it does.
///
/// Stable slugs for the same reason as [`PLAN_ACTION_COPY`]: they appear in the
/// JSON plan and in the text plan's verbose column, and an operator asking "why
/// is this being re-uploaded?" must get an answer that does not change wording
/// between releases.
pub const PLAN_REASON_MISSING: &str = "missing-at-destination";
/// See [`PLAN_REASON_MISSING`]. Both sides exist; the byte counts disagree.
pub const PLAN_REASON_SIZE: &str = "size-differs";
/// See [`PLAN_REASON_MISSING`]. Same size, source modified more recently.
pub const PLAN_REASON_MODIFIED: &str = "modified";
/// See [`PLAN_REASON_MISSING`]. Content hashes disagree (`--checksum`).
pub const PLAN_REASON_CHECKSUM: &str = "checksum-differs";
/// See [`PLAN_REASON_MISSING`]. Proven the same; nothing to do.
pub const PLAN_REASON_IDENTICAL: &str = "identical";
/// See [`PLAN_REASON_MISSING`]. Present at the destination (`--ignore-existing`).
pub const PLAN_REASON_EXISTS: &str = "exists";
/// See [`PLAN_REASON_MISSING`]. Destination is newer (`--update`).
pub const PLAN_REASON_DESTINATION_NEWER: &str = "destination-newer";
/// See [`PLAN_REASON_MISSING`]. At the destination only — a `sync` extra.
pub const PLAN_REASON_EXTRA: &str = "not-at-source";
/// See [`PLAN_REASON_MISSING`]. An empty source directory
/// (`--create-empty-src-dirs`).
pub const PLAN_REASON_EMPTY_SOURCE_DIR: &str = "empty-source-dir";
/// See [`PLAN_REASON_MISSING`]. The destination was never listed
/// (`--no-traverse`), so every source file is assumed absent.
pub const PLAN_REASON_UNTRAVERSED: &str = "destination-not-listed";

/// Fraction of a destination whose removal by one `sync` is worth shouting
/// about.
///
/// Half. A sync that deletes most of what it finds is usually a mistyped source
/// or a source listing that failed open, and from inside the process both look
/// identical to "the user really did mean to empty this tree". The warning is
/// loud but never blocking: refusing would break the legitimate case, and DCTL's
/// answer to a dangerous command is to make it visible, not to overrule it.
pub const SYNC_DELETE_ALARM_FRACTION: f64 = 0.5;

/// How many refused paths an `--immutable` failure names before eliding the
/// rest.
///
/// Ten. The message has to be actionable at a glance — the first few paths are
/// what tell an operator whether they pointed at the wrong destination or hit
/// one genuinely re-sent file — while a `sync` of a million changed files must
/// not spray a million paths at stderr on its way out. Ten fits in any terminal
/// without scrolling and is far more than is needed to recognise a mistyped
/// root; the *count* in the same sentence is always the complete answer, and
/// re-running with `--dry-run` and without `--immutable` prints the full list as
/// an ordinary plan.
pub const IMMUTABLE_REFUSAL_SAMPLE: usize = 10;

/// Remediation hint attached to an `--immutable` refusal by the transfer family.
///
/// It names the two ways out — a destination that does not already hold these
/// objects, or dropping the flag — because the refusal is not a malfunction to
/// work around: the flag was asked for precisely so that this run would stop.
/// The `--dry-run` suggestion is what turns the elided list back into a complete
/// one without anybody having to guess at what was hidden.
pub const IMMUTABLE_REFUSAL_HINT: &str = "--immutable allows only additions. Point the transfer at a destination that \
     does not already hold these objects, or drop --immutable. To see the full \
     list, re-run with --dry-run and without --immutable.";

/// Reason reported when `--immutable` meets `--no-traverse`.
///
/// The two flags ask for incompatible things, and the incompatibility is not
/// cosmetic: `--no-traverse` says "do not list the destination", so every source
/// file is planned as a first-time copy whether or not something is already
/// there, and the overwrite `--immutable` exists to forbid becomes invisible to
/// the planner. Honouring the pair would mean silently downgrading a guarantee
/// to a hope, so the combination is refused the same way
/// `touch --no-create --immutable` is.
pub const IMMUTABLE_NO_TRAVERSE_CONFLICT: &str = "--immutable and --no-traverse contradict each other: --no-traverse never lists \
     the destination, so an overwrite cannot be detected";

/// Remediation hint attached to [`IMMUTABLE_NO_TRAVERSE_CONFLICT`].
pub const IMMUTABLE_NO_TRAVERSE_HINT: &str = "Drop --no-traverse so the destination is listed and --immutable can be \
     enforced, or drop --immutable if re-sending over whatever is already there \
     is acceptable.";

/// Stable operation names for the transfer family.
///
/// The same words [`crate::cli::Command::name`] returns, and the same words that
/// land in the `op` field of every log span and audit record. Named here because
/// each is quoted by its command's error messages and JSON output as well, and a
/// verb that spelled itself two ways would be two operations to anyone querying
/// the audit log after the fact.
pub const TRANSFER_COMMAND_COPY: &str = "copy";
/// See [`TRANSFER_COMMAND_COPY`].
pub const TRANSFER_COMMAND_MOVE: &str = "move";
/// See [`TRANSFER_COMMAND_COPY`].
pub const TRANSFER_COMMAND_SYNC: &str = "sync";
/// See [`TRANSFER_COMMAND_COPY`].
pub const TRANSFER_COMMAND_COPYTO: &str = "copyto";
/// See [`TRANSFER_COMMAND_COPY`].
pub const TRANSFER_COMMAND_MOVETO: &str = "moveto";

/// Feature name reported when a transfer command reaches the engine boundary.
///
/// One constant, because the wording is a promise: the command parsed, the plan
/// is real, and the *only* missing piece is execution. Five commands phrasing
/// that differently would read as five separate bugs.
pub const TRANSFER_ENGINE_FEATURE: &str = "the verified-write transfer engine";

/// Remediation hint attached to [`TRANSFER_ENGINE_FEATURE`].
pub const TRANSFER_ENGINE_HINT: &str = "The current engine moves whole files through memory, so very large objects \
     are refused rather than attempted. Streaming transfers (PLAN.md §6, §16.2) \
     lift this limit. Use --dry-run to see exactly what would be transferred.";

/// Object key under which a vault stores its wrapped root key.
///
/// Mirrors `dctl_core`'s own layout constant, which is private to that crate.
/// The duplication is deliberate and narrow: the CLI needs to *recognise* a
/// vault directory without unlocking it, so that a plain filesystem copy into
/// one can be refused rather than silently writing plaintext next to the
/// envelope. If `dctl-core` ever exposes this, delete this constant and use
/// theirs — a test in `commands::transfer::engine` pins the behaviour either way.
pub const VAULT_ENVELOPE_OBJECT_KEY: &str = "system/envelope.bin";

// ── The envelope header, as `docs/FORMAT.md` §2 freezes it ───────────────────
//
// Enough of the DKE1 header to answer one question — *is there a vault here?* —
// and deliberately not one byte more. Nothing below can decrypt anything, and
// nothing below needs a key: the slots, their KDF parameters and the wrapped
// root key are `dctl-crypto`'s business, and reading them here would be a second
// implementation of a format that already has one.
//
// The question matters at exactly two moments. `dctl init` must refuse to
// overwrite an envelope that already exists, because replacing one orphans every
// object stored under it; and `dctl config import` must confirm that the
// location it is being asked to address really is a vault's store, rather than
// writing a plausible-looking pair of remotes that point at an empty bucket.
//
// These are safe to state independently of `dctl-core` because `PLAN.md` D8/D9
// freeze them **forever**: a 20-year restorability promise is exactly the
// promise that the magic, the version byte and the slot-count bound cannot be
// revised. A field that could change would not belong here.

/// Magic that opens a `DKE1` envelope (`docs/FORMAT.md` §2, offset 0).
pub const VAULT_ENVELOPE_MAGIC: &[u8] = b"DKE1";

/// Envelope format version this build recognises (`docs/FORMAT.md` §2, offset 4).
///
/// A *newer* version is reported as a vault DCTL cannot address rather than as
/// "no vault here": the difference is between telling an operator to upgrade and
/// telling them their data is not where they left it.
pub const VAULT_ENVELOPE_VERSION: u8 = 1;

/// Bytes of the envelope needed to recognise one: magic, version, `vault_id` and
/// `slot_count` (`docs/FORMAT.md` §2).
///
/// Fetched as a range rather than as a whole object so recognition costs one
/// small ranged GET against a cloud provider instead of a full download.
pub const VAULT_ENVELOPE_HEADER_LEN: u64 = 23;

/// Offset of the `slot_count` field within the envelope header.
pub const VAULT_ENVELOPE_SLOT_COUNT_OFFSET: usize = 21;

/// Bounds `docs/FORMAT.md` §2 puts on `slot_count`: at least one slot, at most
/// 64.
///
/// Checked because a file that merely *starts* with four plausible bytes is not
/// an envelope, and treating one as a vault would make `dctl config import`
/// write addressing for something that cannot be unlocked.
pub const VAULT_ENVELOPE_MIN_SLOTS: u16 = 1;
/// See [`VAULT_ENVELOPE_MIN_SLOTS`].
pub const VAULT_ENVELOPE_MAX_SLOTS: u16 = 64;

/// Refusal shown when a plain write lands in a vault the configuration does not
/// describe.
///
/// The *fallback* wording, and it says so. When a store remote claims the
/// location, the refusal names both views — which remote seals, which one
/// addresses the ciphertext — and needs no constant because it is built from
/// those names. This one is for the location no section describes: an imported
/// vault, a directory moved by hand, a store registered on another machine.
/// There is no remote to offer, so the hint says what is missing and how to
/// supply it rather than guessing.
///
/// It closes by restating the invariant, because this is the moment a user is
/// most likely to expect the tool to "just encrypt it": what a command encrypts
/// is decided by the remote name typed, and never by what a destination happens
/// to contain.
pub const PLAIN_WRITE_INTO_VAULT_HINT: &str = "That directory holds a vault envelope, and no configured remote names \
     the location — so DCTL cannot tell you which vault remote addresses it. \
     Writing here as a plain filesystem path would store your data unencrypted \
     beside the ciphertext. Run `dctl config import` to register the vault, \
     then write through its vault remote. DCTL never switches to sealed mode on \
     its own: what a command encrypts is decided by the remote name typed.";

/// Largest file the whole-buffer transfer path will attempt, in bytes.
///
/// `dctl_core::Vault::put_file` and `get_file` take and return complete buffers,
/// so one file's plaintext is resident while it moves. Attempting a 50 GB video
/// through that path would be killed by the OOM killer or swap the machine to a
/// standstill — and either way the user learns nothing actionable. Refusing
/// beforehand, with a message that names the limit, is the honest behaviour.
///
/// One gibibyte is chosen to be comfortably servable on any machine that can run
/// the tool at all, while still covering the overwhelming majority of documents,
/// photographs and raw camera files. It disappears entirely when the streaming
/// engine lands — at which point this constant and the check that reads it are
/// deleted together, not raised.
pub const TRANSFER_WHOLE_FILE_LIMIT: u64 = 1024 * 1024 * 1024;

/// Feature name reported when a pattern-based filter is requested.
pub const PATTERN_FILTER_FEATURE: &str =
    "pattern filtering (--include/--exclude/--filter-from/--files-from)";

/// Remediation hint attached to [`PATTERN_FILTER_FEATURE`].
///
/// The wording matters more than usual here. Quietly ignoring an `--exclude`
/// during a `sync` would delete precisely the files the rule was written to
/// protect, so refusing is a data-safety guarantee rather than an inconvenience.
pub const PATTERN_FILTER_HINT: &str = "A filter that was silently ignored would make `sync` delete the files it was \
     written to protect, so DCTL refuses instead. Narrow the transfer with an \
     explicit SOURCE, or with --min-size/--max-size/--max-depth, which are \
     honoured.";

/// Feature name reported when a transfer command must enumerate a named remote.
pub const REMOTE_ENUMERATION_FEATURE: &str = "listing a remote";

/// Remediation hint attached to [`REMOTE_ENUMERATION_FEATURE`].
pub const REMOTE_ENUMERATION_HINT: &str = "Enumerating a remote needs an unlocked vault, which the command context does \
     not yet carry. Transfers between local paths can be planned today.";

// ─────────────────────────────────────────────────────────────────────────────
// Point-in-time arguments — `--at`, `--since`, `--until`
// ─────────────────────────────────────────────────────────────────────────────
//
// Only the *spellings* live here. The Gregorian arithmetic that turns a date
// into a Unix second is not policy — it is a fixed property of the calendar —
// so it stays beside its algorithm in `commands::recovery::timespec` rather
// than being dressed up as a tunable somebody might "adjust".

/// Sentinel meaning "this instant".
///
/// A word rather than an omitted argument, so a script can pass the value
/// through unconditionally: `--at "$WHEN"` works whether `$WHEN` holds a date or
/// `now`, with no branch at the call site.
pub const TIME_NOW_KEYWORD: &str = "now";

/// Prefix marking a raw Unix timestamp (`@1753574400`).
///
/// Sigil-prefixed, following `git`'s spelling, because a bare integer is
/// ambiguous with a relative offset: `3600` could mean "an epoch second in 1970"
/// or "3600 seconds ago", and guessing would be wrong about half the time.
pub const TIME_UNIX_PREFIX: char = '@';

/// Seconds in a week — the coarsest unit a relative time accepts.
///
/// The ladder stops here deliberately. Months and years are not fixed durations
/// (28–31 days, 365–366 days), so `--at 1M` could only ever be an approximation,
/// and an approximate point in time is precisely the wrong thing to hand to a
/// restore.
pub const SECONDS_PER_WEEK: u64 = 7 * SECONDS_PER_DAY;

/// Suffixes accepted on a relative time, paired with their length in seconds.
///
/// A relative time always means *ago*: `--at 2d` is "the vault as it stood two
/// days ago". There is no spelling for a future instant, because a backup holds
/// nothing to restore from the future.
///
/// `m` is minutes, not months — the one ambiguity every tool accepting `1m` has
/// to pick a side on, and minutes is what `sleep`, `systemd` and `journalctl`
/// all mean by it.
pub const TIME_RELATIVE_SUFFIXES: &[(char, u64)] = &[
    ('s', 1),
    ('m', SECONDS_PER_MINUTE),
    ('h', SECONDS_PER_HOUR),
    ('d', SECONDS_PER_DAY),
    ('w', SECONDS_PER_WEEK),
];

/// Characters accepted between the date and the time of day.
///
/// [`RFC3339_DATE_TIME_SEPARATOR`] is the spelling DCTL *writes*; the lower-case
/// form and a plain space are accepted on input because `date`, PostgreSQL and
/// most log files emit one of those, and rejecting a copy-pasted timestamp would
/// serve nobody.
pub const TIME_DATE_TIME_SEPARATORS: &[char] = &[RFC3339_DATE_TIME_SEPARATOR, 't', ' '];

/// Zone designators meaning UTC, in both cases.
pub const TIME_UTC_DESIGNATORS: &[char] = &[RFC3339_UTC_DESIGNATOR, 'z'];

/// Signs that introduce a numeric UTC offset (`+02:00`, `-05:00`).
pub const TIME_OFFSET_SIGNS: &[char] = &['+', '-'];

/// Earliest year a calendar spelling may name.
///
/// The epoch itself: DCTL stores Unix seconds, and a date before 1970 can only
/// be a typo or a clock that never got set. Bounding the range means
/// `20265-01-01` is rejected at the flag instead of silently producing an
/// instant 18 000 years out — which, as a `--since`, would quietly match nothing
/// at all while looking like it worked.
pub const TIME_MIN_YEAR: i64 = 1970;

/// Latest year a calendar spelling may name. Four digits is all RFC 3339 has.
pub const TIME_MAX_YEAR: i64 = 9999;

/// Hint appended to a time-parsing failure: one example of each accepted shape,
/// so the fix is visible without opening the manual.
pub const TIME_PARSE_EXAMPLES: &str = "2026-07-26, 2026-07-26T14:30:00Z, 2d, @1753574400, or now";

// ─────────────────────────────────────────────────────────────────────────────
// Object replication — `dctl replicate` (`PLAN.md` §13.3)
// ─────────────────────────────────────────────────────────────────────────────
//
// The command that makes 3-2-1 real, and the only transfer verb in the tool
// that needs **no vault password**: it moves a vault's opaque ciphertext objects
// from one object store to another, byte for byte, under the same keys. A backup
// operator can run it without ever holding decryption capability, and that
// separation of duties is a structural property rather than a policy somebody
// has to remember to apply.
//
// Everything below serves one rule: a replica is a *whole* vault or it is not a
// replica. That is why the refusals here are refusals rather than warnings — a
// partially replicated object store is a store whose index references objects it
// does not have, and the moment that is discovered is restore day.

/// Value names shown in `--help` for `dctl replicate`'s two arguments.
///
/// Spelled with the trailing colon and with `-STORE` in the word, because both
/// halves are load-bearing: the colon says a *remote* is expected rather than a
/// directory, and `STORE` says which of a vault's two remotes it is. A user who
/// reads `SOURCE` and types the vault remote gets a refusal where they expected
/// a replication, which is a worse first experience than a help line that spells
/// the answer out.
pub const REPLICATE_SOURCE_VALUE_NAME: &str = "SOURCE-STORE:";
/// See [`REPLICATE_SOURCE_VALUE_NAME`].
pub const REPLICATE_DEST_VALUE_NAME: &str = "DEST-STORE:";

/// Action slug for an object this run copies from one store to the other.
///
/// Stable machine values for the same reason [`PLAN_ACTION_COPY`] is: they land
/// in `--json` and in the first column of the plan table, and a script branching
/// on them must not break when a message is reworded.
///
/// Deliberately its own word rather than a reuse of [`PLAN_ACTION_COPY`]. A
/// compliance reviewer reading an audit trail needs to see that this run moved
/// ciphertext with no key present, which is a materially different act from a
/// `copy` through a vault remote — and two acts that differ in whether a
/// decryption key was held must not share a slug.
pub const REPLICATE_ACTION_REPLICATE: &str = "replicate";

/// See [`REPLICATE_ACTION_REPLICATE`]. An object present at both ends with the
/// same byte count, which `--verify strict` reads back and hash-compares before
/// deciding whether it is really the same object.
pub const REPLICATE_ACTION_REVERIFY: &str = "reverify";

/// See [`REPLICATE_ACTION_REPLICATE`]. An object this run could not move.
///
/// Recorded as an outcome rather than dropped from the report, because a
/// replication that silently listed one object fewer than it moved is exactly
/// the "reported as done when it did not happen" failure `PLAN.md` §6 forbids.
pub const REPLICATE_ACTION_FAILED: &str = "failed";

/// Reason slugs an *execution* produces, as opposed to a plan.
///
/// A plan reasons about metadata and reuses the transfer family's vocabulary —
/// [`PLAN_REASON_MISSING`], [`PLAN_REASON_SIZE`], [`PLAN_REASON_EXISTS`]. These
/// four say what went wrong while bytes were moving, and they are separate slugs
/// because the remedies are: an unreadable source is a problem at the primary,
/// an unwritable destination is a problem at the replica, and a mismatch is a
/// provider that acknowledged bytes it did not store.
pub const REPLICATE_REASON_UNREADABLE: &str = "source-unreadable";
/// See [`REPLICATE_REASON_UNREADABLE`].
pub const REPLICATE_REASON_UNWRITABLE: &str = "destination-unwritable";
/// See [`REPLICATE_REASON_UNREADABLE`]. What the destination served back is not
/// what it was given.
pub const REPLICATE_REASON_MISMATCH: &str = "destination-mismatch";
/// See [`REPLICATE_REASON_UNREADABLE`]. Larger than
/// [`REPLICATE_WHOLE_OBJECT_LIMIT`].
pub const REPLICATE_REASON_TOO_LARGE: &str = "object-too-large";

/// Largest object the replicator will move in one piece, in bytes.
///
/// [`dctl_store::Backend::put`] takes a whole buffer, so one object's ciphertext
/// is resident while it moves. The limit is the same order as
/// [`TRANSFER_WHOLE_FILE_LIMIT`] and set for the same reason — a machine that
/// cannot hold the object is better told so than OOM-killed halfway — but it is
/// its own constant because it bounds a *different* quantity: a vault's stored
/// objects are chunked ciphertext, not user files, so the two ceilings move
/// independently and tying them together would make one of the two arbitrary.
///
/// It disappears when the storage layer grows a streaming put; at that point
/// this constant and the check that reads it are deleted together, not raised.
pub const REPLICATE_WHOLE_OBJECT_LIMIT: u64 = 1024 * 1024 * 1024;

/// Bytes read back from the destination under `--verify sample`.
///
/// The point of the sampled mode is to prove the provider *serves back* what it
/// accepted, which is a different claim from "it accepted the right bytes" — a
/// verified write already establishes the latter. One mebibyte is enough to
/// catch the failures that mode exists for (a truncated object, a store that
/// acknowledged a write it never durably made, a range endpoint that returns the
/// wrong object) while costing a fixed, predictable amount of egress per object
/// rather than a proportional one.
pub const REPLICATE_SAMPLE_WINDOW_BYTES: u64 = 1024 * 1024;

/// What each `--verify` strength actually checked, for the run's commentary.
///
/// Written here rather than reused from [`crate::commands::integrity::mode`]
/// because that module's sentences say "decrypted", and nothing in a replication
/// is decrypted. A report that borrowed the wrong sentence would claim a
/// stronger guarantee than the run made, in the one command whose selling point
/// is that it holds no key.
pub const REPLICATE_VERIFY_CHECKSUM: &str = "hashed each object's ciphertext at the source and refused to commit anything \
     the destination did not store byte-for-byte";
/// See [`REPLICATE_VERIFY_CHECKSUM`].
pub const REPLICATE_VERIFY_SAMPLE: &str = "as checksum, and additionally read a window of each object back from the \
     destination and compared it with the source";
/// See [`REPLICATE_VERIFY_CHECKSUM`].
pub const REPLICATE_VERIFY_STRICT: &str = "as checksum, and additionally read every object back from the destination in \
     full and compared its BLAKE3 with the source's";

/// Remediation attached to a refused filter.
///
/// The wording is the whole point. `dctl copy --raw --include '*.jpg'` would
/// invite exactly the mistake this command exists to make impossible: an object
/// store holding some of a vault's objects is not a smaller vault, it is a
/// broken one, and the break is invisible until a restore needs the object that
/// was filtered out.
pub const REPLICATE_FILTER_HINT: &str = "A filtered replica is not a vault. A vault's object store is a single \
     consistent set — its index references every object in it — so a store \
     holding a subset of them is broken rather than smaller, and nothing detects \
     that until a restore needs one of the missing objects. `dctl replicate` \
     therefore has no filters at all. To copy selected *files*, use `dctl copy` \
     through the vault remote, which needs the vault password.";

/// Remediation attached to a source or destination that names a path inside a
/// store rather than the store itself.
///
/// A prefix is a filter written in the argument instead of in a flag, and it
/// produces the same broken replica, so it is refused in the same breath.
pub const REPLICATE_SUBPATH_HINT: &str = "Replication copies a whole object store, so both ends address a store's root \
     — write them as 'NAME:' with nothing after the colon. A prefix would \
     produce a partial replica, which is the same broken result a filter would.";

/// Remediation attached to a location that is not a vault's object store.
///
/// Naming the exact command that declares one matters more than usual: the
/// alternative reading of "it is empty, so it must be the new replica" is
/// precisely the auto-detection invariant I4 forbids, and an operator who is
/// refused without being told the spelling will reach for `--force` instead.
pub const REPLICATE_STORE_HINT: &str = "`dctl replicate` moves a vault's opaque objects between two object stores, so \
     both ends must be one. A store registered by `dctl init` already declares \
     itself; declare another with `dctl config create NAME TYPE bucket=BUCKET \
     require_vault=true`, or address a location that already holds a vault's \
     envelope. Refusing an undeclared, empty location is what stops a vault's \
     object tree being written over an ordinary directory.";

/// Remediation attached to a source and destination that are the same place.
pub const REPLICATE_SAME_STORE_HINT: &str = "A replica has to be somewhere else to be a replica. Check the two remote \
     names: `dctl config list` shows which location each one addresses.";

// ─────────────────────────────────────────────────────────────────────────────
// Audit log — `dctl audit` (`PLAN.md` §7)
// ─────────────────────────────────────────────────────────────────────────────
//
// The chain is the evidence. Everything here exists so that a break is
// *detectable and locatable*, never merely suspected: a fixed hash width so a
// truncated value is malformed rather than accidentally comparing equal, an
// explicit genesis link so a deleted first record cannot pass as "no
// predecessor", and a field separator no field value can contain.

/// Filename of the local hash-chained audit log inside the platform data
/// directory.
///
/// JSON Lines, not a database. An append-only chain has to outlive the tool that
/// wrote it: one self-describing record per line is greppable, diffable, safely
/// appendable, and readable by any language's standard library in twenty years —
/// the same reasoning that governs the object format (`PLAN.md` §13.1).
pub const AUDIT_LOG_FILE_NAME: &str = "audit.jsonl";

/// The `prev` value carried by the first record in a chain.
///
/// All zeros rather than an absent field. A genesis record that merely *lacks* a
/// predecessor is indistinguishable from a record whose predecessor was deleted,
/// and detecting exactly that deletion is the whole purpose of the chain.
///
/// Its length is [`HASH_HEX_LEN_BLAKE3`]; the pairing is asserted in this
/// module's tests.
pub const AUDIT_CHAIN_GENESIS_PREV: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Index carried by the genesis record. Indices are dense and ascending from
/// here, so a gap is itself evidence rather than a formatting quirk.
pub const AUDIT_CHAIN_FIRST_INDEX: u64 = 0;

/// Separator between the fields of the canonical byte string a record's hash is
/// computed over.
///
/// U+001F (unit separator) because it cannot legally occur *inside* a field:
/// control characters are rejected everywhere by [`crate::platform::names`], so
/// no path or operator-supplied value can forge a field boundary and make two
/// different records hash identically.
pub const AUDIT_HASH_FIELD_SEPARATOR: char = '\u{1f}';

/// Characters of a chain hash shown in the text listing.
///
/// Twelve hex characters is 48 bits: enough for a human to tell adjacent records
/// apart at a glance, far too few to verify anything — `dctl audit verify`
/// exists for that — and narrow enough to leave the path column its width.
pub const AUDIT_HASH_DISPLAY_LEN: usize = 12;

/// Column headers of the `dctl audit list` table.
pub const AUDIT_COLUMN_INDEX: &str = "Index";
/// See [`AUDIT_COLUMN_INDEX`].
pub const AUDIT_COLUMN_TIME: &str = "Time";
/// See [`AUDIT_COLUMN_INDEX`].
pub const AUDIT_COLUMN_OP: &str = "Op";
/// See [`AUDIT_COLUMN_INDEX`].
pub const AUDIT_COLUMN_RESULT: &str = "Result";
/// See [`AUDIT_COLUMN_INDEX`].
pub const AUDIT_COLUMN_PATH: &str = "Path";
/// See [`AUDIT_COLUMN_INDEX`].
pub const AUDIT_COLUMN_HASH: &str = "Hash";

/// Row limit meaning "every record". Zero rather than a sentinel maximum, so
/// `--limit 0` reads as "no limit" exactly the way `--max-size 0` does.
pub const AUDIT_LIST_UNLIMITED: usize = 0;

/// Verdict printed by `dctl audit verify` when the chain is intact.
///
/// One lower-case word on stdout so the check composes:
/// `[ "$(dctl audit verify)" = intact ]` is the whole test a cron job needs.
pub const AUDIT_VERDICT_INTACT: &str = "intact";

/// Verdict printed when the chain is broken. Emitted *alongside* exit code 24,
/// never instead of it.
pub const AUDIT_VERDICT_BROKEN: &str = "broken";

/// Feature name reported when a restore is asked for an earlier point in time.
///
/// Refused rather than approximated. A `--at 2d` that quietly planned *today's*
/// contents would produce a plan that does not answer the question asked, and a
/// restore whose output does not match its arguments is worse than one that
/// refuses: the operator would have no reason to look twice.
pub const POINT_IN_TIME_FEATURE: &str =
    "restoring a snapshot or an earlier point in time (--snapshot/--at)";

/// Remediation hint attached to [`POINT_IN_TIME_FEATURE`].
pub const POINT_IN_TIME_HINT: &str = "The index records one current version per path in this build; selecting an \
     earlier one needs the versioned, snapshot-backed index of PLAN.md §13.5. \
     Restore the current contents by dropping the flag.";

/// Feature name reported when a recovery command is asked for a glob filter.
///
/// Deliberately distinct from [`PATTERN_FILTER_FEATURE`], which also names
/// `--files-from`. A restore *does* honour `--files-from`: an exact list of
/// logical paths needs no matcher, and it is the one input that lets the restore
/// pre-flight (`PLAN.md` §13.6) run before the engine exists. Refusing it for
/// symmetry would remove the only way to prove a restore is safe today.
pub const GLOB_FILTER_FEATURE: &str = "glob filtering (--include/--exclude/--filter-from)";

/// Feature name reported when the audit log itself has never been written.
///
/// Named as the *writer*, not the reader: `dctl audit` reads and verifies a log
/// today, and the missing half is the engine-side append that `PLAN.md` §7
/// requires after every operation. Saying so precisely is what stops "no log
/// found" from being mistaken for "nothing has happened".
pub const AUDIT_WRITER_FEATURE: &str = "the tamper-evident audit log writer";

/// Remediation hint attached to [`AUDIT_WRITER_FEATURE`].
pub const AUDIT_WRITER_HINT: &str = "No audit log exists to inspect: appending a chained record after every \
     operation (PLAN.md §7) needs the dctl-core engine. Verification works \
     today — point --audit-log at a chain written elsewhere.";

// ─────────────────────────────────────────────────────────────────────────────
// Snapshots — `dctl backup --snapshot`, `dctl restore --snapshot`
// ─────────────────────────────────────────────────────────────────────────────

/// Prefix of an automatically generated snapshot name (`snap-1753574400`).
///
/// The suffix is the Unix second the run started: it sorts chronologically as
/// plain text and is unambiguous in every timezone, unlike a local-time
/// spelling, which repeats itself for an hour every autumn.
pub const SNAPSHOT_AUTO_NAME_PREFIX: &str = "snap-";

/// Longest snapshot name accepted.
///
/// Generous for a label a human types, and short enough that a name can still be
/// one path component on every filesystem DCTL supports.
pub const SNAPSHOT_NAME_MAX_LEN: usize = 64;

/// Punctuation allowed in a snapshot name, in addition to ASCII alphanumerics.
///
/// Deliberately narrow, and deliberately its own constant rather than a reuse of
/// [`REMOTE_NAME_EXTRA_CHARS`]: a snapshot name may end up as a path component,
/// an object-key fragment *and* a URL segment, so the accepted set is the
/// intersection of what all three tolerate unescaped.
pub const SNAPSHOT_NAME_EXTRA_CHARS: &[char] = &['-', '_', '.'];

// ─────────────────────────────────────────────────────────────────────────────
// Backup & restore pre-flight (`PLAN.md` §13.6)
// ─────────────────────────────────────────────────────────────────────────────
//
// A backup you never restored is not a backup. Everything here serves one rule:
// every reason a restore could fail must be found *before* the first byte is
// written, not 3.9 TB into a 4 TB run.

/// Longest path Win32 accepts without the `\\?\` prefix or opt-in long-path
/// support.
///
/// Checked during a restore pre-flight because the failure it causes is silent
/// and late: 200 000 files land, then one deep path fails and the tree is
/// half-written.
pub const WINDOWS_MAX_PATH_LEN: usize = 260;

/// See [`PLAN_ACTION_COPY`]. A local file that a backup would store in the
/// vault.
pub const PLAN_ACTION_STORE: &str = "store";
/// See [`PLAN_ACTION_COPY`]. A vault object a restore would write to disk.
pub const PLAN_ACTION_RESTORE: &str = "restore";
/// See [`PLAN_ACTION_COPY`]. A restore that would replace an existing local
/// file — the one action in the family that destroys data, and therefore the one
/// that is spelled differently from [`PLAN_ACTION_RESTORE`] in every rendering.
pub const PLAN_ACTION_OVERWRITE: &str = "overwrite";

/// Column headers of the pre-flight report.
pub const PREFLIGHT_COLUMN_SEVERITY: &str = "Severity";
/// See [`PREFLIGHT_COLUMN_SEVERITY`].
pub const PREFLIGHT_COLUMN_PROBLEM: &str = "Problem";
/// See [`PREFLIGHT_COLUMN_SEVERITY`].
pub const PREFLIGHT_COLUMN_PATH: &str = "Path";

/// Severity of a pre-flight finding that this platform cannot survive.
///
/// The distinction from [`PREFLIGHT_SEVERITY_PORTABILITY`] is the report's whole
/// point: *blocking* means the name cannot be created here, so the restore would
/// fail partway through; *portability* means it works here but will not work
/// everywhere — a warning about the next machine, not about this one.
pub const PREFLIGHT_SEVERITY_BLOCKING: &str = "blocking";

/// See [`PREFLIGHT_SEVERITY_BLOCKING`].
pub const PREFLIGHT_SEVERITY_PORTABILITY: &str = "portability";

/// Problem slugs used in the `problem` field of a pre-flight finding.
///
/// Stable slugs rather than prose, for the same reason [`PLAN_ACTION_COPY`] is:
/// they appear in `--json` output, and a script branching on them must not break
/// when a message is reworded.
pub const PREFLIGHT_PROBLEM_ILLEGAL_NAME: &str = "illegal-name";
/// See [`PREFLIGHT_PROBLEM_ILLEGAL_NAME`]. Two vault paths differ only in case,
/// which a case-insensitive filesystem cannot represent side by side.
pub const PREFLIGHT_PROBLEM_CASE_COLLISION: &str = "case-collision";
/// See [`PREFLIGHT_PROBLEM_ILLEGAL_NAME`]. One path needs a directory where
/// another needs a file of the same name.
pub const PREFLIGHT_PROBLEM_TYPE_CONFLICT: &str = "directory-file-conflict";
/// See [`PREFLIGHT_PROBLEM_ILLEGAL_NAME`]. The native path would exceed
/// [`WINDOWS_MAX_PATH_LEN`].
pub const PREFLIGHT_PROBLEM_PATH_TOO_LONG: &str = "path-too-long";

// ─────────────────────────────────────────────────────────────────────────────
// Byte-stream family — `cat`, `rcat`
// ─────────────────────────────────────────────────────────────────────────────
//
// The two commands whose stdout and stdin *are* the payload rather than a report
// about it. Everything here serves one rule: a pipeline sees object bytes and
// nothing else, so these values govern how bytes are moved — never how they are
// decorated.

/// Working-buffer size for the byte pumps (`cat` reading out, `rcat` reading in).
///
/// 256 KiB is the balance point between three pressures. Larger buffers stop
/// paying: at this size the per-write syscall cost is already far below a percent
/// of the copy, so a bigger buffer mostly buys resident memory. Smaller buffers
/// cost latency in exactly the case that must stay responsive —
/// `dctl cat film.mkv | head -c 1M` should hand its consumer the first bytes
/// immediately and be told to stop, not fill a megabyte first. And the buffer is
/// allocated once per invocation and reused for every object, so memory stays
/// O(concurrency) rather than O(file size), which is `PLAN.md` §16.2's rule for
/// every path in the tool.
pub const STREAM_CHUNK_BYTES: usize = 256 * 1024;

/// Prefix of the staging name a local `rcat` writes before renaming into place.
///
/// A leading dot hides the partial file from ordinary listings and from most
/// indexing and backup daemons — which matters because a staging file is, by
/// definition, a file whose contents are not yet trustworthy.
pub const LOCAL_STAGING_PREFIX: &str = ".";

/// Suffix of that staging name.
///
/// The binary's own name and the process id are inserted before it at run time,
/// so a stray staging file names the tool and the run that owns it without
/// hard-coding a brand [`dctl_meta`] is free to change. Finding one after a crash
/// is then unambiguous *and* safe: the rename into the final name is the commit,
/// so anything still carrying this suffix was never reported as stored
/// (`PLAN.md` §6).
pub const LOCAL_STAGING_SUFFIX: &str = ".tmp";

/// Feature name reported when `cat` is asked for an object in a remote.
///
/// Named for the capability rather than the command, following
/// [`TRANSFER_ENGINE_FEATURE`]: the range arithmetic, the plan and the writer all
/// work today, and the single missing piece is the vault's ranged read.
pub const RANGE_READ_FEATURE: &str = "reading an object out of a remote";

/// Remediation hint attached to [`RANGE_READ_FEATURE`].
///
/// Says what already works, because the useful next step is usually to run the
/// same command against a local path rather than to wait for a release.
pub const RANGE_READ_HINT: &str = "Reading a remote object needs an unlocked vault and a ranged read of the \
     chunks covering the request (PLAN.md §11), which the command context does \
     not yet carry. `cat` works on local paths today, including --head, --tail, \
     --offset and --count.";

/// Feature name reported when `rcat` is asked to store a stream into a remote.
pub const STREAM_WRITE_FEATURE: &str = "storing a stream into a remote";

/// Remediation hint attached to [`STREAM_WRITE_FEATURE`].
///
/// The second half is the load-bearing part. `rcat` refuses *before* reading a
/// byte, because a pipe cannot be rewound: consuming the producer's output and
/// then failing would destroy data that was never stored anywhere.
pub const STREAM_WRITE_HINT: &str = "Storing a stream in a remote needs the verified-write engine to accept an \
     upload of unknown length (PLAN.md §6), which the command context does not \
     yet carry. Nothing was read from standard input, so the producing command's \
     output is intact — send it to a local path instead, or store the data with \
     `dctl copy` once it is on disk.";

/// Remediation hint for `cat --json` without `--discard`.
///
/// The conflict is structural rather than a policy choice: stdout carries either
/// the object's bytes or a JSON report, and interleaving them would corrupt both.
pub const CAT_JSON_STREAM_HINT: &str = "stdout carries either object bytes or JSON, never both — interleaving them \
     would corrupt the stream and the document. Add --discard to read the objects \
     and emit only the JSON report, or drop --json to get the bytes.";

/// Outcome slugs in `rcat`'s JSON record.
///
/// Stable machine values for the same reason [`PLAN_ACTION_COPY`] is: a script
/// branching on them must not break when a message is reworded. The three are
/// exhaustive — a stream is stored, planned but never read, or refused — and
/// only `stored` ever accompanies a byte count, which is what keeps a plan from
/// being mistaken for completed work.
pub const RCAT_OUTCOME_STORED: &str = "stored";
/// See [`RCAT_OUTCOME_STORED`]. A `--dry-run`: nothing was read.
pub const RCAT_OUTCOME_PLANNED: &str = "planned";
/// See [`RCAT_OUTCOME_STORED`]. The operator refused the replacement.
pub const RCAT_OUTCOME_DECLINED: &str = "declined";

/// Remediation hint for `rcat` invoked with a terminal on standard input.
///
/// Without the refusal the command simply blocks, which reads as a hang rather
/// than as a missing pipe — the most confusing way for a byte-stream command to
/// fail.
pub const RCAT_TERMINAL_STDIN_HINT: &str = "rcat stores what a pipeline produces: 'producer | dctl rcat vault:name'. To \
     store a file that already exists, use 'dctl copy' instead.";

// ─────────────────────────────────────────────────────────────────────────────
// Directory family — `mkdir`, `touch`
// ─────────────────────────────────────────────────────────────────────────────
//
// Two commands that exist because an object store has neither directories nor a
// settable modification time, and a user porting a shell script expects both.
// The strings below are what makes the illusion consistent: one marker name that
// every command must agree on, and one report vocabulary so `mkdir --dry-run`
// and `touch --dry-run` read alike.

/// Name of the zero-byte object that stands in for a directory.
///
/// Object stores have no directories — `photos/2024/a.jpg` is one flat key with
/// slashes in it, and a directory containing no objects simply does not exist.
/// A `mkdir` therefore has to write something, and what it writes is an empty
/// object at `<dir>/.dctl-dir`.
///
/// A dot-prefixed name for the usual reason (invisible in a casual listing), and
/// brand-named so it can never collide with a user's own file: nobody has a
/// `.dctl-dir` they care about, whereas `.keep` and `.gitkeep` are real files in
/// real trees that a `sync` must round-trip untouched.
///
/// Every listing command is responsible for hiding markers, and `rmdir` for
/// treating a directory that holds nothing but its marker as empty. Renaming
/// this constant orphans existing markers, so it is effectively frozen once a
/// vault has been written.
pub const DIRECTORY_MARKER_NAME: &str = ".dctl-dir";

/// Column headers of the directory-family plan table.
///
/// Family-scoped rather than generic, following [`PLAN_COLUMN_ACTION`]'s
/// convention: `mkdir` and `touch` describe a single request as label/value
/// pairs, and that layout can change without disturbing the transfer family's
/// columns.
pub const DIRECTORY_COLUMN_FIELD: &str = "Field";
/// See [`DIRECTORY_COLUMN_FIELD`].
pub const DIRECTORY_COLUMN_VALUE: &str = "Value";

/// Row labels of the directory-family plan table, in the order they appear.
///
/// Named once because each label is also a documentation heading and a support
/// answer ("what does the Marker row mean?"); two spellings of the same row
/// across two commands would make both answers wrong.
pub const DIRECTORY_LABEL_COMMAND: &str = "Command";
/// See [`DIRECTORY_LABEL_COMMAND`]. The target exactly as the user wrote it.
pub const DIRECTORY_LABEL_TARGET: &str = "Target";
/// See [`DIRECTORY_LABEL_COMMAND`]. Whether the run was allowed to change data.
pub const DIRECTORY_LABEL_MODE: &str = "Mode";
/// See [`DIRECTORY_LABEL_COMMAND`]. One row per directory in a `--parents` chain.
pub const DIRECTORY_LABEL_DIRECTORY: &str = "Directory";
/// See [`DIRECTORY_LABEL_COMMAND`]. The marker object a directory resolves to.
pub const DIRECTORY_LABEL_MARKER: &str = "Marker";
/// See [`DIRECTORY_LABEL_COMMAND`]. Whether missing parents are created too.
pub const DIRECTORY_LABEL_PARENTS: &str = "Parents";
/// See [`DIRECTORY_LABEL_COMMAND`]. The object `touch` addresses.
pub const DIRECTORY_LABEL_OBJECT: &str = "Object";
/// See [`DIRECTORY_LABEL_COMMAND`]. The modification time that would be written.
pub const DIRECTORY_LABEL_TIMESTAMP: &str = "Timestamp";
/// See [`DIRECTORY_LABEL_COMMAND`]. Where that time came from.
pub const DIRECTORY_LABEL_TIMESTAMP_SOURCE: &str = "Timestamp source";
/// See [`DIRECTORY_LABEL_COMMAND`]. Whether a missing object would be created.
pub const DIRECTORY_LABEL_CREATE: &str = "Create if missing";

/// Value of the `Mode` row, and of the JSON `mode` field.
///
/// A word rather than a boolean because it is read by a human in a table and by
/// a machine in a document, and "dry-run" answers "what happened here?" without
/// a legend where `true` would not say *what* was true.
pub const DIRECTORY_MODE_DRY_RUN: &str = "dry-run";
/// See [`DIRECTORY_MODE_DRY_RUN`].
pub const DIRECTORY_MODE_EXECUTE: &str = "execute";

/// Value of the JSON `status` field on a directory-family plan.
///
/// Only ever this. A plan describes a request that has *not* run, and `PLAN.md`
/// §6 forbids reporting work that did not happen — so there is no `"created"`
/// spelling for a document to accidentally carry.
pub const DIRECTORY_STATUS_PLANNED: &str = "planned";

/// How a boolean option is rendered in the plan table.
///
/// Shares its vocabulary with [`DESTRUCTIVE_CONFIRMATION`], so "yes" means the
/// same thing wherever the user reads or types it.
pub const DIRECTORY_BOOL_YES: &str = DESTRUCTIVE_CONFIRMATION;
/// See [`DIRECTORY_BOOL_YES`].
pub const DIRECTORY_BOOL_NO: &str = "no";

/// Action phrases used in the `[dry-run]` notice, which reads
/// "`[dry-run] would <action>: <target>`".
///
/// Named here rather than typed at the call site because the notice is what a
/// user greps a dry run for (`dctl sync -n | grep '^\[dry-run\]'`), which makes
/// its wording an interface rather than a message.
pub const DIRECTORY_ACTION_MKDIR: &str = "create directory";
/// See [`DIRECTORY_ACTION_MKDIR`].
pub const DIRECTORY_ACTION_TOUCH: &str = "set the modification time of";

/// Where a `touch` timestamp came from, as reported in the plan.
pub const DIRECTORY_TIMESTAMP_SOURCE_NOW: &str = "now";
/// See [`DIRECTORY_TIMESTAMP_SOURCE_NOW`]. Supplied with `--timestamp`.
pub const DIRECTORY_TIMESTAMP_SOURCE_EXPLICIT: &str = "explicit";

/// Remediation hint attached to the directory family's `unimplemented` error.
///
/// Says precisely how far the command got, because "not implemented" on its own
/// invites the user to doubt their arguments when the arguments were fine.
pub const DIRECTORY_ENGINE_HINT: &str = "Parsing, validation and planning are complete: re-run with --dry-run to see \
     exactly what would be created. Writing the object needs a dctl-core vault \
     handle (PLAN.md §6) reachable from the command context, which the CLI does \
     not carry yet.";

// ─────────────────────────────────────────────────────────────────────────────
// Timestamps (`dctl touch --timestamp`)
// ─────────────────────────────────────────────────────────────────────────────
//
// DCTL parses timestamps itself rather than taking a calendar dependency, so the
// pieces of the grammar are named here. Two rules are worth stating up front,
// because both are deliberate:
//
// * **Everything is UTC.** A naked time is read as UTC and a zone offset is
//   refused rather than converted. A backup run on a laptop that crossed a
//   timezone must not silently shift the modification times it writes, and
//   "which zone was this machine in that night?" is not a question a restore
//   should have to answer.
// * **Whole seconds.** The index stores `modified_unix` as whole seconds
//   (`dctl_index::Record`), so a sub-second fraction is accepted and discarded
//   rather than rejected — a timestamp copied from another tool's RFC 3339
//   output should just work.

/// Prefix that introduces a raw count of seconds since the Unix epoch.
///
/// `@1714564800` is the spelling scripts already have, and it is unambiguous:
/// nothing else in the grammar starts with `@`.
pub const TIMESTAMP_EPOCH_PREFIX: char = '@';

/// Separator between the year, month and day fields.
pub const TIMESTAMP_DATE_SEPARATOR: char = '-';

/// Separator between the hour, minute and second fields.
pub const TIMESTAMP_TIME_SEPARATOR: char = ':';

/// Separator between the seconds field and a fractional part, which is parsed
/// and then discarded (see the section note).
pub const TIMESTAMP_FRACTION_SEPARATOR: char = '.';

/// Characters accepted between the date and the time.
///
/// `T` is RFC 3339; a space is what `date` prints and what a human types; the
/// lower-case `t` is accepted because RFC 3339 §5.6 permits it.
pub const TIMESTAMP_DATE_TIME_SEPARATORS: &[char] = &['T', 't', ' '];

/// Suffixes accepted for "this is UTC", and stripped before parsing.
pub const TIMESTAMP_UTC_SUFFIXES: &[char] = &['Z', 'z'];

/// Characters that introduce a zone offset, which DCTL refuses rather than
/// converts (see the section note).
pub const TIMESTAMP_OFFSET_MARKERS: &[char] = &['+', '-'];

/// Canonical spelling of the date/time separator when DCTL *prints* a timestamp.
pub const TIMESTAMP_DATE_TIME_MARKER: char = 'T';

/// Canonical spelling of the UTC suffix when DCTL prints a timestamp.
pub const TIMESTAMP_UTC_MARKER: char = 'Z';

/// Field counts of a well-formed date and time.
///
/// A date is always `YYYY-MM-DD`. A time is `HH:MM` or `HH:MM:SS` — seconds are
/// optional because `touch -t 2024-05-01 09:00` is how people actually write it.
pub const TIMESTAMP_DATE_FIELDS: usize = 3;
/// See [`TIMESTAMP_DATE_FIELDS`].
pub const TIMESTAMP_TIME_FIELDS_MIN: usize = 2;
/// See [`TIMESTAMP_DATE_FIELDS`].
pub const TIMESTAMP_TIME_FIELDS_MAX: usize = 3;

/// Zero-padded width of the year when a timestamp is printed.
pub const TIMESTAMP_YEAR_WIDTH: usize = 4;

/// Zero-padded width of every other timestamp field.
pub const TIMESTAMP_FIELD_WIDTH: usize = 2;

/// Accepted spellings, quoted verbatim in a parse failure so the fix is visible
/// without opening the manual.
pub const TIMESTAMP_EXAMPLES: &str =
    "2024-05-01T12:00:00Z, '2024-05-01 12:00', 2024-05-01, or @1714564800";

/// The year the Unix epoch starts in — where the calendar walk begins.
pub const UNIX_EPOCH_YEAR: i64 = 1970;

/// Bounds on an accepted year.
///
/// Not a policy so much as a guard rail: the conversion walks a year at a time,
/// so an unbounded input would be an unbounded loop. Four digits is also the
/// only width RFC 3339 defines, so a year outside this range could not be
/// printed back in the format it was read in.
pub const TIMESTAMP_MIN_YEAR: i64 = 1;
/// See [`TIMESTAMP_MIN_YEAR`].
pub const TIMESTAMP_MAX_YEAR: i64 = 9999;

/// Length of each month in a common year, January first.
///
/// February's leap day is added by the leap-year rule rather than encoded here,
/// so the table describes exactly one thing.
pub const MONTH_LENGTHS: &[u32] = &[31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/// Months in a year — the length of [`MONTH_LENGTHS`], named for the places that
/// validate a month field before indexing it.
pub const MONTHS_PER_YEAR: u32 = 12;

/// The month that gains the leap day.
pub const LEAP_DAY_MONTH: u32 = 2;

/// Days in a year that is not a leap year.
pub const DAYS_PER_COMMON_YEAR: i64 = 365;

/// Days a leap year adds.
pub const LEAP_DAY_COUNT: i64 = 1;

/// The three periods of the Gregorian leap rule: a leap year every four years,
/// except every hundred, except every four hundred.
pub const LEAP_YEAR_CYCLE: i64 = 4;
/// See [`LEAP_YEAR_CYCLE`].
pub const LEAP_CENTURY_SKIP: i64 = 100;
/// See [`LEAP_YEAR_CYCLE`].
pub const LEAP_CENTURY_KEEP: i64 = 400;

/// Largest hour, minute and second a valid time may carry.
///
/// Second 60 — the leap second RFC 3339 allows — is refused rather than clamped:
/// silently rewriting a timestamp is exactly the kind of quiet difference that
/// makes a later comparison say "modified" about a file nobody touched.
pub const MAX_HOUR: u32 = 23;
/// See [`MAX_HOUR`].
pub const MAX_MINUTE: u32 = 59;
/// See [`MAX_HOUR`].
pub const MAX_SECOND: u32 = 59;

// ─────────────────────────────────────────────────────────────────────────────
// Durations written on the command line
// ─────────────────────────────────────────────────────────────────────────────
//
// The inverse of [`DURATION_SECOND_SUFFIX`] and its siblings: these turn what a
// user *writes* (`5m`, `500ms`, `90`) into a [`std::time::Duration`]. The ladder
// is expressed in milliseconds because that is the finest unit any DCTL flag
// needs, and it is derived from the `SECONDS_PER_*` constants so that parsing can
// never drift from formatting.

/// Milliseconds in one second.
pub const MILLIS_PER_SECOND: u64 = 1_000;

/// Milliseconds in one millisecond — the identity row of the ladder below.
///
/// Spelled out for the same reason as [`BYTES_PER_BYTE`]: every row of the table
/// is then a named quantity rather than a bare literal.
pub const MILLIS_PER_MILLISECOND: u64 = 1;

/// Every duration suffix DCTL accepts, paired with its value in milliseconds.
///
/// Lookup is an exact match on the ASCII-lower-cased suffix. A bare number means
/// **seconds**, matching `--timeout` and every other bare number of time in the
/// tool, so `--dir-cache-time 300` and `--dir-cache-time 5m` are the same dial.
pub const DURATION_SUFFIX_MULTIPLIERS_MS: &[(&str, u64)] = &[
    ("", MILLIS_PER_SECOND),
    ("ms", MILLIS_PER_MILLISECOND),
    ("s", MILLIS_PER_SECOND),
    ("m", SECONDS_PER_MINUTE * MILLIS_PER_SECOND),
    ("h", SECONDS_PER_HOUR * MILLIS_PER_SECOND),
    ("d", SECONDS_PER_DAY * MILLIS_PER_SECOND),
];

/// Accepted spellings, quoted in a parse failure. Mirrors
/// [`SIZE_PARSE_EXAMPLES`]'s job for sizes.
pub const DURATION_PARSE_EXAMPLES: &str = "5m, 1s, 500ms, or 90 (bare seconds)";

// ─────────────────────────────────────────────────────────────────────────────
// `dctl mount`
// ─────────────────────────────────────────────────────────────────────────────
//
// Defaults for a command that cannot run yet (`PLAN.md` §11 phase 2), and that is
// exactly why they are pinned now: the flag surface is published in `--help`, in
// the generated shell completions and in the docs the moment this ships, and a
// default that moves later silently changes the behaviour of every script that
// relied on it. Each value below is the one `PLAN.md` §15 argues for.

/// Default `--dir-cache-time`.
///
/// Five minutes. Directory listings are the most latency-expensive thing a mount
/// does — a `ls` on a cold directory is a provider round trip — and a media
/// player or file browser re-reads them constantly. Five minutes is long enough
/// that browsing feels local and short enough that a file added by another
/// machine appears without a remount.
pub const MOUNT_DEFAULT_DIR_CACHE_TIME: &str = "5m";

/// Default `--attr-timeout`, the kernel's grace period for cached file
/// attributes.
///
/// One second, matching FUSE's own default. Longer risks a writer seeing a stale
/// size; shorter turns every `stat` into a round trip and makes `ls -l` crawl.
pub const MOUNT_DEFAULT_ATTR_TIMEOUT: &str = "1s";

/// Default `--buffer-size`, the in-memory read-ahead buffer held per open file.
///
/// 16 MiB is four of the 4 MiB AEAD chunks `PLAN.md` §15 aligns reads to, so a
/// sequential reader always has whole chunks queued and never waits on a partial
/// one. Per *open file*, so the ceiling on a mount's memory is this times the
/// number of files a player has open — small enough to be safe on a laptop.
pub const MOUNT_DEFAULT_BUFFER_SIZE: &str = "16M";

/// Default `--vfs-read-ahead`, extra data fetched past what was asked for when
/// the VFS cache is on.
///
/// Off. Read-ahead beyond the buffer only pays once chunks are being written to
/// the on-disk cache, which is `--vfs-cache-mode full`; enabling it by default
/// would spend bandwidth and cache space on a streaming read that never revisits
/// the bytes.
pub const MOUNT_DEFAULT_VFS_READ_AHEAD: &str = "0";

/// Byte count that means "disabled" for a mount buffer or read-ahead window.
///
/// Named because `--buffer-size off` and `--buffer-size 0` both land here, and a
/// bare `0` at the use site reads as a bug rather than as a setting.
pub const MOUNT_SIZE_DISABLED: u64 = 0;

/// Remediation hint attached to `mount`'s `unimplemented` error.
///
/// States what *is* finished, so the failure reads as a scheduled absence rather
/// than as a broken command: everything except the filesystem adapter itself has
/// already run by the time the user sees this.
pub const MOUNT_ENGINE_HINT: &str = "The mountpoint checks, the flag surface and the per-platform backend choice \
     are final and have already run — only the filesystem adapter is missing. It \
     is PLAN.md phase 2 (§11, §15): FUSE3 on Linux, FSKit/fuse-t/macFUSE on \
     macOS, WinFSP on Windows.";

// ─────────────────────────────────────────────────────────────────────────────
// Removal family — `delete`, `deletefile`, `purge`, `rmdir`, `rmdirs`, `cleanup`
// ─────────────────────────────────────────────────────────────────────────────
//
// The six commands that destroy data. They share a vocabulary because they
// share a hazard: a user reading `delete --dry-run` and then `purge --dry-run`
// must be reading the same report in the same words, or the difference between
// the two commands — the whole reason both exist — is buried in presentation
// noise. The strings below are that shared report.

/// Value name shown in `--help` for the removal family's positional argument.
///
/// Spelled out rather than left as clap's derived `PATH`, because `PATH` is
/// exactly the wrong guess: these commands never operate on a local path, and a
/// user who reads `PATH` and types `./photos` gets an error where they expected
/// a deletion.
pub const REMOTE_PATH_VALUE_NAME: &str = "REMOTE:PATH";

/// Value name for `cleanup`, which sweeps a remote rather than a path.
///
/// Distinct from [`REMOTE_PATH_VALUE_NAME`] so the help text shows the usual
/// invocation (`dctl cleanup vault:`); a path is still accepted, and scopes the
/// sweep.
pub const REMOTE_ROOT_VALUE_NAME: &str = "REMOTE:";

/// Verbs used in the destructive confirmation prompt and the `--dry-run`
/// notice, one per command.
///
/// Named here because each verb is read twice — once in
/// `Ctx::confirm_destructive`'s prompt and once in the `[dry-run] would …`
/// line — and a command whose prompt said "delete" while its dry run said
/// "remove" would leave the user unsure which of the two they had just
/// previewed. Deliberately *not* reusing [`PLAN_ACTION_DELETE`]: that is a cell
/// in the transfer family's plan table, and the two would drift the moment one
/// of them needed rewording.
pub const REMOVAL_ACTION_DELETE: &str = "delete";
/// See [`REMOVAL_ACTION_DELETE`]. Used by `purge`, whose scope is a whole tree.
pub const REMOVAL_ACTION_PURGE: &str = "purge";
/// See [`REMOVAL_ACTION_DELETE`]. Used by `rmdir`, which removes one container.
pub const REMOVAL_ACTION_REMOVE_DIR: &str = "remove directory";
/// See [`REMOVAL_ACTION_DELETE`]. Used by `rmdirs`, which sweeps many.
pub const REMOVAL_ACTION_REMOVE_EMPTY_DIRS: &str = "remove empty directories";
/// See [`REMOVAL_ACTION_DELETE`]. Used by `cleanup`, which reclaims debris.
pub const REMOVAL_ACTION_CLEANUP: &str = "clean up";

/// Column headers of the removal-family plan table.
///
/// Family-scoped for the same reason [`DIRECTORY_COLUMN_FIELD`] is: a removal
/// describes one request as label/value pairs, and that layout must be free to
/// change without disturbing the transfer family's action/size/path columns.
pub const REMOVAL_COLUMN_FIELD: &str = "Field";
/// See [`REMOVAL_COLUMN_FIELD`].
pub const REMOVAL_COLUMN_VALUE: &str = "Value";

/// Row labels of the removal-family plan table, in the order they appear.
///
/// The first three are on every plan; the rest appear only when the flag they
/// describe was given, so a plan never pads itself with rows saying "not set".
pub const REMOVAL_LABEL_COMMAND: &str = "Command";
/// See [`REMOVAL_LABEL_COMMAND`]. The target, canonicalised.
pub const REMOVAL_LABEL_TARGET: &str = "Target";
/// See [`REMOVAL_LABEL_COMMAND`]. Whether the run was allowed to change data.
pub const REMOVAL_LABEL_MODE: &str = "Mode";
/// See [`REMOVAL_LABEL_COMMAND`]. `--include`, one row for every pattern.
pub const REMOVAL_LABEL_INCLUDE: &str = "Include";
/// See [`REMOVAL_LABEL_COMMAND`]. `--exclude`.
pub const REMOVAL_LABEL_EXCLUDE: &str = "Exclude";
/// See [`REMOVAL_LABEL_COMMAND`]. `--filter-from`.
pub const REMOVAL_LABEL_FILTER_FROM: &str = "Filter from";
/// See [`REMOVAL_LABEL_COMMAND`]. `--files-from`.
pub const REMOVAL_LABEL_FILES_FROM: &str = "Files from";
/// See [`REMOVAL_LABEL_COMMAND`]. `--min-size`, in the run's chosen units.
pub const REMOVAL_LABEL_MIN_SIZE: &str = "Min size";
/// See [`REMOVAL_LABEL_COMMAND`]. `--max-size`.
pub const REMOVAL_LABEL_MAX_SIZE: &str = "Max size";
/// See [`REMOVAL_LABEL_COMMAND`]. `--max-depth`, absent when unlimited.
pub const REMOVAL_LABEL_MAX_DEPTH: &str = "Max depth";
/// See [`REMOVAL_LABEL_COMMAND`]. `delete --rmdirs`.
pub const REMOVAL_LABEL_EMPTY_DIRS: &str = "Remove empty directories";
/// See [`REMOVAL_LABEL_COMMAND`]. `rmdirs --leave-root`.
pub const REMOVAL_LABEL_LEAVE_ROOT: &str = "Leave root";
/// See [`REMOVAL_LABEL_COMMAND`]. Which classes `cleanup` will sweep.
pub const REMOVAL_LABEL_CLASSES: &str = "Classes";
/// See [`REMOVAL_LABEL_COMMAND`]. `cleanup --min-age`.
pub const REMOVAL_LABEL_MIN_AGE: &str = "Minimum age";

/// Separator between repeated values sharing one plan row (`*.jpg, *.raw`).
///
/// Comma-space rather than the table's own [`TABLE_COLUMN_GAP`]: two patterns
/// separated by spaces alone read as two columns that failed to align.
pub const REMOVAL_LIST_SEPARATOR: &str = ", ";

/// Value of the `Mode` row, and of the JSON `dry_run` field's human twin.
///
/// A word rather than a bare boolean, for the reason
/// [`DIRECTORY_MODE_DRY_RUN`] gives: a table cell reading `true` does not say
/// what was true.
pub const REMOVAL_MODE_DRY_RUN: &str = "dry-run";
/// See [`REMOVAL_MODE_DRY_RUN`].
pub const REMOVAL_MODE_EXECUTE: &str = "execute";

/// Value of the JSON `status` field on a removal plan.
///
/// Only ever this. A plan describes a request that has **not** run, and
/// `PLAN.md` §6 forbids reporting work that did not happen — so the document
/// has no `"deleted"` spelling to accidentally carry, and no counters for a
/// consumer to mistake for results.
pub const REMOVAL_STATUS_PLANNED: &str = "planned";

/// How a boolean option is rendered in a removal plan.
///
/// Shares its vocabulary with [`DESTRUCTIVE_CONFIRMATION`], so "yes" means the
/// same thing wherever the user reads or types it.
pub const REMOVAL_BOOL_YES: &str = DESTRUCTIVE_CONFIRMATION;
/// See [`REMOVAL_BOOL_YES`].
pub const REMOVAL_BOOL_NO: &str = "no";

/// Prefix on the removal family's `unimplemented` error hint, introducing the
/// engine capability the command is waiting on.
pub const REMOVAL_ENGINE_MISSING: &str = "The removal itself is not wired up yet, because it needs";

/// Remediation hint attached to the removal family's `unimplemented` error.
///
/// States how far the command got, because "not implemented" on its own invites
/// the user to doubt their arguments when the arguments were fine — and, for a
/// destructive command especially, to wonder whether something was half-removed.
/// Nothing was: the refusal happens before any mutation.
pub const REMOVAL_ENGINE_HINT: &str = "Nothing was changed. Parsing, target \
     resolution, filter validation and the destructive gate all ran — re-run \
     with --dry-run to see the resolved request. See PLAN.md §11 for the phase \
     that delivers the rest.";

/// How `purge` describes the scope it is refusing to assume consent for.
///
/// Two spellings because the difference matters more than any other sentence
/// the command prints: one purge takes a subtree, the other takes everything.
pub const PURGE_SCOPE_REMOTE: &str = "the entire remote";
/// See [`PURGE_SCOPE_REMOTE`].
pub const PURGE_SCOPE_SUBTREE: &str = "everything under this path";

/// Default `--min-age` for `cleanup`: how old debris must be before a sweep
/// will touch it.
///
/// A day. The margin exists because an in-progress multipart upload and an
/// abandoned one are indistinguishable from the outside — nothing in the object
/// says which — so the age is the *only* thing standing between a cleanup and
/// another process's live work. Twenty-four hours is far longer than any single
/// verified write (`PLAN.md` §6) and still short enough that debris does not
/// accumulate a bill.
pub const CLEANUP_DEFAULT_MIN_AGE: &str = "24h";

/// Key infix that marks an object as staged rather than committed.
///
/// `PLAN.md` §6 step 3 stages every upload under a temporary key and only makes
/// it visible after the checksum matches, so an interrupted write leaves an
/// object carrying this marker behind. It is the remote-side twin of
/// [`LOCAL_STAGING_SUFFIX`], and `cleanup`'s `staging` class is defined as
/// "objects whose key contains it".
pub const CLEANUP_STAGING_MARKER: &str = ".tmp.";

/// Hint appended to an age-parsing failure, showing one example of each shape.
///
/// Mirrors [`SIZE_PARSE_EXAMPLES`]: the accepted spellings are exactly the ones
/// [`crate::output::size::duration`] prints, so anything DCTL shows can be
/// typed back at it.
pub const CLEANUP_AGE_PARSE_EXAMPLES: &str = "24h, 7d, 90m, or 30s";

// ─────────────────────────────────────────────────────────────────────────────
// Utility family — `about`, `version`, `completion`
// ─────────────────────────────────────────────────────────────────────────────
//
// The three commands that answer questions about DCTL itself rather than about
// stored data, and the only three that must keep working when everything else
// is broken. `PLAN.md` §7 makes that a requirement rather than a nicety: an
// operator whose vault will not unlock needs to be able to say which build they
// are running and which provider they pointed it at, and a command that needed
// a config file or a password to answer would be useless at exactly the moment
// it is reached for.

/// Separator between the items of a set named inline in a message.
///
/// Used where a hint has to spell out the options — "Supported types are local,
/// b2, s3, r2." — so that the list reads as prose rather than as a rendered
/// table. Distinct from [`THOUSANDS_SEPARATOR`] (which formats one number) and
/// from [`LISTING_FIELD_SEPARATOR`] (which separates the columns of a line a
/// script parses): this one is only ever read by a person.
pub const INLINE_LIST_SEPARATOR: &str = ", ";

// ── Build stamping (`dctl version`) ──────────────────────────────────────────
//
// The facts below cannot be discovered at runtime: a compiled binary has no way
// to ask which compiler produced it, which commit it came from, or which target
// it was built for. `build.rs` learns them at build time and passes them in as
// compile-time environment variables, which `crate::commands::version` reads
// with `option_env!`.
//
// Every one of them is **optional**. A build from a source tarball has no git
// hash, and a build script that could not run `rustc --version` has no compiler
// string; both report [`UNKNOWN_VALUE`] rather than a plausible-looking guess,
// because a wrong commit hash in a bug report costs more than a missing one.
//
// `option_env!` requires a string *literal*, so each name is spelled twice —
// once here as the documented contract and once at the macro call site. A test
// in `crate::commands::version::build_info` holds the two spellings together.
// That test is their only reader, which is why each carries `dead_code`: the
// constant is not what `build_info` consumes, it is what proves `build_info`
// consumed the right thing. Removing them would not remove a variable from the
// build; it would remove the check that `build.rs` and the binary still agree
// on its name, and a build stamp that silently stopped arriving reports
// `unknown` rather than failing.

/// Compile-time variable carrying the git commit the build came from.
#[allow(dead_code)]
pub const BUILD_ENV_GIT_HASH: &str = "DCTL_BUILD_GIT_HASH";

/// Compile-time variable carrying the `rustc --version` string.
#[allow(dead_code)]
pub const BUILD_ENV_RUSTC: &str = "DCTL_BUILD_RUSTC";

/// Compile-time variable carrying the target triple the binary was built for.
///
/// Stamped from cargo's own `TARGET`, which is exact. Deriving it at runtime
/// from `std::env::consts` would be a guess: the arch and OS are available but
/// the vendor and ABI — the `unknown` and the `gnu` in
/// `x86_64-unknown-linux-gnu` — are not, and a triple that is *nearly* right is
/// worse than none when someone is matching a binary against a bug report.
#[allow(dead_code)]
pub const BUILD_ENV_TARGET: &str = "DCTL_BUILD_TARGET";

/// Compile-time variable carrying the cargo profile (`debug`, `release`).
#[allow(dead_code)]
pub const BUILD_ENV_PROFILE: &str = "DCTL_BUILD_PROFILE";

/// Compile-time variable carrying the cargo features this build enabled.
///
/// Joined with [`BUILD_FEATURE_SEPARATOR`]. Absent when the build enabled none,
/// which is what a default build of this crate does today — the field exists so
/// that an optional feature added later (a FUSE mount, a provider behind a flag)
/// appears in every bug report without anyone having to remember to add it.
#[allow(dead_code)]
pub const BUILD_ENV_FEATURES: &str = "DCTL_BUILD_FEATURES";

/// Separator `build.rs` joins the enabled feature names with.
///
/// A comma with no space, so the value survives being carried through a shell
/// export and an environment variable without quoting.
pub const BUILD_FEATURE_SEPARATOR: char = ',';

// ── `dctl version` output ────────────────────────────────────────────────────

/// Column headers for the `dctl version` table.
pub const VERSION_COLUMN_SETTING: &str = "Setting";
/// See [`VERSION_COLUMN_SETTING`].
pub const VERSION_COLUMN_VALUE: &str = "Value";

/// Row labels in the `dctl version` report.
///
/// Spelled exactly as the JSON field names, in `snake_case`, following the
/// convention [`INIT_FIELD_REMOTE`] sets: a script ported from `--format text`
/// to `--format json` changes its parser and nothing else. A test in the command
/// module holds the two vocabularies together.
pub const VERSION_FIELD_VERSION: &str = "version";
/// See [`VERSION_FIELD_VERSION`].
pub const VERSION_FIELD_BINARY: &str = "binary";
/// See [`VERSION_FIELD_VERSION`].
pub const VERSION_FIELD_GIT_HASH: &str = "git_hash";
/// See [`VERSION_FIELD_VERSION`].
pub const VERSION_FIELD_RUSTC: &str = "rustc";
/// See [`VERSION_FIELD_VERSION`].
pub const VERSION_FIELD_TARGET: &str = "target";
/// See [`VERSION_FIELD_VERSION`].
pub const VERSION_FIELD_PROFILE: &str = "profile";
/// See [`VERSION_FIELD_VERSION`].
pub const VERSION_FIELD_OS: &str = "os";
/// See [`VERSION_FIELD_VERSION`].
pub const VERSION_FIELD_ARCH: &str = "arch";
/// See [`VERSION_FIELD_VERSION`].
pub const VERSION_FIELD_FEATURES: &str = "features";
/// See [`VERSION_FIELD_VERSION`].
pub const VERSION_FIELD_DEBUG_ASSERTIONS: &str = "debug_assertions";

/// Separator between feature names in the *text* rendering.
///
/// [`INLINE_LIST_SEPARATOR`] rather than [`BUILD_FEATURE_SEPARATOR`], because
/// this one is read by a person in a table cell and the other is parsed out of
/// an environment variable. The JSON shape carries an array and applies neither.
pub const VERSION_FEATURE_SEPARATOR: &str = INLINE_LIST_SEPARATOR;

/// Text rendering of an empty feature list.
///
/// A word rather than [`UNKNOWN_VALUE`], because "this build enabled no optional
/// features" is a *known* answer and must not be confused with "we could not
/// find out", which is what the dash means everywhere else in the report.
pub const VERSION_FEATURES_NONE: &str = "none";

/// Feature name reported when `dctl version --check` is asked to look for an
/// update.
pub const VERSION_UPDATE_CHECK_FEATURE: &str = "dctl version --check";

/// Remediation hint attached to [`VERSION_UPDATE_CHECK_FEATURE`].
///
/// Says what *did* happen as well as what did not: the report above the error is
/// real, and a user reading only the last line should not conclude that the
/// whole command failed.
pub const VERSION_UPDATE_CHECK_HINT: &str = "The build information above is complete and was printed. Only the update \
     lookup is missing: DCTL has no release feed to query in this build, and \
     inventing an 'up to date' answer would be worse than saying so.";

// ── `dctl about` output ──────────────────────────────────────────────────────

/// Column headers for the remote-summary table of `dctl about`.
pub const ABOUT_COLUMN_SETTING: &str = "Setting";
/// See [`ABOUT_COLUMN_SETTING`].
pub const ABOUT_COLUMN_VALUE: &str = "Value";

/// Column headers for the capability table of `dctl about --capabilities`.
pub const ABOUT_COLUMN_CAPABILITY: &str = "Capability";
/// See [`ABOUT_COLUMN_CAPABILITY`].
pub const ABOUT_COLUMN_SUPPORTED: &str = "Supported";
/// See [`ABOUT_COLUMN_CAPABILITY`].
pub const ABOUT_COLUMN_DESCRIPTION: &str = "Description";

/// Text rendering of a capability the provider has.
///
/// Lower-case words rather than glyphs: this table is grepped
/// (`dctl about --capabilities b2:bucket | grep multipart`) at least as often as
/// it is read, and a tick mark is neither typeable nor safe on a legacy console.
/// The JSON shape carries a real boolean and never applies these.
pub const ABOUT_SUPPORTED_YES: &str = "yes";
/// See [`ABOUT_SUPPORTED_YES`].
pub const ABOUT_SUPPORTED_NO: &str = "no";

/// Row labels in the `dctl about` remote summary, spelled as the JSON field
/// names for the reason given on [`VERSION_FIELD_VERSION`].
pub const ABOUT_FIELD_REMOTE: &str = "remote";
/// See [`ABOUT_FIELD_REMOTE`].
pub const ABOUT_FIELD_PROVIDER: &str = "provider";
/// See [`ABOUT_FIELD_REMOTE`].
pub const ABOUT_FIELD_STORAGE_PROVIDER: &str = "storage_provider";
/// See [`ABOUT_FIELD_REMOTE`].
pub const ABOUT_FIELD_ENCRYPTED: &str = "encrypted";
/// See [`ABOUT_FIELD_REMOTE`].
pub const ABOUT_FIELD_CHAIN: &str = "chain";
/// See [`ABOUT_FIELD_REMOTE`].
///
/// Unlike its siblings this one names no table row — the capability matrix is
/// its own table — so the only thing that reads it is the test asserting that
/// `--json` really nests the matrix under this key. That is a JSON shape users
/// script against, and a `serde` rename is a literal that cannot read a
/// constant, so the constant's job here is to be the assertion's copy of the
/// contract rather than the serialiser's.
#[allow(dead_code)]
pub const ABOUT_FIELD_CAPABILITIES: &str = "capabilities";

/// Hint shown when `dctl about` was given neither a remote nor a default.
pub const ABOUT_TARGET_HINT: &str = "Name the remote in the command ('dctl about vault:'), or set a default with \
     --remote / DCTL_REMOTE.";

/// Feature name reported when `dctl about` is asked for usage and quota.
///
/// Spelled as the *missing measurement* rather than as the command, because
/// everything else `about` does — resolving the remote, following a vault chain,
/// reporting capabilities — works, and a user told "`dctl about` is not
/// implemented" would reasonably stop reading there.
pub const ABOUT_USAGE_FEATURE: &str = "reading usage and quota from a remote";

/// Remediation hint attached to [`ABOUT_USAGE_FEATURE`].
pub const ABOUT_USAGE_HINT: &str = "No provider in this build can be asked how much it is holding — \
     `dctl_store::Backend` has no usage or quota call, which is why both appear \
     as unsupported in the capability table. `dctl about --capabilities REMOTE` \
     reports what the remote can do, offline and without credentials.";

/// Notice printed before a capability report, so nobody reads it as a live
/// answer from the provider.
///
/// The distinction matters: these rows describe what the *backend
/// implementation* supports, which is knowable without a network round trip and
/// is therefore what `--capabilities` answers. What a particular bucket permits
/// this particular key to do is a different question, and one DCTL cannot answer
/// until it can talk to the provider.
pub const ABOUT_CAPABILITIES_NOTICE: &str = "capabilities are declared by the backend implementation, not probed from \
     the provider: no request was made and no credential was read";

// ── The capability matrix ────────────────────────────────────────────────────
//
// What each provider type can do, as a table rather than as a match, so
// `dctl about --capabilities` and the documentation generator read the same
// rows. Every claim below is a property of the backend in `dctl-store`, not of
// the provider's marketing: `range_reads` is here because `Backend::get_range`
// is on the trait and every implementation honours it, and `usage_reporting` is
// absent from every provider because no such call exists on the trait at all.
//
// The third column lists the provider types that have the capability. Listing
// the *haves* rather than a full grid keeps a new provider from silently
// inheriting a `false` it was never considered for — an omission shows up as
// "unsupported", which is the safe direction to be wrong in.
//
// [`PROVIDER_VAULT`] never appears: a vault remote stores nothing itself, so its
// capabilities are those of the remote it wraps. `about` follows the chain to
// the storage provider and reports that one's row.

/// Serve an arbitrary byte range without transferring the whole object.
pub const CAPABILITY_RANGE_READS: &str = "range_reads";

/// Refuse to report a write as stored until the stored bytes match the expected
/// content hash.
pub const CAPABILITY_VERIFIED_WRITES: &str = "verified_writes";

/// Enumerate objects one bounded page at a time.
pub const CAPABILITY_PAGED_LISTING: &str = "paged_listing";

/// Split one large object across several requests.
pub const CAPABILITY_MULTIPART_UPLOAD: &str = "multipart_upload";

/// Represent a directory that contains no objects.
pub const CAPABILITY_EMPTY_DIRECTORIES: &str = "empty_directories";

/// Report how much the remote currently holds.
pub const CAPABILITY_USAGE_REPORTING: &str = "usage_reporting";

/// Report the account's storage allowance and what is left of it.
pub const CAPABILITY_QUOTA_REPORTING: &str = "quota_reporting";

/// Every capability, what it means, and which providers have it.
///
/// Ordered by how load-bearing the capability is to DCTL's promises rather than
/// alphabetically, so the table reads as an argument: the three the durability
/// and streaming contracts rest on come first, the two that vary by provider
/// follow, and the two nothing supports yet come last.
pub const BACKEND_CAPABILITIES: &[(&str, &str, &[&str])] = &[
    (
        CAPABILITY_RANGE_READS,
        "Serve an arbitrary byte range without transferring the whole object. \
         What makes 'dctl cat' seekable and a mount usable on a 50 GB file.",
        &[PROVIDER_LOCAL, PROVIDER_B2, PROVIDER_S3, PROVIDER_R2],
    ),
    (
        CAPABILITY_VERIFIED_WRITES,
        "Refuse to report a write as stored until the stored bytes match the \
         expected content hash (PLAN.md §6 step 5).",
        &[PROVIDER_LOCAL, PROVIDER_B2, PROVIDER_S3, PROVIDER_R2],
    ),
    (
        CAPABILITY_PAGED_LISTING,
        "Enumerate objects one bounded page at a time, so memory stays flat on a \
         ten-million-object remote (PLAN.md §16.2).",
        &[PROVIDER_LOCAL, PROVIDER_B2, PROVIDER_S3, PROVIDER_R2],
    ),
    (
        CAPABILITY_MULTIPART_UPLOAD,
        "Split one large object across several requests, so a failure retries a \
         part rather than the whole file.",
        &[PROVIDER_B2, PROVIDER_S3, PROVIDER_R2],
    ),
    (
        CAPABILITY_EMPTY_DIRECTORIES,
        "Hold a directory with no objects under it. An object store has no \
         directories at all — only keys that happen to share a prefix.",
        &[PROVIDER_LOCAL],
    ),
    (
        CAPABILITY_USAGE_REPORTING,
        "Report how many bytes and objects the remote currently holds. No \
         backend in this build can: the trait has no call for it.",
        &[],
    ),
    (
        CAPABILITY_QUOTA_REPORTING,
        "Report the account's storage allowance and what is left of it. No \
         backend in this build can: the trait has no call for it.",
        &[],
    ),
];

// ── `dctl completion` ────────────────────────────────────────────────────────
//
// The script goes to **stdout** and nothing else does, so
// `dctl completion zsh > ~/.zsh/completions/_dctl` writes a usable file and
// `dctl completion bash | source /dev/stdin` works in a live shell. The install
// line below is a *note*, and therefore goes to stderr like every other note.

/// Field names in the `--json` rendering of a completion script.
///
/// Spelled here and, separately, by the `serde` derive on the report struct —
/// a rename attribute takes a literal and cannot read a constant. These three
/// are what the shape test compares the serialiser's output against, which is
/// their whole purpose and why they carry `dead_code`: a shell script that pipes
/// `dctl completion zsh --json` into `jq -r .script` breaks silently if a field
/// is renamed, and this is the thing that notices.
#[allow(dead_code)]
pub const COMPLETION_FIELD_SHELL: &str = "shell";
/// See [`COMPLETION_FIELD_SHELL`].
#[allow(dead_code)]
pub const COMPLETION_FIELD_BINARY: &str = "binary";
/// See [`COMPLETION_FIELD_SHELL`].
#[allow(dead_code)]
pub const COMPLETION_FIELD_SCRIPT: &str = "script";

/// Shell names, spelled exactly as `clap_complete`'s `Shell` value enum spells
/// them on the command line.
///
/// Named here so [`COMPLETION_INSTALL_HINTS`] can be keyed by the same word the
/// user typed. `Shell` is `#[non_exhaustive]`, so a lookup by name rather than a
/// `match` is also what keeps a future shell from breaking the build — it gets
/// no install hint until someone writes one, which is a missing note rather than
/// a missing feature.
pub const COMPLETION_SHELL_BASH: &str = "bash";
/// See [`COMPLETION_SHELL_BASH`].
pub const COMPLETION_SHELL_ELVISH: &str = "elvish";
/// See [`COMPLETION_SHELL_BASH`].
pub const COMPLETION_SHELL_FISH: &str = "fish";
/// See [`COMPLETION_SHELL_BASH`].
pub const COMPLETION_SHELL_POWERSHELL: &str = "powershell";
/// See [`COMPLETION_SHELL_BASH`].
pub const COMPLETION_SHELL_ZSH: &str = "zsh";

/// Where each shell wants the generated script, as a line the user can run.
///
/// Written as a shell command rather than as prose because that is what a person
/// does next, and a wrong path here costs someone half an hour of wondering why
/// tab completion does nothing. Each entry uses the conventional location for
/// that shell rather than a DCTL-specific one, so it composes with whatever
/// completion setup the user already has.
pub const COMPLETION_INSTALL_HINTS: &[(&str, &str)] = &[
    (
        COMPLETION_SHELL_BASH,
        "install with: dctl completion bash > /etc/bash_completion.d/dctl \
         (or ~/.local/share/bash-completion/completions/dctl)",
    ),
    (
        COMPLETION_SHELL_ZSH,
        "install with: dctl completion zsh > \"${fpath[1]}/_dctl\" — the file \
         must be on $fpath before compinit runs",
    ),
    (
        COMPLETION_SHELL_FISH,
        "install with: dctl completion fish > ~/.config/fish/completions/dctl.fish",
    ),
    (
        COMPLETION_SHELL_POWERSHELL,
        "install with: dctl completion powershell >> $PROFILE",
    ),
    (
        COMPLETION_SHELL_ELVISH,
        "install with: dctl completion elvish >> ~/.config/elvish/rc.elv",
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkers_outpace_transfers() {
        // The check pipeline must stay ahead of the transfers it feeds.
        const {
            assert!(DEFAULT_CHECKERS > DEFAULT_TRANSFERS);
        }
    }

    #[test]
    fn low_level_retries_exceed_high_level_retries() {
        const {
            assert!(DEFAULT_LOW_LEVEL_RETRIES > DEFAULT_RETRIES);
        }
    }

    #[test]
    fn remote_names_cannot_collide_with_drive_letters() {
        const {
            assert!(
                MIN_REMOTE_NAME_LEN >= 2,
                "a one-character remote name would be ambiguous with C:\\"
            );
        }
    }

    #[test]
    fn unit_tables_are_parallel_and_ascending() {
        assert_eq!(BINARY_UNIT_SUFFIXES.len(), DECIMAL_UNIT_SUFFIXES.len());
        assert_eq!(BINARY_UNIT_SUFFIXES[0], "B");
        assert_eq!(DECIMAL_UNIT_SUFFIXES[0], "B");
    }

    #[test]
    fn divisors_match_their_conventions() {
        assert!((BINARY_DIVISOR - 1024.0).abs() < f64::EPSILON);
        assert!((DECIMAL_DIVISOR - 1000.0).abs() < f64::EPSILON);
    }

    #[test]
    fn time_constants_are_consistent() {
        assert_eq!(SECONDS_PER_HOUR, 3600);
        assert_eq!(SECONDS_PER_DAY, 86_400);
    }

    #[test]
    fn truncation_ratio_is_a_proper_fraction() {
        const {
            assert!(TRUNCATE_TAIL_NUMERATOR < TRUNCATE_TAIL_DENOMINATOR);
        }
    }

    #[test]
    fn truncation_floor_leaves_room_for_the_marker() {
        // Below the marker's own width there is nothing to split, so the floor
        // must sit above it or the head/tail arithmetic has no budget at all.
        assert!(TRUNCATE_MIN_WIDTH > TRUNCATION_ELLIPSIS.chars().count());
    }

    #[test]
    fn glyph_sets_are_interchangeable() {
        // `indicatif` reads `progress_chars` positionally (filled, edge, empty),
        // so the fallback set must have exactly the same number of slots or the
        // ASCII bar would be drawn from the wrong glyphs.
        assert_eq!(
            PROGRESS_CHARS_UNICODE.chars().count(),
            PROGRESS_CHARS_ASCII.chars().count()
        );
        assert!(PROGRESS_CHARS_ASCII.is_ascii());
        assert!(!PROGRESS_CHARS_UNICODE.is_ascii());
    }

    #[test]
    fn spinner_sets_animate_and_terminate() {
        // Every set needs at least one rotation frame plus the final completion
        // frame, or a finished bar parks on a spinner that looks stalled.
        assert!(SPINNER_TICKS_UNICODE.len() >= 2);
        assert!(SPINNER_TICKS_ASCII.len() >= 2);
        assert!(SPINNER_TICKS_ASCII.iter().all(|t| t.is_ascii()));
        assert!(SPINNER_TICKS_UNICODE.iter().all(|t| !t.is_empty()));
    }

    #[test]
    fn locale_variables_are_in_posix_precedence_order() {
        // LC_ALL must be consulted first: it is the override that beats both of
        // the others, and checking it last would silently ignore it.
        assert_eq!(LOCALE_ENV_VARS.first(), Some(&"LC_ALL"));
        assert!(LOCALE_ENV_VARS.contains(&"LANG"));
    }

    #[test]
    fn utf8_markers_are_upper_case() {
        // They are compared against an upper-cased locale value, so a lower-case
        // entry here could never match anything.
        for marker in UTF8_LOCALE_MARKERS {
            assert_eq!(*marker, marker.to_ascii_uppercase());
        }
    }

    #[test]
    fn summary_label_column_fits_every_label() {
        // If a label outgrows the column the values stop lining up, which is the
        // one thing the fixed width buys.
        for label in [
            SUMMARY_LABEL_TRANSFERRED,
            SUMMARY_LABEL_VERIFIED,
            SUMMARY_LABEL_FILES,
            SUMMARY_LABEL_CHECKS,
            SUMMARY_LABEL_SKIPPED,
            SUMMARY_LABEL_DELETED,
            SUMMARY_LABEL_RETRIES,
            SUMMARY_LABEL_MISMATCHES,
            SUMMARY_LABEL_ERRORS,
            SUMMARY_LABEL_ELAPSED,
        ] {
            assert!(
                label.chars().count() <= SUMMARY_LABEL_WIDTH,
                "'{label}' does not fit in a {SUMMARY_LABEL_WIDTH}-character column"
            );
        }
    }

    #[test]
    fn size_suffixes_are_lower_case_and_unique() {
        // Lookup lower-cases the user's suffix before matching, so an upper-case
        // key in the table would be permanently unreachable.
        for (index, (suffix, _)) in SIZE_SUFFIX_MULTIPLIERS.iter().enumerate() {
            assert_eq!(
                *suffix,
                suffix.to_ascii_lowercase(),
                "'{suffix}' would never match"
            );
            for (other, _) in &SIZE_SUFFIX_MULTIPLIERS[index + 1..] {
                assert_ne!(suffix, other, "'{suffix}' is listed twice");
            }
        }
    }

    #[test]
    fn size_suffix_multipliers_follow_their_conventions() {
        let lookup = |name: &str| {
            SIZE_SUFFIX_MULTIPLIERS
                .iter()
                .find(|(suffix, _)| *suffix == name)
                .map(|(_, multiplier)| *multiplier)
        };

        // A bare letter is binary; the two-letter SI spelling is decimal. This is
        // the distinction the table exists to encode.
        assert_eq!(lookup("g"), Some(BYTES_PER_GIB));
        assert_eq!(lookup("gib"), Some(BYTES_PER_GIB));
        assert_eq!(lookup("gb"), Some(BYTES_PER_GB));
        assert!(
            lookup("g") > lookup("gb"),
            "the bare letter must be the larger, binary unit"
        );
        assert_eq!(lookup("x"), None);
    }

    #[test]
    fn the_size_ladder_is_derived_from_the_divisors() {
        assert!((BYTES_PER_MIB - BINARY_DIVISOR * BINARY_DIVISOR).abs() < f64::EPSILON);
        assert!((BYTES_PER_KB - 1_000.0).abs() < f64::EPSILON);
        assert!((BYTES_PER_TB - 1e12).abs() < f64::EPSILON);
    }

    #[test]
    fn the_no_limit_spellings_are_distinct() {
        assert_ne!(SIZE_LIMIT_OFF, SIZE_LIMIT_ZERO);
        assert!(SIZE_PARSE_EXAMPLES.contains(SIZE_LIMIT_OFF));
    }

    #[test]
    fn duration_suffixes_are_distinct_single_letters() {
        let suffixes = [
            DURATION_SECOND_SUFFIX,
            DURATION_MINUTE_SUFFIX,
            DURATION_HOUR_SUFFIX,
            DURATION_DAY_SUFFIX,
        ];
        for (index, suffix) in suffixes.iter().enumerate() {
            assert!(suffix.is_ascii_alphabetic());
            assert!(!suffixes[index + 1..].contains(suffix));
        }
    }

    #[test]
    fn precision_narrows_as_magnitude_grows() {
        // The whole point of the cutoff: fewer decimals once the mantissa is
        // wider, so a size column keeps a constant width either side of it.
        let widths = [
            format!("{:.*}", SIZE_DECIMALS_BELOW_CUTOFF, 9.99_f64).len(),
            format!("{:.*}", SIZE_DECIMALS_ABOVE_CUTOFF, 10.0_f64).len(),
        ];
        assert_eq!(widths[0], widths[1], "the cutoff must not change the width");
    }

    #[test]
    fn the_fallback_success_mark_survives_a_non_unicode_terminal() {
        // The whole reason the fallback exists: it must contain nothing that a
        // legacy console or a non-UTF-8 locale could turn into mojibake.
        assert!(SUCCESS_MARK_ASCII.is_ascii());
        assert!(!SUCCESS_MARK.is_ascii());
    }

    #[test]
    fn the_new_vault_password_floor_is_a_real_floor() {
        // A zero or one-character minimum would make the check decorative.
        const {
            assert!(MIN_VAULT_PASSWORD_LEN >= 8, "NIST SP 800-63B sets eight");
        }
    }

    #[test]
    fn provider_types_are_lower_case_unique_and_described() {
        // The first column is matched verbatim against a config file's `type`
        // key, so an upper-case entry could never be selected, and a duplicate
        // would make `config providers` print the same row twice.
        for (index, (name, description)) in REMOTE_PROVIDER_TYPES.iter().enumerate() {
            assert_eq!(*name, name.to_ascii_lowercase(), "'{name}' is unmatchable");
            // A one-character type could not be used as a remote name either.
            assert!(name.len() >= MIN_REMOTE_NAME_LEN, "'{name}' is too short");
            assert!(!description.is_empty(), "'{name}' has no description");
            for (other, _) in &REMOTE_PROVIDER_TYPES[index + 1..] {
                assert_ne!(name, other, "'{name}' is listed twice");
            }
        }
    }

    #[test]
    fn every_provider_constant_appears_in_the_advertised_table() {
        // `config providers` prints the table while the registry matches on the
        // constants. A constant missing from the table would build a backend
        // nobody could discover; a table row with no constant would advertise a
        // provider the registry cannot build.
        let advertised: Vec<&str> = REMOTE_PROVIDER_TYPES.iter().map(|(n, _)| *n).collect();
        let known = [PROVIDER_LOCAL, PROVIDER_B2, PROVIDER_S3, PROVIDER_R2];
        for name in known {
            assert!(advertised.contains(&name), "'{name}' is not advertised");
        }
        assert_eq!(advertised.len(), known.len(), "the two lists disagree");
    }

    #[test]
    fn remote_settings_keys_are_lower_case_and_distinct() {
        // They are matched verbatim against TOML keys a human typed, and TOML is
        // case-sensitive, so an upper-case entry would silently never match.
        let keys = [
            CONFIG_KEY_BUCKET,
            CONFIG_KEY_ENDPOINT,
            CONFIG_KEY_REGION,
            CONFIG_KEY_ACCOUNT,
            CONFIG_KEY_PATH,
            CONFIG_REMOTE_TYPE_KEY,
        ];
        for (index, key) in keys.iter().enumerate() {
            assert_eq!(*key, key.to_ascii_lowercase(), "'{key}' is unmatchable");
            assert!(!key.is_empty());
            assert!(
                !keys[index + 1..].contains(key),
                "'{key}' names two different settings"
            );
        }
    }

    #[test]
    fn credential_variables_are_distinct_and_name_no_config_key() {
        // Two providers sharing one variable would make a single export silently
        // reconfigure both, and a credential that also had a config-file
        // spelling would defeat the rule that secrets never live in the file.
        let credentials = [
            ENV_B2_KEY_ID,
            ENV_B2_APP_KEY,
            ENV_S3_ENDPOINT,
            ENV_S3_REGION,
            ENV_S3_ACCESS_KEY,
            ENV_S3_SECRET_KEY,
            ENV_R2_ACCOUNT_ID,
            ENV_R2_ACCESS_KEY,
            ENV_R2_SECRET_KEY,
        ];
        for (index, name) in credentials.iter().enumerate() {
            assert_eq!(*name, name.to_ascii_uppercase(), "'{name}' is not a var");
            assert!(
                !credentials[index + 1..].contains(name),
                "'{name}' is claimed by two providers"
            );
        }
        // The secret-bearing ones in particular must have no config spelling.
        for secret in [
            ENV_B2_APP_KEY,
            ENV_S3_ACCESS_KEY,
            ENV_S3_SECRET_KEY,
            ENV_R2_ACCESS_KEY,
            ENV_R2_SECRET_KEY,
        ] {
            let lowered = secret.to_ascii_lowercase();
            for key in [
                CONFIG_KEY_BUCKET,
                CONFIG_KEY_ENDPOINT,
                CONFIG_KEY_REGION,
                CONFIG_KEY_ACCOUNT,
                CONFIG_KEY_PATH,
            ] {
                assert!(!lowered.ends_with(key), "'{secret}' has a config spelling");
            }
        }
    }

    #[test]
    fn the_two_path_separators_and_the_remote_separator_are_distinct() {
        // The spec parser tests all three against the same user-typed string; a
        // collision would make one rule shadow another.
        assert_ne!(PATH_SEPARATOR, WINDOWS_PATH_SEPARATOR);
        assert_ne!(PATH_SEPARATOR, REMOTE_SEPARATOR);
        assert_ne!(WINDOWS_PATH_SEPARATOR, REMOTE_SEPARATOR);
        assert_ne!(RELATIVE_PATH_MARKER, REMOTE_SEPARATOR);
        assert_ne!(RELATIVE_PATH_MARKER, PATH_SEPARATOR);
    }

    #[test]
    fn the_separator_set_holds_both_separators_and_nothing_else() {
        // It is the single statement of "this character divides components".
        // Dropping one would let that character survive into a stored name;
        // adding an ordinary character would make legal filenames unstorable.
        assert!(LOGICAL_PATH_SEPARATORS.contains(&PATH_SEPARATOR));
        assert!(LOGICAL_PATH_SEPARATORS.contains(&WINDOWS_PATH_SEPARATOR));
        assert_eq!(LOGICAL_PATH_SEPARATORS.len(), 2);
    }

    #[test]
    fn the_editor_search_order_prefers_visual() {
        // POSIX gives VISUAL precedence for a full-screen editor, which is what
        // someone hand-editing TOML expects to get.
        assert_eq!(EDITOR_ENV_VARS.first(), Some(&"VISUAL"));
        assert!(EDITOR_ENV_VARS.contains(&"EDITOR"));
        assert!(!DEFAULT_EDITOR.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn the_exposure_mask_is_the_complement_of_the_enforced_mode() {
        // Every bit the enforced mode grants must be outside the mask, and every
        // bit outside the owner triad must be inside it — otherwise the warning
        // fires on a correctly-permissioned file, or stays silent on a leaky one.
        assert_eq!(CONFIG_FILE_MODE & CONFIG_FILE_EXPOSED_MODE_MASK, 0);
        assert_eq!(CONFIG_FILE_EXPOSED_MODE_MASK, 0o777 & !0o700);
    }

    #[cfg(unix)]
    #[test]
    fn the_config_directory_is_no_more_open_than_the_config_file() {
        // A 0600 file inside a directory others can write is still replaceable
        // wholesale, so the directory must be at least as closed as the file.
        assert_eq!(CONFIG_DIR_MODE & CONFIG_FILE_EXPOSED_MODE_MASK, 0);

        // The owner needs search (`x`) on a directory or nothing inside it is
        // reachable — a mode copied straight from the file would lock the user
        // out of their own configuration.
        const OWNER_SEARCH: u32 = 0o100;
        assert_ne!(
            CONFIG_DIR_MODE & OWNER_SEARCH,
            0,
            "the owner needs search permission on the configuration directory"
        );
    }

    #[test]
    fn vault_is_a_wrapper_and_never_a_destination() {
        // `dctl config providers` lists places bytes can land. A vault remote is
        // not one: it wraps a base remote, so offering it would produce a config
        // that names no storage at all.
        assert!(
            !REMOTE_PROVIDER_TYPES
                .iter()
                .any(|(name, _)| *name == PROVIDER_VAULT),
            "vault must not be advertised as a provider"
        );
        // It is still a legal `type` value, and must obey the same spelling rules
        // as the real providers or a config file could not name it.
        assert_eq!(PROVIDER_VAULT, PROVIDER_VAULT.to_ascii_lowercase());
        assert!(PROVIDER_VAULT.len() >= MIN_REMOTE_NAME_LEN);
    }

    #[test]
    fn remote_name_bounds_leave_room_for_a_usable_name() {
        const {
            assert!(
                MAX_REMOTE_NAME_LEN > MIN_REMOTE_NAME_LEN,
                "the ceiling must sit above the floor"
            );
        }
        // Every provider type is also a reserved remote name, so each has to fit
        // inside the bounds or the reservation could never be triggered.
        for (name, _) in REMOTE_PROVIDER_TYPES {
            assert!(name.len() <= MAX_REMOTE_NAME_LEN);
        }
    }

    #[test]
    fn remote_name_punctuation_cannot_be_confused_with_a_path() {
        // The whole point of restricting the charset: a name containing any of
        // these could not be told apart from a path in a `name:path` spec.
        // [`RELATIVE_PATH_MARKER`] is deliberately *not* in this list — `.` is
        // allowed inside a name (`vault.old`) and excluded only as the first
        // character, which is the rule that keeps `../backup` a path.
        for forbidden in [PATH_SEPARATOR, WINDOWS_PATH_SEPARATOR, REMOTE_SEPARATOR] {
            assert!(
                !REMOTE_NAME_EXTRA_CHARS.contains(&forbidden),
                "'{forbidden}' would make a name ambiguous with a path"
            );
        }
        assert!(REMOTE_NAME_EXTRA_CHARS.iter().all(char::is_ascii));
    }

    #[test]
    fn a_vault_chain_may_be_at_least_a_wrapper_over_a_base() {
        // Two links is the minimum a working vault remote needs: itself and the
        // plain remote it stores through. A smaller bound would reject every
        // valid config.
        const {
            assert!(
                MAX_VAULT_CHAIN_DEPTH >= 2,
                "a vault remote plus its base is already two links"
            );
        }
    }

    #[test]
    fn the_config_header_states_the_no_secrets_rule() {
        // The header is the enforcement rule written where someone will read it.
        // If these words ever disappear, the file stops warning the one person
        // it exists for: whoever is about to paste a key into it.
        assert!(CONFIG_FILE_HEADER.contains("NON-SECRET"));
        assert!(CONFIG_FILE_HEADER.contains("Credentials"));
        // Every line must be a TOML comment, or a saved config would not parse.
        for line in CONFIG_FILE_HEADER.lines() {
            assert!(
                line.is_empty() || line.starts_with('#'),
                "header line is not a TOML comment: {line}"
            );
        }
    }

    #[test]
    fn the_staging_file_is_distinguishable_from_the_config() {
        // The staging name is `<config><sep><pid><suffix>`; if the suffix were
        // empty the temp file would collide with the real one and a crash would
        // leave a half-written config in place of the good one.
        assert!(!CONFIG_TEMP_SUFFIX.is_empty());
        assert!(CONFIG_TEMP_SUFFIX.starts_with(CONFIG_TEMP_NAME_SEPARATOR));
        assert!(!CONFIG_FILE_NAME.ends_with(CONFIG_TEMP_SUFFIX));
    }

    #[test]
    fn config_setting_keys_are_distinct_and_toml_safe() {
        // A bare TOML key may contain only these characters; anything else would
        // have to be quoted, which no hand-editor would expect.
        let keys = [
            CONFIG_REMOTE_TYPE_KEY,
            CONFIG_KEY_REMOTES,
            CONFIG_KEY_BUCKET,
            CONFIG_KEY_ENDPOINT,
            CONFIG_KEY_REGION,
            CONFIG_KEY_ACCOUNT,
            CONFIG_KEY_PATH,
            CONFIG_KEY_BASE,
            CONFIG_KEY_BASE_PATH,
            CONFIG_KEY_CHUNK_SIZE,
            CONFIG_KEY_VERIFY,
            CONFIG_KEY_REQUIRE_VAULT,
        ];
        for (index, key) in keys.iter().enumerate() {
            assert!(!key.is_empty());
            assert!(
                key.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'),
                "'{key}' would need quoting in TOML"
            );
            assert!(!keys[index + 1..].contains(key), "'{key}' is listed twice");
        }
    }

    #[test]
    fn a_derived_store_name_is_still_a_legal_remote_name() {
        // `<name>-store` is typed on every replication command line, so the
        // suffix has to be made of characters a remote name may contain — and
        // has to leave room under the ceiling for a name somebody actually
        // chose. A suffix that pushed every name over the limit would make the
        // default unusable and the `--store-name` escape hatch mandatory.
        for character in INIT_STORE_NAME_SUFFIX.chars() {
            assert!(
                character.is_ascii_alphanumeric() || REMOTE_NAME_EXTRA_CHARS.contains(&character),
                "'{character}' cannot appear in a remote name"
            );
        }
        // A suffix that reads as part of the name it follows would make
        // `archivestore` and `archive` two names nobody can tell apart at a
        // glance, which is the opposite of what naming the base is for.
        assert!(!INIT_STORE_NAME_SUFFIX.is_empty());
        assert!(INIT_STORE_NAME_SUFFIX.starts_with(REMOTE_NAME_EXTRA_CHARS));
        const {
            assert!(INIT_STORE_NAME_SUFFIX.len() + MIN_REMOTE_NAME_LEN < MAX_REMOTE_NAME_LEN);
        }
    }

    #[test]
    fn the_envelope_header_is_exactly_the_frozen_format_fields() {
        // The header is `magic(4) ‖ version(1) ‖ vault_id(16) ‖ slot_count(2)`,
        // and the offsets below are read straight out of a fetched range. An
        // arithmetic slip here would look for the slot count inside the vault id
        // and reject every real envelope.
        const {
            assert!(VAULT_ENVELOPE_MAGIC.len() == 4);
            assert!(VAULT_ENVELOPE_SLOT_COUNT_OFFSET == 4 + 1 + 16);
            assert!(VAULT_ENVELOPE_HEADER_LEN as usize == VAULT_ENVELOPE_SLOT_COUNT_OFFSET + 2);
            assert!(VAULT_ENVELOPE_MIN_SLOTS >= 1);
            assert!(VAULT_ENVELOPE_MAX_SLOTS >= VAULT_ENVELOPE_MIN_SLOTS);
            assert!(VAULT_ENVELOPE_VERSION >= 1);
        }
        // The key is a logical path: `/`-separated on every platform, relative
        // to the store's root, never absolute.
        assert!(!VAULT_ENVELOPE_OBJECT_KEY.starts_with(PATH_SEPARATOR));
        assert!(VAULT_ENVELOPE_OBJECT_KEY.contains(PATH_SEPARATOR));
    }

    #[test]
    fn config_verify_slugs_are_distinct_and_machine_readable() {
        // They land in `--json`, so a duplicate would make two different faults
        // indistinguishable to whatever is deciding whether to fail a release.
        let slugs = [
            CONFIG_VERIFY_STATUS_OK,
            CONFIG_FINDING_UNKNOWN_BASE,
            CONFIG_FINDING_CHAIN_CYCLE,
            CONFIG_FINDING_CHAIN_TOO_DEEP,
            CONFIG_FINDING_ILLEGAL_NAME,
            CONFIG_FINDING_CASE_COLLISION,
            CONFIG_FINDING_INCOMPLETE_SETTINGS,
            CONFIG_FINDING_PLAIN_AT_VAULT_LOCATION,
        ];
        for (index, slug) in slugs.iter().enumerate() {
            assert!(!slug.contains(' '), "'{slug}' must be a slug");
            assert_eq!(*slug, slug.to_lowercase());
            assert!(!slugs[index + 1..].contains(slug), "'{slug}' twice");
        }
        // The two modes are the answer to one question and must never collide.
        assert_ne!(CONFIG_MODE_PLAIN, CONFIG_MODE_SEALED);
        // A location separator that could be read as remote syntax would make a
        // rendered location ambiguous in the error messages that print it.
        assert_ne!(LOCATION_FIELD_SEPARATOR, REMOTE_SEPARATOR);
        assert_ne!(LOCATION_FIELD_SEPARATOR, PATH_SEPARATOR);
    }

    #[test]
    fn the_hashsum_separator_is_exactly_the_coreutils_one() {
        // Two spaces, nothing else: `sha256sum -c` splits on them, so a single
        // space or a tab would silently produce a file that cannot be checked.
        assert_eq!(HASHSUM_FIELD_SEPARATOR, "  ");
        assert_eq!(HASHSUM_FIELD_SEPARATOR.len(), 2);
        assert!(HASHSUM_FIELD_SEPARATOR.chars().all(|c| c == ' '));
        // The binary marker replaces the *second* space, so it must not be one.
        assert_ne!(HASHSUM_BINARY_MARKER, ' ');
    }

    #[test]
    fn hash_widths_are_two_hex_digits_per_output_byte() {
        assert_eq!(HASH_HEX_LEN_BLAKE3, blake3::OUT_LEN * 2);
        assert_eq!(HASH_HEX_LEN_SHA1, 20 * 2);
        assert_eq!(HASH_HEX_LEN_SHA256, 32 * 2);
    }

    #[test]
    fn integrity_verdicts_and_differences_are_distinct_slugs() {
        // Both sets are matched against as strings by downstream consumers, so a
        // duplicate would make two different outcomes indistinguishable.
        let slugs = [
            VERDICT_OK,
            VERDICT_CORRUPT,
            VERDICT_MISSING,
            VERDICT_UNREADABLE,
            DIFFERENCE_MATCH,
            DIFFERENCE_DIFFER,
            DIFFERENCE_MISSING_ON_SRC,
            DIFFERENCE_MISSING_ON_DST,
            DIFFERENCE_ERROR,
        ];
        for (index, slug) in slugs.iter().enumerate() {
            assert!(!slug.is_empty());
            assert!(!slug.contains(' '), "'{slug}' must be one token");
            assert!(!slugs[index + 1..].contains(slug), "'{slug}' listed twice");
        }
    }

    #[test]
    fn combined_marks_are_distinct_and_never_path_characters() {
        // The mark is separated from the path by one space and nothing else, so
        // a mark that could itself be a space would make the line ambiguous.
        let marks = [
            COMBINED_MARK_MATCH,
            COMBINED_MARK_MISSING_ON_SRC,
            COMBINED_MARK_MISSING_ON_DST,
            COMBINED_MARK_DIFFER,
            COMBINED_MARK_ERROR,
        ];
        for (index, mark) in marks.iter().enumerate() {
            assert_ne!(*mark, COMBINED_MARK_SEPARATOR);
            assert!(!marks[index + 1..].contains(mark), "'{mark}' listed twice");
        }
    }

    #[test]
    fn a_scrub_reads_everything_unless_told_otherwise() {
        // The default has to be a full pass: `PLAN.md` §13.4's promise is that
        // rot is found before restore day, and a sampled default would quietly
        // leave most of the dataset unmeasured while still printing "healthy".
        assert_eq!(SCRUB_FULL_SAMPLE_PERCENT as u64, SCRUB_SAMPLE_BASIS);
        const {
            assert!(SCRUB_MIN_SAMPLE_PERCENT >= 1, "0% would measure nothing");
        }
        const {
            assert!(SCRUB_MIN_SAMPLE_PERCENT < SCRUB_FULL_SAMPLE_PERCENT);
        }
        assert_eq!(SCRUB_MAX_ERRORS_UNLIMITED, 0);
        assert!(!SCRUB_SAMPLE_KEY_CONTEXT.is_empty());
    }

    #[test]
    fn health_grades_are_distinct() {
        assert_ne!(HEALTH_HEALTHY, HEALTH_DEGRADED);
        assert_ne!(HEALTH_DEGRADED, HEALTH_DAMAGED);
        assert_ne!(HEALTH_HEALTHY, HEALTH_DAMAGED);
    }

    #[test]
    fn the_integrity_failure_message_says_the_data_was_not_served() {
        // This is the promise exit code 21 encodes; a reworded notice that drops
        // the negation would invert its meaning.
        assert!(INTEGRITY_NOT_SERVED_NOTICE.contains("NOT"));
        assert!(!INTEGRITY_FAILURE_HINT.is_empty());
    }

    #[test]
    fn plan_action_slugs_are_distinct_and_lower_case() {
        // They are simultaneously a JSON value and the first column of the text
        // plan; two actions sharing a slug would make a filtered dry run select
        // the wrong rows — including the deletes.
        let actions = [
            PLAN_ACTION_COPY,
            PLAN_ACTION_UPDATE,
            PLAN_ACTION_DELETE,
            PLAN_ACTION_SKIP,
            PLAN_ACTION_MKDIR,
        ];
        for (index, action) in actions.iter().enumerate() {
            assert_eq!(*action, action.to_ascii_lowercase());
            assert!(!actions[index + 1..].contains(action), "'{action}' twice");
        }
    }

    #[test]
    fn plan_reason_slugs_are_distinct() {
        let reasons = [
            PLAN_REASON_MISSING,
            PLAN_REASON_SIZE,
            PLAN_REASON_MODIFIED,
            PLAN_REASON_CHECKSUM,
            PLAN_REASON_IDENTICAL,
            PLAN_REASON_EXISTS,
            PLAN_REASON_DESTINATION_NEWER,
            PLAN_REASON_EXTRA,
            PLAN_REASON_EMPTY_SOURCE_DIR,
            PLAN_REASON_UNTRAVERSED,
        ];
        for (index, reason) in reasons.iter().enumerate() {
            assert!(!reasons[index + 1..].contains(reason), "'{reason}' twice");
        }
    }

    #[test]
    fn the_plan_arrow_survives_a_pipe() {
        // The plan is stdout data, so every glyph in it has to be readable by a
        // consumer that never negotiated UTF-8.
        assert!(PLAN_PATH_ARROW.is_ascii());
    }

    #[test]
    fn a_modify_window_of_zero_would_resend_everything() {
        // Whole-second timestamps at the provider round-trip to a value the local
        // clock disagrees with by a fraction; a zero window turns that into a
        // full re-upload on every run.
        const {
            assert!(DEFAULT_MODIFY_WINDOW_SECS >= 1);
        }
    }

    #[test]
    fn walks_never_follow_symlinks() {
        // A self-referential link would loop forever and an outward link would
        // copy data the user never named. Both are worse than a skipped link.
        const {
            assert!(!WALK_FOLLOW_SYMLINKS);
        }
    }

    #[test]
    fn the_sync_delete_alarm_is_a_proper_fraction() {
        const {
            assert!(SYNC_DELETE_ALARM_FRACTION > 0.0);
        }
        const {
            assert!(SYNC_DELETE_ALARM_FRACTION <= 1.0);
        }
    }

    #[test]
    fn the_immutable_refusal_names_enough_paths_to_be_actionable() {
        // One path is not enough to tell a mistyped destination from a single
        // genuinely re-sent file, and an unbounded list turns a refusal into a
        // flood on a large tree.
        const {
            assert!(IMMUTABLE_REFUSAL_SAMPLE >= 3);
        }
        // Both refusals have to point at a way forward, and both ways out are
        // named: the flag itself, and the traversal that makes it enforceable.
        assert!(IMMUTABLE_REFUSAL_HINT.contains("--immutable"));
        assert!(IMMUTABLE_REFUSAL_HINT.contains("--dry-run"));
        assert!(IMMUTABLE_NO_TRAVERSE_CONFLICT.contains("--no-traverse"));
        assert!(IMMUTABLE_NO_TRAVERSE_HINT.contains("--no-traverse"));
    }

    #[test]
    fn capability_gaps_explain_themselves() {
        // An `unimplemented` error is still an error a user has to act on, so
        // every one of them carries a next step.
        for hint in [
            TRANSFER_ENGINE_HINT,
            PATTERN_FILTER_HINT,
            REMOTE_ENUMERATION_HINT,
        ] {
            assert!(!hint.is_empty());
        }
        // The filter refusal must say *why* silence would be worse than failure.
        assert!(PATTERN_FILTER_HINT.contains("sync"));
    }

    #[test]
    fn the_genesis_link_is_a_full_width_zero_hash() {
        // A short genesis value would compare unequal to every real hash for the
        // wrong reason, and a *long* one would never be produced by the writer.
        // Both would make the first record unverifiable.
        assert_eq!(AUDIT_CHAIN_GENESIS_PREV.len(), HASH_HEX_LEN_BLAKE3);
        assert!(AUDIT_CHAIN_GENESIS_PREV.chars().all(|c| c == '0'));
    }

    #[test]
    fn the_audit_hash_separator_cannot_occur_inside_a_field() {
        // The forgery this prevents: if a path could contain the separator, two
        // different records could serialise to the same bytes and hash alike.
        // Control characters are rejected by `platform::names`, which is what
        // makes the guarantee hold.
        assert!(AUDIT_HASH_FIELD_SEPARATOR.is_control());
        assert!((AUDIT_HASH_FIELD_SEPARATOR as u32) < 0x20);
    }

    #[test]
    fn an_abbreviated_hash_is_never_mistakeable_for_a_whole_one() {
        // The listing shows a prefix for recognition only. If it were the full
        // width, a reader could believe the listing had verified something.
        const {
            assert!(AUDIT_HASH_DISPLAY_LEN < HASH_HEX_LEN_BLAKE3);
        }
        const {
            assert!(AUDIT_HASH_DISPLAY_LEN > 0);
        }
    }

    #[test]
    fn the_two_audit_verdicts_are_distinct_and_lower_case() {
        // They are compared by scripts, so case has to be stable.
        assert_ne!(AUDIT_VERDICT_INTACT, AUDIT_VERDICT_BROKEN);
        for verdict in [AUDIT_VERDICT_INTACT, AUDIT_VERDICT_BROKEN] {
            assert_eq!(verdict, verdict.to_lowercase());
        }
    }

    #[test]
    fn relative_time_suffixes_ascend_and_do_not_repeat() {
        // A duplicate letter would make one row unreachable; a non-ascending
        // table would mean the doc comment lies about which unit is coarsest.
        for (index, (letter, seconds)) in TIME_RELATIVE_SUFFIXES.iter().enumerate() {
            assert!(letter.is_ascii_lowercase());
            assert!(*seconds > 0);
            for (other, other_seconds) in &TIME_RELATIVE_SUFFIXES[index + 1..] {
                assert_ne!(letter, other, "'{letter}' is listed twice");
                assert!(other_seconds > seconds, "the ladder must ascend");
            }
        }
        // Minutes, never months: the documented resolution of the `1m` question.
        assert_eq!(
            TIME_RELATIVE_SUFFIXES
                .iter()
                .find(|(letter, _)| *letter == 'm')
                .map(|(_, seconds)| *seconds),
            Some(SECONDS_PER_MINUTE)
        );
    }

    #[test]
    fn accepted_time_spellings_include_the_one_dctl_writes() {
        // DCTL prints RFC 3339 with a `T` and a `Z`; anything it prints must be
        // something it can read back, or a script cannot round-trip a timestamp.
        assert!(TIME_DATE_TIME_SEPARATORS.contains(&RFC3339_DATE_TIME_SEPARATOR));
        assert!(TIME_UTC_DESIGNATORS.contains(&RFC3339_UTC_DESIGNATOR));
        const {
            assert!(TIME_MIN_YEAR < TIME_MAX_YEAR);
        }
        assert!(TIME_PARSE_EXAMPLES.contains(TIME_NOW_KEYWORD));
    }

    #[test]
    fn snapshot_name_punctuation_stays_out_of_path_syntax() {
        // A snapshot name may become a path component and an object-key
        // fragment, so nothing in it may be read as structure.
        for extra in SNAPSHOT_NAME_EXTRA_CHARS {
            assert_ne!(*extra, PATH_SEPARATOR);
            assert_ne!(*extra, REMOTE_SEPARATOR);
        }
        assert!(SNAPSHOT_NAME_MAX_LEN > SNAPSHOT_AUTO_NAME_PREFIX.len());
    }

    #[test]
    fn plan_actions_are_distinct_slugs() {
        // These land in `--json`; two actions sharing a slug would be
        // indistinguishable to a consumer deciding whether data is destroyed.
        let actions = [
            PLAN_ACTION_STORE,
            PLAN_ACTION_RESTORE,
            PLAN_ACTION_OVERWRITE,
            PLAN_ACTION_SKIP,
        ];
        for (index, action) in actions.iter().enumerate() {
            assert!(!actions[index + 1..].contains(action), "'{action}' twice");
        }
    }

    #[test]
    fn preflight_problem_slugs_are_distinct_and_kebab_case() {
        let problems = [
            PREFLIGHT_PROBLEM_ILLEGAL_NAME,
            PREFLIGHT_PROBLEM_CASE_COLLISION,
            PREFLIGHT_PROBLEM_TYPE_CONFLICT,
            PREFLIGHT_PROBLEM_PATH_TOO_LONG,
        ];
        for (index, problem) in problems.iter().enumerate() {
            assert!(!problem.contains(' '), "'{problem}' must be a slug");
            assert_eq!(*problem, problem.to_lowercase());
            assert!(!problems[index + 1..].contains(problem));
        }
        assert_ne!(PREFLIGHT_SEVERITY_BLOCKING, PREFLIGHT_SEVERITY_PORTABILITY);
    }

    #[test]
    fn removal_actions_are_distinct_verbs() {
        // Each one is read in a confirmation prompt: two commands sharing a
        // verb would leave the user unsure which they had just approved.
        let actions = [
            REMOVAL_ACTION_DELETE,
            REMOVAL_ACTION_PURGE,
            REMOVAL_ACTION_REMOVE_DIR,
            REMOVAL_ACTION_REMOVE_EMPTY_DIRS,
            REMOVAL_ACTION_CLEANUP,
        ];
        for (index, action) in actions.iter().enumerate() {
            assert!(!action.is_empty());
            assert!(!actions[index + 1..].contains(action), "'{action}' twice");
        }
    }

    #[test]
    fn removal_plan_labels_are_unique() {
        // Two rows sharing a label would make the table ambiguous, and the
        // JSON key derived from it collide.
        let labels = [
            REMOVAL_LABEL_COMMAND,
            REMOVAL_LABEL_TARGET,
            REMOVAL_LABEL_MODE,
            REMOVAL_LABEL_INCLUDE,
            REMOVAL_LABEL_EXCLUDE,
            REMOVAL_LABEL_FILTER_FROM,
            REMOVAL_LABEL_FILES_FROM,
            REMOVAL_LABEL_MIN_SIZE,
            REMOVAL_LABEL_MAX_SIZE,
            REMOVAL_LABEL_MAX_DEPTH,
            REMOVAL_LABEL_EMPTY_DIRS,
            REMOVAL_LABEL_LEAVE_ROOT,
            REMOVAL_LABEL_CLASSES,
            REMOVAL_LABEL_MIN_AGE,
        ];
        for (index, label) in labels.iter().enumerate() {
            assert!(!labels[index + 1..].contains(label), "'{label}' twice");
        }
    }

    #[test]
    fn a_removal_plan_can_only_ever_say_it_planned() {
        // PLAN.md §6: a plan describes work that has not happened, so there is
        // no second status for a document to carry.
        assert_eq!(
            REMOVAL_STATUS_PLANNED,
            REMOVAL_STATUS_PLANNED.to_lowercase()
        );
        assert!(!REMOVAL_STATUS_PLANNED.is_empty());
        assert_ne!(REMOVAL_MODE_DRY_RUN, REMOVAL_MODE_EXECUTE);
        assert_eq!(REMOVAL_BOOL_YES, DESTRUCTIVE_CONFIRMATION);
        assert_ne!(REMOVAL_BOOL_YES, REMOVAL_BOOL_NO);
    }

    #[test]
    fn the_cleanup_staging_marker_matches_the_local_one() {
        // The remote marker is the local suffix with the key separator that
        // follows it; if one is renamed the other has to move with it.
        assert!(CLEANUP_STAGING_MARKER.starts_with(LOCAL_STAGING_SUFFIX));
        assert!(CLEANUP_AGE_PARSE_EXAMPLES.contains(CLEANUP_DEFAULT_MIN_AGE));
    }

    #[test]
    fn every_tree_glyph_slot_is_the_same_width() {
        // An indent is a repeated slot, so an odd one out would make a deep tree
        // drift one column sideways per level — and would make the two sets
        // non-interchangeable, which is the whole point of having a fallback.
        let slots = [
            TREE_BRANCH_UNICODE,
            TREE_LAST_BRANCH_UNICODE,
            TREE_VERTICAL_UNICODE,
            TREE_BRANCH_ASCII,
            TREE_LAST_BRANCH_ASCII,
            TREE_VERTICAL_ASCII,
            TREE_INDENT,
        ];
        for slot in slots {
            assert_eq!(
                slot.chars().count(),
                TREE_INDENT.chars().count(),
                "{slot:?} is not the standard slot width"
            );
        }
        // The fallback must contain nothing that can become mojibake.
        for slot in [
            TREE_BRANCH_ASCII,
            TREE_LAST_BRANCH_ASCII,
            TREE_VERTICAL_ASCII,
        ] {
            assert!(slot.is_ascii(), "{slot:?}");
        }
        assert!(!TREE_BRANCH_UNICODE.is_ascii());
        // Nothing may be drawn under the last child.
        assert!(TREE_INDENT.trim().is_empty());
    }

    #[test]
    fn the_modtime_column_is_exactly_an_rfc3339_timestamp_wide() {
        // `lsl` reserves this many characters and never pads or truncates the
        // field, so the two have to be derived from the same arithmetic.
        let separators = 5; // two dashes, the T, two colons
        let width = RFC3339_YEAR_WIDTH
            + RFC3339_FIELD_WIDTH * 5
            + separators
            + RFC3339_UTC_DESIGNATOR.len_utf8();
        assert_eq!(width, LISTING_MODTIME_COLUMN_WIDTH);
        // The placeholder for an unknown time has to fit inside it.
        assert!(UNKNOWN_VALUE.chars().count() <= LISTING_MODTIME_COLUMN_WIDTH);
    }

    #[test]
    fn a_listing_and_a_progress_bar_agree_on_how_wide_a_size_is() {
        // Both can be on screen at once; a size that occupied different widths
        // in each would read as a rendering fault.
        assert_eq!(LISTING_SIZE_COLUMN_WIDTH, FILE_BYTES_COLUMN_WIDTH);
        // Wide enough for a mantissa, a separator and the longest suffix, which
        // is what `crate::output::size::bytes` can produce at its widest.
        let widest_suffix = BINARY_UNIT_SUFFIXES
            .iter()
            .map(|s| s.chars().count())
            .max()
            .unwrap_or_default();
        assert!(LISTING_SIZE_COLUMN_WIDTH > widest_suffix + 1);
    }

    #[test]
    fn the_recursive_wildcard_is_the_single_one_doubled() {
        // The compiler reads `**` by looking for two of `*`; a mismatch here
        // would make one of the two spellings unreachable.
        assert_eq!(
            GLOB_RECURSIVE_SEQUENCE,
            format!("{GLOB_ANY_SEQUENCE}{GLOB_ANY_SEQUENCE}")
        );
        // Every metacharacter must be distinct, or one shadows another.
        let marks = [
            GLOB_ANY_SEQUENCE,
            GLOB_ANY_CHAR,
            GLOB_CLASS_OPEN,
            GLOB_CLASS_CLOSE,
            GLOB_CLASS_RANGE,
            GLOB_ESCAPE,
        ];
        for (index, mark) in marks.iter().enumerate() {
            assert!(!marks[index + 1..].contains(mark), "{mark} is listed twice");
            assert_ne!(*mark, PATH_SEPARATOR);
        }
        assert!(!GLOB_CLASS_NEGATE.is_empty());
    }

    #[test]
    fn the_streamed_array_indent_matches_the_serialiser_it_imitates() {
        // The claim `listing::emit` makes: a hand-assembled array is
        // byte-identical to one `serde_json` pretty-printed whole.
        let printed = serde_json::to_string_pretty(&serde_json::json!([{ "a": 1 }]))
            .expect("a literal value serialises");
        assert!(
            printed.contains(&format!("\n{JSON_INDENT}{{")),
            "indent drifted from serde_json: {printed}"
        );
        assert_eq!(
            JSON_EMPTY_ARRAY,
            format!("{JSON_ARRAY_OPEN}{JSON_ARRAY_CLOSE}")
        );
        assert_ne!(JSON_ARRAY_SEPARATOR, JSON_ARRAY_OPEN);
    }

    #[test]
    fn the_hex_alphabet_covers_every_nibble_exactly_once() {
        // Indexed by nibble, so a short or duplicated table would silently
        // corrupt a content hash in `lsjson`.
        assert_eq!(HEX_DIGITS.len(), 16);
        let mut sorted = HEX_DIGITS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), HEX_DIGITS.len());
        // Lower case throughout, so a hash rendered here compares equal to one
        // rendered by `sha256sum` or `b3sum` without a case fold.
        assert!(
            HEX_DIGITS
                .iter()
                .all(|digit| digit.is_ascii_digit() || digit.is_ascii_lowercase())
        );
    }
}
