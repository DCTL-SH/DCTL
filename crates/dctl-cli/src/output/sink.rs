//! The output sink: every byte a command writes goes through here.
//!
//! The sink owns the two decisions that must be made once per invocation and
//! then obeyed everywhere — which format results are serialised in, and whether
//! styling is allowed — so no command has to re-derive them and none can
//! disagree. It also enforces the module's one rule: **stdout carries data,
//! stderr carries everything else** (see the [`crate::output`] module docs).
//!
//! Writers are `&self`, not `&mut self`, because a transfer has many tasks
//! reporting at once. Each write locks the underlying stream for the duration of
//! one line, which is what keeps two concurrent workers from interleaving
//! half-lines into an unparseable listing.

use std::io::{IsTerminal, Write};

use anstream::AutoStream;

use crate::constants::{ERROR_PREFIX, SUCCESS_MARK, SUCCESS_MARK_ASCII, WARNING_PREFIX};

use super::color::{ColorChoice, Palette};
use super::format::Format;
use super::size::Units;
use super::stats::Snapshot;
use super::summary;
use super::table::Table;

/// The output sink for one command invocation.
pub struct Out {
    format: Format,
    palette: Palette,
    /// What the `AutoStream` wrapping stdout is told about colour.
    ///
    /// Kept alongside the palette because the two answer different halves of
    /// one question: the palette decides whether escape sequences are produced,
    /// the stream decides whether they survive being written. Left to its own
    /// detection the stream would strip everything `--color always` just asked
    /// for the moment stdout is a pipe.
    stream_color: anstream::ColorChoice,
    units: Units,
    quiet: bool,
    verbosity: u8,
}

impl Out {
    /// Build the sink from the resolved global flags.
    ///
    /// Colour is settled here and nowhere else: a machine format is never
    /// coloured, whatever `--color` says, because escape sequences inside JSON
    /// break every consumer downstream.
    #[must_use]
    pub fn new(
        format: Format,
        color: ColorChoice,
        units: Units,
        quiet: bool,
        verbosity: u8,
    ) -> Self {
        let permitted = format.permits_color();
        let colored = permitted && color.resolve_stdout();
        Self {
            format,
            palette: Palette::new(colored),
            stream_color: if permitted {
                color.to_anstream()
            } else {
                anstream::ColorChoice::Never
            },
            units,
            quiet,
            verbosity,
        }
    }

    /// A plain, uncoloured sink.
    ///
    /// Test-only: every real invocation builds its sink from the resolved
    /// globals in [`crate::ctx::Ctx::new`], so a command that reached for this
    /// would be silently discarding the user's `--format` and `--color`. Tests
    /// want exactly that — a sink whose output is stable regardless of the
    /// terminal running the suite — so it exists for them and is not compiled
    /// into the binary.
    #[cfg(test)]
    #[must_use]
    pub fn plain() -> Self {
        Self::new(Format::Text, ColorChoice::Never, Units::Binary, false, 0)
    }

    #[must_use]
    pub const fn format(&self) -> Format {
        self.format
    }

    #[must_use]
    pub const fn palette(&self) -> &Palette {
        &self.palette
    }

    #[must_use]
    pub const fn units(&self) -> Units {
        self.units
    }

    #[must_use]
    pub const fn is_json(&self) -> bool {
        self.format.is_json()
    }

    /// Whether `--quiet` is in force.
    ///
    /// Exposed so renderers that live outside this file — the end-of-run report
    /// in [`super::summary`] — can honour the flag without reaching into the
    /// sink's private state or being handed a second copy of it to drift from.
    ///
    /// Verbosity has no such accessor on purpose: the only thing that varies
    /// with `-v` is whether [`Out::info`] prints, and that decision stays inside
    /// this file so no caller can implement a second, subtly different
    /// threshold for the same flag.
    #[must_use]
    pub const fn is_quiet(&self) -> bool {
        self.quiet
    }

    // ── stdout: data ─────────────────────────────────────────────────────

    /// Write a data line to stdout.
    ///
    /// A broken pipe is *not* an error: `dctl ls vault: | head -5` closes the
    /// pipe early, and reporting that as a failure would be wrong. Every other
    /// I/O error propagates.
    pub fn line(&self, text: impl AsRef<str>) -> std::io::Result<()> {
        let mut stream = AutoStream::new(std::io::stdout().lock(), self.stream_color);
        match writeln!(stream, "{}", text.as_ref()) {
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
            other => other,
        }
    }

    /// Write pre-rendered text (already newline-terminated) to stdout.
    ///
    /// Broken-pipe tolerant for the same reason as [`Out::line`]: a table cut
    /// short by `head` is a successful command, not a failed one.
    pub fn write(&self, text: impl AsRef<str>) -> std::io::Result<()> {
        let mut stream = AutoStream::new(std::io::stdout().lock(), self.stream_color);
        match write!(stream, "{}", text.as_ref()) {
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
            other => other,
        }
    }

    /// Serialise a value as JSON on stdout, honouring [`Format::JsonLines`].
    ///
    /// # Errors
    /// Returns any stdout write failure other than a broken pipe, and turns a
    /// serialisation failure into [`std::io::Error::other`] so callers have one
    /// error type to handle rather than two.
    pub fn json<T: serde::Serialize>(&self, value: &T) -> std::io::Result<()> {
        let text = self.format.encode(value).map_err(std::io::Error::other)?;
        self.line(text)
    }

    /// Render a table to stdout in the active format.
    pub fn table(&self, table: &Table) -> std::io::Result<()> {
        self.write(table.render(&self.palette))
    }

    // ── stderr: everything else ──────────────────────────────────────────

    /// Write one already-styled line to stderr, honouring this run's `--color`.
    ///
    /// The counterpart of [`Out::line`], and it exists for the same reason that
    /// one wraps stdout in an explicit [`AutoStream`]. `anstream::eprintln!`
    /// writes through a *global* stream left on `Auto`, which re-runs its own
    /// terminal check and strips everything the palette just produced — so
    /// `--color always 2> >(less -R)` came out plain, and `dctl check` on two
    /// matching trees emitted **zero** escape sequences under `--color always`
    /// because its confirmation is a stderr line. Half the output layer obeyed
    /// the flag and half re-decided it.
    ///
    /// A failed write to stderr is dropped rather than propagated: these are
    /// notes about work, and a terminal that went away must not turn a
    /// successful run into a failed one. [`Out::notice`] says the same thing at
    /// more length for the one caller that cannot afford to be styled at all.
    fn stderr_line(&self, text: &str) {
        let mut stream = AutoStream::new(std::io::stderr().lock(), self.stream_color);
        let _ = writeln!(stream, "{text}");
    }

    /// A note shown at `-v` and above.
    pub fn info(&self, text: impl AsRef<str>) {
        if !self.quiet && self.verbosity >= 1 {
            let dim = self.palette.dim();
            self.stderr_line(&format!("{dim}{}{dim:#}", text.as_ref()));
        }
    }

    /// A warning. Always shown unless `--quiet`.
    pub fn warn(&self, text: impl AsRef<str>) {
        if !self.quiet {
            let style = self.palette.warn();
            self.stderr_line(&format!(
                "{style}{WARNING_PREFIX}{style:#} {}",
                text.as_ref()
            ));
        }
    }

    /// An error. Always shown, even under `--quiet` — silence about a failure
    /// is the one thing [the plan](https://doc.dctl.sh/project/plan) §7 forbids.
    pub fn error(&self, text: impl AsRef<str>) {
        let style = self.palette.error();
        self.stderr_line(&format!("{style}{ERROR_PREFIX}{style:#} {}", text.as_ref()));
    }

    /// A pre-formatted line of stderr, verbatim: no prefix, no styling, and not
    /// suppressed by `--quiet` or by a machine `--format`.
    ///
    /// Exists for exactly one caller, and the constraints come from it: the
    /// recovery-phrase block `dctl init` prints
    /// ([`crate::commands::init::phrase`]). Each of the three properties is
    /// load-bearing rather than convenient.
    ///
    /// * **Verbatim** — the block draws its own frame and its own column grid,
    ///   and a prefix glyph on every line would break both. What makes it
    ///   readable is that it does not look like the rest of the output.
    /// * **Not suppressed by `--quiet`** — for the same reason [`Out::error`] is
    ///   not. `--quiet` asks for less noise, not for an irreversible thing to
    ///   happen silently; a vault whose second key was generated and never shown
    ///   has no second key at all.
    /// * **On stderr under every format** — stdout is the result stream, so a
    ///   phrase written there would land in `| tee` output, a JSON document or a
    ///   CI artefact. A phrase in a log file is a compromised vault, and unlike
    ///   a password it cannot be rotated away.
    pub fn notice(&self, text: impl AsRef<str>) {
        let mut stderr = std::io::stderr().lock();
        // A failed write to stderr has nowhere to be reported, and it must not
        // fail the command: the vault has already been created by the time this
        // runs, and turning "the terminal went away" into an error would report
        // a failure for work that succeeded.
        let _ = writeln!(stderr, "{}", text.as_ref());
    }

    /// A success confirmation on stderr, so it does not pollute piped data.
    ///
    /// The mark follows the palette: a sink that is allowed to emit ANSI is
    /// talking to a terminal that will also render the check glyph, and one that
    /// is not gets the ASCII fallback instead of mojibake.
    pub fn success(&self, text: impl AsRef<str>) {
        if !self.quiet {
            let style = self.palette.success();
            let mark = if self.palette.is_enabled() {
                SUCCESS_MARK
            } else {
                SUCCESS_MARK_ASCII
            };
            self.stderr_line(&format!("{style}{mark}{style:#} {}", text.as_ref()));
        }
    }

    /// A blank separator line on stderr.
    ///
    /// Exposed for [`super::summary`], which draws the end-of-run report and is
    /// the one renderer outside this file that writes to stderr directly. It
    /// goes through [`Out::stderr_line`] like everything else so the report
    /// obeys this run's `--color` rather than re-deciding it.
    pub fn blank_stderr_line(&self) {
        self.stderr_line("");
    }

    /// One already-styled report row on stderr. See [`Out::blank_stderr_line`].
    pub fn stderr_row(&self, text: &str) {
        self.stderr_line(text);
    }

    /// The end-of-run report.
    ///
    /// Kept as a method for the callers that already have a sink in hand; the
    /// rows themselves are domain logic and live in [`super::summary`].
    pub fn summary(&self, snapshot: &Snapshot) {
        summary::render(self, snapshot);
    }

    /// Whether stderr is a terminal — used to pick a progress mode.
    #[must_use]
    pub fn stderr_is_terminal() -> bool {
        std::io::stderr().is_terminal()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::stats::Stats;

    #[test]
    fn json_output_is_never_coloured() {
        // Even with --color always, a machine format must stay clean.
        let out = Out::new(Format::Json, ColorChoice::Always, Units::Binary, false, 0);
        assert!(!out.palette().is_enabled());
        assert!(out.is_json());
    }

    #[test]
    fn text_output_respects_an_explicit_color_choice() {
        let out = Out::new(Format::Text, ColorChoice::Always, Units::Binary, false, 0);
        assert!(out.palette().is_enabled());
        let out = Out::new(Format::Text, ColorChoice::Never, Units::Binary, false, 0);
        assert!(!out.palette().is_enabled());
    }

    #[test]
    fn json_lines_is_recognised_as_json() {
        let out = Out::new(
            Format::JsonLines,
            ColorChoice::Never,
            Units::Binary,
            false,
            0,
        );
        assert!(out.is_json());
        assert_eq!(out.format(), Format::JsonLines);
    }

    #[test]
    fn plain_sink_is_uncoloured_text() {
        let out = Out::plain();
        assert!(!out.palette().is_enabled());
        assert!(!out.is_json());
        assert_eq!(out.units(), Units::Binary);
    }

    #[test]
    fn quiet_suppresses_the_summary_but_never_errors() {
        // Smoke test: these must not panic under any configuration.
        let quiet = Out::new(Format::Text, ColorChoice::Never, Units::Binary, true, 0);
        quiet.summary(&Stats::new().snapshot());
        quiet.warn("suppressed");
        quiet.error("never suppressed");
    }

    #[test]
    fn summary_renders_for_a_clean_run() {
        let stats = Stats::new();
        stats.set_total_bytes(2048);
        stats.set_total_files(2);
        stats.add_bytes(2048);
        stats.file_done();
        stats.file_done();
        Out::plain().summary(&stats.snapshot());
    }

    #[test]
    fn quiet_is_reported_as_configured() {
        // The summary renderer reads this back out of the sink rather than
        // being passed its own copy, so the accessor is load-bearing.
        let out = Out::new(Format::Text, ColorChoice::Never, Units::Binary, true, 2);
        assert!(out.is_quiet());
        assert!(!Out::plain().is_quiet());
    }

    #[test]
    fn an_explicit_colour_choice_survives_a_pipe() {
        // `--color always | less -R` is the whole reason the flag exists: the
        // palette emits escapes and the stream must not strip them back off.
        let forced = Out::new(Format::Text, ColorChoice::Always, Units::Binary, false, 0);
        assert!(matches!(forced.stream_color, anstream::ColorChoice::Always));
        // A machine format overrides the flag in the other direction.
        let json = Out::new(Format::Json, ColorChoice::Always, Units::Binary, false, 0);
        assert!(matches!(json.stream_color, anstream::ColorChoice::Never));
    }

    #[test]
    fn writing_data_to_a_closed_stdout_is_not_a_failure() {
        // Cannot close stdout in-process without affecting the test harness, so
        // this asserts the ordinary path succeeds; the broken-pipe arm is the
        // one exception carved out of it.
        let out = Out::plain();
        assert!(out.line("").is_ok());
        assert!(out.write("").is_ok());
    }

    #[test]
    fn json_encoding_follows_the_sink_format() {
        // A JSON Lines sink must emit one line per record even for a nested
        // value, or a line-at-a-time consumer breaks.
        let value = serde_json::json!({"a": {"b": 1}});
        let jsonl = Out::new(
            Format::JsonLines,
            ColorChoice::Never,
            Units::Binary,
            false,
            0,
        );
        assert!(!jsonl.format().encode(&value).unwrap().contains('\n'));
        assert!(jsonl.json(&value).is_ok());
    }
}
