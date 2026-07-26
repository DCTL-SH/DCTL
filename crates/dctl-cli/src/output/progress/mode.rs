//! Which of the three progress renderings is active, and how that is decided.
//!
//! The choice is made once, at start-up, from the flags and the shape of the
//! process's stderr — never re-evaluated mid-run. A display that switched
//! rendering half way through a transfer would corrupt whatever was already on
//! screen (or in the log file), so the decision is deliberately a one-time,
//! total function of its three inputs and is trivially testable because of it.

/// How progress is rendered.
///
/// The three variants exist because the same run can be watched by a human on a
/// terminal, tailed as a log file, or consumed by a machine — and drawing bars
/// into the last two would be actively harmful, not merely ugly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Live bars on a terminal: an aggregate bar plus one row per in-flight
    /// file, redrawn continuously with cursor movement and ANSI styling.
    Bars,
    /// Periodic plain-text status lines, no ANSI and no cursor movement. What a
    /// redirected run gets, because bar redraws would otherwise fill a log file
    /// with megabytes of escape sequences.
    Plain,
    /// No progress output at all.
    Quiet,
}

impl Mode {
    /// Pick a mode from the flags and the environment.
    ///
    /// Precedence, highest first:
    ///
    /// 1. `--quiet` wins over everything. A user who asked for silence gets it
    ///    even if they also passed `--progress`, because the alternative is a
    ///    tool that talks after being told not to.
    /// 2. `--progress` forces bars on, which is what makes bars available inside
    ///    a `script`/PTY wrapper or a CI job that renders ANSI but does not look
    ///    like a terminal to `isatty`.
    /// 3. Otherwise bars appear only when stderr really is a terminal; anything
    ///    redirected falls back to [`Mode::Plain`].
    ///
    /// Note that the terminal test is on **stderr**, not stdout: progress is
    /// written to stderr precisely so `dctl cat … | ffplay -` can keep its bars
    /// while stdout carries data.
    #[must_use]
    pub const fn resolve(force_progress: bool, quiet: bool, stderr_is_terminal: bool) -> Self {
        if quiet {
            Self::Quiet
        } else if force_progress || stderr_is_terminal {
            Self::Bars
        } else {
            Self::Plain
        }
    }

    /// Whether this mode draws bars, and therefore whether per-file rows,
    /// steady ticking and cursor manipulation are worth setting up at all.
    ///
    /// Exists so callers ask a question about intent rather than comparing
    /// against a variant, which keeps a future fourth mode from silently taking
    /// the wrong branch at every call site.
    #[must_use]
    pub const fn draws_bars(self) -> bool {
        matches!(self, Self::Bars)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_resolution_respects_precedence() {
        // --quiet beats everything.
        assert_eq!(Mode::resolve(true, true, true), Mode::Quiet);
        // --progress forces bars even when piped.
        assert_eq!(Mode::resolve(true, false, false), Mode::Bars);
        // Bars on a terminal, plain lines when redirected.
        assert_eq!(Mode::resolve(false, false, true), Mode::Bars);
        assert_eq!(Mode::resolve(false, false, false), Mode::Plain);
    }

    #[test]
    fn quiet_wins_over_every_other_input() {
        // Silence is absolute: no combination of the other two can defeat it.
        for force_progress in [false, true] {
            for is_terminal in [false, true] {
                assert_eq!(
                    Mode::resolve(force_progress, true, is_terminal),
                    Mode::Quiet,
                    "--quiet must win (force={force_progress}, tty={is_terminal})"
                );
            }
        }
    }

    #[test]
    fn only_bars_actually_draws() {
        assert!(Mode::Bars.draws_bars());
        assert!(!Mode::Plain.draws_bars());
        assert!(!Mode::Quiet.draws_bars());
    }

    #[test]
    fn resolution_is_total_and_deterministic() {
        // Same inputs, same answer — the mode is fixed for the life of a run.
        for force in [false, true] {
            for quiet in [false, true] {
                for tty in [false, true] {
                    assert_eq!(
                        Mode::resolve(force, quiet, tty),
                        Mode::resolve(force, quiet, tty)
                    );
                }
            }
        }
    }
}
