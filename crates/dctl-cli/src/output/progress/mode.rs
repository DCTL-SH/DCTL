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
    /// 2. Bars appear only when stderr really is a terminal. A `script`/PTY
    ///    wrapper counts, because it *is* one; a pipe or a file does not, and
    ///    there `--progress` cannot conjure bars — [`Mode::Bars`] draws through a
    ///    terminal handle and renders nothing without one.
    /// 3. `--progress` therefore cannot force bars where they cannot be drawn.
    ///    It used to try, and the cost was measured: selecting [`Mode::Bars`]
    ///    off a terminal drew nothing *and* stopped the ticker, which runs only
    ///    in [`Mode::Plain`]. `--bwlimit 1M --stats 1` on 10 MiB wrote 1675 bytes
    ///    of status to a redirected stderr without `-P` and 170 bytes with it.
    ///    The flag that exists to keep progress on a redirected run was the only
    ///    way to turn it off.
    ///
    /// What survives is a guarantee rather than a change of behaviour:
    /// `--progress` promises that progress is not switched off, and off a
    /// terminal that is the periodic plain line. It is honest and it is
    /// harmless, but it is not yet *measurable* in the sense
    /// [`crate::cli::reach`] requires — see HANDOVER §11.2. Making it so means
    /// either drawing bars into a pipe (which the [`Mode::Plain`] doc argues
    /// against) or refusing the flag when stderr is not a terminal, and the
    /// refusal table takes only the flags as input, never the environment.
    ///
    /// Note that the terminal test is on **stderr**, not stdout: progress is
    /// written to stderr precisely so `dctl cat … | ffplay -` can keep its bars
    /// while stdout carries data.
    #[must_use]
    pub const fn resolve(force_progress: bool, quiet: bool, stderr_is_terminal: bool) -> Self {
        if quiet {
            Self::Quiet
        } else if stderr_is_terminal {
            Self::Bars
        } else {
            // `force_progress` deliberately does not reach here. Off a terminal
            // the only rendering that produces anything is the plain periodic
            // line, so honouring `--progress` means choosing it.
            let _ = force_progress;
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
        // --progress cannot force bars through a pipe: nothing would be drawn,
        // and the periodic line would stop with it.
        assert_eq!(Mode::resolve(true, false, false), Mode::Plain);
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

    /// `--progress` must never leave a run with *less* progress than it had.
    ///
    /// Measured on the release binary, 10 MiB paced to 1 MiB/s with
    /// `--stats 1`, stderr redirected to a file:
    ///
    /// ```text
    /// without -P : 1675 bytes, 10 periodic status lines
    /// with    -P :  170 bytes,  0 periodic status lines
    /// ```
    ///
    /// [`Mode::Bars`] draws through a terminal handle, so off a terminal it
    /// renders nothing at all — and selecting it also stops the ticker, which
    /// only runs in [`Mode::Plain`]. The flag whose whole purpose is progress on
    /// a redirected run was the only way to remove it.
    ///
    /// The rule this asserts is the weakest one that forbids that: forcing
    /// progress may never select a mode that renders less than the mode the same
    /// run would have chosen on its own.
    #[test]
    fn forcing_progress_never_shows_less_than_not_forcing_it() {
        for is_terminal in [false, true] {
            let unforced = Mode::resolve(false, false, is_terminal);
            let forced = Mode::resolve(true, false, is_terminal);
            assert_ne!(
                forced,
                Mode::Quiet,
                "--progress must never silence a run (tty={is_terminal})"
            );
            if !is_terminal {
                assert_eq!(
                    forced, unforced,
                    "off a terminal, bars draw nothing and suppress the periodic                      line, so forcing them is strictly worse than not"
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
