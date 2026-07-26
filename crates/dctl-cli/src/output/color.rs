//! Colour policy and the palette.
//!
//! Colour is decided once, at startup, and every writer obeys that decision.
//! The rules, in priority order:
//!
//! 1. `--color never|always|auto` on the command line.
//! 2. `NO_COLOR` set to anything — the [no-color.org](https://no-color.org)
//!    convention; disables colour even when stdout is a terminal.
//! 3. `CLICOLOR_FORCE` set and non-zero — forces colour even through a pipe.
//! 4. `TERM=dumb` — no colour.
//! 5. Otherwise: colour when the stream is a terminal, plain text when piped.
//!
//! On Windows, `anstream` handles the console details: on Windows 10+ it enables
//! virtual-terminal processing, and on older consoles it converts ANSI sequences
//! into console API calls. Nothing here needs a `#[cfg(windows)]` branch.

use std::io::IsTerminal;

use anstyle::{AnsiColor, Color, Style};
use clap::ValueEnum;

/// When to emit ANSI styling.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lower")]
pub enum ColorChoice {
    /// Colour when writing to a terminal, plain text when redirected.
    #[default]
    Auto,
    /// Always emit colour, even through a pipe.
    Always,
    /// Never emit colour.
    Never,
}

impl ColorChoice {
    /// Resolve to a concrete yes/no for the given stream.
    #[must_use]
    pub fn resolve(self, is_terminal: bool) -> bool {
        match self {
            Self::Always => true,
            Self::Never => false,
            Self::Auto => {
                if std::env::var_os("NO_COLOR").is_some() {
                    return false;
                }
                if matches!(std::env::var("CLICOLOR_FORCE"), Ok(v) if v != "0") {
                    return true;
                }
                if matches!(std::env::var("TERM").as_deref(), Ok("dumb")) {
                    return false;
                }
                is_terminal
            }
        }
    }

    /// Resolve against the real stdout.
    #[must_use]
    pub fn resolve_stdout(self) -> bool {
        self.resolve(std::io::stdout().is_terminal())
    }

    /// Translate into `anstream`'s equivalent so the two agree.
    ///
    /// Both halves of the decision have to be told: the palette decides whether
    /// escape sequences are *produced*, and the `AutoStream` wrapping stdout
    /// decides whether they *survive*. Left on `Auto`, the stream re-runs its
    /// own terminal check and strips everything the palette just emitted, so
    /// `--color always | less -R` would come out plain — the one case the flag
    /// exists for.
    #[must_use]
    pub const fn to_anstream(self) -> anstream::ColorChoice {
        match self {
            Self::Auto => anstream::ColorChoice::Auto,
            Self::Always => anstream::ColorChoice::Always,
            Self::Never => anstream::ColorChoice::Never,
        }
    }
}

/// The palette. Semantic names, not colour names, so the meaning survives a
/// theme change.
///
/// Deliberately restricted to the 8 basic ANSI colours: they are the only ones
/// that render correctly on every terminal DCTL targets, including the legacy
/// Windows console and a monochrome CI log.
pub struct Palette {
    enabled: bool,
}

impl Palette {
    #[must_use]
    pub const fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Styling disabled — every style resolves to a no-op.
    ///
    /// Test-only. A running command never picks a palette directly: [`Out`]
    /// owns that decision, folding `--color` together with the output format so
    /// a machine format can never be styled. A production caller that wanted
    /// this would be re-deciding colour a second time, which is precisely the
    /// disagreement [`Out`] exists to prevent — so the constructor is not
    /// compiled into the binary at all.
    ///
    /// [`Out`]: crate::output::Out
    #[cfg(test)]
    #[must_use]
    pub const fn plain() -> Self {
        Self { enabled: false }
    }

    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn style(&self, style: Style) -> Style {
        if self.enabled { style } else { Style::new() }
    }

    /// A successful outcome.
    #[must_use]
    pub fn success(&self) -> Style {
        self.style(Style::new().fg_color(Some(Color::Ansi(AnsiColor::Green))))
    }

    /// A hard failure.
    #[must_use]
    pub fn error(&self) -> Style {
        self.style(
            Style::new()
                .fg_color(Some(Color::Ansi(AnsiColor::Red)))
                .bold(),
        )
    }

    /// Something the user should look at but which is not fatal.
    #[must_use]
    pub fn warn(&self) -> Style {
        self.style(Style::new().fg_color(Some(Color::Ansi(AnsiColor::Yellow))))
    }

    /// Structural chrome: table rules, separators, units.
    #[must_use]
    pub fn dim(&self) -> Style {
        self.style(Style::new().dimmed())
    }

    /// Column headers and section titles.
    #[must_use]
    pub fn header(&self) -> Style {
        self.style(Style::new().bold())
    }

    /// A file or object path.
    #[must_use]
    pub fn path(&self) -> Style {
        self.style(Style::new().fg_color(Some(Color::Ansi(AnsiColor::Cyan))))
    }

    /// A byte count, rate, or other measured quantity.
    #[must_use]
    pub fn number(&self) -> Style {
        self.style(Style::new().fg_color(Some(Color::Ansi(AnsiColor::Magenta))))
    }

    /// A cryptographic digest or key fingerprint.
    #[must_use]
    pub fn hash(&self) -> Style {
        self.style(Style::new().dimmed())
    }
}

#[cfg(test)]
mod tests {
    use super::{ColorChoice, Palette};

    #[test]
    fn explicit_choices_ignore_the_environment() {
        assert!(ColorChoice::Always.resolve(false));
        assert!(!ColorChoice::Never.resolve(true));
    }

    #[test]
    fn auto_follows_the_stream_when_no_overrides() {
        // Guard against a NO_COLOR set in the developer's own environment
        // making this assertion meaningless.
        if std::env::var_os("NO_COLOR").is_none()
            && std::env::var_os("CLICOLOR_FORCE").is_none()
            && !matches!(std::env::var("TERM").as_deref(), Ok("dumb"))
        {
            assert!(ColorChoice::Auto.resolve(true));
        }
        assert!(!ColorChoice::Auto.resolve(false));
    }

    #[test]
    fn disabled_palette_yields_empty_styles() {
        let plain = Palette::plain();
        assert!(!plain.is_enabled());
        // A default Style renders as nothing at all.
        assert_eq!(format!("{}", plain.error()), "");
        assert_eq!(format!("{}", plain.success()), "");
    }

    #[test]
    fn enabled_palette_yields_real_styles() {
        let colored = Palette::new(true);
        assert!(colored.is_enabled());
        assert_ne!(format!("{}", colored.error()), "");
    }
}
