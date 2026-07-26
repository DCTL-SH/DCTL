//! Glyph selection: which characters the bars and spinners are drawn from.
//!
//! This is the one part of the display that cannot be decided from the flags
//! alone, because it depends on what the terminal on the other end can actually
//! render. Getting it wrong is not a cosmetic problem: a box-drawing bar sent to
//! a legacy Windows console or a `LANG=C` session arrives as a stream of
//! replacement characters that is *wider* than the bar it replaced, so the line
//! wraps and every subsequent redraw smears down the screen.
//!
//! The detection is therefore conservative and cheap, and it is performed once
//! per run rather than per file — see [`super::Progress`], which stores the
//! resolved set.

use crate::constants::{
    LOCALE_ENV_VARS, PROGRESS_CHARS_ASCII, PROGRESS_CHARS_UNICODE, SPINNER_TICKS_ASCII,
    SPINNER_TICKS_UNICODE, UTF8_LOCALE_MARKERS, WINDOWS_TERMINAL_ENV,
};

/// The glyphs used to draw bars and spinners.
///
/// Held as a value rather than re-derived at each use so that one run renders
/// consistently: a mid-run environment change (or a second `detect` call that
/// forgot to pass `force_ascii`) can never leave the aggregate bar in Unicode
/// while the per-file rows fall back to ASCII.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Charset {
    /// Filled body, leading edge and unfilled remainder, in the positional order
    /// `indicatif`'s `progress_chars` expects.
    pub(super) progress_chars: &'static str,
    /// Spinner animation frames; the last is the completion frame.
    pub(super) tick_strings: &'static [&'static str],
}

impl Charset {
    /// The preferred set, used whenever the terminal can be trusted with UTF-8.
    pub(super) const UNICODE: Self = Self {
        progress_chars: PROGRESS_CHARS_UNICODE,
        tick_strings: SPINNER_TICKS_UNICODE,
    };

    /// The safe set: renders identically everywhere, including on consoles that
    /// predate UTF-8 support entirely.
    pub(super) const ASCII: Self = Self {
        progress_chars: PROGRESS_CHARS_ASCII,
        tick_strings: SPINNER_TICKS_ASCII,
    };

    /// Choose a set, honouring an explicit `--ascii` override first.
    ///
    /// The override exists because detection is a heuristic and the user is the
    /// authority on their own terminal: forcing ASCII must always be possible,
    /// while forcing Unicode is not offered — a broken bar is not something the
    /// user can undo once it has been drawn.
    pub(super) fn detect(force_ascii: bool) -> Self {
        if force_ascii || !terminal_supports_unicode() {
            Self::ASCII
        } else {
            Self::UNICODE
        }
    }
}

/// Best-effort check that the terminal can render multi-byte glyphs.
///
/// Three platforms, three different answers:
///
/// * **Windows** — only the modern Windows Terminal renders these reliably, and
///   [`WINDOWS_TERMINAL_ENV`] is the documented marker for it. `conhost.exe`
///   gets ASCII, which is the correct answer for it.
/// * **Unix** — an explicit UTF-8 locale is the only positive signal available
///   without querying the terminal, so any of [`LOCALE_ENV_VARS`] naming UTF-8
///   counts.
/// * **macOS** — Terminal.app and iTerm are UTF-8 unconditionally and frequently
///   run with no locale set at all (notably under `launchd`), so an unset locale
///   there means "unconfigured", not "not UTF-8".
///
/// Reads the environment, so it is not `const`; callers cache the result.
pub(super) fn terminal_supports_unicode() -> bool {
    if cfg!(target_os = "windows") {
        return std::env::var_os(WINDOWS_TERMINAL_ENV).is_some();
    }
    for var in LOCALE_ENV_VARS {
        if let Ok(value) = std::env::var(var) {
            let value = value.to_ascii_uppercase();
            if UTF8_LOCALE_MARKERS
                .iter()
                .any(|marker| value.contains(marker))
            {
                return true;
            }
        }
    }
    // macOS terminals default to UTF-8 even with an unset locale.
    cfg!(target_os = "macos")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forcing_ascii_overrides_any_detection() {
        // The user's explicit answer must beat the heuristic on every platform,
        // whatever this machine's locale happens to say.
        assert_eq!(Charset::detect(true), Charset::ASCII);
    }

    #[test]
    fn detection_yields_one_of_the_two_known_sets() {
        let detected = Charset::detect(false);
        assert!(detected == Charset::ASCII || detected == Charset::UNICODE);
    }

    #[test]
    fn detection_is_stable_within_a_run() {
        // Both bars must agree; an unstable answer would mix glyph sets on one
        // screen, which is exactly what caching the charset prevents.
        assert_eq!(Charset::detect(false), Charset::detect(false));
        assert_eq!(terminal_supports_unicode(), terminal_supports_unicode());
    }

    #[test]
    fn the_fallback_set_is_pure_ascii() {
        // The whole point of the fallback: nothing in it can become mojibake.
        assert!(Charset::ASCII.progress_chars.is_ascii());
        assert!(Charset::ASCII.tick_strings.iter().all(|t| t.is_ascii()));
    }

    #[test]
    fn the_two_sets_are_actually_different() {
        // A copy-paste slip that made ASCII an alias of UNICODE would silently
        // disable the fallback and nothing else would catch it.
        assert_ne!(Charset::ASCII, Charset::UNICODE);
        assert!(!Charset::UNICODE.progress_chars.is_ascii());
    }

    #[test]
    fn both_sets_supply_every_slot_indicatif_reads() {
        // `progress_chars` is positional (filled, edge, empty) and the spinner
        // needs at least one frame, or indicatif renders an empty bar. The two
        // sets must also agree on slot count, since either can be substituted
        // for the other at run time.
        for set in [Charset::ASCII, Charset::UNICODE] {
            assert!(!set.progress_chars.is_empty());
            assert!(!set.tick_strings.is_empty());
            assert!(set.tick_strings.iter().all(|frame| !frame.is_empty()));
        }
        assert_eq!(
            Charset::ASCII.progress_chars.chars().count(),
            Charset::UNICODE.progress_chars.chars().count()
        );
    }
}
