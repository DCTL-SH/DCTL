//! Wrapping an already-rendered field in the style its meaning earns.
//!
//! # Why this is a module and not six `format!` calls
//!
//! `--color always` used to emit **zero** escape sequences from `ls`, `lsl`,
//! `lsd`, `tree`, `check` and `size`. The palette existed, the flag was parsed,
//! and `about` really did colour two sequences' worth — so the flag was
//! *measurably* honoured on the one command nobody reaches for and inert on
//! every command an operator reads.
//!
//! The reason it stayed that way is that each renderer would have had to reach
//! for the palette, pick a [`Style`], and remember the `{style:#}` reset — six
//! times, in six files, with no compiler complaint for the five that did not.
//! Naming the *meanings* here instead means a renderer asks for
//! [`path`] or [`number`] and cannot get the mechanics wrong, and a reader can
//! see the whole convention in one place rather than inferring it from six.
//!
//! # Padding happens first, and that is not a style choice
//!
//! An escape sequence is zero columns wide on a terminal and several bytes long
//! in a `String`. A column padded *after* styling therefore looks correct in a
//! test that counts characters and is ragged on screen. Every function here
//! takes text that has **already** been aligned by
//! [`crate::commands::listing::render`] and wraps it, so the alignment is
//! computed on visible characters and cannot drift.
//!
//! # A disabled palette costs a clone and nothing else
//!
//! [`Palette::new(false)`](Palette) resolves every style to
//! [`Style::new()`], which renders as the empty string in both the opening and
//! the `{style:#}` reset position. So a `--color never` run produces byte-identical
//! output to one with no styling code at all, and no function here needs a
//! branch on whether colour is on — the one decision was already made, once, in
//! [`Out::new`](crate::output::Out::new).

use anstyle::Style;

use super::color::Palette;

/// Wrap `text` in `style`.
///
/// The single place the opening sequence and its reset are spelled. Written out
/// once because getting the reset wrong is invisible in a passing test and
/// leaves a terminal painted cyan for everything printed after the command
/// exits.
fn wrap(style: Style, text: &str) -> String {
    format!("{style}{text}{style:#}")
}

/// A file or object path — the field a reader's eye goes to first.
#[must_use]
pub fn path(palette: &Palette, text: &str) -> String {
    wrap(palette.path(), text)
}

/// A directory, distinguished from a file in the same listing.
///
/// The distinction lives on the palette rather than being composed here, and
/// [`Palette::directory`] says why: an attribute added to a style *after* the
/// palette has resolved it is applied even when styling is off.
#[must_use]
pub fn directory(palette: &Palette, text: &str) -> String {
    wrap(palette.directory(), text)
}

/// A measured quantity: a byte count, an object count, a rate.
#[must_use]
pub fn number(palette: &Palette, text: &str) -> String {
    wrap(palette.number(), text)
}

/// A timestamp.
///
/// Dimmed rather than coloured. In `lsl` the time is the widest column and the
/// least often the reason somebody ran the command, so it is the one field that
/// should recede.
#[must_use]
pub fn time(palette: &Palette, text: &str) -> String {
    wrap(palette.dim(), text)
}

/// Structural chrome: a tree's connectors, a separator, a unit suffix.
#[must_use]
pub fn chrome(palette: &Palette, text: &str) -> String {
    wrap(palette.dim(), text)
}

/// A field label in a report — `Total objects:`, and its siblings.
#[must_use]
pub fn label(palette: &Palette, text: &str) -> String {
    wrap(palette.header(), text)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One of this module's functions, named, so a failure says which.
    type Named = (&'static str, fn(&Palette, &str) -> String);

    /// Every function in this module, so a new one cannot be added without
    /// being held to all three properties below.
    fn all() -> Vec<Named> {
        vec![
            ("path", path),
            ("directory", directory),
            ("number", number),
            ("time", time),
            ("chrome", chrome),
            ("label", label),
        ]
    }

    #[test]
    fn a_disabled_palette_returns_the_text_unchanged() {
        // The property `--color never` rests on, and the reason no caller needs
        // its own `if colored` branch. Byte-for-byte equality, not "contains".
        let plain = Palette::new(false);
        for (name, paint) in all() {
            assert_eq!(paint(&plain, "photos/a.jpg"), "photos/a.jpg", "{name}");
        }
    }

    #[test]
    fn an_enabled_palette_wraps_the_text_and_resets_afterwards() {
        let colored = Palette::new(true);
        for (name, paint) in all() {
            let rendered = paint(&colored, "photos/a.jpg");
            assert!(rendered.contains("photos/a.jpg"), "{name}");
            assert!(rendered.starts_with('\u{1b}'), "{name}: no opening escape");
            // The reset matters more than the opener: without it the escape
            // leaks into whatever the shell prints next.
            assert!(
                rendered.ends_with('m'),
                "{name}: no trailing reset sequence in {rendered:?}"
            );
            assert!(
                rendered.matches('\u{1b}').count() >= 2,
                "{name}: styled but never reset"
            );
        }
    }

    #[test]
    fn styling_never_changes_the_visible_text() {
        // What keeps a padded column the width its renderer computed: the
        // escapes are added around the text, never inside it, so stripping them
        // recovers exactly what went in.
        let colored = Palette::new(true);
        let padded = "     1.5 KiB";
        for (name, paint) in all() {
            let rendered = paint(&colored, padded);
            let visible: String = strip(&rendered);
            assert_eq!(visible, padded, "{name}");
        }
    }

    #[test]
    fn a_directory_is_distinguishable_from_a_file_on_a_monochrome_terminal() {
        // Two colours are one colour to a reader whose terminal has none, and
        // `lsd` output is read in exactly those places. Bold is the difference
        // that survives — and it must be *only* in the enabled palette, which
        // the first test above is what pins.
        let colored = Palette::new(true);
        assert_ne!(directory(&colored, "photos"), path(&colored, "photos"));
        assert!(directory(&colored, "photos").contains("1m"));
    }

    /// Drop CSI sequences, keeping the visible text.
    fn strip(text: &str) -> String {
        let mut out = String::new();
        let mut chars = text.chars().peekable();
        while let Some(character) = chars.next() {
            if character != '\u{1b}' {
                out.push(character);
                continue;
            }
            if chars.peek() == Some(&'[') {
                chars.next();
                for character in chars.by_ref() {
                    if ('\u{40}'..='\u{7e}').contains(&character) {
                        break;
                    }
                }
            }
        }
        out
    }
}
