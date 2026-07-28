//! The tolerance every modification-time comparison in this binary applies.
//!
//! One function, because there are two families of comparison — the transfer
//! family's [`ComparePolicy`](crate::commands::transfer::ComparePolicy) and
//! `check`'s [`Comparison`](crate::commands::check::Comparison) — and the moment
//! they disagree about how close is close enough, `dctl check` starts calling a
//! tree `dctl sync` has just made identical `3 of 3 paths differ`. That is not a
//! hypothetical: `check` compared timestamps for exact equality while `sync`
//! allowed a second, and the two verbs answered the same question differently
//! over the same data.
//!
//! ## Why a tolerance is needed at all
//!
//! Because the two sides of a comparison are not obliged to record a time the
//! same way, and none of them can be talked out of it:
//!
//! * A **local source** is read at whatever resolution the filesystem keeps —
//!   nanoseconds on ext4, 100 ns on NTFS, two whole seconds on FAT.
//! * **DCTL's own records** — the index row, a sealed object's metadata, and
//!   every backend listing — hold whole unix seconds. A source modified at
//!   `…:07.812` is therefore stored as `…:07`, and comparing the two for equality
//!   finds a difference of 812 ms in a file nobody touched.
//! * **SFTP** carries `mtime` as unsigned 32-bit seconds, so a server cannot
//!   return more precision than that even when its filesystem has it.
//! * **B2** stores milliseconds; DCTL writes whole seconds into that field, and
//!   another tool writing the same object may not.
//!
//! With a zero tolerance every one of those becomes "modified", and a nightly
//! `sync` re-uploads the dataset for a reason no operator can see. rclone reaches
//! the same conclusion by a different route — it takes the *precision* each
//! backend advertises and uses the widest — and exposes the same escape hatch,
//! `--modify-window`.
//!
//! ## Why the floor is one second and not zero
//!
//! DCTL has exactly one storage resolution: whole seconds, everywhere, on every
//! backend. So a window below one second cannot express a real distinction — it
//! can only reject files as different because of digits that were never stored.
//! A user who asks for one is refused with that sentence rather than silently
//! given a working default, because a flag that quietly ignores its argument is
//! the defect this codebase keeps finding in other people's tools.
//!
//! Wider is always allowed: `--modify-window 2` is exactly what a FAT-formatted
//! destination needs, and it is the reason the flag is a knob rather than a
//! constant.

use std::time::Duration;

use crate::cli::GlobalArgs;
use crate::constants::{MIN_MODIFY_WINDOW_SECS, MODIFY_WINDOW_TOO_SMALL_HINT};
use crate::error::{CliError, Result};
use crate::exit::ExitCode;

/// The tolerance to apply, given the global flags.
///
/// # Errors
/// [`ExitCode::Usage`] for a window narrower than the whole second DCTL records,
/// naming the resolution and what the flag can usefully be set to instead.
pub fn resolve(globals: &GlobalArgs) -> Result<Duration> {
    if globals.modify_window < MIN_MODIFY_WINDOW_SECS {
        return Err(CliError::new(
            ExitCode::Usage,
            format!(
                "--modify-window {}: DCTL records modification times in whole \
                 seconds, so a window below {MIN_MODIFY_WINDOW_SECS}s would \
                 report unchanged files as modified",
                globals.modify_window
            ),
        )
        .with_hint(MODIFY_WINDOW_TOO_SMALL_HINT));
    }
    Ok(Duration::from_secs(globals.modify_window))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn globals(args: &[&str]) -> GlobalArgs {
        Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied())).globals
    }

    #[test]
    fn the_default_is_the_one_second_the_records_are_kept_in() {
        assert_eq!(
            resolve(&globals(&[])).expect("the default is usable"),
            Duration::from_secs(MIN_MODIFY_WINDOW_SECS)
        );
    }

    #[test]
    fn a_wider_window_is_honoured() {
        // The case the flag exists for: a FAT destination rounds to two seconds,
        // so a one-second window calls half its files modified forever.
        assert_eq!(
            resolve(&globals(&["--modify-window", "2"])).expect("wider is fine"),
            Duration::from_secs(2)
        );
    }

    #[test]
    fn a_window_below_the_stored_resolution_is_refused_rather_than_ignored() {
        // Silently clamping would be a flag that parses and does nothing, which
        // is what `--bwlimit` was criticised for. The refusal says why.
        let error = resolve(&globals(&["--modify-window", "0"]))
            .expect_err("zero cannot be honoured by whole-second records");
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.message().contains("whole"), "{}", error.message());
        assert!(error.hint().is_some(), "a refusal must say what to do next");
    }
}
