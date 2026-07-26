//! Turning an I/O failure into a [`CliError`] that names the path it happened to.
//!
//! Both byte-stream commands touch the local filesystem, and both must answer the
//! same question the same way: *what failed, where, and what exit code does a
//! script see?* The classification itself already exists — [`CliError`]'s
//! `From<std::io::Error>` maps a missing file onto exit 4 and a permission
//! failure onto exit 7 — so this module adds the one thing that mapping cannot
//! know, the path, without re-deriving the table. Two copies of that table is
//! precisely how one command comes to exit 4 where another exits 2 for the same
//! condition.

use std::io;
use std::path::Path;

use crate::error::CliError;
use crate::exit::ExitCode;

/// Attach `path` to an I/O failure, preserving its classification.
///
/// The hint is added only for a missing file, where there is something useful to
/// say. A permission error or a full disk needs no advice from us: the message
/// already names the condition, and inventing a remediation for it would be
/// noise in front of a real problem.
#[must_use]
pub fn at_path(path: &Path, error: io::Error) -> CliError {
    let classified = CliError::from(error);
    let code = classified.code();
    let message = format!("{}: {}", path.display(), classified.message());

    if code == ExitCode::FileNotFound {
        return CliError::new(code, message)
            .with_hint("Check the path, or list what is there with `dctl ls`.");
    }
    CliError::new(code, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_path_is_named_and_the_code_is_preserved() {
        let error = at_path(
            Path::new("/data/report.pdf"),
            io::Error::from(io::ErrorKind::NotFound),
        );
        assert_eq!(error.code(), ExitCode::FileNotFound);
        assert!(error.message().contains("/data/report.pdf"));
        assert!(error.hint().is_some());
    }

    #[test]
    fn classification_still_comes_from_one_place() {
        // Whatever `CliError::from` decides for a kind, this must not second-guess
        // it — that is the whole reason the helper exists.
        for (kind, expected) in [
            (io::ErrorKind::NotFound, ExitCode::FileNotFound),
            (io::ErrorKind::PermissionDenied, ExitCode::FatalError),
            (io::ErrorKind::WriteZero, ExitCode::Uncategorised),
        ] {
            let direct = CliError::from(io::Error::from(kind));
            let decorated = at_path(Path::new("x"), io::Error::from(kind));
            assert_eq!(direct.code(), expected);
            assert_eq!(decorated.code(), direct.code());
        }
    }

    #[test]
    fn a_failure_with_no_useful_advice_carries_none() {
        let error = at_path(
            Path::new("x"),
            io::Error::from(io::ErrorKind::PermissionDenied),
        );
        assert!(error.hint().is_none());
    }
}
