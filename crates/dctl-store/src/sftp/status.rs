//! What an SFTP server's status code says happened — and the one that says
//! nothing at all.
//!
//! ## The measurement this module exists for
//!
//! A destination whose filesystem was full reported this, once per refused
//! write:
//!
//! ```text
//! backend error: sftp server reported Failure: Err Message: Failure, Language Tag:
//! ```
//!
//! The identical fault on `local:` reports `io error: No space left on device
//! (os error 28)` and exits 7 — the disk, named, and an operator who runs `df`
//! next. That SFTP line was recorded as undiagnosable, and making it as
//! diagnosable as the local one was named as the work; this module and
//! [`super::space`] are that work.
//!
//! ## The premise that turned out to be false
//!
//! It is natural to assume `ENOSPC` arrives as a status code of its own, and it
//! does not. Measured on **OpenSSH 9.9p1**, with OpenSSH's own `sftp` client, a
//! 2 MiB `tmpfs` filled to 248 KiB free, and a 1 MB object:
//!
//! ```text
//! sftp> put /tmp/probe1m.bin /mnt/fullfs/store/obj.bin
//! write remote "/mnt/fullfs/store/obj.bin": Failure
//! ```
//!
//! `SSH_FX_FAILURE`, and the message field carries the word `Failure` rather
//! than a `strerror`. Removing a non-empty directory on the same server answers
//! identically, so the code does not even separate a full disk from a refusal
//! that has nothing to do with storage.
//!
//! The cause is in the server and cannot be worked around from this side:
//! `errno_to_portable` gives `ENOENT` and `EACCES` codes of their own and maps
//! **everything else — `ENOSPC`, `EDQUOT`, `EROFS`, `EFBIG`, `EIO`,
//! `ENOTEMPTY` — to the one catch-all**, and version 3's status packet has no
//! field an errno could travel in.
//!
//! So no reading of a status code can name a full disk, and a module that
//! claimed to would be inventing the diagnosis. Closing the defect therefore
//! takes two separate pieces of work, deliberately kept apart because one is
//! certain and the other is evidence:
//!
//! * **[`classify`] — the sweep, here.** Every status the protocol defines is
//!   turned into the error `local:` raises for the same condition, so one fault
//!   reads the same whichever backend met it. Five of the six used to collapse
//!   into a single `StoreError::Backend` string.
//! * **[`super::space`] — the probe.** For the catch-all, on the write path
//!   only, the far end is asked how much room is left. That is evidence rather
//!   than a status code, which is why it lives in its own module and why its
//!   answer is allowed to be "I could not find out".
//!
//! ## Why these map onto `StoreError::Io`
//!
//! Not for tidiness: `StoreError::Io` is the variant the layers above already
//! read. [`crate::retry::observed`] decides retriability from the
//! [`std::io::ErrorKind`] — a denial is never retried, and neither is a full
//! disk — and `dctl-cli`'s exit mapping routes
//! [`crate::durable::is_out_of_space`] to the disk-full exit code. A
//! `StoreError::Backend` string reaches neither. Sweeping the class *the way it
//! was swept on local* means arriving at the same variant, not merely at a
//! better sentence.

use std::io;

use openssh_sftp_client::error::SftpErrorKind;

use crate::error::StoreError;

/// The server's own explanatory text, when it is worth repeating.
///
/// Version 3's status packet carries a free-text message and a language tag.
/// OpenSSH fills the message with the *name of the status* — `Failure`,
/// `Permission denied` — which adds nothing to a line that already names the
/// status, and other servers put a real `strerror` there, which adds a great
/// deal. Repeating the first kind produces `refused and gave no reason
/// (Failure)`; dropping the second kind throws away the only diagnosis
/// available.
///
/// So it is kept when it says something the code does not. The comparison is
/// deliberately loose — case and surrounding whitespace ignored — because it is
/// choosing whether to print a sentence, and nothing branches on the result.
fn server_note(text: &str) -> Option<String> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    // The status names, as OpenSSH spells them when it has nothing to add.
    const UNINFORMATIVE: [&str; 5] = [
        "failure",
        "permission denied",
        "no such file",
        "bad message",
        "op unsupported",
    ];
    if UNINFORMATIVE
        .iter()
        .any(|known| known.eq_ignore_ascii_case(text))
    {
        return None;
    }
    Some(text.to_string())
}

/// One sentence: what happened, where, and whatever the server added.
fn detail(what: &str, key: &str, note: Option<String>) -> String {
    match note {
        Some(said) => format!("sftp: {what} '{key}' (server said: {said})"),
        None => format!("sftp: {what} '{key}'"),
    }
}

/// Turn one protocol status into the error the rest of DCTL acts on.
///
/// Pure, and total over [`SftpErrorKind`] — which is `#[non_exhaustive]`, so the
/// final arm is a language requirement rather than a shrug. It is spelled to be
/// honest about that: a status this build does not know the name of is reported
/// as one, not folded into the catch-all it is not.
///
/// `message` is the status packet's free-text field, already unwrapped from the
/// wire type by the caller. Taking a `&str` rather than the library's
/// `SftpErrMsg` keeps this function a pure mapping between two things the crate
/// owns — which is what lets every branch of it be exercised without a server.
pub(super) fn classify(key: &str, kind: SftpErrorKind, message: &str) -> StoreError {
    let note = server_note(message);
    match kind {
        // Unchanged, and the one status that already had a home. Kept here so
        // the whole mapping is readable in one place.
        SftpErrorKind::NoSuchFile => StoreError::NotFound(key.to_string()),

        // `local:` raises `PermissionDenied` for the same condition and the
        // retry layer already refuses to retry it. OpenSSH answers this for
        // `EACCES`, `EPERM` and `EFAULT`, so no errno is invented here — the
        // kind is what is known, and the kind is what is reported.
        SftpErrorKind::PermDenied => StoreError::Io(io::Error::new(
            io::ErrorKind::PermissionDenied,
            detail("the server denied permission for", key, note),
        )),

        // The server understood the request and does not implement it. Its own
        // kind because the remedy is a different server or a different
        // operation, never a retry: `fsync` is tolerated for exactly this
        // reason and nothing else.
        SftpErrorKind::OpUnsupported => StoreError::Io(io::Error::new(
            io::ErrorKind::Unsupported,
            detail("the server does not implement the operation on", key, note),
        )),

        // A malformed packet, a protocol mismatch, or — the case a real server
        // produces most often — a handle opened read-only that a write arrived
        // on. All three are defects in the request rather than in the store, and
        // all three are equally true next time.
        SftpErrorKind::BadMessage => StoreError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            detail("the server rejected the request for", key, note),
        )),

        // The catch-all, and the whole reason this module exists. Everything the
        // server could not give a code to arrives here: a full filesystem, an
        // exceeded quota, a read-only mount, a non-empty directory, a device
        // error. It is deliberately **not** guessed at — [`super::space`] asks
        // the far end a question whose answer is evidence, and only that answer
        // is allowed to name the disk.
        SftpErrorKind::Failure => StoreError::Refused {
            backend: super::SFTP_BACKEND_NAME,
            path: key.to_string(),
            detail: note.unwrap_or_else(|| REFUSED_WITHOUT_REASON.to_string()),
        },

        // `#[non_exhaustive]`, so this arm is required. Reported as an
        // unrecognised status rather than folded into `Failure`, because the two
        // are different facts and a build that meets a code it was not compiled
        // against should say so.
        other => StoreError::Refused {
            backend: super::SFTP_BACKEND_NAME,
            path: key.to_string(),
            detail: format!(
                "the server answered with a status this build does not recognise ({other:?})"
            ),
        },
    }
}

/// What the catch-all means when the server added nothing to it.
///
/// The honest sentence for where the diagnosis cannot be made: it names the
/// *protocol* as the reason the cause is missing, so an operator does not read
/// it as DCTL having failed to look.
pub(super) const REFUSED_WITHOUT_REASON: &str =
    "the server refused it and the protocol's status carries no reason";

#[cfg(test)]
mod tests {
    use super::*;

    /// The status packet's free-text field, as the caller hands it over.
    const fn msg(text: &str) -> &str {
        text
    }

    #[test]
    fn every_status_that_is_not_a_missing_file_used_to_be_one_string_and_now_is_not() {
        // The defect, stated as the property that was wrong: five distinct
        // conditions rendered as `sftp server reported <name>: Err Message: ...`
        // and reached the same place. An operator could not tell a full disk
        // from a permission problem, and the retry layer could not tell a denial
        // from anything else.
        let statuses = [
            SftpErrorKind::PermDenied,
            SftpErrorKind::OpUnsupported,
            SftpErrorKind::BadMessage,
            SftpErrorKind::Failure,
        ];
        let mut seen: Vec<String> = Vec::new();
        for kind in statuses {
            let error = classify("o/thing.bin", kind, msg("Failure"));
            assert!(
                !matches!(error, StoreError::Backend(_)),
                "{kind:?} still collapses into the undiagnosable variant: {error}"
            );
            let rendered = format!("{error}");
            assert!(
                rendered.contains("o/thing.bin"),
                "{kind:?} must name what it refused: {rendered}"
            );
            assert!(
                !seen.contains(&rendered),
                "{kind:?} is indistinguishable from a status already mapped: {rendered}"
            );
            seen.push(rendered);
        }
    }

    #[test]
    fn a_denial_arrives_as_the_kind_local_raises_so_it_is_never_retried() {
        // The half that is not about wording. `crate::retry::observed` reads the
        // `ErrorKind`; a `StoreError::Backend` string reaches none of that, so a
        // denial used to be classified by the default arm rather than by what it
        // is.
        let error = classify("o/thing.bin", SftpErrorKind::PermDenied, msg(""));
        let StoreError::Io(io) = &error else {
            panic!("a denial must arrive as an io error, not as {error:?}");
        };
        assert_eq!(io.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(!crate::retry::observed::Observed::of(&error).transient);
    }

    #[test]
    fn a_missing_file_is_still_an_absence_rather_than_a_refusal() {
        assert!(matches!(
            classify("o/gone.bin", SftpErrorKind::NoSuchFile, msg("")),
            StoreError::NotFound(key) if key == "o/gone.bin"
        ));
    }

    #[test]
    fn the_catch_all_says_the_protocol_carried_no_reason_rather_than_inventing_one() {
        // The measured case: OpenSSH answers `ENOSPC` with `Failure` and the
        // literal word "Failure" in the message. Nothing here may claim to know
        // it was the disk — that is `super::space`'s job, and only with evidence.
        let error = classify("o/thing.bin", SftpErrorKind::Failure, msg("Failure"));
        let rendered = format!("{error}");
        assert!(
            rendered.contains(REFUSED_WITHOUT_REASON),
            "the sentence must name the protocol as the reason: {rendered}"
        );
        for invented in ["No space", "space left", "disk", "quota"] {
            assert!(
                !rendered.contains(invented),
                "a status code cannot show this, so it must not be claimed: {rendered}"
            );
        }
    }

    #[test]
    fn a_server_that_explains_itself_is_quoted_and_one_that_parrots_the_code_is_not() {
        // Servers other than OpenSSH do put a `strerror` in the message, and it
        // is the only diagnosis available when they do.
        let explained = classify(
            "o/thing.bin",
            SftpErrorKind::Failure,
            msg("No space left on device"),
        );
        assert!(
            format!("{explained}").contains("No space left on device"),
            "a real explanation must survive: {explained}"
        );

        // OpenSSH's own message is the status name, and repeating it produces
        // "gave no reason (Failure)".
        let parroted = classify("o/thing.bin", SftpErrorKind::Failure, msg("Failure"));
        assert!(
            !format!("{parroted}").contains("(Failure)"),
            "the status name is not an explanation: {parroted}"
        );
    }
}
