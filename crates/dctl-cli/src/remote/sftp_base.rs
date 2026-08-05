//! The one reading of an sftp `base`, shared by every door that writes one.
//!
//! The rule itself is [`dctl_store::SftpBase`]'s — a leading `/` is absolute, a
//! leading `~` is relative to the SSH login directory, and anything else is
//! refused because it used to mean both. This module is the CLI half: it turns
//! the refusal into a sentence naming what to type, and it is the *only* place
//! that reads a base, so the two commands that write one cannot drift apart
//! again.
//!
//! ## What drifted
//!
//! `dctl config create store sftp base=/srv/vault` meant `/srv/vault`;
//! `dctl init --base sftp:host/srv/vault` meant `$HOME/srv/vault`, because the
//! shorthand's `HOST/BASE` separator consumed the leading slash and the
//! remainder was read as login-relative. Same host, same visible path, two
//! directories — and `dctl init` printed
//! `OK created vault 'v' on 'sftp:host/srv/vault'` while writing the envelope
//! somewhere else. An operator who configured a remote one way and re-created it
//! the other way after a rebuild pointed their backups at a directory nobody had
//! named.
//!
//! [`from_spec`] therefore splits the host off at the first `/` and what
//! follows is exactly what `base=` takes, character for character — which is
//! what `both_entry_points_agree_on_every_base` asserts.
//!
//! ## And then the fix for that drift had a hazard of its own
//!
//! Keeping the split separator made every bare `sftp:HOST/dir` **absolute**,
//! which is not what anyone types it expecting: `scp host:dir`, rclone's sftp
//! backend and an operator's own ssh habits all read that as the login
//! directory. Measured cost of the mismatch —
//! `sftp:archive.example.com/dctl-bench-store` put 1.6 GiB of a benchmark's
//! ciphertext at the server's filesystem **root**, on the OS disk, while the
//! operator was reading the number of free terabytes on the data volume they
//! thought they had named.
//!
//! So the rule is rclone's now: one slash is the login directory, two is the
//! root (`sftp:HOST//srv/vault`), and `~` may still be spelled explicitly. The
//! doubled separator survives canonicalisation because
//! [`RemoteSpec`](crate::remote::RemoteSpec) splits this provider's host off
//! before cleaning the tail — collapsing `//` is what had made the absolute
//! spelling unspellable and forced the single slash to carry that meaning.
//! Stored configs are untouched: the file always holds the self-describing
//! canonical form, so this changes what *typing* means and nothing about what
//! an existing remote resolves to.

use dctl_store::SftpBase;

use crate::constants::{
    CONFIG_KEY_BASE, CONFIG_KEY_HOST, PATH_SEPARATOR, PROVIDER_SFTP, REMOTE_SEPARATOR,
};
use crate::error::{CliError, Result};
use crate::exit::ExitCode;

/// Read a `base=` setting, in its canonical spelling.
///
/// # Errors
/// [`ExitCode::Usage`] for a base that declares neither form. The refusal names
/// both spellings, because the whole point is that the operator states which one
/// they meant instead of a parser deciding for them.
pub fn from_setting(base: &str) -> Result<String> {
    SftpBase::parse(base).map(|b| b.canonical()).ok_or_else(|| {
        CliError::new(
            ExitCode::Usage,
            format!("'{base}' does not say where on the server it is"),
        )
        .with_hint(format!(
            "An sftp {CONFIG_KEY_BASE} is either absolute — \
             '{CONFIG_KEY_BASE}=/{base}' — or under the SSH login directory — \
             '{CONFIG_KEY_BASE}=~/{base}'. A bare relative path used to mean the \
             second one here and the first one in 'sftp{REMOTE_SEPARATOR}HOST/…', \
             so it now has to say which; pick the one you meant and nothing else \
             changes."
        ))
    })
}

/// Split an `sftp:HOST/BASE` spec's path into the ssh destination and the
/// canonical base.
///
/// `path` is the whole remainder after `sftp:`, as
/// [`RemoteSpec`](crate::remote::RemoteSpec) canonicalised it — which for this
/// provider preserves a doubled separator, because that is what tells the two
/// meanings apart.
///
/// The rule is rclone's, and it is the one an operator typing an ssh
/// destination already has in their fingers:
///
/// | spelling | base | same as `base=` |
/// |---|---|---|
/// | `sftp:host/vault` | `~/vault`, under the SSH login directory | `~/vault` |
/// | `sftp:host//srv/vault` | `/srv/vault`, from the filesystem root | `/srv/vault` |
/// | `sftp:host/~/vault` | `~/vault` | `~/vault` |
///
/// **The single slash used to mean absolute**, and that was a measured
/// hazard rather than a preference: `sftp:host/dctl-store` put 1.6 GiB of a
/// benchmark's ciphertext at the server's filesystem root, on the OS disk,
/// while every convention the operator had — rclone's, scp's, their own ssh
/// config — said it would land under their home directory. Nothing in a
/// stored config changes: the file always holds the self-describing
/// canonical form (`/abs` or `~/rel`), so this is a change to what typing
/// means, not to what any existing remote resolves to.
///
/// # Errors
/// [`ExitCode::Usage`] for a missing host, a missing base, or a `/~name`
/// tail — the one spelling whose meaning genuinely changed and whose two
/// readings are both plausible, so it is refused with both explicit forms
/// rather than silently picking one.
pub fn from_spec(spec: &str, path: &str) -> Result<(String, String)> {
    let (host, tail) = match path.find(PATH_SEPARATOR) {
        // Keep the separator: it is the leading slash of an absolute path, and
        // eating it is the whole defect.
        Some(at) => (&path[..at], &path[at..]),
        None => (path, ""),
    };

    if host.is_empty() {
        return Err(
            CliError::new(ExitCode::Usage, format!("'{spec}' names no ssh host")).with_hint(
                format!(
                    "Write it as '{PROVIDER_SFTP}{REMOTE_SEPARATOR}HOST/BASE-DIR' — for \
             example '{PROVIDER_SFTP}{REMOTE_SEPARATOR}backup.example.com/srv/dctl-store'. \
             HOST is an ~/.ssh/config alias or user@host, and all of its \
             connection details come from your ssh config."
                ),
            ),
        );
    }
    if tail.is_empty() || tail == "/" || tail == "//" {
        return Err(CliError::new(
            ExitCode::Usage,
            format!("'{spec}' names no base directory on '{host}'"),
        )
        .with_hint(format!(
            "Write it as \
             '{PROVIDER_SFTP}{REMOTE_SEPARATOR}{host}/dctl-store' for a \
             directory under the SSH login directory, or \
             '{PROVIDER_SFTP}{REMOTE_SEPARATOR}{host}//srv/dctl-store' for an \
             absolute one. That is the directory the ciphertext objects go \
             under."
        )));
    }

    // Everything after `HOST/` is character-for-character what `base=` takes,
    // which is the invariant that keeps one rule instead of two: `//x` is the
    // absolute `/x`, `/~/x` is the home-relative `~/x`, and a bare `/x` is the
    // home-relative `~/x` this provider now defaults to.
    let written = if let Some(rest) = tail.strip_prefix("//") {
        // Absolute: hand on the single leading separator.
        format!("/{rest}")
    } else if let Some(rest) = tail.strip_prefix("/~") {
        if rest.is_empty() || rest.starts_with(PATH_SEPARATOR) {
            // `~` / `~/rest`, spelled explicitly.
            tail[1..].to_string()
        } else {
            // `/~name`: under the old absolute-by-default rule this was a
            // literal directory called `~name` at the root; under the new one
            // the tilde would be read as another user's home. Both readings
            // are plausible and they address different machines' worth of
            // data, so neither is guessed.
            return Err(CliError::new(
                ExitCode::Usage,
                format!("'{spec}' is ambiguous: '~{}' could name a home directory or a literal directory", &rest[..rest.find(PATH_SEPARATOR).unwrap_or(rest.len())]),
            )
            .with_hint(format!(
                "Say which: \
                 '{PROVIDER_SFTP}{REMOTE_SEPARATOR}{host}/{tail}' as an \
                 absolute path is \
                 '{PROVIDER_SFTP}{REMOTE_SEPARATOR}{host}/{tail}' written with \
                 two leading slashes, and a directory under your own login \
                 directory is \
                 '{PROVIDER_SFTP}{REMOTE_SEPARATOR}{host}/~{}'.",
                rest
            )));
        }
    } else {
        // The default, and the one this spelling exists for: a directory
        // under the SSH login directory, exactly as `scp host:dir` means.
        format!("~{tail}")
    };

    let base = SftpBase::parse(&written)
        .map(|b| b.canonical())
        .ok_or_else(|| {
            CliError::new(
                ExitCode::Usage,
                format!("'{spec}' does not say where on '{host}' the base is"),
            )
            .with_hint(format!(
                "Write '{PROVIDER_SFTP}{REMOTE_SEPARATOR}{host}/dctl-store' for \
                 a directory under the SSH login directory or \
                 '{PROVIDER_SFTP}{REMOTE_SEPARATOR}{host}//srv/dctl-store' for \
                 an absolute one."
            ))
        })?;

    Ok((host.to_string(), base))
}

/// The two settings an sftp store remote is written from.
///
/// A pair rather than two loose strings so a caller cannot write the host into
/// the base's key, which `dctl config create` does by hand three files away.
#[must_use]
pub fn settings(host: &str, base: &str) -> std::collections::BTreeMap<String, String> {
    [
        (CONFIG_KEY_HOST.to_string(), host.to_string()),
        (CONFIG_KEY_BASE.to_string(), base.to_string()),
    ]
    .into_iter()
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::RemoteSpec;

    /// Parse `spec` the way every command does, then split it the way the sftp
    /// shorthand does — so the test exercises the real path, including the
    /// logical-path canonicalisation that collapses `//` and made an absolute
    /// base unspellable.
    fn via_spec(spec: &str) -> Result<(String, String)> {
        let RemoteSpec::Named { remote, path } = RemoteSpec::parse(spec)? else {
            panic!("'{spec}' did not parse as a named remote");
        };
        assert_eq!(remote, PROVIDER_SFTP);
        from_spec(spec, &path)
    }

    /// How an operator writes `written` after a host in a `sftp:` spec.
    ///
    /// An absolute base already carries its own separator; a `~` one needs the
    /// separator that divides host from path. Either way the text after the host
    /// is the text `base=` takes, which is the property being asserted.
    /// The shorthand that names exactly what `base=written` names.
    ///
    /// Everything after `HOST/` is character-for-character what `base=` takes,
    /// which is the invariant that keeps one rule instead of two: an absolute
    /// `/x` is written `HOST//x`, and anything else is appended as-is.
    fn spec_for(host: &str, written: &str) -> String {
        format!("{PROVIDER_SFTP}{REMOTE_SEPARATOR}{host}{PATH_SEPARATOR}{written}")
    }

    #[test]
    fn both_entry_points_agree_on_every_base() {
        // The defect, as a property rather than an example. For every directory
        // an operator can name, `dctl config create NAME sftp host=H base=X`
        // and `dctl init --base sftp:H/X` name the same directory and store the
        // same string — the tail after `HOST/` being character-for-character
        // what `base=` takes. Before this, `base=/srv/vault` was `/srv/vault`
        // while `sftp:HOST/srv/vault` was a *different* directory, and now the
        // absolute one is spelled `sftp:HOST//srv/vault` and means the same.
        for written in ["/srv/vault", "/srv//vault/", "~/dctl-store", "~", "/data"] {
            let through_setting = from_setting(written)
                .unwrap_or_else(|e| panic!("base={written} was refused: {}", e.message()));
            let spec = spec_for("backup.example.com", written);
            let (host, through_spec) =
                via_spec(&spec).unwrap_or_else(|e| panic!("{spec}: {}", e.message()));
            assert_eq!(host, "backup.example.com", "{spec}");
            assert_eq!(
                through_spec, through_setting,
                "'{written}' means two things depending on which command wrote it"
            );
        }
    }

    #[test]
    fn one_slash_is_the_login_directory_and_two_is_the_root() {
        // The rule an operator already has in their fingers, from scp, from
        // rclone, from their own ssh config — and the measured reason it is
        // this way round: under the old absolute-by-default rule
        // `sftp:h/dctl-store` put 1.6 GiB of benchmark ciphertext at the
        // server's filesystem root, on the OS disk, while every convention
        // said it would land under the home directory.
        let (host, base) = via_spec("sftp:h/dctl-store").unwrap();
        assert_eq!(host, "h");
        assert_eq!(base, "~/dctl-store");

        // And the absolute spelling, which the canonicalisation used to
        // collapse and therefore made unspellable.
        let (host, base) = via_spec("sftp:h//srv/vault").unwrap();
        assert_eq!(host, "h");
        assert_eq!(base, "/srv/vault");
    }

    #[test]
    fn a_login_relative_base_is_written_with_a_tilde_through_either_door() {
        assert_eq!(from_setting("~/dctl-store").unwrap(), "~/dctl-store");
        assert_eq!(via_spec("sftp:h/~/dctl-store").unwrap().1, "~/dctl-store");
        assert_eq!(via_spec("sftp:h/~").unwrap().1, "~");
    }

    #[test]
    fn a_setting_that_declares_neither_form_is_refused_with_both_spellings() {
        let error = from_setting("dctl-store").unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        let hint = error.hint().unwrap_or_default();
        assert!(hint.contains("base=/dctl-store"), "{hint}");
        assert!(hint.contains("base=~/dctl-store"), "{hint}");
    }

    #[test]
    fn a_spec_with_no_host_or_no_base_is_refused_before_anything_is_written() {
        // `sftp:` alone names nothing at all.
        let error = via_spec("sftp:").unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);

        // A host with no base is the more likely typo, and the one that used to
        // be worth catching: it is a whole vault addressed at a directory nobody
        // named.
        let error = via_spec("sftp:backup.example.com").unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(
            error.message().contains("base directory"),
            "{}",
            error.message()
        );
        let error = via_spec("sftp:backup.example.com/").unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[test]
    fn a_tilde_that_starts_a_directory_name_is_refused_rather_than_guessed() {
        // `~backups` is the one spelling whose meaning genuinely changed:
        // under absolute-by-default it was a literal directory called
        // `~backups` at the root, and under the home-relative default the
        // tilde reads as another user's home — which SFTP cannot expand
        // anyway. Two plausible readings addressing different machines' worth
        // of data, so neither is guessed.
        let error = via_spec("sftp:h/~backups/store").unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(
            error.hint().is_some_and(|hint| hint.contains("//")),
            "the hint must name the explicit absolute spelling"
        );

        // Both explicit spellings still work, which is what makes the refusal
        // actionable rather than a dead end.
        assert_eq!(
            via_spec("sftp:h//~backups/store").unwrap().1,
            "/~backups/store"
        );
        assert_eq!(via_spec("sftp:h/~/~backups").unwrap().1, "~/~backups");
    }
}
