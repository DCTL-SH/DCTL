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
//! `docs/HANDOVER.md` §16.3. `dctl config create store sftp base=/srv/vault`
//! meant `/srv/vault`; `dctl init --base sftp:host/srv/vault` meant
//! `$HOME/srv/vault`, because the shorthand's `HOST/BASE` separator consumed the
//! leading slash and the remainder was read as login-relative. Same host, same
//! visible path, two directories — and `dctl init` printed
//! `OK created vault 'v' on 'sftp:host/srv/vault'` while writing the envelope
//! somewhere else. An operator who configured a remote one way and re-created it
//! the other way after a rebuild pointed their backups at a directory nobody had
//! named.
//!
//! [`from_spec`] therefore splits the host off at the first `/` and keeps that
//! slash on the base. What follows the host in the spec is exactly what `base=`
//! takes, character for character, which is what
//! `both_entry_points_agree_on_every_base` asserts.

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
/// [`RemoteSpec`](crate::remote::RemoteSpec) canonicalised it. The base is
/// everything from the first separator **inclusive**, so the operator's
/// `/srv/vault` survives as `/srv/vault` rather than becoming `srv/vault` and
/// being read as login-relative.
///
/// # Errors
/// [`ExitCode::Usage`] for a missing host, a missing base, or a base that
/// declares neither form — which in this spelling can only be a `~`-less
/// remainder, and the hint says so.
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
             example '{PROVIDER_SFTP}{REMOTE_SEPARATOR}lsx-001/srv/dctl-store'. \
             HOST is an ~/.ssh/config alias or user@host, and all of its \
             connection details come from your ssh config."
                ),
            ),
        );
    }
    if tail.is_empty() || tail == "/" {
        return Err(CliError::new(
            ExitCode::Usage,
            format!("'{spec}' names no base directory on '{host}'"),
        )
        .with_hint(format!(
            "Write it as \
             '{PROVIDER_SFTP}{REMOTE_SEPARATOR}{host}/srv/dctl-store' for an \
             absolute directory, or \
             '{PROVIDER_SFTP}{REMOTE_SEPARATOR}{host}/~/dctl-store' for one under \
             the SSH login directory. That is the directory the ciphertext \
             objects go under."
        )));
    }

    // A `~` in this spelling arrives as `/~/…`; strip the separator back off so
    // the shared rule sees the same text `base=~/…` would give it.
    let written = tail.strip_prefix("/~").map_or(tail, |rest| {
        if rest.is_empty() || rest.starts_with(PATH_SEPARATOR) {
            // Reconstruct `~` / `~/rest` without allocating a second string.
            &tail[1..]
        } else {
            tail
        }
    });

    let base = SftpBase::parse(written)
        .map(|b| b.canonical())
        .ok_or_else(|| {
            CliError::new(
                ExitCode::Usage,
                format!("'{spec}' does not say where on '{host}' the base is"),
            )
            .with_hint(format!(
                "Write '{PROVIDER_SFTP}{REMOTE_SEPARATOR}{host}/srv/dctl-store' \
                 for an absolute directory or \
                 '{PROVIDER_SFTP}{REMOTE_SEPARATOR}{host}/~/dctl-store' for one \
                 under the SSH login directory."
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
    fn spec_for(host: &str, written: &str) -> String {
        if written.starts_with(PATH_SEPARATOR) {
            format!("{PROVIDER_SFTP}{REMOTE_SEPARATOR}{host}{written}")
        } else {
            format!("{PROVIDER_SFTP}{REMOTE_SEPARATOR}{host}{PATH_SEPARATOR}{written}")
        }
    }

    #[test]
    fn both_entry_points_agree_on_every_base() {
        // The defect, as a property rather than an example. For every directory
        // an operator can name, `dctl config create NAME sftp host=H base=X` and
        // `dctl init --base sftp:H…X` name the same directory and store the
        // same string. Before this, `base=/srv/vault` was `/srv/vault` and
        // `sftp:HOST/srv/vault` was `$HOME/srv/vault`.
        for written in ["/srv/vault", "/srv//vault/", "~/dctl-store", "~", "/data"] {
            let through_setting = from_setting(written)
                .unwrap_or_else(|e| panic!("base={written} was refused: {}", e.message()));
            let spec = spec_for("lsx-001", written);
            let (host, through_spec) =
                via_spec(&spec).unwrap_or_else(|e| panic!("{spec}: {}", e.message()));
            assert_eq!(host, "lsx-001", "{spec}");
            assert_eq!(
                through_spec, through_setting,
                "'{written}' means two things depending on which command wrote it"
            );
        }
    }

    #[test]
    fn the_shorthand_keeps_the_slash_it_split_on() {
        // §16.3 in one assertion. `sftp:h/srv/vault` used to yield the base
        // `srv/vault`, which the backend resolved against the login directory —
        // so the vault landed in `$HOME/srv/vault` while every message said
        // `/srv/vault`.
        let (host, base) = via_spec("sftp:h/srv/vault").unwrap();
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
        let error = via_spec("sftp:lsx-001").unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(
            error.message().contains("base directory"),
            "{}",
            error.message()
        );
        let error = via_spec("sftp:lsx-001/").unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[test]
    fn a_tilde_that_starts_a_directory_name_is_not_a_home_reference() {
        // `~backups` is a directory called `~backups`, not user `backups`'s
        // home: SFTP cannot expand the second and inventing it would create the
        // first under a name nobody typed.
        let (_, base) = via_spec("sftp:h/~backups/store").unwrap();
        assert_eq!(base, "/~backups/store");
    }
}
