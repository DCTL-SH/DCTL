//! What an sftp `base` means — decided once, for every way of writing one.
//!
//! ## The defect this exists to close
//!
//! `base` used to mean two different things depending on which command wrote it:
//!
//! ```text
//! $ dctl config create store sftp host=h base=/srv/vault   → /srv/vault
//! $ dctl init --base sftp:h/srv/vault                       → $HOME/srv/vault
//! ```
//!
//! Same server, same visible path, two directories, no warning — because the
//! shorthand's `HOST/BASE` separator ate the leading slash and the remainder was
//! then read as a login-relative path. An operator who configured a remote one
//! way and re-created it the other way after a rebuild pointed their backups at
//! a directory they had never named, and nothing said so. `dctl init` even
//! reported `OK created vault 'v' on 'sftp:h/srv/vault'` while writing the
//! envelope to `~/srv/vault`.
//!
//! ## The rule
//!
//! One rule, and it is rclone's — *if the path does not begin with a `/` it is
//! relative to the home directory of the user* — made explicit so it cannot be
//! read two ways:
//!
//! * `/srv/vault` — **absolute** on the server.
//! * `~/vault`, or `~` alone — **relative to the SSH login directory**.
//! * anything else — **refused**. `base=vault` is the spelling that meant one
//!   thing through one door and another through the other, so it no longer means
//!   anything: it has to declare itself as `~/vault` or `/vault`.
//!
//! Refusing rather than picking is what makes this safe to change. A bare
//! relative base in an existing configuration now fails loudly with the
//! one-character fix in the message, instead of being silently reinterpreted —
//! which would be the very failure this closes, inflicted by the fix for it.
//!
//! ## And the shorthand keeps the slash
//!
//! `sftp:HOST/BASE` splits at the first `/` and the base is the remainder
//! **including that slash**, so what an operator reads after the host is what
//! they get: `sftp:h/srv/vault` is `/srv/vault`, the same string `base=` takes.
//! `sftp:h/~/vault` is `~/vault`. The two doors take the same text and produce
//! the same directory, which is the property `both_entry_points_agree` in
//! `dctl-cli` holds them to.

/// A base directory on an sftp server, in a form that says which kind it is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Base {
    /// An absolute path on the server, with no trailing slash: `/srv/vault`.
    Absolute(String),
    /// A path under the SSH login directory, or that directory itself.
    ///
    /// The stored string is the part *after* `~/`, so the login directory is
    /// `Home(String::new())`.
    Home(String),
}

impl Base {
    /// Read a written base, or `None` if it declares neither form.
    ///
    /// `None` is the input this module refuses on the caller's behalf: the
    /// caller owns the wording, because what a user should type instead depends
    /// on whether they are writing a config setting or a `sftp:` spec.
    #[must_use]
    pub fn parse(input: &str) -> Option<Self> {
        let trimmed = input.trim();
        if let Some(rest) = trimmed.strip_prefix('~') {
            // `~`, `~/`, `~/a/b` — everything after the tilde is under the
            // login directory. A bare `~foo` (another user's home) is not
            // supported by SFTP without the `expand-path` extension, and
            // pretending otherwise would create a directory literally named
            // `~foo`, so it is read as `foo` under this user's home exactly as
            // the wire layer has always read it.
            return Some(Self::Home(clean(rest)));
        }
        if let Some(rest) = trimmed.strip_prefix('/') {
            let cleaned = clean(rest);
            return Some(Self::Absolute(format!("/{cleaned}")));
        }
        None
    }

    /// The canonical spelling — what gets written into the configuration.
    ///
    /// Always self-describing: an operator reading `dctl config show` can see
    /// which of the two they have without knowing this module exists. That
    /// visibility is half the fix; the other half is that both entry points
    /// produce it.
    #[must_use]
    pub fn canonical(&self) -> String {
        match self {
            Self::Absolute(path) => path.clone(),
            Self::Home(rest) if rest.is_empty() => "~".to_string(),
            Self::Home(rest) => format!("~/{rest}"),
        }
    }

    /// The path the SFTP protocol is given.
    ///
    /// SFTP has no `~` — the optional `expand-path` extension aside — and the
    /// openssh `sftp-server` resolves a *relative* path against the login
    /// directory. So the login-relative form goes on the wire with the tilde
    /// stripped, which is what [`super::path::normalize_base`] has always done
    /// and what `the_wire_form_matches_the_backends_own_normalisation` holds
    /// this to.
    #[must_use]
    pub fn wire(&self) -> String {
        match self {
            Self::Absolute(path) => path.clone(),
            Self::Home(rest) => rest.clone(),
        }
    }
}

/// Collapse redundant separators and trim the trailing one.
fn clean(path: &str) -> String {
    path.split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sftp::path::normalize_base;

    #[test]
    fn an_absolute_base_stays_absolute() {
        assert_eq!(
            Base::parse("/srv/vault"),
            Some(Base::Absolute("/srv/vault".into()))
        );
        assert_eq!(
            Base::parse("/srv//vault/"),
            Some(Base::Absolute("/srv/vault".into()))
        );
        assert_eq!(Base::parse("/"), Some(Base::Absolute("/".into())));
    }

    #[test]
    fn a_tilde_base_is_relative_to_the_login_directory() {
        assert_eq!(Base::parse("~/vault"), Some(Base::Home("vault".into())));
        assert_eq!(Base::parse("~"), Some(Base::Home(String::new())));
        assert_eq!(Base::parse("~/a//b/"), Some(Base::Home("a/b".into())));
    }

    #[test]
    fn a_base_that_declares_neither_is_refused_rather_than_guessed() {
        // The whole defect in one assertion. `vault` used to be
        // `$HOME/vault` through the config and to be unreachable through the
        // shorthand, and `srv/vault` looked absolute to everybody who wrote it.
        for undeclared in ["vault", "srv/vault", "./vault", "", "   "] {
            assert_eq!(Base::parse(undeclared), None, "'{undeclared}'");
        }
    }

    #[test]
    fn the_canonical_spelling_round_trips() {
        for written in ["/srv/vault", "~/vault", "~", "/"] {
            let parsed = Base::parse(written).unwrap();
            let canonical = parsed.canonical();
            assert_eq!(
                Base::parse(&canonical),
                Some(parsed),
                "'{written}' → '{canonical}' did not read back the same"
            );
        }
        assert_eq!(
            Base::parse("/srv//vault/").unwrap().canonical(),
            "/srv/vault"
        );
        assert_eq!(Base::parse("~/a//b/").unwrap().canonical(), "~/a/b");
    }

    #[test]
    fn the_wire_form_matches_the_backends_own_normalisation() {
        // Two descriptions of the same thing, held to each other. If they ever
        // disagreed, a base would be validated as one directory and addressed as
        // another — which is the defect this module exists to close, moved one
        // layer down.
        for written in ["/srv/vault", "/srv//vault/", "~/vault", "~", "~/a/b", "/"] {
            let parsed = Base::parse(written).unwrap();
            assert_eq!(
                parsed.wire(),
                normalize_base(written),
                "'{written}': the policy and the wire disagree"
            );
        }
    }
}
