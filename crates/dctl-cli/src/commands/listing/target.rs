//! What the user typed, resolved into something a source can be opened on.
//!
//! Every listing verb takes one optional positional argument spelled the way
//! rclone spells it — `REMOTE:PATH` — and the ambiguity in that grammar is the
//! whole reason this module exists. `vault:photos` names a remote; `C:\photos`
//! and `\\nas\photos` are Windows paths that merely look like one; `./photos`
//! and `/srv/photos` are plainly local. Getting that wrong is not a cosmetic
//! bug: a `sync` that mistook `C:` for a remote would write to the wrong side.
//!
//! The disambiguation rules live in [`crate::remote::spec`], and this module
//! calls them rather than restating them. Every rule but one is identical on
//! every operating system; the exception is the drive letter, which is a drive
//! only where drives exist, because that is the only arrangement in which
//! `dctl ls r:` and `dctl copy ./x r:` can agree about what `r:` is. rclone
//! splits it in the same place (`fs/fspath/path.go:163`).
//!
//! The path half is canonicalised through
//! [`clean_logical`](crate::platform::path::clean_logical) on the way in, so
//! `photos//2024/` and `photos/./2024` address the same prefix, an NFD spelling
//! typed on macOS finds the NFC records an index written on Linux holds, and a
//! `..` component is rejected rather than being allowed to walk out of the
//! subtree the user named.

use std::path::PathBuf;

use crate::constants::{
    LISTING_TARGET_HINT, PATH_SEPARATOR, REMOTE_NAME_EXTRA_CHARS, REMOTE_SEPARATOR,
};
use crate::error::{CliError, Result};
use crate::platform::path;
use crate::remote::RemoteSpec;
use crate::remote::spec::{looks_local, names_a_remote, not_a_remote_name};

/// A resolved listing target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    /// A logical prefix inside a configured remote.
    Remote {
        /// Remote name, without the separator.
        remote: String,
        /// Canonical logical prefix. Empty means the whole vault.
        prefix: String,
    },
    /// A path on the local filesystem.
    Local(PathBuf),
}

impl Target {
    /// Resolve the positional argument, falling back to `--remote`.
    ///
    /// `spec` is the argument as typed, or `None` when the command was given
    /// none. An empty string is treated as absent rather than as "the remote
    /// named nothing", so `dctl ls ""` behaves like `dctl ls`.
    ///
    /// # Errors
    /// [`ExitCode::Usage`](crate::exit::ExitCode::Usage) when there is nothing
    /// to list — no argument and no `--remote` — when the remote name is not a
    /// legal one, or when the path half escapes its own root with `..`.
    pub fn parse(spec: Option<&str>, fallback_remote: Option<&str>) -> Result<Self> {
        let spec = spec.map(str::trim).filter(|s| !s.is_empty());

        let Some(spec) = spec else {
            let remote = fallback_remote
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    CliError::usage("no path given and no default remote configured")
                        .with_hint(LISTING_TARGET_HINT)
                })?;
            // `--remote` may itself carry a path (`--remote vault:photos`), so
            // it goes through the same grammar rather than a second one.
            return Self::parse_spec(remote);
        };

        Self::parse_spec(spec)
    }

    /// The logical prefix a source should be opened at. Empty for a local
    /// target, whose scoping lives in the path itself.
    #[must_use]
    pub fn prefix(&self) -> &str {
        match self {
            Self::Remote { prefix, .. } => prefix,
            Self::Local(_) => "",
        }
    }

    /// Whether this target names a configured remote.
    ///
    /// `cfg(test)` deliberately. Production used to branch on it — a local
    /// target was refused, a remote one was listed — and that branch is gone:
    /// [`crate::source::open`] answers for both, so a listing verb that could
    /// still ask would be a listing verb that could grow a second answer. What
    /// remains is the grammar's own observation point, and the grammar is worth
    /// testing exhaustively because `C:\data` being read as a remote is the
    /// mistake that writes to the wrong side of a transfer.
    #[cfg(test)]
    #[must_use]
    pub const fn is_remote(&self) -> bool {
        matches!(self, Self::Remote { .. })
    }

    /// The same target in the vocabulary [`crate::source::open`] speaks.
    ///
    /// Two grammars exist because two families needed one: the transfer commands
    /// parse a [`RemoteSpec`] from a positional argument, and the listing verbs
    /// parse a [`Target`] from an optional one that falls back to `--remote`.
    /// They agree on every rule that matters — because both ask
    /// [`crate::remote::spec`] rather than deciding for themselves — and this is
    /// the single conversion between them.
    ///
    /// Doing it here rather than in [`super::source`] is deliberate: a second
    /// place that turns "what the user typed" into a remote is a second place
    /// that can decide `archive` is a relative directory, which is exactly the
    /// class of bug that made a `copy` into a vault write into a folder called
    /// `vault` and exit 0.
    #[must_use]
    pub fn spec(&self) -> RemoteSpec {
        match self {
            Self::Remote { remote, prefix } => RemoteSpec::Named {
                remote: remote.clone(),
                path: prefix.clone(),
            },
            Self::Local(path) => RemoteSpec::Local(path.clone()),
        }
    }

    /// The target as the user would write it, for error messages and for the
    /// root label of a tree.
    #[must_use]
    pub fn display(&self) -> String {
        match self {
            Self::Remote { remote, prefix } => format!("{remote}{REMOTE_SEPARATOR}{prefix}"),
            Self::Local(path) => path.display().to_string(),
        }
    }

    /// Apply the grammar to a non-empty spec.
    fn parse_spec(spec: &str) -> Result<Self> {
        // A UNC path is local everywhere and a drive is local where drives
        // exist, checked before the colon split so `C:\data` on Windows never
        // becomes a remote called `C`.
        if looks_local(spec) {
            return Ok(Self::Local(PathBuf::from(spec)));
        }

        let Some((remote, rest)) = spec.split_once(REMOTE_SEPARATOR) else {
            return Ok(Self::Local(PathBuf::from(spec)));
        };

        validate_remote_name(remote, spec)?;

        let prefix = path::clean_logical(rest).ok_or_else(|| {
            // Shared with `RemoteSpec::parse` so one spelling of `..` cannot be
            // refused two different ways depending on which verb saw it, and so
            // the wording — which used to say a path escaped a root it plainly
            // stayed inside — is written once. See `path::parent_dir_refusal`.
            let (reason, hint) = path::parent_dir_refusal(spec, remote, rest, REMOTE_SEPARATOR);
            CliError::usage(reason).with_hint(hint)
        })?;

        Ok(Self::Remote {
            remote: remote.to_string(),
            prefix,
        })
    }
}

/// Reject a remote name that could not have come from a configuration file.
///
/// Catching it here turns a typo into a usage error naming the offending
/// character, instead of a "no such remote" three layers down that leaves the
/// user comparing their spec against the config by eye.
fn validate_remote_name(name: &str, spec: &str) -> Result<()> {
    if !names_a_remote(name) {
        let (reason, hint) = not_a_remote_name(name);
        return Err(CliError::usage(format!("'{spec}': {reason}")).with_hint(hint));
    }

    if let Some(bad) = name
        .chars()
        .find(|c| !c.is_alphanumeric() && !REMOTE_NAME_EXTRA_CHARS.contains(c))
    {
        let allowed: String = REMOTE_NAME_EXTRA_CHARS.iter().collect();
        return Err(
            CliError::usage(format!("remote name '{name}' contains '{bad}'")).with_hint(format!(
                "Remote names may use letters, digits and '{allowed}'."
            )),
        );
    }

    Ok(())
}

/// Join a prefix and a child component into a logical path.
///
/// Lives here because the separator rule is the target's, not the caller's: the
/// listing renderers build sub-paths constantly, and doing it inline is how a
/// leading `/` ends up in a JSON `Path` field on exactly one code path.
///
/// Tolerates a prefix that already ends in a separator. [`Target::parse`] never
/// produces one, but this is also called with roots that arrived from elsewhere,
/// and `photos//2024` would address nothing at all.
#[must_use]
pub fn join(prefix: &str, child: &str) -> String {
    let prefix = prefix.trim_end_matches(PATH_SEPARATOR);
    if prefix.is_empty() {
        child.to_string()
    } else {
        format!("{prefix}{PATH_SEPARATOR}{child}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exit::ExitCode;

    #[test]
    fn a_remote_spec_splits_into_a_name_and_a_prefix() {
        let target = Target::parse(Some("vault:photos/2024"), None).unwrap();
        assert_eq!(
            target,
            Target::Remote {
                remote: "vault".into(),
                prefix: "photos/2024".into(),
            }
        );
        assert!(target.is_remote());
        assert_eq!(target.prefix(), "photos/2024");
    }

    #[test]
    fn a_bare_remote_addresses_the_whole_vault() {
        let target = Target::parse(Some("vault:"), None).unwrap();
        assert_eq!(target.prefix(), "");
        assert_eq!(target.display(), "vault:");
    }

    #[test]
    fn drive_letters_and_unc_paths_stay_local() {
        // The bug this prevents: `C:\data` parsed as remote `C`, path `\data`.
        let target = Target::parse(Some(r"\\nas\share\photos"), None).unwrap();
        assert_eq!(target, Target::Local(PathBuf::from(r"\\nas\share\photos")));
        assert!(!target.is_remote());
        // The drive half is platform-conditional, and must land wherever the
        // transfer verbs land it — never in between.
        for spec in [r"C:\data", "d:/data"] {
            assert_eq!(
                Target::parse(Some(spec), None).unwrap().spec(),
                RemoteSpec::parse(spec).unwrap(),
                "{spec}"
            );
        }
    }

    #[test]
    fn a_path_without_a_colon_is_local() {
        assert_eq!(
            Target::parse(Some("./photos"), None).unwrap(),
            Target::Local(PathBuf::from("./photos"))
        );
        assert_eq!(
            Target::parse(Some("/srv/photos"), None).unwrap(),
            Target::Local(PathBuf::from("/srv/photos"))
        );
    }

    #[test]
    fn the_prefix_is_canonicalised_on_the_way_in() {
        // Redundant separators, `.` components and a trailing slash all address
        // the same subtree, and the index only holds one spelling of it.
        for spec in [
            "vault:photos//2024/",
            "vault:./photos/2024",
            "vault:photos/./2024/",
        ] {
            assert_eq!(
                Target::parse(Some(spec), None).unwrap().prefix(),
                "photos/2024"
            );
        }
    }

    #[test]
    fn unicode_spellings_converge_on_one_prefix() {
        // macOS hands back NFD; an index written on Linux holds NFC. Both must
        // address the same records or a listing on a Mac silently finds nothing.
        let nfd = Target::parse(Some("vault:cafe\u{301}"), None).unwrap();
        let nfc = Target::parse(Some("vault:caf\u{e9}"), None).unwrap();
        assert_eq!(nfd, nfc);
    }

    #[test]
    fn a_parent_component_is_refused() {
        let error = Target::parse(Some("vault:photos/../../etc"), None).unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.hint().is_some());
    }

    #[test]
    fn the_default_remote_is_used_when_no_path_is_given() {
        let target = Target::parse(None, Some("vault:photos")).unwrap();
        assert_eq!(target.prefix(), "photos");
        // An empty argument is "not given", not "the empty remote".
        assert_eq!(
            Target::parse(Some("  "), Some("vault:")).unwrap().prefix(),
            ""
        );
    }

    #[test]
    fn nothing_to_list_is_a_usage_error_with_a_next_step() {
        let error = Target::parse(None, None).unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.hint().is_some_and(|h| h.contains("--remote")));
    }

    #[test]
    fn an_illegal_remote_name_is_rejected_before_any_lookup() {
        // A space or a separator could never have come out of a config file.
        // `1:photos` is *not* on this list any more: a digit is not a drive
        // letter on any platform, so rclone reads it as a remote and so do we.
        for spec in ["my remote:photos", "vault/old:x", ".hidden:x"] {
            let error = Target::parse(Some(spec), None).unwrap_err();
            assert_eq!(error.code(), ExitCode::Usage, "{spec}");
        }
        // The characters real remote names use must keep working.
        for spec in ["b2-prod:", "s3_backup:x", "vault.old:x"] {
            assert!(Target::parse(Some(spec), None).is_ok(), "{spec}");
        }
    }

    #[test]
    fn a_single_letter_before_the_colon_follows_the_platform() {
        // Corrected this pass. `v:photos` is the V: drive on Windows and the
        // remote `v` everywhere else, which is rclone's rule — and, more to the
        // point, the rule `dctl copy` was already applying while this verb
        // applied a different one.
        assert_eq!(
            Target::parse(Some("v:photos"), None).unwrap().spec(),
            RemoteSpec::parse("v:photos").unwrap()
        );
        // A digit is not a drive letter anywhere, so it is a remote everywhere.
        assert_eq!(
            Target::parse(Some("1:photos"), None).unwrap(),
            Target::Remote {
                remote: "1".into(),
                prefix: "photos".into(),
            }
        );
    }

    #[test]
    fn a_target_converts_to_the_spec_the_source_layer_speaks() {
        // Both halves must survive: a remote that lost its prefix would list the
        // whole vault, and a local path that became a named remote would send
        // the run looking for configuration that does not exist.
        assert_eq!(
            Target::parse(Some("vault:photos/2024"), None)
                .unwrap()
                .spec(),
            RemoteSpec::Named {
                remote: "vault".into(),
                path: "photos/2024".into(),
            }
        );
        assert_eq!(
            Target::parse(Some("vault:"), None).unwrap().spec(),
            RemoteSpec::Named {
                remote: "vault".into(),
                path: String::new(),
            }
        );
        assert_eq!(
            Target::parse(Some("/srv/photos"), None).unwrap().spec(),
            RemoteSpec::Local(PathBuf::from("/srv/photos"))
        );
        // The drive-letter rule survives the conversion, however this platform
        // answers it.
        assert_eq!(
            Target::parse(Some(r"C:\data"), None).unwrap().spec(),
            RemoteSpec::parse(r"C:\data").unwrap()
        );
    }

    #[test]
    fn joining_never_produces_a_leading_or_doubled_separator() {
        assert_eq!(join("", "a"), "a");
        assert_eq!(join("photos", "2024"), "photos/2024");
        assert_eq!(join("photos/", "2024"), "photos/2024");
        assert_eq!(join("/", "a"), "a");
    }
}
