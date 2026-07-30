//! Turning a `REMOTE:PATH` argument into something a removal may act on.
//!
//! Every command in the removal family starts here, and none of them may skip
//! it: a typo that silently resolves to the wrong scope is the difference
//! between deleting `photos/2024` and deleting `photos`. The parse is therefore
//! deliberately strict — it refuses anything ambiguous rather than guessing —
//! and it is the only place in the family that interprets user path syntax.
//!
//! The disambiguation rules are [`crate::remote::spec`]'s, consulted rather than
//! re-derived: a single ASCII letter before the colon is a Windows drive letter
//! *on a platform that has drives*, a `\\`-prefixed string is a UNC share, and
//! both are *local* paths that no removal command accepts. Off Windows there is
//! no drive to be confused with, so `r:` there names the remote `r` — which is
//! rclone's rule and, since this module used to apply the drive test everywhere,
//! the one place a `purge` could refuse a remote the transfer verbs would use.

use std::fmt;

use serde::Serialize;

use crate::constants::REMOTE_SEPARATOR;
use crate::error::{CliError, Result};
use crate::platform::path;
use crate::remote::spec::{looks_local, names_a_remote, not_a_remote_name};

/// A resolved removal target: a named remote plus a canonical logical path.
///
/// The path is already cleaned and NFC-normalised, so two spellings of the same
/// name (`photos//2024/` and `photos/2024`, or a macOS decomposed `café`)
/// resolve to one target. Anything that survives construction is safe to hand
/// to the engine unchanged.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Target {
    /// Name of the configured remote, without the separator.
    pub remote: String,
    /// Canonical logical path inside that remote. Empty means the vault root.
    pub path: String,
}

impl Target {
    /// Parse a `REMOTE:PATH` specification.
    ///
    /// # Errors
    /// [`crate::exit::ExitCode::Usage`] when the spec names a local path, omits
    /// the remote, uses a remote name short enough to be a drive letter, or
    /// tries to escape its root with `..`.
    pub fn parse(spec: &str) -> Result<Self> {
        let spec = spec.trim();
        if spec.is_empty() {
            return Err(CliError::usage("no target given")
                .with_hint("Name what to remove, for example 'vault:photos/2024'."));
        }

        // Local paths are rejected before the colon split, because `C:\data`
        // *does* contain a colon and would otherwise parse as a remote.
        if looks_local(spec) {
            return Err(
                CliError::usage(format!("'{spec}' is a local path, not a remote")).with_hint(
                    "The removal commands operate on a remote, written REMOTE:PATH. \
                 Use your operating system's own tools to remove local files.",
                ),
            );
        }

        let Some((remote, rest)) = spec.split_once(REMOTE_SEPARATOR) else {
            return Err(
                CliError::usage(format!("'{spec}' is not a remote specification"))
                    .with_hint("Write the target as REMOTE:PATH, for example 'vault:photos/2024'."),
            );
        };

        if !names_a_remote(remote) {
            let (reason, hint) = not_a_remote_name(remote);
            return Err(CliError::usage(reason).with_hint(hint));
        }

        let Some(path) = path::clean_logical(rest) else {
            return Err(
                CliError::usage(format!("'{rest}' escapes the remote with '..'")).with_hint(
                    "Removal targets are relative to the vault root and may not \
                     contain '..' components.",
                ),
            );
        };

        Ok(Self {
            remote: remote.to_string(),
            path,
        })
    }

    /// Whether this target is the whole remote rather than a path inside it.
    ///
    /// The removal family branches on this constantly: `rmdir vault:` has no
    /// directory to remove, and `purge vault:` is the entire dataset.
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.path.is_empty()
    }

    /// The same target, with its path replaced by the prefix that addresses
    /// **inside the store this removal will actually enumerate**.
    ///
    /// For a named remote and for a vault the two are identical, and this is a
    /// clone. For a **provider shorthand** they are not: `b2:DCTL001/photos`
    /// names the bucket `DCTL001` and the prefix `photos` inside it, and the
    /// removal family used the whole string as a key prefix — so every verb in
    /// it looked under `DCTL001/photos/` *inside* `DCTL001` and found nothing.
    ///
    /// That is `HANDOVER.md` §11.3 item 6 on the write side. It was fixed for
    /// the read family at `2e6d180` and these six verbs were missed, which is
    /// the worse half: a listing that finds nothing is visibly empty, while
    /// `dctl purge b2:DCTL001/2019 --force` reports `OK removed: 0 object(s)` at
    /// exit **0** and a retention job records 2019 as reclaimed.
    ///
    /// Applied once, in [`super::engine::run`], rather than at the eight places
    /// downstream that read [`Target::path`] — the same shape
    /// [`crate::source::open`] uses, and for the same reason: a caller that has
    /// to remember which of two paths to use will eventually use the wrong one.
    /// The *typed* target stays the one the report and every message quote, so
    /// an operator still reads their own argument back.
    ///
    /// # Errors
    /// Whatever [`crate::remote::resolve`] reported — an unknown remote, a
    /// missing required setting, a malformed `chunk_size`. A removal that cannot
    /// say where it would look must not guess: guessing produces an empty
    /// selection, and an empty selection is reported as `0 object(s)` at exit 0.
    pub fn scoped_to(&self, ctx: &crate::ctx::Ctx) -> Result<Self> {
        let path = crate::config::resolve_path(ctx.globals.config.as_deref());
        let configured = crate::config::load_or_default(&path)?;
        let spec = crate::remote::RemoteSpec::Named {
            remote: self.remote.clone(),
            path: self.path.clone(),
        };
        Ok(Self {
            remote: self.remote.clone(),
            path: crate::remote::resolve::logical_prefix(
                &spec,
                &crate::commands::config::settings::catalog(&configured),
            )?,
        })
    }
}

impl fmt::Display for Target {
    /// Renders back to the spelling the user typed, so a prompt, a log record
    /// and an error all quote the same string.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}{}", self.remote, REMOTE_SEPARATOR, self.path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exit::ExitCode;

    fn parse(spec: &str) -> Result<Target> {
        Target::parse(spec)
    }

    #[test]
    fn a_remote_and_a_path_are_split_at_the_first_colon() {
        let target = parse("vault:photos/2024").unwrap();
        assert_eq!(target.remote, "vault");
        assert_eq!(target.path, "photos/2024");
        assert!(!target.is_root());
    }

    /// A context pointing at a config file that does not exist, so resolution
    /// sees the empty catalog — which is the headless case, and the one in which
    /// a provider shorthand is the *only* way to name a bucket.
    fn headless_ctx() -> crate::ctx::Ctx {
        use clap::Parser as _;
        #[derive(clap::Parser, Debug)]
        struct Harness {
            #[command(flatten)]
            globals: crate::cli::GlobalArgs,
        }
        let dir = std::env::temp_dir().join("dctl-removal-scope-no-such-config");
        crate::ctx::Ctx::new(
            Harness::parse_from(["dctl", "--config", &dir.to_string_lossy()]).globals,
        )
    }

    #[test]
    fn a_shorthands_bucket_is_not_part_of_the_prefix_a_removal_deletes_under() {
        // `HANDOVER.md` §11.3 item 6, on the side that destroys rather than the
        // side that merely reports nothing. `b2:DCTL001/2019` names the *bucket*
        // `DCTL001` and the prefix `2019` inside it; using the whole string as a
        // key prefix looks under `DCTL001/2019/` inside `DCTL001`, matches
        // nothing, and `dctl purge … --force` then reports `OK removed:
        // 0 object(s)` at exit 0 — so a retention job marks the year reclaimed
        // and the data is untouched.
        let ctx = headless_ctx();
        for (written, expected) in [
            ("b2:DCTL001", ""),
            ("b2:DCTL001/2019", "2019"),
            ("b2:DCTL001/2019/q4", "2019/q4"),
            ("s3:media/raw", "raw"),
            ("r2:cold", ""),
        ] {
            let scoped = parse(written)
                .expect("a well-formed target")
                .scoped_to(&ctx)
                .expect("a shorthand resolves with no config file");
            assert_eq!(
                scoped.path, expected,
                "'{written}' would delete under the wrong prefix"
            );
            // The remote half is untouched: only the path is re-scoped.
            assert_eq!(scoped.remote, parse(written).expect("parses").remote);
        }
    }

    #[test]
    fn a_target_that_cannot_be_resolved_yields_no_prefix_at_all() {
        // Never `Ok("")`. An empty prefix on an unresolvable remote is a
        // selection of the whole store, or of nothing — and both are answers a
        // removal acts on.
        let ctx = headless_ctx();
        let error = parse("nosuchremote:2019")
            .expect("a well-formed target")
            .scoped_to(&ctx)
            .expect_err("an unknown remote has no prefix");
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.message().contains("nosuchremote"));
    }

    #[test]
    fn a_bare_remote_is_the_root() {
        let target = parse("vault:").unwrap();
        assert!(target.is_root());
        assert_eq!(target.path, "");
        assert_eq!(target.to_string(), "vault:");
    }

    #[test]
    fn paths_are_canonicalised_before_anything_is_removed() {
        // Noise in the spelling must not produce a second, different target:
        // `photos//2024/` and `photos/2024` are the same directory.
        assert_eq!(parse("vault:./photos//2024/").unwrap().path, "photos/2024");
        // Windows users type backslashes; the logical path is always '/'.
        assert_eq!(parse(r"vault:photos\2024").unwrap().path, "photos/2024");
    }

    #[test]
    fn unicode_spellings_converge_on_one_target() {
        // macOS hands back NFD. Without normalisation this would address a
        // different object from the same name typed on Linux — and a removal
        // would silently miss.
        let nfd = parse("vault:cafe\u{301}/a.jpg").unwrap();
        let nfc = parse("vault:caf\u{e9}/a.jpg").unwrap();
        assert_eq!(nfd, nfc);
    }

    #[test]
    fn local_paths_are_refused_rather_than_guessed_at() {
        for spec in [r"\\server\share\x", "/tmp/x"] {
            let error = parse(spec).unwrap_err();
            assert_eq!(error.code(), ExitCode::Usage, "accepted '{spec}'");
            assert!(error.hint().is_some(), "'{spec}' failed without advice");
        }
    }

    #[test]
    fn one_letter_specs_follow_the_same_platform_rule_the_transfer_verbs_use() {
        // A removal that refused `r:photos` on a machine where `dctl copy` had
        // just written to it is the worst version of this drift: the operator
        // cannot delete what they were able to store.
        let removal = parse("r:photos");
        match crate::remote::RemoteSpec::parse("r:photos").expect("classified") {
            crate::remote::RemoteSpec::Named { remote, path } => {
                let target = removal.expect("removal must agree that this is a remote");
                assert_eq!(target.remote, remote);
                assert_eq!(target.path, path);
            }
            crate::remote::RemoteSpec::Local(_) => {
                assert_eq!(removal.unwrap_err().code(), ExitCode::Usage);
            }
        }
        assert!(parse("xy:z").is_ok());
    }

    #[test]
    fn escaping_the_root_is_refused() {
        let error = parse("vault:photos/../../etc").unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[test]
    fn an_empty_target_is_a_usage_error_not_the_whole_vault() {
        // The dangerous default: an empty argument must never widen to "all".
        assert_eq!(parse("").unwrap_err().code(), ExitCode::Usage);
        assert_eq!(parse("   ").unwrap_err().code(), ExitCode::Usage);
    }

    #[test]
    fn a_remote_name_never_contains_a_separator() {
        assert_eq!(parse("a/b:c").unwrap_err().code(), ExitCode::Usage);
    }

    #[test]
    fn the_display_form_round_trips_through_the_parser() {
        let target = parse("vault:photos/2024").unwrap();
        assert_eq!(target.to_string(), "vault:photos/2024");
        assert_eq!(parse(&target.to_string()).unwrap(), target);
    }

    #[test]
    fn the_json_shape_is_remote_plus_path() {
        let target = parse("vault:photos").unwrap();
        let value = serde_json::to_value(&target).unwrap();
        assert_eq!(value["remote"], "vault");
        assert_eq!(value["path"], "photos");
    }
}
