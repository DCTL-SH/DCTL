//! Why `dctl replicate` has no filters, and how it says so.
//!
//! Every other transfer verb in DCTL narrows what it moves. This one refuses to,
//! and the reason is not conservatism — it is that a filtered replica is not a
//! replica at all.
//!
//! A vault's object store is a **single consistent set**. The index inside it
//! references every object in it, and an object is only reachable through the
//! key the vault derived for it. Take a subset and what remains is not a smaller
//! vault: it is a vault with dangling references, and nothing detects that until
//! a restore asks for one of the objects the filter dropped — which is to say,
//! on the worst possible day. `PLAN.md` §13.3 asks for a provider-to-provider
//! replica of a vault's object tree, and "of the object tree" is the load-bearing
//! phrase.
//!
//! This is the sharpest argument for `replicate` being its own verb rather than
//! `copy --raw`. `dctl copy --raw archive-store: offsite: --include '*.jpg'`
//! would parse, would run, and would produce a broken replica while reporting
//! success — and the flag it needed to do so is a *global*, so it could arrive
//! from a shell alias or a CI template nobody re-read. A verb that owns its
//! filter policy can refuse; a flag on a verb that has to honour filters cannot.
//!
//! The refusal is a **usage error** (exit 1) rather than an unimplemented one
//! (exit 7). Nothing here is waiting on an engine: filtering a replication is not
//! a feature DCTL has yet to build, it is one it will not build, and a script
//! that branches on exit 7 would eventually retry a command that is never going
//! to start working.

use crate::cli::GlobalArgs;
use crate::constants::{MAX_DEPTH_UNLIMITED, REPLICATE_FILTER_HINT};
use crate::error::{CliError, Result};
use crate::exit::ExitCode;

/// Refuse a run that asked for any filter at all.
///
/// Checked **first**, before the configuration is read and before either store
/// is contacted, so the answer to "did my filter apply?" never depends on
/// whether the remotes happened to resolve. Every filter flag is listed in the
/// message, not just the first one found: an operator who removes the one flag
/// they were told about and reruns has spent a round trip learning about the
/// second.
///
/// # Errors
/// [`ExitCode::Usage`] naming every filter flag that was set.
pub fn refuse(globals: &GlobalArgs) -> Result<()> {
    let requested = requested(globals);
    if requested.is_empty() {
        return Ok(());
    }

    Err(CliError::new(
        ExitCode::Usage,
        format!(
            "dctl replicate does not accept filters, and {} was given",
            requested.join(", ")
        ),
    )
    .with_hint(REPLICATE_FILTER_HINT))
}

/// Which filter flags this run set, spelled as the user typed them.
///
/// Split out so the list — the part that goes stale when a filter is added to
/// [`GlobalArgs`] — can be asserted against the parser in a test rather than
/// reviewed. `--max-depth` is compared against [`MAX_DEPTH_UNLIMITED`] rather
/// than against zero, because zero is a *narrower* depth than the default and
/// treating it as unset would let the one filter with a numeric default through.
fn requested(globals: &GlobalArgs) -> Vec<&'static str> {
    let mut given = Vec::new();
    if !globals.include.is_empty() {
        given.push("--include");
    }
    if !globals.exclude.is_empty() {
        given.push("--exclude");
    }
    if !globals.filter_from.is_empty() {
        given.push("--filter-from");
    }
    if !globals.files_from.is_empty() {
        given.push("--files-from");
    }
    if globals.min_size.is_some() {
        given.push("--min-size");
    }
    if globals.max_size.is_some() {
        given.push("--max-size");
    }
    if globals.max_depth != MAX_DEPTH_UNLIMITED {
        given.push("--max-depth");
    }
    given
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
    fn an_unfiltered_run_is_allowed() {
        assert!(refuse(&globals(&[])).is_ok());
        // Flags that are not filters must not be mistaken for them.
        assert!(refuse(&globals(&["--verify", "strict", "--transfers", "8"])).is_ok());
    }

    #[test]
    fn every_filter_flag_is_refused() {
        // The whole list, one at a time: a filter that slipped through would
        // produce a replica missing exactly the objects the rule mentioned.
        for argv in [
            vec!["--include", "*.jpg"],
            vec!["--exclude", "tmp/**"],
            vec!["--filter-from", "/etc/rules"],
            vec!["--files-from", "/etc/list"],
            vec!["--min-size", "1M"],
            vec!["--max-size", "1G"],
            vec!["--max-depth", "2"],
        ] {
            let error = refuse(&globals(&argv)).unwrap_err();
            assert_eq!(error.code(), ExitCode::Usage, "{argv:?}");
            assert!(
                error.message().contains(argv[0]),
                "the refusal must name the flag: {}",
                error.message()
            );
        }
    }

    #[test]
    fn a_zero_max_depth_is_a_filter_and_not_a_default() {
        // `0` is narrower than unlimited, not absent. Reading it as "unset"
        // would let the one filter with a numeric default through unnoticed.
        assert!(refuse(&globals(&["--max-depth", "0"])).is_err());
        // Spelled with `=` because clap reads a bare `-1` as a short flag.
        assert!(refuse(&globals(&["--max-depth=-1"])).is_ok());
    }

    #[test]
    fn every_filter_flag_is_named_at_once() {
        // Removing one flag and rerunning only to be told about the next is a
        // round trip per rule, on a command whose runs are measured in hours.
        let error = refuse(&globals(&[
            "--include",
            "*.jpg",
            "--exclude",
            "tmp/**",
            "--max-size",
            "1G",
        ]))
        .unwrap_err();
        for flag in ["--include", "--exclude", "--max-size"] {
            assert!(error.message().contains(flag), "{}", error.message());
        }
    }

    #[test]
    fn the_refusal_explains_that_a_partial_replica_is_broken() {
        let error = refuse(&globals(&["--include", "*"])).unwrap_err();
        let hint = error.hint().unwrap_or_default();
        assert!(hint.contains("not a vault"), "got hint: {hint}");
        // And points at the verb that does narrow a transfer.
        assert!(hint.contains("dctl copy"), "got hint: {hint}");
    }

    #[test]
    fn the_flag_list_covers_every_filter_the_parser_offers() {
        // The check that keeps this module honest when a filter is added to the
        // global block: every flag clap files under "Filtering" must be one this
        // module refuses.
        use clap::CommandFactory as _;
        let command = Harness::command();
        let filtering: Vec<String> = command
            .get_arguments()
            .filter(|arg| arg.get_help_heading() == Some("Filtering"))
            .filter_map(|arg| arg.get_long().map(|long| format!("--{long}")))
            .collect();
        assert!(!filtering.is_empty(), "the harness must expose the group");

        // Setting every one of them at once must name every one of them.
        let error = refuse(&globals(&[
            "--include",
            "*",
            "--exclude",
            "*",
            "--filter-from",
            "f",
            "--files-from",
            "f",
            "--min-size",
            "1",
            "--max-size",
            "1",
            "--max-depth",
            "1",
        ]))
        .unwrap_err();
        for flag in filtering {
            assert!(
                error.message().contains(&flag),
                "'{flag}' is a filter the parser offers and this module ignores: {}",
                error.message()
            );
        }
    }
}
