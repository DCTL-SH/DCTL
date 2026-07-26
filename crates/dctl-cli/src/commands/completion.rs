//! `dctl completion SHELL` — a completion script for the real command tree.
//!
//! The script is generated from `<Cli as CommandFactory>::command()`, which is
//! the *same* [`clap::Command`] the parser is built from. That is the whole
//! design: completions produced from a hand-maintained list drift the moment a
//! flag is added, renamed or hidden, and a shell that offers a flag the binary
//! rejects is worse than one that offers nothing. Here they cannot drift,
//! because there is only one description of the command tree and both the parser
//! and the generator read it.
//!
//! ## Where the script goes
//!
//! **stdout, and nothing else does** — so `dctl completion zsh > "${fpath[1]}/_dctl"`
//! writes a usable file and `dctl completion bash | source /dev/stdin` works in
//! a live shell. The install hint is a note about the result rather than part of
//! it, so it goes to stderr like every other note ([`crate::output`]).
//!
//! ## Formats
//!
//! Text emits the raw script, which is what a redirect wants. `--json` wraps it
//! as `{"shell", "binary", "script"}`, which is what a configuration-management
//! tool wants: it can compare the `script` field against the file already on
//! disk and write only when it differs, without shelling out twice.
//!
//! ## Nothing here needs anything
//!
//! No config, no vault, no network, no password — see
//! [`crate::cli::Command::requires_vault`]. Generating a completion script is
//! pure computation over the parser's own metadata, which is why it is safe to
//! run from a shell's startup file.

use clap::{Args, CommandFactory};
use clap_complete::aot::{Shell, generate};
use serde::Serialize;

use crate::cli::Cli;
use crate::constants::COMPLETION_INSTALL_HINTS;
use crate::ctx::Ctx;
use crate::error::{CliError, Result};

/// Arguments for `dctl completion`.
#[derive(Args, Debug)]
pub struct CompletionArgs {
    /// Shell to generate the script for.
    ///
    /// The accepted values come from `clap_complete`'s own `Shell` enum rather
    /// than a list written here, so a shell it learns to generate for becomes
    /// available without an edit — and one it drops cannot be offered by mistake.
    #[arg(value_name = "SHELL", value_enum)]
    pub shell: Shell,
}

/// The `--json` rendering of a generated script.
///
/// Borrowed rather than owned: the script can be tens of kilobytes, and it is
/// serialised straight out of the buffer it was generated into.
#[derive(Debug, Serialize)]
struct CompletionScript<'a> {
    /// Shell the script is for, spelled as it is on the command line.
    shell: &'a str,
    /// Executable the script completes — the name the shell must see.
    binary: &'a str,
    /// The script itself.
    script: &'a str,
}

/// Write a completion script to stdout.
///
/// # Errors
/// A stdout failure other than a broken pipe, and — in the case that should be
/// impossible — a generator that emitted bytes which are not UTF-8.
///
/// `--dry-run` changes nothing: the command writes only to stdout and mutates
/// nothing, so there is no action for a dry run to withhold. Suppressing the
/// script would break `dctl completion zsh > file` for anyone who has `DCTL`
/// flags exported globally.
pub async fn run(ctx: &Ctx, args: &CompletionArgs) -> Result<()> {
    // The binary's own name rather than the clap command's, so a rebrand through
    // `dctl_meta` renames the completions with everything else.
    let binary = dctl_meta::BINARY_NAME;
    let script = render(args.shell, binary)?;
    let shell = args.shell.to_string();

    if ctx.out.format().is_json() {
        ctx.out.json(&CompletionScript {
            shell: &shell,
            binary,
            script: &script,
        })?;
    } else {
        // `write`, not `line`: the generators already end their output with a
        // newline, and a second one would show up as a stray blank line in a
        // file that gets sourced.
        ctx.out.write(&script)?;
    }

    if let Some(hint) = install_hint(&shell) {
        ctx.out.info(hint);
    }
    Ok(())
}

/// Generate the script for one shell.
///
/// Split out so it is testable without a [`Ctx`] and without stdout: the
/// property worth asserting — that every shell produces a non-empty script
/// naming the real subcommands — is about the generator, not about the sink.
fn render(shell: Shell, binary: &str) -> Result<String> {
    let mut command = Cli::command();
    let mut buffer: Vec<u8> = Vec::new();
    generate(shell, &mut command, binary, &mut buffer);

    String::from_utf8(buffer).map_err(|_| {
        CliError::fatal(format!(
            "the {shell} completion generator produced output that is not UTF-8"
        ))
        .with_hint(
            "This is a bug in DCTL or in clap_complete; nothing was written. \
             Please report it with the output of `dctl version`.",
        )
    })
}

/// Where the generated script has to go for this shell to notice it.
///
/// Looked up by name rather than matched, because `clap_complete`'s `Shell` is
/// `#[non_exhaustive]`: a shell added upstream then arrives without an install
/// note instead of failing to compile, which is a missing sentence rather than a
/// missing feature.
fn install_hint(shell: &str) -> Option<&'static str> {
    COMPLETION_INSTALL_HINTS
        .iter()
        .find(|(name, _)| *name == shell)
        .map(|&(_, hint)| hint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::GlobalArgs;
    use crate::constants::{
        COMPLETION_FIELD_BINARY, COMPLETION_FIELD_SCRIPT, COMPLETION_FIELD_SHELL,
        COMPLETION_SHELL_BASH, COMPLETION_SHELL_ELVISH, COMPLETION_SHELL_FISH,
        COMPLETION_SHELL_POWERSHELL, COMPLETION_SHELL_ZSH,
    };
    use clap::{Parser, ValueEnum};

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn ctx(args: &[&str]) -> Ctx {
        let parsed = Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied()));
        Ctx::new(parsed.globals)
    }

    fn script(shell: Shell) -> String {
        render(shell, dctl_meta::BINARY_NAME).expect("the generator produces UTF-8")
    }

    #[test]
    fn the_shell_argument_is_required_and_validated() {
        // A required positional: `dctl completion` with no shell must be a usage
        // error rather than a guess at the user's shell.
        assert!(Cli::try_parse_from(["dctl", "completion"]).is_err());
        assert!(Cli::try_parse_from(["dctl", "completion", "zsh"]).is_ok());
        assert!(Cli::try_parse_from(["dctl", "completion", "tcsh"]).is_err());
    }

    #[test]
    fn every_documented_shell_is_accepted_on_the_command_line() {
        for shell in [
            COMPLETION_SHELL_BASH,
            COMPLETION_SHELL_ZSH,
            COMPLETION_SHELL_FISH,
            COMPLETION_SHELL_POWERSHELL,
            COMPLETION_SHELL_ELVISH,
        ] {
            assert!(
                Cli::try_parse_from(["dctl", "completion", shell]).is_ok(),
                "{shell} was rejected"
            );
        }
    }

    #[test]
    fn the_shell_names_in_constants_are_the_ones_clap_complete_uses() {
        // The install-hint table is keyed by these words, so a rename upstream
        // must fail here rather than silently drop every hint.
        let spellings: Vec<String> = Shell::value_variants()
            .iter()
            .filter_map(ValueEnum::to_possible_value)
            .map(|value| value.get_name().to_string())
            .collect();
        for shell in [
            COMPLETION_SHELL_BASH,
            COMPLETION_SHELL_ZSH,
            COMPLETION_SHELL_FISH,
            COMPLETION_SHELL_POWERSHELL,
            COMPLETION_SHELL_ELVISH,
        ] {
            assert!(
                spellings.iter().any(|name| name == shell),
                "clap_complete no longer spells a shell '{shell}'"
            );
        }
    }

    #[test]
    fn every_shell_clap_complete_offers_has_an_install_hint() {
        // A generated script nobody knows where to put is not much use.
        for shell in Shell::value_variants() {
            let name = shell.to_string();
            assert!(
                install_hint(&name).is_some(),
                "'{name}' has no install hint"
            );
        }
        assert_eq!(install_hint("tcsh"), None);
    }

    #[test]
    fn completions_are_generated_from_the_real_command_tree() {
        // The property the whole module exists for: a subcommand or a global
        // flag added to `Cli` appears here with no edit to this file.
        for shell in Shell::value_variants() {
            let generated = script(*shell);
            assert!(!generated.is_empty(), "{shell} produced nothing");
            for verb in ["version", "completion", "about", "copy", "sync"] {
                assert!(
                    generated.contains(verb),
                    "{shell} completions omit the '{verb}' subcommand"
                );
            }
        }
    }

    #[test]
    fn the_script_completes_the_binary_under_its_own_name() {
        // The shell matches on the executable's name, so a rebrand through
        // dctl_meta has to reach the script.
        for shell in Shell::value_variants() {
            assert!(
                script(*shell).contains(dctl_meta::BINARY_NAME),
                "{shell} completions do not mention the binary"
            );
        }
    }

    #[test]
    fn the_script_offers_the_global_flags_too() {
        // Globals are flattened into every subcommand; if they were missing here
        // the completions would be technically valid and practically useless.
        let generated = script(Shell::Bash);
        for flag in ["--dry-run", "--json", "--verify"] {
            assert!(generated.contains(flag), "'{flag}' is not completed");
        }
    }

    #[test]
    fn the_json_shape_uses_the_documented_field_names() {
        let value = serde_json::to_value(CompletionScript {
            shell: COMPLETION_SHELL_ZSH,
            binary: dctl_meta::BINARY_NAME,
            script: "#compdef dctl\n",
        })
        .unwrap();
        for field in [
            COMPLETION_FIELD_SHELL,
            COMPLETION_FIELD_BINARY,
            COMPLETION_FIELD_SCRIPT,
        ] {
            assert!(value.get(field).is_some(), "'{field}' is missing");
        }
        assert_eq!(value[COMPLETION_FIELD_SHELL], COMPLETION_SHELL_ZSH);
    }

    #[tokio::test]
    async fn every_output_format_is_supported() {
        for format in ["text", "json", "json-lines"] {
            let ctx = ctx(&["--format", format]);
            assert!(
                run(&ctx, &CompletionArgs { shell: Shell::Zsh })
                    .await
                    .is_ok(),
                "{format} failed"
            );
        }
    }

    #[tokio::test]
    async fn dry_run_still_emits_the_script() {
        // There is nothing to withhold: the command writes to stdout and mutates
        // nothing. Suppressing it would break a redirect for anyone who has
        // --dry-run exported globally.
        let ctx = ctx(&["--dry-run"]);
        assert!(
            run(&ctx, &CompletionArgs { shell: Shell::Bash })
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn quiet_suppresses_the_note_but_never_the_script() {
        // The note lives on stderr and is silenced by --quiet; the script is
        // data on stdout and must survive.
        let ctx = ctx(&["--quiet"]);
        assert!(
            run(&ctx, &CompletionArgs { shell: Shell::Fish })
                .await
                .is_ok()
        );
    }
}
