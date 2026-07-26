# dctl completion

Generate a shell completion script.

## Synopsis

`dctl completion SHELL` writes a completion script for one shell to standard
output. The script is generated from the *same* `clap::Command` the parser is
built from — not from a hand-maintained list — so it cannot drift. A subcommand,
a global flag, a renamed value or a hidden alias added to the command tree
appears in the completions with no edit to any completion code, and a flag the
binary rejects can never be offered.

That property is the whole reason the command exists. A shell that suggests
`--verify strct` because somebody forgot to update a list is worse than a shell
that suggests nothing: the user types what they were offered, the command fails,
and the tool looks broken.

**The script goes to stdout and nothing else does.** So both of these work:

```
dctl completion zsh > "${fpath[1]}/_dctl"
dctl completion bash | source /dev/stdin
```

The install line is a *note about* the result rather than part of it, so it goes
to stderr — and, like every other note, only at `-v` and above. A plain
`dctl completion bash` emits the script and not one byte more, which is what a
redirect needs.

**Nothing here needs anything.** No config file, no vault, no password, no
network, no index. Generating a script is pure computation over the parser's own
metadata, which is why it is safe to call from a shell's startup file:
`dctl completion` is one of the four commands `Command::requires_vault`
excludes, alongside `config`, `version` and `about`. A machine with no
credentials exported and no `config.toml` on disk generates exactly the same
script as a fully configured one.

### Shells

The accepted values come from `clap_complete`'s own `Shell` enum rather than a
list written into DCTL, so a shell it learns to generate for becomes available
without an edit and one it drops cannot be offered by mistake. Today:

| `SHELL` | Where the script has to go |
|---------|----------------------------|
| `bash` | `/etc/bash_completion.d/dctl`, or `~/.local/share/bash-completion/completions/dctl` |
| `zsh` | `"${fpath[1]}/_dctl"` — the file must be on `$fpath` **before** `compinit` runs |
| `fish` | `~/.config/fish/completions/dctl.fish` |
| `powershell` | appended to `$PROFILE` |
| `elvish` | appended to `~/.config/elvish/rc.elv` |

These are the conventional locations for each shell rather than DCTL-specific
ones, so the generated file composes with whatever completion setup is already
there. Anything else — `tcsh`, `nushell` — is rejected by the parser as a usage
error with the list of accepted values, before the command body runs.

The script completes the binary under the name `dctl`, taken from the crate's
own identity constant rather than from clap's command name, so a rebuild under a
different product name renames the completions with everything else. If you have
renamed or symlinked the executable, edit the name in the generated script or
the shell will not match it.

### Formats

Text emits the raw script, newline-terminated exactly as the generator produced
it — no extra trailing blank line, which would show up as a stray line in a file
that gets sourced.

`--json` wraps it as `{"shell", "binary", "script"}`, which is what a
configuration-management tool wants: it can compare the `script` field against
the file already on disk and write only when it differs, without shelling out
twice. `--format json-lines` puts that document on a single line.

### Status in this build

**`dctl completion` is complete.** It generates real scripts for every shell
`clap_complete` supports, today, with no engine work outstanding. It is one of
the few commands on which nothing is deferred.

Two details follow from that:

* **`--dry-run` still emits the script.** There is nothing to withhold — the
  command writes to stdout and mutates nothing — and suppressing it would break
  `dctl completion zsh > file` for anyone who has `DCTL` flags exported
  globally.
* **`--quiet` suppresses the install note, never the script.** The note is
  commentary on stderr; the script is data on stdout.

```
dctl completion <SHELL> [flags]
```

## Examples

Install for zsh, permanently. The file must land on `$fpath` before `compinit`
runs, which is what the note on stderr reminds you of when you ask for it with
`-v`:

```
dctl completion zsh > "${fpath[1]}/_dctl"
dctl completion zsh -v > "${fpath[1]}/_dctl"
install with: dctl completion zsh > "${fpath[1]}/_dctl" — the file must be on $fpath before compinit runs
```

Try completions in the current bash session without installing anything, then
add the same line to `~/.bashrc` once you are happy with it. This is why the
command must never need a config file or a password: a startup file cannot
prompt:

```
dctl completion bash | source /dev/stdin
```

Install for fish, where the location is fixed and the file is picked up on the
next shell start:

```
dctl completion fish > ~/.config/fish/completions/dctl.fish
```

On Windows, generate for PowerShell and write it to a real path. Appending to
`$PROFILE` is the one-liner; writing to an explicit `C:\...` path and dot-sourcing
it keeps the profile short and makes the file easy to replace on upgrade:

```
dctl completion powershell >> $PROFILE

dctl completion powershell | Out-File -Encoding utf8 C:\Users\me\Documents\PowerShell\dctl-completion.ps1
Add-Content $PROFILE '. C:\Users\me\Documents\PowerShell\dctl-completion.ps1'
```

Manage the completion file from configuration management, and rewrite it only
when it has actually changed. `--json` carries the script *and* the shell and
binary it was generated for in one document, so a run can record what it wrote
without shelling out a second time to find out:

```
dctl completion bash --json | jq -r '.shell, .binary'
bash
dctl

dctl completion bash --json | jq -r '.script' > /tmp/dctl.bash
cmp -s /tmp/dctl.bash /etc/bash_completion.d/dctl || install -m 644 /tmp/dctl.bash /etc/bash_completion.d/dctl
```

Check that the completions really do track the command tree — a global flag
added to the parser appears here with no edit to any completion code:

```
dctl completion bash | grep -c -- '--verify'
153

dctl completion zsh | head -1
#compdef dctl
```

Ask for a shell nobody generates for. The parser rejects it with the list of
accepted values and exit 1; nothing is written to stdout, so a redirect does not
create a truncated file's worth of nonsense:

```
dctl completion tcsh
error: invalid value 'tcsh' for '<SHELL>'
  [possible values: bash, elvish, fish, powershell, zsh]

  tip: a similar value exists: 'zsh'
```

## Options

```
  -h, --help   help for completion
```

The positional argument is `<SHELL>` and it is **required** — one of `bash`,
`elvish`, `fish`, `powershell`, `zsh`. `dctl completion` with no shell is a
usage error rather than a guess at `$SHELL`: a wrong guess writes a script the
shell silently ignores, and the user spends half an hour wondering why tab
completion does nothing. This command has no options of its own.

## Options inherited from parent commands

Every global flag is accepted; see [../GLOBAL_FLAGS.md](../GLOBAL_FLAGS.md) for
the full list. The ones that matter here:

| Flag | Effect here |
|------|-------------|
| `--format`, `--json` | `text` (the raw script), `json` (`{shell, binary, script}`), `json-lines` (the same document on one line). |
| `-v`, `--verbose` | Shows the install hint for the chosen shell on stderr. Without it, stderr stays empty. |
| `--quiet` | Silences the install hint. The script on stdout is unaffected. |
| `-n`, `--dry-run` | No effect: the script is still written. Nothing is mutated, so there is nothing to withhold. |
| `--color`, `--ascii` | Styling of the note only; the script itself is never colourised. |

The configuration, authentication, transfer, filtering and durability flags are
accepted and ignored. That is deliberate: an exported `DCTL_PASSWORD_COMMAND` or
a broken `--config` path must never stop a shell's startup file from getting its
completions.

## Exit codes

| Code | Name | When |
|-----:|------|------|
| 0 | `success` | The script was written. This is the normal outcome, on every shell. |
| 1 | `usage` | No `SHELL` argument, or a shell nobody generates for. Reported by the parser before this command runs. |
| 2 | `uncategorised` | A stdout write failed for a reason other than a broken pipe (a full disk on a redirect, for example). |
| 7 | `fatal_error` | The generator produced output that is not UTF-8. This should be impossible; nothing is written, and the message asks for a bug report with the output of `dctl version`. |
| 25 | `cancelled` | Ctrl-C or SIGTERM. |

Codes 0–10 mirror rclone's taxonomy; 20+ are DCTL's own. See
[../EXIT_CODES.md](../EXIT_CODES.md) for the full contract.

## See also

* [dctl version](dctl_version.md) — the other command that needs no
  configuration, no vault and no network; its output is what a completion bug
  report should carry.
* [dctl about](dctl_about.md) — what a configured remote resolves to, once the
  completions are helping you type its name.
* [dctl config](dctl_config.md) — the remotes whose names the shell cannot
  complete: they live in a config file, not in the command tree.
