# dctl version

Show version and build information.

## Synopsis

`dctl version` prints which build this is and what produced it. It has the
strictest operational requirement in the whole CLI: it must work with **no
configuration, no network, no index and no vault**. It is the first thing
somebody runs when the tool is misbehaving, and a diagnostic that needs the
thing being diagnosed is not a diagnostic.

Nothing in this command opens a file, resolves a remote, spawns a process, reads
an environment variable at run time, or asks for a password. Every value it
prints was decided when the binary was compiled. `--config /nonexistent`,
`--index /nonexistent`, `--no-ask-password` and `--remote definitely-not-a-remote:`
all still produce a full report and exit 0; `dctl version` is one of the four
commands that never needs an unlocked vault, alongside `config`, `completion`
and `about`.

**`dctl version` is not `dctl --version`.** The global `-V` / `--version` flag
is clap's, propagated to every subcommand, and prints one line — `dctl 0.0.1` —
which is what a script that just wants to compare release numbers should parse.
The subcommand prints the ten-field report below, which is what belongs in a bug
report.

### The fields

| Field | Meaning | Source |
|-------|---------|--------|
| `version` | the release this binary is built from | `Cargo.toml`, always present |
| `binary` | the executable's own name, so a rebranded build identifies itself | compile-time constant |
| `git_hash` | the commit the build came from, abbreviated to 12 hex digits | `build.rs` |
| `rustc` | the compiler that produced the binary, as `rustc --version` reports it | `build.rs` |
| `target` | the target triple it was built for | `build.rs`, from cargo's own `TARGET` |
| `profile` | the cargo profile it was built under (`debug`, `release`) | `build.rs` |
| `os` | the operating system it is *running* on | compile-time `cfg` |
| `arch` | the CPU architecture it is running on | `std::env::consts::ARCH` |
| `features` | optional cargo features compiled in | `build.rs`; `none` in a default build |
| `debug_assertions` | whether the binary is checking its own invariants | compile-time `cfg` |

Four of these — the commit, the compiler, the target triple and the profile —
are not discoverable from inside a running process at all, so the crate carries
a build script that learns them at build time and stamps them in as compile-time
environment variables (`DCTL_BUILD_GIT_HASH`, `DCTL_BUILD_RUSTC`,
`DCTL_BUILD_TARGET`, `DCTL_BUILD_PROFILE`, `DCTL_BUILD_FEATURES`). A release
pipeline that already knows the commit from its own checkout metadata can export
any of those variables and have the value used verbatim, in preference to the
script's own probe.

**Absent is a real answer.** The build script never fails a build and never
guesses: no `git` on `PATH`, a source tarball with no repository, a sandboxed
builder that cannot execute `rustc` — all ordinary, and all produce a *missing*
value rather than a plausible-looking one. A missing value renders as `-` in
text and as `null` in JSON, and the key is never omitted. A wrong commit hash in
a bug report gets believed, and then costs somebody an afternoon.

`features` is the one field where an empty value is an *answer* rather than an
absence, so it renders as the word `none`, never as `-`. This crate declares no
optional features today; the field exists so the day one is added — a FUSE
mount, a provider behind a flag — it appears in every bug report without anyone
having to remember to put it there.

`profile` and `debug_assertions` are reported separately on purpose: a custom
profile can enable assertions in a release build, and a binary that is checking
its own invariants behaves and performs differently from one that is not.

### Output and formats

The report is the command's *result*, so it goes to **stdout** and commentary
goes to stderr. `--quiet` silences notes and warnings but never the report:
`dctl version -q` still answers. A closed pipe is a success —
`dctl version | head -1` exits 0.

`--json` emits one document with the same field names as the text row labels, so
a script that moves from `--format text` to `--format json` changes its parser
and nothing else. `--format json-lines` emits that document on a single line,
which is what a fleet inventory wants: one `dctl version` per host piped into
one stream.

### Status in this build

**`--check` is not implemented, and the missing piece is not code.** Asking
whether a newer release exists needs a release feed to ask, and the project
publishes none — no endpoint, no signed manifest, no channel. The gap is
therefore *outside the workspace*: `dctl-cli` is not waiting on `dctl-core` or
on any crate, and the refusal says so rather than naming one. Rather than
printing "you are up to date" — a claim about work that never happened, which
`PLAN.md` §6 forbids outright — the flag fails with exit code **7**.

The build report is still printed first, and deliberately so: `--check` is typed
by somebody whose machine is already misbehaving, and swallowing the one part of
the command that does work would leave them with nothing. The non-zero exit says
precisely what did not happen, and the hint says it in words: *the build
information above is complete and was printed*.

Everything else on this page works today. `PLAN.md` §11 runs to phase 5 and
**none of the five schedules an update check**, because a release feed has to
exist before a client can query one — so this is a refusal with no phase behind
it, and it says that rather than leaving a reader to search the roadmap for an
entry that is not there.

```
dctl version [flags]
```

## Examples

The report to paste into a bug report. `git_hash` is `-` here because this
binary was not built from a git checkout, which is an ordinary situation and is
shown as a gap rather than filled in with a guess:

```
dctl version
version           0.0.1
binary            dctl
git_hash          -
rustc             rustc 1.94.1 (e408947bf 2026-03-25)
target            aarch64-apple-darwin
profile           debug
os                macos
arch              aarch64
features          none
debug_assertions  true
```

Extract a single fact for a script. Unknown values are `null` rather than an
empty string or a missing key, so `jq` can tell "not built from a checkout" from
"older version of dctl":

```
dctl version --json | jq -r '.target'
aarch64-apple-darwin

dctl version --json | jq -r '.git_hash // "unknown"'
unknown
```

Inventory a fleet. One line per host, no buffering, no summary record to strip:

```
ssh host-a dctl version --format json-lines >> inventory.jsonl
ssh host-b dctl version --format json-lines >> inventory.jsonl
jq -s 'group_by(.version) | map({version: .[0].version, hosts: length})' inventory.jsonl
```

Prove the command needs nothing. Every one of these still prints the full report
and exits 0, which is the whole operational point — it answers on a machine
where the config is unreadable, the index is missing and the vault will not
unlock:

```
dctl version --config /nonexistent/dctl/config.toml --index /nonexistent/vault.redb --no-ask-password
```

On Windows, where a local path is involved only because you are saving the
report, the same JSON goes through PowerShell unchanged. `C:\path` is never
parsed by DCTL here — `version` takes no remote and no path, so there is no
drive-letter ambiguity to resolve:

```
dctl version --json | Out-File -Encoding utf8 C:\Users\me\Desktop\dctl-version.json
(Get-Content C:\Users\me\Desktop\dctl-version.json | ConvertFrom-Json).rustc
```

Ask for an update check and be told plainly that none happened. The report above
the error is real; only the lookup is missing:

```
dctl version --check
version           0.0.1
binary            dctl
git_hash          -
rustc             rustc 1.94.1 (e408947bf 2026-03-25)
target            aarch64-apple-darwin
profile           debug
os                macos
arch              aarch64
features          none
debug_assertions  true
error: dctl version --check: an update check against a release feed (missing
  outside the workspace: the project publishes no release endpoint to ask) is
  not implemented in this build
warning: The build information above is complete and was printed. Only the
  update lookup is missing: DCTL publishes no release feed to query, and no
  PLAN.md §11 phase adds one — inventing an 'up to date' answer would be worse
  than saying so. Compare the version above against however you obtained this
  build.
```

The single-line form, for a script that only wants the release number:

```
dctl --version
dctl 0.0.1
```

## Options

```
      --check   Also check whether a newer release is available
  -h, --help    help for version
```

`dctl version` takes no positional arguments. `dctl version vault:` is a usage
error rather than a silently ignored argument — somebody who typed it meant
[dctl about](dctl_about.md).

## Options inherited from parent commands

Every global flag is accepted; see [../GLOBAL_FLAGS.md](../GLOBAL_FLAGS.md) for
the full list. Almost none of them apply, because this command reads nothing and
writes nothing. The ones that do:

| Flag | Effect here |
|------|-------------|
| `--format`, `--json` | `text` (an aligned two-column table), `json` (one document), `json-lines` (the same document on one line). |
| `--color`, `--ascii` | Table styling only. |
| `--quiet` | Silences notes and warnings on stderr. The report on stdout is unaffected. |
| `-n`, `--dry-run` | No effect. The command mutates nothing, so there is nothing to withhold. |

The configuration, authentication, transfer, filtering and durability flags are
accepted and ignored — deliberately, so that a shell alias or an exported
`DCTL_*` variable can never stop `dctl version` from answering.

## Exit codes

| Code | Name | When |
|-----:|------|------|
| 0 | `success` | The report was printed. This is what a plain `dctl version` always returns. |
| 1 | `usage` | An unknown flag, or a positional argument. Reported by the parser before this command runs. |
| 2 | `uncategorised` | A stdout write failed for a reason other than a broken pipe. |
| 7 | `fatal_error` | `--check`: **every** invocation carrying that flag, after the report has been printed. |
| 25 | `cancelled` | Ctrl-C or SIGTERM. |

Codes 0–10 mirror rclone's taxonomy; 20+ are DCTL's own. See
[../EXIT_CODES.md](../EXIT_CODES.md) for the full contract.

## See also

* [dctl about](dctl_about.md) — the same kind of question, asked about a remote
  rather than about the binary.
* [dctl completion](dctl_completion.md) — the other command that needs no
  configuration, no vault and no network.
* [dctl config](dctl_config.md) — what this build is configured to talk to.
