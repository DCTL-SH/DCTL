# dctl delete

Delete objects in a path, honouring filters.

## Synopsis

`dctl delete` removes the objects under `REMOTE:PATH` that the filter flags
select, and leaves the directory structure standing. This is the rclone
distinction, kept exactly:

* **`delete` honours filters and keeps directories.**
  `dctl delete --include '*.tmp' vault:project` removes the scratch files and
  nothing else; every directory they lived in survives.
* **[`purge`](dctl_purge.md) ignores filters and removes the tree.**
  `dctl purge vault:project` removes the project.

Choosing the wrong one of those two is the most expensive mistake this command
family allows, so it is stated here, in `dctl purge --help`, and in the source
of both commands.

**Blast radius.** With no filter flags at all, `dctl delete vault:photos`
removes *every object* under `photos`, at every depth. There is no implicit
`--max-depth`, no implicit size bound, and no confirmation prompt unless you ask
for one with `--interactive`. The command is destructive by classification
(`Command::is_destructive`), which means it goes through the confirmation gate,
but a non-interactive run treats the fact that you typed the command as consent.
Reach for `--dry-run` first, and `--interactive` when you are not sure.

**`--rmdirs` is the one exception to "keeps directories".** After a filtered
delete has emptied a directory, an empty directory is usually litter rather than
information, so `--rmdirs` sweeps the ones the delete itself emptied. It never
removes the target root, and it never removes a directory that still holds an
object. To sweep empty directories independently of a delete, use
[`rmdirs`](dctl_rmdirs.md).

**Target resolution.** `REMOTE:PATH` is parsed strictly, and anything ambiguous
is refused rather than guessed at. A remote name must be at least two characters
— which is what makes `C:\data` unambiguously a Windows drive path on every
platform, not just on Windows — and UNC paths (`\\server\share`), bare local
paths (`/srv/data`), and any path containing a `..` component are all rejected
with exit code 1. The surviving path is cleaned and NFC-normalised, so
`vault:./photos//2024/`, `vault:photos\2024` and `vault:photos/2024` are one
target, and a macOS-decomposed `café` addresses the same objects as a
Linux-composed one.

**Filters are validated before the destructive gate**, deliberately. A
`--max-size` that does not parse is a typo, and a typo in a size limit on a
delete is exactly the mistake that removes more than intended: `--min-size 10M
--max-size 1M` is rejected as a usage error rather than silently matching
nothing and reporting success. `--max-depth -1` means unlimited and is the
default; note that clap reads a bare `-1` as a flag, so an explicit unlimited
must be written `--max-depth=-1`.

**Relationship to the verified-write contract.** A removal is not a write.
`--verify`, `--verify-samples`, `--checksum` and `--size-only` are transfer
dials and change nothing about what this command does; exit code 20
(`checksum_mismatch`) cannot be produced by a delete. What *is* shared with
`PLAN.md` §6 is the rule that DCTL never reports work it did not do — which is
why this command currently fails rather than exiting 0 (see below), and why a
`--dry-run` plan carries no counters.

### What runs today

**The removal itself is not implemented in this build.** Argument parsing,
target resolution, filter validation, the destructive gate and the `--dry-run`
plan all run now. The deletion does not: the vault exposes no filtered listing
and the command context carries no vault handle, so after printing its plan the
command exits **7** (`fatal_error`) with:

```
error: dctl delete is not implemented in this build
warning: The removal itself is not wired up yet, because it needs listing a vault
so the filters can select what to remove. Nothing was changed. Parsing, target
resolution, filter validation and the destructive gate all ran — re-run with
--dry-run to see the resolved request. See PLAN.md §11 for the phase that
delivers the rest.
```

This is on purpose. A command that quietly exited 0 having deleted nothing would
break `PLAN.md` §6's core promise more thoroughly than any crash. Nothing is
changed on any run, including a run with `--force`. The vault enumeration these
commands need arrives with the `PLAN.md` §11 **Phase 1 (B2 MVP)** work that also
delivers `ls`, the encrypted index and the B2 backend.

```
dctl delete REMOTE:PATH [flags]
```

## Examples

In this build every run that gets past validation ends with the engine refusal
shown above; those two stderr lines are omitted from the examples below except
where they are the point.

Preview what a filtered delete would cover. The plan goes to stdout; the
`[dry-run]` notice goes to stderr. Today the run then exits 7, so `--dry-run`
tells you how DCTL resolved your arguments, not which objects exist:

```console
$ dctl delete vault:photos/2024 --include '*.tmp' --rmdirs --dry-run
warning: [dry-run] would delete: vault:photos/2024
Command                   delete
Target                    vault:photos/2024
Mode                      dry-run
Include                   *.tmp
Remove empty directories  yes
```

The same plan as JSON, for a script that wants to record what was requested. The
document describes the *request* only — there is no `files_deleted` key, because
no listing was performed. `delete` always emits a `filters` key (it is the
command that honours them; the object is empty when no filter flag was given),
whereas the commands that ignore filters omit the key entirely. Individual
filter fields are omitted when unset, so "no size limit" and "a limit of zero"
are never confused:

```console
$ dctl delete b2prod:bucket/media --exclude 'keep/**' --max-size 10M --dry-run --json
{
  "command": "delete",
  "target": {
    "remote": "b2prod",
    "path": "bucket/media"
  },
  "dry_run": true,
  "filters": {
    "exclude": [
      "keep/**"
    ],
    "max_size": 10485760
  },
  "options": {
    "rmdirs": false
  },
  "status": "planned"
}
```

Remove every object under a path, with an interactive confirmation. The prompt
is written to stderr and only the exact word `yes` proceeds; anything else exits
25 (`cancelled`):

```console
$ dctl delete archive:projects/apollo --rmdirs --interactive
delete 'archive:projects/apollo'? Type 'yes' to confirm: no
error: cancelled: 'delete' on 'archive:projects/apollo' was not confirmed
warning: Type 'yes' at the prompt to confirm, or pass --force to approve
destructive actions without being asked.
```

If there is no terminal to prompt on — a cron job, a CI step — `--interactive`
fails with exit 1 rather than hanging or assuming consent.

A local path is refused, not guessed at. On Windows, a drive letter is always a
drive letter — a one-character prefix can never be a remote name:

```console
$ dctl delete C:\Users\me\photos
error: 'C:\Users\me\photos' is a local path, not a remote
warning: The removal commands operate on a remote, written REMOTE:PATH. Use your
operating system's own tools to remove local files.
$ echo $LASTEXITCODE
1
```

A crossed size bound is a usage error rather than a silent no-op, and it fails
before the destructive gate is ever reached:

```console
$ dctl delete vault:photos --min-size 10M --max-size 1M --force
error: --min-size (10485760) is larger than --max-size (1048576)
warning: No object can satisfy both bounds, so the command would remove nothing.
Swap them, or drop one.
```

## Options

```
  -h, --help    help for delete
      --rmdirs  Also remove directories left empty by the deletion
```

The positional argument is `<REMOTE:PATH>`: the objects to delete. Filters
apply.

## Options inherited from parent commands

Every global flag is accepted on this command; see
[../GLOBAL_FLAGS.md](../GLOBAL_FLAGS.md) for the full set. The ones that change
what `delete` does:

| Flag | Effect here |
|------|-------------|
| `--include`, `--exclude`, `--filter-from`, `--files-from` | Select which objects are removed. Recorded in the plan. |
| `--min-size`, `--max-size`, `--max-depth` | Narrow the selection. Validated before the destructive gate. |
| `-n`, `--dry-run` | Print the plan and change nothing. Overrides `--force`. |
| `--force` | Approve the destructive action without prompting. |
| `-i`, `--interactive` | Prompt before the deletion; requires typing `yes`. Conflicts with `--force`. |
| `--format`, `--json` | Render the `--dry-run` plan as an aligned table, one JSON document, or one JSON Lines record. |
| `--units` | Units used for the `Min size` / `Max size` rows of the text plan. |

`--verify`, `--verify-samples`, `--checksum` and `--size-only` are parsed but do
not apply: nothing is written or compared. `--immutable` is not yet consulted by
the removal family — do not rely on it to protect a vault from `dctl delete`.

## Exit codes

See [../EXIT_CODES.md](../EXIT_CODES.md) for the full contract.

| Code | Name | When |
|------|------|------|
| 1 | `usage` | Unparseable command line; a target that is a local path, a UNC path, a too-short remote name, empty, or contains `..`; an unparseable or crossed size bound; an invalid `--max-depth`; `--interactive` with no terminal to prompt on. |
| 7 | `fatal_error` | The removal engine is unavailable. **Every run that gets past validation ends here today**, including `--dry-run`. Nothing was changed. |
| 25 | `cancelled` | An interactive confirmation was declined, or the run was interrupted with Ctrl-C. |

Exit code 0 is not currently reachable for this command: it cannot report a
deletion it did not perform. When the engine lands, 6 (`partial_failure`) will
also become reachable for a run in which some objects failed to delete.

## See also

* [dctl deletefile](dctl_deletefile.md) — remove exactly one named object.
* [dctl purge](dctl_purge.md) — remove a path and everything under it, ignoring filters.
* [dctl rmdir](dctl_rmdir.md) — remove one empty directory.
* [dctl rmdirs](dctl_rmdirs.md) — sweep the empty directories under a path.
* [dctl cleanup](dctl_cleanup.md) — reclaim abandoned uploads, staging litter and old versions.
* [dctl ls](dctl_ls.md) — list what a filter set would match, before removing it.
* [dctl sync](dctl_sync.md) — make a destination match a source, which also deletes.
