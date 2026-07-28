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
is refused rather than guessed at. `C:\data` is a Windows drive path where drives
exist and the remote `C` elsewhere, which is rclone's rule and the same rule the
transfer verbs apply — a removal that refused a remote `copy` had just written to
would be the worst possible disagreement. UNC paths (`\\server\share`), bare local
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

**The removal runs.** The filtered listing this command needs shipped with the
rest of the listing family, and `delete` uses it: objects are selected, removed
and counted, and the plan and the execution report the same paths.

```
$ dctl delete vault:r1 --include '*.txt' --force
Command                   delete
Target                    vault:r1
Mode                      execute
Include                   *.txt
Remove empty directories  no
removed              6 B  r1/a.txt
removed             12 B  r1/b.txt
removed              8 B  r1/sub/c.txt
OK removed: 3 object(s), 26 B
```

Earlier revisions of this page said the deletion "is not implemented in this
build" and quoted an exit-7 refusal. No build now produces it. A page that
understates a **destructive** command is not the harmless direction of drift: a
reader who believes `--force` cannot remove anything is the reader most likely to
run it against the wrong path to see what the plan says.

```
dctl delete REMOTE:PATH [flags]
```

## Examples

Every example below runs in this build and removes what it names. Earlier
revisions of this page prefaced them with an engine refusal that no longer
exists.

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
| 0 | `success` | The selected objects were removed — including when the filters selected none, which is a true answer to the question that was asked rather than a failure. |
| 1 | `usage` | Unparseable command line; a target that is a local path, a UNC path, a too-short remote name, empty, or contains `..`; an unparseable or crossed size bound; an invalid `--max-depth`; `--interactive` with no terminal to prompt on. |
| 7 | `fatal_error` | The remote is not configured and is not a known provider. |
| 22 | `vault_locked` | Wrong password or recovery phrase, or a damaged envelope. |
| 23 | `index_error` | The encrypted index or its journal could not be read or written. |
| 25 | `cancelled` | An interactive confirmation was declined, or the run was interrupted with Ctrl-C. |

An earlier revision of this table said exit 0 "is not currently reachable" and
that **every** run past validation ended at 7 with the engine unavailable.
Neither is true: the removal runs, and a `--dry-run` exits 0 as well.

Note the one place `delete` differs from its neighbours: a target that holds
nothing exits **0**, not 3. `delete` is filter-driven — it asks "remove whatever
matches under here" — and an empty match is a real answer. [`purge`](dctl_purge.md)
and [`rmdir`](dctl_rmdir.md) name a specific directory and so exit **3** when it
is not there, and [`deletefile`](dctl_deletefile.md) names one object and exits
**4**. Three codes for three different questions, which is why a script must not
treat them as one.

## See also

* [dctl deletefile](dctl_deletefile.md) — remove exactly one named object.
* [dctl purge](dctl_purge.md) — remove a path and everything under it, ignoring filters.
* [dctl rmdir](dctl_rmdir.md) — remove one empty directory.
* [dctl rmdirs](dctl_rmdirs.md) — sweep the empty directories under a path.
* [dctl cleanup](dctl_cleanup.md) — reclaim abandoned uploads, staging litter and old versions.
* [dctl ls](dctl_ls.md) — list what a filter set would match, before removing it.
* [dctl sync](dctl_sync.md) — make a destination match a source, which also deletes.
