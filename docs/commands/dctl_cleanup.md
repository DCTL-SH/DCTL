# dctl cleanup

Clean up a remote: abandoned uploads, stale temporary objects, old versions.

## Synopsis

The other five removal commands remove things you put there. `dctl cleanup`
removes the debris DCTL and the provider leave behind — none of it visible in a
listing, all of it billed for. Four classes, selectable individually with
`--class` because they carry very different risks:

* **`multipart` — abandoned multipart uploads.** `PLAN.md` §6 step 3 stages
  every upload through a multipart, and a crash between parts leaves one open.
  The parts already stored are charged for, and no listing shows them.
  Reclaiming them is nearly free of risk once they are old enough.
* **`staging` — stale staging objects.** A staged upload that never reached
  step 4 is left under a temporary key containing the marker `.tmp.`. This
  litter is a *consequence* of the verified-write contract, not a bug: DCTL
  writes to a temporary key first and only makes an object visible once its
  checksum matches, so an interrupted write is guaranteed to leave a partial
  object that was never committed and that nothing references.
* **`orphans` — content objects no index record refers to.** The store holds an
  object that nothing in the encrypted index points at, so no path can ever name
  it and no read will ever reach it. It is billable and invisible, which is why
  it is swept by default — but it is also what a *stale* index looks like from
  the outside, so run [`dctl index rebuild`](dctl_index.md) first if you have any
  reason to doubt the index you are sweeping against.
* **`versions` — superseded object versions.** On a versioned bucket every
  overwrite and every delete keeps the previous object alive and billable.
  **This is the dangerous class**: pruning versions destroys the only remaining
  copy of a file you overwrote, and undoes whatever safety net bucket versioning
  was giving you — including the ability to recover from a mistaken
  [`purge`](dctl_purge.md).

With no `--class` flag, **all four classes are swept**. A cleanup that swept
nothing by default would be a command that only looked like it worked.

**`--min-age` is the load-bearing flag, not a tuning knob.** Every one of those
classes is indistinguishable, from the outside, from work another DCTL process
is doing right now: an upload three seconds old is either abandoned or in
flight, and nothing in the object itself says which. The age is the *only* thing
standing between a cleanup and a concurrent run's live data. It defaults to
`24h` — comfortably longer than any single verified write — and lowering it on a
machine where other DCTL processes may be running risks deleting their staged
parts. Ages are written `24h`, `7d`, `90m`, `30s`, or as a bare number of
seconds; the suffixes are exactly the ones DCTL prints, so anything it shows you
can be typed back at it. `0` is legal and means no margin at all.

**Scope.** The positional argument is written `REMOTE:`. A path may be given and
scopes the sweep to the objects beneath it where the provider can list by
prefix; abandoned multipart uploads and object versions are provider-level
concepts, so treat a path as a hint rather than a hard boundary. **Filters are
ignored** — debris has no logical path for a pattern to match, so `--include`
and `--exclude` cannot narrow this command. Target parsing is the family's
strict one: at least two characters before the colon (so `C:\data` is a local
path and is refused), no UNC paths, no `..`.

**Reclaimed space is reported through the ordinary counters.** What was removed
is counted through the same `file_deleted` statistic and end-of-run summary rows
every other command uses; this command introduces no second vocabulary for the
same numbers.

### What runs today

**The sweep runs, and reports per class which ones a backend can actually
answer.** `staging` and `orphans` are reclaimed from the object store directly.
`multipart` and `versions` need provider APIs a backend may not expose — the
local backend does not — and those classes come back as `unsupported` with a
warning naming what could not be enumerated, rather than as silence that would
read as "nothing to reclaim":

```console
$ dctl cleanup vault: --force
Command      cleanup
Target       vault:
Mode         execute
Classes      multipart, staging, orphans, versions
Minimum age  1d00h
unsupported            -  multipart
unsupported            -  versions
warning: multipart: This backend exposes no way of listing a provider's in-progress multipart uploads. Nothing of that class was touched. [...]
warning: versions: This backend exposes no way of listing an object's superseded versions. Nothing of that class was touched. [...]
OK removed: 0 object(s), 0 B
$ echo $?
0
```

The run is exit **0** because it did everything that could be done and said
exactly what could not. Earlier revisions of this page said the whole sweep "is
not implemented in this build" and quoted an exit-7 refusal that no build now
produces — which is the difference that matters: `unsupported` is a per-class
fact about one backend, not a statement about the command.

The alternative — printing `reclaimed 0 bytes` from a sweep that never listed
anything — is exactly the lie `PLAN.md` §6 forbids. The provider APIs for
multipart listing arrive with the §11 **Phase 1 (B2 MVP)** backend work; the
`versions` class additionally depends on the snapshots/versioning work listed
under **Phase 4 (Hardening)**.

```
dctl cleanup REMOTE: [flags]
```

## Examples

Every example below runs in this build. Earlier revisions of this page prefaced
them with an engine refusal that no longer exists.

Preview a default cleanup of a whole remote: all four classes, the 24-hour
margin. The `Minimum age` row is printed the way DCTL prints every duration,
which is also a spelling `--min-age` accepts:

```console
$ dctl cleanup b2prod: --dry-run
warning: [dry-run] would clean up: b2prod:
Command      cleanup
Target       b2prod:
Mode         dry-run
Classes      multipart, staging, orphans, versions
Minimum age  1d00h
```

Sweep only the two cheap classes, leaving object versions alone — the safe
weekly job. `--class` is repeatable and the order you give is the order kept:

```console
$ dctl cleanup b2prod: --class multipart --class staging --min-age 7d --dry-run
warning: [dry-run] would clean up: b2prod:
Command      cleanup
Target       b2prod:
Mode         dry-run
Classes      multipart, staging
Minimum age  7d00h
```

The JSON plan quotes the age in seconds, so no consumer has to parse `24h`, and
names the staging marker so the plan explains what the `staging` class matches.
There is no `filters` key: debris cannot be filtered by path:

```console
$ dctl cleanup vault:photos/2024 --class staging --min-age 2h --dry-run --json
{
  "command": "cleanup",
  "target": {
    "remote": "vault",
    "path": "photos/2024"
  },
  "dry_run": true,
  "options": {
    "classes": [
      "staging"
    ],
    "min_age_secs": 7200,
    "staging_marker": ".tmp."
  },
  "status": "planned"
}
```

An unparseable age fails before the destructive gate, not after the first
deletion:

```console
$ dctl cleanup b2prod: --min-age banana --force
error: 'banana' is not a valid age
warning: Ages are written as 24h, 7d, 90m, or 30s.
$ echo $?
1
```

A local path is not a remote. On Windows, `C:` is a drive letter — a remote name
is at least two characters, which is what keeps the two apart on every platform:

```console
$ dctl cleanup C:\Users\me\vault --force
error: 'C:\Users\me\vault' is a local path, not a remote
warning: The removal commands operate on a remote, written REMOTE:PATH. Use your
operating system's own tools to remove local files.
```

An unknown class is rejected by the parser, with the valid ones listed:

```console
$ dctl cleanup b2prod: --class everything
error: invalid value 'everything' for '--class <CLASS>'
  [possible values: multipart, staging, versions]
```

## Options

```
  -h, --help           help for cleanup
      --class <CLASS>  Class of debris to reclaim. Repeatable; every class by
                       default [possible values: multipart, staging, versions]
      --min-age <AGE>  Leave anything younger than this alone — it may still be
                       in flight [default: 24h]
```

The positional argument is `<REMOTE:>`: the remote to sweep. A path scopes the
sweep to the objects beneath it, where the provider can list by prefix.

## Options inherited from parent commands

Every global flag is accepted; see [../GLOBAL_FLAGS.md](../GLOBAL_FLAGS.md). The
ones that matter here:

| Flag | Effect here |
|------|-------------|
| `-n`, `--dry-run` | Print the plan and change nothing. Overrides `--force`. |
| `--force` | Approve the destructive action without prompting. |
| `-i`, `--interactive` | Prompt before the sweep; requires typing `yes`. Conflicts with `--force`. |
| `--format`, `--json` | Render the `--dry-run` plan as a table, one JSON document, or one JSON Lines record. |
| `--quiet` | Suppress the `[dry-run]` notice and warnings. Errors are still printed. |

The filter flags are accepted and ignored: debris has no logical path to match
against. Unlike [`purge`](dctl_purge.md), this command does not warn about them.
`--immutable` is not yet consulted by the removal family.

## Exit codes

See [../EXIT_CODES.md](../EXIT_CODES.md) for the full contract.

| Code | Name | When |
|------|------|------|
| 1 | `usage` | Unparseable command line, including an unknown `--class`; an unparseable or overflowing `--min-age`; a local, UNC, too-short-remote, empty or `..`-containing target; `--interactive` with no terminal to prompt on. |
| 7 | `fatal_error` | The remote is not configured and is not a known provider. |
| 22 | `vault_locked` | Wrong password or recovery phrase, or a damaged envelope. |
| 23 | `index_error` | The encrypted index or its journal could not be read or written. |
| 25 | `cancelled` | An interactive confirmation was declined, or the run was interrupted with Ctrl-C. |

Exit **0** means the sweep ran. It covers a run in which some classes came back
`unsupported` because the backend cannot enumerate them — the command still did
everything it could and named what it could not, which is why that is a success
and not a failure. An earlier revision of this table said 0 "is not currently
reachable"; it is the ordinary outcome.

## See also

* [dctl delete](dctl_delete.md) — remove objects by filter and keep the directories.
* [dctl purge](dctl_purge.md) — remove a path and everything under it.
* [dctl rmdirs](dctl_rmdirs.md) — sweep the empty directories a cleanup leaves behind.
* [dctl deletefile](dctl_deletefile.md) — remove exactly one named object.
* [dctl about](dctl_about.md) — remote usage and quota, to see what a cleanup would reclaim.
* [dctl size](dctl_size.md) — total size and object count of what is actually stored.
