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
  step 4 is left under a key whose last component begins with `.dctl-staging.`.
  This litter is a *consequence* of the verified-write contract, not a bug: DCTL
  writes to a temporary name first and `rename`s onto the real one only once its
  checksum matches, so an interrupted write is guaranteed to leave a partial
  object that was never committed and that nothing references.

  **The marker is a leading-dot prefix on the name, not a substring anywhere in
  the key.** This page used to say `.tmp.`, which the code stopped using because
  a substring test matched real files — `report.tmp.2024.csv`,
  `db.tmp.2024-07-27.sql`, Office's own `~$report.tmp.docx` — and this command
  deletes what it matches.
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
parts.

It is the **global** `--min-age`, documented in
[GLOBAL_FLAGS.md](../GLOBAL_FLAGS.md#sizes-and-ages), not a flag of this command.
That is a correction: `cleanup` used to declare its own `--min-age` with its own
parser behind it, in which `1M` meant one *minute* while the same string means
one *month* to rclone and to every other age DCTL reads. Two dialects for one
flag name inside one binary is how a sweep comes to leave a margin thirty times
smaller than the operator intended, against a class of object that is
indistinguishable from another process's live work. There is one parser now:
`ms`, `s`, `m`, `h`, `d`, `w`, `M` (30 days), `y` (365 days), or a bare number of
seconds. `off` and `0` are legal and mean no margin at all, which the plan prints
as `0s` above the destructive gate rather than leaving you to infer.

The 24-hour default is applied by this command rather than by the flag, because
an absent `--min-age` on `copy` means "no age filter" while an absent `--min-age`
here has to mean the safety margin.

**Scope.** The positional argument is written `REMOTE:`. A path may be given and
scopes the sweep to the objects beneath it where the provider can list by
prefix; abandoned multipart uploads and object versions are provider-level
concepts, so treat a path as a hint rather than a hard boundary. **Filters are
ignored** — debris has no logical path for a pattern to match, so `--include`
and `--exclude` cannot narrow this command. Target parsing is the family's
strict one: the same rule every other verb applies (a drive letter is a drive on
a platform that has drives, and a remote everywhere else), no UNC paths, no `..`.

**Reclaimed space is reported through the ordinary counters.** What was removed
is counted through the same `file_deleted` statistic and end-of-run summary rows
every other command uses; this command introduces no second vocabulary for the
same numbers.

### What runs today

**The sweep runs, and reports per class which ones a backend can actually
answer.** There are three answers, not two, and the difference between them is
the point of the page:

| Answer | Means | Exit |
|--------|-------|------|
| a count | The class was enumerated and this is what was reclaimed. | 0 |
| `not-staged` | The class was asked about and this backend has none of it. | 0 |
| `unsupported` | This backend cannot enumerate the class at all. | 0, or **6** if you named that class with `--class` |

`orphans` is reclaimed from the index and the store together. `staging` is
enumerated **on purpose**, through a storage call that exists only for it:
`local:` and `sftp:` stage every write beside its object and rename onto the
final name, so a killed `copy` leaves a full-size staging file and this is the
command that reclaims it. Earlier revisions of this page did not say so, and
earlier builds could not: discovery went through the ordinary object listing,
which omits staging files by design, so the sweep searched a list its quarry had
already been removed from and reported `OK removed: 0 object(s), 0 B` over a
store holding megabytes of debris.

`b2`, `s3` and `r2` upload straight to the object's final key, so nothing is ever
written under a temporary one and nothing can be abandoned there. They answer
`not-staged` with that sentence rather than a bare zero — a true number that
reads exactly like the false all-clear above. What an interrupted **large**
upload leaves on those providers is an unfinished multipart upload, which is
billed, which no listing shows, and which is the `multipart` class below.

`multipart` and `versions` need provider APIs no backend here exposes, and those
classes come back as `unsupported` with a warning naming what could not be
enumerated, rather than as silence that would read as "nothing to reclaim":

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

A B2 remote whose 200 MiB upload was killed part-way prints all three answers at
once, which is what the distinction is for: `multipart` unsupported (the class
that really did leak there, named), `staging` not-staged (the class that cannot
leak there, and why), `versions` unsupported.

The alternative — printing `reclaimed 0 bytes` from a sweep that never listed
anything — is exactly the lie `PLAN.md` §6 forbids. The provider APIs for
multipart listing arrive with the §11 **Phase 1 (B2 MVP)** backend work; the
`versions` class additionally depends on the snapshots/versioning work listed
under **Phase 4 (Hardening)**.

**`--min-age` protects a run that is happening right now.** Now that the sweep
can see staging files it can also see the one a *concurrent* backup is part way
through writing, so `--min-age 0s` over a store something else is writing into
will delete that file. Nothing is corrupted by it — the writer's rename fails and
the object is simply not committed, exactly as if the run had been interrupted,
and the next run stores it — but the default of a day exists so that a nightly
`cleanup` and a nightly `backup` that overlap do not fight. Use `0s` when you
know nothing else is writing.

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
    "staging_marker": ".dctl-staging."
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

A local path is not a remote. On Windows `C:` is a drive letter and is refused
here as a local path; off Windows the same argument names the remote `C`, which,
unconfigured, fails by name:

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
  [possible values: multipart, staging, orphans, versions]
```

## Options

```
  -h, --help           help for cleanup
      --class <CLASS>  Class of debris to reclaim. Repeatable; every class by
                       default [possible values: multipart, staging, orphans,
                       versions]
```

`--min-age` is inherited from the global Filtering group and defaults to `24h`
for this command; see the note above.

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
| 1 | `usage` | Unparseable command line, including an unknown `--class`; an unparseable `--min-age`; a local, UNC, malformed-remote, empty or `..`-containing target; `--interactive` with no terminal to prompt on. |
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
