# dctl backup

Back up a local tree into a vault.

## Synopsis

`dctl backup` stores a local directory (or a single file) in a vault. It is
`copy` with two additions that only make sense for an archive: it can mark the
run as a **snapshot**, and it runs the **name pre-flight** over everything it is
about to store (`PLAN.md` §13.6).

The second addition is the point of the command. A filename that is legal on
this machine and illegal on the machine that will one day restore it —
`report:final.pdf`, `aux.txt`, `data.`, a path past Windows' `MAX_PATH`, or
`README.md` sitting beside `readme.md` — is a defect introduced at *backup* time
and discovered years later, at the worst possible moment, 3.9 TB into a 4 TB
restore. Reporting it while the operator is still standing there, able to rename
the file, is most of the value a backup command can add over a copy.

**Those findings are warnings, not refusals.** The bytes are perfectly storable,
and refusing to back up a legal local file because Windows dislikes its name
would lose data today to protect a machine that may never exist. Each finding is
printed with a `portability` severity and the run continues. Two things change
that:

* `--strict-names` turns any finding into a refusal (exit **7**). Use it when the
  restore target is known to be Windows, or when the archive is meant to be
  portable by policy.
* A **control character** in a name is fatal regardless. No filesystem anywhere
  accepts one, so storing it would guarantee an object nobody can ever restore.

**`backup` is additive.** It stores what it finds; it never deletes anything from
the vault and never removes the local source. Making a destination match a source
— which means deleting from the destination — is [`dctl sync`](dctl_sync.md), and
that separation is deliberate: the command you point at an archive every night
must not be the command that can empty it.

**The verified-write contract still governs every byte** (`PLAN.md` §6). When the
engine lands, nothing is reported as stored until its bytes have been
checksum-verified at the destination and durably committed to the index; a
mismatch hard-aborts, commits nothing and exits **20**. `--verify` selects the
strength (`checksum`, `sample`, `strict`); it is a global flag rather than a flag
of this command because verification strength is also a per-remote setting in
`config.toml`, and two spellings of one setting is one too many.

**The tree walk is written to survive a bad tree.** A directory it cannot read, a
filename that is not valid UTF-8, a file that vanished between the listing and
the `stat`, a dangling symlink — each is recorded as a problem and the walk
continues. A backup that aborts on the first unreadable directory backs up
nothing; one that reports four problems and 200 000 files gives its operator
something to act on. The problems are never swallowed: each counts as an error,
so the run exits **6** (`partial_failure`) even though it produced a plan. Entries
are sorted, so two scans of an unchanged tree produce byte-identical output and
plans can be diffed between runs.

Symbolic links are **skipped** by default and reported. `--follow-symlinks`
stores what they point at instead, and the walk then remembers the canonical path
of every directory it enters — a symlink pointing at its own ancestor is the
oldest way to make a backup tool run until the disk fills.

**Filters.** `--min-size`, `--max-size`, `--max-depth` and `--files-from` are
honoured (`--max-depth 1` means the top level only, matching rclone). Glob
filters — `--include`, `--exclude`, `--filter-from` — are **refused** with exit 7
rather than ignored: an `--exclude '*.iso'` that was quietly dropped would upload
the archive the rule existed to keep out, and nobody would find out until the
bill arrived. Crossed size bounds (`--min-size 10G --max-size 1M`) are a usage
error for the same reason — no file can satisfy both, so the run would report a
clean success having stored nothing.

**Paths.** The vault side is written `REMOTE:PATH`; the local side is an ordinary
path. Following rclone's rule, `C:\data`, `d:/data` and `\\server\share` are
treated as **local on every platform**, so a script written on Windows behaves
identically on a Linux build agent. Remote names are at least two characters,
which is exactly what makes the drive-letter rule unambiguous — `C:\vault` as the
`REMOTE` operand is rejected as a usage error rather than resolving to a remote
called `C`. Logical paths inside the vault are canonicalised (`/`-separated, NFC,
no `.` or `..`), so a name typed on a Mac and a name typed on Linux address the
same object.

**Snapshots.** `--snapshot` marks the run as one restorable point in time;
`--snapshot-name` names it, and requires `--snapshot` (otherwise
`--snapshot-name nightly` would silently do nothing). Without a name, one is
generated as `snap-<unix seconds>` — it sorts chronologically as plain text and
is unambiguous in every timezone, unlike a local-time spelling, which repeats
itself for an hour every autumn. A name is ASCII letters, digits and `-`, `_`,
`.`, at most 64 characters, and may not start with a dot: the intersection of
what a path component, an object key and a URL segment all tolerate unescaped,
because a name that needs escaping in three places will one day be escaped
differently in two of them.

### Status in this build

**A real `dctl backup` run is not implemented.** Everything up to the first byte
is: argument and snapshot validation, the tree walk, the filters DCTL can
evaluate exactly, the name pre-flight, and the full plan in all three output
formats. What does not exist is the verified-write engine (`PLAN.md` §6), so a
run without `--dry-run` ends in
`dctl backup is not implemented in this build` at exit **7**. It never prints a
success message for work that did not happen.

That check fires **before** the tree is walked, deliberately. Scanning four
million files only to then report that the transfer cannot happen would waste an
hour to tell the operator something a millisecond of argument checking already
knew. `--dry-run` is the flag that asks for the scan, and the error's hint says
so.

`--snapshot` is validated and recorded in the plan document, but snapshots are
not yet stored or selectable —
[`dctl restore --snapshot`](dctl_restore.md) refuses rather than approximating.
Snapshots and versioning are **Phase 4 (Hardening)** in `PLAN.md` §11; the
verified-write engine that turns a plan into stored bytes is Phase 0/1.

```
dctl backup LOCAL REMOTE:PATH [flags]
```

## Examples

Plan a nightly archive and read what it would do. `--dry-run` is the flag that
performs the scan and the pre-flight; nothing is written, and the counters
describe what *would* move.

```
dctl backup /srv/photos vault:photos --dry-run
Severity     Path                      Problem
-----------  ------------------------  ----------------------------------------------------------------------------
portability  reports/aux.txt           'aux.txt': 'AUX' is a reserved Windows device name
portability  reports/report:final.pdf  'report:final.pdf': contains ':', which Windows does not allow in a filename
Action  Size    Path
------  ------  --------------------------------------------------------------
store   28 MiB  /srv/photos/2024/IMG_4417.CR3 -> vault:photos/2024/IMG_4417.CR3
store    2 B    /srv/photos/reports/aux.txt -> vault:photos/reports/aux.txt
warning: 2 name(s) may not restore on every platform; see the report above
```

Neither name stops the run — the bytes are storable and DCTL stores exactly what
it was given, never a silently mangled version. But `aux.txt` will not restore on
Windows and `report:final.pdf` will not either, and now is when that is cheap to
fix.

Refuse to store anything that would not come back everywhere. This is the setting
for an archive whose restore target is unknown, or known to be Windows:

```
dctl backup /srv/photos vault:photos --strict-names --dry-run
error: 2 name(s) would not restore on every supported platform
  hint: Rename them, or drop --strict-names to store them with a warning.
```

Back up a Windows tree into a Backblaze B2 vault, as one named snapshot. The
local side is an ordinary Windows path, drive letter and all; the vault side must
be `REMOTE:PATH`, and a remote name of at least two characters is what keeps the
two unambiguous:

```
dctl backup C:\Users\jo\Documents b2prod:bucket/laptop --snapshot --snapshot-name pre-upgrade
```

Getting that backwards is caught before anything is read:

```
dctl backup /srv/photos C:\vault
error: 'C:\vault' is a local path, not a vault
  hint: A recovery has one local side and one vault side. The vault is written
  REMOTE:PATH; the local side is an ordinary path.
```

Archive only the large originals from the top two levels, and feed the plan to a
script. `--min-size` and `--max-depth` are honoured exactly; the JSON document
carries the pre-flight findings and the planned entries together.

```
dctl backup /mnt/raw coldvault:archive/2026 --min-size 20M --max-depth 2 --dry-run --json
```

Back up exactly the files a manifest names — nothing else, no globbing involved:

```
dctl backup /srv/photos vault:photos --files-from /etc/dctl/nightly.txt --dry-run
```

Ask for a glob and be told no, rather than being ignored:

```
dctl backup /srv/photos vault:photos --exclude '*.iso' --dry-run
error: glob filtering (--include/--exclude/--filter-from) is not implemented in this build
  hint: A filter that was silently ignored would make `sync` delete the files it
  was written to protect, so DCTL refuses instead. Narrow the transfer with an
  explicit SOURCE, or with --min-size/--max-size/--max-depth, which are honoured.
```

A tree with an unreadable directory in it. The walk does not stop; the problem is
reported, the rest of the plan is produced, and the exit code says the run was not
clean:

```
dctl backup /srv/photos vault:photos --dry-run
warning: /srv/photos/private: Permission denied (os error 13)
...
      Errors: 1
warning: completed with errors
$ echo $?
6
```

## Options

```
  -h, --help                 help for backup
      --snapshot             Record this run as a snapshot, so it can be restored as one point in time
      --snapshot-name <NAME> Name the snapshot. Without this, one is generated from the start time
      --follow-symlinks      Store what symbolic links point at, rather than skipping them
      --strict-names         Refuse to store any name that could not be restored on every supported platform
```

Both operands are required: `<LOCAL>` is the local directory or file to back up,
`<REMOTE>` is the vault to store it in, written `REMOTE:PATH`. A bare `vault:`
means the vault root. `--snapshot-name` requires `--snapshot`.

## Options inherited from parent commands

Every global flag is accepted on `dctl backup`, before or after the subcommand.
The ones that change what this command does are `--dry-run` (which is what makes
it do anything at all in this build), `--verify`/`--verify-samples` (the
strength of the post-write verification), `--min-size`/`--max-size`/
`--max-depth`/`--files-from` (honoured) versus `--include`/`--exclude`/
`--filter-from` (refused), `--format`/`--json`/`--units`/`--quiet`/`-v`
(output), and `--transfers`/`--checkers`/`--bwlimit`/`--retries`/`--max-transfer`
(how the writes will be paced once the engine exists). See
[../GLOBAL_FLAGS.md](../GLOBAL_FLAGS.md) for the full list.

Output obeys the stdout/stderr split: the pre-flight findings and the planned
entries are **data** and go to stdout; counts, notices and warnings are commentary
and go to stderr. `--json` emits one document carrying `operation`, `source`,
`destination`, `snapshot`, `dry_run`, `files`, `bytes`, a `preflight` array and an
`entries` array. `--format json-lines` emits one self-describing record per line
(`{"record":"preflight",…}`, `{"record":"entry",…}`, and a closing
`{"record":"summary",…}`), so a plan over ten million files streams instead of
being buffered. An **absent** `entries` field means "not computed"; an empty one
means "computed, and there is nothing to store" — collapsing the two would let a
consumer read "nothing to back up" from a run that never got as far as looking.

## Exit codes

| Code | Name | When |
|-----:|------|------|
| 0 | `success` | A `--dry-run` completed with no scan problems. Not reachable for a real transfer in this build. |
| 1 | `usage` | A local path where the vault operand belongs (`C:\vault`, `/srv/out`), a missing operand, `--snapshot-name` without `--snapshot`, an invalid snapshot name, an unparseable or crossed `--min-size`/`--max-size`, a negative `--max-depth`, or a `--files-from` line containing `..`. |
| 2 | `uncategorised` | An I/O error, other than "not found" or "permission denied", reading a `--files-from` list. |
| 3 | `dir_not_found` | The `<LOCAL>` source does not exist. Reported before the engine check, so a typo is never mistaken for a missing feature. |
| 4 | `file_not_found` | A `--files-from` list does not exist. |
| 6 | `partial_failure` | The run produced a plan, but the walk recorded at least one problem: an unreadable directory, a name that is not valid UTF-8, a vanished file, or a dangling symlink. |
| 7 | `fatal_error` | Returned by every real (non-`--dry-run`) invocation in this build (`not implemented`). Also: a glob filter was requested, a name contains a control character no filesystem accepts, or `--strict-names` was given and the pre-flight found anything. |
| 20 | `checksum_mismatch` | A verified write refused to commit. Nothing was stored and the local source was not touched. Needs the engine described under *Status in this build*. |
| 25 | `cancelled` | Ctrl-C or SIGTERM. Nothing in flight was reported as complete. |

In this build only **1**, **2**, **3**, **4**, **6**, **7** and **25** are
reachable. Codes 0–10 mirror rclone's taxonomy; 20+ are DCTL's own. See
[../EXIT_CODES.md](../EXIT_CODES.md) for the full contract.

## See also

* [dctl restore](dctl_restore.md) — the other half of the pair, and the only
  thing that proves a backup was one.
* [dctl copy](dctl_copy.md) — the same store operation without the snapshot
  marker or the name pre-flight.
* [dctl sync](dctl_sync.md) — make a destination match a source. **Deletes from
  the destination**; `backup` never does.
* [dctl verify](dctl_verify.md) — confirm afterwards that what was stored still
  matches its recorded hashes.
* [dctl audit](dctl_audit.md) — the tamper-evident record of what this command
  wrote.
* [dctl check](dctl_check.md) — compare a local tree against a vault without
  transferring anything.
