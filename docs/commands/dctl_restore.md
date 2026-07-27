# dctl restore

Restore a vault, or part of one, to a local tree.

## Synopsis

`dctl restore` writes a vault, or a subtree of one, back onto local disk. It is
the command the whole tool exists for: a backup you never restored is not a
backup (`PLAN.md` §13.6), and every other guarantee DCTL makes is only as good as
this one working on the day it is needed.

**The way a restore fails is almost never the network. It is a filename.**
`report:final.pdf` landing on Windows. `README.md` and `readme.md` landing on the
same case-insensitive volume, where one silently overwrites the other and both
are reported as successes. A path four characters past `MAX_PATH`. A vault entry
that needs `a/b` to be a directory while another entry needs `a/b` to be a file.
Each of those fails *partway through*, leaving a tree that is neither the old one
nor the new one — and each is knowable before the first byte moves.

So **every path is pre-flighted before anything is written, and every problem is
reported, not just the first**. An operator who fixes one name, waits six hours
and hits the next has been told the truth three times and helped none. The report
is data on stdout in whichever format was asked for, so it can be read by a person
or fed to a script.

Findings come in two severities. `blocking` means this platform cannot create the
name: a control character (which no filesystem anywhere accepts), a case
collision on a case-insensitive filesystem (macOS and Windows by default), a
directory/file type conflict — one entry needs `a/b` to be a directory while
another entry *is* the file `a/b`, which no filesystem in existence allows — or,
on Windows, a reserved device name, a
reserved character, a trailing dot, or a path past `MAX_PATH`. `portability`
means it would fail somewhere else but not here. Nothing is ever renamed to make
it fit: DCTL restores exactly the name it stored, and silently mangling one would
break the promise the backup was taken on.

**Which files a restore considers** comes from the scope of the `REMOTE:PATH`
operand and from the filter flags, all of which are honoured: `--include`,
`--exclude`, `--filter-from`, `--files-from`, `--min-size`, `--max-size` and
`--max-depth` go through the same `crate::filter` engine `dctl copy` and
`dctl backup` use, so one rule means one thing everywhere. They are matched
against the path **relative to the tree that was named**, matching how `copy`
treats a source directory: under `dctl restore archive:photos /out`,
`--include '2024/**'` means what a reader of `/out` expects rather than silently
requiring the `photos/` prefix that is about to be stripped. A filter that will
not *compile* is a usage error before anything is read, because a run that
proceeded with a rule the operator believes is in force is the data-loss case.

**A blocked path stops the whole restore unless `--skip-unwritable` is given.**
That default is the conservative one, because a partial restore that *looks*
complete is precisely the failure this command exists to prevent. Leaving files
out has to be something the operator asked for out loud. When they do ask, the
blocked entries still appear in the plan, marked `skip` with reason `blocking` —
listed rather than omitted, because a plan that silently drops the interesting
rows is how a partial restore comes to look complete.

**Overwriting is the destructive part, and it is gated three times.** A restore
into an empty directory destroys nothing. A restore into a directory that already
holds files does, so:

1. `--immutable` refuses outright — it forbids touching anything that already
   exists.
2. Without `--overwrite`, a restore that *would* replace anything refuses and
   names how many files (exit **7**).
3. With `--overwrite`, the replacement still passes through the destructive
   confirmation gate: `--dry-run` declines and prints
   `[dry-run] would overwrite: N existing file(s) under …`, `--interactive`
   prompts for a typed confirmation, `--force` approves without asking, and a
   bare run proceeds. Declining an interactive prompt on a real run exits **25**
   with `restore cancelled: nothing was written`.

**Scope.** `restore vault:photos /srv/out` writes `photos/2024/a.jpg` to
`/srv/out/2024/a.jpg`, not to `/srv/out/photos/2024/a.jpg` — the operand names
the tree, so repeating it under the destination would nest the result one level
deeper than anybody asked for. This mirrors how `copy` treats a source directory.
Scope comparison uses whole path components, so `vault:photos` never captures
`photos-backup`. A bare `vault:` is the entire dataset.

**Paths.** The vault side is written `REMOTE:PATH`; the local side is an ordinary
path and must be a directory (or not exist yet). Following rclone's rule,
`C:\data`, `d:/data` and `\\server\share` are treated as **local on every
platform**, so a script written on Windows behaves identically on a Linux build
agent — and `C:\Backups\photos` as the `REMOTE` operand is a usage error rather
than a remote called `C`. Logical paths are canonicalised (`/`-separated, NFC, no
`.` or `..`) so two spellings of one filename cannot address two different
objects.

**Every object is verified as it lands, and the writes are constant-memory.**
Each file is streamed out of the vault chunk by chunk into a temporary sibling of
its destination and renamed into place only after the whole object authenticates:
every chunk tag and the object footer are checked, and a streaming BLAKE3 over
the emitted plaintext is compared against the object's own DEK-authenticated
content hash. A mismatch removes the temporary file and leaves **no destination
file at all** — not a partial one, not a stale one — and exits **21**. Peak
memory is O(chunk) per file, so the largest object in the vault restores on a
laptop (`PLAN.md` §16.2).

On top of that, the length of what landed is compared against the length the
index recorded. The core proves an object is consistent with *itself*; this
catches an **index that disagrees with the store**, which is what a partial
rebuild or a database restored from an older backup looks like. Rows whose size
was never measured — `dctl index rebuild` writes those deliberately, as a
list-only pass — are exempt and the run says so rather than silently reporting a
total of zero.

**One bad object does not abandon the restore.** A per-file failure is counted,
reported by name, and skipped; the run continues and the exit code reflects it
(**6**, or **20** when the failure was an integrity check). A locked vault stops
the run, because every remaining file would fail identically.

### Status in this build

**`dctl restore` runs for real.** It unlocks the vault, enumerates the tree that
was named, pre-flights every path, prints the plan, applies the safety gates, and
then streams every object onto disk.

The vault is unlocked even for `--dry-run`, and that is not an oversight: a
restore cannot pre-flight names it has not read, so a rehearsal that skipped the
listing would rehearse nothing. It is a read-only operation and writes nothing.

Plan sizes are the **plaintext sizes the index recorded**, so what a `--dry-run`
says it will write is what a real run writes. (They used to be `0` for every row,
because the command had no vault to ask.)

One thing is still refused rather than approximated. **Point-in-time selection**
— `--at` and `--snapshot` — exits **7**: the index records one current version
per path in this build, and quietly planning *today's* contents for `--at 2d`
would answer a question nobody asked. The values are still parsed and validated
first, so a malformed `--at yesterday` is a usage error (exit **1**) rather than
sending the operator hunting for a missing feature. The versioned,
snapshot-backed index that makes it real is **Phase 4 (Hardening)** in
`PLAN.md` §11 — the same phase [`dctl backup --snapshot`](dctl_backup.md) names.

```
dctl restore REMOTE:PATH LOCAL [flags]
```

## Examples

Rehearse a restore before the day you need it. The vault is enumerated, the
pre-flight inspects every name against *this* machine's rules, and `--dry-run`
guarantees nothing is written — the destination directory is not even created.

```
dctl restore vault: /srv/restore-drill --dry-run
Severity     Path                      Problem
-----------  ------------------------  -------------------------------------------------------------------------------
blocking     photos/2024/readme.md     differs from 'photos/2024/README.md' only in case, which macos cannot represent
portability  reports/report:final.pdf  'report:final.pdf': contains ':', which Windows does not allow in a filename
Action     Size  Path
-------  ------  ---------------------------------------------------------------------
restore  28 MiB  vault:photos/2024/IMG_4417.CR3 -> /srv/restore-drill/photos/2024/IMG_4417.CR3
restore    10 B  vault:photos/2024/README.md -> /srv/restore-drill/photos/2024/README.md
skip       10 B  vault:photos/2024/readme.md -> /srv/restore-drill/photos/2024/readme.md
restore     4 B  vault:reports/report:final.pdf -> /srv/restore-drill/reports/report:final.pdf
error: 1 of 4 path(s) cannot be written on this platform
  hint: Every one is listed above. Rename them in the vault, restore somewhere
  with different rules, or pass --skip-unwritable to restore the rest and be told
  exactly what was left out.
```

That is the failure worth finding in a drill rather than in an incident: two
objects whose names differ only in case cannot both exist on a macOS volume, and
a restore that wrote them both would report two successes having produced one
file.

Restore the rest anyway, and be told exactly what was left out. The skipped row
stays in the plan so it is visible rather than absent:

```
dctl restore vault: /srv/restore-drill --skip-unwritable --dry-run
warning: 1 path(s) will be skipped: they cannot be written here
```

Then perform the restore. The whole tree comes back, streamed and verified:

```
dctl restore archive: /srv/out
Action        Size  Path
-------  ---------  --------------------------------------------------------------
restore       10 B  archive:README.md -> /srv/out/README.md
restore        9 B  archive:notes/café.txt -> /srv/out/notes/café.txt
restore        0 B  archive:notes/empty.txt -> /srv/out/notes/empty.txt
restore  293.0 KiB  archive:photos/2024/a.jpg -> /srv/out/photos/2024/a.jpg

 Transferred: 293.0 KiB / 293.0 KiB, 100%, 54.1 KiB/s
       Files: 4 / 4
      Errors: 0
     Elapsed: 5s

$ diff -r /srv/photos /srv/out && echo IDENTICAL
IDENTICAL
```

Restore only part of a vault, with a rule. Filters are matched against the path
relative to the tree that was named:

```
dctl restore archive: /srv/out --exclude 'photos/**'
```

Pull one tree out of a B2 vault onto a Windows workstation. The vault side is
`REMOTE:PATH`; the local side is an ordinary Windows path. The named tree is not
repeated underneath the destination, so `photos/2024/IMG_4417.CR3` lands at
`C:\Restores\2024\IMG_4417.CR3`:

```
dctl restore b2prod:bucket/photos C:\Restores --dry-run
```

Getting the two operands the wrong way round is caught before anything is read:

```
dctl restore C:\Backups\photos /srv/out
error: 'C:\Backups\photos' is a local path, not a vault
  hint: A recovery has one local side and one vault side. The vault is written
  REMOTE:PATH; the local side is an ordinary path.
```

Restore over a directory that already has files in it. The default refuses and
counts them; `--overwrite` allows it, and `--dry-run` still declines to touch
anything while telling you what would go:

```
dctl restore vault:photos /srv/photos --dry-run
error: the restore would replace 1 existing file(s) under /srv/photos
  hint: Restore into an empty directory, or pass --overwrite to replace what is
  already there.

dctl restore vault:photos /srv/photos --overwrite --dry-run
warning: [dry-run] would overwrite: 1 existing file(s) under /srv/photos
```

Ask for an earlier point in time and be refused rather than misled:

```
dctl restore vault:photos /srv/out --at 2d
error: restoring a snapshot or an earlier point in time (--snapshot/--at)
  (missing in dctl-index: the index format holds one current version per path,
  so there is no earlier one to select) is not implemented in this build
  hint: The index records one current version per path in this build; selecting
  an earlier one needs the versioned, snapshot-backed index of PLAN.md §13.5,
  scheduled as phase 4 (§11) and marked optional there. Restore the current
  contents by dropping the flag, or keep dated backups in separate remotes.
```

Feed a restore drill to a monitoring system. JSON Lines streams one
self-describing record per line and closes with a summary, so a ten-million-file
plan never has to be buffered:

```
dctl restore vault: /srv/drill --skip-unwritable --dry-run --format json-lines | tail -1
{"record":"summary","operation":"restore","dry_run":true,"files":4,"bytes":300028,"preflight":2,"blocking":1}
```

## Options

```
  -h, --help              help for restore
      --snapshot <NAME>   Restore the tree as it stood in this named snapshot
      --at <TIME>         Restore the tree as it stood at this instant
      --skip-unwritable   Restore what can be written and report the rest, instead of refusing the whole run when a name cannot be created here
      --overwrite         Replace local files that already exist. Without it, a restore that would overwrite anything refuses
```

Both operands are required: `<REMOTE>` is the vault to restore from, written
`REMOTE:PATH` (a bare `vault:` is the whole dataset); `<LOCAL>` is the local
directory to restore into. `--snapshot` and `--at` are mutually exclusive — they
are two spellings of the same question with different answers. `--at` accepts
`2026-07-26`, `2026-07-26T14:30:00Z`, `2d` (two days ago), `@1753574400` (Unix
seconds) or `now`, always interpreted as **UTC**: a local-time reading would make
one command select different objects on a laptop in Berlin than on a build agent,
and would be ambiguous for one hour every autumn. There is no spelling for a
future instant, because a backup holds nothing to restore from the future.

## Options inherited from parent commands

Every global flag is accepted on `dctl restore`, before or after the subcommand.
The ones that change what this command does are every filter flag —
`--include`, `--exclude`, `--filter-from`, `--files-from`, `--min-size`,
`--max-size`, `--max-depth`, all honoured — plus `--dry-run`,
`--password`/`--password-command`/`--password-file`/`--no-ask-password` (how the
vault is unlocked), `--index` (which index is read), `--immutable` (which makes
any overwrite fatal), `--interactive`/`--force` (which decide whether the
overwrite gate prompts), and `--format`/`--json`/`--units`/`--quiet`/`-v`
(output). See
[../GLOBAL_FLAGS.md](../GLOBAL_FLAGS.md) for the full list.

Output obeys the stdout/stderr split: the pre-flight findings and the planned
entries are **data** and go to stdout; counts, notices, warnings and the failure
summary are commentary and go to stderr. That is what makes
`dctl restore vault: /out --dry-run --json | jq '.preflight[]'` work while
progress is still animating on the terminal. `--json` emits one document with
`operation`, `source`, `destination`, `dry_run`, `files`, `bytes`, a `preflight`
array and an `entries` array; `--format json-lines` emits
`{"record":"preflight",…}`, `{"record":"entry",…}` and a closing
`{"record":"summary",…}`. The `preflight` array is **always** present — an absent
one would read as "not checked", and a restore that did not check is exactly what
§13.6 forbids. An absent `entries` field means "not computed"; an
empty one means "computed, and there is nothing to restore".

## Exit codes

| Code | Name | When |
|-----:|------|------|
| 0 | `success` | Every planned object was restored and verified, or a `--dry-run` completed with nothing blocked. |
| 1 | `usage` | A local path where the vault operand belongs (`C:\Backups`, `/srv/in`), a missing operand, a destination that exists and is not a directory, an unparseable `--at`, an invalid `--snapshot` name, `--at` together with `--snapshot`, an unparseable or crossed `--min-size`/`--max-size`, a negative `--max-depth`, a `--files-from` line containing `..`, or `--interactive` with no terminal to prompt on. |
| 2 | `uncategorised` | An I/O error, other than "not found" or "permission denied", reading a `--files-from` list. |
| 4 | `file_not_found` | A `--files-from` list does not exist. |
| 6 | `partial_failure` | At least one object could not be restored. The rest were, and each failure was named. |
| 7 | `fatal_error` | `--at`/`--snapshot` was given; at least one path cannot be written here and `--skip-unwritable` was not given; the restore would replace existing files and `--overwrite` was not given; `--immutable` was given and it would replace something; or the remote is not configured. |
| 20 | `checksum_mismatch` | An object did not verify as it landed. **No file was left under its name.** |
| 21 | `integrity_failure` | AEAD authentication failed on read — wrong key, tampered ciphertext, or wrong context. **The data was not served**, and no file was written. |
| 22 | `vault_locked` | No password was available, or the envelope would not unwrap. |
| 25 | `cancelled` | An `--interactive` overwrite was declined (`restore cancelled: nothing was written`), or Ctrl-C / SIGTERM. |

Codes 0–10 mirror rclone's taxonomy; 20+ are DCTL's own. See
[../EXIT_CODES.md](../EXIT_CODES.md) for the full contract.

## See also

* [dctl backup](dctl_backup.md) — the other half of the pair. Its pre-flight
  warns at store time about the names this command refuses at restore time.
* [dctl copy](dctl_copy.md) — pull objects out of a vault without the pre-flight,
  the snapshot vocabulary or the overwrite gate.
* [dctl check](dctl_check.md) — compare a vault against a local tree without
  transferring anything; the cheap rehearsal between full drills.
* [dctl verify](dctl_verify.md) — confirm the stored objects are intact before
  you need them.
* [dctl scrub](dctl_scrub.md) — the scheduled whole-dataset check that exists to
  keep this command boring.
* [dctl audit](dctl_audit.md) — the tamper-evident record of what was written,
  and therefore of what should come back.
