# dctl backup

Back up a local tree into a vault.

## Synopsis

`dctl backup` stores a local directory (or a single file) in a vault. It is
`copy` with two additions that only make sense for an archive: it runs the
**name pre-flight** over everything it is about to store (`PLAN.md` §13.6), and
it stores by **streaming** rather than by buffering.

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

**One local condition is a refusal rather than a warning, and it is the reverse
of the case above.** Two files whose names differ only in Unicode normalisation —
`re\u{301}sume\u{301}.txt` and `r\u{e9}sum\u{e9}.txt`, identical on screen and
different on disk — are two files on a byte-oriented filesystem and **one**
logical vault path, because a logical path is NFC so that one file has one key on
every platform. Storing both would keep the last and report every one of them as
backed up, which is the failure `PLAN.md` §6 forbids by name. So the run stops
before anything is written (exit **7**), and every colliding file is listed with
its non-ASCII characters escaped, because the names are the same glyphs and a
message that printed them as they display would print one string twice:

```
Severity  Path        Problem
--------  ----------  ----------------------------------------------------------------
blocking  résumé.txt  2 local files normalise to this one vault path, so storing
                      them all would keep only the last:
                      '/src/re\u{0301}sume\u{0301}.txt', '/src/r\u{00e9}sum\u{00e9}.txt'

error: 2 local file(s) share 1 vault path(s) once their names are normalised
```

The `Path` column carries the logical path — one row, because there is one
destination — and the escapes are in the problem, where the two *source* names
are named.

Rename all but one at the source. There is no flag to proceed, because there is
no correct file to keep: whichever were stored, the other is lost. The same
refusal applies to `copy`, `sync` and `move` — every verb that reads a local
tree. See [../RESTORE_DRILL.md](../RESTORE_DRILL.md#the-sharp-edge-two-files-one-path),
which is where it was found.

**Storing is constant-memory, and that is why `backup` is its own verb.** It
uses the core's streaming store (`Vault::put_file_from_path`), which seals the
source straight from disk into a temporary object and hands that to the backend's
streaming write. No stage ever holds the whole file or the whole object, so peak
memory is O(chunk) per file regardless of size — `PLAN.md` §16.2. There is
therefore **no whole-file size limit** on `backup`, unlike `copy`, which moves a
file through a buffer and refuses anything above
`TRANSFER_WHOLE_FILE_LIMIT` (1 GiB). A backup tool that could not store the
largest file on the disk would not be a backup tool.

**Each file is stored with its own modification time**, read from the source
immediately before it is sealed rather than carried from the scan: a scan of ten
million files can finish hours before a given file's turn comes, and the recorded
time is worth having only if it describes the bytes that were actually stored.
That is what lets a later `dctl check` or `dctl copy` recognise an unchanged file
instead of re-storing it. A source whose time cannot be read is stored with none —
never with the clock, which would look like a real answer and could stop the file
ever being backed up again.

**One bad file does not abandon the run.** A file that cannot be read or that the
core refuses is counted, reported by name, and skipped; the run continues and the
recorded errors downgrade the exit code to **6** (`partial_failure`). A *fatal*
failure — a locked vault, a cancelled run — stops the run instead, because every
remaining file would fail identically.

**`backup` is additive.** It stores what it finds; it never deletes anything from
the vault and never removes the local source. Making a destination match a source
— which means deleting from the destination — is [`dctl sync`](dctl_sync.md), and
that separation is deliberate: the command you point at an archive every night
must not be the command that can empty it.

**The verified-write contract governs every byte** (`PLAN.md` §6). Nothing is
reported as stored until the object has been written and verified against its own
hash, the authoritative §5 name record written, and the index entry durably
committed — in that order, inside one core call, so there is no window in which a
file is uploaded but uncommitted. A mismatch commits nothing and exits **20**. `--verify` selects the
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

**Filters are all honoured, through one engine.** `--include`, `--exclude`,
`--filter-from`, `--files-from`, `--min-size`, `--max-size` and `--max-depth` are
evaluated by the same `crate::filter` engine `dctl copy` and the listing family
use, so a rule means exactly the same thing to every command (`--max-depth 1` is
the top level only, matching rclone; one `--include` makes the unmatched default
an exclusion, also matching rclone). What is refused is a filter that will not
*compile* — a malformed pattern, an unreadable rule file — because a run that
proceeded with a rule the operator believes is in force is the data-loss case.
Crossed size bounds (`--min-size 10G --max-size 1M`) are a usage error for the
same reason: no file can satisfy both, so the run would report a clean success
having stored nothing.

**Paths.** The vault side is written `REMOTE:PATH`; the local side is an ordinary
path. Following rclone's rule, `\\server\share` is local on every platform and
`C:\data` and `d:/data` are local on a platform that has drives — off Windows
they name the remotes `C` and `d`, exactly as rclone reads them, and a remote
that is not configured fails by name rather than becoming a directory nobody
asked for. Logical paths inside the vault are canonicalised (`/`-separated, NFC,
no `.` or `..`), so a name typed on a Mac and a name typed on Linux address the
same object.

**Snapshots are refused on a real run** — see *Status in this build*. `--snapshot`
marks the run as one restorable point in time;
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

**`dctl backup` runs for real.** It walks the tree, applies the filters, runs the
name pre-flight, prints the plan in whichever format was asked for, and then —
unless `--dry-run` — unlocks the vault and streams every file into it.

The vault is unlocked **after** the report, so a `--dry-run` never asks for a
password and a run refused by `--strict-names` or by a control-character name
never asks for one either.

**`--snapshot` is refused on a real run** (exit **7**), and that is deliberate
rather than an oversight. Storing the files while quietly dropping the snapshot
name would leave an operator believing a named point in time exists; they would
discover it does not on the day they reached for it, which is the single worst
moment (`PLAN.md` §13.6). A `--dry-run` still plans and names the snapshot,
because planning is not claiming. The versioned, snapshot-backed index that makes
`--snapshot` real is **Phase 4 (Hardening)** in `PLAN.md` §11 — the same phase
[`dctl restore --at`](dctl_restore.md) names.

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
be `REMOTE:PATH`, and on Windows the drive letter wins over any remote of the
same name, so the two are never confused:

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

Exclude the scratch files, and see the rule applied rather than refused:

```
dctl backup /srv/photos archive: --exclude '*.tmp' --dry-run
Action       Size  Path
------  ---------  -------------------------------------------------------------
store        10 B  /srv/photos/README.md -> archive:README.md
store         9 B  /srv/photos/notes/café.txt -> archive:notes/café.txt
store         0 B  /srv/photos/notes/empty.txt -> archive:notes/empty.txt
store   293.0 KiB  /srv/photos/photos/2024/a.jpg -> archive:photos/2024/a.jpg

 Transferred: 0 B / 293.0 KiB, 0%, -
       Files: 0 / 4
      Errors: 0
```

Then run it for real. The same four files, streamed and committed:

```
dctl backup /srv/photos archive: --exclude '*.tmp'
 Transferred: 293.0 KiB / 293.0 KiB, 100%, 31.0 KiB/s
       Files: 4 / 4
      Errors: 0
     Elapsed: 9s
```

Ask for a snapshot and be told no, rather than being given a name that could
never be restored:

```
dctl backup /srv/photos archive: --snapshot --snapshot-name nightly
error: recording a backup as a named snapshot (--snapshot) (missing in
  dctl-index: the index format holds one current version per path, so a snapshot
  name would have nothing to pin) is not implemented in this build
  hint: The index records one current version per path in this build, so a
  snapshot name could be stored but never restored. The versioned,
  snapshot-backed index of PLAN.md §13.5 — phase 4 (§11), listed there as
  optional — is what makes it real. Back up without --snapshot; the files
  themselves are stored identically.
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
The ones that change what this command does are `--dry-run` (plan only, and no
password prompt), `--password`/`--password-command`/`--password-file`/
`--no-ask-password` (how the vault is unlocked), `--index` (which index the
commit lands in), every filter flag — `--include`, `--exclude`, `--filter-from`,
`--files-from`, `--min-size`, `--max-size`, `--max-depth`, all honoured —
`--format`/`--json`/`--units`/`--quiet`/`-v`
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
| 0 | `success` | Every scanned file was stored, or a `--dry-run` completed with no scan problems. |
| 1 | `usage` | A local path where the vault operand belongs (`C:\vault`, `/srv/out`), a missing operand, `--snapshot-name` without `--snapshot`, an invalid snapshot name, an unparseable or crossed `--min-size`/`--max-size`, a negative `--max-depth`, or a `--files-from` line containing `..`. |
| 2 | `uncategorised` | An I/O error, other than "not found" or "permission denied", reading a `--files-from` list. |
| 3 | `dir_not_found` | The `<LOCAL>` source does not exist. Reported before the engine check, so a typo is never mistaken for a missing feature. |
| 4 | `file_not_found` | A `--files-from` list does not exist. |
| 6 | `partial_failure` | The walk recorded a problem — an unreadable directory, a name that is not valid UTF-8, a vanished file, a dangling symlink — or a file could not be stored. The rest of the tree was still stored. |
| 7 | `fatal_error` | `--snapshot` on a real run; a name contains a control character no filesystem accepts; two or more local files share one vault path once their names are normalised; `--strict-names` was given and the pre-flight found anything; the `REMOTE` operand names a vault's object store rather than the vault; or the remote is not configured. |
| 20 | `checksum_mismatch` | A verified write refused to commit. Nothing was stored and the local source was not touched. |
| 25 | `cancelled` | Ctrl-C or SIGTERM. Nothing in flight was reported as complete. |

Also reachable: **22** (`vault_locked`) when no password is available. Codes
0–10 mirror rclone's taxonomy; 20+ are DCTL's own. See
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
