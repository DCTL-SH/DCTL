# dctl copy

Copy files from source to destination, skipping identical files.

## Synopsis

`dctl copy` makes the destination a **superset** of the source. Every file the
source has and the destination lacks is transferred; every file that differs is
re-transferred; every file that already matches is skipped; and every file that
exists *only* at the destination is left exactly where it is. That last clause
is the entire difference between `copy` and [`sync`](dctl_sync.md), and it is
why `copy` is the verb to reach for when you are not sure which one you want.

`copy` is not classified destructive. It never removes a destination file, so it
never prompts, never needs `--force`, and cannot be talked into emptying a tree
by a mistyped source. The worst outcome of a wrong `SOURCE` is that the wrong
data lands somewhere; nothing that was already there is lost.

**Both arguments are containers.** `dctl copy ./photos vault:photos/2024` places
the *contents* of `./photos` under `vault:photos/2024`, preserving relative
paths — `./photos/raw/a.cr3` becomes `vault:photos/2024/raw/a.cr3`. A `SOURCE`
that names a single file is allowed and lands *inside* `DEST` under its own
name, matching rclone: `dctl copy report.pdf vault:archive` writes
`vault:archive/report.pdf`. When you want `DEST` to be the object's name rather
than the directory it goes in, use [`copyto`](dctl_copyto.md). That is the
intended addressing; the prefix after the colon is not yet applied to the stored
key, and *What runs today* says exactly what happens instead.

**What "identical" means.** The decision is made once, per file, by the shared
comparison rules — the same code `sync` uses, which is what stops the two verbs
from disagreeing about which files are current. The rules apply in this order:

1. Nothing at the destination means copy. No flag overrides this; a flag that
   skipped a file the destination does not have would silently lose data.
2. `--ignore-existing` skips anything already present, without comparing it.
3. `--update` skips anything whose destination copy is newer than the source.
4. Otherwise the configured comparison decides: size and modification time by
   default (with a one-second tolerance, so filesystems with different timestamp
   granularity do not re-transfer everything); content hashes under the global
   `--checksum`; size alone under the global `--size-only`.

A size difference always wins over a matching timestamp. A destination whose
timestamp cannot be read is treated as modified rather than identical — the safe
direction, because re-transferring costs bandwidth and skipping costs data.

**The verified-write contract.** DCTL never reports a file as stored until it
is. What "stored" means depends on where the file is going, so both directions
are spelled out rather than described as one thing.

*Into a vault.* The plaintext is read, sealed, and written to the backend under
its object key by a **verified write**: the sealed bytes are hashed before they
are sent and the stored object is compared against that hash. The local backend
goes further — it writes a temporary file, `fsync`s it, reads it back off the
disk, compares again, and only then publishes it with an atomic rename, so a
half-written object is never visible under its real key. Only after that write
returns is the index record committed — and the index commit is what makes the
file exist as far as DCTL is concerned. `dctl-core`'s `put_file` returns `Ok`
only once all of it has happened, so there is no window in which an object is
stored but uncommitted. The "Files" counter is incremented after it returns,
never before.

*To a local path.* The destination's parent directories are created, the file is
written, and `fsync` is awaited before success is reported — a write still
sitting in the page cache has not survived a power cut. Note what this is *not*:
the destination is written in place rather than staged under a temporary name
and renamed, so an interrupted overwrite can leave a destination file truncated.
The source is never touched by that, which is what keeps [`move`](dctl_move.md)
safe.

**The five progress stages are honest about where the work happens.** `read`,
`encrypt`, `upload`, `verify`, `commit` are real positions in the pipeline and
the bar reports the one a file is actually at. For a vault destination the seal,
the verified write and the index commit are a single core operation performed at
`upload`; `encrypt` and `commit` therefore do no work of their own and claim
none. That is a *stronger* guarantee than performing them separately, not a
weaker one — there is no moment at which bytes are uploaded but uncommitted. The
stages separate again when `dctl-core` grows the streaming API of `PLAN.md`
§16.2, without any change to the commands above it.

**What happens on a checksum mismatch.** For a vault destination the comparison
is inside the verified write, so a mismatch aborts during the `upload` stage —
before the index commit. Nothing is committed, nothing is reported as
transferred, and the run exits **20** (`checksum_mismatch`) rather than the
generic error code, so a script can tell corruption apart from a timeout. It is
a per-file failure: the remaining files are still attempted, and the mismatch
still decides the process exit code at the end.

**What `--verify` actually does.** Be precise about this, because the three
names promise more separation than the engine currently delivers:

* `checksum` (the default) adds nothing to the verified write described above.
  Against a filesystem destination that means it adds nothing at all — there is
  no second party holding a checksum to disagree with.
* `sample` and `strict` are **identical today**, and both are a full read-back.
  On an upload each file is fetched again, decrypted, and its plaintext BLAKE3
  compared with the hash the index recorded; a failure exits **21**
  (`integrity_failure`) with `read-back verification failed for '<path>'`. That
  is the egress `PLAN.md` §12 says must be opt-in — it downloads everything just
  uploaded.
* `--verify-samples` parses and is **not consulted**. Partial sampling does not
  exist yet, which is why `sample` costs exactly what `strict` costs.
* Filesystem-to-filesystem, `verify` does nothing in any mode. The guarantee
  there is the durable write, and nothing else is claimed.

The summary's `Verified:` row counts the bytes that reached the end of the
pipeline, and labels them `checksum-matched`. For an upload that label is
accurate. For a local-to-local copy read it as "written and flushed" — that
stage did no comparison, because there was nothing to compare against.

**Failure policy.** One bad file does not abandon the run. A per-file error is
counted and printed on stderr, the loop continues, and the accumulated errors
downgrade the process exit code to **6** (`partial_failure`) — never rolled up
into success. A *fatal* failure is different: a locked vault, an index error, a
cancelled run or a usage error would make every remaining file fail identically,
so the run stops rather than emitting one copy of the same error per file.

**Filters.** `--max-depth`, `--min-size` and `--max-size` are evaluated for real
by the directory walk. The pattern filters — `--include`, `--exclude`,
`--filter-from`, `--files-from` — are **refused**, not ignored: passing any of
them fails with exit 7 before anything is listed. The reason lives in
[`sync`](dctl_sync.md), where a dropped `--exclude` deletes the files the rule
was written to protect, and the family refuses uniformly rather than being safe
in one verb and dangerous in another.

**Omissions are announced.** Symbolic links are never followed — a link to an
ancestor makes a walk loop forever and a link out of the tree copies data nobody
named — and filenames that are not valid UTF-8 cannot be stored. Both are
counted and warned about on stderr rather than passed over quietly, because
finding out from a restore is far too late. Names are NFC-normalised on their
way into a vault, so a file typed on macOS and on Linux becomes one object.

**`--dry-run` is authoritative.** The plan is a pure function of two listings and
a policy: no I/O, no clock, no mutation. The same value is either printed for
review or handed to the executor, so what a dry run shows is what a real run
performs. There is no second traversal that decides while it acts.

### What runs today

**`copy` transfers real bytes now.** Two shapes work end to end:

* **Filesystem to filesystem.** `dctl copy /srv/src /srv/dst` reads, writes and
  flushes every planned file, creates the directories it needs, and reports what
  it did. Nothing about it is a stub.
* **Filesystem into a vault**, with `--no-traverse`. Each file is sealed, written
  with the verified write above, and committed to the index. The password is
  acquired once, before the first file, in this order: `--password` or
  `DCTL_PASSWORD`, then `--password-command`, then `--password-file`, then a
  terminal prompt — which `--no-ask-password` turns into exit **22** rather than
  a job that blocks forever on an invisible prompt.

`--no-traverse` is required for the vault case only because **listing a named
remote is still not implemented**. That refusal (exit **7**, `listing a remote
is not implemented in this build`) fires before anything else, which has three
consequences worth stating outright:

* A vault **destination** must be planned with `--no-traverse`. Every source
  file is then planned as a `copy` with the reason `destination-not-listed`,
  including files already stored — so a re-run re-uploads and re-commits them
  rather than skipping them.
* A vault **source** — the download direction — cannot be planned at all.
  `dctl copy vault:photos ./out` stops at source enumeration with exit 7. The
  engine implements downloads; the command cannot reach them yet.
* **Remote to remote** stops at the same place, and is refused a second time by
  the engine if it ever gets past it: a direct vault-to-vault path needs
  re-encryption support that `dctl-core` does not expose. Copy down to a local
  path first, then copy that up.

**Addressing a vault is the part that is not finished.** Read this before
pointing `copy` at a `REMOTE:PATH`, because both halves of the spec are handled
differently from how they read:

* **The name before the colon is resolved as a directory**, relative to the
  current working directory. `dctl copy ./src archive:` unlocks the vault in
  `./archive`. A remote defined with `dctl config create`, and the provider
  shorthands `b2:`, `s3:` and `r2:`, are **not** resolved on this path: they
  become directory names too, so they fail to unlock and the run exits **22**
  (`unlock failed: wrong password or corrupted envelope`). The only vault
  reachable today is therefore a local one sitting directly beside you. Cloud
  backends exist and are tested in `dctl-store`; the transfer commands cannot
  address them yet.
* **The path after the colon is dropped.** `dctl copy ./src archive:photos`
  stores `a.txt` and `sub/b.txt` at the vault's root, not under `photos/`. Treat
  a vault destination as addressing the root until this is fixed — and note that
  the plan printed by `--dry-run` shows the *intended* spec, so it reads better
  than what happens.

Neither of these loses data or reports success falsely; both put objects
somewhere other than the spec says. `local:` is not a way round it — that prefix
means "read the rest as a filesystem path", so it lands in the plain-write
refusal below, which is the correct answer to it.

**Three refusals protect data rather than announce missing features**, all exit
**7**:

* **A plain write into a vault's object namespace.** Writing there as an
  ordinary filesystem path would store the data *unencrypted, next to the
  ciphertext*, and report success — for a tool whose whole promise is that data
  is sealed before it lands, that is the worst available outcome, so it is
  refused rather than done quietly. The rule comes from your **configuration**,
  not from what the destination currently contains:

  * If `DEST` is a store remote — `archive-store:` — or a local path at or
    inside a store remote's location, the run stops before the first file with
    `'<dir>' is the object store for remote 'archive'`, and the hint names both
    views: `archive:` to store the data sealed, and `dctl replicate
    archive-store: DEST-STORE:` to copy the stored objects exactly as they are
    with no vault password.
  * If `DEST` is a local path that holds a vault envelope but no configured
    remote describes it, the refusal says exactly that and points at
    `dctl config import`. There is no remote to name, so none is invented.

  What never happens is DCTL deciding to encrypt for you. Encryption follows the
  remote name typed, so the same command means the same thing tomorrow as it
  does today, whatever has been created at the destination in between.
* **Files above the whole-file limit.** `dctl-core` takes and returns complete
  buffers, so a file's plaintext is resident in memory while it moves. Anything
  over **1 GiB** (1073741824 bytes) is refused by name and size rather than
  attempted, because attempting it would be killed by the OOM killer or swap the
  machine to a standstill. The refusal is fatal: files earlier in plan order have
  already been transferred, and the rest are not attempted. Streaming transfers
  (`PLAN.md` §16.2) delete the limit rather than raise it.
* **`--checksum` when either side cannot supply a hash.** It fails instead of
  silently downgrading to size-and-time. The user asked for content equality;
  answering a different question would be exactly the misreporting the
  durability contract forbids.

* **`--immutable` when the plan contains an `update`.** An existing destination
  object being replaced is exactly what the flag forbids, so the whole run fails
  with exit **7** before any byte moves and the message names the paths. A
  destination that does not exist yet is an addition, not an overwrite, and still
  copies. `--immutable` with `--no-traverse` is a usage error (exit **1**): an
  unlisted destination cannot be checked for overwrites.

**Still parsed and not yet consulted:** `--transfers`, `--checkers`, `--bwlimit`,
`--retries` and `--low-level-retries`. Files are transferred one at a time, in
plan order, with no bandwidth shaping and no retry loop — the `Retries` row of
the summary is therefore always absent.

Nothing is ever reported as copied when it was not, on any of those paths.

```
dctl copy SOURCE DEST [flags]
```

The hidden compatibility aliases `dctl put` and `dctl get` parse the same
arguments and run this command.

## Examples

The stderr run summary (`Transferred: … / Files: … / Errors: …`) and the
structured `ERROR` log line are omitted below except where they are the point.

Copy one local tree into another. This runs for real: two files are read,
written and flushed, and the third is skipped because it was proven identical:

```console
$ dctl copy /mnt/media/incoming /srv/archive/incoming -v
2 to copy, 0 to update, 0 to delete, 1 unchanged (1.91 MiB)

 Transferred: 1.91 MiB / 1.91 MiB, 100%, 42 MiB/s
    Verified: 1.91 MiB checksum-matched
       Files: 2 / 2
      Checks: 3 / 3
     Skipped: 1 (unchanged)
      Errors: 0
     Elapsed: 0s
$ echo $?
0
```

Copy a local tree into a vault. `--no-traverse` is required because the
destination cannot be listed yet, so every source file is planned as a copy; the
password is read once, before the first file. Here `archive` is a vault
directory in the working directory — see *What runs today* for why that is
currently the only kind of vault a transfer can address:

```console
$ dctl copy ./dailies archive: --no-traverse --password-command 'pass dctl' --progress
```

Relative paths inside the tree are preserved — `dailies/2024-06-01/a1.mov` is
stored as `2024-06-01/a1.mov`.

Preview first. `--dry-run` prints the plan on stdout in the active format and
changes nothing; `-v` adds the one-line shape summary on stderr:

```console
$ dctl copy /mnt/media/incoming /srv/archive/incoming --dry-run -v
2 to copy, 0 to update, 0 to delete, 1 unchanged (1.91 MiB)
Action      Size  Path
------  --------  ---------
copy    1.91 MiB  big.mov
copy         3 B  sub/b.txt
```

Plan the upload before running it. `--no-traverse` means the destination is
never enumerated, so a dry run needs no password at all. Every source file is
assumed missing, and the plan says so — the reason slug is
`destination-not-listed` rather than `missing-at-destination`, which is the
honest distinction between "nothing is there" and "we did not look":

```console
$ dctl copy /mnt/media/incoming vault:photos/2024 --dry-run --no-traverse --json
{
  "command": "copy",
  "source": "/mnt/media/incoming",
  "destination": "vault:photos/2024",
  "dry_run": true,
  "summary": {
    "copy": 3,
    "update": 0,
    "delete": 0,
    "skip": 0,
    "mkdir": 0,
    "bytes": 2000007
  },
  "actions": [
    {
      "action": "copy",
      "source": "a.txt",
      "dest": "a.txt",
      "size": 4,
      "reason": "destination-not-listed"
    },
    {
      "action": "copy",
      "source": "big.mov",
      "dest": "big.mov",
      "size": 2000000,
      "reason": "destination-not-listed"
    },
    {
      "action": "copy",
      "source": "sub/b.txt",
      "dest": "sub/b.txt",
      "size": 3,
      "reason": "destination-not-listed"
    }
  ]
}
```

The `source` and `destination` fields are **roots**: joining one to an action's
relative path yields the object's full spec. A plan pulled out of a CI log is
self-describing for exactly that reason.

Copy from Windows. A one-character prefix is always a drive letter, on every
platform, so `C:\media\dailies` is a local path and never a remote called `C`.
The same rule protects UNC paths (`\\nas\media`) and relative paths that happen
to contain a colon:

```console
$ dctl copy C:\media\dailies vault:footage --dry-run --no-traverse
```

If the drive is not mounted the source is missing, and that is an error rather
than a successful transfer of nothing:

```console
$ dctl copy C:\media\dailies vault:footage --dry-run
error: source not found: C:\media\dailies
warning: Check the path, and the remote name if one was given.
$ echo $?
3
```

Copy one file into a directory. `DEST` is the container, so the object keeps its
own name and lands at `/srv/archive/report.pdf` — contrast
[`copyto`](dctl_copyto.md), which would treat `archive` as the new name:

```console
$ dctl copy report.pdf /srv/archive
```

An up-to-date destination is an honest success, not a claim of work done.
Nothing is opened and no password is asked for, because nothing needed
transferring:

```console
$ dctl copy /srv/src /srv/dst --size-only -v
0 to copy, 0 to update, 0 to delete, 1 unchanged (0 B)
nothing to transfer: the destination is up to date
$ echo $?
0
```

A plain copy into a vault's object store is refused, before the first file. The
alternative is writing your data next to the ciphertext in the clear and calling
it a success. With the vault registered — `dctl init --name archive --base
local:/srv/vault` — the refusal comes from the configuration and can name both
views, so there is something to do next:

```console
$ dctl copy ./photos /srv/vault
error: '/srv/vault' is the object store for remote 'archive'
warning: Use `archive:` to store data sealed — every write through it is
encrypted, and no flag turns that off. To copy the objects already stored there
exactly as they are, run `dctl replicate archive-store: DEST-STORE:`, which
needs no vault password. DCTL will not switch between the two on its own: what a
command encrypts is decided by the remote name typed.
$ echo $?
7
```

Naming a subdirectory does not get round it — `/srv/vault/photos` is inside the
same store, and the message still names `/srv/vault` so you can see what you
hit. For a vault this machine's configuration knows nothing about, the envelope
on disk is the only evidence there is, and the refusal says so rather than
guessing at a remote name:

```console
$ dctl copy ./photos /mnt/usb/vault-from-the-office
error: refusing to write plaintext into '/mnt/usb/vault-from-the-office': it
contains a vault that no configured remote describes
$ echo $?
7
```

A file too large for the whole-buffer engine is refused by name and size rather
than attempted. The refusal is fatal, so the run stops there — `a-small.txt`,
earlier in plan order, was already transferred:

```console
$ dctl copy /mnt/ingest /srv/archive
error: 'z-huge.bin' is 2147483648 bytes, above the 1073741824 byte whole-file limit
warning: The current engine moves whole files through memory, so very large
objects are refused rather than attempted. Streaming transfers (PLAN.md §6,
§16.2) lift this limit. Use --dry-run to see exactly what would be transferred.
$ echo $?
7
```

A vault source cannot be enumerated yet, so the download direction stops before
the engine is reached:

```console
$ dctl copy vault:photos ./restored
error: listing a remote is not implemented in this build
warning: Enumerating a remote needs an unlocked vault, which the command context
does not yet carry. Transfers between local paths can be planned today.
$ echo $?
7
```

Pattern filters are refused rather than quietly dropped:

```console
$ dctl copy /srv/src vault:backup --exclude 'cache/**'
error: pattern filtering (--include/--exclude/--filter-from/--files-from) is not implemented in this build
warning: A filter that was silently ignored would make `sync` delete the files it
was written to protect, so DCTL refuses instead. Narrow the transfer with an
explicit SOURCE, or with --min-size/--max-size/--max-depth, which are honoured.
$ echo $?
7
```

## Options

```
      --create-empty-src-dirs  Recreate empty source directories at the destination
      --ignore-existing        Skip files that already exist at the destination, without comparing them
      --update                 Skip files where the destination is newer than the source
      --no-traverse            Do not list the destination; assume every source file is missing there
  -h, --help                   Print help (see more with '--help')
  -V, --version                Print version
```

Positional arguments:

| Argument | Meaning |
|----------|---------|
| `<SOURCE>` | A local path, or `REMOTE:PATH`. A single file is allowed and lands inside `DEST` under its own name. |
| `<DEST>` | A local path, or `REMOTE:PATH`. Its existing contents are never removed. |

Notes on the flags:

* `--create-empty-src-dirs` exists because an empty directory holds no objects
  and therefore has no representation in a vault — without this flag it
  disappears on the round trip. It adds `mkdir` entries to the plan, with the
  reason `empty-source-dir`.
* `--ignore-existing` skips by *presence*, without comparing. It never applies
  to a file the destination does not have.
* `--update` skips only when the destination is newer than the source by more
  than the one-second modification window.
* `--no-traverse` trades correctness of the skip decision for speed: the
  destination is not listed at all, so every source file is planned as a copy
  even if an identical object is already there. Worth it when the destination
  holds far more files than the source. `sync` does not offer this flag; see
  [dctl sync](dctl_sync.md).

## Options inherited from parent commands

Every global flag is accepted; see [../GLOBAL_FLAGS.md](../GLOBAL_FLAGS.md) for
the full list. The ones that change what this command does:

| Flag | Effect here |
|------|-------------|
| `--checksum` | Compare content hashes instead of size and time. Currently refuses with exit 7 when either side has no hash rather than downgrading. Conflicts with `--size-only`. |
| `--size-only` | Compare size alone, ignoring timestamps. Useful against a destination that cannot report modification times. |
| `--verify <MODE>` | `checksum` (default) adds nothing to the verified write. `sample` and `strict` are identical today and both re-read every uploaded object in full; against a filesystem destination all three do nothing. |
| `--verify-samples <N>` | Parsed and **not consulted**: partial sampling does not exist yet. |
| `-n`, `--dry-run` | Print the plan and change nothing. Complete and trustworthy today. |
| `--password`, `--password-command`, `--password-file`, `--no-ask-password` | How the vault password is acquired, once, before the first file. Only a vault destination needs one. Nothing available exits **22**. |
| `--index <PATH>` | The index database the vault commit is written to. Defaults to the platform data directory. |
| `--format`, `--json` | Render the plan as a table, one JSON document, or one JSON Lines record per action. |
| `--min-size`, `--max-size`, `--max-depth` | Honoured by the walk, and applied to both listings. An unsatisfiable size range is a usage error rather than a silent transfer of nothing. |
| `--include`, `--exclude`, `--filter-from`, `--files-from` | **Refused** with exit 7, not ignored. |
| `-P`, `--progress`, `--stats` | Per-file bars showing the real pipeline stage — a row at `verify` has been written but is not yet counted as stored. |
| `--transfers`, `--bwlimit`, `--retries`, `--low-level-retries` | Parsed and **not consulted**. Files move one at a time, unshaped and unretried. |
| `--immutable` | **Honoured at plan time.** Any `update` in the plan fails the run with exit **7** before anything moves, naming the paths; a missing destination is an addition and still copies. Refused with `--no-traverse` (exit **1**), which never lists the destination. |
| `-q`, `--quiet` | Suppresses the summary and the skipped-symlink warnings. Errors are still printed. |

`--force` and `--interactive` have no effect on `copy`: it is not destructive
and never asks for confirmation.

## Exit codes

See [../EXIT_CODES.md](../EXIT_CODES.md) for the full contract.

| Code | Name | When |
|------|------|------|
| 0 | `success` | Every planned file was transferred, or a `--dry-run` completed, or every file was already identical so there was nothing to transfer. |
| 1 | `usage` | Unparseable command line; an empty spec or one that climbs above a remote's root with `..`; source and destination are the same place; `DEST` is an existing file rather than a directory; an unparseable or unsatisfiable `--min-size`/`--max-size`; `--immutable` together with `--no-traverse`. |
| 3 | `dir_not_found` | `SOURCE` does not exist. A missing `DEST` is not an error — that is the ordinary first run. |
| 5 | `temporary_error` | A cloud backend failed in a way worth retrying. Not reachable today: transfers cannot address a cloud backend yet, and a local destination does not produce it. |
| 6 | `partial_failure` | The run finished, and at least one file failed. The successful files are stored; the failures were printed on stderr as they happened. This is the code to branch on. |
| 7 | `fatal_error` | A named remote had to be listed; a file exceeded the whole-file limit; `DEST` is a local directory holding a vault; `--checksum` with no hashes available; a pattern filter was passed; both sides are remotes; `--immutable` and the plan would replace something. Files already transferred before the refusal stay transferred; nothing further is attempted — except the `--immutable` refusal, which happens before any transfer at all. |
| 20 | `checksum_mismatch` | The backend stored bytes other than the ones sent. Nothing was committed for that file. |
| 21 | `integrity_failure` | `--verify sample`/`strict` read an object back and it did not authenticate, or a decrypted object did not match its recorded hash. It was written but must not be trusted. |
| 22 | `vault_locked` | No password was available, or the envelope did not unwrap. Nothing was transferred. |
| 23 | `index_error` | The index database could not be opened or committed. |
| 25 | `cancelled` | The run was interrupted with Ctrl-C or SIGTERM. |

## See also

* [dctl move](dctl_move.md) — the same transfer, then delete each source after its own durable commit.
* [dctl sync](dctl_sync.md) — make the destination *identical*, deleting what the source does not have.
* [dctl copyto](dctl_copyto.md) — copy to an exact destination name rather than into a container.
* [dctl moveto](dctl_moveto.md) — `copyto`'s destination semantics with `move`'s ordering guarantee.
* [dctl check](dctl_check.md) — compare two sides without transferring anything.
* [dctl verify](dctl_verify.md) — prove that stored objects decrypt and match their recorded hashes.
