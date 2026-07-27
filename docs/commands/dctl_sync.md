# dctl sync

Make the destination identical to the source. Deletes from destination.

## Synopsis

**`dctl sync` deletes files you did not name.** It is the only verb in the
transfer family that does, and that single property drives everything about how
it behaves. After a successful sync, `DEST` contains exactly what `SOURCE`
contains: files missing at the destination are transferred, files that differ
are re-transferred, and **files present only at the destination are removed**.

The blast radius is the whole destination tree. `dctl sync ./photos
/srv/photos` with an empty or wrong `./photos` is an instruction to delete
every photo, and from inside the process an unmounted volume and an empty
directory are the same syscall result. Several guards below exist specifically
for that case, but the first line of defence is `--dry-run`, and the habit worth
building is to never run a sync you have not previewed.

If you want to add and update without ever removing, use
[`copy`](dctl_copy.md). That is the whole difference between the two verbs.

### The safety guards

`sync` refuses rather than guesses when the arguments cannot mean what they say.
Each refusal below is a usage error (exit 1) raised before anything is modified.

* **A single-file source.** `dctl sync photo.jpg backups/` reads as "make
  `backups/` contain exactly `photo.jpg`", which means deleting everything else
  in it. Almost nobody means that, so it is refused and the hint names the two
  verbs that do: `copy` to add the file without deleting anything, `copyto` to
  write it to an exact destination name.
* **An empty source against a non-empty destination.** A source that listed zero
  files, when the destination holds some, is refused — this is the unmounted
  volume case. `--force` is the escape hatch, because deliberately emptying a
  tree is a real thing to want and DCTL's job is to make it explicit rather than
  impossible. To remove a tree on purpose, [`purge`](dctl_purge.md) is the
  command that says so in its name.
* **Source and destination are the same place.** Structural equality catches the
  obvious case and canonicalisation catches `photos` versus `./photos` and a
  symlinked duplicate. A sync onto itself would be a race between listing a tree
  and deleting from it.
* **A destination that is already a file.** A tree cannot be written inside a
  file; the hint points at `copyto`/`moveto`.

Two more safeguards are not refusals but noise, deliberately:

* **The mass-deletion warning.** When a sync would remove half or more of the
  files it found at the destination, an unconditional warning goes to stderr —
  not gated behind `-v`, because it is the last chance to notice a typo:
  `warning: this would delete 1 of the 2 files at the destination`. It never
  blocks. Emptying a tree is legitimate; being quiet about it is not.
* **Every filter is applied to *both* listings.** `--include`, `--exclude`,
  `--filter-from`, `--files-from`, `--min-size`, `--max-size` and `--max-depth`
  all go through one engine, and the *same* engine on both sides. This matters
  more here than anywhere else in the tool: a rule that reached only the source
  would make `sync` see every excluded destination file as an extra and
  **delete** it. Because a rule hides a file on both sides, it is neither
  transferred nor deleted — `dctl sync src dst --exclude 'archive/**'` protects
  `archive/` at the destination rather than emptying it. A pattern that will not
  *compile* is a usage error before anything is listed. `dctl sync src dst --min-size 100`
  leaves a 4-byte destination file alone rather than treating it as an extra.

### The confirmation

`sync` is classified destructive, and asks for approval when — and only when —
the computed plan actually removes something. A sync that only adds files does
not prompt, because there is nothing destructive about it.

Note what the default is: running without `--interactive` does **not** prompt.
Typing the command is taken as consent, because prompting by default would break
every script. `--interactive` asks on stderr and requires the exact word `yes`;
with no terminal available it fails with a usage error rather than hanging.
`--force` approves without asking, and is also what unlocks the empty-source
guard. A declined confirmation exits **25** (`cancelled`), never a silent zero —
a command that declined to do its work has not succeeded.

### When the deletions happen

`sync` both adds and removes, so it is the only verb where ordering is a
user-visible choice. The three modes are rclone's, and each answers a different
question:

| Mode | Ordering | Choose it when |
|------|----------|----------------|
| `--delete-before` | every delete, then every transfer | the destination is nearly full and cannot hold the old and new copies at once. The only mode where an interrupted run can leave the destination holding *neither*. |
| `--delete-during` | interleaved, in plan order (**default**) | bounded peak usage without a long delete-only phase. |
| `--delete-after` | every transfer, then every delete | the destination is the only copy. Nothing is removed until every replacement is durably committed, so an interrupted run leaves a superset rather than a gap — at the cost of needing room for both. |

The three flags are mutually exclusive and clap rejects any combination of them
at parse time, before either side is enumerated. Whatever the mode, **the plan
is fixed before execution begins**: the executor reorders the entries it was
given, it never recomputes them. The list a `--dry-run` printed is the list that
gets performed.

### `--no-traverse` is not offered

`dctl sync --no-traverse` is a parse error, not a no-op. Skipping the
destination listing is a sensible optimisation for `copy`, where the listing
only decides what to skip. For `sync` the listing *is* where the deletions come
from, so the flag would either do nothing or delete nothing. A flag that parses
and is then ignored is a defect, so the parser does not accept it.

### The verified-write contract

Sync's transfers are the family's transfers, unchanged, and
[`copy`](dctl_copy.md) documents them in full. In short: a file bound for a
vault is sealed, written with a verified write — the stored object compared
against the hash of what was sent — and then committed to the index, and the
index commit is what makes it count as stored. A file bound for a local path is
written and `fsync`ed before success is reported. A mismatch between what was
sent and what the backend stored aborts before the index commit: nothing is
committed, nothing is reported as transferred, and the run exits **20**
(`checksum_mismatch`).

The interaction with deletion is the part to understand. A destination file
being *replaced* is only replaced by a commit that verified; a destination file
being *removed* is removed because the source does not have it, which is a
listing fact rather than a transfer outcome. Under `--delete-after` no removal
happens until every replacement has committed, which is why that mode is the one
to reach for when the destination is irreplaceable.

Per-file failures are counted and survived: the loop continues and the errors
downgrade the exit code to **6** (`partial_failure`), never rolled up into
success. A failed *deletion* is counted as an error but is never counted as a
deletion — the "files deleted" number in the summary means files that are
actually gone. Fatal failures (locked vault, index error, cancellation) stop the
run rather than producing one identical error per remaining file.

### `--dry-run` is authoritative

The plan is a pure function of two listings and a policy — no I/O, no clock, no
mutation — and the same value is either printed for review or handed to the
executor. Every planned deletion is shown, in every output format, because a
deletion nobody could review before it happened is not a deletion anybody
approved. `dctl sync src dst --dry-run --json | jq '.actions[] | select(.action
== "delete")'` is a supported workflow: plan data goes to stdout, and progress,
warnings and the summary go to stderr where they cannot corrupt it.

### What runs today

**Between two local paths, `sync` runs for real** — transfers *and* deletions,
in all three orderings. Files missing at the destination are written and
flushed, files that differ are rewritten, and files the source does not have are
removed from the destination. The mass-deletion warning, the confirmation, the
guards and `--dry-run` all sit in front of that unchanged.

**A `sync` with a vault on one side runs too.** Both directions work: a vault is
enumerated through `crate::source`, the same reader `dctl ls` uses, so the
listing an operator reads before approving a deletion describes the sync that
follows. `dctl sync archive: /srv/mirror` makes the local tree match the vault,
removing what the vault does not hold; `dctl sync /srv/photos archive:` does the
reverse.

**Remote-to-remote is still refused**, at connect time rather than part-way
through a tree, and the message distinguishes two different waits. With a sealed
end it needs a re-encrypting transfer `dctl-core` does not expose, and **no
`PLAN.md` §11 phase schedules one**. With two plain ends nothing needs re-sealing
and nothing is waiting on the core: the `dctl-cli` engine holds one backend and
one local side, and no phase names that either. Sync down to a local path first,
then sync that up.

The refusals `copy` documents apply here unchanged, all exit **7** and all
before anything is removed: a **plain write into a directory that holds a
vault**, a file **above the 1 GiB whole-file limit** (the core is whole-buffer;
streaming is `PLAN.md` §16.2), and **`--checksum`** against a plain object store,
whose provider checksum is not the plaintext hash a vault records. The oversized-file refusal is fatal, so under
`--delete-before` the deletions have already happened when it fires, and under
`--delete-after` none of them have.

`--immutable` **is** honoured, at plan time, and it is strictest here: `sync` is
the verb that both replaces and removes, so a plan containing **any** `update` or
`delete` fails the whole run with exit **7** before anything moves, naming the
paths. Only additions are allowed — which is to say that under `--immutable`,
`sync` degrades to `copy` and refuses outright rather than quietly doing so. All
three `--delete-*` orderings are equally refused; the ordering only decides when
deletions happen, not whether they are permitted.

`--transfers`, `--bwlimit` and `--retries` are parsed and not consulted. Files
move one at a time.

```
dctl sync SOURCE DEST [flags]
```

## Examples

The stderr run summary and the structured `ERROR` log line are omitted below
except where they are the point. A `REMOTE:PATH` on either side stops with exit
7 before anything happens; see *What runs today*.

Preview before anything else. `-v` adds the one-line shape summary; the
mass-deletion warning appears regardless of verbosity:

```console
$ dctl sync /mnt/media/incoming /srv/archive/incoming --dry-run --size-only -v
2 to copy, 0 to update, 1 to delete, 1 unchanged (1.91 MiB)
warning: this would delete 1 of the 2 files at the destination
Action      Size  Path
------  --------  ---------
copy    1.91 MiB  big.mov
copy         3 B  sub/b.txt
delete       2 B  stale.txt
```

Review the deletions machine-side before approving a real run. This is the
artefact worth attaching to a change ticket — it names both endpoints, so it is
still meaningful pulled out of a CI log a month later:

```console
$ dctl sync /mnt/media/incoming /srv/archive/incoming --dry-run --size-only --json
{
  "command": "sync",
  "source": "/mnt/media/incoming",
  "destination": "/srv/archive/incoming",
  "dry_run": true,
  "summary": { "copy": 2, "update": 0, "delete": 1, "skip": 1, "mkdir": 0, "bytes": 2000003 },
  "actions": [
    { "action": "copy", "source": "big.mov", "dest": "big.mov", "size": 2000000, "reason": "missing-at-destination" },
    { "action": "copy", "source": "sub/b.txt", "dest": "sub/b.txt", "size": 3, "reason": "missing-at-destination" },
    { "action": "delete", "source": "", "dest": "stale.txt", "size": 2, "reason": "not-at-source" }
  ]
}
```

Run the sync, removing nothing until every replacement is durable.
`--delete-after` is the mode to reach for when the destination is the only copy:

```console
$ dctl sync /mnt/media/incoming /srv/archive/incoming --delete-after --size-only -v
2 to copy, 0 to update, 1 to delete, 1 unchanged (1.91 MiB)
warning: this would delete 1 of the 2 files at the destination

 Transferred: 1.91 MiB / 1.91 MiB, 100%, 44 MiB/s
    Verified: 1.91 MiB checksum-matched
       Files: 2 / 2
      Checks: 4 / 4
     Skipped: 1 (unchanged)
     Deleted: 1
      Errors: 0
     Elapsed: 0s
$ echo $?
0
```

Sync a Windows working drive. `E:\projects\apollo` is a local path — a
one-character prefix is a drive letter on every platform, never a remote called
`E`:

```console
$ dctl sync E:\projects\apollo F:\backup\apollo --delete-after --progress
```

Mirror a vault onto local disk. The vault is listed like any other side, which is
what makes the deletions computable at all:

```console
$ dctl sync archive: /srv/mirror --force
warning: this would delete 1 of the 1 files at the destination
 Transferred: 293.0 KiB / 293.0 KiB, 100%, 34.8 KiB/s
    Verified: 293.0 KiB checksum-matched
       Files: 4 / 4
      Checks: 5 / 5
     Deleted: 1
      Errors: 0
     Elapsed: 8s
```

The empty-source guard. This is the difference between a typo and a restore:

```console
$ dctl sync /mnt/backup /srv/archive/photos
error: '/mnt/backup' contains no files, so '/srv/archive/photos' would delete all 2 of them
warning: An unmounted volume and an empty directory look identical from here.
Check the source, or pass --force if the destination really should be emptied.
To remove a tree deliberately, use `dctl purge`.
$ echo $?
1
```

A single-file source is refused, with the two verbs that do mean it named in the
hint:

```console
$ dctl sync photo.jpg b2prod:bucket/media
error: 'photo.jpg' is a file, so 'sync' would make 'b2prod:bucket/media' contain nothing else
warning: Use 'copy' to add the file without deleting anything, or 'copyto' to
write it to an exact destination name.
$ echo $?
1
```

A pattern filter protects the destination rather than emptying it. The rule is
applied to **both** listings, so `archive/` is invisible on either side and is
neither transferred nor deleted — which is the whole reason one engine answers
for both:

```console
$ dctl sync /srv/src /srv/dst --exclude 'archive/**' --dry-run
```

`--no-traverse` is not a flag this command has:

```console
$ dctl sync /srv/src /srv/dst --no-traverse
error: unexpected argument '--no-traverse' found
$ echo $?
1
```

Two answers to "when is data deleted?" is not a question resolved by precedence:

```console
$ dctl sync /srv/src /srv/dst --delete-before --delete-after
error: the argument '--delete-before' cannot be used with '--delete-after'
$ echo $?
1
```

An already-identical destination needs neither a prompt nor an engine:

```console
$ dctl sync /srv/src /srv/dst --size-only -v
0 to copy, 0 to update, 0 to delete, 1 unchanged (0 B)
nothing to do: the destination already matches the source
$ echo $?
0
```

## Options

```
      --create-empty-src-dirs  Recreate empty source directories at the destination
      --ignore-existing        Skip files that already exist at the destination, without comparing them
      --update                 Skip files where the destination is newer than the source
      --delete-before          Delete destination files before transferring
      --delete-during          Delete destination files during the transfer. The default
      --delete-after           Delete destination files after transferring everything
  -h, --help                   Print help (see more with '--help')
  -V, --version                Print version
```

Positional arguments:

| Argument | Meaning |
|----------|---------|
| `<SOURCE>` | A local path, or `REMOTE:PATH`. Must be a directory; a single file is refused. |
| `<DEST>` | A local path, or `REMOTE:PATH`. **Files not present at the source are DELETED from it.** |

There is deliberately **no `--no-traverse`**; see the Synopsis.

`--ignore-existing` and `--update` change only whether an existing destination
file is *overwritten*. Neither protects a destination file that the source does
not have at all — that file is an extra, and an extra is deleted. If you need
files at the destination to survive, you need [`copy`](dctl_copy.md), not a flag.

## Options inherited from parent commands

Every global flag is accepted; see [../GLOBAL_FLAGS.md](../GLOBAL_FLAGS.md) for
the full list. The ones that matter here:

| Flag | Effect here |
|------|-------------|
| `-n`, `--dry-run` | Print the plan, including every deletion, and change nothing. Returns before the confirmation. |
| `--force` | Approves the destructive confirmation without prompting, **and** unlocks the empty-source guard. Conflicts with `--interactive`. |
| `-i`, `--interactive` | Prompts before the deletions and requires typing `yes`. With no terminal, exits 1 rather than hanging. |
| `--checksum` | Compare content hashes instead of size and time. Refuses with exit 7 today when a hash is unavailable. Conflicts with `--size-only`. |
| `--size-only` | Compare size alone, ignoring timestamps. Also the way to opt *out* of the content comparison a vault side otherwise forces — see [copy](dctl_copy.md). |
| `--verify <MODE>` | `checksum` (default), `sample`, `strict`. Against the local-to-local destinations `sync` can reach today, all three do nothing beyond the durable write; see [copy](dctl_copy.md) for what they do to a vault. |
| `--verify-samples <N>` | Parsed and **not consulted**: partial sampling does not exist yet. |
| `--min-size`, `--max-size`, `--max-depth` | Honoured, and applied to **both** listings. An excluded file is neither transferred nor deleted, so these narrow the deletion set rather than widening it. |
| `--include`, `--exclude`, `--filter-from`, `--files-from` | **Refused** with exit 7. A dropped rule here deletes the files it was protecting. |
| `--format`, `--json` | Render the plan as a table, one JSON document, or one JSON Lines record per action. |
| `--transfers`, `--bwlimit`, `--retries` | Parsed and **not consulted**. Files move one at a time, unshaped and unretried. |
| `--immutable` | **Honoured at plan time**, and strictest here: any `update` *or* `delete` in the plan fails the run with exit **7** before anything moves, naming the paths. Only additions are allowed. |
| `-q`, `--quiet` | Suppresses the summary and the shape line. The mass-deletion warning is a warning, not commentary; errors are always printed. |

## Exit codes

See [../EXIT_CODES.md](../EXIT_CODES.md) for the full contract.

| Code | Name | When |
|------|------|------|
| 0 | `success` | The destination was made identical to the source, or a `--dry-run` completed, or it already matched. |
| 1 | `usage` | Unparseable command line; two `--delete-*` flags; a single-file `SOURCE`; an empty source against a non-empty destination without `--force`; source and destination are the same place; `DEST` is an existing file; an unparseable or unsatisfiable size range; `--interactive` with no terminal. |
| 3 | `dir_not_found` | `SOURCE` does not exist. A missing `DEST` is not an error. |
| 5 | `temporary_error` | A cloud backend failed in a way worth retrying. `sync` addresses remotes — sealed and plain alike — so this is reachable wherever a cloud backend is actually contacted. A local-to-local sync does not produce it. |
| 6 | `partial_failure` | The run finished with at least one failure. A failed deletion contributes to this and is **never** counted as a deletion in the summary — the "Deleted" number means files that are actually gone. |
| 7 | `fatal_error` | Both sides are remotes; a file exceeded the whole-file limit; `DEST` is a local directory holding a vault; `--checksum` against a plain object store, which cannot supply a plaintext hash; `--immutable` and the plan would replace or delete anything, which is refused before any file is touched. |
| 25 | `cancelled` | The confirmation was declined, or the run was interrupted with Ctrl-C. Nothing further was deleted. |

**20** (`checksum_mismatch`), **21** (`integrity_failure`), **22**
(`vault_locked`) and **23** (`index_error`) are part of this command's contract
and are **not reachable today**: all four require a vault, and every
vault-involving `sync` stops at enumeration with exit 7. They become reachable
when remote listing lands, with the meanings [copy](dctl_copy.md#exit-codes)
gives them.

## See also

* [dctl copy](dctl_copy.md) — add and update without ever removing. The safe verb.
* [dctl move](dctl_move.md) — transfer, then delete the *source*, never the destination.
* [dctl check](dctl_check.md) — see the differences between two sides without changing either.
* [dctl purge](dctl_purge.md) — remove a tree deliberately, rather than as a side effect of an empty source.
* [dctl delete](dctl_delete.md) — remove objects by filter, keeping the directory structure.
* [dctl restore](dctl_restore.md) — the command you need if a sync deleted the wrong thing.
