# dctl move

Move files, deleting the source only after a verified, durable commit.

## Synopsis

`dctl move` is [`copy`](dctl_copy.md) plus one step: after each file is durably
committed at the destination, its source is deleted. Everything else — how
`SOURCE` and `DEST` are parsed, how the two sides are enumerated, which files
count as identical, what the plan looks like — is the same shared machinery, so
`move` and `copy` cannot drift apart about what needs transferring.

**The ordering is the product.** `PLAN.md` §6 step 7 reads: *after the commit is
durable, delete the source.* That single sentence is why a `move` interrupted by
a crash, a network failure, a bad checksum or a Ctrl-C leaves the source file
exactly where it was, and it is what makes DCTL safe to point at the only copy
of something.

The guarantee is encoded rather than documented. Source deletion happens on the
far side of the transfer's result, **per file**: the transfer must return `Ok`
before the deletion is even reachable, and there is no second pass over the plan
to batch the deletions into. At every instant the process could be killed, each
individual file is either still at the source or durably committed at the
destination. Never neither, and never "moved" on the strength of an upload that
had not yet been verified.

**What "durable commit" means concretely**, because the promise is only as good
as the thing it names:

* *Into a vault*, the file is sealed, written to the backend with a verified
  write — the stored object is compared against the hash of what was sent — and
  its index record is committed. `dctl-core` returns `Ok` only after the index
  commit, and only then does the source deletion become reachable. There is no
  window in which the object is stored but uncommitted.
* *To a local path*, the destination file is written and `fsync`ed to stable
  storage, and only then is the source removed. A power cut between the two
  leaves both copies, which is the direction that loses nothing.

Two consequences worth stating plainly:

* **A checksum mismatch aborts before the commit, so the source survives.** For
  a vault destination the comparison is inside the verified write, so a mismatch
  aborts during the upload — the index is never touched, nothing is deleted, and
  the run exits **20** (`checksum_mismatch`) rather than a generic error, so a
  script can tell corruption apart from a timeout.
* **A file that transferred but whose source deletion failed is reported as an
  error.** The data is safe, but the operator now has two copies rather than one
  and needs to know it. Failure messages for a removal always name the side —
  `source a.mov` — because for `move` the difference between a failed
  destination write and a failed source removal is the whole story. A source
  that was *already* gone is not an error: a retried `move` must not fail
  because the first attempt succeeded.

**`move` never deletes at the destination.** It adds to `DEST` and removes from
`SOURCE`. A file that exists only at the destination is left alone, exactly as
under `copy`. The verb that removes destination extras is
[`sync`](dctl_sync.md), and confusing the two is the mistake this separation
exists to prevent.

**Both arguments are containers**, as in `copy`. `dctl move ./scratch
vault:films/2024` moves the *contents* of `./scratch` under
`vault:films/2024`, preserving relative paths. A single-file `SOURCE` is allowed
and lands inside `DEST` under its own name. When `DEST` should be the object's
new name instead, use [`moveto`](dctl_moveto.md). A vault destination is not
reachable from `move` at all today — see *What runs today* — and the two ways
vault addressing still differs from the above are documented under
[copy's *What runs today*](dctl_copy.md#what-runs-today).

**Destructive classification.** `move` is registered as a destructive command,
which controls the confirmation gate: under `--interactive` it asks before it
acts, and `--force` approves without asking. Note what the default is — running
without either flag does **not** prompt. Typing the command is taken as consent,
because prompting by default would break every script. `--interactive` with no
terminal available is a usage error rather than a hang, which is what an
unattended job needs.

**A no-op move deletes nothing.** If every file is already at the destination,
the command says so and stops:

```
nothing to move: every file is already at the destination
```

Deleting the sources on that basis would be defensible, but it is not what the
plan said would happen — and a `move` that removes files without transferring
them is precisely the surprise this command exists not to spring. If you want
the sources gone regardless, remove them explicitly with
[`delete`](dctl_delete.md) or [`purge`](dctl_purge.md).

**Comparison, filters and failure policy** are the family's, identical to
[`copy`](dctl_copy.md): size and modification time by default with a one-second
tolerance, `--checksum` or `--size-only` to change it, `--ignore-existing` and
`--update` to skip — including the substitution a vault side forces, where the
default becomes a content comparison and the run warns why, which matters more
here than anywhere else because what this command does with "identical" is
delete the source; every filter honoured through one engine
(`--include`, `--exclude`, `--filter-from`, `--files-from`, `--min-size`,
`--max-size`, `--max-depth`); per-file failures counted and survived (exit 6), fatal
failures stopping the run. Symbolic links are never followed and are counted and
warned about — a link is not moved, and therefore is not deleted either.

**`--dry-run` is authoritative and deletes nothing.** The plan is computed
without touching either side, and the same value is either printed or executed.
A dry run never reaches the confirmation and never reaches the reaper.

### What runs today

**Filesystem to filesystem, `move` works end to end.** Each planned file is
read, written, flushed, and only then removed from the source. Files the plan
skipped keep their sources. That is the whole command, running for real.

**Moving *into a vault* does not work yet, and fails safely.** The upload path
itself is finished — [`copy`](dctl_copy.md) uses it — but `move` opens a second
vault session for its reaper, and the index database allows a single writer, so
the run stops at connect time with exit **23** (`index_error`):

```
error: index database error: Database already open. Cannot acquire lock.
warning: The index is a rebuildable cache: `dctl index rebuild` rescans object
headers.
```

That happens **before any file is transferred and before any source is
touched**, which is the outcome the ordering guarantee is supposed to produce
when something goes wrong. Until it is fixed, move into a vault in two steps:
`dctl copy` the tree up, verify it, then remove the source deliberately with
[`delete`](dctl_delete.md).

**Moving *out of* a vault plans and runs.** A `REMOTE:PATH` source is enumerated
through `crate::source`, the same reader `dctl ls` uses, so the listing and the
move agree about what is there; each object is fetched, authenticated, written
durably, and only then removed from the vault. Remote-to-remote is still refused
by the engine at connect time, naming which of two gaps applies: a sealed end
needs a re-encrypting transfer `dctl-core` does not expose (no `PLAN.md` §11
phase schedules one), and two plain ends need only a `dctl-cli` engine that
holds two backends (no phase names that either).

The refusals `copy` documents apply here unchanged, all exit **7** and all
before anything is deleted: a **plain write into a directory that holds a
vault**, a file **above the 1 GiB whole-file limit** (the whole-buffer core
would otherwise take the machine down; the limit disappears with streaming,
`PLAN.md` §16.2), and **`--checksum`** against a plain object store, whose
provider checksum is not the plaintext hash a vault records. The oversized-file refusal is fatal, so files earlier in plan order
have already been moved — sources and all — and nothing after it is attempted.

`--immutable` **is** honoured, at plan time: a plan containing an `update` — an
existing destination object being replaced — fails the whole run with exit **7**
before any byte moves, and the message names the paths. It governs the
*destination* only. It does not protect the source, whose removal is what `move`
means; use `copy` for a transfer that leaves the source in place. `--immutable`
with `--no-traverse` is a usage error (exit **1**), because an unlisted
destination cannot be checked for overwrites.

`--transfers`, `--bwlimit` and `--retries` are parsed and not consulted. Files
move one at a time.

```
dctl move SOURCE DEST [flags]
```

## Examples

The stderr run summary and the structured `ERROR` log line are omitted below
except where they are the point.

Move finished renders between two local trees. Each file's source is removed
only after that file's destination write is flushed to stable storage, so an
interrupted run leaves the remainder in `./scratch/renders`:

```console
$ dctl move ./scratch/renders /srv/archive/renders --progress -v
2 to copy, 0 to update, 0 to delete, 0 unchanged (1.91 MiB)

 Transferred: 1.91 MiB / 1.91 MiB, 100%, 44 MiB/s
    Verified: 1.91 MiB checksum-matched
       Files: 2 / 2
      Checks: 2 / 2
      Errors: 0
     Elapsed: 0s
$ ls ./scratch/renders
$ echo $?
0
```

Moving into a vault stops at connect time, with both copies intact — see *What
runs today* for the two-step alternative:

```console
$ dctl move ./scratch/renders archive: --no-traverse --force
error: index database error: Database already open. Cannot acquire lock.
$ ls ./scratch/renders
a1.mov  a2.mov
$ echo $?
23
```

Always preview a move. `--dry-run` computes the same plan the real run would
execute and touches neither side:

```console
$ dctl move /mnt/ingest /srv/archive/ingest --dry-run -v
2 to copy, 0 to update, 0 to delete, 1 unchanged (1.91 MiB)
Action      Size  Path
------  --------  ---------
copy    1.91 MiB  big.mov
copy         3 B  sub/b.txt
```

Note that the plan shows no `delete` rows. The source removals are not plan
entries — they are step 7 of each transfer, and they happen only for the files
the plan lists as `copy` or `update`. The one `unchanged` file above is skipped,
and its source is therefore not deleted.

Move from a Windows staging drive. A one-character prefix is a drive letter on
every platform, so `D:\ingest\2024-06-01` is a local path and never a remote
called `D`:

```console
$ dctl move D:\ingest\2024-06-01 D:\archive\2024-06-01 --dry-run
```

Approve a destructive run without a terminal. `--interactive` prompts and
requires typing `yes`; with stdin not attached to a terminal it refuses rather
than hanging, which is what an unattended job needs:

```console
$ dctl move /mnt/ingest /srv/archive/ingest --interactive < /dev/null
error: cannot confirm 'move (deleting the source of) files from' on '/mnt/ingest': no terminal available
warning: Pass --force to approve destructive actions non-interactively.
$ echo $?
1
```

```console
$ dctl move /mnt/ingest /srv/archive/ingest --force
```

Nothing to move is a success, and it leaves the sources alone:

```console
$ dctl move /srv/staging /srv/archive --size-only -v
0 to copy, 0 to update, 0 to delete, 1 unchanged (0 B)
nothing to move: every file is already at the destination
$ echo $?
0
```

A file too large for the whole-buffer engine is refused rather than attempted,
and the refusal is fatal — so `a-small.txt`, earlier in plan order, has already
been moved and removed from the source, while everything after `z-huge.bin` is
untouched on both sides:

```console
$ dctl move /mnt/ingest /srv/archive --force
error: 'z-huge.bin' is 2147483648 bytes, above the 1073741824 byte whole-file limit
warning: The current engine moves whole files through memory, so very large
objects are refused rather than attempted. Streaming transfers (PLAN.md §6,
§16.2) lift this limit. Use --dry-run to see exactly what would be transferred.
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
| `<SOURCE>` | A local path, or `REMOTE:PATH`. Deleted only after a durable commit at the destination. |
| `<DEST>` | A local path, or `REMOTE:PATH`. Its existing contents are never removed. |

`--ignore-existing` and `--update` deserve a second look here, because under
`move` a skip is also a *non-deletion*: a file the plan skips is neither
transferred nor removed from the source. That is the intended reading — the
source is only ever deleted for a file whose own commit succeeded.

## Options inherited from parent commands

Every global flag is accepted; see [../GLOBAL_FLAGS.md](../GLOBAL_FLAGS.md) for
the full list. The ones that change what this command does:

| Flag | Effect here |
|------|-------------|
| `--force` | Approves the destructive confirmation without prompting. Conflicts with `--interactive`. |
| `-i`, `--interactive` | Prompts before the move and requires typing `yes`. With no terminal, exits 1 rather than hanging. |
| `-n`, `--dry-run` | Print the plan and change nothing. Returns before the confirmation and before any deletion. |
| `--checksum` | Compare content hashes instead of size and time. Refuses with exit 7 today when a hash is unavailable. Conflicts with `--size-only`. |
| `--size-only` | Compare size alone, ignoring timestamps. |
| `--verify <MODE>` | `checksum` (default) adds nothing to the verified write; `sample` and `strict` are identical today and re-read every uploaded object in full; all three do nothing on a filesystem destination. A failure at this stage is what keeps the source in place. See [copy](dctl_copy.md) for the detail. |
| `--verify-samples <N>` | Parsed and **not consulted**: partial sampling does not exist yet. |
| `--immutable` | **Honoured at plan time** for the destination: any `update` fails the run with exit **7** before anything moves, naming the paths. It does **not** protect the source — deleting it is what `move` means. Refused with `--no-traverse` (exit **1**). |
| `--format`, `--json` | Render the plan as a table, one JSON document, or one JSON Lines record per action. |
| `--min-size`, `--max-size`, `--max-depth` | Honoured by the walk. A file excluded by a filter is not moved and not deleted. |
| `--include`, `--exclude`, `--filter-from`, `--files-from` | **Refused** with exit 7, not ignored. |
| `--transfers`, `--bwlimit`, `--retries` | Parsed and **not consulted**. Files move one at a time, unshaped and unretried. |
| `-P`, `--progress` | Per-file bars showing the real pipeline stage; a row at `verify` has been written but is not yet counted as stored, and its source is still in place. |

## Exit codes

See [../EXIT_CODES.md](../EXIT_CODES.md) for the full contract.

| Code | Name | When |
|------|------|------|
| 0 | `success` | Every planned file was transferred and its source removed, or a `--dry-run` completed, or every file was already at the destination so there was nothing to move. |
| 1 | `usage` | Unparseable command line; an empty spec or one containing `..`; source and destination are the same place; `DEST` is an existing file rather than a directory; an unparseable or unsatisfiable size range; `--interactive` with no terminal to prompt on; `--immutable` together with `--no-traverse`. |
| 3 | `dir_not_found` | `SOURCE` does not exist. |
| 5 | `temporary_error` | A cloud backend failed in a way worth retrying; that source is not deleted. Reachable wherever a cloud backend is contacted: reading a plain `b2:`/`s3:`/`r2:` source, writing a plain object into one, or a vault whose store is one of them. |
| 6 | `partial_failure` | The run finished with at least one failure. A file that failed to transfer keeps its source; a file that transferred but whose source removal failed exists twice, and the message names the side. |
| 7 | `fatal_error` | A file exceeded the whole-file limit; `DEST` is a local directory holding a vault; `--checksum` against a plain object store, which cannot supply a plaintext hash; both sides are remotes; `--immutable` and the plan would replace something at the destination. Files completed before the refusal are moved and nothing after it is attempted — except the `--immutable` refusal, which happens before any file is touched. |
| 20 | `checksum_mismatch` | The backend stored the wrong bytes. Nothing was committed and that source is untouched. Not reachable today: no `move` reaches a vault transfer, and a local write has no second party to disagree with. |
| 21 | `integrity_failure` | `--verify sample`/`strict` could not authenticate what was written. The source is untouched; investigate before deleting it by hand. Not reachable today, for the same reason as 20. |
| 22 | `vault_locked` | No password was available, or the envelope did not unwrap. Nothing was transferred and nothing was deleted. |
| 23 | `index_error` | The index database could not be opened or committed — including **every move into a vault today**; see *What runs today*. Nothing was transferred and nothing was deleted. |
| 25 | `cancelled` | An interactive confirmation was declined, or the run was interrupted with Ctrl-C. Nothing further was deleted. |

Exit 20 is the one that carries the specific promise: the destination stored the
wrong bytes, nothing was committed, and the source is untouched.

## See also

* [dctl copy](dctl_copy.md) — the same transfer without the source deletion.
* [dctl moveto](dctl_moveto.md) — move one thing to an exact destination name.
* [dctl sync](dctl_sync.md) — make the destination identical, deleting destination extras.
* [dctl delete](dctl_delete.md) — remove objects without transferring them anywhere.
* [dctl verify](dctl_verify.md) — prove afterwards that what arrived is intact.
