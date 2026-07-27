# dctl copyto

Copy a single file or directory to an exact destination name.

## Synopsis

`dctl copyto` differs from [`copy`](dctl_copy.md) in exactly one thing: what
`DEST` means. `copy` treats it as a **container**; `copyto` treats it as the
object's **name**.

```
dctl copy   report.pdf vault:archive           → vault:archive/report.pdf
dctl copyto report.pdf vault:archive/2024.pdf  → vault:archive/2024.pdf
```

That makes `copyto` the verb for "upload this and call it that" — the one a
backup script reaches for when the destination name carries a date, a build
number or a content hash. It is the same distinction as `cp` versus `cp` with an
explicit target filename, and the same one rclone draws. Those arrows describe
the addressing that runs: the path after the colon is applied to the stored key,
so `dctl copyto ./report.txt archive:deep/nested/r.txt` stores
`deep/nested/r.txt`. An earlier revision of this page said the prefix was not yet
applied, which stopped being true without the page changing.

**For a directory source the two verbs coincide.** A tree copied under an exact
name is just a tree whose destination root is that name, so `dctl copyto ./site
vault:releases/v2.1` places `./site/index.html` at
`vault:releases/v2.1/index.html` and behaves exactly like `copy` from there on,
relative paths and all. The interesting case is a single file, where `DEST`'s
last component becomes the object's name and the directory above it becomes the
destination root.

**Two argument shapes are refused outright**, because neither has a defensible
reading:

* **A `DEST` that names no object** — a bare `vault:` or `/`. An exact-name
  transfer needs a full destination path; inventing a name would put the object
  somewhere the user never wrote.
* **A `DEST` that already exists as a directory.** It cannot be both the
  object's name and the place the object goes. The hint points at `copy`, which
  is the verb that means "put it inside this directory".

Both are usage errors (exit 1), raised before anything is transferred.

**`copyto` is not destructive** in DCTL's classification: it never removes a
file. It will, however, **overwrite** the object `DEST` names if one is already
there and the comparison says it differs — the plan calls that an `update`
rather than a `copy`, and `--dry-run` shows it as such. If you want it to leave
an existing object alone, `--ignore-existing` skips by presence without
comparing, and `--update` skips when the destination is newer.

**Comparison rules** are the family's, applied to the single named object rather
than to a matched pair from two listings: nothing at the destination means copy;
`--ignore-existing` then `--update` can skip; otherwise size and modification
time decide by default (with a one-second tolerance), content hashes under the
global `--checksum`, size alone under `--size-only`.

**The verified-write contract** is the family's, unchanged, and
[`copy`](dctl_copy.md) documents it in full. Into a vault: seal, verified write
— the stored object compared against the hash of what was sent — then the index
commit, which is the only thing that makes the object count as stored. To a
local path: write, then `fsync`, then report success. A mismatch between what
was sent and what the backend stored aborts before the index commit, so nothing
is committed, nothing is reported as transferred, and the run exits **20**
(`checksum_mismatch`) rather than a generic error.

`--verify` is worth reading precisely rather than by name: `checksum` (the
default) adds nothing to that write; `sample` and `strict` are identical today
and both re-read the whole object back, decrypt it and compare its plaintext
hash with the index record, failing with exit **21** (`integrity_failure`);
`--verify-samples` is parsed and not consulted, because partial sampling does
not exist yet. Against a filesystem destination none of the three does anything
— there is no second party holding a checksum to disagree with.

**Filters.** `--max-depth`, `--min-size` and `--max-size` are evaluated for real.
There is a specific consequence for a single-file `copyto`: if the size filters
exclude the one file that was named, the command fails with a usage error rather
than transferring nothing and reporting success. Silently doing nothing is the
hardest failure to notice, so it is refused. The pattern filters — `--include`,
`--exclude`, `--filter-from`, `--files-from` — are honoured through the same
engine the whole family uses; see [`sync`](dctl_sync.md) for why one engine
answering for both sides is what makes them safe.

**`--dry-run` is authoritative.** The plan is computed without touching either
side, and the same value is either printed or executed. A renamed transfer shows
both paths, which is exactly what needs reviewing:

```
Action      Size  Path
------  --------  ---------------------------
copy    1.91 MiB  big.mov -> archive-2024.mov
```

### What runs today

**`copyto` transfers real bytes**, in every direction `copy` reaches:
filesystem to filesystem, filesystem into a vault, and a vault back out to the
filesystem. A renamed local copy is read, written and flushed; an upload is
sealed, written with the verified write and committed to the index, after the
password is acquired once at connect time.

`--no-traverse` is **not** required for a vault destination any more: listing a
vault works, so the destination is planned against what is actually stored. The
flag still does what it says — skip the destination listing entirely — and is
still the way to avoid the read-and-hash cost the vault comparison otherwise
pays.

A vault **source** is planned and downloaded: `dctl copyto archive:site-a/report.txt
./out.txt` writes the plaintext, and `dctl moveto` removes the vault object after
the local write is durable. Earlier revisions of this page said a `REMOTE:PATH`
source "cannot be planned at all" and stopped at exit **7**; that was true and
stopped being true without the page changing.

**Remote to remote is still refused**, in both directions, and this one is real:
a direct vault-to-vault path needs the re-encrypting transfer `dctl-core` does
not expose, and a plain-to-plain path needs an engine that holds two backends at
once. Neither is scheduled by `PLAN.md` §11.

**Addressing a vault applies the whole path.** `dctl copyto ./dump.sql
archive:backups/day.sql` stores `backups/day.sql` — the directory above the name
is honoured along with the name. An earlier revision said only the **last
component** was kept and the rest silently dropped at the vault root, which was a
real defect and is fixed. See
[copy's *What runs today*](dctl_copy.md#what-runs-today) for the history, which is
worth reading before trusting any remaining addressing claim on this page.

The family's data-safety refusals apply unchanged, all exit **7**: a **plain
write into a directory that holds a vault**, a file **above the 1 GiB whole-file
limit** (the core is whole-buffer; streaming is `PLAN.md` §16.2), and
**`--checksum`** when no hashes are available. Pattern filters are *not* on that
list any more — they are honoured, as the Synopsis says.

`--immutable` **is** honoured, at plan time: if `DEST` already names an object
that would be replaced, the plan's single entry is an `update` and the run fails
with exit **7** before any byte moves, naming the path. A `DEST` that does not
exist yet is an addition and still transfers. `--immutable` with `--no-traverse`
is a usage error (exit **1**), because `--no-traverse` skips the destination
lookup entirely and an unlisted destination cannot be checked for overwrites.

`--transfers`, `--bwlimit` and `--retries` are parsed and not consulted.

```
dctl copyto SOURCE DEST [flags]
```

## Examples

The stderr run summary and the structured `ERROR` log line are omitted below
except where they are the point.

Write a local file out under a name that carries the date. This is the case
`copyto` exists for — `copy` would have written
`/srv/backups/dump.sql` instead:

```console
$ dctl copyto ./dump.sql /srv/backups/2024-06-01-dump.sql -v
1 to copy, 0 to update, 0 to delete, 0 unchanged (4.10 MiB)

 Transferred: 4.10 MiB / 4.10 MiB, 100%, 60 MiB/s
    Verified: 4.10 MiB checksum-matched
       Files: 1 / 1
      Checks: 1 / 1
      Errors: 0
     Elapsed: 0s
$ echo $?
0
```

The same thing into a vault — here the one in `./archive`. `--no-traverse` is
required because the destination cannot be listed, and the object is stored
under the destination's **last component**: `2024-06-01-dump.sql` at the vault
root, not `backups/2024-06-01-dump.sql`. See *What runs today*:

```console
$ dctl copyto ./dump.sql archive:backups/2024-06-01-dump.sql --no-traverse \
    --password-command 'pass dctl'
```

Preview a rename. The plan shows both paths, so what is being renamed to what is
reviewable before it happens:

```console
$ dctl copyto /mnt/render/big.mov /srv/archive/archive-2024.mov --dry-run -v
1 to copy, 0 to update, 0 to delete, 0 unchanged (1.91 MiB)
Action      Size  Path
------  --------  ---------------------------
copy    1.91 MiB  big.mov -> archive-2024.mov
```

Copy a Windows build output under a versioned name. `C:\build\out.zip` is a
local path — a one-character prefix is a drive letter on every platform, so it
is never read as a remote called `C`:

```console
$ dctl copyto C:\build\out.zip D:\releases\apollo-2.1.0.zip --dry-run
```

A directory source keeps its relative paths, exactly as `copy` would. Here
`DEST` becomes the tree's root:

```console
$ dctl copyto ./site vault:releases/v2.1 --dry-run --no-traverse
Action  Size  Path
------  ----  ------------
copy     2 B  css/site.css
copy     1 B  index.html
```

Plan rows are sorted by path, so a plan printed twice from the same inputs is
byte-identical and a diff of two dry runs shows only what actually changed.

A destination that is already a directory is refused. It cannot be both the
object's name and its container:

```console
$ dctl copyto report.pdf /srv/archive
error: '/srv/archive' is a directory
warning: An exact-name transfer needs the destination's full object name. Use
'copy' to place the file inside a directory instead.
$ echo $?
1
```

A destination that names nothing is refused for the same reason in reverse. This
check runs before the destination is looked up, so it fires even against a
remote:

```console
$ dctl copyto report.pdf vault:
error: 'vault:' does not name an object
warning: An exact-name transfer needs a full destination path, such as
'vault:archive/2024.tar'.
$ echo $?
1
```

An already-matching destination is a success with nothing to do. The message is
commentary, so it appears at `-v` and above:

```console
$ dctl copyto ./dump.sql /srv/archive/dump.sql --size-only -v
0 to copy, 0 to update, 0 to delete, 1 unchanged (0 B)
nothing to transfer: the destination already matches
$ echo $?
0
```

## Options

```
      --ignore-existing  Skip files that already exist at the destination, without comparing them
      --update           Skip files where the destination is newer than the source
      --no-traverse      Do not list the destination; assume every source file is missing there
  -h, --help             Print help (see more with '--help')
  -V, --version          Print version
```

Positional arguments:

| Argument | Meaning |
|----------|---------|
| `<SOURCE>` | A local path, or `REMOTE:PATH`. A file or a directory. |
| `<DEST>` | Named exactly: the object's full path, **not** the directory it goes in. |

There is deliberately **no `--create-empty-src-dirs`**: rclone does not offer it
on this command, and an exact-name transfer of a single file has no directories
to recreate.

`--no-traverse` skips the destination lookup, which for `copyto` means the
existing object is never examined — every source file is planned as a copy with
the reason `destination-not-listed`, and the "`DEST` is an existing directory"
refusal cannot fire.

## Options inherited from parent commands

Every global flag is accepted; see [../GLOBAL_FLAGS.md](../GLOBAL_FLAGS.md) for
the full list. The ones that change what this command does:

| Flag | Effect here |
|------|-------------|
| `-n`, `--dry-run` | Print the plan and change nothing. Complete and trustworthy today. |
| `--checksum` | Compare content hashes instead of size and time. Refuses with exit 7 today when a hash is unavailable. Conflicts with `--size-only`. |
| `--size-only` | Compare size alone, ignoring timestamps. |
| `--verify <MODE>` | `checksum` (default) adds nothing to the verified write; `sample` and `strict` are identical today and re-read the uploaded object in full; against a filesystem destination all three do nothing. |
| `--verify-samples <N>` | Parsed and **not consulted**: partial sampling does not exist yet. |
| `--password`, `--password-command`, `--password-file`, `--no-ask-password` | How the vault password is acquired, once, before the transfer. Only a vault destination needs one; nothing available exits **22**. |
| `--index <PATH>` | The index database the vault commit is written to. |
| `--format`, `--json` | Render as a table, one JSON document, or one JSON Lines record per action. Both JSON forms carry a `result` object on a **real** run — the executor's own counters, including `errors` — so what was attempted can be told from what was achieved. |
| `--min-size`, `--max-size` | Honoured. If they exclude the single named file, that is a usage error rather than a silent no-op. |
| `--max-depth` | Honoured for a directory source. |
| `--include`, `--exclude`, `--filter-from`, `--files-from` | **Honoured.** A rule file that cannot be read or parsed is a usage error (exit **1**) naming the file and the line, never a run with the rules dropped. |
| `--transfers`, `--bwlimit`, `--retries` | Parsed and **not consulted**. |
| `--immutable` | **Honoured at plan time.** A `DEST` that already exists makes the entry an `update`, which fails the run with exit **7** before anything moves. A `DEST` that does not exist yet still transfers. Refused with `--no-traverse` (exit **1**). |
| `-P`, `--progress` | A per-file bar showing the real pipeline stage. |

`--force` and `--interactive` have no effect: `copyto` is not classified
destructive and never asks for confirmation. It can still overwrite the object
`DEST` names, so review the plan rather than relying on a prompt.

## Exit codes

See [../EXIT_CODES.md](../EXIT_CODES.md) for the full contract.

| Code | Name | When |
|------|------|------|
| 0 | `success` | The object was transferred, or a `--dry-run` completed, or the destination already held a matching object. |
| 1 | `usage` | Unparseable command line; `DEST` names no object (a bare root); `DEST` is an existing directory; source and destination are the same place; the size filters excluded the single named file; an unparseable or unsatisfiable size range; `--immutable` together with `--no-traverse`. |
| 3 | `dir_not_found` | `SOURCE` does not exist. |
| 5 | `temporary_error` | A cloud backend failed in a way worth retrying. Reachable wherever a cloud backend is contacted: reading a plain `b2:`/`s3:`/`r2:` source, writing a plain object into one, or a vault whose store is one of them. |
| 6 | `partial_failure` | A directory source finished with at least one file failing. |
| 7 | `fatal_error` | The file exceeded the whole-file limit; `DEST` is inside a local directory holding a vault; `--checksum` against a plain object store, which cannot supply a plaintext hash; both sides are remotes; `--immutable` and `DEST` already exists, which is refused before any byte moves. |
| 20 | `checksum_mismatch` | The backend stored bytes other than the ones sent. Nothing was committed. |
| 21 | `integrity_failure` | `--verify sample`/`strict` could not authenticate what was written. |
| 22 | `vault_locked` | No password was available, or the envelope did not unwrap. |
| 23 | `index_error` | The index database could not be opened or committed. |
| 25 | `cancelled` | The run was interrupted with Ctrl-C or SIGTERM. |

## See also

* [dctl copy](dctl_copy.md) — copy *into* a container, keeping each object's own name.
* [dctl moveto](dctl_moveto.md) — the same destination semantics, then delete the source.
* [dctl move](dctl_move.md) — move into a container.
* [dctl rcat](dctl_rcat.md) — write standard input to an exact object name.
* [dctl cat](dctl_cat.md) — read one object's contents back out.
