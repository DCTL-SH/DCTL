# dctl moveto

Move a single file or directory to an exact destination name.

## Synopsis

`dctl moveto` is [`copyto`](dctl_copyto.md)'s destination semantics with
[`move`](dctl_move.md)'s ordering guarantee. `DEST` names the **object** rather
than the directory it lands in, and the source is removed **only after** the
destination commit is durable.

```
dctl moveto scratch/render.mov vault:films/2024/final.mov
```

This is the verb for promoting a finished artefact out of a working directory
under its real name — the last step of a render pipeline, a build that ships, a
database dump that becomes the day's backup. It is also **the most dangerous
command in the transfer family at the single-file scale**: a wrong `DEST` moves
the only copy of something somewhere you did not intend. It is classified
destructive, it prompts under `--interactive`, and it refuses rather than
guesses when the argument shapes are ambiguous.

**The ordering is the product, and it is not re-implemented here.** It lives in
the same per-file pipeline `move` uses, so the two verbs cannot drift apart.
`PLAN.md` §6 step 7: after the commit is durable, delete the source. The
deletion sits on the far side of the transfer's result — the transfer must
return `Ok` before the deletion is even reachable — so a crash, a network
failure, a bad checksum or a Ctrl-C leaves the source file exactly where it was.
At every instant the process could be killed, the file is either still at the
source or durably committed at the destination.

"Durable commit" is a concrete thing in each direction. Into a vault it means
the object was sealed, written with a verified write and its index record
committed — `dctl-core` returns `Ok` only after all three. To a local path it
means the destination file was written and `fsync`ed to stable storage. Only
then does the removal become reachable.

* **A checksum mismatch aborts before the commit, so the source survives.** For
  a vault destination the comparison is inside the verified write. If the
  backend stored something other than what was sent, nothing is committed,
  nothing is deleted, and the run exits **20** (`checksum_mismatch`).
* **A file that transferred but whose source deletion failed is reported as an
  error.** The data is safe, but you now have two copies rather than one.
  Removal failures always name the side — `source render.mov` — so a failed
  destination write and a failed source removal are never confused.

**`DEST` is a name, not a container.** `dctl moveto render.mov vault:films`
would try to create an object literally called `films`; that is why an existing
directory destination is refused. Compare:

```
dctl move   render.mov vault:films            → vault:films/render.mov
dctl moveto render.mov vault:films/final.mov  → vault:films/final.mov
```

Those arrows describe the addressing that runs: a vault destination is reachable
and the whole path after the colon is applied, so the second line stores
`films/final.mov`. Both halves of that sentence used to say the opposite — see
*What runs today*.

**For a directory source the two coincide**, exactly as in `copyto`: a tree moved
under an exact name is a tree whose destination root is that name, and the
relative paths inside are preserved.

**Refused argument shapes**, each a usage error (exit 1) raised before anything
is transferred and long before anything could be deleted:

* **A `DEST` that names no object** — a bare `vault:` or `/`.
* **A `DEST` that already exists as a directory.** It cannot be both the
  object's name and the place the object goes.
* **Source and destination are the same file.** Without this guard, step 7 would
  delete what step 6 had just committed. Structural equality catches the obvious
  case and canonicalisation catches `render.mov` versus `./render.mov` and a
  symlinked duplicate.
* **The size filters excluded the single named file.** Transferring nothing and
  reporting success is the hardest failure to notice, so it is refused.

**A no-op moveto deletes nothing.** If the destination already holds a matching
object, the command says `nothing to move: the destination already matches` and
stops. Deleting the source on that basis alone would be a deletion the plan
never announced.

**Destructive classification.** Under `--interactive`, `moveto` asks before it
acts and requires the exact word `yes`; with no terminal available that is a
usage error rather than a hang. `--force` approves without asking. Note what the
default is: running without either flag does **not** prompt — typing the command
is taken as consent, because prompting by default would break every script. A
declined confirmation exits **25** (`cancelled`), never a silent zero.

**Comparison, filters and failure policy** are the family's, identical to
[`copyto`](dctl_copyto.md): nothing at the destination means copy;
`--ignore-existing` then `--update` can skip; otherwise size and modification
time decide by default with a one-second tolerance, content hashes under the
global `--checksum`, size alone under `--size-only`. `--max-depth`,
`--min-size` and `--max-size` are honoured, as are `--include`, `--exclude`,
`--filter-from` and `--files-from`, all through one engine. A skip is also a
non-deletion: the source is only ever removed for a
file whose own commit succeeded.

**`--dry-run` is authoritative and deletes nothing.** The plan is computed
without touching either side, a dry run returns before the confirmation and
before the reaper, and the same value is either printed or executed. A rename
shows both paths:

```
Action      Size  Path
------  --------  --------------------
copy    1.91 MiB  big.mov -> final.mov
```

### What runs today

**Between two local paths, `moveto` works end to end.** The file is written
under its new name, flushed to stable storage, and only then removed from the
source. A run that fails anywhere before that leaves the source where it was.

**Promoting into a vault works end to end.** `dctl moveto ./render.mov
archive:films/2024/final.mov` seals and commits the object at the full path it was
given, and only then removes the local file:

```console
$ dctl moveto ./render.mov archive:films/2024/final.mov
 Transferred: 11 B / 11 B, 100%
    Verified: 11 B checksum-matched
       Files: 1 / 1
$ ls render.mov
ls: render.mov: No such file or directory
$ dctl ls archive:
      11 B films/2024/final.mov
```

An earlier revision of this page said the reaper opened a second vault session,
hit the index's single-writer lock and stopped at connect time with exit **23** —
and recommended promoting in two steps instead. That defect is fixed; the
two-step workaround is no longer needed.

**Moving *out of* a vault works.** `dctl moveto archive:site-b/report.txt
./out2.txt` writes the plaintext locally and then removes the vault object, in
that order — the ordering guarantee applies to a vault source exactly as it does
to a local one. An earlier revision of this page said a `REMOTE:PATH` source
"cannot be planned" and stopped at exit **7**; that was true and stopped being
true without the page changing.

**Remote-to-remote is still refused**, and this one is real: a direct
vault-to-vault path needs the re-encrypting transfer `dctl-core` does not expose,
and a plain-to-plain path needs an engine holding two backends at once. Neither
is scheduled by `PLAN.md` §11.

The family's refusals apply unchanged, all exit **7** and all before anything is
deleted: a **plain write into a directory that holds a vault**, a file **above
the 1 GiB whole-file limit** (the core is whole-buffer; streaming is `PLAN.md`
§16.2), and **`--checksum`** against a plain object store, which cannot supply a
plaintext hash.
`--no-traverse` still skips the destination lookup, and therefore also skips the
"`DEST` is an existing directory" refusal.

`--immutable` **is** honoured, at plan time: if `DEST` already names an object
that would be replaced, the plan's single entry is an `update` and the run fails
with exit **7** before any byte moves, naming the path. It governs the
*destination* only and protects no source — deleting the source is what `moveto`
means; use `copyto` to leave it in place. `--immutable` with `--no-traverse` is a
usage error (exit **1**), because `--no-traverse` skips the destination lookup
and an unlisted destination cannot be checked for overwrites.

`--transfers`, `--bwlimit` and `--retries` are parsed and not consulted.

```
dctl moveto SOURCE DEST [flags]
```

## Examples

The stderr run summary and the structured `ERROR` log line are omitted below
except where they are the point.

Promote a finished render out of a scratch directory under its real name. The
source is removed only after the destination write is flushed to stable storage:

```console
$ dctl moveto ./scratch/render.mov /srv/films/2024/final.mov --force -v
1 to copy, 0 to update, 0 to delete, 0 unchanged (1.91 MiB)

 Transferred: 1.91 MiB / 1.91 MiB, 100%, 51 MiB/s
    Verified: 1.91 MiB checksum-matched
       Files: 1 / 1
      Checks: 1 / 1
      Errors: 0
     Elapsed: 0s
$ ls ./scratch/render.mov
ls: ./scratch/render.mov: No such file or directory
$ echo $?
0
```

The same promotion into a vault stops at connect time, with the render still in
`./scratch` — see *What runs today* for the two-step alternative:

```console
$ dctl moveto ./scratch/render.mov archive:final.mov --no-traverse --force
error: index database error: Database already open. Cannot acquire lock.
$ ls ./scratch/render.mov
./scratch/render.mov
$ echo $?
23
```

Preview it first — always, for this verb. The plan names both paths, which is
the thing to check:

```console
$ dctl moveto /mnt/render/big.mov /srv/archive/final.mov --dry-run -v
1 to copy, 0 to update, 0 to delete, 0 unchanged (1.91 MiB)
Action      Size  Path
------  --------  --------------------
copy    1.91 MiB  big.mov -> final.mov
```

Move a Windows build artefact under a versioned name. `D:\build\out.zip` is a
local path — a one-character prefix is a drive letter on every platform, so it
is never read as a remote called `D`:

```console
$ dctl moveto D:\build\out.zip E:\releases\apollo-2.1.0.zip --dry-run
```

A destination that is already a directory is refused, before anything is
deleted:

```console
$ dctl moveto render.mov /srv/films
error: '/srv/films' is a directory
warning: An exact-name transfer needs the destination's full object name. Use
'copy' to place the file inside a directory instead.
$ echo $?
1
```

Moving a file onto itself is refused. Without this guard, step 7 would delete
what step 6 had just committed:

```console
$ dctl moveto render.mov ./render.mov --force
error: source and destination are the same: render.mov
warning: A transfer onto itself would compare a tree against itself while
modifying it.
$ echo $?
1
```

Approving without a terminal. `--interactive` refuses rather than hanging, which
is what an unattended job needs; `--force` is the scriptable yes:

```console
$ dctl moveto ./scratch/dump.sql /srv/backups/2024-06-01.sql --interactive < /dev/null
error: cannot confirm 'move (deleting the source of)' on './scratch': no terminal available
warning: Pass --force to approve destructive actions non-interactively.
$ echo $?
1
```

Note that the prompt names `./scratch`, the source's **container**, not
`./scratch/dump.sql`. Plan paths are relative to a root, and the root of a
single-file transfer is the directory that holds it; the plan itself, which
`--dry-run` prints, names the file.

An already-matching destination is a success, and the source stays put. The
message is commentary, so it appears at `-v` and above:

```console
$ dctl moveto ./dump.sql /srv/archive/dump.sql --size-only -v
0 to copy, 0 to update, 0 to delete, 1 unchanged (0 B)
nothing to move: the destination already matches
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
| `<SOURCE>` | A local path, or `REMOTE:PATH`. Deleted only after a durable commit at the destination. |
| `<DEST>` | Named exactly: the object's full path, **not** the directory it goes in. |

There is deliberately no `--create-empty-src-dirs`, matching `copyto`.

`--ignore-existing` and `--update` are worth a second look here, because a skip
under `moveto` is also a non-deletion: a file the plan skips is neither
transferred nor removed from the source.

## Options inherited from parent commands

Every global flag is accepted; see [../GLOBAL_FLAGS.md](../GLOBAL_FLAGS.md) for
the full list. The ones that change what this command does:

| Flag | Effect here |
|------|-------------|
| `-n`, `--dry-run` | Print the plan and change nothing. Returns before the confirmation and before any deletion. |
| `--force` | Approves the destructive confirmation without prompting. Conflicts with `--interactive`. |
| `-i`, `--interactive` | Prompts before the move and requires typing `yes`. With no terminal, exits 1 rather than hanging. |
| `--checksum` | Compare content hashes instead of size and time. Refuses with exit 7 today when a hash is unavailable. Conflicts with `--size-only`. |
| `--size-only` | Compare size alone, ignoring timestamps. |
| `--verify <MODE>` | `checksum` (default) adds nothing to the verified write; `sample` and `strict` are identical today and re-read the uploaded object in full; against a filesystem destination all three do nothing. A failure at this stage is what keeps the source in place. |
| `--verify-samples <N>` | Parsed and **not consulted**: partial sampling does not exist yet. |
| `--immutable` | **Honoured at plan time** for the destination: an existing `DEST` makes the entry an `update`, which fails the run with exit **7** before anything moves. It does **not** protect the source — deleting it is what `moveto` means. Refused with `--no-traverse` (exit **1**). |
| `--format`, `--json` | Render the plan as a table, one JSON document, or one JSON Lines record per action. |
| `--min-size`, `--max-size` | Honoured. If they exclude the single named file, that is a usage error rather than a silent no-op. |
| `--include`, `--exclude`, `--filter-from`, `--files-from` | **Honoured.** A file excluded by a rule is not moved and not deleted. A rule file that cannot be read or parsed is a usage error (exit **1**) naming the file and the line, never a run with the rules dropped. |
| `--transfers`, `--bwlimit`, `--retries` | Parsed and **not consulted**. |
| `-P`, `--progress` | A per-file bar showing the real pipeline stage; a row at `verify` has been written but is not yet counted as stored, and its source is still in place. |

## Exit codes

See [../EXIT_CODES.md](../EXIT_CODES.md) for the full contract.

| Code | Name | When |
|------|------|------|
| 0 | `success` | The object was transferred and its source removed, or a `--dry-run` completed, or the destination already held a matching object. |
| 1 | `usage` | Unparseable command line; `DEST` names no object (a bare root); `DEST` is an existing directory; source and destination are the same file; the size filters excluded the single named file; an unparseable or unsatisfiable size range; `--interactive` with no terminal; `--immutable` together with `--no-traverse`. |
| 3 | `dir_not_found` | `SOURCE` does not exist. |
| 5 | `temporary_error` | A cloud backend failed in a way worth retrying; the source is untouched. Reachable wherever a cloud backend is contacted: reading a plain `b2:`/`s3:`/`r2:` source, writing a plain object into one, or a vault whose store is one of them. |
| 6 | `partial_failure` | A directory source finished with at least one file failing. A file that failed keeps its source; a file whose source removal failed exists twice, and the message names the side. |
| 7 | `fatal_error` | The file exceeded the whole-file limit; `DEST` is inside a local directory holding a vault; `--checksum` against a plain object store, which cannot supply a plaintext hash; both sides are remotes; `--immutable` and `DEST` already exists. Nothing was transferred and nothing was deleted. |
| 20 | `checksum_mismatch` | The backend stored the wrong bytes. Nothing was committed and the source is untouched. Not reachable today: no `moveto` reaches a vault transfer, and a local write has no second party to disagree with. |
| 21 | `integrity_failure` | `--verify sample`/`strict` could not authenticate what was written. The source is untouched; investigate before removing it by hand. Not reachable today, for the same reason as 20. |
| 22 | `vault_locked` | No password was available, or the envelope did not unwrap. Nothing was transferred or deleted. |
| 23 | `index_error` | The index database could not be opened or committed — including **every `moveto` into a vault today**; see *What runs today*. Nothing was transferred or deleted. |
| 25 | `cancelled` | The confirmation was declined, or the run was interrupted with Ctrl-C. Nothing was deleted. |

Exit 20 carries the specific promise: the destination stored the wrong bytes,
nothing was committed, and the source is untouched.

## See also

* [dctl copyto](dctl_copyto.md) — the same destination semantics, without deleting the source.
* [dctl move](dctl_move.md) — move *into* a container, keeping each object's own name.
* [dctl copy](dctl_copy.md) — the safe verb: add and update, never remove.
* [dctl deletefile](dctl_deletefile.md) — remove exactly one named object.
* [dctl verify](dctl_verify.md) — prove afterwards that what arrived is intact.
