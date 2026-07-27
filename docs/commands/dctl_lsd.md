# dctl lsd

List directories only.

## Synopsis

`dctl lsd` answers "what is in here" before you decide where to look. It shows
directories and no objects, one level deep by default, with a byte total and an
object count beside each one:

```
  4.31 GiB     1,204 photos/
  88.0 MiB        19 documents/
  1.20 GiB         1 video/
```

The columns are the total size of everything beneath the directory, the number
of objects beneath it, and the directory path with a trailing `/`. rclone prints
`-1` in both numeric columns, having never computed them. DCTL computes them,
because it costs one addition per object on a pass it was making anyway, and
because a size column that always reads `-1` is a column of nothing.

A directory's total is `-` (and `"Size": null` in JSON) when **any** object
beneath it has no recorded size — the state of every row straight after
`dctl index rebuild`, which lists object names without reading their bodies. The
absence is absorbing rather than skipped: a total that quietly omitted the
unmeasured children would be short by an unknown amount and would still look
complete, which is the same misreport a zero was with better manners. The object
count is unaffected, so the row still says the directory is not empty.

### Directories do not exist

An object store has no directories. `photos/2024/IMG_4417.CR3` is one key with
two slashes in it, and every row `lsd` prints is a directory DCTL decided
existed because some object's path implied it. Two consequences surprise people
often enough to state plainly:

* **A directory containing no objects does not appear**, because nothing implies
  it. There is no such thing as an empty directory in a vault, and `lsd` will
  not invent one — nor does anything else in DCTL. [`dctl mkdir`](dctl_mkdir.md)
  does **not** write a `.dctl-dir` marker to make one visible: a marker is an
  object like any other, so `ls`, `size`, `check`, `sync` and a restore would all
  carry it as data, and fabricating a file to simulate a directory is a larger
  misreport than the absence it hides. On a vault `mkdir` therefore creates
  nothing and says so; a prefix appears here the moment an object is stored under
  it. (A marker written by an older build or by another object-store tool is
  still *recognised* by [`rmdir`](dctl_rmdir.md), which is why the name still
  exists in the code.)
* **The totals are recursive.** `photos` reports every byte under it, including
  those in `photos/2024`, which is what the question means when a human asks it.

Parents always print before their children even though a directory's totals are
only known once its whole subtree has been read; the buffering that makes that
possible holds directories, never objects, and only those inside the one
top-level subtree currently open.

### Depth

The default is one level (`LSD_DEFAULT_DEPTH`), because a recursive directory
listing of a real vault is not something anyone reads.

* `-R` / `--recursive` removes the limit entirely.
* The global `--max-depth N` sets it to anything in between, and **wins over
  `-R`** — a user who named a number meant it, even alongside `--recursive`.
* `--max-depth 0` asks for the levels above the top one, of which there are
  none, and correctly reports nothing.

**The depth bounds what is reported, not what is counted.** `--max-depth 1`
means "report the top level", not "ignore anything below it": every object at
every depth still contributes its bytes to the directory that is shown.
Otherwise a top-level directory whose files all live two levels down would
report as empty, which is the sort of answer people act on. This is also why the
global `--max-depth` is not applied to the object stream here — `lsd` has to see
deep objects in order to know the shallow directory exists at all.

### Scope

Everything else is shared with the rest of the listing family, so `lsd`,
[`ls`](dctl_ls.md) and [`size`](dctl_size.md) agree about the same vault by
construction: `--include`/`--exclude` globs with exclusion winning,
`--min-size`/`--max-size`, and the same `REMOTE:PATH` grammar. Size limits apply
to **objects only** and never to a synthesised directory — excluding a directory
because its recursive total exceeded `--max-size` would hide every small file
inside it. `--filter-from` and `--files-from` are refused rather than ignored
(exit 7).

Under `--json` or `--format json-lines`, each directory is emitted as the same
record shape the rest of the family uses, with `"IsDir": true`, `Size` carrying
the recursive byte total (or `null` when any object beneath it has no recorded
size), `ModTime` null (a directory has no modification time
of its own) and `Hashes` empty (it has no content to hash). The object *count*
is not in the JSON shape; use `Size` plus a `dctl ls … | wc -l` if you need
both, or read the text output.

### Writes, commits and empty results

`lsd` writes nothing, commits nothing and never sends bytes to a provider, so a
checksum mismatch is not among its failure modes. The half of the verified-write
contract it does keep is the reporting half: a directory listing that cannot
reach the index **fails**, loudly and non-zero, rather than rendering as "there
are no directories here". The two are not the same claim and must never produce
the same output (`PLAN.md` §6).

When nothing is found, `lsd` distinguishes three cases on stderr (visible with
`-v`): objects were found but all sit at the top level and imply no directory at
all; objects existed but the active filters excluded them; or there is nothing
under the path. Those notes never touch stdout.

`--dry-run` has nothing to suppress here.

### Status in this build

**`dctl lsd` cannot read a vault in this build.** The directory inference, the
recursive totals, the depth rules, the ordering contract and both output
formats are implemented and unit-tested; the index read is not, because the
runtime context does not yet carry an unlocked vault handle. A complete
invocation fails with

```
error: vault:photos: reading the object index is not implemented in this build
warning: The listing pipeline is complete; what is missing is the vault handle, which Ctx does not carry yet. See PLAN.md §11.
```

and exit code **7**, never with an empty listing. `PLAN.md` §11 delivers the
index in **Phase 1 (B2 MVP)**.

```
dctl lsd [REMOTE:PATH] [flags]
```

## Examples

The listings below are what the renderer produces. In this build every complete
invocation stops at the index read described under *Status in this build* and
prints the exit-7 error instead.

See the top level of a vault — the usual first command against an unfamiliar
one:

```
dctl lsd vault:
  4.31 GiB     1,204 photos/
  88.0 MiB        19 documents/
  1.20 GiB         1 video/
```

Descend into one subtree. Paths are relative to the spec, and the totals are
still recursive:

```
dctl lsd vault:photos
  1.42 GiB       412 2023/
  2.89 GiB       792 2024/
```

Walk every level. `-R` removes the depth limit; parents print before their
children:

```
dctl lsd b2prod:bucket/media -R
  18.4 GiB     6,102 raw/
  12.1 GiB     4,008 raw/2024/
  6.30 GiB     2,094 raw/2025/
```

Two levels rather than all of them. An explicit `--max-depth` beats `-R`, so
this is the safe way to bound a script that also passes `--recursive`:

```
dctl lsd vault:photos --max-depth 2
```

Find which directories hold the raw files, without listing the files. The filter
applies to objects; the directory rows are then whatever those objects imply:

```
dctl lsd vault:photos -R --include "*.CR3"
```

Read the totals as structured data. Each row is a record with `IsDir` true and
`Size` carrying the recursive byte total:

```
dctl lsd vault: --json | jq -r '.[] | "\(.Size)\t\(.Path)"'
```

A Windows path is local — `C:` is a drive letter, never a remote named `C`, on
every platform — and is refused rather than quietly listing something else:

```
dctl lsd C:\Users\mx\Pictures
error: listing a local directory is not implemented in this build
warning: Give a remote spec such as 'vault:photos' instead of a filesystem path.
```

## Options

```
  -h, --help       help for lsd
  -R, --recursive  Show directories at every depth, not just the top level
```

The positional argument is `[REMOTE:PATH]`, optional, falling back to
`--remote`. `-V, --version` is propagated to every subcommand.

## Options inherited from parent commands

Every global flag is accepted. `--max-depth` is the one to know: it overrides
both the default depth of one *and* `--recursive`. The filters
`--include` / `--exclude` / `--min-size` / `--max-size` shape the object stream
that the directory rows are derived from (`--filter-from` and `--files-from` are
refused); `--format` / `--json` / `--units` shape the output; `-v` decides
whether the "nothing found" notes appear on stderr. See
[../GLOBAL_FLAGS.md](../GLOBAL_FLAGS.md) for the full list.

## Exit codes

| Code | Name | When |
|-----:|------|------|
| 0 | `success` | The directory listing was printed, including when it was legitimately empty. Not reachable in this build. |
| 1 | `usage` | No path and no `--remote`; an illegal or too-short remote name; a `..` component; a malformed pattern or size value; an unknown flag or a second positional. |
| 2 | `uncategorised` | A stdout write failed for a reason other than a broken pipe. A broken pipe is success. |
| 5 | `temporary_error` | The provider could not be reached and the retry budget was exhausted. Needs the engine work below. |
| 7 | `fatal_error` | Returned by every complete invocation in this build, by a local target, and by `--filter-from`/`--files-from`. |
| 22 | `vault_locked` | Wrong password or second factor, or a damaged envelope. Needs the engine work below. |
| 23 | `index_error` | The encrypted index or its journal could not be read. Needs the engine work below. |
| 25 | `cancelled` | Ctrl-C or SIGTERM. A partially-drawn listing is never reported as complete. |

In this build only **1**, **2**, **7** and **25** are reachable. See
[../EXIT_CODES.md](../EXIT_CODES.md) for the full contract.

## See also

* [dctl ls](dctl_ls.md) — the objects themselves, with sizes.
* [dctl tree](dctl_tree.md) — the same inferred directories drawn as nesting;
  `dctl tree --dirs-only` is the picture version of this command.
* [dctl size](dctl_size.md) — one pair of totals for a whole subtree.
* [dctl lsjson](dctl_lsjson.md) — the machine-readable listing.
* [dctl mkdir](dctl_mkdir.md) — why creating a directory in an object store is
  not what it looks like.
* [dctl rmdirs](dctl_rmdirs.md) — removing directories that hold nothing.
