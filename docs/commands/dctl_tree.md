# dctl tree

Show the object tree.

## Synopsis

`dctl tree` is the listing you read when you are trying to *understand* a vault
rather than process it. Same scope rules as every other listing verb — same
filters, same ordering, same relative paths — rendered as nesting instead of as
rows:

```
vault:photos
├── 2024/
│   ├── IMG_4417.CR3
│   └── IMG_4418.CR3
└── 2025/
    └── IMG_0031.CR3
```

The first line is the label: the spec exactly as it was typed, so a tree pasted
into a ticket says which vault and which subtree it came from. A target with
nothing to name falls back to `.`. Everything below it is drawn from the objects
the index holds; the directories are inferred, because an object store has none.

Children are sorted **by name**, not in the order the index yields them. Path
order puts `b.txt` before `b/` — `.` sorts below `/` — and a tree that echoed
that would look like a rendering fault even though it is a faithful echo of the
index.

### Two dials of its own

* **`-d` / `--dirs-only`** drops the objects and leaves the shape. On a real
  dataset this is the form that stays readable.
* **`-L N` / `--level N`** bounds the depth; `-1` (the default) is unlimited.
  It **composes with the global `--max-depth` rather than overriding it**:
  whichever is tighter wins, so a user who has set a depth for a whole script
  does not have it silently widened here.

`--level` prunes the *picture*, not the arithmetic. A directory sitting on the
boundary is still drawn, and is drawn as a directory (with a trailing `/`), so
the tree never claims to end where it does not. Objects below the cut still
contribute their bytes to the totals — a pruned branch that reported as empty
would be a lie about the vault rather than a truth about the drawing.

### Glyphs are chosen by `--ascii` and by nothing else

`--ascii` swaps the box-drawing characters for `|--`, `` `-- `` and `|`, in slots
of exactly the same width, so the two sets are interchangeable without shifting
a single column:

```
vault:photos
|-- 2024/
|   |-- IMG_4417.CR3
|   `-- IMG_4418.CR3
`-- 2025/
    `-- IMG_0031.CR3
```

Nothing else influences the choice — not the locale, not whether stdout is a
terminal. A progress bar is chrome and may sniff its environment; **a tree is
data**. It gets redirected into a file, piped into `less`, and committed to a
ticket. If the glyphs depended on the plumbing, `dctl tree > out.txt` and
`dctl tree | tee out.txt` would produce different files from the same vault, and
a user diffing two runs would be reading a difference in their shell rather than
in their data.

### Memory: this verb is the exception

Every other listing command streams in constant memory. `tree` cannot, and the
reason is a property of the picture rather than of the code: the connector drawn
beside a node depends on whether that node has any **later siblings**, and a
directory's later siblings are only known once its entire subtree has been read.
Drawing `├──` where `└──` belonged is not a rounding error — it is a picture of
a different tree.

What is held is therefore the *drawing*, bounded by `--level`, and never the
objects: one name and one integer per node, no hashes, no timestamps, no
records. A ten-million-object vault drawn with `--dirs-only --level 2` costs the
directories at two levels and nothing else. The honest framing is that a tree of
ten million objects is not a readable artefact under any implementation —
[`ls`](dctl_ls.md) and [`size`](dctl_size.md) are the commands for that scale,
and they stream. The drawing walk itself is iterative and its indent is a single
buffer, so a pathologically deep path costs its own length rather than its
length squared, and never overflows a call stack.

### JSON is the flat stream, not a nested document

Under `--json` or `--format json-lines`, `tree` emits the same records
[`lsjson`](dctl_lsjson.md) emits, in the same order — no drawing, no nesting. A
nested JSON document would have to be assembled whole before its first byte
could be written, which is the one thing `PLAN.md` §16.2 rules out, and the
hierarchy is already in the `Path` field, losslessly. A consumer that wants a
tree can build one; a consumer that wants records should not have to walk one.

### The footer is on stderr

After the drawing, `tree` reports what it covered — `12 directories, 4,108
files, 4.31 GiB` — on **stderr**, at `-v`. The drawing is the data, and a
trailing sentence appended to it would break `dctl tree | grep`. The byte total
is the whole subtree's, including anything `--level` pruned from the picture:
the drawing was truncated, the vault was not.

The byte figure reads `-` when any object in the tree has no recorded size — the
state of every row straight after `dctl index rebuild`, which lists object names
without reading their bodies. A total that silently dropped the unmeasured files
would be short by an unknown amount and would still look like a total. The
directory and file counts are unaffected.

### Scope, writes and empty results

Scope is shared with the rest of the family: repeatable `--include`/`--exclude`
globs where exclusion wins and `*` stops at a path separator while `**` crosses
one, `--min-size`/`--max-size`, and the same `REMOTE:PATH` grammar in which
`C:\data` and `\\nas\share` are local on every platform. `--filter-from` and
`--files-from` are refused rather than ignored (exit 7). The global `--max-depth`
is applied to the tree as it is built rather than to the object stream, so a
directory at the boundary is still drawn even though everything inside it has
been pruned.

`tree` writes nothing, commits nothing and never sends bytes to a provider, so a
checksum mismatch is not among its failure modes. The half of the verified-write
contract it keeps is the reporting half: an object is drawn only after its write
was checksum-verified and durably committed to the encrypted index (`PLAN.md`
§6), and a run that could not reach that index **fails** rather than drawing a
bare root label that reads as an empty vault. When the tree is legitimately
empty, the reason is noted on stderr at `-v`. `--dry-run` changes neither the
output nor the exit code.

### Status in this build

**`dctl tree` reads a vault, and reads a local directory.** The layout engine,
both glyph sets, the level composition, the filters and the JSON framing are
implemented, and so is the index read this page once said was missing:
`dctl tree vault:` draws the stored objects and `dctl tree ./src` draws a
local tree. Earlier revisions quoted an exit-7 `reading the object index is not
implemented` error that no build now produces.

The one gap left is shared with the rest of the listing family: a **local path
that does not exist** produces a lone root label and exit **0** rather than exit 3
(`dir_not_found`). See [dctl ls](dctl_ls.md) for why that matters before a script
branches on it.

```
dctl tree [REMOTE:PATH] [flags]
```

## Examples

The drawings below are what the renderer produces, and every one of them runs in
this build.

Draw a subtree. The root label is the spec as typed, so the picture identifies
itself:

```
dctl tree vault:photos
vault:photos
├── 2024/
│   ├── IMG_4417.CR3
│   └── IMG_4418.CR3
└── 2025/
    └── IMG_0031.CR3
```

Get the shape of a large vault without the leaves. This is the readable form on
a real dataset, and the cheapest one to hold:

```
dctl tree b2prod:bucket/media --dirs-only --level 2
b2prod:bucket/media
├── raw/
│   ├── 2024/
│   └── 2025/
└── proxies/
    └── 2024/
```

See the footer. It goes to stderr at `-v`, so the drawing on stdout stays
greppable, and its byte total includes what `--level` pruned from the picture:

```
dctl tree vault: --dirs-only -v
…
12 directories, 0 files, 231.6 GiB
```

Draw with ASCII glyphs, for a console or a file format that will not survive box
drawing. `--ascii` is the only input to the choice, so the bytes are identical
everywhere:

```
dctl tree vault:photos --ascii > photos-tree.txt
```

The tighter of the two depth limits wins, so a script that already sets
`--max-depth` cannot have it widened by a `--level` further down the command
line:

```
dctl tree vault:photos --max-depth 2 --level 5   # draws 2 levels, not 5
```

Under `--json`, `tree` stops drawing and emits the flat record stream instead —
the same shape `lsjson` produces, because the hierarchy is already in `Path`:

```
dctl tree vault:photos --format json-lines | jq -r '.Path'
```

A Windows path is local on every platform — `C:` is a drive letter, never a
remote named `C` — so it is walked as a directory rather than resolved against
the configured remotes, and a tree of it is drawn. A UNC path such as
`\\nas\media\photos` behaves the same way; a remote named `C` would instead fail
with `unknown remote 'C'` and exit 7:

```
dctl tree C:\Users\mx\Pictures
C:\Users\mx\Pictures
└── holiday/
    └── IMG_0001.JPG
```

On a machine where that path does not exist the drawing is a lone root label and
the exit code is **0**, not 3 — see *Status in this build*.

## Options

```
  -d, --dirs-only  Show directories only, omitting the objects inside them
  -h, --help       help for tree
  -L, --level <N>  Descend at most this many levels; -1 for unlimited [default: -1]
```

The positional argument is `[REMOTE:PATH]`, optional, falling back to
`--remote`. `-L` accepts a negative number directly, so `-L -1` parses as the
unlimited sentinel rather than as an unknown flag. `-V, --version` is propagated
to every subcommand.

## Options inherited from parent commands

Every global flag is accepted. The ones that matter here are `--ascii` (the sole
input to the glyph choice), `--max-depth` (composed with `--level`, tighter
wins), the filters `--include` / `--exclude` / `--min-size` / `--max-size` /
`--filter-from` / `--files-from`, `--format` / `--json` (which
replace the drawing with the flat record stream), `--units` (the footer's byte
figure) and `-v` (whether the footer appears at all). See
[../GLOBAL_FLAGS.md](../GLOBAL_FLAGS.md) for the full list.

## Exit codes

| Code | Name | When |
|-----:|------|------|
| 0 | `success` | The tree was drawn, including when it was legitimately empty. Not reachable in this build. |
| 1 | `usage` | No path and no `--remote`; an illegal or too-short remote name; a `..` component; a malformed pattern or size value; an unknown flag or a second positional. |
| 2 | `uncategorised` | A stdout write failed for a reason other than a broken pipe. A broken pipe — `\| head` — is success. |
| 5 | `temporary_error` | The provider could not be reached and the retry budget was exhausted. Needs the engine work below. |
| 7 | `fatal_error` | Returned by every complete invocation in this build, by a local target, and by `--filter-from`/`--files-from`. |
| 22 | `vault_locked` | Wrong password or second factor, or a damaged envelope. Needs the engine work below. |
| 23 | `index_error` | The encrypted index or its journal could not be read. Needs the engine work below. |
| 25 | `cancelled` | Ctrl-C or SIGTERM. A partially-drawn tree is never reported as complete. |

In this build only **1**, **2**, **7** and **25** are reachable. See
[../EXIT_CODES.md](../EXIT_CODES.md) for the full contract.

## See also

* [dctl lsd](dctl_lsd.md) — the same inferred directories as rows, with
  recursive byte and object totals.
* [dctl ls](dctl_ls.md) — the streaming listing, and the right command at a
  scale where a tree stops being readable.
* [dctl size](dctl_size.md) — the totals the footer summarises, on their own.
* [dctl lsjson](dctl_lsjson.md) — the record shape `tree --json` emits.
* [dctl mount](dctl_mount.md) — browse the same namespace with an ordinary file
  manager instead.
