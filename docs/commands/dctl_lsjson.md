# dctl lsjson

List objects as JSON, one document per object.

## Synopsis

`dctl lsjson` is the listing a program reads. Where [`ls`](dctl_ls.md) and
[`lsl`](dctl_lsl.md) choose a rendering for a person and emit JSON only when
asked, **`lsjson` emits JSON whatever `--format` says** — that is the whole
reason it is a separate verb rather than an alias for `ls --json`, and it
matches rclone, where `lsjson` is the machine-readable listing regardless of any
other flag.

What `--format` still decides is the *framing*:

| `--format` | Output |
|------------|--------|
| `text` (the default) | One indented JSON array, exactly as rclone produces |
| `json` (or `--json`) | The same array |
| `json-lines` | One compact object per line |

`json-lines` is the one to reach for on a large vault. It starts producing
records immediately, needs no closing bracket to be valid, and lets a consumer
process a listing far larger than its own memory. The array form is streamed too
— the brackets are written by hand around individually-encoded elements, so
memory stays at one element and the bytes are identical to what a whole-document
pretty printer would have produced — but only `json-lines` lets the *reader*
avoid buffering as well.

### The record shape

```json
{
  "Path": "2024/IMG_4417.CR3",
  "Name": "IMG_4417.CR3",
  "Size": 13005824,
  "ModTime": "2024-05-31T16:24:29Z",
  "IsDir": false,
  "Hashes": {
    "blake3": "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
  }
}
```

Field names are rclone's, in rclone's capitalisation, because the scripts this
tool has to accept were written against `rclone lsjson` and `jq -r '.[].Path'`
should keep working after the binary is swapped. The vocabulary is the
interoperability surface; the values are DCTL's. The field set is exactly the
six above and adding a seventh is a compatibility change, guarded by a test.

* **`Path`** is relative to the listing root, exactly as rclone defines it:
  `dctl lsjson vault:photos` reports `2024/IMG_4417.CR3`, not
  `photos/2024/IMG_4417.CR3`. Re-address an entry by re-joining it to the spec
  that produced it.
* **`Size`** is the exact plaintext size in bytes — an integer, never a rounded
  human string. This is where arithmetic belongs; the text listings round on
  purpose. It is **`null`** when the index recorded no size — an object
  `dctl index rebuild` could not read the header of, which that command counts
  and exits **6** over. Null rather than `0`, for the same reason `ModTime` is
  null rather than the epoch: a consumer summing this field must be able to tell
  "this object is empty" from "nobody has weighed this object". A genuinely empty
  file reports `0`.
* **`ModTime`** is RFC 3339 in UTC, or **`null`** when the index recorded none.
  Null rather than the epoch, because "unknown" and "1970" are different answers
  and a consumer must be able to tell them apart.
* **`Hashes`** is a map keyed by algorithm name, not a bare string. One
  algorithm (`blake3`) is recorded today; a map means a second can be added
  without a consumer that reads `Hashes.blake3` ever noticing. A directory
  carries an empty map, having no content of its own to hash.

### What is deliberately absent

No object key, no wrapped DEK, no chunk map. An `lsjson` dump is the artefact
most likely to be pasted into a ticket or committed to a repository, and the
plaintext-path-to-object-key mapping is precisely the metadata the storage
design exists to withhold (`PLAN.md` §2, §7). The internal entry type does not
carry those fields at all, so this shape cannot leak them through a forgotten
`skip_serializing`.

### Scope

Identical to every other listing verb, and shared in the code so the six cannot
drift: repeatable `--include`/`--exclude` globs where exclusion wins and `*`
stops at a path separator while `**` crosses one; `--min-size`/`--max-size`
accepting `10G`, `1.5MiB` or `off`; a one-based `--max-depth` counted from the
listing root; entries in ascending lexicographic path order, never repeated; one
page of 1000 entries in memory regardless of vault size.

**`--filter-from` and `--files-from` are honoured**, by the same rule engine
`dctl copy` uses, so the records this command emits are the objects a transfer
over the same scope would take. A rule file that cannot be read or parsed is a
**usage error** (exit 1) naming the file and the line — never a run with the rules
dropped, and this is the command where that matters most: a machine listing that
silently dropped its rule file would look complete, and its output is what a
script then uses to decide what to delete.

### Empty results, and the one thing this command must never print

An empty listing is a **successful answer to a question**, not a failure: it
emits `[]` (or, under `json-lines`, nothing at all) and exits zero. Emitting
nothing at all in array framing would leave `jq` reading an empty stream and
reporting a parse error, which a script would then have to distinguish from a
real failure.

Which is exactly why a listing that could not reach the index **must not** be
`[]`. `lsjson` writes nothing, commits nothing and never sends bytes to a
provider — there is no checksum-mismatch failure mode here — but it carries the
reporting half of the verified-write contract, and it carries it harder than its
siblings do. An object appears here only after its bytes were checksum-verified
at the destination and durably committed to the encrypted index (`PLAN.md` §6);
a run that could not read that index fails with a non-zero exit code and a hint,
because a consumer handed `[]` would conclude the vault is empty and could then
prune a backup on the strength of it.

When a listing is legitimately empty, the reason is noted on stderr (visible at
`-v`) and distinguishes "nothing here" from "your filters matched nothing". The
JSON on stdout is unaffected. `--dry-run` changes neither the output nor the
exit code.

### Status in this build

**`dctl lsjson` reads a vault, and reads a local directory.** The record
shape, the streamed framings, the filters and the ordering contract are
implemented, and so is the index read this page once said was missing:
`dctl lsjson vault:` lists stored objects and `dctl lsjson ./src` walks the
filesystem. Earlier revisions quoted an exit-7 `reading the object index is not
implemented` error that no build now produces.

The one gap left is shared with the rest of the listing family: a **local path
that does not exist** produces `[]` and exit **0** rather than exit 3
(`dir_not_found`). See [dctl ls](dctl_ls.md) for why that matters before a script
branches on it.

```
dctl lsjson [REMOTE:PATH] [flags]
```

## Examples

The output below is what the renderer produces, and every one of them runs in
this build.

List a subtree as an indented array. No `--json` is needed — `lsjson` emits JSON
whatever the global format is:

```
dctl lsjson vault:photos/2024
[
  {
    "Path": "IMG_4417.CR3",
    "Name": "IMG_4417.CR3",
    "Size": 13005824,
    "ModTime": "2024-05-31T16:24:29Z",
    "IsDir": false,
    "Hashes": {
      "blake3": "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    }
  }
]
```

Stream a large vault one record per line. This is the framing that scales: the
consumer reads a line, parses it and drops it, so a ten-million-object listing
costs neither side its memory:

```
dctl lsjson b2prod:bucket/media --format json-lines | while read -r line; do
  jq -r '.Path' <<<"$line"
done
```

Sum the exact bytes of everything matching a filter. `Size` is an integer here,
which is what the rounded text column cannot give you:

```
dctl lsjson vault:photos --include "*.CR3" | jq '[.[].Size] | add'
```

Export a path-to-hash manifest for an external comparison. `Hashes` is a map, so
the key names the algorithm and a future second algorithm will not break this:

```
dctl lsjson vault:media --format json-lines \
  | jq -r '[.Hashes.blake3, .Path] | @tsv' > media.manifest
```

Find objects whose modification time the index never recorded. `ModTime` is
`null` for those, never the epoch, so the test is unambiguous:

```
dctl lsjson vault: --format json-lines | jq -r 'select(.ModTime == null) | .Path'
```

A rule file and an exact path list both shape the output, through the same
engine every other command consults. This is the command where a silently
dropped rule would be most expensive, because its output is what a downstream
job acts on:

```
$ dctl lsjson archive: --files-from list.txt
[
  {
    "Path": "notes.txt",
    "Name": "notes.txt",
    "Size": 11,
    "ModTime": "2026-07-26T23:30:44Z",
    "IsDir": false,
    "Hashes": {
      "blake3": "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24"
    }
  },
  {
    "Path": "photos/2024/c.jpg",
    "Name": "c.jpg",
    "Size": 7,
    "ModTime": "2026-07-26T23:30:44Z",
    "IsDir": false,
    "Hashes": {
      "blake3": "21497c77362a2bd6f316bfe397a70a83008e0f3397578fa298371b1427620f1a"
    }
  }
]
```

A file that cannot be read or parsed is a usage error naming the file and the
line, never a run with the rules dropped.

A Windows path is local on every platform — `C:` is a drive letter, never a
remote named `C`, and `\\nas\share` is a UNC path — so it is walked as a
directory rather than resolved against the configured remotes. A remote named
`C` would instead fail with `unknown remote 'C'` and exit 7:

```
dctl lsjson C:\Users\mx\Pictures
[
  {
    "Path": "IMG_0001.JPG",
    "Name": "IMG_0001.JPG",
    "Size": 2202009,
    "ModTime": "2024-01-02T09:15:00Z",
    "IsDir": false,
    "Hashes": {}
  }
]
```

On a machine where that path does not exist the output is `[]` and the exit code
is **0**, not 3 — see *Status in this build*.

## Options

```
  -h, --help   help for lsjson
```

`lsjson` declares no flags of its own. The positional argument is
`[REMOTE:PATH]`, optional, falling back to `--remote`. `-V, --version` is
propagated to every subcommand.

## Options inherited from parent commands

Every global flag is accepted. `--format` is the important one, and it is the
only thing that changes this command's output: `text` and `json` both produce
the indented array, `json-lines` produces one compact record per line. `--json`
is a shorthand for `--format json` and is redundant here. Colour is never
applied to these records — escape sequences inside a JSON string break every
downstream parser, so `--color always` still produces clean JSON. The filters
`--include` / `--exclude` / `--min-size` / `--max-size` / `--max-depth` shape
what is listed, as do `--filter-from` and `--files-from`; `--units` has
no effect because nothing in the shape is rounded, and `-v` decides whether the
"nothing matched" note appears on stderr. See
[../GLOBAL_FLAGS.md](../GLOBAL_FLAGS.md) for the full list.

## Exit codes

| Code | Name | When |
|-----:|------|------|
| 0 | `success` | The document was emitted, including the empty `[]` case. Not reachable in this build. |
| 1 | `usage` | No path and no `--remote`; an illegal or too-short remote name; a `..` component; a malformed pattern or size value; an unknown flag or a second positional. |
| 2 | `uncategorised` | A stdout write failed for a reason other than a broken pipe, or a record could not be serialised. A broken pipe is success. |
| 5 | `temporary_error` | The provider could not be reached and the retry budget was exhausted. Needs the engine work below. |
| 7 | `fatal_error` | Returned by every complete invocation in this build, by a local target, and by `--filter-from`/`--files-from`. |
| 22 | `vault_locked` | Wrong password or second factor, or a damaged envelope. Needs the engine work below. |
| 23 | `index_error` | The encrypted index or its journal could not be read. Needs the engine work below. |
| 25 | `cancelled` | Ctrl-C or SIGTERM. A truncated document is never reported as complete. |

In this build only **1**, **2**, **7** and **25** are reachable. Note that a
non-zero exit and a valid-looking `[]` are mutually exclusive by design: check
the exit code before trusting an empty array. See
[../EXIT_CODES.md](../EXIT_CODES.md) for the full contract.

## See also

* [dctl ls](dctl_ls.md) — the same records rendered for a person; `dctl ls
  --json` produces this command's output.
* [dctl lsl](dctl_lsl.md) — the human listing with modification times; its
  `--json` output is this shape.
* [dctl lsd](dctl_lsd.md) — directories only, emitted in this shape with
  `IsDir` true.
* [dctl tree](dctl_tree.md) — under `--json`, emits this same flat stream rather
  than a nested document.
* [dctl size](dctl_size.md) — totals rather than records, with its own small
  `{"count","bytes"}` shape.
* [dctl hashsum](dctl_hashsum.md) — hashes on their own, in the coreutils
  format.
