# dctl lsl

List objects with size, modification time and path.

## Synopsis

`dctl lsl` is [`dctl ls`](dctl_ls.md) with a time column. The same objects, the
same order, the same filters, the same relative paths; the only difference is
one field:

```
  12.4 MiB 2024-05-31T16:24:29Z 2024/IMG_4417.CR3
  14.1 MiB 2024-06-02T09:11:03Z 2024/IMG_4418.CR3
  1.20 GiB                    - video/wedding-master.mov
```

### The time column is RFC 3339, in UTC

rclone prints `2017-05-31 16:24:29.000000000` — a local-time rendering with
nanoseconds it did not measure. DCTL prints `2017-05-31T16:24:29Z`, which is
shorter, sorts correctly as plain text, parses with every date library without a
format string, and — the reason that matters most — **does not change when the
same vault is listed from a different timezone**. The index stores whole unix
seconds and nothing else: no offset, no zone name. Any local rendering would be
the reading machine's guess rather than the file's truth, and would make the
same vault produce different bytes on a laptop in Berlin and on a build agent in
UTC. Output that is diffed, hashed and piped into `jq` cannot afford a timestamp
that moves with the reader.

An object whose index record carries no modification time prints `-`, padded to
the same width, rather than the epoch. `1970-01-01` is a claim; the placeholder
is the truth. A mixed listing is normal after an index rebuild from object
headers, and the padding is what keeps the path column aligned across both
kinds of row.

The column widths are fixed and the offsets never move: ten characters of size,
one space, twenty characters of time, one space, then the unpadded path. That is
what makes `cut -c12-31` and `sort -k2` meaningful over an `lsl` listing, and
what lets the command print its first line before it has read the last object.
Because the rendering is RFC 3339, sorting the column as text sorts it
chronologically — the property rclone's local-time format does not have.

### Scope, ordering and memory

Identical to `ls`, and shared with it in the code so the two cannot drift:
repeatable `--include`/`--exclude` globs where exclusion wins and `*` stops at a
path separator while `**` crosses one; `--min-size`/`--max-size` accepting
`10G`, `1.5MiB` or `off`; a one-based `--max-depth` counted from the listing
root; entries in ascending lexicographic path order, never repeated; one page of
1000 entries in memory regardless of vault size. `--filter-from` and
`--files-from` are refused rather than ignored (exit 7).

Paths are relative to the spec that was given: `dctl lsl vault:photos` reports
`2024/IMG_4417.CR3`.

### JSON is the same shape as every other listing verb

Under `--json` or `--format json-lines`, `lsl` emits exactly the records
[`lsjson`](dctl_lsjson.md) emits — `ModTime` is already in that shape, so giving
a machine consumer a second vocabulary to learn would be a cost with no benefit.
`lsl` differs from `ls` in what a *person* sees, not in what a parser receives.

### Writes, commits and empty results

`lsl` writes nothing, commits nothing and never sends bytes to a provider, so
there is no checksum-mismatch failure mode here. What it does owe the
verified-write contract is the reporting half of it: an object appears in this
listing only after its bytes were checksum-verified at the destination and
durably committed to the encrypted index (`PLAN.md` §6), and a listing that
cannot reach that index **fails with a non-zero exit code** rather than printing
nothing and exiting zero.

An empty result is explained on stderr — "nothing here" and "nothing survived
your filters" are different answers — and only at `-v`. stdout stays empty
either way. `--dry-run` changes neither the output nor the exit code.

### Status in this build

**`dctl lsl` cannot read a vault in this build.** The time conversion, the
column layout, the filters, the ordering contract and both output formats are
implemented and unit-tested; the index read is not, because the runtime context
does not yet carry an unlocked vault handle. A complete invocation fails with

```
error: vault:photos: reading the object index is not implemented in this build
warning: The listing pipeline is complete; what is missing is the vault handle, which Ctx does not carry yet. See PLAN.md §11.
```

and exit code **7**, never with an empty listing. `PLAN.md` §11 delivers the
index in **Phase 1 (B2 MVP)**.

```
dctl lsl [REMOTE:PATH] [flags]
```

## Examples

The listings below are what the renderer produces. In this build every complete
invocation stops at the index read described under *Status in this build* and
prints the exit-7 error instead.

List a subtree with modification times:

```
dctl lsl vault:photos/2024
  12.4 MiB 2024-05-31T16:24:29Z IMG_4417.CR3
  14.1 MiB 2024-06-02T09:11:03Z IMG_4418.CR3
```

Find the most recently modified objects. The time column sorts chronologically
as plain text, which is the whole point of RFC 3339:

```
dctl lsl vault: | sort -k2 | tail -20
```

Find everything written since a given date, using nothing but string
comparison — no date parsing, no timezone to get wrong:

```
dctl lsl b2prod:bucket/media | awk '$2 >= "2024-01-01T00:00:00Z"'
```

Combine with filters. The scope rules are shared with `ls`, so this lists
exactly the objects `dctl ls` would list with the same flags:

```
dctl lsl vault:photos --include "*.CR3" --min-size 8M --max-depth 2
```

Read it as structured data. The JSON is the same shape `lsjson` emits, so a
consumer written against one works against the other:

```
dctl lsl vault:photos --json | jq -r 'sort_by(.ModTime) | .[-1].Path'
```

A Windows path is local on every platform — `C:` is a drive letter, never a
remote named `C` — and is refused rather than quietly listing something else:

```
dctl lsl C:\Users\mx\Pictures
error: listing a local directory is not implemented in this build
warning: Give a remote spec such as 'vault:photos' instead of a filesystem path.
```

## Options

```
  -h, --help   help for lsl
```

`lsl` declares no flags of its own; everything that shapes a listing is a global
flag, so the six listing verbs cannot drift apart. The positional argument is
`[REMOTE:PATH]`, optional, falling back to `--remote`. `-V, --version` is
propagated to every subcommand.

## Options inherited from parent commands

Every global flag is accepted. The relevant ones are `--remote` (the default
target), the filters
`--include` / `--exclude` / `--min-size` / `--max-size` / `--max-depth`
(`--filter-from` and `--files-from` are refused), `--format` / `--json` /
`--units` (output shape — note that the time column is **not** affected by any
flag, by design), `--quiet` and `-v` (whether the stderr notes appear), and
`--config` / `--index` / the `--password*` group. See
[../GLOBAL_FLAGS.md](../GLOBAL_FLAGS.md) for the full list.

## Exit codes

| Code | Name | When |
|-----:|------|------|
| 0 | `success` | The listing was printed, including when it was legitimately empty. Not reachable in this build. |
| 1 | `usage` | No path and no `--remote`; an illegal or too-short remote name; a `..` component; a malformed pattern or size value; an unknown flag or a second positional. |
| 2 | `uncategorised` | A stdout write failed for a reason other than a broken pipe. A broken pipe — `\| head` — is success. |
| 5 | `temporary_error` | The provider could not be reached and the retry budget was exhausted. Needs the engine work below. |
| 7 | `fatal_error` | Returned by every complete invocation in this build, by a local target, and by `--filter-from`/`--files-from`. |
| 22 | `vault_locked` | Wrong password or second factor, or a damaged envelope. Needs the engine work below. |
| 23 | `index_error` | The encrypted index or its journal could not be read. Needs the engine work below. |
| 25 | `cancelled` | Ctrl-C or SIGTERM. A truncated listing is never reported as complete. |

In this build only **1**, **2**, **7** and **25** are reachable; filter and spec
errors are always diagnosed before the unimplemented one. See
[../EXIT_CODES.md](../EXIT_CODES.md) for the full contract.

## See also

* [dctl ls](dctl_ls.md) — the same listing without the time column.
* [dctl lsjson](dctl_lsjson.md) — the same records as JSON, whatever `--format`
  says.
* [dctl lsd](dctl_lsd.md) — directories only, with recursive totals.
* [dctl tree](dctl_tree.md) — the same objects drawn as nesting.
* [dctl touch](dctl_touch.md) — set the modification time this column reports.
* [dctl check](dctl_check.md) — compare two trees by time, size or checksum.
