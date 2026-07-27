# dctl size

Show total size and object count.

## Synopsis

`dctl size` is the cheapest question in the listing family and the one most often
asked from a script: two numbers over a subtree.

```
dctl size vault:photos
Total objects: 1,234
Total size: 1.44 GiB (1546188226 bytes)
```

It measures the same scope every other listing verb uses, and shares the code
that decides that scope, so `dctl size --include "*.CR3"` and
`dctl ls --include "*.CR3" | wc -l` agree by construction. A pair of commands
that disagreed about the same vault would leave a user no way to tell which one
was lying.

### Two renderings of the same number

The text report prints the rounded human figure **and** the exact byte count,
because they answer different questions. `1.44 GiB` is what a person reads;
`1546188226` is what gets subtracted from a quota, and a rounded figure quietly
loses up to five per cent of it. The exact figure carries no thousands
separators and no unit ladder — it is there to be pasted into arithmetic. The
object count is grouped (`1,234`) because it is only ever read, never computed
with.

`--units decimal` changes the rounded figure to the convention providers bill in
(`1.55 GB`); the exact byte count never changes, since a byte is a byte.

Under `--json` (or `--format json`) the shape is:

```json
{
  "count": 1234,
  "bytes": 1546188226,
  "measured_bytes": 1546188226,
  "unmeasured": 0,
  "sizes": "plaintext"
}
```

and under `--format json-lines` the same object on a single line. `count` and
`bytes` are rclone's `size --json` shape, lower case, so a script that already
reads `.count` and `.bytes` keeps working. Both values are exact: rounding
belongs in the text rendering and nowhere else, and a machine has no use for a
rounded number and every use for a stable one.

### When the total cannot be computed

A vault's sizes live in its index. `dctl index rebuild` is a **list-only pass**
by design — it recovers object names without reading their bodies — so straight
after a disaster-recovery rebuild no row in the vault has a recorded size.

`bytes` is then **`null`**, not `0`:

```json
{ "count": 1234, "bytes": null, "measured_bytes": 0, "unmeasured": 1234, "sizes": "plaintext" }
```

```text
Total objects: 1,234
Total size (plaintext): at least 0 B (0 bytes)
Unmeasured objects: 1,234
warning: some objects carry no recorded size, so this figure is a lower bound…
```

* `bytes` — the exact total, and `null` when even one object in scope has no
  recorded size. A capacity monitor reading `.bytes` after a rebuild used to be
  told a forty-terabyte vault held `0`, which it cannot tell from an empty one.
  A `null` breaks that monitor's arithmetic loudly, at the moment it would
  otherwise have reported a fiction.
* `measured_bytes` — always a number: the sum of the objects that *did* have a
  recorded size. When `bytes` is `null` this is the honest lower bound, and it is
  the figure the text report prints. When `bytes` is not `null` the two are equal.
* `unmeasured` — how many objects in scope had no recorded size, which is the
  reason `bytes` is `null`.

A genuinely empty file is **measured**: it has a recorded size of zero, and it
does not make the total unknown. The two states are different facts and the shape
keeps them apart.

Nothing in this build fills those sizes in on a read — `cat`, `hashsum` and a
whole `scrub` all leave the row exactly as unmeasured as they found it, despite
what `rebuild_index`'s own documentation says. Only writing the file again
records a size, so the remedy is to re-run the copy that produced the vault.

An empty scope reports zeroes rather than nothing — `Total objects: 0` /
`Total size: 0 B (0 bytes)`. "Zero objects" is an answer; silence is not. That
zero is a *measurement*: an empty scope really does hold nothing, which is why it
is a number here and `null` in the unmeasured case above. Unlike its siblings,
`size` prints no "nothing matched" note, because the zeroes already say it.

### Memory

Two 64-bit integers, whatever the vault holds. This is the command that proves
the streaming pipeline is real: counting ten million objects must not need ten
million anything (`PLAN.md` §16.2). Entries arrive one page of 1000 at a time and
are added and dropped. The additions saturate rather than wrap — a vault whose
total overflows a `u64` is not something DCTL will meet, and a saturated value
would at least be visibly wrong where a wrapped one would look plausible.

### Scope

Identical to [`ls`](dctl_ls.md), and worth restating because the whole value of
this command is that the number matches:

* `--include` and `--exclude` are repeatable globs; **exclusion wins**, and
  `--include` narrows whatever survived. `*` stops at a path separator, `**`
  crosses one.
* A pattern with a leading `/` is anchored at the listing root; a pattern with no
  `/` at all matches the file name at any depth; anything else matches the
  root-relative path or any component-aligned suffix of it.
* `--min-size` / `--max-size` accept `10G`, `1.5MiB` or `off`, and apply to
  objects.
* `--max-depth N` counts from the listing root, one-based; `-1` is unlimited.
* `--filter-from` and `--files-from` are **refused, not ignored** (exit 7). A
  total computed from silently-dropped rules is a wrong number that looks right,
  and capacity decisions get made on these numbers.

The positional argument is `REMOTE:PATH`, falling back to `--remote` /
`DCTL_REMOTE`. `C:\data`, `d:/data` and `\\nas\share` are local paths on every
platform — checked before the colon split, so `C:` is never a remote named `C` —
and a remote name needs at least two characters. The path half is canonicalised
(`/`-separated, NFC, no `.` components, no trailing slash) and a `..` component
is rejected.

### What is measured, and what is not

`size` reports **plaintext** bytes: the sum of the sizes the index recorded for
the objects in scope. That is not the same as what the provider bills for.
Ciphertext carries per-chunk AEAD tags and per-object headers, a vault-wrapped
remote stores its own metadata, and a provider may retain old versions and
abandoned multipart uploads that no longer appear in any listing. Use
[`dctl about`](dctl_about.md) for the provider's own view of usage and quota,
and [`dctl cleanup`](dctl_cleanup.md) to remove what a listing no longer shows.

### Writes, commits, and why zero is dangerous

`size` writes nothing, commits nothing and never sends bytes to a provider, so a
checksum mismatch is not among its failure modes. What it does carry is the
reporting half of the verified-write contract: an object contributes to these
totals only after its bytes were checksum-verified at the destination and
durably committed to the encrypted index (`PLAN.md` §6), so a half-finished
upload is never counted as stored.

And a run that could not reach the index **fails with a non-zero exit code
rather than reporting zero**. A reported zero would be indistinguishable from an
empty vault, and "the backup is empty" is a conclusion people act on — by
re-uploading, or by pruning something else. `--dry-run` changes neither the
output nor the exit code.

### Status in this build

**`dctl size` cannot read a vault in this build.** Spec parsing, the filters,
the streaming accumulation and both output shapes are implemented and
unit-tested; the index read is not, because the runtime context does not yet
carry an unlocked vault handle. A complete invocation fails with

```
error: b2prod:bucket/media: reading the object index is not implemented in this build
warning: The listing pipeline is complete; what is missing is the vault handle, which Ctx does not carry yet. See PLAN.md §11.
```

and exit code **7** — never with a zero total. `PLAN.md` §11 delivers the index
in **Phase 1 (B2 MVP)**.

```
dctl size [REMOTE:PATH] [flags]
```

## Examples

The reports below are what the renderer produces. In this build every complete
invocation stops at the index read described under *Status in this build* and
prints the exit-7 error instead.

Measure a whole vault:

```
dctl size vault:
Total objects: 8,417
Total size: 231.6 GiB (248686112768 bytes)
```

Measure one subtree, in the convention the provider bills in. The rounded figure
follows `--units`; the exact byte count never does:

```
dctl size b2prod:bucket/media --units decimal
Total objects: 6,102
Total size: 248.7 GB (248686112768 bytes)
```

Measure only what a filter selects. The same flags on `dctl ls` list exactly the
objects counted here:

```
dctl size vault:photos --include "*.CR3" --min-size 8M
```

Feed the exact numbers to a script. The field names are rclone's, so an existing
consumer of `rclone size --json` keeps working:

```
dctl size vault:photos --json | jq '.bytes'
```

Track a vault's growth from a cron job, one line per run. `json-lines` gives a
compact single-line record that appends cleanly to a log:

```
dctl size vault: --format json-lines >> capacity.jsonl
```

A rule file and an exact path list both narrow what is measured, through the
same engine `copy` and `sync` use — so a capacity figure describes exactly the
objects a transfer under those rules would move:

```
$ dctl size archive: --files-from list.txt
Total objects: 2
Total size (plaintext): 18 B (18 bytes)
```

A file that cannot be read or parsed is a usage error rather than a run with the
rules dropped: a capacity number computed from ignored rules is a wrong number
that looks right.

A Windows path is local on every platform, so it is refused rather than measured
as if it were a vault. `C:` is a drive letter, never a remote named `C`:

```
dctl size C:\Users\mx\Pictures
error: listing a local directory is not implemented in this build
warning: Give a remote spec such as 'vault:photos' instead of a filesystem path.
```

## Options

```
  -h, --help   help for size
```

`size` declares no flags of its own; everything that shapes the measurement is a
global flag, so its totals cannot drift from what the other listing verbs show.
The positional argument is `[REMOTE:PATH]`, optional, falling back to
`--remote`. `-V, --version` is propagated to every subcommand.

## Options inherited from parent commands

Every global flag is accepted. The relevant ones are the filters
`--include` / `--exclude` / `--min-size` / `--max-size` / `--max-depth`
(`--filter-from` and `--files-from` are refused), `--units` (the rounded figure
only), `--format` / `--json` (which replace the two text lines with the
`{"count","bytes"}` object), `--quiet`, and `--config` / `--index` / the
`--password*` group. See [../GLOBAL_FLAGS.md](../GLOBAL_FLAGS.md) for the full
list.

## Exit codes

| Code | Name | When |
|-----:|------|------|
| 0 | `success` | The totals were printed, including a legitimate zero. Not reachable in this build. |
| 1 | `usage` | No path and no `--remote`; an illegal or too-short remote name; a `..` component; a malformed pattern or size value; an unknown flag or a second positional. |
| 2 | `uncategorised` | A stdout write failed for a reason other than a broken pipe. A broken pipe is success. |
| 5 | `temporary_error` | The provider could not be reached and the retry budget was exhausted. Needs the engine work below. |
| 7 | `fatal_error` | Returned by every complete invocation in this build, by a local target, and by `--filter-from`/`--files-from`. |
| 22 | `vault_locked` | Wrong password or second factor, or a damaged envelope. Needs the engine work below. |
| 23 | `index_error` | The encrypted index or its journal could not be read. Needs the engine work below. |
| 25 | `cancelled` | Ctrl-C or SIGTERM. A partial total is never printed as if it were final. |

In this build only **1**, **2**, **7** and **25** are reachable. A zero total is
only ever printed on exit 0, so a script must check the exit code before
believing one. See [../EXIT_CODES.md](../EXIT_CODES.md) for the full contract.

## See also

* [dctl ls](dctl_ls.md) — the objects behind the count, over the same scope.
* [dctl lsd](dctl_lsd.md) — the same totals broken down per directory.
* [dctl tree](dctl_tree.md) — its stderr footer reports the same byte total for
  the drawn subtree.
* [dctl about](dctl_about.md) — the provider's own usage and quota figures,
  which include ciphertext overhead and retained versions.
* [dctl cleanup](dctl_cleanup.md) — remove abandoned uploads and old versions
  that a listing no longer shows but the bill still does.
