# dctl check

Compare source and destination without transferring.

## Synopsis

`dctl check` compares two trees and reports how they differ. It is the safest
command in the tool: it reads both sides, it writes nothing to either of them,
and it cannot be talked into copying something "while it is there". The only
thing it can create is the verdict files you explicitly ask for with
`--combined`, `--differ`, `--match` and the `--missing-on-*` flags — everything
else it produces goes to stdout.

It exists because `PLAN.md` §13.6 is blunt about the alternative: a backup
nobody ever compared against its source is a hope, not a backup. `check` is what
turns the hope into a measurement.

Every path lands in exactly one of five buckets:

| verdict | `--combined` mark | meaning |
|---------|:-----------------:|---------|
| `match` | `=` | on both sides and the same |
| `differ` | `*` | on both sides, contents disagree |
| `missing-on-dst` | `+` | only at the source |
| `missing-on-src` | `-` | only at the destination |
| `error` | `!` | could not be compared — never a silent pass |

The marks are rclone's, because the combined file is exactly the artefact people
already have `awk` one-liners for.

**What "the same" means is the global comparison dial**, and this is the pitfall
worth reading twice. By default `check` compares size and modification time,
which is cheap and catches the overwhelming majority of real differences — but
two files can share both and still differ. `--size-only` is cheaper still and
deliberately ignores time, for destinations whose clocks or metadata cannot be
trusted. `--checksum` is the only mode that proves the contents match. The
report always names which one ran and carries a `proves_contents` boolean,
because "0 differences" is a very different claim under each; when a metadata
comparison is in force, `check` says so on stderr under `-v`.

When a comparison needs a field one side does not have, the verdict is `error`,
never a quiet fallback to a weaker comparison and never `match`. A comparison
that downgrades itself silently is worse than one that fails, because it reports
a guarantee it did not check. In practice that is the default mode against a
destination with no recorded modification time.

### A sealed vault is compared like anything else, and there is no substitution

There used to be one. It goes in the history rather than in a footnote, because
it changed what a `check` run cost and a script may still be reading for it.

A vault used to record the moment each object was written, not the modification
time of the file it was written from — `dctl-core`'s `put_file` took no such
parameter. The number in the index was therefore true and described something
else, so the default size-and-modtime comparison against a vault answered a
question about when the copy ran: `dctl check ./src archive:` reported every path
as `differ` immediately after `dctl copy ./src archive:` had stored them
correctly.

The answer at the time was to substitute the *stronger* comparison — the index
also carries the plaintext BLAKE3 — and announce it on stderr. It worked, and it
cost a full read of the other side on every run.

The write takes the time now (`dctl_core::Modified`), so a vault's index row
carries the source's own modification time and the ordinary size-and-modtime
comparison answers it from metadata alone. The report's `comparison` field says
`size-and-modtime`, because that is what ran; nothing is substituted and the
warning that announced the substitution no longer appears.

`dctl copy`, `move` and `sync` reach the same answer the same way, which is what
keeps `check` and `copy` agreeing about the same two trees. See
`docs/commands/dctl_copy.md`, including the note on what happens the first time
this build meets a vault written by an older one.

*What that leaves.* Size and modification time cannot see an edit that changed
neither — the same limit rclone and rsync have. `--checksum` is the mode that
proves contents, and against a vault half of it is free: the index answers for
its side without reading an object.

`--checksum` is the exception, and deliberately so. A vault knows the plaintext
BLAKE3 of everything it holds and answers from its index for nothing; a local
tree or a plain object store knows no such thing. Rather than report `error` for
every path — which would leave the only comparison that proves contents
permanently unusable against a local tree — `check` **reads the object and
hashes it** on the side that has no recorded hash. That is what `--checksum`
costs: a full read of every object on any side that is not a vault, and memory
proportional to the largest object, because the read is whole-object. The cost is
stated rather than capped; a size limit would trade a documented cost for an
arbitrary refusal. `--checksum` still reports `error` if an object cannot be
read — including a vault object that fails authentication, which is named on
stderr and does not stop the run.

`--one-way` ignores paths that exist only at the destination. That is the right
question to ask after a `copy`: "is everything from the source present and
correct at the destination?" — extra files at the destination are what `copy`
leaves behind by design. Suppressed paths are not counted at all, so they cannot
inflate the difference total or change the exit code.

**The verdict files are the point of the command in a script.** A per-verdict
file carries bare paths, one per line, which is precisely the shape
`--files-from` consumes, so the whole repair loop is two commands:

```
dctl check vault:media b2prod:bucket/media --missing-on-dst todo.txt
dctl copy  vault:media b2prod:bucket/media --files-from todo.txt
```

`--combined` instead writes `<mark> <path>` for every path including matches.
Two flags may not name the same file: interleaved verdicts cannot be told apart
afterwards, so that is rejected up front with a usage error. Output paths are
validated *before* anything is compared — a destination that is a directory, or
whose parent directory does not exist, is reported immediately rather than after
a multi-hour walk. Validation touches the filesystem only to ask those
questions; it creates nothing, so a run that fails before it compares anything
leaves no empty files behind for a later script to mistake for "no differences
found". Under `--dry-run`, `check` prints a `[dry-run] would write: <path>` line
for each requested file and creates none of them.

Either side may be a remote or a local path — `check` is the one command in the
integrity family that does not require a remote, so local-to-local comparisons
are allowed. Following rclone's rule, `C:\data`, `d:/data` and `\\server\share`
are treated as **local** on every platform. Remote names must be at least two
characters, which is what makes the drive-letter rule unambiguous. Paths inside
a vault are canonicalised (`/`-separated, NFC, no `.` or `..`); a `..` component
is rejected.

Differences are reported as exit code **6** (`partial_failure`), not 21.
Nothing failed to authenticate — the two trees simply disagree — and conflating
the two would send someone hunting for corruption that is not there.

On stdout, text output lists only the disagreements as a `Status`/`Path` table;
matches are counted, not listed, because a check of a million agreeing objects
should print a summary rather than a million lines. Two trees that agree produce
*no stdout at all*, so `dctl check src: dst: && echo clean` works. `--json`
emits one document with `source`, `dest`, `comparison`, `proves_contents`,
`one_way`, a `differences` array and a `summary` counting `checked`, `matched`,
`differ`, `missing_on_src`, `missing_on_dst` and `errors` — every verdict has
its own key, so `0` is information rather than an absent field.
`--format json-lines` emits one difference per line and no summary.

A clean run is **not silent**. Stdout stays empty — that is the contract above —
but stderr carries one confirmation line naming how many paths were compared and
under which comparison:

```
✓ 3 paths compared, all match (checksum): './src' and 'archive:'
```

The count and the comparison are both load-bearing. A health gate that says
nothing when healthy cannot be told apart from one that did nothing, and exit 0
with no output was previously the same answer for "ten million objects agree" as
for "the prefix matched no objects, so neither side was ever read". That second
case now says so in its own words rather than reporting a zero:

```
✓ nothing was compared: neither 'archive:phtoos' nor './photos' listed any object
```

The line goes to stderr, so `dctl check … > findings.txt` still writes findings
only, and `--quiet` suppresses it.

### How the two sides are read

Both arguments are opened the same way, through the binary's single read
abstraction, so a sealed vault, a plain object store and a local directory are
all just *sides* — neither argument is privileged, and
`dctl check archive: ./photos` and `dctl check ./photos archive:` are the same
walk with the labels swapped. A vault side reports plaintext paths, plaintext
sizes and recorded hashes; a plain side reports whatever the provider holds.

Each side keys its objects by the path **relative to its own root**, which is
what lets a remote rooted at `photos` and a local directory called `photos`
describe the same file with the same name. The two ordered streams are then
merged, one entry held per side, so comparing two ten-million-object trees costs
two entries of memory rather than a map of one of them (`PLAN.md` §16.2).

The `--filter-from` and `--files-from` rule files are **honoured**, by the same
engine `dctl copy` uses, so the scope `check` reports on is the scope a transfer
would take. A rule file that cannot be read or parsed is a **usage error**
(exit 1) naming the file and the line rather than a run with the rules dropped —
silently comparing more than was asked for is worse than saying so.
`--include`, `--exclude`,
`--min-size`, `--max-size` and `--max-depth` are applied, identically to both
sides — filtering only the source would report every excluded file as
`missing-on-src`, a finding manufactured by the filter rather than by the data.

```
dctl check SOURCE DEST [flags]
```

## Examples

Prove that a local photo library really is in the vault, contents and all.
`--checksum` is the only comparison that answers that question; the default
size-and-modtime comparison would answer a weaker one.

```
dctl check ./photos/2024 vault:photos/2024 --checksum
```

Compare two providers after a migration and capture the work still to do.
`--one-way` ignores objects that exist only at B2 (older material that was never
in the vault), and `--missing-on-dst` writes a plain path list ready for
`--files-from`.

```
dctl check vault:media b2prod:bucket/media --one-way --missing-on-dst /var/tmp/todo.txt
dctl copy  vault:media b2prod:bucket/media --files-from /var/tmp/todo.txt
```

A Windows local tree against a vault, capturing every verdict in one marked
file. `C:` is a drive letter, so the first argument is a local path, not a
remote named `C`; the same command works unchanged on a Linux build agent given
a Linux path.

```
dctl check "C:\Users\mx\Pictures\2024" vault:photos/2024 --combined C:\Temp\check-2024.txt
```

The combined file that produces looks like this — `=` same, `*` different, `+`
at the source only, `-` at the destination only, `!` could not be compared:

```
= 2024/IMG_4417.CR3
* 2024/IMG_4418.CR3
+ 2024/IMG_4491.CR3
- 2024/thumbs.db
! 2024/IMG_4502.CR3
```

Feed a nightly comparison into a monitoring system. JSON names the comparison
that produced the counts, so a `size-and-modtime` run can never be read as a
checksum-verified one.

```
dctl check vault:documents ./documents --size-only --json
```

## Options

```
      --combined <FILE>         Write every path with its one-character verdict mark to FILE
      --differ <FILE>           Write paths that exist on both sides but differ to FILE
  -h, --help                    help for check
      --match <FILE>            Write paths that matched to FILE
      --missing-on-dst <FILE>   Write paths that exist only at the source to FILE
      --missing-on-src <FILE>   Write paths that exist only at the destination to FILE
      --one-way                 Ignore paths that exist only at the destination
```

`SOURCE` and `DEST` are both required. Each is a `REMOTE:PATH` spec or a local
path; a bare `vault:` or a trailing separator names a whole tree.

## Options inherited from parent commands

Every global flag is accepted on `dctl check`. The ones that change what this
command does are `--checksum` and `--size-only` (which select the comparison and
are mutually exclusive), the `--include`/`--exclude`/`--min-size`/`--max-size`/
`--max-depth` filters, `--dry-run` (which suppresses the verdict files, this
command's only mutation, while still performing the comparison and printing the
report), and the output flags `--format`/`--json`/`--quiet`/`-v`. See
[../GLOBAL_FLAGS.md](../GLOBAL_FLAGS.md) for the full list.

`--filter-from` and `--files-from` are **honoured** and applied to both sides; a
rule file that cannot be read or parsed stops the run as a usage error (exit 1)
naming the file and the line, because a comparison that silently covered more
than was asked for would be worse than one that stops.
`--checkers` is accepted and has no effect here — the merge walks both sides in
lockstep and holds one entry per side, so there is nothing to run in parallel
without buying back the memory the streaming walk exists to avoid.

## Exit codes

| Code | Name | When |
|-----:|------|------|
| 0 | `success` | The two sides agree under the active comparison. |
| 1 | `usage` | Unknown flag, a missing side, a path containing `..`, a remote name shorter than two characters, two verdict flags aimed at one file, or a verdict destination that is a directory. |
| 2 | `uncategorised` | A verdict file could not be written for a reason other than a missing directory or a permission denial; or a report could not be serialised. |
| 3 | `dir_not_found` | The parent directory of a verdict file does not exist. |
| 6 | `partial_failure` | The run finished and the two sides disagree — `differ`, `missing-on-*` or `error` paths were found. Nothing was transferred. |
| 7 | `fatal_error` | A side that could not be opened — an unresolvable remote, an unreadable configuration, or `--filter-from`/`--files-from`; also a permission denial writing a verdict file. |
| 22 | `vault_locked` | A sealed side would not unlock. |
| 25 | `cancelled` | Ctrl-C or SIGTERM. |

A side that could not be opened is an **error**, never an empty listing. A tree
that was never read must not come back as "everything is missing", which would
invite someone to repair it by copying a whole dataset over a destination that
was fine.

`check` never returns 21: a disagreement between two trees is not an
authentication failure. See [../EXIT_CODES.md](../EXIT_CODES.md) for the full
contract.

## See also

* [dctl verify](dctl_verify.md) — compare stored objects against the hashes the
  vault recorded for them, rather than two trees against each other.
* [dctl copy](dctl_copy.md) — the command that consumes a `--missing-on-dst`
  list via `--files-from`.
* [dctl sync](dctl_sync.md) — make the destination identical to the source.
  Destructive: it deletes from the destination, which is exactly what `check`
  lets you preview first.
* [dctl scrub](dctl_scrub.md) — proactive whole-dataset verification.
* [dctl restore](dctl_restore.md) — the restore drill `check` is the cheap
  rehearsal for.
