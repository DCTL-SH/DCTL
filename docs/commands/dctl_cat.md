# dctl cat

Write object contents to standard output.

## Synopsis

`dctl cat` writes the bytes of one or more objects to standard output, in the
order the arguments were given, with nothing between them. It is the read half of
DCTL's byte-stream family; [`rcat`](dctl_rcat.md) is the write half. Where
[`copy`](dctl_copy.md) moves objects between two named places and reports on
them, `cat` puts the object *into a pipeline* — `dctl cat vault:film.mkv | ffplay
-`, `dctl cat b2prod:bucket/media/clip.mkv > clip.mkv`, `dctl cat dump.sql.gz |
gunzip | psql`.

**stdout carries object bytes and nothing else, ever.** Progress bars, warnings,
the `--dry-run` plan and the `--discard` report all go to stderr, which is what
lets `dctl cat vault:film.mkv --progress | ffplay -` animate a progress bar on
the terminal while the video plays. The bytes themselves are written to a locked
`stdout` directly rather than through DCTL's text sink: no trailing newline is
added, no colour escape is inserted, and no re-encoding happens, so a tarball, a
film or a database dump arrives byte for byte.

**A closed pipe is a success, not a failure.** `dctl cat big.mkv | head -c 1M`
closes the read end of the pipe after a megabyte. Rust ignores `SIGPIPE`, so the
write returns `EPIPE` instead of killing the process; treating that as an error
would make every `| head` in every script exit non-zero. `cat` therefore stops
cleanly, notes `output stream closed — stopping` on stderr at `-v`, and exits
**0**. Every *other* write failure propagates — a full disk on a redirected
stdout is a real failure and is reported as one (exit 2).

**Every argument is pre-flighted before a single byte is written.** Each object
is located, its size is read, and the requested byte range is resolved against
that size — for *all* arguments — before the copy loop starts. `dctl cat a.bin
vault:b.bin > out.bin` must not emit half a stream and then fail, because a
truncated file that looks complete is exactly the false success `PLAN.md` §6
exists to prevent. If any argument is unreadable, the run fails having written
nothing at all.

**Ranges are ranges, not read-and-discard.** `--head`, `--tail`, `--offset` and
`--count` are four spellings of one question — which slice of this object do you
want — and they fold into a single byte window that becomes a real `seek` plus a
bounded read on a local file. No byte outside the window is ever read. The rules:

| Flags | Window |
|-------|--------|
| none | the whole object |
| `--head N` | the first `N` bytes; shorthand for `--offset 0 --count N` |
| `--tail N` | the last `N` bytes; shorthand for `--offset -N` |
| `--offset N` | from byte `N` to the end |
| `--offset -N` | from `N` bytes before the end, to the end |
| `--offset N --count M` | `M` bytes starting at `N` (`N` may be negative) |
| `--count M` | the first `M` bytes |

`--head` cannot be combined with any other range flag, and `--tail` cannot be
combined with `--offset` or `--count`; both are refused by the parser *and*
re-checked in the range code, with a hint naming the equivalent spelling.
Everything else is **clamped rather than refused**, exactly as `dd` and `tail -c`
behave: an offset past the end yields an empty result, and a length longer than
what remains is truncated, so asking for the last mebibyte of a 300-byte file
gives you the 300 bytes. A range applies **per object, not to the concatenation**
— `dctl cat a.bin b.bin --head 10` writes ten bytes from each, twenty in total.

All four flags accept size suffixes on the same terms as `--max-size`: `1K` and
`1KiB` are 1024, `1kB` is 1000, `1.5M` is 1,572,864. `--offset` additionally
accepts a sign, and `allow_hyphen_values` is set for it, so `--offset -1M` needs
no `=`. One deliberate difference from the size *filters*: for a length, `0`
means zero bytes rather than "unlimited", so `--head 0` writes nothing, and the
filter word `off` is rejected outright — a length has no "off".

**`--discard` reads everything and writes nothing.** The bytes travel the same
path through the same copy loop and are dropped at the last step, so what a
discarding run proves about an object is what a real read would find: that it can
be read end to end, and how many bytes came back. It is also the escape hatch for
structured output, because **`--json` requires `--discard`**. stdout cannot carry
raw object bytes and a JSON document at once, and interleaving them would corrupt
both, so the combination is refused with exit **1** rather than silently
producing garbage. `--format json` emits one array at the end of the run;
`--format json-lines` emits one record per object as it completes, so a consumer
can parse and drop them one at a time. Every record carries `spec`, `remote`
(`null` for a local path), `path`, `size`, `offset`, `length`, `bytes` and
`dry_run` — `bytes` being the only field that reports work that really happened,
and `dry_run` being present on every record so a plan can never be mistaken for a
result by omission.

**`--dry-run` writes nothing to stdout**, even though `cat` destroys nothing. The
bytes *are* this command's effect, and a run advertised as effect-free must not
dump a 50 GB film into the caller's pipe. It still locates every object, stats
it, and resolves every range, so a dry run that succeeds is real evidence that
the arguments are good; a dry run naming a missing file still fails with exit 4.

**Path model.** An argument is either `REMOTE:PATH` or a local path, and local is
a legitimate answer here — `cat` and `rcat` are the two commands in the tool that
accept one. A remote name must be at least two characters, which is what makes
`C:\media\clip.mkv` unambiguously a Windows drive path on every platform, not
just on Windows; `\\server\share\clip.mkv` (UNC) is local; and a colon inside a
directory name (`./odd:name/f`) leaves the argument local because a remote name
may not contain a path separator. The two halves are normalised differently on
purpose: a **remote** path is a logical vault path, so it is cleaned and
NFC-normalised (`vault:./photos//a.jpg` and `vault:photos/a.jpg` address one
object, and a macOS-decomposed `café` matches a Linux-composed one), while a
**local** path is handed to the operating system verbatim, because the filesystem
decides what that name means. A remote path containing a `..` component is
refused with exit 1.

**Only regular files are read.** A directory is a usage error pointing at
[`ls`](dctl_ls.md); so is a device, socket or FIFO. That is not fussiness: every
range flag is resolved against the size reported by `stat`, and a FIFO reports
zero, so `--tail 1M` on one would silently select nothing and `cat` would appear
to succeed while writing no bytes.

**Relationship to the verified-write contract.** `cat` stores nothing, so
`PLAN.md` §6's commit machinery does not apply and exit 20 (`checksum_mismatch`)
is not reachable. `--verify`, `--verify-samples`, `--checksum`, `--size-only` and
`--immutable` are accepted but change nothing here. What §6 *does* impose is the
rule that DCTL never reports work it did not do, which is why an unreadable
argument aborts the whole run before output starts, why a dry run emits no bytes,
and why a remote object fails loudly instead of producing an empty successful
stream. A vault's bytes are AEAD-authenticated before they are returned, and an
object that fails authentication aborts with exit 21 rather than handing corrupt
plaintext to the pipeline.

### What runs today

**Local paths are fully implemented, including every range flag.** The seek, the
bounded read, the copy loop, the broken-pipe rule, `--discard`, `--dry-run` and
both JSON formats all work now and are exercised against real files.

**Remote objects are read too**, through the one source abstraction, so
`dctl cat archive:notes.md` (a sealed vault) and `dctl cat archive-store:<key>`
(the plain object store beneath it) both work, with every range flag honoured.
This page previously said remote reads were unimplemented and quoted an exit-7
refusal; that has not been true for some time.

### What a windowed read of a sealed object costs

**A window costs the window.** A vault serves `--offset`/`--count` by computing
the chunks that cover the requested bytes and issuing one ranged request for
exactly those (`docs/FORMAT.md` §3, "Random-access"). Cost is O(window) in memory
and in egress, not O(object):

```
dctl cat b2vault:film.mkv --offset 20G --count 4
```

returns four bytes and transfers one chunk — a megabyte at the default chunk
size — plus a small bounded header read the first time that object is touched.
Seeking somewhere else in the same run costs one more request and no header read.

Measured on a sealed 96 MiB object, a ten-byte window costs about **1.6 MiB of
peak resident memory above the unlock baseline**; reading the same object whole
costs **+97 MiB**. Against a 512 MiB object the window costs **the same ~1 MiB**
while the whole-object read costs **over 700 MiB** and takes twenty times as
long. That is the property that matters: the window's cost is set by the chunk
size, not by the file. (The baseline is around 140 MiB and is almost entirely
Argon2id's working memory during unlock, not the read.)

**What a window authenticates.** Every returned byte carries its chunk's own
Poly1305 tag, over additional data that binds the object's authenticated header
and the chunk's index — so bytes from another object, another position, or a
truncated object are all rejected rather than returned. The two *whole-object*
checks are different: the trailing BLAKE3 footer and the object's recorded
plaintext hash each cover the entire file, and no partial read can compute
either. `cat --offset` therefore does not check them, and does not pretend to.
[`dctl verify`](dctl_verify.md) and `dctl scrub` stream the object end to end and
remain the commands that make the whole-object statement.

**Reading the object whole is a different call.** `dctl cat archive:film.mkv`
with no range flags, and `--offset 0` with no `--count`, both take the
whole-object path, which decrypts every chunk and re-hashes the result against
the object's own recorded hash. That is the stronger guarantee, and it needs room
for the file.

Earlier releases had no ranged read at all: a vault served a window by fetching
and decrypting the entire object, so `--count 4` against a 3.7 GiB film was a
3.7 GiB transfer. `cat` warned about that on stderr above 64 MiB. Both the cost
and the warning are gone.

```
dctl cat REMOTE:PATH... [flags]
```

## Examples

Write a local object to a pipeline. Nothing but the file's bytes reaches
`ffplay`; the progress bar is drawn on stderr, and when `ffplay` is closed the
broken pipe ends the run with status 0:

```console
$ dctl cat /srv/media/clip.mkv --progress | ffplay -
$ echo $?
0
```

Read a byte window out of the middle of a large local file. The offset is a real
`seek`, so only the 512 bytes in the window are read, no matter how far into the
file they are:

```console
$ dctl cat /srv/backups/db-2026-07-26.dump --offset 4G --count 512 | xxd | head -4
```

Inspect the tail of a rotated log without reading the whole thing. `--tail`
accepts the same size suffixes as every other length flag, and a file smaller
than the request yields the whole file rather than an error:

```console
$ dctl cat /var/log/dctl/transfer.log --tail 4K
```

Prove that a set of objects can be read end to end without spooling them
anywhere. `--discard` reads every byte through the identical code path and drops
it at the last step; the report goes to stderr:

```console
$ dctl cat /srv/media/a.mkv /srv/media/b.mkv --discard
✓ 8.41 GiB read and discarded from 2 objects
```

The same run as JSON. `--json` is refused without `--discard`, because stdout
cannot carry both the bytes and the document, and `--format json` collects one
array for the whole run:

```console
$ dctl cat /srv/media/a.mkv --discard --json
[
  {
    "spec": "/srv/media/a.mkv",
    "remote": null,
    "path": "/srv/media/a.mkv",
    "size": 4509715660,
    "offset": 0,
    "length": 4509715660,
    "bytes": 4509715660,
    "dry_run": false
  }
]
```

Streaming the same information one record at a time, for a consumer that does not
want the whole array in memory. `--format json-lines` writes each record as the
object completes:

```console
$ dctl cat /srv/media/a.mkv /srv/media/b.mkv --discard --format json-lines
{"spec":"/srv/media/a.mkv","remote":null,"path":"/srv/media/a.mkv","size":4509715660,"offset":0,"length":4509715660,"bytes":4509715660,"dry_run":false}
{"spec":"/srv/media/b.mkv","remote":null,"path":"/srv/media/b.mkv","size":4522692608,"offset":0,"length":4522692608,"bytes":4522692608,"dry_run":false}
```

Forgetting `--discard` is a usage error rather than a corrupted stream:

```console
$ dctl cat /srv/media/a.mkv --json
error: --json cannot share stdout with an object's bytes
warning: stdout carries either object bytes or JSON, never both — interleaving
them would corrupt the stream and the document. Add --discard to read the objects
and emit only the JSON report, or drop --json to get the bytes.
$ echo $?
1
```

Rehearse a read. The plan is written to stderr, no bytes go to stdout, and the
arguments are still validated for real:

```console
$ dctl cat /srv/media/a.mkv --tail 1M --dry-run
warning: [dry-run] would read: /srv/media/a.mkv (bytes 4508667084..4509715660 of 4.20 GiB)
```

On Windows, a drive letter is always a drive letter — a one-character prefix can
never be a remote name — so `C:\...` is read as the local path it is, and a UNC
share works the same way:

```console
C:\> dctl cat C:\Media\clip.mkv --head 4K --discard
✓ 4.00 KiB read and discarded from 1 objects
C:\> dctl cat \\nas01\media\clip.mkv --discard
```

An argument that cannot be read is refused loudly rather than served as an empty
stream, and because that happens during pre-flight, the readable first argument
is never written either — a truncated file that looks complete is the failure
`PLAN.md` §6 exists to prevent:

```console
$ dctl cat /srv/media/a.mkv vault:photos/2024/nosuch.jpg > out.bin
error: 'vault:photos/2024/nosuch.jpg' is not there
warning: Check the path with `dctl ls`. If the object was written from another
machine, this machine's index has not seen it yet — `dctl index rebuild` rescans
the store.
$ ls -l out.bin
-rw-r--r--  1 me  staff  0 26 Jul 15:41 out.bin
```

## Options

```
  -h, --help        help for cat
      --count <N>   Write at most this many bytes from each object
      --discard     Read the objects but write nothing: proves they can be read end to end
      --head <N>    Write only the first N bytes of each object
      --offset <N>  Start reading at this byte offset. Negative counts back from the end
      --tail <N>    Write only the last N bytes of each object
```

At least one positional `<REMOTE:PATH>` is required; more than one is written in
the order given, with no separator. `--head` conflicts with `--tail`, `--offset`
and `--count`; `--tail` conflicts with `--offset` and `--count`. All four length
values accept size suffixes (`1K`, `1kB`, `1.5M`); `off` is not a length and is
rejected.

## Options inherited from parent commands

Every global flag is accepted on `dctl cat`, before or after the verb; see
[../GLOBAL_FLAGS.md](../GLOBAL_FLAGS.md) for the full set. The ones that change
what `cat` does:

| Flag | Effect here |
|------|-------------|
| `--format`, `--json` | Emit records instead of a human line. **Requires `--discard`.** `json` is one array at the end; `json-lines` is one record per object as it completes. |
| `-n`, `--dry-run` | Resolve and report every read, write no bytes. |
| `-P`, `--progress` | Draw the transfer bar on stderr; its totals come from pre-flight, so the bar has a real denominator from the first byte. |
| `--units` | `binary` (KiB) or `decimal` (kB) in the stderr report. Does not affect the JSON, which is always exact bytes. |
| `-v`, `--quiet` | `-v` adds a per-object `path: size` line on stderr; `--quiet` silences everything but errors. Neither touches stdout. |

`cat` is not classified as a transfer command, so no end-of-run summary is
printed — the object's bytes are the output, and a summary block would be noise
after them.

`--verify`, `--verify-samples`, `--checksum`, `--size-only` and `--immutable` are
parsed but do not apply: nothing is written or compared. The filter flags
(`--include`, `--exclude`, `--filter-from`, `--files-from`, `--min-size`,
`--max-size`, `--max-depth`) do not apply either — `cat` names its objects
explicitly. `--transfers`, `--checkers`, `--bwlimit`, `--retries` and
`--max-transfer` are not consulted by this command in this build: `cat` is a
single copy loop over one reused 256 KiB buffer, so its memory is O(1) regardless
of object size or argument count.

## Exit codes

See [../EXIT_CODES.md](../EXIT_CODES.md) for the full contract.

| Code | Name | When |
|-----:|------|------|
| 0 | `success` | Every requested byte was written, **or** the consumer closed the pipe early, **or** the run was a `--dry-run`. |
| 1 | `usage` | Unknown flag, no arguments, an unparseable size or offset, contradictory range flags, `--json`/`--format json*` without `--discard`, a bare `vault:`, an empty argument, a `..` component in a remote path, a directory, or a device/socket/FIFO. |
| 2 | `uncategorised` | Any other I/O failure while reading or writing — a full disk on a redirected stdout, or a failure to emit a JSON record. |
| 4 | `file_not_found` | A local path does not exist, or a remote object is not there. Raised during pre-flight, so nothing was written. |
| 7 | `fatal_error` | The argument names a remote that cannot be resolved or unlocked, or a local file could not be opened for lack of permission. |
| 25 | `cancelled` | Ctrl-C or SIGTERM. Partial output may already have reached the pipe, but nothing was reported as complete. |

Exit 20 (`checksum_mismatch`) cannot occur: `cat` commits nothing. Exit 6
(`partial_failure`) is not reachable either — a failed argument aborts the run
rather than degrading it. Exit 21 (`integrity_failure`) is reachable when a vault
object fails authentication, in which case its bytes are **not** written.

## See also

* [dctl rcat](dctl_rcat.md) — the mirror image: read standard input and store it as one object.
* [dctl copy](dctl_copy.md) — move objects between two named places, with the full verified-write contract.
* [dctl copyto](dctl_copyto.md) — copy a single object to an exact destination name.
* [dctl ls](dctl_ls.md) — list objects and their sizes before reading one.
* [dctl hashsum](dctl_hashsum.md) — print content hashes instead of content.
* [dctl verify](dctl_verify.md) — prove stored objects still decrypt and match their recorded hashes.
* [dctl mount](dctl_mount.md) — the same ranged reads presented as a filesystem.
