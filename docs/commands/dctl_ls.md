# dctl ls

List objects with size and path.

## Synopsis

`dctl ls` is the listing every other command in the family is compared against:
one line per object, recursive by default, paths relative to the spec that was
given. The semantics are rclone's on purpose, because `rclone ls remote:path |
wc -l` is in a lot of people's scripts and a port should need edits to the
remote names and nothing else.

Each line is a fixed-width size column, one space, then the path:

```
  1.00 KiB 2024/shoot-notes.txt
  12.4 MiB 2024/IMG_4417.CR3
  14.1 MiB 2024/IMG_4418.CR3
```

The size column is ten characters wide and right-aligned, so a listing lines up
on screen without the command having to read every object before it can print
the first one. The path column is last and is never padded, so `awk '{print
$NF}'` gets the path on every row. Sizes are rendered for a human and follow
`--units`: `1.44 GiB` by default, `1.55 GB` under `--units decimal`. **Anything
arithmetic belongs in `--json`**, where `Size` is an exact integer and always
will be; a rounded figure quietly loses up to five per cent of a quota
calculation.

An object whose index record carries **no size at all** prints `-`, padded to the
same width, rather than `0 B`. That is the state of every row straight after
`dctl index rebuild`, which lists object names without reading their bodies (see
[`dctl index`](dctl_index.md)). A zero there is a number, and a number gets
summed; the placeholder cannot be. In `--json` the same absence is `"Size": null`.
A file that genuinely *is* zero bytes long still prints `0 B` — the two are
different facts and the listing keeps them apart.

Paths are relative to the spec, exactly as rclone defines it: `dctl ls
vault:photos` reports `2024/IMG_4417.CR3`, not `photos/2024/IMG_4417.CR3`.
Re-address an entry by re-joining it to the spec that produced it. Name a
directory prefix rather than a single object — a spec that names one object
exactly (`vault:photos/a.jpg`) is accepted and lists that object, but since
paths are relative to the spec there is nothing left to print in the path
column.

### Scope

`ls` shares its scope machinery with `lsd`, `lsl`, `lsjson`, `tree` and `size`,
so all six agree about the same vault by construction. A `--exclude` that hid a
file from `ls` but not from `size` would make two commands disagree and leave a
user no way to tell which one was lying.

* `--include` and `--exclude` are repeatable globs. **Exclusion wins**: an entry
  that matches any exclusion is gone regardless of what else it matches, and
  `--include` then narrows whatever survived.
* A pattern beginning with `/` is anchored at the listing root and matched
  against the whole root-relative path. A pattern containing no `/` at all is
  matched against the **file name**, at any depth — `*.jpg` means what everyone
  assumes it means. Anything else is matched against the root-relative path and
  against every suffix of it that starts on a component boundary, so `tmp/*`
  finds `photos/tmp/a` as well as `tmp/a`, and never `photos-tmp/a`.
* In the glob dialect `*` stops at a path separator and `**` crosses one; `?` is
  one non-separator character, `[a-z]` and `[!ab]` are classes, and `\*` is a
  literal asterisk.
* `--min-size` / `--max-size` accept `10G`, `1.5MiB` and `off`.
* `--max-depth N` counts from the listing root and is one-based, so
  `--max-depth 1` means "objects sitting directly in the root". `-1` is
  unlimited and is the default.
* `--filter-from` and `--files-from` are **honoured**, by the same rule engine
  `dctl copy` uses, so the objects `ls` shows are the objects a transfer over the
  same scope would take. A rule file that cannot be read or parsed is a **usage
  error** (exit 1) naming the file and the line, never a run with the rules
  dropped: a listing whose rule file was silently ignored looks complete, and
  listings are what people read before deciding what to delete.

### Ordering, memory and what is actually shown

Entries arrive in ascending lexicographic order of logical path and are never
repeated. Nothing is buffered between pages: the pipeline holds one page of
1000 entries at a time, so a `dctl ls` of a ten-million-object vault costs the
same memory as a listing of ten (`PLAN.md` §16.2). That is why the first line
appears immediately and why `dctl ls vault: | head -5` is cheap — a closed pipe
is treated as success, not as a write failure.

An object appears in a listing only once its write was checksum-verified at the
destination **and** durably committed to the encrypted index (`PLAN.md` §6). A
half-finished upload, or one whose verification failed, is not in the index and
therefore is not in the listing; the verified-write contract is what makes `ls`
a statement about stored data rather than about attempted uploads. `ls` itself
writes nothing, commits nothing and cannot produce a checksum-mismatch failure,
because it never sends bytes to a provider.

The mirror-image half of that contract is the one `ls` has to keep: **never
report an outcome that did not happen.** A listing that cannot reach the index
fails loudly with a non-zero exit code rather than rendering as an empty vault —
a wrong password is exit **22**, an unreadable index is **23**, an unknown remote
is **7**. A script that branched on an empty listing could go on to prune a
backup it believed had been superseded.

**That now holds for a local path too.** `dctl ls ./nope` exits **3**
(`dir_not_found`) and says the path does not exist; so do `lsl`, `lsjson`, `lsd`,
`tree` and `size` over the same target. It used to print nothing and exit **0**,
with only a `-v` note on stderr — the same answer as an empty directory, and
indistinguishable from "the backups are gone" on a machine where the volume
simply was not mounted. A local path that is a *file* rather than a directory is
a usage error (**1**) naming it, instead of the walk's raw
`io error: Not a directory (os error 20)` at exit 2.

A vault prefix that holds nothing is a different case and still exits **0**: in a
vault a path exists exactly while an object is stored under it — the same stance
`dctl mkdir` and `dctl rmdir` take — so an empty listing there is a real answer
rather than an unread one. That is why the check applies only to local targets.

The existence check resolves symbolic links, so `dctl ls /data` where
`/data -> /mnt/disk/data` lists the tree it points at. That is the root the
operator typed. A link found **inside** the tree is a different question and is
answered by `--links`, which passes over one by default and always says so:
`dctl ls /srv` where the only thing under `/srv` is `data -> /mnt/bigdisk/data`
prints nothing on stdout and `skipped 1 symbolic link(s)` on stderr, naming the
flag that lists it. `-v` names the link itself. Silence there was the read-side
half of the defect that made `dctl copy /srv` store nothing and exit 0.

When a listing legitimately comes back empty, `ls` says so on stderr — and
distinguishes the two reasons, because "the directory is empty" sends a user
looking for missing files while "your `--include` matched nothing" sends them to
their own command line. Those notes require `-v`; stdout stays empty either way,
so `dctl ls … | wc -l` still reports zero.

`ls` mutates nothing, so `--dry-run` changes neither its output nor its exit
code. A read-only command that printed `[dry-run] would list` would be noise,
not safety.

### Target grammar

The single positional argument is `REMOTE:PATH`. If it is absent or blank the
command falls back to `--remote` / `DCTL_REMOTE`, which goes through the same
grammar and may itself carry a path (`--remote vault:photos`). With neither, the
command is a usage error rather than a guess.

`\\nas\share\photos` is a **local** path on every platform and `C:\data` and
`d:/data` are local where drives exist, both checked before the colon split. Off
Windows those two name the remotes `C` and `d`, which is rclone's rule. Remote
names may be one character or more and may use letters, digits, `-`, `_` and `.`.
The path half is canonicalised on the way in:
`photos//2024/`, `photos/./2024` and `photos/2024` address the same prefix, an
NFD spelling typed on macOS finds the NFC records an index written on Linux
holds, and a `..` component is rejected rather than allowed to walk out of the
subtree that was named.

### Status in this build

**`dctl ls` reads a vault, and reads a local directory.** Spec parsing, the glob,
the size and depth filters, the rule files, the ordering contract, the streaming
pipeline and all three output formats are implemented, and so is the index read
this page once said was missing: `dctl ls vault:` lists stored objects, and
`dctl ls ./src` walks the filesystem. Earlier revisions of this page claimed both
were unimplemented and quoted an exit-7 error that no build now produces — the
listing shipped and the page did not follow. Undersold documentation is its own
defect: a reader who believes the command cannot work will not run it, and will
not report the one case where it still misreports (an absent local path, above).

The remaining gaps are named where they bite rather than here: exit **3** is not
produced for a missing local directory (*Ordering, memory and what is actually
shown*), and a row whose object `dctl index rebuild` could not read the header
of carries no size (*Synopsis*).

```
dctl ls [REMOTE:PATH] [flags]
```

## Examples

The listings below are what the renderer produces, and every one of them runs in
this build.

List everything in a vault, recursively:

```
dctl ls vault:
  4.00 KiB documents/2024-tax.pdf
  12.4 MiB photos/2024/IMG_4417.CR3
  14.1 MiB photos/2024/IMG_4418.CR3
  1.20 GiB video/wedding-master.mov
```

List one subtree. Paths come back relative to the spec, so `photos/2024/` is not
repeated on every line:

```
dctl ls vault:photos/2024
  12.4 MiB IMG_4417.CR3
  14.1 MiB IMG_4418.CR3
```

Count the raw files in a bucket-backed remote, larger than 8 MB, without reading
a single object body — this is an index query, so there is no egress:

```
dctl ls b2prod:bucket/media --include "*.CR3" --min-size 8M | wc -l
```

Exclusion beats inclusion, which is what makes the pair safe to combine. Here
`private/` is gone even though its contents are JPEGs:

```
dctl ls vault:photos --include "*.jpg" --exclude "private/**"
```

Get exact byte counts for arithmetic. The text size column is rounded on
purpose; `--json` is where the integers live:

```
dctl ls vault:photos/2024 --json | jq '[.[].Size] | add'
```

A Windows path is local, not a remote called `C`. DCTL treats a drive letter and
a UNC path as local on every platform, so the same script behaves the same way on
a build agent: the path is walked as a directory, and it is never resolved
against the configured remotes. The proof is what you *do not* get — a remote
named `C` would fail with `unknown remote 'C'` and exit 7:

```
dctl ls C:\Users\mx\Pictures
  2.10 MiB IMG_0001.JPG
  3.40 MiB holiday/IMG_0002.JPG
```

On a machine where that path does not exist the run exits **3**
(`dir_not_found`) and prints nothing on stdout, so a script cannot read a missing
volume as an empty one.

A rule file shapes the listing, in file order. It is read by the same engine
`dctl copy` uses, so the objects `ls` shows are the objects the transfer that
follows would take:

```
$ cat rules.txt
- /photos/tmp/**
+ /photos/**
- **
$ dctl ls archive: --filter-from rules.txt
       7 B photos/2024/c.jpg
       7 B photos/b.jpg
```

A file that cannot be read or parsed is a usage error naming the file and the
line, rather than a run with the rules dropped — a listing that looks complete
while ignoring the rules meant to shape it is what people read before deciding
what to delete.

## Options

```
  -h, --help   help for ls
```

`ls` declares no flags of its own — everything that shapes a listing is a global
flag, so the six listing verbs cannot drift apart. The positional argument is
`[REMOTE:PATH]`, optional, and falls back to `--remote`. A second positional is
a usage error rather than being silently ignored, so a typo in `dctl ls vault:a
vault:b` is reported instead of hidden. `-V, --version` is propagated to every
subcommand.

## Options inherited from parent commands

Every global flag is accepted. The ones that change what this command does are
`--remote` (the default target), the filters
`--include` / `--exclude` / `--min-size` / `--max-size` / `--max-depth` /
`--filter-from` / `--files-from`, `--format` / `--json` and
`--units` (output shape), `--quiet` and `-v` (whether the stderr notes appear),
and `--config` / `--index` / the `--password*` group (reaching the vault at
all). See [../GLOBAL_FLAGS.md](../GLOBAL_FLAGS.md) for the full list.

## Exit codes

| Code | Name | When |
|-----:|------|------|
| 0 | `success` | The listing was printed, including when it was legitimately empty — an empty *vault* prefix is a real answer. |
| 1 | `usage` | No path and no `--remote`; a remote name shorter than two characters or containing an illegal character; a `..` component; a malformed `--include`/`--exclude` pattern or `--min-size`/`--max-size` value; an unknown flag or a second positional; a local path that exists and is not a directory. |
| 3 | `dir_not_found` | A local path that does not exist. Nothing was read, so this is never reported as an empty tree. |
| 2 | `uncategorised` | A stdout write failed for a reason other than a broken pipe (a full disk on a redirected listing). A broken pipe — `\| head` — is success. |
| 5 | `temporary_error` | The provider could not be reached and the retry budget was exhausted. |
| 7 | `fatal_error` | The remote name is not configured and is not a known provider (`unknown remote 'x'`). |
| 22 | `vault_locked` | Wrong password or recovery phrase, or a damaged envelope. |
| 23 | `index_error` | The encrypted index or its journal could not be read (a missing or unreadable `--index` path). |
| 25 | `cancelled` | Ctrl-C or SIGTERM. A truncated listing is never reported as complete. |

All of these are reachable. A usage error is reported before anything else is
attempted, so a typo in a pattern is diagnosed as a typo rather than as a failure
to reach the vault.

See [../EXIT_CODES.md](../EXIT_CODES.md) for the full contract.

## See also

* [dctl lsl](dctl_lsl.md) — the same listing with a modification-time column.
* [dctl lsjson](dctl_lsjson.md) — the same listing as JSON, whatever `--format`
  says.
* [dctl lsd](dctl_lsd.md) — directories only, with recursive totals.
* [dctl tree](dctl_tree.md) — the same objects drawn as nesting.
* [dctl size](dctl_size.md) — the object count and byte total over the same
  scope.
* [dctl hashsum](dctl_hashsum.md) — content hashes for the same objects.
