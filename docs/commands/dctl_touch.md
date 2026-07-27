# dctl touch

Create an object, or update its modification time.

## Synopsis

An object store has no `utimes()`. A provider's "last modified" is the time *it*
accepted the upload, and nothing a client sends can change it afterwards. DCTL
therefore keeps the file's real modification time in its own encrypted index
(`modified_unix`), which is also what makes a `copy` or `check` comparison
meaningful across two providers that disagree about their own clocks.

**This is not a niche convenience.** [`sync`](dctl_sync.md) and
[`copy`](dctl_copy.md) decide what to transfer from size and modification time,
so being able to set a time is being able to say "this file is current, do not
re-upload 40 GB of it". It is also how you make a freshly restored tree stop
looking newer than its source, and how a scripted pipeline stamps a sentinel
object that a later step waits on.

### What runs, per backend

`touch` is two operations wearing one name — *create an empty object* and *set a
modification time* — and the three kinds of place DCTL can address support
different halves of it:

| | A local remote | A vault remote | An object store |
|---|---|---|---|
| The object is missing | created empty | created empty | refused |
| The object exists | re-stamped, contents untouched | **refused** | refused |
| `--timestamp` | honoured exactly | honoured on create; **refused** on an object that exists | refused |
| `--no-create` on a missing object | `skipped` | `skipped` | refused |

**A local remote does both halves**, because the operating system owns the
timestamps: a missing file is created empty, an existing one is re-stamped
without losing a byte, and both the modification and access times are written —
`touch(1)` sets both, and a tool that moved only one would leave a tree no
`find -newer` agrees with.

**A vault creates — with the time you asked for — and cannot re-stamp.** An
empty object is a real, storable thing: `dctl touch archive:sentinel` seals a
zero-byte object, writes it with the same verified write every other object gets,
and commits an index record. It then appears in `dctl ls archive:` at `0 B`, like
any other file. `dctl touch -t 2024-05-01 archive:sentinel` creates it carrying
that time, and `dctl lsl archive:` prints the time it was asked for.

Changing the time of an object the vault *already* holds has nowhere to go, and
the command refuses rather than doing something else:

```
error: a dctl_core::Vault call that updates the modification time of a stored
record — which is what re-stamping an object a vault already holds would need —
is not implemented in this build
warning: The object was not modified. A vault keeps modification times in its
encrypted index and dctl-core exposes no call that updates one, so DCTL will not
pretend to. Re-write the object (`dctl copy` or `dctl rcat`) if a current time is
what you need, or run `touch` against a plain local remote, where the
filesystem's own timestamps are settable. 'archive:sentinel' keeps the
modification time it was written with (2026-07-26T23:34:45Z).
```

The message names the **missing call**, not the command. Everything `dctl touch`
does against a vault works; there is no branch missing here to go and find.

The gap is a `dctl-core` boundary rather than a missing branch here: the time
lives in the encrypted index, `Vault` exposes no operation that updates a
record's `modified_unix`, and the index handle is private to the core. Two
alternatives were rejected — re-storing the object would need contents `touch`
does not have and must not destroy, and opening the index directly from the CLI
would mean a second writer to a database the vault holds open and a second
implementation of a format `dctl-core` owns.

**`--timestamp` on the create path used to be refused too, and no longer is.**
The refusal was honest while it stood: the write took no time from the caller, so
there was no argument for the flag to become, and creating the object while
reporting the requested time would have been a lie. That argument now exists —
added so `dctl copy` could record a source's modification time instead of the
moment of the upload — so the flag is honoured. Only re-stamping something the
vault already holds is still refused, and for its own reason.

**An object store is refused outright, and this one is nobody's build gap.**
The refusal used to read "nothing in this build writes a plain object into a
bucket". That is no longer true — `dctl copy ./file b2:bucket/key` writes one —
and it was never the reason `touch` could not work there. A bucket has no
`utimes()`: B2, S3 and R2 each assign `Last-Modified` when they accept the
object and expose no operation that moves it. The missing capability is the
**provider's**, one layer below `dctl-store`, and **no phase of `PLAN.md`
delivers it**, so the message names no release to wait for. Creating an empty
object there *is* possible — that is a write, not a stamp — and `dctl copy` of
an empty file performs it.

### Timestamps are UTC and whole seconds

Both rules are enforced by the argument parser, before the command body runs:

* A time with no zone is read as UTC, and **an explicit zone offset is refused
  rather than converted**. A laptop that crossed a timezone between two backups
  must not write two different modification times for the same content, and
  "which zone was this machine in that night?" is not a question a restore should
  have to answer. Append `Z` if the time already is UTC; convert it yourself if
  it is not.
* The index stores whole seconds, so a fractional part is parsed and **discarded**
  rather than rejected — a timestamp pasted from another tool's RFC 3339 output
  just works, and rounding it would move the file's time by up to a second
  without saying so.

The accepted spellings are `2024-05-01T12:00:00Z`, `'2024-05-01 12:00'`,
`2024-05-01`, and `@1714564800` (seconds since the Unix epoch). The separator
between date and time may be `T`, `t` or a space; the seconds field is optional;
a trailing `Z` or `z` is accepted and redundant. Dates are validated against a
real calendar with the Gregorian leap rule, so `2024-02-29` is accepted,
`2023-02-29` and `2024-04-31` are errors rather than the following day, and
second `60` — RFC 3339's leap second — is refused rather than silently clamped.
Years run from `0001` to `9999`; times before 1970 are negative, not an error, so
`@-1` and `1969-12-31T23:59:59Z` are the same instant. Whatever the input
spelling, the report prints one canonical form, `YYYY-MM-DDTHH:MM:SSZ`, alongside
the raw epoch integer the index would store — so a script never has to re-parse
the string DCTL just printed.

### Flags that could not act

**`--no-create` mirrors `touch -c`**: re-stamp what exists, stay silent about what
does not. A missing object is reported as `skipped`, which is a success with a
distinct word rather than a silent zero. Combining it with the global
`--immutable` is a **usage error**, not a no-op: `--no-create` forbids creating
and `--immutable` forbids modifying, so the run could not possibly act, and a
command guaranteed to do nothing is a mistake worth naming. Either flag on its
own is fine.

**Target resolution is the directory family's strict parse**, shared with
[`mkdir`](dctl_mkdir.md): the target is `REMOTE:PATH`; a remote name is at least
two characters, so `C:\Users\me\notes.txt` is a Windows drive path and
`\\server\share\x` is a UNC path, and both are local and refused; a string with
no colon is local too; `..` components are refused; the remote root (`archive:`)
is not a target, because stamping a time on the root means nothing. The path is
canonicalised — `.` and empty components dropped, backslashes folded to `/`, NFC
applied — so `archive:./notes//todo.md` and `archive:notes/todo.md` are one
object, and macOS's decomposed spelling of an accented name matches Linux's
composed one.

**An object inside a vault's object store is refused**, by the same addressing
rule that stops `copy` and `rcat` writing plaintext there.

**Relationship to the verified-write contract.** When an object has to be
created in a vault, the empty object goes through the `PLAN.md` §6 pipeline like
any other: sealed, written with the provider's stored checksum compared against
the locally computed one, and committed to the index in a single durable
operation. A mismatch hard-aborts with exit 20 (`checksum_mismatch`) and nothing
is committed. `touch` never truncates or replaces an object that already has
content — on a filesystem it sets a field and leaves every byte in place, and to
*write* content you use [`rcat`](dctl_rcat.md) or [`copy`](dctl_copy.md).

```
dctl touch REMOTE:PATH [flags]
```

## Examples

Create an empty object in a vault. It is a real object: it appears in `ls`, it
can be read back, and it carries the time of the write:

```console
$ dctl touch archive:sentinel
Command            touch
Target             archive:sentinel
Mode               execute
Object             sentinel
Backend            vault
Timestamp          2026-07-26T22:23:40Z
Timestamp source   now
Create if missing  yes
Outcome            created
OK created empty object: archive:sentinel
$ dctl ls archive:
      12 B a.txt
       0 B sentinel
```

Create and stamp a file on a local remote. `Timestamp source` says where the time
came from, so a report read later is not ambiguous about whether a time was
chosen or defaulted:

```console
$ dctl touch scratch:notes.txt -t '2024-05-01 12:00'
Command            touch
Target             scratch:notes.txt
Mode               execute
Object             notes.txt
Backend            local
Timestamp          2024-05-01T12:00:00Z
Timestamp source   explicit
Create if missing  yes
Outcome            created
OK created empty object: scratch:notes.txt
$ ls -l /mnt/scratch/notes.txt
-rw-r--r--  1 mx  wheel  0 May  1  2024 /mnt/scratch/notes.txt
```

Re-stamping an existing file changes the time and nothing else:

```console
$ dctl touch scratch:notes.txt -t @0
...
Outcome            stamped
OK set the modification time of: scratch:notes.txt
$ cat /mnt/scratch/notes.txt
content
```

`--no-create` against something that is not there does nothing, and says so:

```console
$ dctl touch archive:absent -c
...
Create if missing  no
Outcome            skipped
OK not there and --no-create was given, so nothing was done for: archive:absent
$ echo $?
0
```

An object the vault already holds cannot be re-stamped. **The refusal names the
missing `dctl-core` call rather than this command**, because that is where the
gap actually is — nothing is missing in `dctl touch`, and a message blaming it
would send you looking here for a branch that is not absent:

```console
$ dctl touch archive:sentinel
error: a dctl_core::Vault call that updates the modification time of a stored record — which is what re-stamping an object a vault already holds would need — is not implemented in this build
warning: The object was not modified. A vault keeps modification times in its encrypted index and dctl-core exposes no call that updates one, so DCTL will not pretend to. Re-write the object (`dctl copy` or `dctl rcat`) if a current time is what you need, or run `touch` against a plain local remote, where the filesystem's own timestamps are settable. 'archive:sentinel' keeps the modification time it was written with (2026-07-26T23:34:45Z).
$ echo $?
7
```

Creating one with a chosen time, on the other hand, works:

```console
$ dctl touch archive:dated -t 2024-05-01T12:00:00Z
OK created: archive:dated
$ dctl lsl archive:
        0 2024-05-01T12:00:00Z dated
```

That used to be a second refusal, and the reasoning it carried was sound at the
time: `Vault::put_file` stamped the moment of the write and took no timestamp
from the caller, so there was no argument for `--timestamp` to become. The write
takes one now — `dctl copy` needed it to record a source's modification time
instead of the moment of the upload — and a refusal kept past the reason for it is
how a tool ends up with rules nobody can explain.

A bucket has no settable modification time — the one thing `touch` exists to
set. The refusal says so, and offers the two things that *are* possible instead
of a phase that is never coming:

```console
$ dctl touch b2:mybucket/x
error: setting the modification time of an object in an object store — the
provider assigns it on write and exposes no way to change it — (b2, dctl touch)
is not implemented in this build
warning: Nothing was written. A bucket's 'last modified' is the time the provider
stored the object, not a value DCTL can set — no phase of PLAN.md changes that,
because it is the provider's own model. To create an empty object there, copy an
empty file with `dctl copy`; to stamp a time, address a local remote, whose
filesystem timestamps are settable.
$ echo $?
7
```

The plan as JSON. The timestamp appears twice on purpose — once canonically for a
human, once as the integer the index stores — and `status` reports what happened:

```console
$ dctl touch archive:photos/2024/index.json -c --json
{
  "command": "touch",
  "target": {
    "remote": "archive",
    "path": "photos/2024/index.json"
  },
  "dry_run": false,
  "options": {
    "object": "photos/2024/index.json",
    "backend": "vault",
    "timestamp": "2026-07-26T22:28:38Z",
    "timestamp_unix": 1785104918,
    "timestamp_source": "now",
    "create_if_missing": false
  },
  "status": "skipped"
}
```

A zone offset is refused rather than converted, because converting would make the
same command mean different things on two machines:

```console
$ dctl touch archive:notes/todo.md -t 2024-05-01T12:00:00+02:00
error: invalid value '2024-05-01T12:00:00+02:00' for '--timestamp <TIME>': '2024-05-01T12:00:00+02:00' carries a zone offset. DCTL timestamps are UTC: convert the time first, or append Z if it already is.

For more information, try '--help'.
$ echo $?
1
```

A date that does not exist is an error, never the following day:

```console
$ dctl touch archive:notes/todo.md -t 2023-02-29
error: invalid value '2023-02-29' for '--timestamp <TIME>': '2023-02-29' is not a date DCTL can represent (years 1 to 9999, and the day must exist in its month)
```

`--no-create` with the global `--immutable` forbids both halves of what this
command does, so it is refused before anything else happens:

```console
$ dctl touch archive:notes/todo.md --no-create --immutable
error: --no-create and --immutable together allow neither creating nor modifying
anything
warning: Drop --immutable to re-stamp an object that exists, or drop --no-create
to create one that does not.
$ echo $?
1
```

A Windows path is local, drive letter and all, and is refused before the target
is resolved. The rule applies on every platform, so a script written on Windows
behaves identically on a Linux build agent:

```console
$ dctl touch C:\Users\me\notes\todo.md
error: 'C:\Users\me\notes\todo.md' is a local path, not a remote
warning: This command operates on a remote, written REMOTE:PATH. Your operating
system's own mkdir and touch already handle local paths.
```

## Options

```
  -h, --help              help for touch
  -c, --no-create         Do not create the object if it does not exist
  -t, --timestamp <TIME>  Modification time to set, instead of the current time
```

The positional argument is `<REMOTE:PATH>`: the object to create or re-stamp. It
is required and must name something inside a remote. `--timestamp` is validated
by the argument parser, so a malformed value fails as a usage error with the
accepted spellings quoted, before the command body runs. Without it, the time is
the moment the command started, read as UTC.

## Options inherited from parent commands

Every global flag is accepted; see [../GLOBAL_FLAGS.md](../GLOBAL_FLAGS.md). The
ones that matter here:

| Flag | Effect here |
|------|-------------|
| `-n`, `--dry-run` | Print the plan, change nothing, exit 0. A vault is not unlocked and no password is asked for. |
| `--immutable` | Refuses to modify anything that already exists. **Conflicts with `--no-create`** — together they permit nothing, and the combination is a usage error. |
| `--format`, `--json` | Render the report as an aligned table (`text`, the default), one pretty JSON document (`json`), or one JSON record per line (`json-lines`). |
| `--quiet` | Suppress the outcome line and the `[dry-run]` notice. The report still goes to stdout; errors are still printed. |
| `-v`, `--verbose` | `-vv` logs the resolved remote, path, backend kind, epoch timestamp and whether a missing object would be created. |

The filter flags are accepted and have no effect: this command addresses one
named object, not a set. `--verify`, `--checksum` and `--size-only` do nothing —
a vault's empty object is already written through the verified-write pipeline,
and there is nothing to compare.

## Exit codes

See [../EXIT_CODES.md](../EXIT_CODES.md) for the full contract.

| Code | Name | When |
|------|------|------|
| 0 | `success` | The object was created, re-stamped, or deliberately skipped. The `Outcome` row and the JSON `status` say which. |
| 1 | `usage` | An unparseable command line; a `--timestamp` DCTL does not accept, carrying a zone offset, or naming a date that does not exist; an empty target; a local, UNC or drive-letter path; a remote name shorter than two characters or containing a separator; a `..` component; the remote root (`REMOTE:`); `--no-create` together with `--immutable`; an existing object under `--immutable`; a target that names a directory on a filesystem. |
| 2 | `uncategorised` | The report could not be written to stdout. A closed pipe is *not* an error. |
| 4 | `file_not_found` | A local target whose parent directory does not exist — `touch(1)` does not create directories either. |
| 7 | `fatal_error` | An unknown remote; a re-stamp a vault cannot perform; an object store, which has no settable modification time at all; a destination the addressing rule claims for a vault's object store. In every one of these, **nothing was written**. |
| 20 | `checksum_mismatch` | A vault's empty object was not stored as sent. Nothing was committed. |
| 22 | `vault_locked` | The vault would not unlock. |
| 23 | `index_error` | The index commit failed. |
| 25 | `cancelled` | Ctrl-C or SIGTERM. No partial work is reported as stored. |

## See also

* [dctl mkdir](dctl_mkdir.md) — the other half of the directory family: create a directory.
* [dctl rcat](dctl_rcat.md) — create an object *with* content, from standard input.
* [dctl copy](dctl_copy.md) — transfer files, skipping ones whose size and modification time already match.
* [dctl sync](dctl_sync.md) — make a destination identical to a source; the command whose decisions a `touch` changes.
* [dctl check](dctl_check.md) — compare two trees without transferring, to see which times differ.
* [dctl lsl](dctl_lsl.md) — list objects with their modification times.
