# dctl touch

Create an object, or update its modification time.

## Synopsis

An object store has no `utimes()`. A provider's "last modified" is the time *it*
accepted the upload, and nothing a client sends can change it afterwards. DCTL
therefore keeps the file's real modification time in its own encrypted index
(`modified_unix`), which is also what makes a `copy` or `check` comparison
meaningful across two providers that disagree about their own clocks.
`dctl touch` writes that field — and, when the object does not exist yet, an
empty object for the field to hang on.

**This is not a niche convenience.** [`sync`](dctl_sync.md) and
[`copy`](dctl_copy.md) decide what to transfer from size and modification time,
so being able to set a time is being able to say "this file is current, do not
re-upload 40 GB of it". It is also how you make a freshly restored tree stop
looking newer than its source, and how a scripted pipeline stamps a sentinel
object that a later step waits on.

**Timestamps are UTC and whole seconds.** Both rules are enforced by the argument
parser, before the command body runs:

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
spelling, the plan prints one canonical form, `YYYY-MM-DDTHH:MM:SSZ`, alongside
the raw epoch integer the index will store — so a script never has to re-parse
the string DCTL just printed.

**`--no-create` mirrors `touch -c`**: re-stamp what exists, stay silent about what
does not. Combining it with the global `--immutable` is a **usage error**, not a
no-op: `--no-create` forbids creating and `--immutable` forbids modifying, so the
run could not possibly act, and a command guaranteed to do nothing is a mistake
worth naming. Either flag on its own is fine.

**Target resolution is the directory family's strict parse**, shared with
[`mkdir`](dctl_mkdir.md): the target is `REMOTE:PATH`; a remote name is at least
two characters, so `C:\Users\me\notes.txt` is a Windows drive path and
`\\server\share\x` is a UNC path, and both are local and refused; a string with
no colon is local too; `..` components are refused; the remote root (`vault:`) is
not a target, because stamping a time on the root means nothing. The path is
canonicalised — `.` and empty components dropped, backslashes folded to `/`, NFC
applied — so `vault:./notes//todo.md` and `vault:notes/todo.md` are one object,
and macOS's decomposed spelling of an accented name matches Linux's composed one.

**Relationship to the verified-write contract.** When the object has to be
created, the empty object is written through the `PLAN.md` §6 pipeline like any
other: staged under a temporary key, the provider's stored checksum compared
against the locally computed one, and **a mismatch hard-aborts** — the staged
object is deleted, nothing is committed, and the exit code is 20
(`checksum_mismatch`). The modification time itself becomes real only when the
index entry is committed in a single ACID transaction; until that commit, nothing
has changed. `touch` never truncates or replaces an object that already has
content — for an existing object it sets a field, and for a missing one it
creates an empty object. To *write* content, use [`rcat`](dctl_rcat.md) or
[`copy`](dctl_copy.md).

### What runs today

**Neither half of the write is implemented in this build.** Argument parsing,
timestamp conversion, target resolution, the `--no-create` / `--immutable`
refusal, the plan and every output format are complete and tested. Creating the
empty object needs a `dctl-core` vault handle reachable from the command context,
which the CLI does not carry yet; setting the time additionally needs an index
operation for "update the modification time of an existing record", which does
not exist yet either.

Rather than print a success message for a write that never happened — the one
thing `PLAN.md` §6 forbids — a real run emits its plan and then exits **7**
(`fatal_error`):

```
error: dctl touch is not implemented in this build
warning: Parsing, validation and planning are complete: re-run with --dry-run to
see exactly what would be created. Writing the object needs a dctl-core vault
handle (PLAN.md §6) reachable from the command context, which the CLI does not
carry yet.
```

A `--dry-run` exits **0**, because a dry run promises a report and delivers
exactly that. A failure today therefore says nothing about whether the object
exists or what time it carries — nothing was read. The engine arrives with the
`PLAN.md` §11 **Phase 1 (B2 MVP)** milestone, which is where the vault handle,
the encrypted index and the §6 write pipeline land.

```
dctl touch REMOTE:PATH [flags]
```

## Examples

Stamp an object with the current time. The plan goes to stdout, the `[dry-run]`
notice to stderr; `Timestamp source` says where the time came from, so a report
read later is not ambiguous about whether a time was chosen or defaulted:

```console
$ dctl touch vault:notes/todo.md --dry-run
Command            touch
Target             vault:notes/todo.md
Mode               dry-run
Object             notes/todo.md
Timestamp          2026-07-26T09:15:04Z
Timestamp source   now
Create if missing  yes
warning: [dry-run] would set the modification time of: vault:notes/todo.md
```

Set an explicit time, so a restored file stops looking newer than the source it
came from and `sync` stops wanting to re-upload it. Note the canonical rendering:
the input was written in the loose form, the plan prints RFC 3339:

```console
$ dctl touch b2prod:bucket/media/reel.mov -t '2024-05-01 12:00' --dry-run
Command            touch
Target             b2prod:bucket/media/reel.mov
Mode               dry-run
Object             bucket/media/reel.mov
Timestamp          2024-05-01T12:00:00Z
Timestamp source   explicit
Create if missing  yes
warning: [dry-run] would set the modification time of: b2prod:bucket/media/reel.mov
```

The same plan as JSON. The timestamp appears twice on purpose — once canonically
for a human, once as the integer the index stores — and no field claims the write
happened:

```console
$ dctl touch vault:photos/2024/index.json -t @1714564800 -c --dry-run --json
{
  "command": "touch",
  "target": {
    "remote": "vault",
    "path": "photos/2024/index.json"
  },
  "dry_run": true,
  "options": {
    "object": "photos/2024/index.json",
    "timestamp": "2024-05-01T12:00:00Z",
    "timestamp_unix": 1714564800,
    "timestamp_source": "explicit",
    "create_if_missing": false
  },
  "status": "planned"
}
```

A zone offset is refused rather than converted, because converting would make the
same command mean different things on two machines:

```console
$ dctl touch vault:notes/todo.md -t 2024-05-01T12:00:00+02:00
error: invalid value '2024-05-01T12:00:00+02:00' for '--timestamp <TIME>': '2024-05-01T12:00:00+02:00' carries a zone offset. DCTL timestamps are UTC: convert the time first, or append Z if it already is.

For more information, try '--help'.
$ echo $?
1
```

A date that does not exist is an error, never the following day:

```console
$ dctl touch vault:notes/todo.md -t 2023-02-29
error: invalid value '2023-02-29' for '--timestamp <TIME>': '2023-02-29' is not a date DCTL can represent (years 1 to 9999, and the day must exist in its month)
```

`--no-create` with the global `--immutable` forbids both halves of what this
command does, so it is refused before anything else happens:

```console
$ dctl touch vault:notes/todo.md --no-create --immutable --dry-run
error: --no-create and --immutable together allow neither creating nor modifying anything
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
| `-n`, `--dry-run` | Print the plan, change nothing, exit 0. The only way this command succeeds today. |
| `--immutable` | Refuses to modify anything that already exists. **Conflicts with `--no-create`** — together they permit nothing, and the combination is a usage error. |
| `--format`, `--json` | Render the plan as an aligned table (`text`, the default), one pretty JSON document (`json`), or one JSON record per line (`json-lines`). |
| `--quiet` | Suppress the `[dry-run]` notice and warnings. The plan still goes to stdout; errors are still printed. |
| `-v`, `--verbose` | `-vv` logs the resolved remote, path, epoch timestamp and whether a missing object would be created. |

The filter flags are accepted and have no effect: this command addresses one
named object, not a set. `--verify`, `--checksum` and `--size-only` do nothing
until the write exists.

## Exit codes

See [../EXIT_CODES.md](../EXIT_CODES.md) for the full contract.

| Code | Name | When |
|------|------|------|
| 0 | `success` | `--dry-run` only: the plan was printed and nothing was written. |
| 1 | `usage` | An unparseable command line; a `--timestamp` DCTL does not accept, carrying a zone offset, or naming a date that does not exist; an empty target; a local, UNC or drive-letter path; a remote name shorter than two characters or containing a separator; a `..` component; the remote root (`REMOTE:`); `--no-create` together with `--immutable`. |
| 2 | `uncategorised` | The plan could not be written to stdout. A closed pipe is *not* an error. |
| 7 | `fatal_error` | Creating the object and setting the time are both unavailable. **Every real run ends here today**, after the plan has been printed. Nothing was written and nothing was read. |
| 25 | `cancelled` | Ctrl-C or SIGTERM. No partial work is reported as stored. |

When the engine lands, the §6 contract makes 20 (`checksum_mismatch`) reachable
for an empty object the provider stored incorrectly, 22 (`vault_locked`) for a
vault that will not unlock, and 23 (`index_error`) for a failed index commit.
`--no-create` against an object that is not there follows `touch -c`: there is
nothing to do, and nothing to report.

## See also

* [dctl mkdir](dctl_mkdir.md) — the other half of the directory family: create a directory.
* [dctl rcat](dctl_rcat.md) — create an object *with* content, from standard input.
* [dctl copy](dctl_copy.md) — transfer files, skipping ones whose size and modification time already match.
* [dctl sync](dctl_sync.md) — make a destination identical to a source; the command whose decisions a `touch` changes.
* [dctl check](dctl_check.md) — compare two trees without transferring, to see which times differ.
* [dctl lsl](dctl_lsl.md) — list objects with their modification times.
