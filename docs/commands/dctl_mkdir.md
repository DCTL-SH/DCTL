# dctl mkdir

Create a directory.

## Synopsis

An object store has no directories. `photos/2024/a.jpg` is one flat key that
happens to contain slashes, and a "directory" is nothing more than a shared
prefix among keys — which means **a directory containing no objects does not
exist at all**. It cannot be listed, entered, synced or restored, because there
is nothing there to list.

`dctl mkdir` closes that gap the way object-store tools generally do: it writes a
zero-byte **marker object** at `<dir>/.dctl-dir`. The marker gives the prefix at
least one key, so the directory survives a listing, a `sync` and a restore. On a
backend that *does* have directories — a local filesystem, SFTP — the engine will
create a real directory and skip the marker; that choice belongs to the backend,
not to this command, which is why the plan below names the marker as what *this*
target resolves to rather than as a universal promise. Note that nothing else in
the tree consumes `.dctl-dir` yet: hiding markers from listings, and treating a
directory that holds only its marker as empty for [`rmdir`](dctl_rmdir.md),
arrive with the same engine work described under *What runs today*.

**Most of the time you do not need this command.** `copy`, `sync`, `move` and
`backup` create whatever prefixes their objects require. `mkdir` is for the case
where the *empty* directory is the point: a watch folder something else will drop
files into, a layout created ahead of the data, a subtree you intend to
[`mount`](dctl_mount.md) before it has contents.

**`--parents` plans the whole ancestor chain, outermost first.** `dctl mkdir -p
vault:a/b/c` plans `a`, then `a/b`, then `a/b/c`, and the plan prints them in
that creation order so it can be checked against what actually happened. Without
`--parents` exactly one directory is planned, and whether its parent exists is
the engine's problem to report — the same division of labour as `mkdir(1)`, which
answers `No such file or directory` rather than creating the chain for you.

**Target resolution is the directory family's strict parse**, shared with
[`touch`](dctl_touch.md):

* The target is `REMOTE:PATH`. A remote name is at least two characters, so
  `C:\photos\2024` is a Windows drive path, `\\server\share\x` is a UNC path, and
  both are local and refused. A string with no colon at all is local too.
* `..` components are refused rather than resolved: a target may not climb out of
  the vault it names.
* The remote root is not a target. `dctl mkdir vault:` is a usage error — the
  root always exists, and guessing which directory was meant would be worse than
  saying so.
* The path is canonicalised before anything looks at it: `.` and empty components
  are dropped, backslashes fold to `/`, and the result is NFC-normalised. So
  `vault:./photos//2024/` and `vault:photos/2024` are one directory, and the
  decomposed `café` a macOS shell hands over is the same target as the composed
  `café` a Linux shell does. Two spellings must never become two directories.

**Relationship to the verified-write contract.** The marker is an object like any
other, so when the engine lands it goes through the `PLAN.md` §6 pipeline: staged
under a temporary key, the provider's stored checksum compared against the
locally computed one, and **a mismatch hard-aborts** — the staged object is
deleted, nothing is committed, the exit code is 20 (`checksum_mismatch`), and the
directory does not exist afterwards. The directory counts as created only after
the index entry is committed in a single ACID transaction; that commit, not the
upload, is what makes it real. `mkdir` never deletes or overwrites anything: it
is the exact inverse of [`rmdir`](dctl_rmdir.md), and the only command in the
directory family that is not destructive in any mode.

### What runs today

**The write is not implemented in this build.** Argument parsing, target
resolution, the `--parents` chain, marker naming, the plan and every output
format are complete and tested. Writing the marker needs a `dctl-core` vault
handle reachable from the command context, and the CLI does not carry one yet.

Rather than print a success message for a write that never happened — the one
thing `PLAN.md` §6 forbids — a real run emits its plan and then exits **7**
(`fatal_error`):

```
error: dctl mkdir is not implemented in this build
warning: Parsing, validation and planning are complete: re-run with --dry-run to
see exactly what would be created. Writing the object needs a dctl-core vault
handle (PLAN.md §6) reachable from the command context, which the CLI does not
carry yet.
```

A `--dry-run` exits **0**, because a dry run promises a report and delivers
exactly that. In particular, **a `dctl mkdir` that fails today says nothing about
whether the directory exists** — nothing was inspected and nothing was written.
The engine arrives with the `PLAN.md` §11 **Phase 1 (B2 MVP)** milestone, which
is where the vault handle, the encrypted index and the §6 write pipeline land.

```
dctl mkdir REMOTE:PATH [flags]
```

## Examples

Preview one directory. The plan goes to stdout; the `[dry-run]` notice goes to
stderr, so `... --dry-run > plan.txt` keeps the two apart:

```console
$ dctl mkdir vault:photos/2024 --dry-run
Command    mkdir
Target     vault:photos/2024
Mode       dry-run
Parents    no
Directory  photos/2024
Marker     photos/2024/.dctl-dir
warning: [dry-run] would create directory: vault:photos/2024
```

With `--parents`, every ancestor is listed in creation order, each with the
marker it would write. This is the report to read before a scripted layout runs:

```console
$ dctl mkdir vault:photos/2024/raw/scans -p --dry-run
Command    mkdir
Target     vault:photos/2024/raw/scans
Mode       dry-run
Parents    yes
Directory  photos
Directory  photos/2024
Directory  photos/2024/raw
Directory  photos/2024/raw/scans
Marker     photos/2024/raw/scans/.dctl-dir
warning: [dry-run] would create directory: vault:photos/2024/raw/scans
```

The same plan as JSON, for a script that wants the chain rather than the prose.
The document describes the *request* only — there is no `created` field, because
a plan is not an outcome:

```console
$ dctl mkdir b2prod:bucket/media/proxies -p --dry-run --json
{
  "command": "mkdir",
  "target": {
    "remote": "b2prod",
    "path": "bucket/media/proxies"
  },
  "dry_run": true,
  "options": {
    "parents": true,
    "directories": [
      {
        "path": "bucket",
        "marker": "bucket/.dctl-dir"
      },
      {
        "path": "bucket/media",
        "marker": "bucket/media/.dctl-dir"
      },
      {
        "path": "bucket/media/proxies",
        "marker": "bucket/media/proxies/.dctl-dir"
      }
    ]
  },
  "status": "planned"
}
```

A real run prints the same plan, labelled `execute`, and then refuses. Nothing
was written and nothing was checked:

```console
$ dctl mkdir vault:photos/2025
Command    mkdir
Target     vault:photos/2025
Mode       execute
Parents    no
Directory  photos/2025
Marker     photos/2025/.dctl-dir
error: dctl mkdir is not implemented in this build
warning: Parsing, validation and planning are complete: re-run with --dry-run to
see exactly what would be created. ...
$ echo $?
7
```

A Windows path is local, drive letter and all, and is refused before anything is
resolved. The rule is the same on every platform, so a script written on Windows
fails identically on a Linux build agent:

```console
$ dctl mkdir C:\Users\me\Pictures\2024
error: 'C:\Users\me\Pictures\2024' is a local path, not a remote
warning: This command operates on a remote, written REMOTE:PATH. Your operating
system's own mkdir and touch already handle local paths.
$ echo $?
1
```

The remote root is not a directory anyone can create:

```console
$ dctl mkdir archive:
error: 'archive:' is the root of 'archive'
warning: The root of a remote always exists. Name the directory inside it, for
example 'archive:photos/2024'.
```

## Options

```
  -h, --help     help for mkdir
  -p, --parents  Create missing parent directories as well
```

The positional argument is `<REMOTE:PATH>`: the directory to create. It is
required, and it must name something *inside* a remote. A trailing separator is
accepted and cleaned away — `vault:photos/2024/` and `vault:photos/2024` are the
same target.

## Options inherited from parent commands

Every global flag is accepted; see [../GLOBAL_FLAGS.md](../GLOBAL_FLAGS.md). The
ones that matter here:

| Flag | Effect here |
|------|-------------|
| `-n`, `--dry-run` | Print the plan, change nothing, exit 0. The only way this command succeeds today. |
| `--format`, `--json` | Render the plan as an aligned table (`text`, the default), one pretty JSON document (`json`), or one JSON record per line (`json-lines`). |
| `--quiet` | Suppress the `[dry-run]` notice and warnings. The plan still goes to stdout; errors are still printed. |
| `-v`, `--verbose` | `-vv` logs the resolved remote, path, `--parents` flag and the number of planned directories. |

The filter flags (`--include`, `--exclude`, `--min-size`, …) are accepted and
have no effect: this command addresses one named container, not a set of objects.
`--verify`, `--checksum` and `--size-only` likewise do nothing until the marker
write exists. `--immutable` is not consulted — `mkdir` only ever adds.

## Exit codes

See [../EXIT_CODES.md](../EXIT_CODES.md) for the full contract.

| Code | Name | When |
|------|------|------|
| 0 | `success` | `--dry-run` only: the plan was printed and nothing was written. |
| 1 | `usage` | An unparseable command line; an empty target; a local, UNC or drive-letter path; a remote name shorter than two characters or containing a separator; a `..` component; the remote root (`REMOTE:`). |
| 2 | `uncategorised` | The plan could not be written to stdout. A closed pipe is *not* an error — `dctl mkdir ... --json \| head -1` succeeds. |
| 7 | `fatal_error` | The marker write is unavailable. **Every real run ends here today**, after the plan has been printed. Nothing was created and nothing was inspected. |
| 25 | `cancelled` | Ctrl-C or SIGTERM. No partial work is reported as stored. |

When the engine lands, the §6 contract makes 20 (`checksum_mismatch`) reachable
for a marker the provider stored incorrectly, 22 (`vault_locked`) for a vault
that will not unlock, 23 (`index_error`) for a failed index commit, and 3
(`dir_not_found`) for a missing parent when `--parents` was not given.

## See also

* [dctl touch](dctl_touch.md) — the other half of the directory family: create an object, or set its modification time.
* [dctl rmdir](dctl_rmdir.md) — the exact inverse: remove one empty directory.
* [dctl rmdirs](dctl_rmdirs.md) — sweep every empty directory under a path.
* [dctl purge](dctl_purge.md) — remove a directory *and* everything in it.
* [dctl copy](dctl_copy.md) — creates the prefixes its objects need; use it instead when the directory is not the point.
* [dctl mount](dctl_mount.md) — serve a vault or a subtree as a filesystem, where `mkdir` becomes a filesystem operation.
