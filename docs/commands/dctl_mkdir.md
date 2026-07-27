# dctl mkdir

Create a directory, where the backend has directories.

## Synopsis

A filesystem has directories: real objects that exist in their own right, can be
empty, and can be created before anything is put in them. An object store has
none. `photos/2024/a.jpg` is one flat key that happens to contain slashes, and a
"directory" there is nothing more than a shared prefix among keys — so it exists
exactly while some key sits under it, and **a directory containing no objects
does not exist at all**. A vault inherits that exactly: its index maps logical
paths to sealed objects, and a prefix nothing is stored under is simply a prefix
nothing is stored under.

So `dctl mkdir` does two different things, and reports which:

| Backend | What happens | Outcome |
|---------|--------------|---------|
| A local remote (`type = "local"`) | a real directory is created | `created`, or `already_present` |
| A vault remote | nothing is created; nothing is missing | `not_required` |
| An object store (`b2`, `s3`, `r2`) | nothing is created; nothing is missing | `not_required` |

**On a vault, `mkdir` succeeds and writes nothing.** That is a decision, not an
omission, and the command says so on every run:

```
OK archive:photos/2024: vault has no directories: a path there exists exactly
while an object is stored under it, so there is nothing to create and nothing is
missing
```

Two alternatives were considered and rejected:

* **Refusing.** The postcondition a user wants from `mkdir` — *an object may now
  be stored at this path* — already holds before they type it. Failing would
  break the ordinary `dctl mkdir archive:a/b && dctl copy ./x archive:a/b/` for a
  condition that is not an error, and a command that refuses when its goal is
  already met teaches people to ignore its exit code.
* **Writing a `.dctl-dir` marker object.** This is what earlier builds planned to
  do. A marker is a real object in *your* namespace: `ls`, `size`, `check`,
  `sync`, `hashsum` and every restore would carry it as data and round-trip it.
  Fabricating a file so that a directory can be reported is a larger misreport
  than the absence it hides. DCTL therefore never writes one. The name is still
  *recognised* by [`rmdir`](dctl_rmdir.md), so a marker left by an older build or
  by another object-store tool pointed at the same bucket is treated as a
  directory declaration rather than as one of your files.

**`--parents` follows the same rule**, because anything else would be
incoherent. Where directories exist it creates the whole ancestor chain
outermost first and makes an existing directory a success, exactly like
`mkdir -p`. Where they do not, there is nothing to create at any level of the
chain, so the flag changes nothing — the plan still lists the chain, because the
plan describes the request rather than the outcome.

**Most of the time you do not need this command.** `copy`, `sync`, `move` and
`backup` create whatever prefixes their objects require. `mkdir` is for the case
where the *empty* directory is the point: a watch folder on a local remote, a
layout created ahead of the data, a subtree you intend to
[`mount`](dctl_mount.md) before it has contents.

**No password, ever.** Whether a place has directories is a property of the
configuration, not of the data, so a vault is classified without being unlocked
and a bucket without being contacted. `dctl mkdir archive:x` works on a machine
with no credentials exported and no vault password to hand.

**Target resolution is the directory family's strict parse**, shared with
[`touch`](dctl_touch.md):

* The target is `REMOTE:PATH`. A remote name is at least two characters, so
  `C:\photos\2024` is a Windows drive path, `\\server\share\x` is a UNC path, and
  both are local and refused. A string with no colon at all is local too. Your
  operating system's own `mkdir(1)` already handles local paths; to create a
  directory through DCTL, address a remote that names one.
* `..` components are refused rather than resolved: a target may not climb out of
  the remote it names.
* The remote root is not a target. `dctl mkdir archive:` is a usage error — the
  root always exists, and guessing which directory was meant would be worse than
  saying so.
* The path is canonicalised before anything looks at it: `.` and empty components
  are dropped, backslashes fold to `/`, and the result is NFC-normalised. So
  `scratch:./photos//2024/` and `scratch:photos/2024` are one directory, and the
  decomposed `café` a macOS shell hands over is the same target as the composed
  `café` a Linux shell does. Two spellings must never become two directories.

**A directory inside a vault's object store is refused.** `archive-store:` names
the tree of opaque objects belonging to the vault `archive`, and DCTL will not
create anything in it — the same addressing rule that stops `copy` and `rcat`
writing plaintext there. The refusal is derived from the configuration, so it
does not depend on what the store currently holds.

`mkdir` never deletes or overwrites anything. It is the exact inverse of
[`rmdir`](dctl_rmdir.md) and the only command in the directory family that cannot
destroy data in any mode.

```
dctl mkdir REMOTE:PATH [flags]
```

## Examples

Create a directory on a local remote. The report goes to stdout; the outcome line
goes to stderr, so `... > report.txt` keeps the two apart:

```console
$ dctl mkdir scratch:photos/2024 -p
Command    mkdir
Target     scratch:photos/2024
Mode       execute
Backend    local
Parents    yes
Directory  photos
Directory  photos/2024
Outcome    created
OK created directory: scratch:photos/2024
$ echo $?
0
```

The same command against a vault. It succeeds, creates nothing, and says why:

```console
$ dctl mkdir archive:photos/2024
Command    mkdir
Target     archive:photos/2024
Mode       execute
Backend    vault
Parents    no
Directory  photos/2024
Outcome    not_required
OK archive:photos/2024: vault has no directories: a path there exists exactly while an object is stored under it, so there is nothing to create and nothing is missing
$ echo $?
0
```

As JSON, for a script that branches on the result. `status` carries the outcome
of a real run, and `planned` only ever for a `--dry-run`, so
`jq -e '.status == "created"'` is a working test for *a directory was made*:

```console
$ dctl mkdir archive:photos/2024 -p --json
{
  "command": "mkdir",
  "target": {
    "remote": "archive",
    "path": "photos/2024"
  },
  "dry_run": false,
  "options": {
    "parents": true,
    "backend": "vault",
    "directories": [
      {
        "path": "photos"
      },
      {
        "path": "photos/2024"
      }
    ]
  },
  "status": "not_required"
}
```

A dry run prints the plan, changes nothing, and carries `planned`:

```console
$ dctl mkdir scratch:new/tree -p --dry-run
Command    mkdir
Target     scratch:new/tree
Mode       dry-run
Backend    local
Parents    yes
Directory  new
Directory  new/tree
warning: [dry-run] would create directory: scratch:new/tree
```

Without `--parents`, a missing parent is the operating system's error, exactly as
`mkdir(1)` reports it:

```console
$ dctl mkdir scratch:a/b/c
error: No such file or directory (os error 2)
warning: creating /mnt/scratch/a/b/c
$ echo $?
4
```

A vault's object store is refused, and nothing is created:

```console
$ dctl mkdir archive-store:photos
error: '/srv/v' is the object store for remote 'archive'
warning: Use `archive:` to store data sealed — every write through it is
encrypted, and no flag turns that off. To copy the objects already stored there
exactly as they are, run `dctl replicate archive-store: DEST-STORE:`, which needs
no vault password. ...
$ echo $?
7
```

An unknown remote is named rather than quietly turned into a directory of that
name in the working directory:

```console
$ dctl mkdir nosuch:photos
error: unknown remote 'nosuch'
warning: Run `dctl config list` to see configured remotes, or address a provider
directly as one of local, b2, s3, r2.
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
accepted and cleaned away — `scratch:photos/2024/` and `scratch:photos/2024` are
the same target.

## Options inherited from parent commands

Every global flag is accepted; see [../GLOBAL_FLAGS.md](../GLOBAL_FLAGS.md). The
ones that matter here:

| Flag | Effect here |
|------|-------------|
| `-n`, `--dry-run` | Print the plan, change nothing, exit 0. |
| `--format`, `--json` | Render the report as an aligned table (`text`, the default), one pretty JSON document (`json`), or one JSON record per line (`json-lines`). |
| `--quiet` | Suppress the outcome line and the `[dry-run]` notice. The report still goes to stdout; errors are still printed. |
| `-v`, `--verbose` | `-vv` logs the resolved remote, path, backend kind, `--parents` flag and the number of planned directories. |

The filter flags (`--include`, `--exclude`, `--min-size`, …) are accepted and
have no effect: this command addresses one named container, not a set of objects.
`--verify`, `--checksum` and `--size-only` likewise do nothing — `mkdir` writes
no object, so there is nothing to verify. `--immutable` is not consulted: `mkdir`
only ever adds.

## Exit codes

See [../EXIT_CODES.md](../EXIT_CODES.md) for the full contract.

| Code | Name | When |
|------|------|------|
| 0 | `success` | The directory was created, was already there, or was not required. The `Outcome` row and the JSON `status` say which. |
| 1 | `usage` | An unparseable command line; an empty target; a local, UNC or drive-letter path; a remote name shorter than two characters or containing a separator; a `..` component; the remote root (`REMOTE:`); a file already occupying the name. |
| 2 | `uncategorised` | The report could not be written to stdout. A closed pipe is *not* an error — `dctl mkdir ... --json \| head -1` succeeds. |
| 4 | `file_not_found` | A missing parent without `--parents`, reported by the operating system with the path named. |
| 7 | `fatal_error` | An unknown remote, an unreadable or inconsistent configuration, a permission failure, or a destination the addressing rule claims for a vault's object store. |
| 25 | `cancelled` | Ctrl-C or SIGTERM. No partial work is reported as done. |

## See also

* [dctl touch](dctl_touch.md) — the other half of the directory family: create an object, or set its modification time.
* [dctl rmdir](dctl_rmdir.md) — the exact inverse: remove one empty directory.
* [dctl rmdirs](dctl_rmdirs.md) — sweep every empty directory under a path.
* [dctl purge](dctl_purge.md) — remove a directory *and* everything in it.
* [dctl copy](dctl_copy.md) — creates the prefixes its objects need; use it instead when the directory is not the point.
* [dctl mount](dctl_mount.md) — serve a vault or a subtree as a filesystem, where `mkdir` becomes a filesystem operation.
