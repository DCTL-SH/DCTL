# dctl deletefile

Delete a single named object.

## Synopsis

`dctl deletefile` removes exactly one object: the one you named. It is the
narrowest command in the removal family, and the only one whose blast radius is
a single object no matter what else is on the command line.

**Filters are ignored here**, for the same reason `cp file dest` ignores them:
you named the thing, so there is nothing left to select. `--include`,
`--exclude`, `--min-size` and friends are accepted by the parser (they are
global flags) and have no effect. If you want a filtered removal, that is
[`delete`](dctl_delete.md).

**A directory is an error, not a recursion.** `dctl deletefile vault:photos`
must never quietly become a tree removal — that is [`purge`](dctl_purge.md)'s
job, and confusing the two is how someone loses a decade of photographs meaning
to remove one file. Two syntactic forms are refused outright with exit code 1:

* a target ending in a separator, `vault:photos/` or `vault:photos\`, which
  names a directory;
* a bare remote, `vault:`, which names the vault root.

The semantic half of that check — *is this path a directory in the vault?* —
needs a listing the engine does not expose yet, so today only the syntactic half
runs. Once the engine lands, a path that resolves to a directory will fail the
same way, never recurse.

**Target resolution** is the family's strict parse. A remote name must be at
least two characters, so a one-character prefix is always a Windows drive
letter: `C:\Users\me\a.jpg` is a local path and is refused, as are UNC paths
(`\\server\share\x`), bare local paths, and anything containing a `..`
component. The surviving path is cleaned and NFC-normalised, so a
macOS-decomposed `café/a.jpg` and a Linux-composed one address the same object.
Note that canonicalisation strips a trailing separator, so the directory check
above reads the *raw* argument, not the cleaned one.

**`dctl rm` is a deprecated alias for this command**, kept working because the
prototype CLI shipped it and scripts already use it. It is hidden from
`dctl --help`, takes the same single argument, and behaves identically. This is
also why `deletefile` has no options of its own: the alias has to keep meaning
exactly what it meant. In a `--dry-run` plan the `command` field reads
`deletefile` even when you invoked it as `rm`.

**Relationship to the verified-write contract.** A removal is not a write, so
`--verify`, `--checksum` and `--size-only` change nothing here and exit code 20
(`checksum_mismatch`) cannot be produced. What carries over from `PLAN.md` §6 is
the rule that DCTL never reports work it did not do: the `--dry-run` plan
carries no counters and never says an object was removed.

### What runs today

**The removal runs.** `Vault::delete_file` is reached and the named object is
gone when the command returns:

```
$ dctl deletefile vault:r2/a.txt --force
Command  deletefile
Target   vault:r2/a.txt
Mode     execute
removed              6 B  r2/a.txt
OK removed: 1 object(s), 6 B
```

Earlier revisions of this page said the removal "is not implemented in this
build" and quoted an exit-7 refusal that no build now produces. Understating a
destructive command is the dangerous direction: it invites a reader to point
`--force` at a path they have not checked.

```
dctl deletefile REMOTE:PATH [flags]
```

## Examples

Preview the removal of one object. The `[dry-run]` notice goes to stderr, the
plan to stdout:

```console
$ dctl deletefile vault:photos/2024/IMG_0421.CR3 --dry-run
warning: [dry-run] would delete: vault:photos/2024/IMG_0421.CR3
Command  deletefile
Target   vault:photos/2024/IMG_0421.CR3
Mode     dry-run
```

The JSON plan has no `filters` key at all. That absence is the contract: it is
how a machine consumer sees that no filter applied, rather than having to
interpret an empty object:

```console
$ dctl deletefile b2prod:bucket/media/reel-final.mov --dry-run --json
{
  "command": "deletefile",
  "target": {
    "remote": "b2prod",
    "path": "bucket/media/reel-final.mov"
  },
  "dry_run": true,
  "options": {},
  "status": "planned"
}
```

A trailing separator names a directory and is refused before anything is
touched — including on Windows, where the separator may be a backslash:

```console
$ dctl deletefile vault:photos/2024/
error: 'vault:photos/2024/' names a directory, not an object
warning: Use `dctl rmdir` for an empty directory, or `dctl purge` to remove a
directory and everything in it.
```

A Windows drive path is a local path, and no removal command accepts one. A
one-character prefix can never be a remote name, which is what keeps `C:\` and
`vault:` unambiguous on every platform:

```console
$ dctl deletefile C:\Users\me\Pictures\IMG_0421.CR3
error: 'C:\Users\me\Pictures\IMG_0421.CR3' is a local path, not a remote
warning: The removal commands operate on a remote, written REMOTE:PATH. Use your
operating system's own tools to remove local files.
```

The deprecated `rm` spelling still works and resolves to the same command:

```console
$ dctl rm vault:scratch/notes.txt --dry-run --format json-lines
{"command":"deletefile","target":{"remote":"vault","path":"scratch/notes.txt"},"dry_run":true,"options":{},"status":"planned"}
```

## Options

```
  -h, --help   help for deletefile
```

The positional argument is `<REMOTE:PATH>`: the single object to delete. Filters
do not apply. This command deliberately has no options of its own.

## Options inherited from parent commands

Every global flag is accepted; see [../GLOBAL_FLAGS.md](../GLOBAL_FLAGS.md). The
ones that matter here:

| Flag | Effect here |
|------|-------------|
| `-n`, `--dry-run` | Print the plan and change nothing. Overrides `--force`. |
| `--force` | Approve the destructive action without prompting. |
| `-i`, `--interactive` | Prompt before the removal; requires typing `yes`. Conflicts with `--force`. |
| `--format`, `--json` | Render the `--dry-run` plan as a table, one JSON document, or one JSON Lines record. |
| `--quiet` | Suppress the `[dry-run]` notice and warnings. Errors are still printed. |

The filter flags are accepted but ignored — unlike [`purge`](dctl_purge.md),
this command does not warn about them, because a single named object was never
going to be narrowed by a pattern. `--immutable` is not yet consulted by the
removal family.

## Exit codes

See [../EXIT_CODES.md](../EXIT_CODES.md) for the full contract.

| Code | Name | When |
|------|------|------|
| 1 | `usage` | Unparseable command line; a target that names a directory (trailing separator) or the vault root (`REMOTE:`); a local, UNC or too-short-remote target; a target containing `..`; `--interactive` with no terminal to prompt on. |
| 4 | `file_not_found` | The named object does not exist. |
| 7 | `fatal_error` | The remote is not configured and is not a known provider. |
| 22 | `vault_locked` | Wrong password or recovery phrase, or a damaged envelope. |
| 23 | `index_error` | The encrypted index or its journal could not be read or written. |
| 25 | `cancelled` | An interactive confirmation was declined, or the run was interrupted with Ctrl-C. |

Exit **0** means the object was removed. An earlier revision of this table said 0
"is not currently reachable" and that every run past validation ended at 7 with
the engine unavailable; neither is true, and 4 is produced today rather than
being owed.

## See also

* [dctl delete](dctl_delete.md) — remove many objects, selected by filters.
* [dctl purge](dctl_purge.md) — remove a path and everything under it.
* [dctl rmdir](dctl_rmdir.md) — remove one empty directory.
* [dctl rmdirs](dctl_rmdirs.md) — sweep the empty directories under a path.
* [dctl cleanup](dctl_cleanup.md) — reclaim abandoned uploads, staging litter and old versions.
* [dctl ls](dctl_ls.md) — confirm an object's exact path before removing it.
