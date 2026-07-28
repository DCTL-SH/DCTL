# dctl rmdir

Remove an empty directory.

## Synopsis

`dctl rmdir` removes one directory, and only if it is already empty. It is the
safe member of the removal family and deliberately the timid one: it removes a
container, never contents.

**A non-empty directory is an error, not a recursion.** Falling back to removing
the contents would make `rmdir` a synonym for [`purge`](dctl_purge.md), and the
whole point of a command that refuses is that a script can rely on the refusal —
`dctl rmdir` succeeding tells you the directory was empty. If you want the
contents gone, that is [`delete`](dctl_delete.md) (filtered, keeps directories)
or [`purge`](dctl_purge.md) (everything). `mkdir` is this command's exact
inverse.

Two things follow from "one directory":

* **The vault root is not a directory anyone may remove.** `dctl rmdir vault:`
  is a usage error, not an empty success. The root *is* the vault, not a
  directory inside it; dismantling a vault is a different operation with a
  different name (`dctl config delete`), and quietly succeeding here would
  suggest something had happened that did not.
* **Filters are ignored.** A filter selects objects; this command does not act
  on objects at all. To sweep many empty directories under a path, use
  [`rmdirs`](dctl_rmdirs.md).

**Target resolution** is the family's strict parse: a remote name of at least
two characters, so `C:\photos\2024` is a Windows drive path and is refused, as
are UNC paths, bare local paths and anything containing `..`. Unlike
[`deletefile`](dctl_deletefile.md), a **trailing separator is fine here** —
`vault:photos/2024/` names a directory, and a directory is exactly what this
command expects. The path is cleaned and NFC-normalised, so
`vault:photos//2024/` and `vault:photos/2024` are one target.

**Relationship to the verified-write contract.** Nothing is written, so
`--verify`, `--checksum` and `--size-only` have no effect and exit code 20
(`checksum_mismatch`) cannot be produced. The rule from `PLAN.md` §6 that does
apply is that DCTL never reports work it did not do — which matters more here
than it looks, because removing an empty directory is precisely the kind of
no-op a tool is tempted to report as success whether or not it happened.

### What runs today

**Both the emptiness check and the removal run.** Directory enumeration shipped
with the listing family, and this command uses it: a non-empty directory is
refused as a **usage error** (exit 1) that names one of the objects standing in
the way, and points at the two commands that would do what was probably meant.

```
$ dctl rmdir vault:r3 --force
error: 'vault:r3' is not empty: it holds 'r3/a.txt'
warning: Use `dctl purge` to remove a directory and everything in it, or `dctl delete` to remove the objects and leave the structure standing.
```

A path that does not exist at all is exit **3** (`dir_not_found`), with a note
explaining that a vault stores no record of an empty directory and so cannot tell
one that was never created from one that holds nothing.

In particular, **a `dctl rmdir` that exits 1 saying the directory is not empty
did inspect it**, and names the object it found. An earlier revision of this page
said the opposite — that nothing was inspected and a non-zero exit meant only
that the command was unimplemented — which would have taught a reader to ignore
the one message that is telling them the truth. A non-empty directory is a
failure here and never becomes a recursion.

```
dctl rmdir REMOTE:PATH [flags]
```

## Examples

Every example below runs in this build. Earlier revisions of this page prefaced
them with an engine refusal that no longer exists.

Preview the removal of one directory. The `[dry-run]` notice goes to stderr, the
plan to stdout:

```console
$ dctl rmdir vault:photos/2024/raw --dry-run
warning: [dry-run] would remove directory: vault:photos/2024/raw
Command  rmdir
Target   vault:photos/2024/raw
Mode     dry-run
```

A trailing separator is accepted, because a directory is what this command
wants. The plan quotes the canonical form back, without the separator:

```console
$ dctl rmdir b2prod:bucket/media/proxies/ --dry-run --json
{
  "command": "rmdir",
  "target": {
    "remote": "b2prod",
    "path": "bucket/media/proxies"
  },
  "dry_run": true,
  "options": {},
  "status": "planned"
}
```

The vault root is refused. `dctl rmdir archive:` never means "empty the
archive":

```console
$ dctl rmdir archive: --force
error: 'archive:' is the vault root, not a directory
warning: Name a directory inside the remote, for example 'vault:photos/2024'.
$ echo $?
1
```

A Windows path is local and is refused, drive letter and all. Use the operating
system's own tools for local directories:

```console
$ dctl rmdir C:\Users\me\Pictures\2024
error: 'C:\Users\me\Pictures\2024' is a local path, not a remote
warning: The removal commands operate on a remote, written REMOTE:PATH. Use your
operating system's own tools to remove local files.
```

A string with no colon at all is not a remote specification, and is refused
before anything is touched:

```console
$ dctl rmdir photos/2024
error: 'photos/2024' is not a remote specification
warning: Write the target as REMOTE:PATH, for example 'vault:photos/2024'.
```

## Options

```
  -h, --help   help for rmdir
```

The positional argument is `<REMOTE:PATH>`: the empty directory to remove. This
command has no options of its own.

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

The filter flags are accepted and ignored: this command acts on a container, not
on objects. `--immutable` is not yet consulted by the removal family.

## Exit codes

See [../EXIT_CODES.md](../EXIT_CODES.md) for the full contract.

| Code | Name | When |
|------|------|------|
| 1 | `usage` | Unparseable command line; **the vault root (`REMOTE:`)**; a local, UNC, malformed-remote, empty or `..`-containing target; `--interactive` with no terminal to prompt on. |
| 3 | `dir_not_found` | The directory does not exist. |
| 7 | `fatal_error` | The remote is not configured and is not a known provider. |
| 22 | `vault_locked` | Wrong password or recovery phrase, or a damaged envelope. |
| 23 | `index_error` | The encrypted index or its journal could not be read or written. |
| 25 | `cancelled` | An interactive confirmation was declined, or the run was interrupted with Ctrl-C. |

Exit **0** means the directory was removed. A **non-empty** directory is exit
**1**, in the `usage` row above: it names the object that is in the way and never
becomes a recursion. An earlier revision of this table said 0 and 3 were
unreachable and that the emptiness check itself was unavailable — so a reader was
told that a non-zero exit carried no information about emptiness, when it is
precisely what it carries.

## See also

* [dctl rmdirs](dctl_rmdirs.md) — sweep every empty directory under a path.
* [dctl mkdir](dctl_mkdir.md) — the exact inverse of this command.
* [dctl purge](dctl_purge.md) — remove a directory *and* everything in it.
* [dctl delete](dctl_delete.md) — remove objects by filter and keep the directories.
* [dctl deletefile](dctl_deletefile.md) — remove exactly one named object.
* [dctl lsd](dctl_lsd.md) — list directories, to see which are candidates.
