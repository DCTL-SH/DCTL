# dctl purge

Remove a path and all of its contents.

## Synopsis

`dctl purge` removes everything: every object beneath `REMOTE:PATH`, at every
depth, plus the directories themselves. It is the widest blast radius in the
tool, and `dctl purge vault:` means *the entire remote*.

**This command ignores filters.** That is the distinction rclone users expect,
kept exactly:

* **[`delete`](dctl_delete.md) honours filters and leaves the directory
  structure standing.** `dctl delete --include '*.tmp' vault:project` removes
  the scratch files.
* **`purge` ignores filters and removes the tree.** `dctl purge vault:project`
  removes the project.

Because filters are *ignored* rather than *unsupported*, passing `--include`,
`--exclude`, `--filter-from`, `--files-from`, `--min-size` or `--max-size` to a
purge prints a warning on stderr:

```
warning: purge ignores filters: the whole tree goes. Use `dctl delete` to remove
a filtered subset.
```

Silence would be worse than noise. A user who believes `--exclude 'keep/**'`
protected something is a user who is about to lose it.

**The extra gate.** Every removal command is destructive, but this is the only
one that refuses a bare invocation. Everywhere else, running non-interactively
counts as consent — you typed the command, which is enough for one file or one
filtered set. A whole tree is not one file, so `purge` demands that the consent
be explicit and fails with exit code 1 otherwise:

```
error: refusing to purge 'vault:project': it removes everything under this path
warning: Pass --force to approve it, --interactive to be asked first, or
--dry-run to see what it would cover. Use `dctl delete` if you meant to remove
objects and keep the directories.
```

Purging a bare remote says so in as many words — the message reads *it removes
the entire remote* rather than *everything under this path*. `--dry-run` is
exempt from the gate: refusing to let you *preview* a purge would be hostile,
and a preview removes nothing.

**Target resolution** is the family's strict parse. A remote name must be at
least two characters, so `C:\projects\apollo` is a Windows drive path and is
refused, as are UNC paths (`\\server\share`), bare local paths, and anything
containing a `..` component — the last of these matters more here than anywhere
else in the family, since `..` on a tree removal is how a typo escapes the
subtree you meant. The surviving path is cleaned and NFC-normalised, so
`vault:project/`, `vault:./project` and `vault:project` are one target.

**Relationship to the verified-write contract.** A purge writes nothing, so
`--verify`, `--checksum` and `--size-only` have no effect and exit code 20
(`checksum_mismatch`) cannot be produced. The contract's rule that survives here
is the honesty one from `PLAN.md` §6: nothing is reported that did not happen.
The `--dry-run` plan carries no object list and no counters — only the resolved
request and `"status": "planned"`.

**A purge is not recoverable by DCTL.** There is no trash, no undo and no
snapshot in this build; whether a deleted object can be resurrected depends
entirely on the provider (B2 lifecycle rules, bucket versioning). If versioning
is on, note that [`cleanup --class versions`](dctl_cleanup.md) is the command
that would later destroy those survivors too.

### What runs today

**The tree removal runs.** The recursive enumeration this command needs shipped
with the listing family, and `purge` removes the path and everything beneath it:

```
$ dctl purge vault:r2 --force
Command  purge
Target   vault:r2
Mode     execute
removed             12 B  r2/b.txt
removed              8 B  r2/sub/c.txt
OK removed: 2 object(s), 20 B
```

A path that holds nothing is exit **3** (`dir_not_found`) with a note saying so,
not a silent success.

Earlier revisions of this page said the removal "is not implemented in this
build" and quoted an exit-7 refusal that no build now produces. For the most
destructive verb in the tool, that understatement is the worst possible drift —
it reads as a safety net, and there is none.

```
dctl purge REMOTE:PATH [flags]
```

## Examples

Every example below runs in this build and removes what it names. Earlier
revisions of this page prefaced them with an engine refusal that no longer
exists.

Preview a tree removal. No approval flag is needed for a preview, because a
preview removes nothing:

```console
$ dctl purge b2prod:bucket/media/2019 --dry-run
warning: [dry-run] would purge: b2prod:bucket/media/2019
Command  purge
Target   b2prod:bucket/media/2019
Mode     dry-run
```

A bare purge is refused. This is the gate that distinguishes `purge` from every
other removal command:

```console
$ dctl purge vault:projects/apollo
error: refusing to purge 'vault:projects/apollo': it removes everything under this path
warning: Pass --force to approve it, --interactive to be asked first, or
--dry-run to see what it would cover. Use `dctl delete` if you meant to remove
objects and keep the directories.
$ echo $?
1
```

Approve it explicitly. `--force` is the scriptable "yes, all of it";
`--interactive` prompts on stderr and requires the exact word `yes`. Past the
gate the tree is gone:

```console
$ dctl purge vault:projects/apollo --force
Command  purge
Target   vault:projects/apollo
Mode     execute
removed             6 B  projects/apollo/a.txt
removed            12 B  projects/apollo/b.txt
OK removed: 2 object(s), 18 B
$ echo $?
0
```

Filters do not narrow a purge, and DCTL says so rather than letting you believe
otherwise:

```console
$ dctl purge vault:projects/apollo --exclude 'keep/**' --force
warning: purge ignores filters: the whole tree goes. Use `dctl delete` to remove
a filtered subset.
```

Purging a whole remote is legal and is described as such. The JSON plan has no
`filters` key at all — that absence is how a machine consumer sees that none
applied:

```console
$ dctl purge archive: --dry-run --json
{
  "command": "purge",
  "target": {
    "remote": "archive",
    "path": ""
  },
  "dry_run": true,
  "options": {},
  "status": "planned"
}
```

A Windows drive path is local, and no removal command accepts one — a
one-character prefix is always a drive letter, on every platform:

```console
$ dctl purge C:\projects\apollo --force
error: 'C:\projects\apollo' is a local path, not a remote
warning: The removal commands operate on a remote, written REMOTE:PATH. Use your
operating system's own tools to remove local files.
```

## Options

```
  -h, --help   help for purge
```

The positional argument is `<REMOTE:PATH>`: the path to remove, with all of its
contents. Filters are ignored. This command has no options of its own — the
approval it requires comes from the global `--force` / `--interactive` flags.

## Options inherited from parent commands

Every global flag is accepted; see [../GLOBAL_FLAGS.md](../GLOBAL_FLAGS.md). The
ones that matter here:

| Flag | Effect here |
|------|-------------|
| `--force` | Approves the purge without prompting. Required (or `--interactive`) for any non-dry run. |
| `-i`, `--interactive` | Prompts before the purge; requires typing `yes`. Conflicts with `--force`. |
| `-n`, `--dry-run` | Print the plan and change nothing. Exempt from the extra gate; overrides `--force`. |
| `--format`, `--json` | Render the `--dry-run` plan as a table, one JSON document, or one JSON Lines record. |
| `--quiet` | Suppresses the ignored-filter warning and the `[dry-run]` notice. Errors are still printed. |

The filter flags are accepted, ignored, and warned about. `--immutable` is not
yet consulted by the removal family — do not rely on it to protect a vault from
`dctl purge`.

## Exit codes

See [../EXIT_CODES.md](../EXIT_CODES.md) for the full contract.

| Code | Name | When |
|------|------|------|
| 1 | `usage` | Unparseable command line; a local, UNC, too-short-remote, empty or `..`-containing target; **a run with neither `--force` nor `--interactive` nor `--dry-run`**; `--interactive` with no terminal to prompt on. |
| 3 | `dir_not_found` | The path holds nothing, so there is nothing to purge. |
| 7 | `fatal_error` | The remote is not configured and is not a known provider. |
| 22 | `vault_locked` | Wrong password or recovery phrase, or a damaged envelope. |
| 23 | `index_error` | The encrypted index or its journal could not be read or written. |
| 25 | `cancelled` | An interactive confirmation was declined, or the run was interrupted with Ctrl-C. |

Exit **0** means the tree was removed. An earlier revision of this table said 0
"is not currently reachable" and that every run past the gates ended at 7; neither
is true, and 3 is produced today rather than being owed. 6 (`partial_failure`)
remains unreachable — a tree is removed object by object and a failure part-way
through is reported as an error rather than a partial success.

## See also

* [dctl delete](dctl_delete.md) — remove objects by filter and keep the directories.
* [dctl deletefile](dctl_deletefile.md) — remove exactly one named object.
* [dctl rmdir](dctl_rmdir.md) — remove one directory, and only if it is already empty.
* [dctl rmdirs](dctl_rmdirs.md) — sweep the empty directories under a path.
* [dctl cleanup](dctl_cleanup.md) — reclaim abandoned uploads, staging litter and old versions.
* [dctl size](dctl_size.md) — see how much a tree holds before purging it.
