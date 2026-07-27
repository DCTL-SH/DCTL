# dctl rmdirs

Remove empty directories under a path.

## Synopsis

`dctl rmdirs` is the plural of [`rmdir`](dctl_rmdir.md), and it keeps that
command's promise: it removes containers, never contents. A directory that still
holds an object is left standing. That is what makes the sweep safe to run over
a whole vault after a filtered [`delete`](dctl_delete.md) has left empty shells
behind.

The two commands differ in what a non-empty directory means. `rmdir` **errors**
on one, because you named that directory and DCTL will not silently do something
other than what you asked. `rmdirs` **skips** it, because you named a region,
not a victim.

**The sweep is depth-first by necessity.** Removing `a/b` can be what makes `a`
empty, so a single pass that visited parents first would leave half the litter
behind and then report success.

**`--leave-root` keeps the target directory itself**, even when the sweep empties
it. That is the flag a scheduled job wants: the tree it writes into should still
exist tomorrow morning, and re-creating a directory that a nightly cleanup
removed is a race nobody needs. It has nothing to protect when the target is a
bare `REMOTE:` — the root is the vault itself and was never a candidate for
removal.

**Blast radius.** Bounded, but wider than it first looks: `dctl rmdirs vault:`
walks the entire vault. Nothing holding an object is touched, so no file data
can be lost — but an *intentionally* empty directory (a placeholder, a
watch-folder a downstream tool expects to exist) is indistinguishable from
litter and will go. Use `--leave-root` and a narrower target when a specific
directory must survive, and `--dry-run` when you are not sure.

**Filters are ignored.** A filter selects objects; this command removes empty
containers. `--include`/`--exclude` will not stop a directory from being swept,
and the plan does not carry a `filters` key.

**Target resolution** is the family's strict parse: a remote name of at least
two characters, so `C:\photos` is a Windows drive path and is refused, as are
UNC paths, bare local paths and anything containing `..`. A trailing separator
is fine — the target is a directory. The path is cleaned and NFC-normalised.
Unlike `rmdir`, a bare `REMOTE:` **is** allowed here: sweeping a whole vault is
a legitimate request.

**Relationship to the verified-write contract.** Nothing is written, so
`--verify`, `--checksum` and `--size-only` have no effect and exit code 20
(`checksum_mismatch`) cannot be produced. What carries over from `PLAN.md` §6 is
the rule that DCTL never reports work it did not do: the plan carries no count
of directories, and this command cannot report a sweep that did not happen.

### What runs today

**The sweep runs.** Recursive enumeration shipped with the listing family, and
this command walks it:

```
$ dctl rmdirs vault: --force
Command     rmdirs
Target      vault:
Mode        execute
Leave root  no
OK removed: 0 object(s), 0 B
```

A vault stores no record of a directory that holds no objects, so on a healthy
vault there is usually nothing for this sweep to find and `0 object(s)` is the
honest answer rather than a failure — exit **0**. Earlier revisions of this page
said the sweep "is not implemented in this build" and quoted an exit-7 refusal
that no build now produces.

```
dctl rmdirs REMOTE:PATH [flags]
```

## Examples

Every example below runs in this build. Earlier revisions of this page prefaced
them with an engine refusal that no longer exists.

Sweep a whole vault, keeping the root — the shape a nightly job wants:

```console
$ dctl rmdirs vault: --leave-root --dry-run
warning: [dry-run] would remove empty directories: vault:
Command     rmdirs
Target      vault:
Mode        dry-run
Leave root  yes
```

Tidy up after a filtered delete. `dctl delete --include '*.tmp'` leaves the
directories that held the scratch files standing; this removes the ones it
emptied, plus any parents that became empty as a result. `--force` approves the
sweep without prompting:

```console
$ dctl rmdirs b2prod:bucket/media/scratch --force
Command     rmdirs
Target      b2prod:bucket/media/scratch
Mode        execute
Leave root  no
OK removed: 0 object(s), 0 B
$ echo $?
0
```

The JSON plan carries the flag, and JSON Lines keeps one plan on one line so a
line-at-a-time consumer can read it:

```console
$ dctl rmdirs archive:projects --leave-root --dry-run --format json-lines
{"command":"rmdirs","target":{"remote":"archive","path":"projects"},"dry_run":true,"options":{"leave_root":true},"status":"planned"}
```

A local path is refused. On Windows the drive letter is always a drive letter,
never a remote name:

```console
$ dctl rmdirs C:\Users\me\Pictures --force
error: 'C:\Users\me\Pictures' is a local path, not a remote
warning: The removal commands operate on a remote, written REMOTE:PATH. Use your
operating system's own tools to remove local files.
```

A remote name without its colon is not a target — the parse refuses rather than
guessing that you meant the whole vault:

```console
$ dctl rmdirs vault --force
error: 'vault' is not a remote specification
warning: Write the target as REMOTE:PATH, for example 'vault:photos/2024'.
```

## Options

```
  -h, --help        help for rmdirs
      --leave-root  Keep the target directory itself, even if the sweep empties it
```

The positional argument is `<REMOTE:PATH>`: the path to sweep. A bare `REMOTE:`
sweeps the whole vault.

## Options inherited from parent commands

Every global flag is accepted; see [../GLOBAL_FLAGS.md](../GLOBAL_FLAGS.md). The
ones that matter here:

| Flag | Effect here |
|------|-------------|
| `-n`, `--dry-run` | Print the plan and change nothing. Overrides `--force`. |
| `--force` | Approve the destructive action without prompting. |
| `-i`, `--interactive` | Prompt once, before the sweep; requires typing `yes`. Conflicts with `--force`. |
| `--format`, `--json` | Render the `--dry-run` plan as a table, one JSON document, or one JSON Lines record. |
| `--quiet` | Suppress the `[dry-run]` notice and warnings. Errors are still printed. |

The filter flags are accepted and ignored; unlike [`purge`](dctl_purge.md), this
command does not warn about them. `--immutable` is not yet consulted by the
removal family.

## Exit codes

See [../EXIT_CODES.md](../EXIT_CODES.md) for the full contract.

| Code | Name | When |
|------|------|------|
| 1 | `usage` | Unparseable command line; a local, UNC, too-short-remote, empty or `..`-containing target; `--interactive` with no terminal to prompt on. A bare `REMOTE:` is **not** an error here. |
| 7 | `fatal_error` | The remote is not configured and is not a known provider. |
| 22 | `vault_locked` | Wrong password or recovery phrase, or a damaged envelope. |
| 23 | `index_error` | The encrypted index or its journal could not be read or written. |
| 25 | `cancelled` | An interactive confirmation was declined, or the run was interrupted with Ctrl-C. |

Exit **0** covers both a sweep that removed directories and one that found
nothing to remove — an empty sweep is the normal state of a tidy vault, and is a
success rather than a failure. An earlier revision of this table said 0 "is not
currently reachable" and described that behaviour as owed; it is what runs.

## See also

* [dctl rmdir](dctl_rmdir.md) — remove one named directory, erroring if it is not empty.
* [dctl delete](dctl_delete.md) — remove objects by filter; `--rmdirs` sweeps what it empties.
* [dctl purge](dctl_purge.md) — remove a directory *and* everything in it.
* [dctl cleanup](dctl_cleanup.md) — reclaim abandoned uploads, staging litter and old versions.
* [dctl mkdir](dctl_mkdir.md) — create a directory.
* [dctl lsd](dctl_lsd.md) — list directories, to see what a sweep would consider.
