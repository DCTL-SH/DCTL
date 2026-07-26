# DCTL command documentation

One page per command, grouped by workflow rather than alphabetically — the same
order `dctl --help` prints: set it up, look at it, move data, remove data, prove
the data is intact, mount it.

**New here?** Read three pages, in this order.
[**dctl config**](dctl_config.md) tells you where the configuration file lives,
what may go in it, and why no credential ever does.
[**dctl copy**](dctl_copy.md) is the transfer verb to learn first: it adds and
updates but never removes, so a mistyped argument costs bandwidth rather than
data. [**dctl sync**](dctl_sync.md) is the one that deletes — read it *before*
you run it, not after. Everything else is a variation on those three.

[**dctl**](dctl.md) is the root page: what the tool is, the `REMOTE:PATH`
syntax (including why `C:\data` is always a local path and never a remote named
`C`), the configuration file's location on each platform, the global options,
and the exit-code contract.

Commands marked **destructive** can remove data. They prompt under
`--interactive`, and refuse without `--force` where the blast radius is a whole
tree. Every command accepts `--dry-run`.

## Setup

| Command | Description |
|---------|-------------|
| [dctl config](dctl_config.md) | Create and manage configuration and remotes. |
| [dctl init](dctl_init.md) | Create a vault and register both of its remotes. |

## Listing

| Command | Description |
|---------|-------------|
| [dctl ls](dctl_ls.md) | List objects with size and path. |
| [dctl lsd](dctl_lsd.md) | List directories only. |
| [dctl lsl](dctl_lsl.md) | List objects with size, modification time and path. |
| [dctl lsjson](dctl_lsjson.md) | List objects as JSON, one document per object. |
| [dctl tree](dctl_tree.md) | Show the object tree. |
| [dctl size](dctl_size.md) | Show total size and object count. |

## Transfer

| Command | Description |
|---------|-------------|
| [dctl copy](dctl_copy.md) | Copy files from source to destination, skipping identical files. |
| [dctl move](dctl_move.md) | Move files, deleting the source only after a verified, durable commit. **Destructive.** |
| [dctl sync](dctl_sync.md) | Make the destination identical to the source. Deletes from destination. **Destructive.** |
| [dctl copyto](dctl_copyto.md) | Copy a single file or directory to an exact destination name. |
| [dctl moveto](dctl_moveto.md) | Move a single file or directory to an exact destination name. **Destructive.** |

## Replication

| Command | Description |
|---------|-------------|
| [dctl replicate](dctl_replicate.md) | Replicate a vault's ciphertext objects to a second store. No password. |

The only transfer verb that needs **no vault password**: it moves opaque
ciphertext between two object stores, so a backup operator can satisfy 3-2-1
without ever holding decryption capability. It deletes nothing, and it refuses
every filter — a partial replica is not a vault.

## Content

| Command | Description |
|---------|-------------|
| [dctl cat](dctl_cat.md) | Write object contents to standard output. |
| [dctl rcat](dctl_rcat.md) | Read standard input and write it to an object. |

## Removal

| Command | Description |
|---------|-------------|
| [dctl delete](dctl_delete.md) | Delete objects in a path, honouring filters. **Destructive.** |
| [dctl deletefile](dctl_deletefile.md) | Delete a single named object. **Destructive.** |
| [dctl purge](dctl_purge.md) | Remove a path and all of its contents. **Destructive.** |
| [dctl rmdir](dctl_rmdir.md) | Remove an empty directory. **Destructive.** |
| [dctl rmdirs](dctl_rmdirs.md) | Remove empty directories under a path. **Destructive.** |
| [dctl cleanup](dctl_cleanup.md) | Clean up a remote: abandoned uploads, stale temporary objects, old versions. **Destructive.** |

## Directories

| Command | Description |
|---------|-------------|
| [dctl mkdir](dctl_mkdir.md) | Create a directory. |
| [dctl touch](dctl_touch.md) | Create an object, or update its modification time. |

## Integrity

| Command | Description |
|---------|-------------|
| [dctl verify](dctl_verify.md) | Verify that stored objects decrypt and match their recorded hashes. |
| [dctl check](dctl_check.md) | Compare source and destination without transferring. |
| [dctl scrub](dctl_scrub.md) | Re-read and verify the whole dataset, reporting its health. |
| [dctl hashsum](dctl_hashsum.md) | Print content hashes for objects. |
| [dctl index](dctl_index.md) | Operate on the local index: rebuild it from the backend. |

## Audit & recovery

| Command | Description |
|---------|-------------|
| [dctl audit](dctl_audit.md) | Inspect and verify the tamper-evident audit log. |
| [dctl backup](dctl_backup.md) | Back up a local tree into a vault. |
| [dctl restore](dctl_restore.md) | Restore a vault, or part of one, to a local tree. |

## Mount

| Command | Description |
|---------|-------------|
| [dctl mount](dctl_mount.md) | Mount a remote as a filesystem. |

## Utility

| Command | Description |
|---------|-------------|
| [dctl about](dctl_about.md) | Show remote usage, quota and capability information. |
| [dctl version](dctl_version.md) | Show version and build information. |
| [dctl completion](dctl_completion.md) | Generate a shell completion script. |

## Compatibility aliases

The prototype CLI's verbs still parse, so existing scripts keep working. They
are hidden from `--help` and delegate to the modern command, which is what new
scripts should spell.

| Alias | Documented at |
|-------|---------------|
| `dctl put` | [dctl copy](dctl_copy.md) — local file into a vault. |
| `dctl get` | [dctl copy](dctl_copy.md) — vault into a local file. |
| `dctl rm` | [dctl deletefile](dctl_deletefile.md) |

## Elsewhere in the docs

* [../FORMAT.md](../FORMAT.md) — the on-disk container and index format.
* [../EXIT_CODES.md](../EXIT_CODES.md) — the exit-code contract in full.
