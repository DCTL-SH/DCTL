# dctl index

Operate on the local index: rebuild it from the backend.

## Synopsis

The index is a **cache and a privacy layer, never a single point of failure**
(`PLAN.md` §13.5). Every fact it holds is derivable from the backend: the
path→object mapping lives in the encrypted `n/*` name records, and each object
carries its own data key and metadata in a self-describing header. It exists
because deriving those facts on demand would mean a network round trip per path,
and because keeping the mapping local is what stops a provider from learning the
shape of the dataset it is holding.

That makes the index something an operator occasionally has to act on directly,
which is what this command group is for. Today it has one verb.

```
dctl index rebuild REMOTE:
```

## dctl index rebuild

Rescan the backend's name records and write the authoritative path→object
mapping into the local index.

**This is the recovery path.** A wiped laptop, a corrupted database, or a machine
that has never seen this vault before needs exactly two things to become fully
functional: the password, and this command. A lost index never means lost data —
that is the whole reason the index is allowed to be a cache.

It is also the remedy several of DCTL's own error messages name. An index-layer
failure, an object that is recorded but absent at the provider (`missing` in a
`scrub` report), and a `cat` of a file written on another machine all point here.

### What it costs, and what it recovers

Two bounded reads per file. The `n/*` name record gives the path and the object
key; the object's own **header** gives the size, the modification time and the
content hash it was sealed with. No object body is ever fetched, so a vault of
any size rebuilds for the price of a listing plus a few kilobytes per object —
never a restore.

The rebuilt rows are therefore the rows that were written. A listing taken
straight afterwards is indistinguishable from one taken before the index was
lost, `dctl check --checksum` against the source tree matches, and `dctl size`
reports a total rather than a lower bound.

**It used not to.** A rebuild was a list-only pass and its rows carried no size,
no content hash and no modification time. Nothing filled them in afterwards
either — `cat`, `hashsum` and a whole `scrub` all read the object and answer from
it without writing back — so the only cure was storing every file again. The
result was an index that looked rebuilt and behaved degraded: `dctl check` cannot
compare a row with no size and no hash, `dctl size` reports a lower bound in the
shape of a total, and `dctl sync` treats every file as changed and re-uploads the
whole dataset. `PLAN.md` §13.5 always described an index *"rebuildable by scanning
object headers"*; the headers were simply not being scanned.

### When an object cannot be described

The path is indexed anyway — the mapping is what makes the file readable at all —
and the row is counted as **unmeasured**. The report carries the count, and a run
with any unmeasured row warns and exits **6** (`partial_failure`):

```
dctl index rebuild archive:
Files  Unmeasured  Index
-----  ----------  ------------------------------------
 1204           2  /home/example/.dctl/index/vault.redb
warning: 2 object(s) are mapped but could not be described: ...
```

There are exactly two causes and they call for different actions: the object a
name record points at is not at the provider (a durability incident — run
`dctl scrub` to find out which), or its metadata uses a schema this build does
not parse (a version problem). Both paths remain listable and readable; only
their measurements are missing.

An unmeasured row renders as `-`, the same placeholder `lsl` already uses for a
modification time the index never recorded. It used to render as `0 B`, which is
a *number* — and a number gets believed, summed and acted on. See
[`dctl size`](dctl_size.md#when-the-total-cannot-be-computed) for the JSON shape
that carries the absence.

### Idempotent, and safe to repeat

Existing rows are overwritten with the authoritative mapping from the backend. A
name record that cannot be decrypted — one belonging to a different vault sharing
the same bucket — is skipped with a warning rather than aborting the run. Nothing
in the backend is written or deleted, so a rebuild cannot lose data.

### Whole vaults only

`REMOTE:` names the vault. A path inside one (`archive:photos`) is **refused**,
not silently widened: the scan enumerates every name record in the backend and
has no prefix-scoped form, so accepting the path and rebuilding everything would
do more than was asked, and accepting it and rebuilding nothing would do less. A
partial rebuild would also leave the index describing two different points in
time.

A local path is a usage error. A directory of ordinary files has no path→object
mapping and nothing to rebuild one from. Following rclone's rule,
`\\server\share` is local on every platform and `C:\data` and `d:/data` are local
where drives exist; off Windows they name the remotes `C` and `d`.

### Output

Stdout carries the count and the index that was written:

```
Files  Index
-----  ------------------------------------
    2  /var/lib/dctl/index.redb
```

The count is the point. It is what an operator compares against what they
expected the vault to contain, and a rebuild that finds *fewer* files than the
last listing is the signal that objects have gone missing at the provider. Zero
is information too — it says the scan ran and found no name records, which is a
very different statement from a command that printed nothing.

`--json` emits one document with `remote`, `index`, `files`, `measured` and
`unmeasured`. `unmeasured` is always present, including as `0`: an absent field
would be read as "none", which is the same claim made by a report that never
counted it.
`--format json-lines` emits the same single document, rather than nothing: a
consumer must not have to special-case this command by discovering it is silent.

## Examples

Recover a machine that has lost its index. Only the password and the remote are
needed; nothing local survives from before.

```
dctl index rebuild archive:
Files  Unmeasured  Index
-----  ----------  ------------------------------------
 1204           0  /home/example/.dctl/index/vault.redb
```

Reconcile after a `scrub` reported `missing` objects — the index and the provider
disagree, and the backend is the authority:

```
dctl scrub archive: --json | jq -r '.findings[] | select(.status=="missing") | .path'
dctl index rebuild archive:
```

Rehearse first. `--dry-run` writes nothing and does not even unlock the vault,
so it never prompts for a password:

```
dctl index rebuild archive: --dry-run
warning: [dry-run] would rebuild the index for: archive:
```

Feed the count to a monitoring system:

```
dctl index rebuild archive: --json | jq .files
```

`index rebuild` needs a whole vault:

```
dctl index rebuild archive:photos
ERROR: dctl index rebuild rebuilds a whole vault, but 'archive:photos' names a path inside one
  hint: Drop the path and name the remote alone, for example 'archive:'. The scan
        reads every name record in the backend and has no prefix-scoped form, so a
        partial rebuild would leave the index describing two different points in
        time.
```

## Options

```
  -h, --help   help for index
```

`rebuild` takes one positional `REMOTE:` and no flags of its own. Everything that
varies — which index file, which configuration, where the password comes from —
is a global flag, so there is exactly one spelling of each.

## Options inherited from parent commands

Every global flag is accepted on `dctl index rebuild`. The ones that change what
this command does are `--index` (which index database to write; otherwise the
platform data directory), `--config`, the password flags
`--password`/`--password-file`/`--password-command`/`--no-ask-password`,
`--dry-run` (which suppresses the write, this command's only mutation), and the
output flags `--format`/`--json`/`--quiet`/`-v`. See
[../GLOBAL_FLAGS.md](../GLOBAL_FLAGS.md) for the full list.

`--key-file` is refused rather than silently dropped, as it is on every command
that unlocks a vault: this build cannot mix a second factor into the key, and
unlocking with the password alone would give weaker protection than was asked
for while exiting 0.

## Exit codes

| Code | Name | When |
|-----:|------|------|
| 0 | `success` | The index was rebuilt, or `--dry-run` reported what it would do. |
| 1 | `usage` | Unknown flag, missing target, a local target, a target naming a path inside a vault, a remote name shorter than two characters, or a path containing `..`. |
| 2 | `uncategorised` | The report could not be serialised. Not reachable for these types in practice. |
| 7 | `fatal_error` | An unresolvable remote, an unreadable configuration, or a `--key-file` this build cannot apply. |
| 22 | `vault_locked` | Wrong password, or an envelope that will not unwrap. |
| 23 | `index_error` | The index database could not be written. |
| 25 | `cancelled` | Ctrl-C or SIGTERM. A partly-completed rebuild is never reported as a clean one. |

A rebuild that could not run is an **error**, never a count of zero: a script
reading `files: 0` would take it for an empty vault.

See [../EXIT_CODES.md](../EXIT_CODES.md) for the full contract.

## See also

* [dctl scrub](dctl_scrub.md) — the command whose `missing` verdict this one
  answers: the index says an object is there and the provider disagrees.
* [dctl ls](dctl_ls.md) — what the index looks like afterwards, zero sizes and
  all.
* [dctl cat](dctl_cat.md) — reads the object rather than the index, so it is
  correct immediately after a rebuild.
* [dctl config import](dctl_config.md) — the other half of recovering a machine:
  writing the remotes that address a vault which already exists.
* [dctl restore](dctl_restore.md) — the full-restore drill a rebuild is the
  cheap first step of.
