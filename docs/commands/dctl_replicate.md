# dctl replicate

Replicate a vault's ciphertext objects to a second store. No password.

## Synopsis

`dctl replicate` copies a vault's opaque ciphertext objects from one object store
to another, byte for byte, under the same object keys. It is the command that
makes `PLAN.md` §13.3's 3-2-1 redundancy real, and its defining property is
stated first because everything else follows from it: **it needs no vault
password.**

Nothing in a replication derives a key, unwraps an envelope, opens the index, or
holds a byte of plaintext. The objects go in opaque and come out opaque.

```console
$ dctl replicate archive-store: offsite-store:
✓ 'offsite-store:' now holds every object in 'archive-store:' (14203 object(s), 87 moved this run)
```

**Separation of duties, as a structural property.** A backup operator can be
given credentials for the primary store and the offsite store, a cron entry, and
nothing else — no vault password, no recovery phrase, no ability to read a single
file they are protecting. They satisfy 3-2-1 without ever holding decryption
capability. The person who *can* read the data and the person who guarantees a
second copy of it exists are then two different people **because the tool cannot
be run any other way**, rather than because a policy document says so and an
audit checks afterwards.

This is why [`dctl init`](dctl_init.md) gives the base store a name
(`archive-store` beside `archive`) instead of leaving it anonymous. A nameless
base would force every replication job to re-describe the location, and a
location typed twice is a location that eventually differs.

### Why a verb and not `copy --raw`

Three reasons, none of them cosmetic.

* **The audit log records `replicate`.** A compliance reviewer reading the trail
  needs to see that this operation moved ciphertext with no key present. That is
  a materially different act from a `copy` through a vault remote, and two acts
  differing in whether a decryption key was held must not share a name.
* **It can refuse filters outright.** A filtered replication is a broken vault
  (see below), and `dctl copy --raw --include '*.jpg'` invites exactly that —
  from a *global* flag that could arrive out of a shell alias or a CI template
  nobody re-read. A verb that owns its filter policy can say no; a flag bolted
  onto a verb that must honour filters cannot.
* **It has its own exit-code story.** A filter is a usage error here rather than
  a narrowing; a store that is not a store is a fatal configuration error rather
  than an empty transfer; and a destination that serves back something other than
  what it stored is exit 20 on a command where that means the *second copy* is
  suspect, not the first.

### Both ends must be object stores

| typed | result |
|-------|--------|
| `archive:` (a vault remote) | **refused** — reading through it would decrypt |
| `archive-store:` (declared a store) | replicated; no password, no probe |
| `local:/srv/vault` (holds an envelope) | replicated; no password |
| an undeclared, empty location | **refused** — declare it first |
| `archive-store:photos` (a prefix) | **refused** — a partial replica is not a vault |

A location earns its place at one end in exactly two ways. It is **declared** —
the configuration says `require_vault = true`, which is what `dctl init` writes
for the store remote it registers — or it is **demonstrated**, meaning a vault's
envelope is at its root, found by the same key-free probe `dctl config import`
uses. A declared store needs no probe at all, so the ordinary offsite job costs
no extra round trip against either provider before it starts.

An empty, undeclared location is refused, and that refusal is the point rather
than an oversight. The tempting alternative — "it is empty, so it must be the new
replica" — is precisely the auto-detection that invariant I4 forbids: what the
command did would then depend on what the destination happened to contain, and
`dctl replicate archive-store: ~/Documents` would spray a vault's object tree
across somebody's files the first time and refuse the second. Declaring a
replica's store is one command, run once, and the refusal names it.

Note what the probe is *not* doing. It answers "may this location be one end of a
replication", never "should these bytes be encrypted". Replication has one
encryption behaviour — there is none, bytes pass through untouched — fixed at the
verb, and nothing found on a store can change it. **Eligibility may be
demonstrated; semantics may not.**

### There are no filters

`--include`, `--exclude`, `--filter-from`, `--files-from`, `--min-size`,
`--max-size` and `--max-depth` are all **refused** with exit code 1, and the
refusal names every one that was given rather than only the first.

A vault's object store is a single consistent set: the index inside it references
every object in it, and an object is only reachable through the key the vault
derived for it. Take a subset and what remains is not a smaller vault — it is a
vault with dangling references, and nothing detects that until a restore asks for
one of the objects the filter dropped, which is to say on the worst possible day.

The refusal is a *usage* error, not an unimplemented one. Nothing here is waiting
on an engine: filtering a replication is not a feature DCTL has yet to build, it
is one it will not build, and a script that branched on exit 7 would eventually
retry a command that is never going to start working. To copy selected *files*,
use [`dctl copy`](dctl_copy.md) through the vault remote — which needs the vault
password, and that is the whole distinction.

A prefix on either argument (`archive-store:photos`) is refused for the same
reason: it is a filter written in the argument instead of in a flag.

### What each run decides, and what it costs

The plan is built from metadata alone — the object keys and byte counts on each
side — so `--dry-run` can print it without paying for the run it is rehearsing.

| at the destination | `--verify checksum` / `sample` | `--verify strict` |
|--------------------|-------------------------------|-------------------|
| absent | `replicate` | `replicate` |
| present, different size | `replicate` | `replicate` |
| present, same size | `skip` | `reverify` |

The last row is the interesting one. At the default strength an object with the
same key and the same size is taken to be the same object and skipped, which is
what makes a weekly offsite job cost the week's new objects rather than the whole
vault. `--verify strict` refuses that inference: it reads the object back from
*both* ends and compares BLAKE3s, replacing the replica's copy if they differ.
That is the mode to schedule quarterly, and the only one that proves a replica
rather than assuming it. The report says which of the two happened, per object,
so the weaker claim is never mistaken for the stronger one.

Verification of what this run *writes* follows `--verify` too:

| `--verify` | what it checks | what it claims |
|------------|----------------|----------------|
| `checksum` (default) | the object's ciphertext BLAKE3 is handed to the verified write, which commits nothing that does not match | the destination *stored* what we sent |
| `sample` | as above, plus 1 MiB read back from the destination and compared | …*and serves it back* |
| `strict` | as above, plus the whole object read back and its BLAKE3 compared | the replica *is* this object |

**Nothing is ever deleted from the destination.** Objects the replica holds and
the source does not are counted, reported as `extra`, and left exactly where they
are. Replication adds a copy; it never removes one, and no flag enables it to.
Removing the second copy is the one action that could turn a redundancy job into
a data-loss event.

### One failure is not the whole run

An object that cannot be read, cannot be written, or arrives wrong is recorded
against that object and the walk continues. The report names every failure, so a
run that moved 9 998 of 10 000 objects says so rather than saying "done", and the
process exits non-zero. A replication that stopped at the first failure would be
worse: the objects it had not reached yet are the ones with no second copy.

### Status in this build

`dctl replicate` is **implemented and does real work**: it resolves both stores,
plans, moves objects, verifies them, and reports. Two limits are worth knowing
before scheduling it.

* Objects move **one at a time**. `--transfers` accepts only `1` for that
  reason, on this command and every other; a larger value is refused with exit 7
  rather than accepted and ignored.
* An object is moved in one piece, because the storage layer's `put` takes a
  whole buffer. An object larger than **1 GiB** is reported as a failure with
  reason `object-too-large` rather than attempted; the limit disappears when the
  storage layer grows a streaming put.

```
dctl replicate SOURCE-STORE: DEST-STORE: [flags]
```

## Examples

The nightly offsite job. No password is read, so this is the line a backup
operator's cron entry contains, on a machine that holds no vault password at all:

```
dctl replicate archive-store: offsite-store:
```

Rehearse it first. `--dry-run` lists exactly what would be replicated, and moves
nothing:

```
dctl replicate archive-store: offsite-store: --dry-run
warning: [dry-run] would replicate 87 object(s) from 'archive-store:' to: offsite-store:
Action     Size     Path
replicate  4.0 MiB  o/3f/9a1c…
replicate  4.0 MiB  o/3f/9a1d…
```

The quarterly proof. Every object is read back from the replica and hash-compared
against the primary, and anything that drifted is replaced. This is a full egress
read of *both* stores, which is why it is quarterly rather than nightly:

```
dctl replicate archive-store: offsite-store: --verify strict -v
```

Feed a scheduled run to a monitoring system. `summary.failed` is the number to
alert on; `dry_run` is the field that says whether a second copy actually exists.
`skipped` and `reverified` are deliberately separate — a skip *assumes* the
replica holds the object, a reverification *proves* it — and `bytes` counts what
was written to the destination, which for a clean `--verify strict` run is zero
even though every object was read:

```
dctl replicate archive-store: offsite-store: --json | jq '.summary'
{
  "objects": 14203,
  "replicated": 87,
  "reverified": 0,
  "skipped": 14116,
  "failed": 0,
  "bytes": 364904448,
  "extra": 0
}
```

Replicate a vault that has no configuration on this machine at all — the
disaster-recovery case. Both ends are bare locations; the source is admitted
because it holds an envelope:

```
dctl replicate local:/mnt/recovered-disk b2:offsite-bucket
```

The vault remote is refused, and the refusal names the argument that works:

```
dctl replicate archive: offsite-store:
ERROR: SOURCE-STORE: 'archive:' is a vault remote, and reading a vault decrypts it
  hint: Replication moves opaque ciphertext and holds no key, so it is addressed at
        the object store rather than at the sealed view. 'archive' seals on the way
        through to 'archive-store'; replicate 'archive-store:' instead.
```

So is a filter, whether it was typed or inherited from a shell alias:

```
dctl replicate archive-store: offsite-store: --include '*.jpg'
ERROR: dctl replicate does not accept filters, and --include was given
  hint: A filtered replica is not a vault. …
```

And so is a destination nobody declared:

```
dctl replicate archive-store: /home/me/Documents
ERROR: DEST-STORE: '/home/me/Documents' is not a vault's object store: the
       configuration does not declare it one, and no vault envelope is stored there
  hint: … declare another with `dctl config create NAME TYPE bucket=BUCKET
        require_vault=true` …
```

## Options

```
  -h, --help   help for replicate
```

None of its own, and deliberately so. Every knob this command could grow — a
filter, a prefix, a "replicate only the new ones" switch — is a way to produce a
partial replica, and a partial replica is not a vault. The one dial that does
apply is the global `--verify`.

## Options inherited from parent commands

Every global flag is accepted. The ones that change what this command does are
`--verify` (see the table above), `--dry-run`, `--config` (which decides where
the store remotes are looked up), and the output flags
`--format`/`--json`/`--units`/`--quiet`/`-v`/`--progress`. The filtering flags are
accepted by the parser, because they are global, and **refused** by this command.
`--transfers` accepts only `1`; see *Status in this build*. The two cost
controls — `--bwlimit` and `--max-transfer` — are **not** applied by this command:
they are charged in the transfer pipeline, which `replicate` does not go through.
That is a gap rather than a decision, and it is named here rather than left to be
discovered on an invoice. See [../GLOBAL_FLAGS.md](../GLOBAL_FLAGS.md) for the
full list.

The authentication flags — `--password`, `--password-command`, `--password-file`
— are accepted and never read. There is no code path in this command that opens a
vault, and a test asserts that a complete run finishes without one.

## Exit codes

| Code | Name | When |
|-----:|------|------|
| 0 | `success` | Every object in the source store is now in the destination store. |
| 1 | `usage` | A filter flag, a missing argument, a malformed spec, a path inside a store, a vault remote on either side, or two arguments naming the same location. |
| 2 | `uncategorised` | The report could not be serialised. |
| 4 | `file_not_found` | A store could not be listed because it is not there. |
| 5 | `temporary_error` | A provider failed and the retry budget was exhausted before either store could be enumerated. |
| 6 | `partial_failure` | Some objects could not be replicated. The report names each one; the rest did arrive. |
| 7 | `fatal_error` | An unreadable configuration, an unresolvable remote, missing credentials, or a location that is neither declared a vault's object store nor holds one. |
| 20 | `checksum_mismatch` | A destination stored, or served back, something other than what it was sent. **Suspect the replica, not the source** — nothing at the source was touched. |
| 25 | `cancelled` | Ctrl-C or SIGTERM. Objects already committed at the destination stay; the run is never reported as complete. |

See [../EXIT_CODES.md](../EXIT_CODES.md) for the full contract.

## See also

* [dctl init](dctl_init.md) — creates the vault and registers the store remote
  this command is addressed at. Read the "why the base gets a name" section.
* [dctl config import](dctl_config.md) — writes addressing for a vault that
  already exists, using the same key-free envelope probe this command admits a
  bare location with.
* [dctl copy](dctl_copy.md) — the verb for moving *files* through a vault remote.
  It encrypts, it honours filters, and it needs the vault password.
* [dctl scrub](dctl_scrub.md) — proves the objects in one store are still
  readable. Replication gives you a second copy; a scrub tells you whether either
  copy has rotted.
* [dctl check](dctl_check.md) — compare two trees without transferring.
