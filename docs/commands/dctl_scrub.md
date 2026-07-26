# dctl scrub

Re-read and verify the whole dataset, reporting its health.

## Synopsis

`dctl scrub` re-reads a dataset on purpose, before you need it. It is the
ZFS-scrub discipline written into `PLAN.md` §13.4, and its whole reason for
existing is one sentence: **never discover corruption for the first time on
restore day.** Cloud objects rot, providers lose replicas, and a backup that has
sat untouched for three years has never once been proved readable. A scheduled
scrub converts that unknown into a number.

A run walks the remote, selects the objects the plan covers, reads each one back
in full, checks it as strongly as that remote allows, and reports a health grade
together with how much of the dataset it actually read and what the reading
proved.

The grade is three words, not two:

| grade | meaning | exit |
|-------|---------|-----:|
| `healthy` | everything read authenticated | 0 |
| `degraded` | damage was found and **all of it** was repaired | 0 |
| `damaged` | damage was found that could not be repaired | 21 (or 4/5) |

`degraded` deliberately does not fail the run. The object is readable again, and
exiting non-zero for a successful repair would train an operator to ignore the
one code that means data is actually gone. It is still reported, and every
object that had to be rebuilt is still named in the findings — the storage
underneath is failing even when the system handled it. **`degraded` is not
reachable in this build**, because nothing repairs — see `--repair` below.

**The grade always says what the reading could prove.** A sealed vault checks
every chunk's authentication tag and the object's own recorded content hash, so
`healthy` there means *these are the bytes that were written*; the report carries
`"assurance": "authenticated"`. A plain remote — including the object store a
vault's ciphertext lives in — records no hash of its own, so the strongest honest
claim is *the object was still there and every byte of it came back*, reported as
`"assurance": "read-back"` and warned about on stderr. The weaker check is
genuinely useful: it is how a replica quietly losing objects is caught. It is
simply not the same statement, and one word must not carry both.

**Cost is the thing to plan around.** A full scrub reads every byte in the
vault, which on a cloud remote is a full egress bill. Every selected object is
read back **in full** whatever `--verify` says: there is no provider-checksum
comparison behind a scrub in this build, so a cheaper strength cannot be
honoured. Asking for one produces a warning on stderr, and the report records the
strength that actually ran (`strict`) rather than the one requested — a report
naming a check that did not happen would be the misreport this command exists to
prevent. Memory does not scale with the object: a vault is verified by
stream-decrypting into a sink, so a fifty-gigabyte video costs a chunk rather
than a video. `--sample-percent` bounds the cost by reading a slice of the
dataset instead of all of it. The selection is a
BLAKE3 keyed hash of each logical path under a **per-run seed**, which makes it
deterministic within a run — the plan is decided before the walk and gives the
same answer if an object is revisited — and different between runs, so
successive scrubs cover different slices instead of reading the same tenth
forever. The seed is printed and carried in the report as a 16-digit hex string,
so a run that found damage in a 10% sample can be replayed over exactly that
10%. A sampled run warns, on stderr, that its grade covers only the objects it
read; `scrub` counts skipped objects explicitly so "healthy" can never be read
as "all of it is healthy" when most of it was never looked at.

`--max-errors N` stops the run after N damaged objects. It is unlimited by
default (`0`) because the most valuable thing a scrub reports is *how
widespread* the damage is, and stopping early hides that; when a budget is set,
the run warns that the report may understate the extent of the damage, and the
report carries `stopped_early: true` so a machine consumer can tell too.

**`--repair` is refused, not ignored.** Repair means rebuilding a damaged object
from redundancy — the par2-style Reed-Solomon parity of `PLAN.md` §13.3 — and
this build writes no parity, so there is nothing to rebuild from. Passing the
flag ends the run with exit code **1** and a message naming what would have to
exist first. `--dry-run` does not soften that: a dry run of an impossible
operation is still impossible, and printing `[dry-run] would repair` would
promise a capability that is not there. Accepting the flag and quietly doing
nothing would be worse still — a run reporting `damaged` would leave the operator
believing a repair had been attempted and failed for some other reason.

With repair unavailable, `scrub` writes nothing at all, which is why `--dry-run`
has nothing to suppress and why the command is safe to schedule anywhere.

The target must be a remote. `REMOTE:` scrubs the whole dataset; `REMOTE:PATH`
scrubs a prefix, matched by whole path components — `photos` is not the parent of
`photos-backup`. A local directory is rejected as a usage error: it is not a
remote holding a copy of anything, so there is nothing there to scrub. Following
rclone's rule, `C:\data`, `d:/data` and `\\server\share` are local on every
platform; remote names must be at least two characters, which is what makes the
drive-letter rule unambiguous.

`--include`, `--exclude`, `--min-size`, `--max-size` and `--max-depth` narrow
what is read. `--filter-from` and `--files-from` are **refused** rather than
ignored, because their rule-file semantics are not implemented and a scrub that
silently covered less than was asked for would overstate its coverage.

Stdout carries the findings and nothing else: a `Status`/`Size`/`Path` table of
the damaged objects, with healthy ones counted rather than listed. A healthy
scrub therefore prints **nothing** on stdout — the grade and the coverage belong
on stderr with the rest of the commentary. `--json` emits one document with
`target`, `health`, `verify_mode`, `sample_percent`, `seed`, `repair_enabled`,
`assurance`, `stopped_early`, a `coverage` block (`scanned`, `skipped`, `bytes`,
`healthy`, `damaged`, `repaired`) and a `findings` array. `--format json-lines`
emits one finding per line.

`coverage.bytes` and each finding's size come from the index, which is where a
vault's plaintext sizes live. Straight after `dctl index rebuild` those sizes are
not yet known and read as zero — the rebuild says so when it runs, and the object
was still read back in full regardless.

### Damage is a finding, not an exit

A corrupt or unreachable object does not stop the walk. The most valuable thing
a scrub reports is *how widespread* the damage is, and returning at the first bad
object would hide every other one. Each failure is named on stderr as it is
found, classified into one of three verdicts — `corrupt` (the bytes came back and
were not the bytes that were stored), `missing` (the index and the provider
disagree), `unreadable` (the provider never answered) — because the operator's
next action differs for each. `--max-errors` is how stopping early becomes an
explicit decision, and the report carries `stopped_early` so a machine consumer
can tell it happened.

```
dctl scrub REMOTE:[PATH] [flags]
```

## Examples

The monthly job: read every object in the vault back, decrypt it, and confirm
its whole-file BLAKE3. This is a full egress read of the dataset, which is the
point — it is also the reason most people run it on a schedule rather than
interactively.

```
dctl scrub vault: --verify strict -v
```

The weekly job on a vault too large to read in one night. Ten percent per run,
a different tenth each time, so the whole dataset is covered over a quarter. The
warning on stderr names the seed; keep it if the run finds anything.

```
dctl scrub b2prod:bucket --verify strict --sample-percent 10
```

Scrub a single prefix. Damage that is found is named object by object and makes
the run exit 21; nothing is rewritten, because nothing can be.

```
dctl scrub vault:photos/2019
```

`--repair` is refused rather than accepted and quietly dropped, and `--dry-run`
does not change that:

```
dctl scrub vault:photos/2019 --repair
ERROR: --repair has nothing to rebuild from in this build
  hint: Per-object Reed-Solomon parity is `PLAN.md` §13.3 and is not written by
        this build, so no redundancy exists for `--repair` to read. Re-run
        without it to get the health report, then restore any damaged object
        from another copy of the 3-2-1 set.
```

Scrub the object store a vault's ciphertext lives in. This proves every sealed
object is still retrievable — which is what catches a replica quietly losing
objects — and the report says plainly that it proves no more than that:

```
dctl scrub archive-store: --json
warning: 'archive-store:' records no hash of its own — every byte was re-read,
         but this remote records no hash of its own, so a pass proves the object
         is retrievable and not that it is unchanged
{ "target": "archive-store:", "health": "healthy", "assurance": "read-back", ... }
```

Feed a scheduled scrub to a monitoring system, bounding the damage report so a
catastrophically broken remote does not tie up the job for eight hours. The
JSON carries `stopped_early` when the budget was reached, and `coverage.skipped`
so the grade is never mistaken for a statement about the whole vault.

```
dctl scrub vault: --sample-percent 25 --max-errors 100 --json
```

`scrub` needs a remote. A Windows path is a local path — `C:` is a drive letter,
not a remote named `C` — and a local directory is not a remote holding a copy of
anything, so there is nothing there to scrub:

```
dctl scrub C:\Backups\vault
ERROR: dctl scrub needs a remote path, but 'C:\Backups\vault' is local
  hint: Write the target as 'REMOTE:PATH', for example 'vault:photos'.
```

## Options

```
  -h, --help                       help for scrub
      --max-errors <N>             Stop after this many damaged objects. 0 means no limit [default: 0]
      --repair                     Rebuild damaged objects from redundancy or parity where possible (refused: see above)
      --sample-percent <PERCENT>   Read this percentage of the dataset instead of all of it [default: 100]
```

`--sample-percent` accepts 1–100 and is range-checked by the parser, so `0` and
`101` are rejected before the run starts. Zero is excluded on purpose: a scrub
that reads nothing could only ever report health it never measured.

## Options inherited from parent commands

Every global flag is accepted on `dctl scrub`. The ones that change what this
command does are the `--include`/`--exclude`/`--min-size`/`--max-size`/
`--max-depth` filters and the output flags
`--format`/`--json`/`--units`/`--quiet`/`-v`. See
[../GLOBAL_FLAGS.md](../GLOBAL_FLAGS.md) for the full list.

Several are accepted and do **not** change what happens here, which is worth
knowing before a schedule is built around them. `--verify` and
`--verify-samples` cannot make a scrub cheaper — every selected object is read
back in full — and asking for a weaker strength produces a warning rather than a
weaker check. `--dry-run` has nothing to suppress, because a scrub with
`--repair` refused writes nothing at all. `--transfers` and `--bwlimit` do not
pace the read-back: it is sequential, which is what keeps memory at one object's
chunk regardless of dataset size.

`--filter-from` and `--files-from` are **refused**: their rule-file semantics are
not implemented, and a scrub that silently covered less than was asked for would
overstate its coverage.

## Exit codes

| Code | Name | When |
|-----:|------|------|
| 0 | `success` | Grade `healthy`: everything the run read came back intact. |
| 1 | `usage` | Unknown flag, missing target, a local target, `--repair`, `--sample-percent` outside 1–100, a remote name shorter than two characters, or a path containing `..`. |
| 2 | `uncategorised` | The report could not be serialised. Not reachable for these types in practice. |
| 4 | `file_not_found` | The worst verdict was `missing`: objects are in the index but absent at the provider. |
| 5 | `temporary_error` | The worst verdict was `unreadable`: the provider could not serve objects and the retry budget was exhausted. |
| 7 | `fatal_error` | An unresolvable remote, an unreadable configuration, `--filter-from`/`--files-from`, or another setup failure. |
| 21 | `integrity_failure` | Grade `damaged`: objects failed authentication. **The data was NOT served.** |
| 22 | `vault_locked` | A sealed target would not unlock. |
| 25 | `cancelled` | Ctrl-C or SIGTERM. A partly-completed scrub is never reported as a clean one. |

`degraded` is not reachable in this build: it means damage that was repaired, and
nothing repairs.

See [../EXIT_CODES.md](../EXIT_CODES.md) for the full contract.

## See also

* [dctl verify](dctl_verify.md) — the same authentication check, aimed at one
  object or prefix on demand rather than at the dataset on a schedule.
* [dctl check](dctl_check.md) — compare two trees; use it to confirm a second
  copy exists, which with `--repair` unavailable is the only thing that makes
  damage recoverable.
* [dctl index rebuild](dctl_index.md) — reconcile the index with what the
  provider actually holds, which is the remedy for a `missing` verdict.
* [dctl hashsum](dctl_hashsum.md) — export the recorded hashes so the dataset can
  be checked by tools that have never heard of DCTL.
* [dctl restore](dctl_restore.md) — the operation a scrub exists to keep boring.
* [dctl audit](dctl_audit.md) — the tamper-evident record of what was written.
