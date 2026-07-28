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

The grade is four words, not two:

| grade | meaning | exit |
|-------|---------|-----:|
| `healthy` | everything read authenticated | 0 |
| `degraded` | damage was found and **all of it** was repaired | 0 |
| `damaged` | damage was found that could not be repaired | 21 (or 4/5) |
| `unverified` | **no object was read at all** | 9 |

`unverified` is not a health grade and does not pretend to be one. The other
three describe what reading found; this one says nothing was read, so there is no
claim to make. It is reached when the prefix matches no object, when the dataset
is empty, when the filters admit nothing, or when `--sample-percent` selected
nothing — four causes with four different next actions, so the message names
which one applied.

It exits **9** (`no_files_transferred`, "succeeded but did no work") rather than
0. Nothing failed, so it is not an error code; but `dctl scrub archive:` over a
real dataset and `dctl scrub archive:typo` over nothing used to be the same
silent exit 0, which let a nightly cron verify nothing and stay green until
somebody needed a restore. Code 9 is the code scripts already branch on for "the
run worked and did no work", so an existing wrapper needs no new vocabulary.

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
rclone's rule, `\\server\share` is local on every platform and `C:\data` and
`d:/data` are local where drives exist; off Windows they name the remotes `C` and
`d`.

`--include`, `--exclude`, `--min-size`, `--max-size` and `--max-depth` narrow
what is read, and so do `--filter-from` and `--files-from`, which are
**honoured** by the same rule engine `dctl copy` uses. A rule file that cannot be
read or parsed stops the run as a usage error (exit 1) naming the file and the
line, rather than being dropped: a scrub that silently covered less than was
asked for would overstate its coverage, which is the one thing a health report
must never do.

Stdout carries the findings and nothing else: a `Status`/`Size`/`Path` table of
the damaged objects, with healthy ones counted rather than listed. A healthy
scrub therefore prints **nothing** on stdout — the grade and the coverage belong
on stderr with the rest of the commentary.

**Every text-mode run reports what it covered, at default verbosity**, on stderr:

```text
OK healthy: 3 objects read and checked, 25 B (authenticated) under 'archive:'
```

A scrub's product *is* its coverage, and a clean run used to print nothing at all
on either stream unless `-v` was given — indistinguishable from a scrub that had
found nothing to read, and from a binary that never ran. The line names the
grade, the object count, the bytes, what the reading proved, and the target; it
gains a clause for objects the sample skipped, for objects with no recorded size,
and for damage. `--quiet` suppresses it, and the zero-coverage case is carried by
the exit code and its error message instead, which print regardless.

`--json` emits one document with `target`, `health`, `verify_mode`,
`sample_percent`, `seed`, `repair_enabled`, `assurance`, `stopped_early`, a
`coverage` block (`scanned`, `skipped`, `bytes`, `measured_bytes`, `unmeasured`,
`healthy`, `damaged`, `repaired`) and a `findings` array. `--format json-lines`
emits one finding per line. The prose summary is text-mode only: the JSON already
carries every number in it, and a second rendering is a second thing that can
disagree with the data.

### Sizes that were never measured

`coverage.bytes` and each finding's size come from the index, which is where a
vault's plaintext sizes live. A row can still lack one: `dctl index rebuild`
reads each object's header for the size, and an object it could not read back
leaves the path mapped and unmeasured (the rebuild counts those and exits **6**).

They are reported as **unknown**, not as zero. `coverage.bytes` becomes `null`,
`coverage.unmeasured` counts the rows responsible, `coverage.measured_bytes`
carries the honest lower bound, and a finding's `size` is `null`. In text the
byte figure reads `-` and the summary line says so. A full, honest scrub of a
forty-terabyte vault used to file itself as having read `"bytes": 0`, which is a
false line in the one artefact whose entire value is being true.

The objects are still read back in full and still graded, because the grade does
not depend on knowing a length. A read does not fill the size in — `cat`,
`hashsum` and `scrub` all leave the row as unmeasured as they found it — so the
remedy is `dctl index rebuild`, which reads the header the size lives in.

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

`--filter-from` and `--files-from` are **honoured**, and a rule file that cannot
be read or parsed stops the run as a usage error (exit 1) naming the file and the
line — never dropped, because a scrub that silently covered less than was asked
for would overstate its coverage.

## Exit codes

| Code | Name | When |
|-----:|------|------|
| 0 | `success` | Grade `healthy`: everything the run read came back intact, and it read something. |
| 1 | `usage` | Unknown flag, missing target, a local target, `--repair`, `--sample-percent` outside 1–100, a remote name shorter than two characters, or a path containing `..`. |
| 2 | `uncategorised` | The report could not be serialised. Not reachable for these types in practice. |
| 4 | `file_not_found` | The worst verdict was `missing`: objects are in the index but absent at the provider. |
| 5 | `temporary_error` | The worst verdict was `unreadable`: the provider could not serve objects and the retry budget was exhausted. |
| 7 | `fatal_error` | An unresolvable remote, an unreadable configuration, `--filter-from`/`--files-from`, or another setup failure. |
| 9 | `no_files_transferred` | Grade `unverified`: the run completed and read no object at all. Nothing failed; nothing was proved either. |
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
