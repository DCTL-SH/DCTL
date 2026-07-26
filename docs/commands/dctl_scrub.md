# dctl scrub

Re-read and verify the whole dataset, repairing from redundancy.

## Synopsis

`dctl scrub` re-reads a dataset on purpose, before you need it. It is the
ZFS-scrub discipline written into `PLAN.md` §13.4, and its whole reason for
existing is one sentence: **never discover corruption for the first time on
restore day.** Cloud objects rot, providers lose replicas, and a backup that has
sat untouched for three years has never once been proved readable. A scheduled
scrub converts that unknown into a number.

A run walks the vault's index, selects the objects the plan covers, reads each
one back and authenticates it at the global `--verify` strength, optionally
rebuilds damaged objects from redundancy or parity, and reports a health grade
together with how much of the dataset it actually read.

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
underneath is failing even when the system handled it.

**Cost is the thing to plan around.** A full scrub reads every byte in the
vault, which on a cloud remote is a full egress bill, and the `--verify`
strength decides how thoroughly each object is read (`checksum` compares stored
checksums with no egress; `sample` Range-reads and decrypts a few chunks per
object; `strict` reads and decrypts everything). `--sample-percent` bounds the
cost by reading a slice of the dataset instead of all of it. The selection is a
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

**`--repair` is the only part of a scrub that writes anything**, and therefore
the only part `--dry-run` suppresses. The interlock is resolved before the plan
is built rather than at the point of writing: under `--dry-run`, repair is
turned off, a `[dry-run] would repair damaged objects in: <target>` notice is
printed, and the plan itself never carries permission to write. Repair rebuilds
damaged objects from redundancy or parity (`PLAN.md` §13.3) where the material
to do so exists; where it does not, the object stays damaged and the run fails.

The target must be a remote. `REMOTE:` scrubs the whole dataset; `REMOTE:PATH`
scrubs a prefix. A scrub compares stored objects against hashes the vault
recorded for them, so a local directory — which has no such record — is rejected
as a usage error. Following rclone's rule, `C:\data`, `d:/data` and
`\\server\share` are local on every platform; remote names must be at least two
characters, which is what makes the drive-letter rule unambiguous.

Stdout carries the findings and nothing else: a `Status`/`Size`/`Path` table of
the damaged objects, with healthy ones counted rather than listed. A healthy
scrub therefore prints **nothing** on stdout — the grade and the coverage belong
on stderr with the rest of the commentary. `--json` emits one document with
`target`, `health`, `verify_mode`, `sample_percent`, `seed`, `repair_enabled`,
`stopped_early`, a `coverage` block (`scanned`, `skipped`, `bytes`, `healthy`,
`damaged`, `repaired`) and a `findings` array. `--format json-lines` emits one
finding per line.

### Status in this build

**`dctl scrub` is not implemented in this build.** Argument parsing, target
resolution, the sampling and error-budget logic, the health grading, the report
shape in all three formats, the `--repair`/`--dry-run` interlock and the
exit-code classification are written and unit-tested; reading objects back is
not. `dctl_core::Vault` has no prefix-wide verification entry point and `Ctx`
does not yet carry an unlocked vault.

A complete invocation therefore builds and reports its plan on stderr and then
fails with `dctl scrub is not implemented in this build` and exit code **7**. It
does not print a health grade it never measured, which would be precisely the
lie this command exists to prevent. `PLAN.md` §11 does not name `scrub` in a
numbered phase — the command is specified in §13.4, and the nearest roadmap slot
is **Phase 4 (Hardening)**, which is where crash-consistency and format work
land.

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

Scrub a single prefix and repair what can be repaired. Rebuilt objects are
reported as `degraded` and the run still exits 0; anything that could not be
rebuilt makes the run `damaged` and exits 21.

```
dctl scrub vault:photos/2019 --repair --verify strict
```

Rehearse the same command first. `--dry-run` disables repair before the plan is
built, so nothing can be written, and prints what it would have done:

```
dctl scrub vault:photos/2019 --repair --dry-run
warning: [dry-run] would repair damaged objects in: vault:photos/2019
```

Feed a scheduled scrub to a monitoring system, bounding the damage report so a
catastrophically broken remote does not tie up the job for eight hours. The
JSON carries `stopped_early` when the budget was reached, and `coverage.skipped`
so the grade is never mistaken for a statement about the whole vault.

```
dctl scrub vault: --sample-percent 25 --max-errors 100 --json
```

`scrub` needs a remote. A Windows path is a local path — `C:` is a drive letter,
not a remote named `C` — and there is nothing local to scrub against, because a
local directory carries none of the recorded hashes a scrub compares with:

```
dctl scrub C:\Backups\vault
ERROR: dctl scrub needs a remote path, but 'C:\Backups\vault' is local
  hint: Write the target as 'REMOTE:PATH', for example 'vault:photos'.
```

## Options

```
  -h, --help                       help for scrub
      --max-errors <N>             Stop after this many damaged objects. 0 means no limit [default: 0]
      --repair                     Rebuild damaged objects from redundancy or parity where possible
      --sample-percent <PERCENT>   Read this percentage of the dataset instead of all of it [default: 100]
```

`--sample-percent` accepts 1–100 and is range-checked by the parser, so `0` and
`101` are rejected before the run starts. Zero is excluded on purpose: a scrub
that reads nothing could only ever report health it never measured.

## Options inherited from parent commands

Every global flag is accepted on `dctl scrub`. The ones that change what this
command does are `--verify` and `--verify-samples` (how thoroughly each object
is read), `--dry-run` (which disables `--repair`), the `--include`/`--exclude`/
`--filter-from`/`--files-from`/`--max-depth` filters, `--transfers`/`--bwlimit`/
`--retries` (how the read-back is paced against a provider), and the output
flags `--format`/`--json`/`--units`/`--quiet`/`-v`. See
[../GLOBAL_FLAGS.md](../GLOBAL_FLAGS.md) for the full list.

## Exit codes

| Code | Name | When |
|-----:|------|------|
| 0 | `success` | Grade `healthy`, or `degraded` — damage was found and all of it was repaired. Not reachable in this build. |
| 1 | `usage` | Unknown flag, missing target, a local target, `--sample-percent` outside 1–100, a remote name shorter than two characters, or a path containing `..`. |
| 2 | `uncategorised` | The report could not be serialised. Not reachable for these types in practice. |
| 4 | `file_not_found` | The worst verdict was `missing`: objects are in the index but absent at the provider. |
| 5 | `temporary_error` | The worst verdict was `unreadable`: the provider could not serve objects and the retry budget was exhausted. |
| 7 | `fatal_error` | Returned by every complete invocation in this build (`not implemented`), and by configuration or setup failures. |
| 21 | `integrity_failure` | Grade `damaged`: objects failed authentication and were not repaired. **The data was NOT served.** |
| 25 | `cancelled` | Ctrl-C or SIGTERM. A partly-completed scrub is never reported as a clean one. |

In this build only **1**, **7** and **25** are reachable — the `--sample-percent`
range check and the local-target rejection both run before the unimplemented
error. Codes 0, 4, 5 and 21 need the engine work described under *Status in this
build*.

See [../EXIT_CODES.md](../EXIT_CODES.md) for the full contract.

## See also

* [dctl verify](dctl_verify.md) — the same authentication check, aimed at one
  object or prefix on demand rather than at the dataset on a schedule.
* [dctl check](dctl_check.md) — compare two trees; use it to confirm a second
  copy exists before relying on `--repair`.
* [dctl hashsum](dctl_hashsum.md) — export the recorded hashes so the dataset can
  be checked by tools that have never heard of DCTL.
* [dctl restore](dctl_restore.md) — the operation a scrub exists to keep boring.
* [dctl audit](dctl_audit.md) — the tamper-evident record of what was written.
