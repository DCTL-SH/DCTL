# dctl verify

Verify that stored objects decrypt and match their recorded hashes.

## Synopsis

`dctl verify` is the read-side half of DCTL's verified-write contract
(`PLAN.md` §6). A write refuses to commit unless the destination's checksum
matches the one computed locally; `verify` asks the same question again later,
on demand, against objects that have already been stored. It answers "is what
the provider holds still the thing I wrote?" — nothing is transferred, nothing
is repaired, and neither the vault nor any local tree is modified.

**How hard it looks is the global `--verify` dial, not a flag of this command.**
That is deliberate: verification strength is a per-remote setting in
`config.toml` as well as a command-line flag, and a second spelling on `verify`
would create two settings that mean one thing. The three strengths make three
materially different claims:

| `--verify` | what it does | what it proves | egress |
|------------|--------------|----------------|--------|
| `checksum` (default) | compares the provider's stored checksum against ours | the provider still holds the ciphertext we sent | none |
| `sample` | additionally Range-reads and decrypts `--verify-samples` chunks per object (default 8) | those chunks decrypt and authenticate | partial |
| `strict` | reads and decrypts every object in full, confirming its whole-file BLAKE3 | the plaintext is intact, end to end | full |

Every report names the strength that produced it, because "1,204 objects
verified" means three different things depending on the answer and readers
assume the strongest one. When a strength that reads object bytes (`sample`,
`strict`) is aimed at a *tree* rather than a single object, `verify` warns
before it starts: a strict verify of `vault:` downloads the whole vault, and the
bill for that arrives after the run does.

**Failure is loud, and it is specific.** Each object gets one of four verdicts —
`ok`, `corrupt` (authentication or hash comparison failed: real damage),
`missing` (the index has a record, the provider has no object), or `unreadable`
(the provider never answered inside the retry budget). They are kept apart
because the operator's next move differs for each, and because calling an
outage "corruption" sends somebody hunting for damage that is not there. The
worst verdict in the run decides the exit code: `corrupt` produces exit **21**
with a message containing the literal phrase *the data was NOT served*, and no
run that found damage ever exits zero.

By default a run examines everything it was pointed at and reports how much is
damaged. `--fail-fast` stops at the first failure instead; it is off by default
because the extent of the damage is usually the most useful thing a verify run
can tell you, and stopping at the first bad object hides it.

The target must be a remote (`REMOTE:PATH`). Verification compares stored bytes
against hashes the vault recorded for them, and a local path has no such record,
so a local target is rejected as a usage error rather than producing a vacuous
"0 objects verified". Following rclone's rule, `C:\data`, `d:/data` and
`\\server\share` are treated as **local** on every platform — a script written on
Windows behaves identically on a Linux build agent. Remote names must be at
least two characters, which is exactly what makes the drive-letter rule
unambiguous. Paths inside a vault are canonicalised (`/`-separated, NFC, no `.`
or `..`) so two spellings of one filename cannot address two different objects;
a path containing `..` is rejected.

Output goes to stdout, commentary to stderr. Text output is an aligned table of
`Status`, `Size`, `Path`, plus a `Detail` column that appears only when
something failed. `--json` emits a single document carrying `target`,
`verify_mode`, an `objects` array and a `summary` of `examined` / `verified` /
`failed` / `bytes`. `--format json-lines` emits one object record per line and
*no* summary record, so a consumer never has to buffer the run. A report with no
objects prints nothing at all on stdout — not even a header, which would read as
a finding to anything downstream.

`verify` mutates nothing, so `--dry-run` has nothing to suppress; it is also not
permission to claim a verification that never ran.

### Status in this build

**`dctl verify` is not implemented in this build.** Argument parsing, target
resolution, the verdict vocabulary, the report shape in all three output
formats, the verdict-to-exit-code mapping and the failure wording are written
and unit-tested; the step that reads and authenticates a stored object is not.
`dctl_core::Vault` exposes `verify_file` for a single path but no way to
enumerate and verify a prefix at a chosen strength, and `Ctx` does not yet carry
an unlocked vault.

A complete invocation therefore validates everything it can, prints its
pre-flight commentary on stderr, and then fails with
`dctl verify is not implemented in this build` and exit code **7**. It does not
print a success message, and it does not print an empty report. `PLAN.md` §11
puts `ls`/`verify`/`check` in **Phase 1 (B2 MVP)**.

```
dctl verify REMOTE:PATH [flags]
```

## Examples

Verify a year of photographs at the default strength. No object bytes are read:
DCTL asks the provider for each object's stored checksum and compares it with
the value recorded in the index at write time.

```
dctl verify vault:photos/2024
```

Prove that an entire bucket is not merely present but readable, then act on the
answer. `--verify strict` downloads and decrypts every object and confirms its
whole-file BLAKE3; `-v` turns on the stderr commentary that names the strength
and explains what it checked, and the warning that a strict verify of a tree
means full egress.

```
dctl verify b2prod:bucket/media --verify strict -v
```

Verify one object and capture the result for a monitoring system. JSON carries
`verify_mode` alongside the counts, so the record cannot later be read as a
stronger claim than the run actually made.

```
dctl verify vault:photos/2024/IMG_4417.CR3 --json
```

Sample-verify a large archive without paying for a full read-back, and stop at
the first bad object because this run only needs a yes/no answer for a nightly
alert.

```
dctl verify coldvault:archive/2019 --verify sample --verify-samples 16 --fail-fast
```

A Windows path is not a remote. `C:` is a drive letter, so this is a local path,
and `verify` rejects it as a usage error (exit 1) instead of contacting a remote
named `C` or silently hashing local files — which would answer a different
question from the one that was asked:

```
dctl verify C:\Backups\photos
ERROR: dctl verify needs a remote path, but 'C:\Backups\photos' is local
  hint: Write the target as 'REMOTE:PATH', for example 'vault:photos'.
```

## Options

```
  -h, --help        help for verify
      --fail-fast   Stop at the first object that fails instead of checking the rest
```

`REMOTE:PATH` is required. A bare `vault:` or a trailing separator
(`vault:photos/`) names a *tree* and verifies everything under it; without the
separator the spec names a single object.

## Options inherited from parent commands

Every global flag is accepted on `dctl verify`, before or after the subcommand.
The ones that change what this command does are `--verify` and
`--verify-samples` (verification strength and depth), the `--include`/
`--exclude`/`--filter-from`/`--files-from` filters, `--format`/`--json`/
`--units`/`--quiet`/`-v` (output), and `--transfers`/`--checkers`/`--retries`/
`--bwlimit` (how the reads are paced). See [../GLOBAL_FLAGS.md](../GLOBAL_FLAGS.md)
for the full list.

## Exit codes

| Code | Name | When |
|-----:|------|------|
| 0 | `success` | Every object examined verified. Not reachable in this build. |
| 1 | `usage` | Unknown flag, missing target, a local target, a remote name shorter than two characters, or a path containing `..`. |
| 2 | `uncategorised` | The report could not be serialised. Not reachable for these types in practice. |
| 4 | `file_not_found` | The worst verdict was `missing`: objects are in the index but absent at the provider. |
| 5 | `temporary_error` | The worst verdict was `unreadable`: the provider could not serve objects and the retry budget was exhausted. |
| 7 | `fatal_error` | Returned by every complete invocation in this build (`not implemented`), and by configuration or setup failures. |
| 21 | `integrity_failure` | At least one object failed authentication. **The data was NOT served.** |
| 25 | `cancelled` | Ctrl-C or SIGTERM. Nothing in flight was reported as complete. |

In this build only **1**, **7** and **25** are reachable. The verdict-driven
codes — 0, 4, 5 and 21 — are implemented and unit-tested but need the engine work
described under *Status in this build* before a run can produce them.

Codes 0–10 mirror rclone's taxonomy; 20+ are DCTL's own. See
[../EXIT_CODES.md](../EXIT_CODES.md) for the full contract.

## See also

* [dctl scrub](dctl_scrub.md) — the scheduled, whole-dataset form of the same
  check, with sampling, repair and a health grade.
* [dctl check](dctl_check.md) — compare two trees against each other rather than
  objects against their recorded hashes.
* [dctl hashsum](dctl_hashsum.md) — print the recorded hashes instead of
  comparing them.
* [dctl audit](dctl_audit.md) — verify the tamper-evident log of what was
  written, rather than the objects themselves.
* [dctl restore](dctl_restore.md) — the drill that a passing `verify` is meant to
  make boring.
