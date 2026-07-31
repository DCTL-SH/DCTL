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

### The `--verify` dial in this build

**Every selected object is read back in full, whatever `--verify` says**, and the
run warns when a cheaper strength was requested. The report records the strength
that actually *ran* (`strict`), not the one that was asked for.

One of the cheaper two cannot be performed at all with the calls that exist; the
other has not been designed. Performing something else while reporting the
requested name would be the misreport `PLAN.md` §6 forbids:

* `checksum` would need the provider's checksum of the *stored object* compared
  against one DCTL holds. `dctl_core::Vault` exposes no such value — the index
  records a hash of the **plaintext**, and the object key the ciphertext lives
  under is deliberately unreachable from the read abstraction. Since `checksum`
  is the *default*, honouring it literally would make a bare `dctl verify
  archive:` read nothing and then print a wall of `ok`.
* `sample` could now be built — a vault serves a genuine ranged authenticated
  read, so spot-checking a few windows of a huge object costs O(window). It is
  still not built, and that difference is deliberate: which windows, how many,
  and what a pass over 1% of a file entitles anyone to claim are design
  questions, and answering them badly produces a check that reads cheap and
  proves nothing.

The day `dctl-core` exposes a stored-object checksum, and `sample` is designed
rather than merely enabled, this becomes a real dial and the warning disappears.

```console
$ dctl verify archive:
warning: --verify=checksum asks for a cheaper check than `dctl verify` can perform in this build: dctl-core exposes no stored-object checksum, and no sampling strategy is defined, so every selected object is read back in full
warning: verifying the tree 'archive:' reads every object it contains
Status  Size  Path
------  ----  ----------------------
ok       3 B  a.jpg
ok      11 B  notes.txt
ok       7 B  photos/2024/c.jpg
ok       7 B  photos/b.jpg
ok       7 B  photos/tmp/scratch.jpg
ok       6 B  private/secret.txt
ok      11 B  tmp/scratch.txt
$ echo $?
0
```

```
dctl verify REMOTE:PATH [flags]
```

## Examples

Verify a year of photographs. Every object under the prefix is read back,
decrypted and authenticated against the hash recorded when it was written.

```
dctl verify vault:photos/2024
```

Damage is loud, and the default says **how much** of the dataset is affected —
one corrupt object out of 40,000 is a restore of one file, and 12,000 is a lost
dataset:

```console
$ dctl verify archive:
warning: corrupt: format: footer mismatch
warning: corrupt: format: footer mismatch
Status   Size  Detail                   Path
-------  ----  -----------------------  ----------------------
ok        3 B  -                        a.jpg
ok       11 B  -                        notes.txt
ok        7 B  -                        photos/2024/c.jpg
corrupt   7 B  format: footer mismatch  photos/b.jpg
ok        7 B  -                        photos/tmp/scratch.jpg
corrupt   6 B  format: footer mismatch  private/secret.txt
ok       11 B  -                        tmp/scratch.txt
error: 2 of 7 objects failed integrity verification — the data was NOT served
warning: Restore the affected objects from another copy, then run `dctl scrub` to check the rest of the dataset — corruption is seldom limited to one object.
$ echo $?
21
```

`--fail-fast` trades that number for speed, and the report says the trade was
made so nobody reads the count as the full extent of the damage:

```console
$ dctl verify archive: --fail-fast --json | jq '{stopped_early, summary}'
{
  "stopped_early": true,
  "summary": {
    "examined": 4,
    "verified": 3,
    "failed": 1,
    "bytes": 28
  }
}
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

## What a pass proves, and the two claims a plain remote cannot make

`verify` publishes two things about every run, in the JSON document and on the
last line of a text run, because the count on its own is read as a statement
about a dataset and on a plain remote it is not one.

| field | question | `vault:` | plain `local:`/`sftp:` | plain `b2:` |
|-------|----------|----------|------------------------|-------------|
| `assurance` | are these the bytes that were written? | `authenticated` | `read-back` — **no** | `provider-checksum` |
| `inventory` | is everything that was written still here? | `recorded` | `self-reported` — **no** | `self-reported` — **no** |

A **vault** answers both. Every object has an index row written at store time and
kept outside the remote, so an object the backend has lost is reported `missing`
and the run exits **4**; every byte is authenticated against a hash recorded
under the vault's own key, so a changed byte exits **21**.

A **plain remote** answers neither by default, and the run **refuses at exit 27**
rather than reporting `ok`:

* it records no digest of what was written, so a changed byte reads back exactly
  like an unchanged one — unless the provider records one of its own, which B2
  does and `local:`/`sftp:` do not;
* it keeps no record of what it *should* hold, so `verify` enumerates the remote
  and then re-reads the keys the remote just reported. Both sides of that
  comparison are one source. An object deleted from it is not `missing`; it is
  simply not listed, and a store that quietly lost half its objects would report
  the other half.

The second is true of **every** plain remote including B2, and it is why the
refusal fires there too. There is no manifest to turn on: an expectation kept
inside the remote is lost by whatever lost the object, a plain remote is a shared
namespace DCTL takes no lock on, and a record of what should be there cannot be
rebuilt from a listing without adopting whatever the listing has already lost.
The record DCTL does ship is a vault.

Each limit has its own flag, and the flag's name is the sentence being agreed to.
Setting one does not accept the other.

## Options

```
  -h, --help                        help for verify
      --fail-fast                   Stop at the first object that fails instead of checking the rest
      --allow-read-back             Run against a remote that cannot detect a changed byte, and accept
                                    that a rotted object will read back as `ok`
      --allow-listing-as-inventory  Treat this remote's own listing as the record of what it should
                                    hold, and accept that an object deleted from it will not be reported
```

`--allow-read-back` buys the check that *can* be made on a remote with no
recorded digests: every byte of every listed object re-read in full, which proves
those objects are still retrievable. It proves nothing about whether they
changed, and nothing at all about one that is gone.

`--allow-listing-as-inventory` buys nothing — there is no weaker check of a set
than reading the set itself. It exists so that an operator who wants the
retrievability run on a plain remote can have it, having said in writing that a
lost object will not be reported. If that is not acceptable, the two things that
do detect a loss are a vault (`dctl init`) and `dctl check SOURCE REMOTE:`, which
compares a replica against the tree it replicates.

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
| 0 | `success` | Every object examined verified, and at least one was. |
| 9 | `no_files_transferred` | The run examined **no object**: the prefix matched nothing, the dataset is empty, or the filters admitted nothing. Nothing failed and nothing was proved; the message names which cause applied. `dctl scrub` answers the same condition the same way. |
| 1 | `usage` | Unknown flag, missing target, a local target, a remote name shorter than two characters, or a path containing `..`. |
| 2 | `uncategorised` | The report could not be serialised. Not reachable for these types in practice. |
| 4 | `file_not_found` | The worst verdict was `missing`: objects are in the index but absent at the provider. |
| 5 | `temporary_error` | The worst verdict was `unreadable`: the provider could not serve objects and the retry budget was exhausted. |
| 7 | `fatal_error` | An unresolvable remote, an unreadable configuration, or a vault that would not unlock. |
| 21 | `integrity_failure` | At least one object failed authentication. **The data was NOT served.** |
| 25 | `cancelled` | Ctrl-C or SIGTERM. Nothing in flight was reported as complete. |
| 27 | `verification_not_possible` | The remote cannot make a claim this command publishes, and the run stopped **before reading anything**. Not damage and not loss: the message names each claim that cannot be made and the flag that accepts it. See the table above. |

All of these are reachable.

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
