# Exit codes

Every `dctl` invocation ends at `std::process::exit` with a code from
`ExitCode` (`crates/dctl-cli/src/exit.rs`). The numbers are a **public
contract**: scripts branch on them, so a code's meaning never changes once
released. New conditions get new numbers — they never reuse or re-scope an
existing one.

`main` deliberately never returns `Result`. Rust's default `Termination` for an
`Err` prints a `Debug` representation and exits 1, which would collapse the
whole taxonomy: a checksum mismatch and a typo in a flag would be
indistinguishable to a script.

## The two ranges

**0–10 mirror rclone's taxonomy.** The intent is that existing automation ports
across with minimal edits — a wrapper that already treats 5 as "retry the job
tonight" and 6 as "page someone about the file list" keeps working when the
binary underneath it changes. The numbers, and the conditions they stand for,
are the ones rclone publishes.

**20+ are DCTL-specific.** They cover failures rclone has no concept of, because
rclone has no vault: a verified write refusing to commit, AEAD authentication
failing on read, the encrypted index or write-ahead journal being unreadable,
the tamper-evident audit log failing its hash chain, and that log no longer
ending where it was anchored. Folding any of these
into 2 (`uncategorised`) or 7 (`fatal_error`) would tell an operator that
something went wrong while hiding the only thing that matters — whether the data
is intact.

The gap between 10 and 20 is left free so rclone can extend its own range without
colliding with DCTL's.

## All codes

Slugs and descriptions below are taken verbatim from `ExitCode::slug()` and
`ExitCode::describe()`.

| Code | Slug | Meaning |
|-----:|------|---------|
| 0 | `success` | Completed successfully |
| 1 | `usage` | Command-line syntax or usage error |
| 2 | `uncategorised` | Error not otherwise categorised |
| 3 | `dir_not_found` | Directory not found |
| 4 | `file_not_found` | File not found |
| 5 | `temporary_error` | Temporary error; retries exhausted |
| 6 | `partial_failure` | Some files failed to transfer |
| 7 | `fatal_error` | Fatal error; cannot continue |
| 8 | `transfer_limit_exceeded` | `--max-transfer` limit reached |
| 9 | `no_files_transferred` | Succeeded, but the run did no work |
| 10 | `duration_limit_exceeded` | `--max-duration` limit reached |
| 20 | `checksum_mismatch` | Verified write refused: checksum mismatch |
| 21 | `integrity_failure` | AEAD authentication failed on read |
| 22 | `vault_locked` | Vault locked: wrong password or corrupt envelope |
| 23 | `index_error` | Encrypted index or journal error |
| 24 | `audit_chain_broken` | Audit log hash chain verification failed |
| 25 | `cancelled` | Operation cancelled |
| 26 | `audit_head_mismatch` | Audit log head does not match the expected anchor |

The same table is written once in the code, as `ExitCode::slug` and
`ExitCode::describe` in `crates/dctl-cli/src/exit.rs`. This page is kept in step
with it by hand; there is no `dctl help exitcodes` subcommand, and this page used
to claim there was.

The slug is also the machine channel: it appears as the `error_code` field in
structured log records and in `--json` output, so a log pipeline can alert on
`error_code = checksum_mismatch` rather than parsing a number out of a shell
wrapper.

---

# The DCTL-specific codes

Each of these exists because the honest answer to "did that work?" is more than
yes or no. Read the **state** line first — it is the part that decides what you
do next.

## 20 — `checksum_mismatch`

**Verified write refused: checksum mismatch**

**Trigger.** A verified write read back what the destination stored and it did
not match what was sent. Raised as `StoreError::ChecksumMismatch { expected,
actual }` in the storage layer and classified in `error.rs`; also produced by
`Ctx::outcome()` when a batch run recorded any per-file mismatch, in which case
it outranks the ordinary partial-failure code 6.

**State of the data.** *Nothing was committed and the source is untouched.* This
is the strongest guarantee in the whole table. The write did not land, the index
commit that would make it count as stored never happened, and no source file was
deleted, moved or truncated on the strength of it. Whatever you were copying
still exists exactly where it was.

**What to do.** Retry — a single mismatch is usually one corrupted transfer. If
it persists, the provider or the network path is corrupting data in flight, and
that is a fault to find before you push more bytes through it. Do **not** work
around it by disabling verification; the code firing is the system doing its job.
Check the run's log for the `path` field to see which object failed.

## 21 — `integrity_failure`

**AEAD authentication failed on read**

**Trigger.** Stored data failed AEAD authentication when read back — wrong key,
tampered ciphertext, or the wrong binding context. Raised as `CoreError::Integrity`
or a `CryptoError`, and produced by `verify`, `scrub`, `hashsum` and the transfer
engine when the worst verdict in a run is `Corrupt`.

**State of the data.** *The plaintext was not served.* DCTL does not return bytes
that failed authentication, not even partially, not even with a warning — an
unauthenticated read is exactly the thing AEAD exists to prevent. The stored
object itself is still there, and still corrupt or forged; nothing was
overwritten or deleted in response.

**What to do.** Treat that object as lost from this copy. Restore it from another
copy or another tier, then run `dctl scrub` across the rest of the dataset —
corruption is rarely a single object, and the point of a scrub is to find the
others before restore day rather than on it. Note that `scrub` deliberately does
**not** exit 21 for damage it repaired: an object that is readable again is not a
data-loss event, and failing on it would train an operator to ignore the one code
that means data is gone.

## 22 — `vault_locked`

**Vault locked: wrong password or corrupt envelope**

**Trigger.** The vault could not be unlocked — a wrong password, a password
source that delivered something other than what was typed (`--password-file`,
`--password-command`), or a missing or corrupted key envelope. Raised as
`CoreError::Unlock`.

A second factor is *not* among the causes: this build cannot apply one, so
`--key-file` is refused with exit **7** before an unlock is attempted (see
[`--key-file`](GLOBAL_FLAGS.md#--key-file-path)) and can never be the reason a
vault failed to open.

**State of the data.** *Nothing was read and nothing was written.* Unlock happens
before any transfer work, so a run that dies here did not touch the vault or the
source. In a batch run this is classified fatal (see
`transfer::pipeline::is_fatal`), so the run stops at the first occurrence rather
than producing one identical failure per file across ten million files.

**What to do.** Check the password first, and check how it reached DCTL — a
`--password-file` or `--password-command` that emits a stray character produces a
different secret than the one you typed.

**There is a second way in: the recovery phrase.** `dctl init` prints a BIP-39
phrase when it creates the vault and reports `recovery_phrase_issued true`. That
phrase opens the vault independently of the password, and **changing the password
never invalidates it** — an old sheet of paper is still current.

```
dctl vault recover vault:            # open with the phrase, then set a new password
dctl vault recover vault: --keep-password   # prove the phrase still works, change nothing
```

The phrase is not limited to that one verb. `--recovery-phrase` and
`--recovery-phrase-file` are **global** flags, so `ls`, `cat`, `copy` and
`restore` all run under the phrase alone — which matters, because somebody who
has lost their password needs their data back, not a demonstration that the
phrase is valid. Prefer `--recovery-phrase-file` or `DCTL_RECOVERY_PHRASE`: an
argument is visible to every other process on the machine, and unlike a password
this secret cannot be rotated.

Two earlier revisions of this page were wrong about this in opposite directions,
and both cost the reader the same thing. The first told you to run
`dctl vault recover` with "the BIP39 phrase generated at init" when neither
existed. The correction then over-swung to "there is no second way in… no
`dctl vault recover` subcommand has ever existed", and stayed on the page after
both became real — telling somebody who was locked out to give up while the
command that would have let them in was in the binary they were running. A page
read at that moment has to be re-checked against the binary, not against the last
thing that was true.

If the password is definitely right, the envelope itself may be damaged. It is a
single object, `system/envelope.bin`, in the vault's object store. Restoring that
one object from a replica of the store is the only repair — which is why
`dctl replicate` is worth running before you need it: it copies the envelope
byte-for-byte along with everything else, and needs no password to do so.

## 23 — `index_error`

**Encrypted index or journal error**

**Trigger.** The encrypted index (redb, stored as an AEAD blob) or the
append-only write-ahead journal could not be read or written. Covers all three
`IndexError` variants — database failure, record (de)serialization failure, and
record decryption/authentication failure.

**State of the data.** *Your objects are fine; the catalogue of them is not.* The
index is a **rebuildable cache**, not the system of record — every object carries
its own header, and the index exists so listing does not require rescanning the
remote. A run that stops here has not lost stored data. It has lost the ability
to answer "what is in the vault?" quickly and, until rebuilt, may not be able to
resolve logical paths at all. Like 22, this is fatal to a batch run rather than
per-file.

**What to do.** Run `dctl index rebuild`, which rescans object headers and
reconstructs the index from them. If the failure was a decryption failure rather
than a database failure, also check that you are unlocking the vault you think
you are before rebuilding.

## 24 — `audit_chain_broken`

**Audit log hash chain verification failed**

**Trigger.** The tamper-evident audit log failed its hash-chain verification —
each entry carries the previous entry's hash, and one did not match. Raised in
one place (`commands::audit::verify::break_error`) and shared by `audit verify`,
`audit list` and `audit export`, because a listing of a forged log that exits 0
is worse than no listing at all.

**State of the data.** *Unknown, and that is the finding.* This code says nothing
about whether your objects are intact. It says the record that would let you
*prove* what happened to them no longer proves it. Every operation recorded after
the break position is unattested — it may have happened as described, or not at
all.

**What to do.** **Do not delete the log**, and do not "fix" it by regenerating
it. Keep this copy as evidence. Compare it against any mirrored or offline copy
of the log; a break that appears in one copy and not the other localises the
tampering. Treat everything after the break as unverified history, and escalate —
a broken chain on a system nobody was working on is a security event, not a
maintenance task.

## 25 — `cancelled`

**Operation cancelled**

**Trigger.** Ctrl-C or SIGTERM. `main` races the command future against the
signal, so cancellation is caught wherever the run happened to be. Also returned
when an operator declines an interactive confirmation for a destructive command
(`purge`, `rmdir`).

**State of the data.** *In-flight work was rolled back or left resumable, and
nothing was reported as successful.* The index commit that makes a transfer count
as stored never happened for anything still in flight, so a partially uploaded
object is not in the vault. Work completed and committed before the signal stays
committed — this is a stop, not an undo.

**What to do.** Re-run the same command. Cancellation is not an error condition
and needs no remediation; the reason it gets its own code at all is so a wrapper
script can distinguish "the operator stopped it" from "it finished", which exit 0
would hide and exit 1 would misreport as a usage error.

## 26 — `audit_head_mismatch`

**Audit log head does not match the expected anchor**

**Trigger.** `dctl audit verify --expect-head <anchor>` walked the chain, found
every link sound, and found that the chain does not end at the head the caller
anchored. Raised in one place
(`commands::audit::verify::head_mismatch_error`), and produced by that flag and
nothing else.

**Why it is not 24.** A hash chain detects every edit made *inside* a log and
none made to its **end**: drop the last two records and what remains is a shorter
chain whose every link still holds. 24 says the links failed. 26 says the links
held and this is not the chain you left — a different finding, with a different
first move, and the only way tail truncation is ever visible. It also covers the
routine case of an anchor that is simply older than the log, which must not be
reported behind the code operators are told to page on.

**State of the data.** *Unknown, and possibly less of it than you have a record
of.* Like 24, this says nothing about whether your objects are intact. It says
the account of what happened to them is not the account you last saw.

**What to do — read the `kind` first.** `--json` carries
`head_mismatch.kind`, and the four are not the same event:

| `kind` | What happened | What to do |
|--------|---------------|------------|
| `advanced` | The anchored head is **still in the chain**; records were appended after it. Nothing was removed. | Not an incident. Read the new records with `dctl audit list`, then take a fresh anchor with `dctl audit head`. |
| `truncated` | The chain is **shorter** than the anchor says it was; the message carries the exact number missing. | **Incident.** |
| `diverged` | The anchored position holds a record that is not the one anchored: history at or before the anchor was rewritten, or this is a different chain. | **Incident.** |
| `absent` | The anchored head is nowhere in the chain, and the anchor carried no record count, so the loss cannot be measured. | **Incident** — and switch to the counted anchor `dctl audit head` prints, so the next answer carries a number. |

On any of the three incident kinds: **do not re-anchor, and do not delete the
log.** A fresh anchor taken from a shortened log makes the shortened log the new
baseline and destroys the only evidence that anything was removed. Keep the file,
keep the old anchor, and compare against any mirrored or offline copy.

Where an operator is supposed to keep the anchor, and how often to take one, is
[`AUDIT_LOG.md`](AUDIT_LOG.md) §10 — written as an operating procedure, because a
defence nobody knows how to run is not a defence.

---

# How each layer's errors map onto codes

Classification happens in exactly one place — `crates/dctl-cli/src/error.rs` — so
a `checksum-mismatch` deep in the storage layer always surfaces as exit 20 with
the same message no matter which command produced it. The mapping is deliberately
conservative: anything that could mean "the data might not be intact" gets its
own loud code rather than the generic bucket.

**`dctl-store` — `StoreError`**

| Variant | Code | Slug |
|---------|-----:|------|
| `NotFound(key)` | 4 | `file_not_found` |
| `ChecksumMismatch { expected, actual }` | 20 | `checksum_mismatch` |
| `InvalidKey(_)` | 1 | `usage` |
| `RangeOutOfBounds { size }` | 1 | `usage` |
| `Io(_)` | 2 | `uncategorised` |
| `Backend(_)` | 5 | `temporary_error` |

`Backend` is the retryable class (network, timeout, 429, 5xx). By the time one
reaches the CLI the retry budget is already spent, which is why it maps to
"retries exhausted" and not to a generic error.

**`dctl-core` — `CoreError`**

| Variant | Code | Slug |
|---------|-----:|------|
| `Unlock` | 22 | `vault_locked` |
| `NotFound(path)` | 4 | `file_not_found` |
| `Integrity(_)` | 21 | `integrity_failure` |
| `Crypto(CryptoError)` | 21 | `integrity_failure` |
| `Index(IndexError)` | 23 | `index_error` |
| `Store(StoreError)` | — | delegates to the `StoreError` table above |

**`dctl-index` — `IndexError`**

All three variants (`Db`, `Serialize`, `Crypto`) reach the CLI wrapped in
`CoreError::Index` and become 23.

**CLI config — `ConfigError`** (`crates/dctl-cli/src/config/error.rs`)

Split on where the fault is: a *fatal* error means the state of the machine is
wrong, a *usage* error means the invocation was wrong. A bad `--name` argument
must not look like a corrupted installation.

| Variants | Code | Slug |
|----------|-----:|------|
| `NameEmpty`, `NameTooShort`, `NameTooLong`, `NameCharset`, `NameStart`, `ReservedName` | 1 | `usage` |
| `Missing`, `Read`, `Write`, `Parse`, `Serialize`, `SecretInConfig`, `DuplicateNameCase`, `UnknownRemote`, `UnknownBase`, `VaultCycle`, `ChainTooDeep` | 7 | `fatal_error` |

**`std::io::Error`**

| Kind | Code | Slug |
|------|-----:|------|
| `NotFound` | 4 | `file_not_found` |
| `PermissionDenied` | 7 | `fatal_error` |
| anything else | 2 | `uncategorised` |

**`anyhow::Error`**

Downcast first: if a `StoreError` is buried in the context chain, its typed
classification is preserved. Otherwise 2 (`uncategorised`). This is the fallback
for helper code, not the normal path.

**Command-level verdicts**

`Verdict` (`commands/integrity/failure.rs`), used by `verify`, `scrub` and
`hashsum`, exits on the *worst* verdict in the run:

| Verdict | Code | Slug |
|---------|-----:|------|
| `Ok` | 0 | `success` |
| `Missing` | 4 | `file_not_found` |
| `Unreadable` | 5 | `temporary_error` |
| `Corrupt` | 21 | `integrity_failure` |

**Parser and process level**

`clap` usage errors exit 1; `--help` and `--version` arrive as `Err` from the
parser but are **not** failures and exit 0, so `dctl --help` does not break a
script running under `set -e`. `CliError::unimplemented` exits 7 — a feature the
parser accepts but no engine implements is an error, never a silent success.

## Partial failure is never rolled up into success

`PLAN.md` §7 forbids reporting partial or unverified work as success, and the
rule is enforced in `main`/`Ctx` rather than trusted to each command. A command
can return `Ok(())` while individual files failed; the **counters, not the return
value, decide the exit status**:

| Counters after the run | Code |
|------------------------|-----:|
| any checksum mismatch recorded | 20 |
| otherwise, any error recorded | 6 |
| otherwise | 0 |

So a `sync` of 10,000 files where 3 fail exits **6**, not 0 — and if any of those
3 failed verification it exits **20**. There is no flag that converts this into
success.

The complement of that rule is that one bad file does not abandon the run. Only
codes 1, 7, 22, 23 and 25 are treated as fatal to a batch (`is_fatal` in
`transfer/pipeline.rs`), because each of those makes every remaining file fail
identically; grinding through ten million files to produce ten million identical
errors helps nobody. Everything else is counted and the run continues.

---

# Branching on the codes in a backup script

The distinction that matters operationally is **retry later** (5 — transient, the
system is fine) versus **stop and investigate** (20, 21, 24, 26 — the system is
telling you something about your data's integrity that will not improve by
running the command again).

```bash
#!/usr/bin/env bash
# Nightly vault backup. Exit codes are a contract; branch on them, not on stderr.
set -uo pipefail   # NOT -e: we need to inspect the code ourselves.

LOG=/var/log/dctl/backup.log

# The audit anchor lives on another host, and this host's key there can only
# append. An anchor kept locally is truncated by the same command as the log it
# is supposed to protect (AUDIT_LOG.md section 10.4).
anchor_take()  { printf '%s %s\n' "$(date -u +%FT%TZ)" "$(dctl audit head)" \
                   | ssh anchor-host 'cat >> /var/lib/dctl-anchors/prod'; }
anchor_last()  { ssh anchor-host 'tail -n1 /var/lib/dctl-anchors/prod' | awk '{print $NF}'; }

dctl sync /srv/data vault:data --log-file "$LOG" --log-format json
code=$?

case $code in
  0)
    logger -t dctl "backup ok"
    ;;

  9)  # succeeded, nothing to do — a no-op night is a good night
    logger -t dctl "backup ok (nothing new)"
    ;;

  # ── retry later: transient, the data is fine ────────────────────────────
  5)  # retries already exhausted inside dctl; the provider or link was down
    logger -t dctl "backup deferred: provider unreachable, retrying at 04:00"
    systemd-run --on-active=4h --unit=dctl-backup-retry /usr/local/bin/backup.sh
    exit 0
    ;;

  6)  # some files failed; the rest are stored. Worth a look, not a page.
    logger -t dctl "backup partial: see $LOG"
    notify-ops "dctl: partial backup, $(date +%F)"
    exit 0
    ;;

  25) # operator stopped it, or the box is shutting down. Not an error.
    logger -t dctl "backup cancelled"
    exit 0
    ;;

  # ── stop and investigate: do not retry, do not overwrite anything ───────
  20) # verified write refused. NOTHING was committed; the source is untouched.
    page-oncall "dctl 20 checksum_mismatch: destination stored wrong bytes. \
Source intact, nothing committed. Suspect provider or network path."
    exit $code
    ;;

  21) # stored data failed authentication on read. It was NOT served.
    page-oncall "dctl 21 integrity_failure: stored object failed AEAD auth. \
Restore from another copy, then scrub the dataset."
    exit $code
    ;;

  24) # the audit log no longer proves what it claims.
    page-oncall "dctl 24 audit_chain_broken: DO NOT DELETE THE LOG. \
Preserve it, compare against the offline mirror, treat later entries as unattested."
    exit $code
    ;;

  26) # the chain verifies but does not end where we anchored it.
    # `advanced` is the log having grown since the last anchor and is routine;
    # the other three kinds mean history is missing. Read the kind, do not
    # re-anchor on an incident — a fresh anchor makes the short log the baseline.
    kind=$(dctl audit verify --json --expect-head "$(anchor_last)" \
             | jq -r '.head_mismatch.kind')
    case $kind in
      advanced)
        dctl audit list --limit 50      # the records the old anchor did not cover
        anchor_take                     # then, and only then, move the baseline
        logger -t dctl "dctl 26 advanced: log grew since the last anchor"
        exit 0
        ;;
      *)
        page-oncall "dctl 26 audit_head_mismatch ($kind): DO NOT DELETE THE LOG \
AND DO NOT RE-ANCHOR. Records are missing from the end. Preserve the log and the \
anchor, compare against the offline mirror."
        exit $code
        ;;
    esac
    ;;

  22) # wrong password/factor, or a damaged envelope. Nothing was touched.
    page-oncall "dctl 22 vault_locked: check credentials, then the envelope."
    exit $code
    ;;

  23) # index or journal unreadable. Objects are fine; the catalogue is not.
    logger -t dctl "dctl 23 index_error: rebuilding index"
    dctl index rebuild && exec "$0"      # one retry after a rebuild
    exit $code
    ;;

  *)  # 1, 2, 3, 4, 7 and anything added later
    page-oncall "dctl exited $code: see $LOG"
    exit $code
    ;;
esac
```

Two things to keep in mind when writing one of these:

- **Do not run the `dctl` call under `set -e`.** It exits the script before you
  can read `$?`, collapsing every code into "the script failed".
- **Have a `*)` arm.** New conditions get new numbers, and a script that silently
  ignores an unrecognised code is a script that will one day ignore a new
  integrity failure.

For a machine consumer, prefer the slug over the number — `--json` output and the
`error_code` log field both carry it, and a slug survives a reader who has never
seen this document.

## What is reachable in this build

Code 8 (`transfer_limit_exceeded`) **is** produced today, by the transfer verbs
under `--max-transfer`. It was unreachable in every earlier build — the flag was
parsed and never enforced, so a run capped at 1 MiB moved 10 MiB and exited 0.
A file is now not *started* when moving it would take the run past the ceiling,
so the limit is never exceeded and exit 8 is what a script sees when it is met.
See [Global flags → `--max-transfer`](GLOBAL_FLAGS.md#--max-transfer-size).

Code 10 (`duration_limit_exceeded`) remains defined and reserved but not
produced: `--max-duration` is not a flag in this build. It is listed here because
the number is already committed to and will not be reused for anything else.

Code 9 (`no_files_transferred`) **is** produced today, by the three commands
whose entire product is a claim that data is there:

* [`dctl scrub`](commands/dctl_scrub.md) — a run that read no object at all
  reports grade `unverified` and exits 9 rather than 0.
* [`dctl verify`](commands/dctl_verify.md) — a run that examined no object exits
  9 and says `nothing was verified: <cause>`.
* [`dctl restore`](commands/dctl_restore.md) — a run that wrote no file exits 9
  and says `nothing was restored: <cause>`, on a real run and on a `--dry-run`
  alike.

Nothing failed in any of them — the prefix matched nothing, or the dataset is
empty, or the filters admitted nothing — but nothing was proved either, and a
scheduled check that stays green while verifying nothing is the failure that
discipline exists to prevent. `verify` used to exit **0** for this and, at the
default verbosity, print nothing on either stream; `restore` used to exit **0**
with a warning. Both are now the same answer `scrub` has always given.

**No transfer verb produces it**, and that is deliberate rather than unfinished.
`dctl copy`, `dctl backup` and `dctl sync` over a source that legitimately holds
no files are correct no-ops that a schedule runs every day, and turning a quiet
Sunday into a non-zero exit would train operators to ignore the code.

Individual commands document which codes they can actually return today — see the
**Exit codes** section of each page under [commands/](commands/).
