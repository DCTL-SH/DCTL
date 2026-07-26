# dctl audit

Inspect and verify the tamper-evident audit log.

## Synopsis

`dctl audit` is the evidence half of `PLAN.md` §7. DCTL keeps an **append-only,
hash-chained** record of every operation — timestamp, operation, result, logical
path, plaintext and ciphertext hashes, size, remote — where each entry carries
the previous entry's hash. That single property is what turns a log file into
evidence: the sequence can be *extended* but not *rewritten*. Editing one entry
changes its hash, which orphans the entry after it; deleting one leaves a gap in
the indices; reordering breaks both. `dctl audit` is how you check, read and hand
over that chain.

There are three verbs, and one rule that binds them:

* `verify` — walk the chain and report the exact record where it fails.
* `list` — show what the log says happened, with filters.
* `export` — hand the chain to somebody else, byte-for-byte re-verifiable.

**Every one of them walks the whole chain, and every one of them exits 24 if it
is broken.** A `list` that printed forged rows and exited 0 would put those rows
on screen with an implicit clean bill of health; an `export` that silently copied
a broken chain into an evidence bundle would be worse. The output is still
produced — an investigator needs it — and the exit code says what it is. For the
same reason, filters on `list` narrow *which records are shown* and never
*whether the chain is walked*: verifying only the records that survived a
`--since` would verify nothing at all.

A subcommand is required. A bare `dctl audit` prints help and exits **1** rather
than quietly defaulting to `verify`, because a command whose most important
behaviour is invisible in the scripts that call it is a command nobody can audit.

**What a break report tells you.** The walk stops at the first failure and names
the *exact position*: which record (0-based position in the file, not a number
the file supplied — a forged `index` field cannot move it), which line
(1-based, since the log is one record per line and that is what an editor
shows), and which of four ways the chain failed. The four are checked in a
deliberate order per record:

| `kind` | meaning |
|--------|---------|
| `malformed-hash` | `hash` or `prev` is not a full-width hex value. Checked first, so a truncated hash can never accidentally compare equal to a prefix. |
| `index-discontinuity` | A gap or a repeat in the indices — what a *deleted* record leaves behind even if somebody re-linked the survivors. |
| `broken-link` | `prev` does not match the preceding record's hash: a record was removed, reordered or inserted. |
| `content-mismatch` | The record's own hash does not cover its content: a field was edited in place. |

Link is checked before content because a removal is the more precise diagnosis.
A forger who edits record 2 *and* re-hashes it shows up as a `broken-link` at
record 3 — the orphan is the evidence — and reporting "record 3's content was
edited" would send an investigator to the wrong place. The walk stops rather than
continuing because everything after a break is unattested; listing thousands of
"also broken" records would bury the one position that matters.

**What is hashed.** Not the JSON. JSON key order, whitespace and number
formatting are free choices, so re-serialising and hashing that would make every
record look forged the moment a writer changed its formatting. A record's hash
covers an explicit, ordered, separator-joined string — `prev`, `index`, `time`,
`op`, `result`, `path`, `size`, `plaintext_hash`, `ciphertext_hash`, `remote` —
joined by U+001F (unit separator), hashed with BLAKE3, rendered as 64 hex
characters. The separator is the anti-forgery property: control characters are
rejected in every DCTL name, so no field value can reach across a boundary and
make two different records serialise to the same bytes. Hex comparison is
case-insensitive, because a conforming writer may legitimately choose either
spelling.

**What this cannot detect: truncation of the tail.** Removing the last *n*
records leaves a chain that verifies perfectly, because nothing inside the log
attests to its own length. Detecting that needs an anchor kept somewhere the
writer cannot reach — the encrypted remote mirror §7 mentions, or a periodically
published head hash. `verify` prints the head hash for exactly that purpose;
compare it against a value you recorded elsewhere. An evidence tool that
overstates what it proves is worse than one that proves less, so this limit is
stated rather than glossed.

**A line that will not parse is treated as tampering**, not as a formatting
inconvenience — reported with its line number, at exit **24**. A line that is not
a record is indistinguishable from a line somebody edited badly, and the two have
to be reported the same way. A crash mid-append produces the same signature,
which is the right trade: an operator told "line 88 812 is not a record" can go
and look; one told nothing cannot.

**Where the log lives.** An explicit `--audit-log` wins. Otherwise the log sits
next to the encrypted index — `--index /data/vaults/one.redb` puts it at
`/data/vaults/audit.jsonl` — so a machine working with two vaults keeps two
independent chains instead of interleaving them into one that describes neither.
With no `--index`, it falls back to the platform data directory —
`~/.local/share/dctl/audit.jsonl` on Linux,
`~/Library/Application Support/dctl/audit.jsonl` on macOS, and the equivalent
under `%APPDATA%` on Windows — which is where the index defaults to as well. The
file is named `audit.jsonl` in every case, and it is line-delimited JSON: one
record per line, which is what makes the break report's line number meaningful.

`verify` and `list` change nothing. `export --output` writes a file, so it
honours `--dry-run`, and overwriting an existing file goes through the
destructive gate: `--dry-run` declines and prints `[dry-run] would overwrite`,
`--interactive` prompts, `--force` approves without asking, and a bare run
proceeds. Exporting over last month's evidence bundle is precisely the accident
worth one confirmation.

### Status in this build

**The reader is complete; the writer is not.** The chain walk, all four failure
diagnoses, the filters and all three renderings work today on any conforming log,
and are exercised by the unit tests. What does not exist is the engine-side
append that `PLAN.md` §7 requires after every operation — it belongs to the
verified-write state machine in **Phase 0** of `PLAN.md` §11, alongside the WAL
and the error taxonomy.

So when no log file exists, `dctl audit` reports
`the tamper-evident audit log writer is not implemented in this build` and exits
**7**. It deliberately does *not* report "0 records, chain intact", which would be
a clean bill of health for a system that has never recorded anything. Point
`--audit-log` at a chain written elsewhere — a mirrored copy, an evidence bundle,
a colleague's export — and every verb works for real.

One rough edge follows from that: a *mistyped* `--audit-log` path produces the
same "writer is not implemented" message and exit 7, because the check is
"nothing is there", not "the default location is empty". The hint always names
the path that was looked for, so read it before concluding the feature is
missing.

```
dctl audit verify [flags]
dctl audit list [flags]
dctl audit export [flags]
```

## Examples

Check a chain and branch on the answer. The verdict is **data**, so the bare word
goes to stdout and a shell test can compare it directly; the exit code carries
the same answer for anything that branches on `$?`.

```
dctl audit verify --audit-log /srv/vaults/prod/audit.jsonl
intact
```

Record the head hash somewhere the writer cannot reach. This is the only defence
against tail truncation: nothing inside the log attests to its own length, so an
anchor kept outside it is what makes a missing tail detectable.

```
dctl audit verify --json | jq -r '.head' >> /mnt/wormstore/dctl-heads.txt
```

See what a chain says happened to one tree over one day. The window is half-open
— inclusive at `--since`, exclusive at `--until` — so two adjacent windows
partition the log instead of sharing a record on the boundary. `--path` compares
whole components, so `photos/2024` does not capture `photos/2024-backup`.

```
dctl audit list --path photos/2024 --since 2026-07-25 --until 2026-07-26
Index  Time                  Op      Result   Hash          Path
-----  --------------------  ------  -------  ------------  -----------
    2  2026-07-25T02:00:11Z  backup  success  7d3a95ec3f01  photos/2024
```

Show the last twenty deletions against a bucket, as JSON Lines for a log
pipeline. `--limit` keeps the *tail* — the most recent records — still in
chronological order, so the chain reads forwards.

```
dctl audit list --op delete --limit 20 --format json-lines
```

Produce an evidence bundle that the recipient can check for themselves. Text
output *is* the canonical JSON Lines form — there is no prose rendering of a hash
chain, and inventing one would produce a file that looks like an export but
cannot be checked — so the copy re-verifies byte for byte:

```
dctl audit export --audit-log /srv/vaults/prod/audit.jsonl > /evidence/2026-07-26.jsonl
dctl audit verify --audit-log /evidence/2026-07-26.jsonl
intact
```

A forged record. Somebody edited what a copy claims to have copied and did not
re-hash it. The verdict still goes to stdout, the diagnosis to stderr, and the
process exits 24:

```
dctl audit verify --audit-log /evidence/2026-07-26.jsonl
broken
error: /evidence/2026-07-26.jsonl: audit chain broken at record 1 (line 2): carries
  hash 7bf17d72…, but its content hashes to 77c25f27… — the record was edited in place
  hint: The audit log no longer proves what it claims. Do not delete it: keep this
  copy, compare it against any mirrored or offline copy, and treat every operation
  recorded after the break as unattested.
$ echo $?
24
```

Read a chain that belongs to a second vault on the same machine, on Windows. The
log follows the index, so naming the index is enough — and a Windows path is
accepted wherever a local path is, drive letter and all:

```
dctl audit list --index C:\ProgramData\dctl\archive\index.redb --limit 50
```

Audit a broken chain anyway, because an investigator needs the rows. Both `list`
and `export` emit their full output first and *then* fail, so a pipeline that
captures stdout gets everything even though the exit code says not to trust it:

```
dctl audit list --audit-log /evidence/tampered.jsonl --json > rows.json || echo "chain broken: $?"
chain broken: 24
```

## Options

```
  -h, --help   help for audit
```

`dctl audit` itself takes no flags beyond `--help`; it requires one of the three
verbs below.

### dctl audit verify

```
  -h, --help               help for verify
      --audit-log <PATH>   Chain to verify. Defaults to the log beside the configured index
```

### dctl audit list

```
  -h, --help               help for list
      --audit-log <PATH>   Chain to read. Defaults to the log beside the configured index
      --op <OP>            Show only this operation, using `dctl`'s own command names
      --path <PATH>        Show only records touching this logical path or a path beneath it
      --since <TIME>       Show only records at or after this instant
      --until <TIME>       Show only records before this instant
      --limit <N>          Show at most this many records, most recent last. 0 shows every record [default: 0]
```

`--op` is an **exact** match against `dctl`'s own command names (`copy`, `move`,
`sync`, `delete`, `backup`, `restore`, …) — a prefix match would make `--op copy`
also select `copyto`. `--path` is canonicalised like every other path
(`/`-separated, NFC, no `.` or `..`); a `--path` containing `..` is a usage
error. `--since`/`--until` accept `2026-07-26`, `2026-07-26T14:30:00Z`, `2d`
(two days ago), `@1753574400` (Unix seconds) or `now`, and are **always UTC**.
Both resolve against a single reference instant, so `--since now --until now`
cannot describe a non-empty window. A record whose own timestamp cannot be parsed
is **kept**, never dropped: hiding the one malformed record is precisely how a
forgery would escape a listing.

### dctl audit export

```
  -h, --help               help for export
      --audit-log <PATH>   Chain to export. Defaults to the log beside the configured index
      --output <PATH>      Write to this file instead of standard output
```

## Options inherited from parent commands

Every global flag is accepted on `dctl audit` and its verbs, before or after the
subcommand. The ones that matter here are `--index` (which decides where the log
is looked for), `--format`/`--json`/`--quiet`/`-v` (output), and — for
`export --output` — `--dry-run`, `--interactive` and `--force`. The transfer,
filtering and durability flags have no effect: `audit` moves no bytes and applies
no path filters beyond its own `--op`/`--path`/`--since`/`--until`. See
[../GLOBAL_FLAGS.md](../GLOBAL_FLAGS.md) for the full list.

`--format` changes each verb differently. For `verify`, text prints the bare word
`intact` or `broken` (what a shell test compares) while `--json` and
`--format json-lines` emit the whole verdict document with the head hash or the
break position. For `list`, text is an aligned table showing only a 12-character
hash *prefix* — it is there to tell adjacent rows apart, not to let anyone
believe a row was checked by looking at it — `--json` is one array, and
`--format json-lines` is one record per line. For `export`, text and
`--format json-lines` are the same canonical form; `--json` produces a single
array document instead.

## Exit codes

| Code | Name | When |
|-----:|------|------|
| 0 | `success` | The chain verified. |
| 1 | `usage` | No verb given, an unknown flag, an unparseable `--since`/`--until`, a `--path` containing `..`, or `--interactive` with no terminal to prompt on. |
| 2 | `uncategorised` | An I/O error other than "not found" or "permission denied" while reading the log or writing `--output`, or a serialisation failure while encoding an export. |
| 4 | `file_not_found` | A component of the `--output` path does not exist. |
| 7 | `fatal_error` | **No log file at the resolved path** — reported as "the tamper-evident audit log writer is not implemented in this build", including when the path came from an explicit `--audit-log` — or the log could not be read for want of permission. |
| 24 | `audit_chain_broken` | **The chain failed.** Returned by all three verbs, after their output has been produced. Also returned when a line in the log is not a parseable record, since that is indistinguishable from tampering. |
| 25 | `cancelled` | An `--interactive` overwrite of `--output` was declined, or Ctrl-C / SIGTERM. |

Exit **24** is the code to branch on. It means one thing and only one thing: the
tamper-evident log no longer proves what it claims. Nothing else in DCTL returns
it. Codes 0–10 mirror rclone's taxonomy; 20+ are DCTL's own. See
[../EXIT_CODES.md](../EXIT_CODES.md) for the full contract.

## See also

* [dctl verify](dctl_verify.md) — check that the stored *objects* still match
  their recorded hashes, rather than checking the record of what was written.
* [dctl scrub](dctl_scrub.md) — the scheduled, whole-dataset form of that check.
* [dctl backup](dctl_backup.md) — the operation whose records fill this log.
* [dctl restore](dctl_restore.md) — the drill an intact chain is meant to make
  provable after the fact.
* [dctl check](dctl_check.md) — compare two trees against each other.
