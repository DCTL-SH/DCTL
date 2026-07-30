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

There are four verbs, and one rule that binds them:

* `verify` — walk the chain and report the exact record where it fails.
* `head` — print the anchor to keep somewhere the writer cannot reach.
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

**What the chain alone cannot detect: truncation of the tail.** Removing the last
*n* records leaves a chain that verifies perfectly, because nothing inside the log
attests to its own length — and the records an attacker most wants gone are the
most recent ones. Nothing written *into* the log can close that: whoever can cut
the tail can cut anything the tail said about itself.

`dctl audit head` and `dctl audit verify --expect-head` are the mechanism that
does. `head` prints an **anchor** — one token, `<records>:<head>` — which you keep
somewhere this machine cannot rewrite; `--expect-head` asserts the chain still
ends there and exits **26** with the number of missing records when it does not.
An unanchored `verify` that says `intact` is making a claim about **content, not
length**, and says so at `-v`. The operating procedure — where to keep the
anchor, how often to take one, and what each exit code means — is
[`../AUDIT_LOG.md`](../AUDIT_LOG.md) §10.

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
`~/.dctl/audit/` — the same directory tree the index and config live in, so a
single backup of `~/.dctl` captures all of it. The
file is named `audit.jsonl` in every case, and it is line-delimited JSON: one
record per line, which is what makes the break report's line number meaningful.

`verify` and `list` change nothing. `export --output` writes a file, so it
honours `--dry-run`, and overwriting an existing file goes through the
destructive gate: `--dry-run` declines and prints `[dry-run] would overwrite`,
`--interactive` prompts, `--force` approves without asking, and a bare run
proceeds. Exporting over last month's evidence bundle is precisely the accident
worth one confirmation.

### What is in the log

Every operation that changes stored data appends one chained record, after its
durable commit and with an `fsync` before the command reports success:

* the transfer family — `copy`, `move`, `sync`, `copyto`, `moveto` — one record
  per file, and for a `move` after the source has been removed;
* the removal family — `delete`, `deletefile`, `purge`, `rmdir`, `rmdirs`,
  `cleanup` — one record per object, after the store confirms;
* `rcat`, `replicate`, `init` and `index rebuild`.

**Failures are in there too**, carrying the command's own slug from
`docs/EXIT_CODES.md`, because a log of nothing but successes cannot answer "what
went wrong on the 3rd?". A command refused *before* it reached the store — a
mistyped remote, a path the vault does not hold — records nothing: it attempted
nothing, and filling an evidence file with typing helps nobody.

Reads append nothing. Neither does `--dry-run`, which changed nothing and so has
nothing to attest to. `docs/AUDIT_LOG.md` §9 is the normative table, including
which hash fields each family populates.

If a record cannot be written, **the command fails** — exit 24 when the log is
not a chain that may be extended, exit 7 for any other write failure. Carrying on
unaudited would be exactly the misreporting `PLAN.md` §7 forbids.

### A missing log is not an empty one

An **empty** log verifies and reports `0 records`: "nothing has been appended" is
a real answer, and a fresh vault gives it until its first `init` or `copy`.

An **absent** file is exit **4** (`file_not_found`), naming the path that was
looked for. It far more often means the reader was pointed somewhere the writer
never wrote — a different `--index`, a different machine, a log that was moved —
than that nothing ever happened, and "0 records, chain intact" would be a clean
bill of health for a chain nobody looked at. Point `--audit-log` at a chain
written elsewhere — a mirrored copy, an evidence bundle, a colleague's export —
and every verb works on it exactly as it does on the local one.

```
dctl audit verify [flags]
dctl audit head [flags]
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

Take an anchor and keep it somewhere this machine cannot rewrite. This is the
only defence against tail truncation: nothing inside the log attests to its own
length, so an anchor kept outside it is what makes a missing tail detectable.

```
dctl audit head
9:37b656508f9217e841bf0963e2fa72225506687d1f1ecb4b34af60e98a2b35c7
```

One token: the record count, a colon, and the head hash. The count is what lets
the next comparison say *how many* records went missing rather than only that
something did. Wire it into whatever already ran DCTL — the credential the DCTL
host holds for the anchor store should be able to **append and nothing else**:

```
dctl backup /srv/data vault:nightly || exit
printf '%s %s\n' "$(date -u +%FT%TZ)" "$(dctl audit head)" \
  | ssh anchor-host 'cat >> /var/lib/dctl-anchors/prod'
```

Then check the log against the last anchor you took. This is the pair that turns
`intact` from a claim about content into a claim about the whole history:

```
dctl audit verify --expect-head 9:37b656508f9217e841bf0963e2fa72225506687d1f1ecb4b34af60e98a2b35c7
intact
```

### What `intact` covers, and the one thing it never does

`intact` is a single token because a cron job's whole test is
`[ "$(dctl audit verify)" = intact ]`, and a single token cannot say which of
three separate claims it just made. `--json` carries a `proves` list that does:

```
dctl audit verify --json --expect-head "$(cat last-anchor)" | jq -c .proves
["integrity","order","length"]
```

Without `--expect-head` the same log answers `["integrity","order"]` — the links
held and nothing attests to the length. **`authorship` is not in that vocabulary
and never will be for this record version.** The chain is unkeyed, so any process
that can append a line to the log can append a correctly linked one; a verified
chain says the records that are there were not tampered with, not that DCTL wrote
them. `dctl audit verify` says so on stderr on every successful run, and
[`AUDIT_LOG.md` §11](../AUDIT_LOG.md) is the argument for why a key DCTL can
itself read would not close it, plus the operating procedure that limits the
damage — ship the log to an append-only collector as it is written, which fixes
everything that has already arrived without making a forged append detectable.

A consumer should branch on `proves`, not on the reputation of the word
`intact`:

```
dctl audit verify --json --expect-head "$a" \
  | jq -e '.proves | index("length")' >/dev/null \
  || echo "this run did not establish the log's length"
```

Somebody trimmed the log. The chain still verifies — every remaining link holds,
which is exactly why this needed an anchor — and the anchor says how much is
gone:

```
dctl audit verify --expect-head 9:37b656508f9217e841bf0963e2fa72225506687d1f1ecb4b34af60e98a2b35c7
head-mismatch
error: /srv/vaults/prod/audit.jsonl: TRUNCATION: the anchor says this chain held 9
  records; it holds 7. 2 records have been removed from the end. Anchored
  9:37b65650…; the chain verifies and now ends at 7:0b91ee77…
  hint: Records this log once held are not in it now. Do not delete this copy and
  do not re-anchor it: keep it as evidence, compare it against any mirrored or
  offline copy, and treat every operation it no longer accounts for as unattested.
  A chain that verifies is not a chain that is complete.
$ echo $?
26
```

The same command on a log that simply moved on. Nothing was removed, so the
wording and the remedy are different even though the exit code is the same — read
the new records, then take a fresh anchor:

```
dctl audit verify --expect-head 6:4c9d4e83a75f5df8e35de5a83378568e45fc26417fcd1749ca2b2cf7f8e036a8
head-mismatch
error: /srv/vaults/prod/audit.jsonl: the chain does not end at the anchored head —
  it still contains it, after 6 records, and has grown to 9: 3 records were appended
  since the anchor was taken. Nothing was removed; the anchor is stale.
$ echo $?
26
```

See what a chain says happened to one tree over one day. The window is half-open
— inclusive at `--since`, exclusive at `--until` — so two adjacent windows
partition the log instead of sharing a record on the boundary. `--path` compares
whole components, so `photos/2024` does not capture `photos/2024-backup`.

```
dctl audit list --path photos/2024 --since 2026-07-25 --until 2026-07-26
Index  Time                  Op      Result   Dir  Bytes    Hash          Path
-----  --------------------  ------  -------  ---  -------  ------------  -----------
    2  2026-07-25T02:00:11Z  backup  success  in   4.19 GiB  7d3a95ec3f01  photos/2024
```

**Answer the egress question: what came *out* of the vault, and how much.** This
is the query the log exists for, and before record schema v2 it could not be
asked — a read was written exactly like the write that preceded it, with `size:
0`. See [`../AUDIT_LOG.md`](../AUDIT_LOG.md) §2.2.

```
dctl audit list --direction out --since 30d
Index  Time                  Op       Result   Dir  Bytes     Hash          Path
-----  --------------------  -------  -------  ---  --------  ------------  -----------------------
   47  2026-07-11T22:04:03Z  cat      success  out  12.4 KiB  0b91ee7715c2  finance/q4-draft.xlsx
   91  2026-07-19T08:31:55Z  restore  success  out  4.19 GiB  3f0c88ad1d40  photos/2024/holiday.mov
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
  -h, --help                    help for verify
      --audit-log <PATH>        Chain to verify. Defaults to the log beside the configured index
      --expect-head <ANCHOR>    Anchor the chain must end at, as `dctl audit head` printed it
```

`--expect-head` is what makes `verify` a check on the log's **length** as well as
its content. Without it the chain is checked for edits only, and a truncated log
passes — honestly, because every remaining link really does hold.

It takes either spelling of an anchor: the counted `<records>:<hash>` that
`dctl audit head` prints, or a bare `<hash>` (what `verify --json | jq -r .head`
gives). The counted form is strictly better and is the one to keep: with it a
truncation is reported as *"2 records have been removed from the end"*; with a
bare hash the same truncation is refused but cannot be counted, because a hash
carries no length. Anything that is neither is a **usage error** (exit 1) rather
than an anchor that quietly matches nothing.

A mismatch is exit **26** and the stdout verdict `head-mismatch` — never
`intact`. `--json` carries a `head_mismatch.kind` naming which of four things
happened, because they call for different responses:

| `kind` | meaning | what to do |
|--------|---------|------------|
| `advanced` | The anchored head is still in the chain; records were appended after it. **Nothing was removed.** | Read the new records, then re-anchor. |
| `truncated` | The chain is shorter than the anchor says it was. The message carries the exact count. | Incident. Do not re-anchor. |
| `diverged` | The anchored position holds a record that is not the anchored one. | Incident: history was rewritten, or this is a different chain. |
| `absent` | The anchored head is nowhere in the chain, and the anchor carried no count. | Incident, and switch to counted anchors so the loss can be measured. |

`advanced` is a non-zero exit and not an alarm, on purpose. A vault in service
appends records between anchors; reporting that as tampering would fail the check
constantly on a healthy system, and a defence operators switch off is not a
defence.

### dctl audit head

```
  -h, --help               help for head
      --audit-log <PATH>   Chain to read. Defaults to the log beside the configured index
```

Prints one line: the **anchor**, `<records>:<head>`. One shell word, safe to
paste into a ticket and to `diff` in a script. `--json` gives the same value plus
its two parts separately (`records`, `head`, `anchor`), so a pipeline that stores
one of them does not have to split a string.

An empty log anchors at `0:` followed by the genesis link, which is a real anchor
and worth taking: without it, the first operation a vault ever performs is the one
no anchor covers.

**A broken chain produces no anchor at all** — nothing on stdout, exit 24. Unlike
`list` and `export`, there is nothing here an investigator needs to read; there is
only a value somebody would later trust, and an anchor taken from a forgery
attests to the forgery. Run `dctl audit verify` for the diagnosis.

### dctl audit list

```
  -h, --help               help for list
      --audit-log <PATH>   Chain to read. Defaults to the log beside the configured index
      --op <OP>            Show only this operation, using `dctl`'s own command names
      --path <PATH>        Show only records touching this logical path or a path beneath it
      --direction <DIR>    Show only records that moved bytes this way: in, out or internal
      --since <TIME>       Show only records at or after this instant
      --until <TIME>       Show only records before this instant
      --limit <N>          Show at most this many records, most recent last. 0 shows every record [default: 0]
```

`--op` is an **exact** match against `dctl`'s own command names (`copy`, `move`,
`sync`, `delete`, `backup`, `restore`, …) — a prefix match would make `--op copy`
also select `copyto`. `--path` is canonicalised like every other path
(`/`-separated, NFC, no `.` or `..`); a `--path` containing `..` is a usage
error.

`--direction` takes exactly `in`, `out` or `internal`, and anything else is a
**usage error** rather than an empty result. That is deliberate: `--direction
outbound` matching no record, printing nothing and exiting 0 would read as *"no
data ever left this vault"*, which is the worst false statement this command
could make. Records written before record schema v2 carry no direction at all and
never match — a filter that counted them as one direction or another would answer
the egress question with rows that could not have said.

`--since`/`--until` accept `2026-07-26`, `2026-07-26T14:30:00Z`, `2d`
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
`intact`, `broken` or `head-mismatch` (what a shell test compares) while `--json`
and `--format json-lines` emit the whole verdict document with the head hash, the
break position or the head-mismatch kind and counts. For `head`, text is the bare
anchor and `--json` is the anchor plus its parts. For `list`, text is an aligned table showing only a 12-character
hash *prefix* — it is there to tell adjacent rows apart, not to let anyone
believe a row was checked by looking at it — `--json` is one array, and
`--format json-lines` is one record per line. For `export`, text and
`--format json-lines` are the same canonical form; `--json` produces a single
array document instead.

## Exit codes

| Code | Name | When |
|-----:|------|------|
| 0 | `success` | The chain verified, and — if `--expect-head` was given — it ends where the anchor says. |
| 1 | `usage` | No verb given, an unknown flag, an unparseable `--since`/`--until`, a `--direction` outside `in`/`out`/`internal`, a `--path` containing `..`, an `--expect-head` that is neither a 64-hex head hash nor `<records>:<hash>`, or `--interactive` with no terminal to prompt on. An `--expect-head` the flag could not read is refused rather than ignored: ignoring it would verify the chain, print `intact`, exit 0 and compare nothing. |
| 2 | `uncategorised` | An I/O error other than "not found" or "permission denied" while reading the log or writing `--output`, or a serialisation failure while encoding an export. |
| 4 | `file_not_found` | A component of the `--output` path does not exist. |
| 4 | `file_not_found` | **No log file at the resolved path**, including when the path came from an explicit `--audit-log`. The message names the path that was looked for. |
| 7 | `fatal_error` | The log exists but could not be read — permission, or a device error. |
| 24 | `audit_chain_broken` | **The chain failed.** Returned by all four verbs, after their output has been produced — except `head`, which produces none. Also returned when a line in the log is not a parseable record, since that is indistinguishable from tampering. |
| 25 | `cancelled` | An `--interactive` overwrite of `--output` was declined, or Ctrl-C / SIGTERM. |
| 26 | `audit_head_mismatch` | **The chain verified and does not end at `--expect-head`.** Records were removed from the end, history diverged, or the anchor is older than the log. `--json` carries the `kind` and the counts. |

Exit **24** and exit **26** are the two to branch on, and they are separate on
purpose. 24 means the links failed: the log no longer proves what it claims. 26
means the links held and this is not the chain you anchored — which is the only
way tail truncation is ever visible, and which also covers the benign case of an
anchor that is simply older than the log. Folding 26 into 24 would put a routine
"take a fresh anchor" behind the code operators are told to treat as a security
event, and that is how a loud code comes to be ignored. Codes 0–10 mirror
rclone's taxonomy; 20+ are DCTL's own. See
[../EXIT_CODES.md](../EXIT_CODES.md) for the full contract.

## See also

* [dctl verify](dctl_verify.md) — check that the stored *objects* still match
  their recorded hashes, rather than checking the record of what was written.
* [dctl scrub](dctl_scrub.md) — the scheduled, whole-dataset form of that check.
* [dctl backup](dctl_backup.md) — the operation whose records fill this log.
* [dctl restore](dctl_restore.md) — the drill an intact chain is meant to make
  provable after the fact.
* [dctl check](dctl_check.md) — compare two trees against each other.
