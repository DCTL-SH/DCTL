# DCTL Tamper-Evident Audit Log — Format Specification v1

> **Normative & standalone.** A DCTL audit log must be verifiable from this
> document alone, with **no DCTL binary**, using nothing but a JSON parser and a
> BLAKE3 implementation. That is not a courtesy: a tamper-evidence claim that can
> only be checked by the tool that produced the evidence is not tamper-evidence
> at all. The same twenty-year-decodability discipline governs `docs/FORMAT.md`
> (`PLAN.md` §13.1, §D8).
>
> **The canonical form of §3 and the field order of §2 are FROZEN.** Reordering a
> field, inserting one, or changing the separator invalidates every chain ever
> written. Additive changes must go through a new file name or a new format
> version, never through a redefinition of v1.
>
> Implemented by `crates/dctl-cli/src/audit/`. The worked example in §7 is pinned
> by a unit test (`audit::chain::tests::the_worked_example_in_the_specification_is_the_one_this_code_produces`),
> so the document and the code cannot drift apart silently.

---

## 1. What the log is, and what it proves

An append-only, **hash-chained** record of every operation DCTL performs
(`PLAN.md` §7, a day-1 non-negotiable). Each entry carries the hash of the
previous entry, so the sequence can be **extended but not rewritten**:

* editing an entry changes its hash and orphans the entry after it;
* deleting an entry leaves a gap in the dense index sequence;
* reordering entries breaks both.

**What it does not prove: length.** Removing entries from the *end* leaves a
chain that verifies perfectly, because nothing inside the log attests to how many
records it should have. Detecting that requires an anchor kept somewhere the
writer cannot reach — an encrypted remote mirror, a periodically published head
hash, a witness signature. This is stated here rather than buried, because an
evidence tool that overstates what it proves is worse than one that proves less.

### File layout

* **Encoding:** [JSON Lines](https://jsonlines.org/) — one JSON object per line,
  UTF-8, terminated by a single `0x0A` byte (`\n`).
* **Default name:** `audit.jsonl`, beside the encrypted index (so two vaults on
  one machine keep two independent chains), or in the platform data directory if
  no index was named.
* **Permissions:** created `0600` on Unix, and re-hardened to `0600` on every
  open so a log created by a laxer tool cannot stay world-readable. A directory
  DCTL creates for it is created `0700`; a pre-existing directory the operator
  chose is left alone. The log holds no keys, but a complete inventory of which
  paths were touched and when is exactly the metadata a vault exists to keep
  private.
* **Blank lines** carry no meaning and are skipped by readers.
* **Order is evidence:** a record's position in the chain is its position in the
  file, never a value the file supplied. A forged `index` field cannot move it.

---

## 2. The record

Eleven fields. `index`, `time`, `op`, `result`, `prev` and `hash` are **required**;
the remaining five default to `""` / `0` when absent, because an operation with
no path (`dctl init`) or no plaintext (`dctl delete`) is an ordinary record and a
reader that refused it could not verify a real log.

| # | Field | JSON type | Meaning |
|---|-------|-----------|---------|
| 1 | `index` | integer | Position in the chain. Dense and ascending from `0`. |
| 2 | `time` | string | When the operation completed. RFC 3339, **always UTC**, whole seconds: `2026-07-26T14:30:00Z`. |
| 3 | `op` | string | The command that ran (`copy`, `move`, `delete`, `verify`, …). |
| 4 | `result` | string | How it ended: the stable slug from `docs/EXIT_CODES.md` (`success`, `checksum_mismatch`, `partial_failure`, …). |
| 5 | `path` | string | Logical vault path the operation touched. `/`-separated, NFC-normalised. `""` when none. |
| 6 | `size` | integer | Plaintext size in bytes. `0` when not applicable. |
| 7 | `plaintext_hash` | string | BLAKE3-256 of the plaintext, lower-case hex. `""` when there was no plaintext. |
| 8 | `ciphertext_hash` | string | BLAKE3-256 of the stored ciphertext, lower-case hex. `""` on a plain (unencrypted) remote. |
| 9 | `remote` | string | The remote the operation was against, scrubbed per §5. |
| 10 | `prev` | string | The **previous** record's `hash`. The link that makes the log a chain. |
| 11 | `hash` | string | This record's own hash, computed per §3. |

`prev` and `hash` are always **64 lower-case hex characters** (BLAKE3-256). A
reader must check the *width* as well as the alphabet: comparing a truncated hash
could accidentally succeed on a prefix, which is precisely the forgery the chain
exists to prevent.

The first record in a chain carries the **genesis link**: `prev` = sixty-four
`0` characters. All zeros rather than an absent field, because a record that
merely *lacks* a predecessor is indistinguishable from one whose predecessor was
deleted — and detecting exactly that deletion is the point.

DCTL writes fields in the order of the table above and writes hex in lower case.
Neither is required of a conforming writer: readers match fields **by name** and
compare hashes **case-insensitively**.

---

## 3. The hash computation (normative)

> **Do not hash the JSON.** JSON object key order, whitespace and number
> formatting are free choices, so re-serialising a record could produce different
> bytes from those the writer hashed, and every record would look forged. The
> hash covers an explicit, ordered, separator-joined string, built from the
> record's *values*.

### 3.1 The canonical string

Concatenate exactly **ten** values, in this order, separated by a single
**U+001F** (UNIT SEPARATOR, byte `0x1F`), with no separator before the first or
after the last:

```
prev ␟ index ␟ time ␟ op ␟ result ␟ path ␟ size ␟ plaintext_hash ␟ ciphertext_hash ␟ remote
```

Rules:

1. `prev` comes **first**. That is what chains the records: changing any earlier
   record changes its hash, which changes this record's `prev`, which changes
   this record's hash, all the way to the head.
2. `index` and `size` are rendered as **plain decimal ASCII**, no sign, no
   leading zeros, no separators (`0`, `1024`, `4294967296`).
3. Every other value is its **string content**, UTF-8, *after* JSON unescaping —
   the characters, not the JSON literal.
4. An empty field contributes zero bytes; its separators are still emitted. Two
   adjacent separators therefore mean "empty field", as in §7's second record.
5. The record's own `hash` field is **not** part of the string.

### 3.2 The hash

```
hash = lowercase_hex( BLAKE3-256( UTF-8 bytes of the canonical string ) )
```

Unkeyed BLAKE3, 32-byte output, rendered as 64 lower-case hex characters.

### 3.3 Why U+001F, and why it can never appear inside a field

The separator is the anti-forgery property. If a field could contain the
separator, a record with `path = "a"` and `op = "b"` would hash identically to
one with `path = "a␟b"` and an empty `op` — and an attacker who can choose a
filename could rewrite history without breaking the chain.

U+001F cannot legally occur inside a field. DCTL enforces this twice, on purpose,
so that neither defence depends on the other being correct:

* control characters are rejected in paths at the naming layer, and
* **every** field passes through a scrub before it enters a record, which
  replaces each control character `U+XXXX` with the six ASCII characters
  `\uxxxx` (backslash, `u`, four lower-case hex digits). Escaped rather than
  dropped, because dropping would make two different paths record identically.

A third-party verifier does not have to implement the escape — it hashes what is
in the file. It should, however, **reject** any record whose canonical string
contains a raw `0x1F` byte, since no conforming writer can produce one.

---

## 4. Verifying a chain (normative algorithm)

Read the file top to bottom, skipping blank lines. Track `previous_hash`,
initialised to the genesis link (sixty-four `0`s). For each record, at
zero-based `position` (file line `position + 1`), check in **this order**:

1. **Well-formedness** — `prev` and `hash` are each exactly 64 hex characters.
   *Checked first, so a truncated hash is reported as malformed rather than
   silently comparing equal to a prefix.*
2. **Index continuity** — `index == position`. *A deleted record leaves a gap
   here even if someone re-linked the survivors, and the gap is the more precise
   diagnosis.*
3. **The link** — `prev` equals `previous_hash` (case-insensitively). *Fails when
   a record was removed, reordered, or inserted.*
4. **The content** — `hash` equals the value computed per §3 (case-insensitively).
   *Fails when a field was edited in place.*

Then set `previous_hash = hash` and continue.

**Stop at the first failure and report its position.** Everything after a break
is unattested: once one link is wrong, the records beyond it prove nothing about
themselves, and listing them as "also broken" buries the one position that
matters. "The audit log is corrupt" is not an answer anybody can investigate;
"record 4991 links to a hash no record produces" is.

Checking the link **before** the content is deliberate. A re-hashed forgery shows
up as a link break at the *following* record, so reporting "record 42's content
was edited" when the truth is "record 41 was deleted" would send an investigator
to the wrong place.

An **empty** log verifies, with the genesis link as its head. That is the claim
"nothing has been appended", which is not the same claim as "nothing happened" —
see §1.

The **head** — the last record's `hash` — is the value to compare against any
anchor kept outside the log. It is the only way to detect truncation.

A line that will not parse as JSON is a **chain failure**, not a formatting
inconvenience: it is indistinguishable from a line somebody edited badly, and
both must be reported the same way, loudly, with the line number.

---

## 5. Redaction (normative)

**No key, password or token may ever appear in the log.** `PLAN.md` §7 makes this
mandatory, and the audit log is the most exposed thing DCTL writes — its whole
purpose is to be handed to an auditor, an insurer or a client. There is no
"redact it later" for an append-only file.

Secrets appear **only as BLAKE3 fingerprints**, spelled `blake3:` followed by
exactly **eight** lower-case hex characters (32 bits — ample to tell two
credentials apart across a million records, far too little to help whoever
obtains the log).

Two scrubs are applied before a value can enter a record:

* **Every field** — control characters escaped as described in §3.3.
* **`remote`** — if it is a URL:
  * **userinfo** (`scheme://USER:SECRET@host/…`) is replaced *in full* by
    `blake3:xxxxxxxx` of the userinfo bytes. A fingerprint rather than a fixed
    placeholder, so two records made with the same credential still correlate —
    which is the question an investigator actually asks — while neither half is
    recoverable.
  * **credential-bearing query parameters** (`X-Amz-Signature`, `token`,
    `Authorization`, …) have their values replaced with `<redacted>`. A
    pre-signed URL carries a working credential with a real time window; logging
    one raw would put it in a permanent record.

A configured remote name (`vault`, `b2prod`) contains no credential and passes
through unchanged.

The escapes and fingerprints are applied *before* the hash is computed, so what
is hashed is exactly what is on disk. A verifier never needs to reverse them.

---

## 6. Durability and crash behaviour (normative)

**A record counts if and only if its `0x0A` terminator is on the medium.** That
single rule is what makes an append atomic in the only sense that matters.

* The writer opens the file `O_APPEND`, writes the whole line (record +
  terminator) as a single append, and **`fsync`s before returning**. An operation is
  reported successful only after that returns: an audit record that did not
  survive a power cut did not happen (`PLAN.md` §6). A newly created log also has
  its **directory entry** fsynced, since bytes are useless if the name pointing
  at them did not survive the same power cut.
* A crash mid-append leaves bytes **after** the last terminator. Those bytes are
  unambiguously *not a record* — never "a record that might be short" — and the
  chain before them is untouched and still verifies. The in-flight operation is
  the only thing lost, and it was never reported as successful.
* On opening a log, the writer discards such a fragment (truncating to the last
  terminator) and logs a warning naming the byte offset and length. **This is the
  only operation in DCTL that shortens the log, and it can only ever remove bytes
  that follow the last complete record** — bytes no operation was ever told had
  landed.
* Before appending, the writer re-reads the head if the file's length has moved
  since it last looked, so a record written by another process is not overwritten
  by a stale link. Simultaneous writers can still fork the chain; the design
  answer is one writer per vault (the index lock of `PLAN.md` §6), and the
  guarantee here is that a fork is **detectable** — the two records share an
  index, and §4 step 2 names the position.

A third-party verifier should treat a trailing unterminated fragment the same
way: verify everything before it, and report it as an interrupted append rather
than as tampering.

---

## 7. Worked example

A two-record log. Bytes as they appear in `audit.jsonl` (two lines, each ending
`0x0A`; wrapped here for readability only):

```jsonl
{"index":0,"time":"2026-07-26T14:30:00Z","op":"copy","result":"success","path":"photos/2024/holiday.mov","size":4294967296,"plaintext_hash":"d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24","ciphertext_hash":"c12f1481789d50a4c549e15c42bda1759277bc954d2f4b62c0f4531937f2e990","remote":"vault","prev":"0000000000000000000000000000000000000000000000000000000000000000","hash":"82003870c5344e3adb90c5e5319c2d77ed90605a4cc09d6f4e313558e5fa8597"}
{"index":1,"time":"2026-07-26T14:31:07Z","op":"delete","result":"success","path":"photos/2023/old.mov","size":0,"plaintext_hash":"","ciphertext_hash":"","remote":"vault","prev":"82003870c5344e3adb90c5e5319c2d77ed90605a4cc09d6f4e313558e5fa8597","hash":"de169675b8da96a4892e92a98fd20b952f389d93fcfb0a38d95cf51bf4df1ccd"}
```

### Record 0

Canonical string (`␟` = one byte, `0x1F`):

```
0000000000000000000000000000000000000000000000000000000000000000␟0␟2026-07-26T14:30:00Z␟copy␟success␟photos/2024/holiday.mov␟4294967296␟d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24␟c12f1481789d50a4c549e15c42bda1759277bc954d2f4b62c0f4531937f2e990␟vault
```

```
BLAKE3-256 → 82003870c5344e3adb90c5e5319c2d77ed90605a4cc09d6f4e313558e5fa8597
```

which is the record's `hash`. Its `prev` is the genesis link, as required of the
first record.

### Record 1

A delete: no plaintext, no ciphertext, size `0`. Note the **three consecutive
separators** where `size`'s value `0` is followed by two empty hash fields —
empty fields contribute no bytes but still take their separators.

```
82003870c5344e3adb90c5e5319c2d77ed90605a4cc09d6f4e313558e5fa8597␟1␟2026-07-26T14:31:07Z␟delete␟success␟photos/2023/old.mov␟0␟␟␟vault
```

```
BLAKE3-256 → de169675b8da96a4892e92a98fd20b952f389d93fcfb0a38d95cf51bf4df1ccd
```

Its `prev` is record 0's `hash`, so the two are linked. The **head** of this
chain is `de169675…`.

### Try tampering with it

Change `photos/2023/old.mov` to anything else and record 1's `hash` no longer
matches its content: §4 step 4 fails at position 1. Re-hash record 1 to cover the
edit and record 2 — had there been one — would fail at step 3 instead, because
its `prev` still names the old hash. Delete record 0 outright and record 1 fails
at step 2, because its `index` is `1` at position `0`.

---

## 8. Verifying without DCTL

### 8.1 Python

Requires `pip install blake3`.

```python
#!/usr/bin/env python3
"""Verify a DCTL audit log. Exits 0 if intact, 1 if broken."""
import json, sys
from blake3 import blake3

US = "\x1f"
GENESIS = "0" * 64
FIELDS = ("prev", "index", "time", "op", "result",
          "path", "size", "plaintext_hash", "ciphertext_hash", "remote")


def canonical(r):
    # index and size are plain decimal; everything else is the string content.
    return US.join(str(r.get(f, 0 if f in ("index", "size") else "")) for f in FIELDS)


def is_hash(v):
    return isinstance(v, str) and len(v) == 64 and all(c in "0123456789abcdefABCDEF" for c in v)


def main(path):
    prev = GENESIS
    position = 0
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            if not line.strip():
                continue
            if not line.endswith("\n"):
                print(f"line {lineno}: unterminated trailing fragment "
                      f"(interrupted append); {position} records verified")
                break
            r = json.loads(line)
            for field in ("prev", "hash"):
                if not is_hash(r.get(field)):
                    sys.exit(f"BROKEN at record {position} (line {lineno}): "
                             f"'{field}' is not a chain hash")
            if r["index"] != position:
                sys.exit(f"BROKEN at record {position} (line {lineno}): "
                         f"index is {r['index']} — a record was removed or reordered")
            if r["prev"].lower() != prev.lower():
                sys.exit(f"BROKEN at record {position} (line {lineno}): "
                         f"links to {r['prev']}, expected {prev}")
            computed = blake3(canonical(r).encode("utf-8")).hexdigest()
            if r["hash"].lower() != computed.lower():
                sys.exit(f"BROKEN at record {position} (line {lineno}): "
                         f"content hashes to {computed}, record carries {r['hash']}")
            prev = r["hash"]
            position += 1
    print(f"intact: {position} records, head {prev}")


if __name__ == "__main__":
    main(sys.argv[1])
```

### 8.2 Shell

Requires `jq` and `b3sum`. Slower, but depends only on tools that are packaged
everywhere — which is the point of the exercise.

```sh
#!/bin/sh
# Verify a DCTL audit log with jq and b3sum.
set -eu
prev=0000000000000000000000000000000000000000000000000000000000000000
position=0

while IFS= read -r line; do
  [ -n "$line" ] || continue

  # The ten canonical fields, in order, separated by U+001F.
  canon=$(printf '%s' "$line" | jq -j --arg us "$(printf '\037')" '
      [.prev, (.index|tostring), .time, .op, .result,
       (.path // ""), ((.size // 0)|tostring),
       (.plaintext_hash // ""), (.ciphertext_hash // ""), (.remote // "")]
      | join($us)')

  computed=$(printf '%s' "$canon" | b3sum --no-names)
  claimed=$(printf '%s' "$line" | jq -r '.hash')
  linked=$(printf '%s' "$line" | jq -r '.prev')
  index=$(printf '%s' "$line" | jq -r '.index')

  [ "$index" = "$position" ] || { echo "BROKEN at record $position: index $index"; exit 1; }
  [ "$linked" = "$prev" ]    || { echo "BROKEN at record $position: bad link";      exit 1; }
  [ "$computed" = "$claimed" ] || { echo "BROKEN at record $position: bad hash";    exit 1; }

  prev=$claimed
  position=$((position + 1))
done < "$1"

echo "intact: $position records, head $prev"
```

Both scripts implement §4 exactly. Against the §7 example they print:

```
intact: 2 records, head de169675b8da96a4892e92a98fd20b952f389d93fcfb0a38d95cf51bf4df1ccd
```

---

## 9. Relationship to the DCTL commands

### 9.1 Which commands append

**Every operation that changes stored data, and no operation that does not.**

| Family | Commands | `op` values |
|--------|----------|-------------|
| Transfer | `copy`, `move`, `sync`, `copyto`, `moveto` | `copy`, `move`, `sync`, `copyto`, `moveto` |
| Removal | `delete`, `deletefile`, `purge`, `rmdir`, `rmdirs`, `cleanup` | the same six words |
| Content | `rcat` | `rcat` |
| Replication | `replicate` | `replicate` |
| Vault | `init`, `index rebuild` | `init`, `index rebuild` |

Reads — `ls`, `lsd`, `lsl`, `lsjson`, `tree`, `size`, `cat`, `verify`, `check`,
`scrub`, `hashsum`, `about` — append **nothing**. That is not an oversight. A log
that recorded every listing would bury the events that matter under the events
that do not, and the file whose value is that somebody will read it end to end is
the file that must stay short enough to read.

`--dry-run` appends nothing either, for the sharper reason: a rehearsal changed
nothing, so a record for it would describe work that did not happen — and would
be indistinguishable from a real record forever afterwards.

### 9.2 When the record is appended

**After the durable commit, never before** (`PLAN.md` §6 step 8), and the fsync
of §6 completes before the command reports success. One record per file, per
object, or per vault-wide operation:

* a transfer records after the index commit; a **`move` records after the source
  removal**, because until the source is gone the move has not happened;
* a removal records after the store confirms — for a vault, after the index row
  is committed away;
* `init` records immediately after the envelope write, which is the irreversible
  step, so a vault's chain begins with an `init` at index `0`;
* `replicate` records after the destination's verified write returns.

**Failures are recorded too**, carrying the command's own classified slug from
`docs/EXIT_CODES.md` — `checksum_mismatch`, `file_not_found`, `temporary_error`.
A log that contained only successes could not answer "what went wrong on the
3rd?", which is most of why anybody reads one.

The boundary is **an attempt on the store**, and it is worth stating exactly. A
file that was read, sealed and refused by the destination is recorded, with the
refusal. A command that was rejected *before* it reached the store — a malformed
`REMOTE:PATH`, a remote no configuration defines, a vault that would not unlock,
a `deletefile` naming a path the vault does not hold — records nothing, because
it attempted nothing and changed nothing. Its failure is in the structured log
and in the exit code, which is where a mistyped command belongs; putting it here
would fill the evidence file with typing.

**If the record cannot be written, the command fails.** Exit 24
(`audit_chain_broken`) when the file on disk is not a chain that may be extended,
and exit 7 (`fatal_error`) for any other failure to write — the disk is full, the
directory is not writable. Deliberately *not* the underlying I/O classification:
a `NotFound` on the log's own directory surfacing as exit 4 would tell a script
something false about the user's data. Proceeding without the trail the operator
configured is the misreporting `PLAN.md` §7 forbids, so the run stops instead.

### 9.3 Which hash fields are populated, and which are not

Stated plainly, because an empty field must not be mistaken for a claim:

| Family | `plaintext_hash` | `ciphertext_hash` |
|--------|------------------|-------------------|
| Transfer | **yes** — BLAKE3 of the plaintext, computed while the bytes were in hand | empty |
| Replication | empty — `replicate` holds no key and no plaintext exists in it | **yes** — the digest the destination's verified write was given |
| Removal, `init`, `index rebuild` | empty — nothing is read | empty |
| `rcat` | empty | empty |

The two gaps are honest limitations rather than choices. `dctl-core`'s
`Vault::put_file` does not return the digest of the object it stored, so a
transfer has no ciphertext hash to record; and `rcat` streams its input to its
destination without ever holding it whole — which is what lets it take a database
dump larger than memory — so there is nothing to hash without giving that up.
Both fields become populated when the underlying API supplies them; neither is
filled with a plausible-looking value in the meantime.

### 9.4 Which commands read

| Command | What it does with this format |
|---------|-------------------------------|
| `dctl audit verify` | Walks the chain per §4 and names the record where it breaks. |
| `dctl audit list` | Renders the records, with filters. |
| `dctl audit export` | Writes the chain out byte-for-byte re-verifiable. |

All three **walk the whole chain and exit 24 (`audit_chain_broken`) if it is
broken** — a `list` that printed forged rows and exited 0 would put those rows on
screen with an implicit clean bill of health.

An **empty** log verifies and reports `0 records`: "nothing has been appended" is
a real answer. An **absent** one is exit 4 (`file_not_found`), because it far more
often means the reader was pointed somewhere the writer never wrote — a different
`--index`, a different machine — than that nothing ever happened, and "0 records,
chain intact" would be a clean bill of health for a chain nobody looked at.

## See also

- [Documentation index](README.md)
- [`dctl audit` command](commands/dctl_audit.md)
- [Security model](SECURITY.md)
