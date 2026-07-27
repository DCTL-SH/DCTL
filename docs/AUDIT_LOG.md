# DCTL Tamper-Evident Audit Log — Format Specification

**Current record schema: v2.** v1 remains readable, verifiable and normative —
see §2.1.

> **Normative & standalone.** A DCTL audit log must be verifiable from this
> document alone, with **no DCTL binary**, using nothing but a JSON parser and a
> BLAKE3 implementation. That is not a courtesy: a tamper-evidence claim that can
> only be checked by the tool that produced the evidence is not tamper-evidence
> at all. The same twenty-year-decodability discipline governs `docs/FORMAT.md`
> (`PLAN.md` §13.1, §D8).
>
> **Both canonical forms of §3 and both field orders of §2 are FROZEN.**
> Reordering a field, inserting one into an existing schema, or changing the
> separator invalidates every chain ever written. Additive changes go through a
> **new schema version**, never through a redefinition of an existing one — and a
> new version does not invalidate the old, because §2.1's rule makes the version
> a property of each *record* rather than of the file.
>
> Implemented by `crates/dctl-cli/src/audit/`. The worked example in §7 spans the
> v1→v2 boundary and is pinned by a unit test
> (`audit::chain::tests::the_worked_example_in_the_specification_is_the_one_this_code_produces`),
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

Fifteen fields in v2. `index`, `time`, `op`, `result`, `prev` and `hash` are
**required**; the rest default to `""` / `0` when absent, because an operation
with no path (`dctl init`) or no plaintext (`dctl delete`) is an ordinary record
and a reader that refused it could not verify a real log.

| # | Field | JSON type | Since | Meaning |
|---|-------|-----------|-------|---------|
| 1 | `v` | integer | v2 | Record schema version. **Absent means 1.** See §2.1. |
| 2 | `index` | integer | v1 | Position in the chain. Dense and ascending from `0`. |
| 3 | `time` | string | v1 | When the operation completed. RFC 3339, **always UTC**, whole seconds: `2026-07-26T14:30:00Z`. |
| 4 | `op` | string | v1 | The command that ran (`copy`, `move`, `delete`, `restore`, …). |
| 5 | `result` | string | v1 | How it ended: the stable slug from `docs/EXIT_CODES.md` (`success`, `checksum_mismatch`, `partial_failure`, …). |
| 6 | `direction` | string | v2 | Which way object bytes crossed the boundary of `remote`: `in`, `out`, `internal`, or `""` when the operation moved none. See §2.2. |
| 7 | `path` | string | v1 | Logical vault path the operation touched. `/`-separated, NFC-normalised. `""` when none. |
| 8 | `size` | integer | v1 | Plaintext size in bytes of the object the operation **concerned**. `0` when not applicable. Not a claim that the bytes moved. |
| 9 | `bytes` | integer | v2 | Object bytes the operation **actually moved**, measured. `0` on failure and on any operation that moves none. See §2.2. |
| 10 | `objects` | integer | v2 | How many objects this record accounts for. `1` for a per-file record; the whole count for a run-level one. |
| 11 | `plaintext_hash` | string | v1 | BLAKE3-256 of the plaintext, lower-case hex. `""` when there was no plaintext. |
| 12 | `ciphertext_hash` | string | v1 | BLAKE3-256 of the stored ciphertext, lower-case hex. `""` on a plain (unencrypted) remote. |
| 13 | `remote` | string | v1 | The remote the operation was against, scrubbed per §5. |
| 14 | `prev` | string | v1 | The **previous** record's `hash`. The link that makes the log a chain. |
| 15 | `hash` | string | v1 | This record's own hash, computed per §3. |

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

### 2.1 Versioning, and the rule for reading old records (normative)

**The version is a property of the record, not of the file.**

A hash-chained log cannot be rewritten in place. That is the whole point of it:
changing one record's bytes changes its hash, orphans the record after it, and
turns the customer's evidence into a chain that reports itself broken. So a
schema change may not migrate anything. Records written by an older build stay
**byte-for-byte** as that build wrote them, forever.

The rule a reader applies, per record, before hashing anything:

1. If the record has **no `v` field**, it is **version 1**. Hash it with the
   ten-value canonical form of §3.1. This is not a fallback or a guess — v1
   predates the field, so its absence is the v1 spelling.
2. If `v` is an integer the reader knows (currently `1` or `2`), hash it with
   that version's canonical form.
3. If `v` is anything else — a future version, `0`, a non-integer — the reader
   **must not guess a canonical form**. Report the record as *unverifiable by
   this reader*, naming the version, and stop. It is not evidence of tampering:
   a log written by a newer DCTL is perfectly good evidence that this build
   cannot check, and telling an operator their chain is broken when the remedy
   is an upgrade would send them hunting for an intruder.

A single log therefore holds v1 records followed by v2 records, links across the
boundary, and verifies end to end. **This is required behaviour, not a
convenience:** the alternative is a product that invalidates its customers'
evidence at every release.

`v` is inside the v2 preimage (§3.1), which is what stops the version being
switched. Strip `v: 2` from a v2 record and a reader computes the v1 string,
which hashes to something else; add `v: 2` to a v1 record and the same happens in
reverse. Both are reported as a content mismatch, which is what they are.

**Writers must emit `v` for every record they write at version 2 or above, and
must not add `v` to a record written at version 1.**

### 2.2 `direction` and `bytes`: what left, and how much (normative)

These two fields exist because v1 could not answer the question an audit log is
for. In v1, `dctl copy vault:tree /out` — an entire tree of plaintext leaving a
vault onto a local disk — was written as `op: "copy"`, `remote: "vault:tree"`,
`size: 0`, and was **indistinguishable from the upload that put it there**.
Meanwhile `backup`, `restore` and `touch` wrote no record at all.

`direction` is one of exactly four values, and nothing else is conforming:

| Value | Meaning |
|-------|---------|
| `in` | Object bytes entered the remote named by `remote`. |
| `out` | Object bytes left it. **This is the egress question.** |
| `internal` | Bytes moved but never crossed the boundary: both ends are the same remote, or neither end is one (a filesystem-to-filesystem copy). |
| `""` | The operation moved no object bytes at all — a delete, a `touch`, an `init`, an index rebuild. |

`bytes` is a **measurement**, never a plan. The distinction is the reason `size`
survives alongside it:

* `size` describes the object the operation *concerned*. A failed transfer of a
  4 GB file records `size: 4294967296`, which is what makes the failure
  investigable.
* `bytes` describes what *moved*. That same failed transfer records `bytes: 0`,
  because nothing was proven to have landed.

A conforming writer must never copy a planned figure into `bytes`. If it did not
measure, it records `0`.

**`bytes` and `direction` travel together.** A record with `bytes > 0` and
`direction: ""` is malformed, and no conforming writer can produce one — DCTL
enforces this in the type system (`audit::record::Entry::moved` sets both or
neither), because a byte count with no direction is precisely the v1 defect.

`objects` lets a chain be totalled. Per-file records carry `1`; a run-level
record — an `index rebuild` over 4 million rows, a `cleanup` that reclaimed 12
objects — carries the whole count, so summing `objects` across a chain gives the
same answer however the work happened to be divided into records.

---

## 3. The hash computation (normative)

> **Do not hash the JSON.** JSON object key order, whitespace and number
> formatting are free choices, so re-serialising a record could produce different
> bytes from those the writer hashed, and every record would look forged. The
> hash covers an explicit, ordered, separator-joined string, built from the
> record's *values*.

### 3.1 The canonical string

**Choose the form from the record's own version (§2.1) before building it.**

**Version 1** — concatenate exactly **ten** values, in this order, separated by a
single **U+001F** (UNIT SEPARATOR, byte `0x1F`), with no separator before the
first or after the last:

```
prev ␟ index ␟ time ␟ op ␟ result ␟ path ␟ size ␟ plaintext_hash ␟ ciphertext_hash ␟ remote
```

**Version 2** — exactly **fourteen** values. The v1 ten are unchanged and
contiguous; the version goes in front of them and the three new fields behind:

```
v ␟ prev ␟ index ␟ time ␟ op ␟ result ␟ path ␟ size ␟ plaintext_hash ␟ ciphertext_hash ␟ remote ␟ direction ␟ bytes ␟ objects
```

The v1 string is a **contiguous substring** of the v2 string. That is a deliberate
property and worth checking by eye: it makes visible that v2 did not *redefine*
any v1 field, only bracket them — `size` in particular still means exactly what it
always meant.

Rules, for both forms:

1. `prev` comes **first among the record fields**. That is what chains the
   records: changing any earlier record changes its hash, which changes this
   record's `prev`, which changes this record's hash, all the way to the head.
   In v2 only the version precedes it, and the version is fixed for the life of
   the schema, so nothing an operation controls comes before the link.
2. `v`, `index`, `size`, `bytes` and `objects` are rendered as **plain decimal
   ASCII**, no sign, no leading zeros, no separators (`0`, `2`, `1024`,
   `4294967296`).
3. Every other value is its **string content**, UTF-8, *after* JSON unescaping —
   the characters, not the JSON literal.
4. An empty field contributes zero bytes; its separators are still emitted. Two
   adjacent separators therefore mean "empty field", as in §7's second record.
5. The record's own `hash` field is **not** part of the string.
6. A field a record does not carry contributes its default — `""` for a string,
   `0` for an integer — exactly as if it had been written explicitly. A v2 record
   with no `direction` key hashes identically to one with `"direction": ""`.

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
2. **Version support** — the record's version, resolved by §2.1, is one this
   reader implements. *Checked before anything is hashed, because the version
   chooses **which bytes** are hashed. A reader that guessed a canonical form
   would report a perfectly good record as a forgery, which is the one mistake an
   evidence tool must not make. Report it as unverifiable-by-this-reader, not as
   tampering.*
3. **Index continuity** — `index == position`. *A deleted record leaves a gap
   here even if someone re-linked the survivors, and the gap is the more precise
   diagnosis.*
4. **The link** — `prev` equals `previous_hash` (case-insensitively). *Fails when
   a record was removed, reordered, or inserted.*
5. **The content** — `hash` equals the value computed per §3, using **this
   record's** canonical form (case-insensitively). *Fails when a field was edited
   in place.*

Then set `previous_hash = hash` and continue.

A chain whose records are not all the same version is **normal**, not suspicious:
it is what a log looks like after the tool that writes it was upgraded. Nothing in
this algorithm compares one record's version against another's.

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

A four-record log **spanning the schema change**: records 0 and 1 were written by
a v1 build, records 2 and 3 by a v2 build after an upgrade. Nothing about records
0 and 1 changed when the tool did — that is the property §2.1 exists to
guarantee, so it is the property the example demonstrates.

Bytes as they appear in `audit.jsonl` (four lines, each ending `0x0A`; wrapped
here for readability only):

```jsonl
{"index":0,"time":"2026-07-26T14:30:00Z","op":"copy","result":"success","path":"photos/2024/holiday.mov","size":4294967296,"plaintext_hash":"d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24","ciphertext_hash":"c12f1481789d50a4c549e15c42bda1759277bc954d2f4b62c0f4531937f2e990","remote":"vault","prev":"0000000000000000000000000000000000000000000000000000000000000000","hash":"82003870c5344e3adb90c5e5319c2d77ed90605a4cc09d6f4e313558e5fa8597"}
{"index":1,"time":"2026-07-26T14:31:07Z","op":"delete","result":"success","path":"photos/2023/old.mov","size":0,"plaintext_hash":"","ciphertext_hash":"","remote":"vault","prev":"82003870c5344e3adb90c5e5319c2d77ed90605a4cc09d6f4e313558e5fa8597","hash":"de169675b8da96a4892e92a98fd20b952f389d93fcfb0a38d95cf51bf4df1ccd"}
{"v":2,"index":2,"time":"2026-08-01T09:15:00Z","op":"restore","result":"success","direction":"out","path":"photos/2024/holiday.mov","size":4294967296,"bytes":4294967296,"objects":1,"plaintext_hash":"d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24","ciphertext_hash":"","remote":"vault","prev":"de169675b8da96a4892e92a98fd20b952f389d93fcfb0a38d95cf51bf4df1ccd","hash":"4c9d4e83a75f5df8e35de5a83378568e45fc26417fcd1749ca2b2cf7f8e036a8"}
{"v":2,"index":3,"time":"2026-08-01T09:15:04Z","op":"cleanup","result":"success","direction":"","path":"","size":0,"bytes":0,"objects":12,"plaintext_hash":"","ciphertext_hash":"","remote":"vault","prev":"4c9d4e83a75f5df8e35de5a83378568e45fc26417fcd1749ca2b2cf7f8e036a8","hash":"37b656508f9217e841bf0963e2fa72225506687d1f1ecb4b34af60e98a2b35c7"}
```

### Record 0 — version 1 (no `v` field)

Ten values, per §3.1's v1 form. Canonical string (`␟` = one byte, `0x1F`):

```
0000000000000000000000000000000000000000000000000000000000000000␟0␟2026-07-26T14:30:00Z␟copy␟success␟photos/2024/holiday.mov␟4294967296␟d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24␟c12f1481789d50a4c549e15c42bda1759277bc954d2f4b62c0f4531937f2e990␟vault
```

```
BLAKE3-256 → 82003870c5344e3adb90c5e5319c2d77ed90605a4cc09d6f4e313558e5fa8597
```

which is the record's `hash`. Its `prev` is the genesis link, as required of the
first record.

### Record 1 — version 1

A delete: no plaintext, no ciphertext, size `0`. Note the **three consecutive
separators** where `size`'s value `0` is followed by two empty hash fields —
empty fields contribute no bytes but still take their separators.

```
82003870c5344e3adb90c5e5319c2d77ed90605a4cc09d6f4e313558e5fa8597␟1␟2026-07-26T14:31:07Z␟delete␟success␟photos/2023/old.mov␟0␟␟␟vault
```

```
BLAKE3-256 → de169675b8da96a4892e92a98fd20b952f389d93fcfb0a38d95cf51bf4df1ccd
```

### Record 2 — version 2: **4 GB left the vault**

The upgrade happened between records 1 and 2. This record is hashed with the
fourteen-value form, and its `prev` is record 1's `hash` — computed under the
*ten*-value form. The link crosses the version boundary untouched, which is the
whole claim of §2.1.

This is also the record v1 could not write. A `restore` appended nothing at all
under the old schema; here it says `direction: "out"` and `bytes: 4294967296`,
so "who took the holiday footage out of the vault, and when" has an answer.

```
2␟de169675b8da96a4892e92a98fd20b952f389d93fcfb0a38d95cf51bf4df1ccd␟2␟2026-08-01T09:15:00Z␟restore␟success␟photos/2024/holiday.mov␟4294967296␟d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24␟␟vault␟out␟4294967296␟1
```

```
BLAKE3-256 → 4c9d4e83a75f5df8e35de5a83378568e45fc26417fcd1749ca2b2cf7f8e036a8
```

### Record 3 — version 2: a run-level record that moved nothing

A `cleanup` that reclaimed 12 objects. `direction` is empty and `bytes` is `0` —
nothing crossed the boundary, the objects were destroyed where they lay — while
`objects` carries the whole run's count rather than one record per object. Note
the **five consecutive separators** around the empty `path`, `plaintext_hash`,
`ciphertext_hash` and `direction`.

```
2␟4c9d4e83a75f5df8e35de5a83378568e45fc26417fcd1749ca2b2cf7f8e036a8␟3␟2026-08-01T09:15:04Z␟cleanup␟success␟␟0␟␟␟vault␟␟0␟12
```

```
BLAKE3-256 → 37b656508f9217e841bf0963e2fa72225506687d1f1ecb4b34af60e98a2b35c7
```

The **head** of this chain is `37b65650…`.

### Try tampering with it

Change `photos/2023/old.mov` to anything else and record 1's `hash` no longer
matches its content: §4 step 5 fails at position 1. Re-hash record 1 to cover the
edit and record 2 fails at step 4 instead, because its `prev` still names the old
hash. Delete record 0 outright and record 1 fails at step 3, because its `index`
is `1` at position `0`.

The version-specific tampering is worth trying too, because it is the one this
schema introduced:

* **Relabel the egress.** Change record 2's `direction` to `"in"` and its `bytes`
  to `0` — the shape of a cover-up, since it turns a 4 GB extraction into an
  upload of nothing. Step 5 fails at position 2, because both fields are inside
  the v2 preimage.
* **Downgrade the record.** Delete record 2's `"v":2` and a reader now computes
  the *ten*-value string for it, which hashes to something else entirely: step 5
  fails. This is why stripping the version cannot be used to move `direction` and
  `bytes` outside the hash.
* **Upgrade an old record.** Add `"v":2` to record 0 and the same happens in
  reverse.

## 8. Verifying without DCTL

Both scripts implement §4 exactly, **including the per-record version rule of
§2.1**. Run against the four-record example of §7 they print:

```
intact: 4 records, head 37b656508f9217e841bf0963e2fa72225506687d1f1ecb4b34af60e98a2b35c7
```

### 8.1 Python

Requires `pip install blake3`.

```python
#!/usr/bin/env python3
"""Verify a DCTL audit log. Exits 0 if intact, 1 if broken."""
import json, sys
from blake3 import blake3

US = "\x1f"
GENESIS = "0" * 64
SUPPORTED = (1, 2)

# The frozen field order, per schema version (AUDIT_LOG.md section 3.1).
# Version 2 is version 1 with "v" in front and three fields behind; the ten v1
# names are unchanged and contiguous, which is why "size" still means what it
# always meant.
V1 = ("prev", "index", "time", "op", "result",
      "path", "size", "plaintext_hash", "ciphertext_hash", "remote")
FIELDS = {
    1: V1,
    2: ("v",) + V1 + ("direction", "bytes", "objects"),
}
NUMERIC = {"v", "index", "size", "bytes", "objects"}


def version(r):
    # Absent means 1: v1 predates the field, so its absence IS the v1 spelling.
    return r.get("v", 1)


def canonical(r):
    fields = FIELDS[version(r)]
    return US.join(str(r.get(f, 0 if f in NUMERIC else "")) for f in fields)


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
            # Before hashing anything: the version chooses WHICH bytes are
            # hashed, so guessing would report a good record as a forgery.
            if version(r) not in SUPPORTED:
                sys.exit(f"UNVERIFIABLE at record {position} (line {lineno}): "
                         f"schema version {version(r)!r} — this verifier knows "
                         f"{SUPPORTED}. Not proof of tampering; get a newer one.")
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

  # Absent "v" means version 1 (AUDIT_LOG.md section 2.1).
  version=$(printf '%s' "$line" | jq -r '.v // 1')
  case "$version" in
    1|2) ;;
    *) echo "UNVERIFIABLE at record $position: schema version $version"; exit 2 ;;
  esac

  # The canonical fields, in the frozen order for this record's version.
  canon=$(printf '%s' "$line" | jq -j --arg us "$(printf '\037')" --argjson v "$version" '
      [.prev, (.index|tostring), .time, .op, .result,
       (.path // ""), ((.size // 0)|tostring),
       (.plaintext_hash // ""), (.ciphertext_hash // ""), (.remote // "")] as $v1
      | (if $v == 1 then $v1
         else [($v|tostring)] + $v1
              + [(.direction // ""), ((.bytes // 0)|tostring), ((.objects // 0)|tostring)]
         end)
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

---

## 9. Relationship to the DCTL commands

### 9.1 Which commands append

> **A record is appended for every operation that moves object content, in either
> direction, and for every operation that changes what is stored. Nothing else
> appends.**

That rule is wider than the one v1 stated ("every operation that changes stored
data"), and the widening is the point. Under the old rule a *read* was not an
event, so `dctl cat archive:q4.xlsx` — an object decrypted and put on a pipe —
was invisible, and so was every `dctl copy vault:tree /out`. For a product sold on
an audit story, **"who took data out" is the question the log exists to answer**,
and a log that records only writes cannot answer it.

| Family | Commands | `direction` |
|--------|----------|-------------|
| Transfer | `copy`, `move`, `sync`, `copyto`, `moveto`, `put`, `get` | `in`, `out` or `internal`, decided by which end is the remote |
| Archive | `backup` | `in` |
| Archive | `restore` | `out` |
| Content | `cat` (remote objects only) | `out` |
| Content | `rcat` | `in` |
| Replication | `replicate` | `in` |
| Removal | `delete`, `deletefile`, `purge`, `rmdir`, `rmdirs`, `cleanup`, `rm` | `""` — a removal destroys bytes where they lie |
| Vault | `init`, `index rebuild`, `vault recover`, `touch` | `""` — no object content moves |

**Enumeration is not content.** `ls`, `lsd`, `lsl`, `lsjson`, `tree`, `size` and
`about` read names and lengths, never object bodies, and append nothing. A log
that recorded every listing would bury the events that matter under the events
that do not, and the file whose whole value is that somebody will read it end to
end is the file that has to stay short enough to read.

`dctl cat` of a **local** path appends nothing either: no remote was involved,
nothing crossed a boundary, and a record naming an empty remote would put local
shell plumbing in the evidence file.

`--dry-run` appends nothing, for the sharper reason: a rehearsal changed nothing,
so a record for it would describe work that did not happen — and would be
indistinguishable from a real record forever afterwards.

**Known gaps, stated rather than left to be discovered.** Two commands fall under
the rule above and do not yet implement it:

* **`mount`** — a mounted vault serves plaintext to whoever reads the filesystem,
  and none of those reads is recorded. Per-read records are not the answer (a
  128 KiB kernel read is not an event anyone wants a line for); the design is a
  session record plus a first-read record per object. **This is the largest
  remaining hole in the audit story.** A log covering a period in which a vault
  was mounted does not account for what was read through it.
* **`mkdir`** — changes stored data on the one backend that has directories.

`verify`, `scrub`, `hashsum` and `check --checksum` read object bodies back and
emit a verdict or a digest, never content: the bytes reach the tool and go no
further, so nothing left the remote in the sense this log records. Recording the
*run* — "the vault was scrubbed on the 3rd, 4.2 TB read, healthy" — would be a
real improvement and is not done.

This table is enforced mechanically, not by review:
`crates/dctl-cli/src/audit/coverage.rs` holds one row per subcommand, asks `clap`
for the list of subcommands, and fails the build if any of them has no row. A new
verb therefore cannot ship without somebody deciding, in writing, whether it
belongs in this log — which is the decision `backup`, `restore` and `touch` each
silently skipped.

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
* `replicate` records after the destination's verified write returns;
* `backup` records after the core's durable commit, per file;
* `restore` and `cat` record after the bytes have left, per object. There is no
  earlier position: until the read completes, nothing has been taken.

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
| Removal, `init`, `index rebuild`, `touch` | empty — nothing is read | empty |
| `backup`, `restore`, `cat`, `rcat` | empty — the bytes are streamed and never held whole | empty |

These gaps are honest limitations rather than choices. `dctl-core`'s
`Vault::put_file` does not return the digest of the object it stored, so a
transfer has no ciphertext hash to record. `rcat` streams its input to its
destination without ever holding it whole — which is what lets it take a database
dump larger than memory — so there is nothing to hash without giving that up, and
`backup`, `restore` and `cat` stream for the same reason and pay the same price.
Every field becomes populated when the underlying API supplies it; none is filled
with a plausible-looking value in the meantime.

For those four verbs the record still carries `bytes`, which is a measurement of
the same stream, so "how much left the vault" is answerable even where "what
exactly" is not.

### 9.4 Which commands read

| Command | What it does with this format |
|---------|-------------------------------|
| `dctl audit verify` | Walks the chain per §4 and names the record where it breaks. |
| `dctl audit list` | Renders the records, with filters. |
| `dctl audit export` | Writes the chain out byte-for-byte re-verifiable. |

All three **walk the whole chain and exit 24 (`audit_chain_broken`) if it is
broken** — a `list` that printed forged rows and exited 0 would put those rows on
screen with an implicit clean bill of health.

`dctl audit list --direction out` is the egress query: everything that left the
remote, with the byte count beside it. A v1 record never matches it, because a v1
record could not state a direction — the filter must not answer "what left the
vault?" with rows that could not have said.

An **empty** log verifies and reports `0 records`: "nothing has been appended" is
a real answer. An **absent** one is exit 4 (`file_not_found`), because it far more
often means the reader was pointed somewhere the writer never wrote — a different
`--index`, a different machine — than that nothing ever happened, and "0 records,
chain intact" would be a clean bill of health for a chain nobody looked at.

## See also

- [Documentation index](README.md)
- [`dctl audit` command](commands/dctl_audit.md)
- [Security model](SECURITY.md)
