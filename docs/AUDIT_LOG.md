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

**The chain alone does not prove length.** Removing entries from the *end*
leaves a chain that verifies perfectly, because nothing inside the log attests to
how many records it should have — and the entries an attacker most wants gone are
the most recent ones. No mechanism inside the file can close that: whoever can
truncate the file can also remove anything the file says about its own length.
The only thing that can is a value recorded where the writer cannot reach it.

That value is the **anchor**, and §10 is the mechanism and the operating
procedure for it: `dctl audit head` prints one, `dctl audit verify --expect-head`
checks one, and a mismatch is exit **26** with the number of missing records when
it is knowable. **Length is proved by §4 and §10 together, never by §4 alone.**

**The chain does not prove authorship at all, and no flag closes that one.** The
hash is unkeyed (§3), so every input to it is a value already in the file: anyone
who can append a line can append a *correctly linked* line. `intact` means the
records that are there were not tampered with. It has never meant that DCTL wrote
them, and this build ships no mechanism that would — §11 is the argument for that
decision, and the operating procedure that bounds what a compromise can rewrite,
which is the strongest thing available and is not the same as authorship.

Both limits are stated at the top rather than buried, because an evidence tool
that overstates what it proves is worse than one that proves less — and an
unanchored `dctl audit verify` that reports `intact` is making the narrowest of
the three claims. `dctl audit verify --json` carries a `proves` field that names
which of them hold, so a consumer never has to infer it from a single word.

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

**A chain that verifies is not a chain that is complete.** The walk above proves
that no record was edited, removed from the middle, reordered or inserted. It
proves nothing about how many records there should be. Whatever this algorithm
concludes, a verifier must report the **head** — the last record's `hash`, or the
genesis link for an empty chain — and the **record count** alongside it, because
those two numbers are the whole of what §10 compares. A verifier that printed
only a verdict would leave its user with no way to detect the one attack the
chain cannot see.

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
anchor 4:37b656508f9217e841bf0963e2fa72225506687d1f1ecb4b34af60e98a2b35c7
```

The second line is the **anchor** of §10, in the same spelling `dctl audit head`
prints and `dctl audit verify --expect-head` accepts. A third-party verifier
emits it for the same reason DCTL does: the first line is a claim about content
and the second is what makes a claim about *length* possible later. An auditor
who runs one of these scripts on an evidence bundle and keeps the anchor can
detect, months afterwards, that the bundle they were given has been shortened.

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
    # Content, then length. The second line is the anchor to keep somewhere the
    # writer cannot reach; nothing inside the log can attest to its own size.
    print(f"intact: {position} records, head {prev}")
    print(f"anchor {position}:{prev}")


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

# Content, then length. The second line is the anchor to keep somewhere the
# writer cannot reach; nothing inside the log can attest to its own size.
echo "intact: $position records, head $prev"
echo "anchor $position:$prev"
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
| `dctl audit verify` | Walks the chain per §4 and names the record where it breaks. With `--expect-head` it also checks the chain's **length** against an anchor, per §10. |
| `dctl audit head` | Prints the anchor of §10 — the value to keep outside the log. |
| `dctl audit list` | Renders the records, with filters. |
| `dctl audit export` | Writes the chain out byte-for-byte re-verifiable. |

All four **walk the whole chain and exit 24 (`audit_chain_broken`) if it is
broken** — a `list` that printed forged rows and exited 0 would put those rows on
screen with an implicit clean bill of health. `head` differs in what it does
*after* noticing: it prints nothing at all, because its output is not evidence to
read but a value somebody will trust later, and an anchor taken from a broken
chain attests to the break.

`dctl audit list --direction out` is the egress query: everything that left the
remote, with the byte count beside it. A v1 record never matches it, because a v1
record could not state a direction — the filter must not answer "what left the
vault?" with rows that could not have said.

An **empty** log verifies and reports `0 records`: "nothing has been appended" is
a real answer. An **absent** one is exit 4 (`file_not_found`), because it far more
often means the reader was pointed somewhere the writer never wrote — a different
`--index`, a different machine — than that nothing ever happened, and "0 records,
chain intact" would be a clean bill of health for a chain nobody looked at.

---

## 10. The anchor: proving length (normative)

§4 proves that no record was **altered**. This section is how a log proves how
many records it should **have**. The two are separate mechanisms because they
have to be: everything §4 checks lives inside the file, and truncation is the one
attack whose evidence an attacker deletes along with the records.

### 10.1 What an anchor is

```
<records>:<head>

9:37b656508f9217e841bf0963e2fa72225506687d1f1ecb4b34af60e98a2b35c7
```

Two values that a verifier already computes (§4): how many records the chain held,
and the hash it ended on. Joined by a colon so the whole thing is **one shell
word**, one line, one token to paste into a ticket and one string for a script to
`diff`.

A **bare `<head>`** is also a conforming anchor, and a reader must accept it. It
is what somebody gets from `dctl audit verify --json | jq -r .head`, and refusing
it would turn a weaker anchor into a usage error. It is weaker in exactly one
way, stated in §10.3.

The genesis link (§2) is the head of an empty chain, so `0:000…0` is the anchor
of a vault that has recorded nothing yet. That is a real anchor and worth taking:
without it, the very first operation a vault performs is the one no anchor covers.

### 10.2 Comparing an anchor against a chain (normative algorithm)

**Walk the chain per §4 first.** An anchor comparison against records whose links
were never checked would report "the log ends where you left it" about a log
forged in the middle, which is a worse answer than either check alone. If §4
fails, report *that* and stop: it is the more specific finding, and it names a
record position an anchor comparison cannot.

Let `n` be the number of records, and define `head_after(k)` as the genesis link
for `k = 0` and the `k`-th record's `hash` otherwise — `None` when `k > n`.

1. If the anchor's head equals `head_after(n)`, **the chain ends where the anchor
   says**. Report a match. The head is the evidence and it decides the verdict; a
   record count that disagreed with a matching head could only be a typo or a
   BLAKE3 collision, and failing an otherwise exact match on it helps nobody.
2. Otherwise, if the anchor carries a count `k`:
   * `head_after(k)` is `None` (`k > n`) → **`truncated`**. Exactly `k - n`
     records have been removed from the end.
   * `head_after(k)` equals the anchor's head → **`advanced`**. The anchored
     history is intact and `n - k` records were appended after it. **Not
     tampering** — see §10.3.
   * otherwise → **`diverged`**. Something else is at the anchored position:
     history at or before the anchor was rewritten, or this is a different chain.
3. Otherwise (a bare head, no count), search for a `k` in `n-1 … 0` with
   `head_after(k)` equal to the anchor's head. Searching downwards because an
   anchor is usually recent.
   * found → **`advanced`**, with `n - k` appended.
   * not found → **`absent`**. Records were removed from the end, or this is a
     different chain, **and which of the two cannot be determined** — a head hash
     carries no length, so there is nothing to subtract. Say so; do not guess.

DCTL reports all four at exit **26** (`audit_head_mismatch`) and the stdout
verdict `head-mismatch`, with the kind and the counts in `--json`. 26 rather than
24 because the two findings are different: 24 says the links failed, 26 says the
links held and this is not the chain you left. Collapsing them would put the
common benign case — `advanced` — behind the code operators are told to treat as
a security event, which is how a loud code comes to be ignored.

### 10.3 Why `advanced` is not an alarm, and why it is not silence either

A log in service grows between anchors. If every append were reported as
tampering the check would be failing constantly on a healthy system, operators
would stop passing the flag, and a defence nobody runs is not a defence.

So `advanced` says what it is: nothing was removed, `n - k` records were appended
that your anchor does not cover, take a fresh one. It is still a **non-zero
exit**, because the caller asserted the chain ended at a particular head and it
does not — and because those uncovered records are worth a glance before they are
anchored. `dctl audit list` shows them.

The bare-head anchor's one weakness lives here too. Against a counted anchor a
truncation is `truncated` with an exact figure; against a bare one the same
truncation is `absent`, which is a refusal and a correct one, but cannot say how
much history is gone. That is why `dctl audit head` prints the counted form.

### 10.4 Where an operator keeps the anchor (operating procedure)

A mechanism nobody knows how to operate is not a defence, so this is written as a
procedure rather than as a flag reference.

**The one rule: the anchor must live somewhere the machine that writes the log
cannot rewrite.** An anchor stored beside `audit.jsonl` — or anywhere the same
account, the same host or the same credential can reach — is truncated in the
same command as the log. That is the whole of the requirement; everything below
is a way of satisfying it.

Three tiers, in increasing order of what they survive:

1. **Append-only to another host.** The DCTL machine holds a credential that can
   only *add* lines somewhere else — a remote syslog collector, an
   append-restricted bucket, an SSH key forced to a `cat >> anchors` command.
   Survives an attacker who takes the DCTL host and nothing else, which is the
   overwhelmingly common case.
2. **Into a system that already ingests security events** — the SIEM, the
   ticketing system, the compliance mailbox. Same protection as tier 1, plus the
   provenance an auditor already trusts, plus somebody else's retention policy.
3. **Published where a third party timestamps it** — a commit in a repository
   hosted elsewhere, a message to an archived list, a transparency log. Survives
   an attacker who takes your whole estate, and lets you prove *when* the anchor
   was taken rather than only what it said.

Tier 1 is the floor. Nothing below tier 1 is an anchor.

**How often.** After every run that writes to the log, or on a fixed schedule.
The interval is the exposure: an attacker who compromises the host can remove any
record written after the last anchor without this check seeing it. Hourly is a
reasonable default for a vault in constant use; per-run is better and is usually
one line in the same script that ran DCTL.

**Taking one** — the append-only tier, in the shape it goes in a backup script:

```sh
dctl backup /srv/data vault:nightly || exit
printf '%s %s\n' "$(date -u +%FT%TZ)" "$(dctl audit head)" \
  | ssh anchor-host 'cat >> /var/lib/dctl-anchors/prod'
```

`dctl audit head` exits 24 without printing anything if the chain is broken, so a
`set -e` script stops before it records an anchor for a forgery.

**Checking one:**

```sh
anchor=$(ssh anchor-host 'tail -n1 /var/lib/dctl-anchors/prod' | awk '{print $NF}')
dctl audit verify --expect-head "$anchor"
```

| Exit | Verdict | What it means | What to do |
|-----:|---------|---------------|------------|
| 0 | `intact` | The chain verifies **and** ends at the anchor. | Nothing. |
| 24 | `broken` | A record was edited, removed from the middle, reordered or inserted. | Keep the file. §4's report names the record. Escalate. |
| 26 | `head-mismatch`, kind `advanced` | The log grew since the anchor. Nothing removed. | Read the new records, then re-anchor. |
| 26 | `head-mismatch`, kind `truncated` | Records were removed from the end, and the message says how many. | **Incident.** Do not re-anchor and do not delete the log. |
| 26 | `head-mismatch`, kind `diverged` | The anchored position holds a different record. | **Incident.** Either history was rewritten, or this is not the log you think. |
| 26 | `head-mismatch`, kind `absent` | The anchored head is nowhere in the chain, and the anchor carried no count. | **Incident.** Use the counted anchor next time so the loss can be measured. |

**On an incident, do not re-anchor.** A fresh anchor taken from a shortened log
makes the shortened log the new baseline and destroys the only evidence that
anything was removed. Keep the file, keep the old anchor, and compare against any
mirrored or offline copy.

**What this still does not prove: authorship.** The chain is unkeyed, so anybody
who can write the file can *append* correctly linked records to it. An anchor
proves that nothing before it was removed or rewritten; it says nothing about who
wrote what came after. §11 is the whole of that question — why this build does not
close it, and what an operator does instead.

### 10.5 Why there is no in-log anchor record

A periodic **anchor record** — a record inside the chain that commits to the head
at some earlier index — is the obvious way to avoid needing external storage. It
is rejected, and the argument is short enough to check.

Such a record at index `k` would attest to `head_after(k)`, which is precisely
`records[k].prev`. **Every record in the chain already commits to its
predecessor's head.** An anchor record therefore adds no information that §4 does
not already have; it is a second copy of a value the chain carries by
construction.

Against truncation it is worse than useless, because it cannot be positioned to
help. A tail truncation removes records from index `n-1` downwards, so any anchor
record that *survives* the truncation is at an index below the cut, and everything
it attests to is still true of the shortened chain. Any anchor record that would
have contradicted the shortened chain is at an index above the cut, and has been
removed along with it. There is no interval, however short, at which this
changes: the attacker chooses where to cut *after* seeing where the anchors are.

The same argument disposes of a record carrying a running count, a length, a
Merkle root over everything before it, or a signature the writer can produce. All
of them are inside the region the attacker controls, and all of them are removed
by the same `head -n -2`.

**The property that actually closes the gap is not "committed" but "out of
reach".** That is why §10.4 is about where a value is kept and not about what is
written into the log. The one variant worth naming as future work is a head hash
pushed into the *encrypted remote* — a different trust domain, a different
credential, and therefore genuinely external — which is a replication feature
rather than a log format change, and is not in this build.

---

## 11. Authorship (normative: out of scope in this build)

**A DCTL audit log does not prove who wrote it, and this build ships no mechanism
that would.** That is a decision with an argument behind it, not an omission, and
this section is the argument. It is stated with the same weight as §1's statement
about length, because a buyer's security review that finds this limit in a
footnote rather than in the specification has found an overclaim.

### 11.1 What is and is not established (normative)

For a chain that verifies under §4:

| claim | established? | by what |
|---|---|---|
| no record was **edited** after it was written | yes | §4, the per-record hash |
| no record was **removed, reordered or inserted** in the interior | yes | §4, the links and the dense index |
| no record was removed from the **end** | only with §10 | an anchor kept out of reach |
| DCTL, rather than some other writer, **produced** these records | **no** | nothing |

`dctl audit verify --json` carries this as a `proves` field — an explicit list of
which of the first three hold for the answer just given — precisely so that a
machine consumer branches on the claims rather than on the reputation of the word
`intact`. **The vocabulary of that field has no token for authorship**, and no
state of the command can put one there. `proves` is on stdout and is not
verbosity-gated, so it is the form of this statement a consumer cannot miss;
`dctl audit verify -v` says the same in prose on stderr, whether or not an anchor
was given.

The reason is in §3: the hash is **unkeyed** BLAKE3 over a canonical string built
from values that are all present in the file. Anyone who can read the log can
compute the next record's `prev`, and anyone who can append a line can append a
correctly linked one. Verification is a public function of public inputs — which
is what makes §8's twenty-line standalone verifiers possible, and is the same
property that makes forgery-by-append available to any writer.

### 11.2 Why a key DCTL can use does not close it

The obvious remedy is to key the chain: a MAC or a signature over each record, or
over the head. It is rejected for this build, and the argument is the one §10.5
already made about anchors, applied to secrets instead of to values.

DCTL appends a record on **every** operation, unattended, in a cron job at 03:00
with nobody present. So whatever key it signs with, it must be able to read
without a human. On the deployment DCTL actually has — a CLI writing
`audit.jsonl` under the operator's own uid — the key file sits on the same host,
under the same uid, as the log. **Every attacker who can write the log can read
the key**, because writing the log already required being that uid on that
machine. A signature under those conditions is not evidence; it is the same
forgery with a certificate attached.

And it is worse than doing nothing, which is the decisive part. An unkeyed chain
makes no claim about authorship, so no auditor is misled by one. A chain signed
with a co-located key makes a claim that is false exactly when it matters, and
converts *"we cannot tell who wrote this"* into *"this is cryptographically
attributed to DCTL"* in the one scenario — host compromise — where the attribution
is wrong. `PLAN.md` §6's rule against reporting work that did not happen applies
to cryptographic claims at least as strongly as to test results.

The same argument disposes of deriving the key from the vault passphrase. It
would also make `dctl audit verify` require the passphrase, turning a cheap
scriptable check into an interactive one, and it would leave every record written
without a vault — plain-storage operations, `config`, `audit` itself (§9.1) —
outside whatever it protected.

### 11.3 What would close it, and its status

Two mechanisms genuinely close authorship. Neither is a log-format change, which
is why the format is not waiting on this.

* **A key the DCTL process can *use* but never *read*** — an `ssh-agent`, a
  PKCS#11 token, a TPM, or a touch-to-sign hardware key. This is the real answer
  to §11.2: the key is out of reach in exactly the sense §10.5 requires, so an
  attacker who takes the host afterwards cannot forge a past record, and with
  touch-to-sign cannot forge a present one either. It is **not in this build**.
  What it needs is a key-management story DCTL does not have today — provisioning,
  rotation, and an answer to *"the token is gone and five years of logs are now
  unverifiable"* — and shipping the signature without that answer would be
  shipping the failure mode rather than the feature.
* **An external append-only witness** — the log, or just its head, delivered as it
  is written to somewhere this machine cannot rewrite. This one **is** available
  now, needs nothing new from DCTL, and is §10.4's procedure: a host that accepts
  appends and not edits, a SIEM, or a third-party timestamp.

  It does **not** close authorship, and it is worth being exact about that
  because it is the easy thing to get wrong here. A witness cannot tell a forged
  append from a genuine one: an attacker who is on the host writes a record into
  `audit.jsonl`, the shipper forwards it like any other, and the collector stores
  it faithfully. What a witness closes is *retroactive* tampering — nothing that
  reached it can afterwards be altered or removed — so it bounds the damage to
  **the window after the compromise** and makes everything before that window
  fixed. That is a great deal less than authorship and a great deal more than
  nothing, and it is the strongest property available today.

### 11.4 What the operator must do instead (operating procedure)

**Nothing here proves authorship either**, and the list is honest about that
rather than presented as a workaround: no arrangement of storage can tell you who
wrote a line. What an operator can do is two different things — make the set of
possible writers small and accountable by other means, and make everything
already written impossible to revise — and between them they turn "somebody could
have forged anything" into "somebody with *this* access could have forged records
after *this* time". In descending order of what they buy:

1. **Ship the log off the host as it is written.** `audit.jsonl` is JSON Lines
   with a stable canonical form, so an ordinary log shipper handles it. A record
   that reached an append-only collector before the host was compromised is a
   record the compromise cannot alter or unsay — so the shorter the shipping
   interval, the smaller the window in which history is still rewritable. It
   subsumes §10.4's anchor procedure and it is the single highest-value control
   on this page. It still does not tell you who wrote a record that arrives
   *after* a compromise; see §11.3.
2. **Keep the log where the DCTL host cannot rewrite history.** A
   remote-append-only mount, an object store with object-lock or versioning, or a
   syslog collector. §10.4's rule that an anchor beside the log is truncated by
   the same command as the log is the same rule applied to the log itself.
3. **Restrict who can be the uid that writes it.** The log is created `0600` and
   re-hardened on every open (§1), so the exposure is exactly the set of
   principals who can become that user, plus root. That set is the honest answer
   to "who could have written this", and it is worth writing down in the runbook
   because it is what an auditor will ask.
4. **Take and store anchors** (§10.4) regardless. They do not prove authorship,
   but they bound how much history a compromise could have removed, which is the
   first question after one.

The threat this leaves open, stated exactly: **an attacker who is already the uid
that writes the log, on the host that writes it, can append records DCTL never
produced, and nothing — not an anchor, not a witness, not any examination of the
file — will show it.** What they cannot do is alter or remove anything already
witnessed elsewhere (§11.4 item 1) or covered by an anchor already taken (§10);
those fix the past, and the exposure is the window since the last one. That is
the boundary, and it is where it will stay until the first mechanism in §11.3
ships.

## See also

- [Documentation index](README.md)
- [`dctl audit` command](commands/dctl_audit.md)
- [Security model](SECURITY.md)
