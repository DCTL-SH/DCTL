# The restore drill

> **A backup you never restored isn't a backup.** — [`PLAN.md`](../PLAN.md) §13.6

Every other guarantee DCTL makes is instrumental. The encryption, the chunking,
the index, the audit log and the provider backends exist so that one command, run
on the worst day, gives the data back. This document is the exercise that decides
whether that is true, and the record of the last time it was run.

It is written for two readers. An **operator** rehearsing before they need it
should follow [The procedure](#the-procedure) and read what each step proves. An
**auditor** should read [What each failure would mean](#what-each-failure-would-mean),
[Results](#results) and [What the drill does not prove](#what-the-drill-does-not-prove) —
in that order, and the last one first if time is short.

---

## The drill is a test, not a ritual

The whole procedure runs unattended, against the shipped binary:

```sh
cargo test -p dctl-cli --test restore_drill
```

The source is [`crates/dctl-cli/tests/restore_drill/`](../crates/dctl-cli/tests/restore_drill/),
one module per concern, and it is the authority: this document describes what
that code does, and if the two ever disagree the code is what ran.

Two things about it are deliberate.

**It drives the binary, never the library.** A drill asserted against
`Vault::get_file` would prove the cryptography works and nothing about whether
the *command a person types on recovery day* is wired to it. That gap is exactly
where this drill found its first defect: every layer worked and the sequence did
not.

**A run that did not happen is never reported as a pass.** The B2 drill is
`#[ignore]`d, so it shows as *ignored* rather than *passed*; asked for explicitly
without credentials, it **fails**, naming the variables that are missing. A
suite that reported a green provider drill on a machine with no keys would be a
lie one layer below the one this exercise exists to catch.

---

## The dataset

A drill over three text files proves that bytes survive a round trip. It does not
prove a *restore* works, because a restore does not fail on bytes — it fails on
names. Every entry below is there to make one specific failure possible.

| Entry | What its absence would hide |
|---|---|
| `media/large.bin` — 12 MiB | a file below one 1 MiB chunk never exercises multi-chunk streaming, the object footer, or the streaming content hash |
| `empty.txt` — 0 bytes | zero-length objects are the classic special case a length check divides by |
| `a name with spaces.txt` | quoting and argument handling, in the plan and on the way back |
| `reports/quarterly summaries/q1 2024.txt` | the same, one level up, where a path is *joined* rather than passed |
| `notes/café.txt` (NFC) | the ordinary spelling on Linux and Windows |
| `notes/naïve.txt` (NFD) | the ordinary spelling on macOS — and the one that comes back respelled |
| `média/photo.txt` (NFD **directory**) | normalisation applies per component, not only to the leaf |
| `notes/Ωmega.txt` | a name outside anything a Latin-1 assumption would survive |
| `archive/2024/q1/reports/regional/north/summary/final notes.txt` | eight levels of nesting a restore has to recreate before it can write |
| `README.md` | a marker string searched for across every stored object |

Ten files, 12 583 158 bytes, deterministic contents — a failure has to be
reproducible, and a random fixture turns *"the restore corrupted byte 7 340 032"*
into an unrepeatable anecdote.

The unicode names are two spellings of **different words**, not two spellings of
one. That distinction is the difference between testing a behaviour and testing a
collision: two spellings of the same word are two files on Linux and one file on
macOS, so a dataset built that way would be a different dataset on each platform
and the manifest would stop being comparable. The collision is a real case and it
has [its own section](#the-sharp-edge-two-files-one-path).

---

## The procedure

Run by hand, this is the whole thing. `$SRC` is the tree being protected; `$OUT`
is an empty directory that does not matter.

```sh
# 1. Record the manifest, before anything is stored.
find "$SRC" -type f -printf '%s %p\n' | sort > manifest.sizes
find "$SRC" -type f -exec b3sum {} + | sort > manifest.hashes

# 2. Create the vault. WRITE THE 24 WORDS DOWN. They are shown once.
dctl init --name drill --base b2:MY-BUCKET 2> phrase.txt
dctl backup "$SRC" drill:

# 3. Destroy the local index. The machine is gone; only the store remains.
rm -rf ~/.dctl/index

# 4. Rebuild it from the backend — the password is not used from here on.
export DCTL_RECOVERY_PHRASE="$(…the words from paper…)"
dctl index rebuild drill:

# 5. Restore, on the phrase alone.
dctl restore drill: "$OUT"

# 6. Diff against the manifest.
find "$OUT" -type f -printf '%s %p\n' | sort   # compare with manifest.sizes
find "$OUT" -type f -exec b3sum {} + | sort    # compare with manifest.hashes
```

Two deviations from the letter of §13.6, both deliberate and both stricter:

* **The recovery phrase is used for step 4 as well as step 5.** Somebody who has
  lost the machine has usually lost what was stored on it, password included.
* **The index directory is deleted, not the file.** A machine that is gone did
  not leave the folder behind. This is what caught
  [defect 1](#1-the-recovery-command-could-not-run-on-a-recovered-machine).

### What each step proves

| Step | What it proves |
|---|---|
| **1 — manifest** | That the comparison at the end is against what went *in*. A manifest taken afterwards would be verifying a backup by reading the backup. |
| **2 — phrase** | That the second key exists, is 24 BIP-39 words, and is **transcribable**: the test parses the numbered grid a human reads, so a block that stopped being readable fails here rather than on recovery day. |
| **3 — destroy** | That the disaster actually happened. The store is counted before and after; if the count moved, the disaster was not local and the drill is testing something else. |
| **4 — rebuild** | `PLAN.md` §13.5: *a lost index never means lost data*. The rebuild reads the encrypted `n/*` name records and then each object's own header, and it must recover exactly as many rows as there were files — with their sizes, times and hashes. |
| **5 — restore** | That the recovery phrase alone — no password anywhere in the environment — reaches every command a recovery needs, not just a `vault recover` verb that reports success. |
| **6 — diff** | The only claim that matters: every path, every size, every BLAKE3. |

The automated drill adds two assertions a by-hand run cannot cheaply make: no
byte of the marker string appears anywhere under the store (the data came back
*and* was never legible in between), and the vault's password still works
afterwards — a recovery that quietly invalidated the primary key would be
discovered by an operator on the day they next ran an ordinary backup.

---

## What each failure would mean

This is the table an auditor is asking for. A drill is only worth running if a
failure at each step points somewhere specific.

| Step fails | What is true about the data | Where to look |
|---|---|---|
| **2 — no phrase, or fewer than 24 words** | Data is fine. The vault has one key instead of two, so a forgotten password becomes permanent loss. `PLAN.md` §13.2 calls that the #1 risk of a twenty-year tool. | `commands/init/phrase.rs` |
| **3 — the store count changed** | Possibly serious: something in the index path is writing to the backend. Until explained, the store is not a passive record. | the audit log for that window |
| **4 — rebuild fails** | **Data is intact and unreachable.** The objects are all there; nothing local can name them. This is a tooling failure, not a data loss, and it is recoverable by fixing the tool. | `commands/index/rebuild.rs`, `session/index.rs` |
| **4 — rebuild recovers fewer rows than files** | **Objects are missing at the provider**, or the listing stopped early (pagination). The number is the alarm: a rebuild that finds fewer files than the last listing is the signal. Cross-check with `dctl scrub`. | provider listing, then `dctl scrub` |
| **5 — restore refuses on the phrase** | Data is fine, but the second key is decorative — it opens the envelope and not the tool. | `session/secret.rs` |
| **5 — restore fails mid-run** | A tree that is neither the old one nor the new one. Note that DCTL writes each file to a temporary sibling and renames only after the whole object authenticates, so a failed file leaves **no** destination file — not a partial one. Exit **20**/**21** means an integrity failure, and the bytes were not served. | the named object, then `dctl verify` |
| **6 — a hash differs** | The most serious outcome available: the pipeline returned bytes it authenticated and they are still wrong. Nothing in this document should be believed until it is explained. | `dctl-crypto`, and the object's own recorded content hash |
| **6 — a file is missing** | Something dropped it between the walk and the store, or between the index and the restore, and reported success. Check the run's file count against the manifest count. | `commands/backup/scan.rs`, `platform/collision.rs` |
| **6 — a path came back respelled** | **Expected, for an NFD name.** See the next section. Anything else respelled is a defect. | below |

---

## The one thing that comes back different

**A filename stored in NFD comes back in NFC. The bytes of the file are
identical; the spelling of its name is not.**

```
stored    "notes/nai\u{308}ve.txt"      (n a i U+0308 v e . t x t)
restored  "notes/na\u{ef}ve.txt"        (n a U+00EF v e . t x t)
```

Both render as `naïve.txt`. Both are 15 bytes with the same BLAKE3. Only the
name's byte sequence changed, and only in the direction NFD → NFC.

### Why

A logical vault path is normalised to Unicode NFC exactly once, in
[`platform/path.rs`](../crates/dctl-cli/src/platform/path.rs), because the index
key and the object key are both keyed BLAKE3 hashes of the path's bytes. macOS
hands back decomposed filenames while Linux and Windows hand back precomposed
ones. Without that rule, the same file backed up from a Mac and from a Linux box
would produce **two different objects under two different keys** — a silent
duplicate that no user could see, explain, or delete, and that doubles storage
for the file it happens to.

### This is correct and it must not be "fixed"

Reverting the normalisation so that the spelling round-trips exactly would
reintroduce the two-objects-for-one-file bug. There is no third option: either
one file has one key on every platform, or the name's byte sequence is preserved.
DCTL chose the first, and this drill asserts it — the test checks that **exactly**
the names stored in NFD came back respelled: no more, which would mean names are
being rewritten, and no fewer, which would mean the normalisation had been
removed.

### What it means in practice

* Content is never affected. Not once, not partially.
* Comparison tools that compare bytes (`cmp`, `b3sum`, `diff`) see no difference.
* Tools that compare *filenames* byte-for-byte (`diff -r`, `rsync -n`) will
  report the NFD names as different on Linux. On macOS they will not, because
  APFS and HFS+ compare names insensitively to normalisation.
* An auditor should record this as **a name-canonicalisation policy**, not as a
  restore defect: the restored name is the same name, in the canonical spelling
  the vault stores.

### The sharp edge: two files, one path

The rule has a consequence on byte-oriented filesystems. On ext4 or XFS,
`re\u{301}sume\u{301}.txt` and `r\u{e9}sum\u{e9}.txt` are **two different
files** — different bytes, both returned by `read_dir`, free to hold different
contents. Under NFC they are one logical path, so a vault can hold one of them.

DCTL **refuses the run**, before anything is stored, and names every colliding
file with its non-ASCII characters escaped:

```
blocking  résumé.txt  2 local files normalise to this one vault path, so storing them all
                      would keep only the last: '/src/re\u{0301}sume\u{0301}.txt',
                      '/src/r\u{00e9}sum\u{00e9}.txt'

error: 2 local file(s) share 1 vault path(s) once their names are normalised
```

Exit **7**, nothing written, source untouched. The escapes are not decoration:
the two names are identical glyphs in every terminal, file manager and editor, so
a message that printed them as they display would print one string twice and help
nobody.

In `--json`, the finding carries the stable slug `normalisation-collision` at
severity `blocking`, alongside every other pre-flight finding — so a scheduled
backup can alert on it without parsing prose:

```sh
dctl backup /srv/data archive: --json | jq -e '
  [.preflight[] | select(.problem == "normalisation-collision")] | length == 0'
```

The refusal applies to `backup`, `copy`, `sync` and `move` — every verb that
reads a local tree. It is the conservative choice, and it matches what
`dctl restore` already does with a case collision on a case-insensitive volume:
there is no correct file to keep, so the run stops and the operator decides.

macOS cannot produce this input at all: creating the second spelling opens the
first file. The drill checks the filesystem rather than the platform and says so
out loud when it cannot run the case.

---

## What a rebuilt index knows

`dctl index rebuild` reads two bounded things per file: the encrypted `n/*` name
record, which gives the path and the object key, and the object's own **header**,
which gives the size, the modification time and the content hash it was sealed
with. No object body is fetched, so a vault of any size rebuilds for the price of
a listing plus a few kilobytes per object.

The rebuilt rows are therefore the rows that were written. `dctl lsl` after step 4
is indistinguishable from `dctl lsl` before the disaster, `dctl size` reports a
total rather than a lower bound, and `dctl check --checksum` against the source
tree matches.

**It used not to.** The rebuild was a list-only pass over the name records alone,
and its rows carried no size, no content hash and no modification time. `PLAN.md`
§13.5 always promised an index *"rebuildable by scanning object headers"*, and the
headers always carried `mtime_unix`, `size` and `content_blake3`
(`dctl-crypto/src/object/meta.rs`) — they were simply not being read. Two
consequences followed, and both were reachable only on recovery day:

* A restore from such an index stamped every file with the **time of the
  restore**, because that was the only fact available. The bytes and the names
  were exact; the timestamps were not the ones that were backed up, so a
  recovered tree looked entirely rewritten to anything that sorts or syncs by
  date — `dctl check` included.
* `dctl check` could not compare at all, `dctl size` under-reported, and the next
  `dctl sync` re-uploaded the whole dataset. Nothing filled the fields in
  afterwards: `cat`, `hashsum` and a whole `scrub` all read the object and answer
  from it without writing back.

Fixing the read half exposed the write half. The `mtime_unix` field was declared,
sealed into every object and **never written to** — the time lived only in the
local index — so it is now recorded at seal time. Objects written by earlier
builds carry the field's `0` sentinel, and a rebuild reports those as having *no*
recorded time rather than as dated `1970-01-01T00:00:00Z`; a fabricated timestamp
makes every such file look older than every other file and inverts an `--update`
comparison.

An object the rebuild cannot read back at all still gets its path mapped — that
is the recovery story — and is counted as **unmeasured**. The command reports the
count and exits **6** when it is not zero.

---

## Results

### Local store — **PASS**

Run 2026-07-27, Linux x86-64, `dctl` at `cc05f90` plus the two fixes below.

```
restore drill (local directory)
  in:       10 files, 12583158 bytes
  stored:   21 objects
  disaster: index destroyed, store still held 21 objects
  rebuilt:  10 rows, from the backend alone
  back:     10 files, 12583158 bytes (8 identical, 2 respelled)
  respelled: stored "me\u{301}dia/photo.txt", restored "média/photo.txt"
  respelled: stored "notes/nai\u{308}ve.txt", restored "notes/naïve.txt"
```

Ten of ten files recovered. Every size and every BLAKE3 matched. The two
respellings are exactly the two names stored in NFD, and both files were
byte-identical. No byte of the plaintext marker appeared in any of the 21 stored
objects. The vault's password still opened it afterwards.

### Backblaze B2 (`DCTL001`) — **NOT RUN**

`DCTL_B2_KEY_ID` and `DCTL_B2_APP_KEY` are not set on the machine this was run
on, and no B2 remote is configured. **The drill has never been executed against a
cloud provider.**

That matters more than the local pass. A local backend decides everything DCTL
controls; a provider decides everything it does not:

* Step 4 lists every `n/*` record. Locally that is one `read_dir`; on B2 it is a
  paginated API walk, and **a rebuild that stopped at the first page would
  recover a plausible-looking subset and report a number nobody could tell was
  wrong.** Nothing in the local run can reach that path.
* Step 5 pulls twelve chunks over a network instead of out of the page cache. A
  ranged request off by a byte, or a retry that restarts a stream without
  rewinding the hasher, appears only here.
* Latency, throttling and partial failures are the ordinary conditions of a real
  restore and are entirely absent locally.

Until that run happens, the honest claim is: **the restore path is proved against
a local store, and unproved against any provider.**

---

## What the drill found

Both defects below were found by running this exercise, and both are fixed. They
are recorded because a drill's value is in what it catches, and because each says
something about where to look next.

### 1. The recovery command could not run on a recovered machine

`dctl index rebuild` — the command whose own documentation says *"a machine that
has never seen this vault before needs exactly two things to become fully
functional: the password, and this command"* — failed on a machine that had never
seen the vault before:

```
$ DCTL_HOME=/fresh/.dctl dctl index rebuild drill:
error: index database error: unable to open database file: /fresh/.dctl/index/vault.redb
warning: The index is a rebuildable cache: `dctl index rebuild` rescans object headers.
$ echo $?
23
```

`dctl init` created `~/.dctl/index/` on the way past; nothing else did. So every
command that opened a vault failed with exit 23 on a fresh machine — and the hint
attached to the failure named the command that had just failed for that reason.
The data was never at risk; the recovery path was.

Fixed in [`session/index.rs`](../crates/dctl-cli/src/session/index.rs), which
creates the directory during `prepare`, before a secret is asked for — so a
permissions problem is reported before somebody transcribes twenty-four words.

**This is the defect that argues for the drill's existence.** Every layer worked.
Eleven unit tests covering the index, the rebuild and the session all passed. The
only thing that failed was the sequence, on the only machine where the sequence
is ever run.

### 2. A backup reported two files stored and stored one

Two files whose names differ only in normalisation were both "stored", in walk
order, the second overwriting the first:

```
$ dctl backup ./collide drill:
store   23 B  /collide/résumé.txt -> drill:collide/résumé.txt
store   24 B  /collide/résumé.txt -> drill:collide/résumé.txt
       Files: 2 / 2
      Errors: 0
$ dctl ls drill:collide
      24 B résumé.txt
```

Exit 0. Twenty-three bytes gone, reported as backed up. `dctl copy` did the same
thing through an independent code path, and `sync` and `move` share that path —
`move` deletes its source, so it would have destroyed the original of the file it
dropped.

This is the failure `PLAN.md` §6 forbids by name: never report work as done that
did not happen. A backup tool is the worst possible place for it, because the
report is the only thing anybody looks at until restore day.

Fixed in [`platform/collision.rs`](../crates/dctl-cli/src/platform/collision.rs),
described in [the section above](#the-sharp-edge-two-files-one-path).

---

## What the drill does not prove

Stated so nobody has to infer it.

* **Any cloud provider.** See [Results](#results). This is the largest gap.
* **Old on-disk formats.** Every run creates a vault with today's build, so
  nothing here exercises reading a vault written by an earlier version.
  `PLAN.md` §13.6 requires golden fixtures *and* old-format fixtures; the
  old-format half does not exist yet, and a twenty-year tool must read every
  format version it ever wrote.
* **Bit rot.** Objects sitting untouched for a year are `dctl scrub`'s subject,
  and it needs a calendar rather than a test runner. The drill proves a restore
  works today, not that the bytes will still be there in 2031.
* **Scale.** Ten files and 12 MiB. Pagination, memory ceilings, resumption and
  the behaviour of a plan with four million rows are not touched.
* **Concurrent writers.** One process, start to finish.
* **`--at` / `--snapshot`.** Point-in-time restore is refused by this build
  (exit 7); the index holds one current version per path.

---

## Rerunning it

```sh
# The whole drill, local, unattended. ~40 s.
cargo test -p dctl-cli --test restore_drill

# Against a real bucket. The bucket is treated as scratch and is RE-INITIALISED:
# anything already in it becomes permanently unreadable. It has no default.
DCTL_B2_KEY_ID=… DCTL_B2_APP_KEY=… DCTL_DRILL_B2_BUCKET=DCTL001 \
  cargo test -p dctl-cli --test restore_drill -- --ignored --nocapture
```

Both print the same summary block in the same shape, so a local run and a
provider run can be compared line for line.

## See also

* [`dctl restore`](commands/dctl_restore.md) — the command the drill is about.
* [`dctl index rebuild`](commands/dctl_index.md) — step 4, and what it costs.
* [`dctl init`](commands/dctl_init.md) — where the recovery phrase comes from,
  and why it is printed exactly once.
* [`dctl scrub`](commands/dctl_scrub.md) — the scheduled check that exists to
  keep restore day boring.
* [PROJECT_STATUS.md](PROJECT_STATUS.md) — the honest state of everything else.
