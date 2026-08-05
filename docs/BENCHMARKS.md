# DCTL vs rclone — measured comparison

A like-for-like benchmark of DCTL against [rclone](https://rclone.org), run on
one machine, with the method, the raw spreads, the instrument proofs and the
cases DCTL loses stated as plainly as the cases it wins.

> **Summary for the README.** On workloads dominated by *file count* rclone is
> dramatically faster: uploading 10,000 small files to a local encrypted
> destination took DCTL 200.4 s against rclone's 5.7 s at matched concurrency
> (**34.9x**) and 2.2 s at each tool's own defaults (**93.2x**). The cause is
> known and quantified rather than mysterious — DCTL issues four
> `F_FULLFSYNC` barriers per file (3.99 ms each on this SSD) plus a full
> read-back verify, and it refuses `--transfers > 1`, while rclone's local
> backend issues no fsync at all and defaults to four parallel transfers. On
> *large* objects the picture reverses: DCTL uploaded a 4 GiB file to its vault
> in 15.5 s against rclone crypt's 20.1 s (**1.30x faster**), using 9% less CPU
> per GiB and storing 15.8x less ciphertext overhead. DCTL's incremental sync is
> much faster on a high-latency remote, but that speed comes from consulting a
> local index instead of the destination: when a stored object was deleted
> behind its back, DCTL's nightly `copy` reported `Checks: 150/150, Errors: 0`
> and did not repair it, while rclone detected and repaired the same damage.
> DCTL is alpha and has not been profiled; rclone has had a decade of tuning.

Related docs: [`README`](README.md) · [`ARCHITECTURE`](ARCHITECTURE.md) ·
[`FORMAT`](FORMAT.md) · [`SECURITY`](SECURITY.md) ·
[`PROJECT_STATUS`](PROJECT_STATUS.md) · [`GLOBAL_FLAGS`](GLOBAL_FLAGS.md).

---

## 1. What this document is, and what it is not

This is a measurement record, not a marketing page. Three rules were applied
throughout, because the failure mode of a self-run benchmark is a flattering
one:

1. **The encrypted comparison is DCTL vault vs `rclone crypt`.** Comparing
   DCTL-encrypted against rclone-plaintext is not a benchmark. Both pairings
   were run and both are labelled.
2. **Every number is a median of repeated runs with the spread shown**, and the
   1-minute load average is recorded next to it. A single run on a laptop
   measures thermal state and background processes as much as it measures
   software.
3. **Nothing is reported unless the restored data verified byte-identical.**
   Every transfer's destination was re-read and BLAKE3-compared against a
   manifest of the source, and a comparison that compared zero files counts as
   a failure, not a pass.

Section 9 lists the findings from an earlier round of this benchmark that these
rules **overturned**, including one that had been written up as DCTL's most
impressive architectural win and turned out to be a single rclone flag.

---

## 2. Method

### 2.1 Machine

| | |
|---|---|
| Model | Apple `Mac16,12` (M4, 10 cores) |
| RAM | 24 GiB |
| OS | macOS 27.0 (build `26A5388g`), Darwin 27.0.0 arm64 |
| Storage | Internal NVMe, APFS. All benchmark data on one device (`/private/tmp`) |
| Network | Loopback for the SFTP backend; a consumer link behind a VPN for B2 |

The machine was **not** dedicated. A second agent session, Bitdefender, NordVPN
and Chrome were resident throughout. Load average is therefore reported per
cell; the final round ran in a 2.2–5.4 band. An earlier round of this project
produced a false finding from a measurement taken at load average 30, which is
why the load band is a first-class column here rather than a footnote.

macOS Spotlight was found mid-project indexing the output trees at ~500% CPU.
`.metadata_never_index` did not suppress it under `/Users/Shared` or
`/Volumes/XDX01`; moving the trees to `/private/tmp` (same device, a rename not
a copy) did. The DCTL upload was re-measured at 199.3 s after the move against
200.3 s before it — the confounder was real but did **not** cause the headline
gap.

### 2.2 Software under test

| | |
|---|---|
| DCTL | `0.0.1`, branch `macos-mount`, release build |
| rclone | current beta release, installed binary |

Every rclone behaviour reported below was established from what that installed
binary actually did, never assumed.

### 2.3 Datasets

| name | files | bytes | mean file | shape |
|---|---|---|---|---|
| `many-small` | 10,000 | 331,673,447 | 33,167 B | 22 dirs x sub-dirs, incompressible random |
| `one-large-rand` | 1 | 4,294,967,296 | 4 GiB | single incompressible object |
| `smoke` | 150 | 4,957,174 | 33,047 B | subset shape of `many-small` |
| `b2-small` | 200 | 6,458,052 | 32,290 B | subset shape of `many-small` |

All payloads are random bytes, so neither tool's behaviour is distorted by
compressibility and the encrypted and plaintext arms move the same volume.

### 2.4 Backends

| label | DCTL | rclone |
|---|---|---|
| `local` plain | `local:` store | local path |
| `local` enc | DCTL **vault** on a local base | `crypt` over a local path |
| `sftp` plain | `sftp:` store | `sftp:` remote |
| `sftp` enc | DCTL **vault** on an SFTP base | `crypt` over an `sftp:` remote |
| `b2` enc | DCTL **vault** in a B2 bucket | `crypt` over a `b2:` remote |

The SFTP server is a scratch `sshd` on `127.0.0.1:2222` writing to the same
NVMe. Both tools go through it, so it is fair — but see
[§11](#11-threats-to-validity): loopback SFTP has none of the latency or
bandwidth limits of a real network, and that shapes several results.

### 2.5 Arms, and why the two tools' defaults cannot be equalised

| arm | `--transfers` | `--checkers` |
|---|---|---|
| `dctl` | 1 | 1 |
| `rclone-matched` | 1 | 1 |
| `rclone-default` | 4 | 8 |

rclone's defaults, read from the binary, are `--transfers 4 --checkers 8
--buffer-size 16Mi`. DCTL's are `--transfers 1 --checkers 1`, and it does not
accept anything else — it **refuses** rather than silently ignoring:

```
error: dctl copy: --transfers is not honoured in this build
warning: This build transfers one file at a time: crate::commands::transfer::execute
walks the plan on a single task, so that the list --dry-run prints and the list the
machine performs are the same one. ... No command was run and nothing was read or written.
```

So DCTL has one arm and rclone has two, and both rclone arms are reported
everywhere. `rclone-matched` is the like-for-like engineering comparison;
`rclone-default` is what a user actually experiences, and it is the honest
number for a migration decision.

### 2.6 Controls

- **Page cache.** `sudo` was not available, so the cache was evicted by reading
  a 28 GiB file **before every leg** of every repetition — before each upload
  and again before each download. The evictor was proven to work each session:
  a warm sequential read measured 18,811 MB/s, the same read after eviction
  3,274 MB/s, and warm again 13,290 MB/s.
- **Repetitions.** 5 for the large-object cells and the ranged-read sweep, 3 for
  the remaining local and SFTP cells, 2–3 for B2 (where one repetition costs
  minutes on a metered VPN link). The count is stated in every table.
- **Ordering.** Arms alternate A/B/B/A across repetitions so that thermal or
  background drift cannot systematically favour whichever tool ran first.
- **Spread.** Every timing is reported as `median [min–max]`. Where the spread
  is wide it is because the machine was noisy, and that is visible rather than
  hidden by the median.

### 2.7 Correctness gate

After every download the destination tree was hashed and compared against a
BLAKE3 manifest of the source under seven guards: expected manifest non-empty,
actual tree non-empty, file counts equal, path sets equal, per-file hash and
size equal, total bytes equal, and **the number of comparisons actually
performed must equal the file count** — a comparison that compared nothing is
recorded as a failure. This last guard exists because an earlier harness in
this project "passed" by comparing two empty listings.

Every cell in §3 verified with `compared == files` on every repetition. One cell
did not and is reported as invalid rather than dropped (§3.1, B2 `b2-small`).

### 2.8 Instrument proofs

Instruments were proven against known quantities before any number was
believed:

| proof | result |
|---|---|
| Timer vs `sleep` | +13 ms constant fork/exec bias; elapsed delta over 4 s accurate to 0.2 ms |
| Cache evictor | 18,811 → **3,274** → 13,290 MB/s |
| Verifier | deliberate bit-flip, missing file, empty destination, **and both-sides-empty** all correctly FAIL |
| Byte-moved snapshot | 3,500,000 B written reported exactly; a true no-op reported **0**; an identical-content rewrite still detected |
| Injected 5.000 s stall on a real transfer | DCTL **+5.0253 s**, rclone **+5.0132 s** — both detected |
| `--bwlimit 32M` on 256 MiB over SFTP | 8.404 s against 8.0 s expected — detected |
| lo0 byte counter noise floor | 0–496 B against a ~1 MB signal |
| **Harness overhead** | bare `subprocess` 3.678 s vs fully instrumented 3.666 s — **−0.3%**, i.e. below noise |

That last one matters: the peak-RSS sampler forks `ps` twice every 20 ms for the
duration of a run, which on a 200 s run is ~20,000 forks. It was measured
against an uninstrumented run of the same command and does not move the result.

Two instruments could **not** be made to work and are reported as unmeasured
rather than estimated:

- **Memory ceiling.** No hard memory cap is enforceable on macOS 27 —
  `RLIMIT_AS`, `RLIMIT_DATA`, `RLIMIT_RSS`, `RLIMIT_STACK` and `ulimit -v` all
  reject with "current limit exceeds maximum limit". Peak RSS is reported
  instead (§3.4); "minimum memory to complete a transfer" is not.
- **Per-process wire bytes via `nettop`.** It samples at 0.5 s and the commands
  under test complete in 0.07 s, so it reported `net_in=0` for reads that
  demonstrably moved megabytes. Replaced with interface byte deltas plus the
  measured noise floor above.

### 2.9 Harness faults found and fixed before any number was reported

Listed because they are the reason to trust the rest, and because several of
them produced *plausible* wrong numbers rather than obvious ones:

1. Command stdout was decoded as UTF-8, **mangling binary payloads** — a 1 MiB
   slice read back as 1,901,707 bytes and every content check downstream was
   meaningless. Fixed by writing payloads to a file.
2. `nettop` sampling slower than the commands (above).
3. `DCTL_INDEX` was never set when staging vault fixtures, so **every DCTL vault
   staging silently failed** and the vault arm measured an empty store.
4. `init_vault_if_needed` ignored the init return code, so a **failed** vault
   init was measured as a fast 1.38 s "copy".
5. A `--bwlimit` proof that appeared to fail because local→local transfers are
   not throttled by that flag at all. Re-run over SFTP, where it works.
6. A reported finding that "rclone `check --download` misses corruption" was
   **wrong**: the injected corruption had not actually broken decryption, so the
   test was void. Re-run with a self-check that proves 1 of 150 files fails to
   decrypt *before* measuring anything.
7. A B2 destination contaminated by a stale file from an earlier killed run,
   which made three rclone arms verify `False`. Purged and re-run clean.

---

## 3. Results

Cells marked **[R]** were re-measured in the final, quiet round and are the
numbers quoted elsewhere in this document. Cells marked **[I]** are inherited
from the earlier round and were **not** independently reproduced — see
[§11](#11-threats-to-validity).

### 3.1 Transfer time

`PUT` = first upload of the whole dataset onto an empty destination. `GET` =
full download to an empty directory, verified byte-identical. All times in
seconds, `median [min–max]`.

| dataset | backend | mode | arm | reps | PUT | MB/s | GET | MB/s | load | ver |
|---|---|---|---|---|---|---|---|---|---|---|
| many-small | local | **enc** | dctl **[R]** | 3 | **200.45** [198.54–201.37] | 1.7 | **82.97** [81.73–85.77] | 4.0 | 2.7–5.1 | Y |
| many-small | local | **enc** | rclone-matched **[R]** | 3 | **5.74** [5.58–6.04] | 57.8 | **4.77** [4.45–5.50] | 69.6 | 2.5–3.6 | Y |
| many-small | local | **enc** | rclone-default **[R]** | 3 | **2.15** [2.08–2.29] | 154.3 | **2.38** [2.31–2.52] | 139.5 | 2.7–3.3 | Y |
| many-small | local | plain | dctl **[R]** | 3 | **112.57** [110.97–117.82] | 2.9 | **114.77** [94.62–116.08] | 2.9 | 2.5–3.1 | Y |
| many-small | local | plain | rclone-matched **[R]** | 3 | **5.60** [5.58–5.66] | 59.3 | **5.21** [5.10–9.19] | 63.7 | 3.1–4.3 | Y |
| many-small | local | plain | rclone-default **[R]** | 3 | **2.75** [2.69–2.76] | 120.7 | **2.76** [2.70–4.15] | 120.2 | 3.5–3.9 | Y |
| many-small | sftp | enc | dctl **[R]** | 3 | **91.01** [86.69–95.21] | 3.6 | **138.28** [132.15–140.28] | 2.4 | 2.2–5.2 | Y |
| many-small | sftp | enc | rclone-matched **[R]** | 3 | **61.06** [60.66–62.13] | 5.4 | **5.50** [5.32–5.71] | 60.3 | 3.1–7.4 | Y |
| many-small | sftp | enc | rclone-default **[R]** | 3 | **21.39** [21.21–21.42] | 15.5 | **3.05** [3.01–3.08] | 108.8 | 3.3–**13.1** | Y |
| one-large-rand | local | **enc** | dctl **[R]** | 5 | **15.50** [15.40–15.74] | 277.2 | **15.69** [15.01–15.80] | 273.7 | 2.2–4.4 | Y |
| one-large-rand | local | **enc** | rclone-matched **[R]** | 5 | **20.13** [19.43–21.85] | 213.4 | **12.77** [9.15–14.30] | 336.2 | 2.3–3.9 | Y |
| one-large-rand | local | **enc** | rclone-default **[R]** | 5 | **20.01** [19.55–20.92] | 214.7 | **11.79** [10.66–18.86] | 364.5 | 2.4–5.4 | Y |
| one-large-rand | local | plain | dctl **[R]** | 5 | **10.48** [10.05–13.35] | 409.8 | **8.24** [7.20–11.89] | 521.2 | 3.7–5.2 | Y |
| one-large-rand | local | plain | rclone-matched **[R]** | 5 | **5.85** [5.68–6.08] | 733.8 | **5.92** [5.73–6.14] | 725.4 | 3.1–3.9 | Y |
| one-large-rand | local | plain | rclone-default **[R]** | 5 | **5.74** [5.71–6.15] | 748.2 | **5.73** [5.69–5.74] | 749.8 | 2.7–4.1 | Y |
| smoke (150f) | b2 | enc | dctl **[I]** | 3 | 336.03 [319.90–360.68] | 0.01 | 86.38 [81.36–87.82] | 0.06 | 1.5–4.5 | Y |
| smoke (150f) | b2 | enc | rclone-matched **[I]** | 3 | 78.28 [50.97–235.37] | 0.06 | 31.73 [30.77–39.86] | 0.16 | 2.0–7.8 | Y |
| smoke (150f) | b2 | enc | rclone-default **[I]** | 3 | 20.96 [16.93–28.41] | 0.24 | 10.25 [9.34–10.70] | 0.48 | 3.8–4.6 | Y |
| b2-small (200f) | b2 | enc | rclone-matched **[I]** | 2 | 94.13 [80.13–108.14] | 0.07 | 44.59 [40.85–48.34] | 0.14 | 1.6–4.0 | Y |
| b2-small (200f) | b2 | enc | rclone-default **[I]** | 2 | 28.29 [25.96–30.63] | 0.23 | 13.88 [13.09–14.68] | 0.47 | 1.9–3.7 | Y |
| b2-small (200f) | b2 | enc | dctl | 3 | *INVALID* | — | *INVALID* | — | — | **N** |

The last row is kept visible rather than deleted: DCTL's vault init failed
(exit 7) against that bucket, the transfer moved nothing, and the verifier
correctly reported zero comparisons. It is a **defect** (§12), not a data point.

### 3.2 Ratios

Greater than 1 means DCTL is slower.

| dataset | backend | mode | vs rclone-matched (1/1) | vs rclone-default (4/8) |
|---|---|---|---|---|
| many-small | local | **enc** | PUT **34.9x** · GET **17.4x** | PUT **93.2x** · GET **34.9x** |
| many-small | local | plain | PUT **20.1x** · GET **22.1x** | PUT **41.0x** · GET **41.6x** |
| many-small | sftp | enc | PUT **1.49x** · GET **25.1x** | PUT **4.26x** · GET **45.4x** |
| one-large-rand | local | **enc** | PUT **0.77x** ✅ · GET 1.23x | PUT **0.77x** ✅ · GET 1.33x |
| one-large-rand | local | plain | PUT 1.79x · GET 1.39x | PUT 1.83x · GET 1.44x |
| smoke | b2 | enc | PUT 4.3x · GET 2.7x | PUT 16.0x · GET 8.4x |

### 3.3 CPU per GiB moved

Sum of user and system CPU from `wait4`, divided by GiB transferred.

| cell | DCTL | rclone-matched | rclone-default |
|---|---|---|---|
| many-small local enc **[R]** | 38.52 | **14.34** | 16.71 |
| many-small local plain **[R]** | 17.41 | **12.30** | 13.79 |
| many-small sftp enc **[R]** | 24.61 | **25.97** | 30.78 |
| one-large-rand local enc **[R]** | **4.45** | 4.89 | 4.93 |
| one-large-rand local plain **[R]** | **1.44** | 2.87 | 2.84 |

On the 4 GiB object DCTL uses **9% less CPU per GiB encrypted** and **half the
CPU plaintext**. It is not CPU that makes DCTL slow on small files: across the
200 s upload DCTL consumed 3.3 s user + 8.4 s system, i.e. **~6% CPU
utilisation**. The other 94% is blocked on durability barriers.

### 3.4 Peak resident memory

Peak RSS across the whole process tree, sampled independently of `ru_maxrss`.

| cell | DCTL | rclone-matched |
|---|---|---|
| many-small local enc | 150.2 MB | 92.3 MB |
| many-small local plain | **11.6 MB** | 67.8 MB |
| many-small sftp enc | 151.9 MB | 92.6 MB |
| one-large-rand local enc | 147.7 MB | 88.3 MB |
| one-large-rand local plain | **9.9 MB** | 54.2 MB |

Both tools are bounded — neither buffers a 4 GiB file. **In plaintext mode DCTL
uses 5.5x less memory than rclone** (11.6 MB against 67.8 MB on the 10,000-file
tree), which is a real DCTL win. The interesting number is the difference
between DCTL's plaintext and encrypted rows: **137.8 MB**, which is the 128 MiB
Argon2id working buffer (`m_cost = 131,072 KiB, t_cost = 3, p = 4`) allocated
once to unlock the vault. DCTL's *transfer* footprint is ~10 MB; the rest is the
key-derivation function, and it is a deliberate security parameter rather than
transfer overhead.

### 3.5 Storage overhead

| | source bytes | stored bytes | overhead | objects |
|---|---|---|---|---|
| DCTL vault, many-small | 331,673,447 | 335,813,760 | **+1.249%** | **20,001** |
| rclone crypt, many-small | 331,673,447 | 332,153,447 | +0.145% | 10,000 |
| DCTL vault, 4 GiB | 4,294,967,296 | 4,295,033,523 | **+0.0015%** | 3 |
| rclone crypt, 4 GiB | 4,294,967,296 | 4,296,015,904 | +0.0244% | 1 |

Both figures reconcile exactly with the published formats, which is a useful
cross-check on the measurement:

- **rclone crypt** uses 64 KiB blocks with a 16-byte Poly1305 tag plus a 32-byte
  file header. For 4 GiB: `16 x (4 GiB / 64 KiB) + 32 = 1,048,608` — measured
  1,048,608, exact. For 10,000 files averaging one block each:
  `10,000 x (32 + 16) = 480,000` — measured 480,000, exact.
- **DCTL vault** uses 1 MiB chunks with a 16-byte tag. For 4 GiB:
  `16 x 4,096 = 65,536` plus a 691-byte object header — measured 66,227.

DCTL is **15.8x more efficient on large objects** (bigger chunks mean fewer
tags) and **8.6x worse on small ones** (414 B/file against rclone's 48 B/file),
because every file costs a second object: content under `o/` and an encrypted
name record under `n/`. That is why the object count is 20,001 rather than
10,000.

---

## 4. Where DCTL is faster

### 4.1 Uploading large objects to an encrypted destination — 1.30x

**15.50 s [15.40–15.74] against rclone crypt's 20.13 s [19.43–21.85]** for
4 GiB, 5 repetitions each, alternating order, cold cache. The spread is tight on
both sides so this is not noise. DCTL also wins against rclone's *default*
concurrency (20.01 s), because a single-file transfer cannot use four transfer
slots.

The reason is chunk size and cipher pipeline, and it can be isolated from the
plaintext rows in the same table:

| | DCTL | rclone |
|---|---|---|
| plaintext 4 GiB PUT | 10.48 s | 5.85 s |
| encrypted 4 GiB PUT | 15.50 s | 20.13 s |
| **cost of encryption** | **+5.01 s = 1.25 s/GiB** | **+14.27 s = 3.57 s/GiB** |

rclone crypt's encryption costs **2.85x more per byte** than DCTL's vault. Two
candidate causes, which this benchmark did **not** separate: DCTL seals 1 MiB
chunks against rclone's 64 KiB blocks, so it makes 16x fewer AEAD calls and
buffer copies; and the implementations differ (Rust `chacha20poly1305`
XChaCha20-Poly1305 with NEON on aarch64, against Go's `nacl/secretbox`
XSalsa20-Poly1305). Both are plausible and I did not build the microbenchmark
that would tell them apart.

This win is real but note its shape: DCTL is **absolutely slower at moving
bytes** (10.48 s vs 5.85 s plaintext, because it reads back and re-hashes
everything it writes — see §5.2). It wins the encrypted case only because
rclone's crypt overhead is larger than DCTL's total handicap. Against a
hypothetical rclone with DCTL's cipher pipeline, DCTL would lose.

### 4.2 CPU and storage efficiency on large objects

**4.45 CPU-s/GiB against 4.89** encrypted, and **1.44 against 2.87** plaintext
(§3.3). **+0.0015% storage overhead against +0.0244%** (§3.5). Same architectural
cause: fewer, larger chunks.

### 4.3 Sync after one changed file, encrypted large object

DCTL 16.31 s against rclone-matched 24.46 s and rclone-default 23.57 s —
**1.50x** and **1.44x** faster respectively, since the work is one full
re-upload of the changed object.

### 4.4 Verifying a backup without the original data

Not a speed result, but the one genuine capability difference found, so it
belongs here. `dctl verify` reads every object in the vault, authenticates each
one against its AEAD tag, and reports damage **with no access to the source
tree** — 0.19 s for 150 objects locally, and it correctly detected both a
deleted object and a size-and-mtime-preserving bit flip (§8).

rclone crypt cannot do this. Its equivalents, `rclone check --download` and
`rclone cryptcheck`, both take a *source* and a *destination* and compare them.
There is no rclone command that answers "is this encrypted backup internally
consistent?" without the originals, because crypt exposes no per-object content
hash. For anyone whose reason to have a backup is that the originals may be
gone, that is a meaningful difference.

### 4.5 Process startup

`dctl --version` in **3.9 ms** against `rclone version` in **26.5 ms** — DCTL's
binary starts 6.8x faster. This is invisible inside a long transfer and matters
only for scripts making many short invocations. It is also entirely erased by
the vault: unlocking costs ~143 ms per process (§5.5).

---

## 5. Where rclone is faster

### 5.1 Many small files — 34.9x at matched concurrency, 93.2x at defaults

The headline loss, and by a wide margin the most important number here.

| | DCTL | rclone-matched | rclone-default |
|---|---|---|---|
| 10,000 files, local encrypted, PUT | **200.45 s** | 5.74 s | 2.15 s |
| per file | **20.04 ms** | 0.574 ms | 0.215 ms |
| CPU utilisation during the run | **~6%** | — | — |

This was reproduced independently in the final round to within 0.6% of the
earlier round's figure (200.45 s vs 199.26 s), at a lower load average, on both
orderings. It is not a measurement artefact.

**The cause is fully accounted for.** Measured on this SSD:

| operation | median |
|---|---|
| plain `fsync` | 0.092 ms |
| **`F_FULLFSYNC`** | **3.99 ms** (n=100, p10 3.24, p90 4.85) |
| SQLite commit, WAL + FULL | 0.093 ms |

Rust's `File::sync_all()` is `F_FULLFSYNC` on macOS. `dctl-store`'s verified
write calls it on the object and again on the parent directory after the atomic
rename — **two barriers per object**. `vault/put.rs` writes **two objects per
file**, the content under `o/` and the name record under `n/`, sequentially.
That is **4 x 3.99 = 15.96 ms per file predicted**; measured 20.04 ms. The
remaining ~4 ms is the read-back verify (each object is re-read and BLAKE3'd
before commit), the mtime stamp, and the index commit.

The prediction holds across modes: the plaintext path writes one object, so two
barriers, so 7.98 ms predicted against 11.26 ms measured (112.57 s / 10,000) —
predicted vault:plain ratio 2.0x, measured **1.78x**.

**rclone's local backend contains no `fsync` call at all.** The only durability
barriers it issues anywhere sit off the transfer path — in its FUSE mount
handlers, its VFS write-back cache, its config-file writer and ncdu's terminal
redraw. **None are on the `copy`/`sync` transfer path.** So this is not rclone
being clever and DCTL slow; it is DCTL buying a durability guarantee that rclone
does not offer, and paying for it four times per file, serially, with
concurrency refused.

That framing should not be used to excuse the result. Three things about it are
genuinely wrong rather than merely expensive, and each is a filed defect (§12):

1. **The barriers are serial.** Four `F_FULLFSYNC` calls per file with
   `--transfers` pinned at 1 means the entire process is one file deep. Even
   keeping every barrier, batching the directory fsyncs or overlapping files
   would recover most of the gap without weakening the guarantee.
2. **The name record costs a second full durability cycle.** Name records are
   small and could be batched into a single journal object per group of files.
3. **The read-back verify re-reads every byte just written**, which on a local
   backend is served from the page cache it just dirtied — so it is validating
   memory, not the medium, for most of its cost.

The evidence that these are the whole story: **over SFTP, where the barrier
moves to the remote sshd and both tools pay a network round trip, the upload gap
collapses from 34.9x to 1.49x.**

### 5.2 Large objects in plaintext — 1.79x

**10.48 s against 5.85 s** for 4 GiB. DCTL reads back and re-hashes everything
it writes, so a local plaintext copy moves the data three times (read source,
write destination, read destination back) against rclone's two. 3/2 = 1.5x of
the 1.79x measured; the rest is the BLAKE3 pass and single-threaded streaming.

This number **improved** from an earlier round's 2.5x purely by running on a
quieter machine, which is a warning about the earlier figure rather than a
credit to DCTL.

### 5.3 Downloads — every single cell

DCTL lost every `GET` cell measured, without exception: 17.4x on many-small
local encrypted, 25.1x over SFTP, 1.23x even on the 4 GiB encrypted object it
*won* on upload. The restore path writes files through the same verified-write
machinery, so a 10,000-file restore pays the same barriers as a 10,000-file
backup — 82.97 s, or 8.30 ms per file.

The SFTP figure is the starkest: **DCTL 138.28 s against rclone's 5.50 s**, a
25.1x loss, and 45.4x against rclone's defaults. Note the asymmetry within
DCTL's own SFTP results — upload 91.01 s, download 138.28 s. Uploading to SFTP
is *faster* than downloading from it, which is the opposite of both tools'
behaviour everywhere else and of rclone's on the same backend (61.06 s up,
5.50 s down). The restore path is doing something the upload path is not, and
it has not been profiled.

### 5.4 Listing

| 10,000 entries | median | derived per-entry |
|---|---|---|
| dctl ls, plain | 0.2397 s | 23.3 µs |
| rclone ls, plain | **0.0393 s** | **1.8 µs** |
| dctl ls, vault | 0.2237 s | **7.4 µs** |
| rclone ls, crypt | **0.1026 s** | 6.1 µs |

rclone is 6.1x faster plaintext and 2.2x faster encrypted at the command level.
But subtracting each tool's measured fixed startup (§4.5, §5.5) shows the
*encrypted* listings are within ~21% of each other per entry (7.4 µs against
6.1 µs) — the 2.2x at the command level is almost entirely Argon2id. The
plaintext listing is a real 13x per-entry loss and worth profiling. Note also
that DCTL's *vault* listing is 3x faster per entry than its own *plaintext*
listing, because the vault answers from the SQLite index while the plaintext
path walks the filesystem.

### 5.5 Vault unlock — 143 ms on every invocation

`dctl ls` against a one-object store: **7.0 ms plaintext, 149.8 ms vault**. The
~143 ms difference is the Argon2id key derivation (128 MiB, 3 passes, 4 lanes).

This is a deliberate security parameter and lowering it would weaken the vault,
so it is not a defect. But it is a per-process cost, so any workflow that
invokes `dctl` many times in a loop pays it every time, and it dominates every
short vault operation measured here — including the ranged reads in §6.

### 5.6 Everything on B2

DCTL was 4.3x slower than rclone-matched and 16.0x slower than rclone-default
uploading 150 files to B2. **These numbers were not reproduced in the final
round** — the credentials are not in this environment and the scratch buckets
were deleted — so they carry the weakest confidence of anything here. See §11.

---

## 6. Where the two are not comparable

### 6.1 Ranged reads — a corrected finding

An earlier round reported that on a 1 MiB read from the middle of a 4 GiB
object over SFTP, DCTL's vault fetched 1.03x the requested bytes while rclone
crypt fetched 4.93x, and framed the 4.8x gap as architectural. **That framing
was wrong on two counts, and both corrections cut against DCTL.**

**Correction 1: most of rclone's amplification is one default flag.** rclone's
SFTP backend issues up to 64 outstanding read requests per file
(`--sftp-concurrency 64`). Turning that off collapses the amplification;
`--buffer-size 0`, the flag originally suspected, does nothing.

**Correction 2: the test size was exactly DCTL's chunk size.** DCTL's default
chunk is 1 MiB, so a 1 MiB aligned read is the single most flattering request
DCTL can be given — one whole chunk, no partial chunk at either end. Sweeping
the request size and alignment shows the real curve (SFTP, 5 reps, loopback
byte counters, all outputs SHA-256 verified):

| request | DCTL vault | rclone crypt, default | rclone crypt, `--sftp-disable-concurrent-reads` |
|---|---|---|---|
| 4 KiB | 1,077,444 B (263x) | 4,006,070 B (978x) | **147,138 B (36x)** |
| 64 KiB | 1,077,576 B (16.4x) | 3,609,718 B (55x) | **147,202 B (2.3x)** |
| 1 MiB, aligned | **1,077,288 B (1.03x)** | 4,940,130 B (4.71x) | 1,148,046 B (1.09x) |
| 1 MiB, unaligned | 2,135,172 B (2.04x) | 5,146,202 B (4.91x) | **1,148,086 B (1.09x)** |
| 8 MiB | 8,482,160 B (1.01x) | 12,196,990 B (1.45x) | 8,621,074 B (1.03x) |

The honest reading:

- **At rclone's defaults**, DCTL fetches fewer bytes for requests of 64 KiB and
  above. On a metered link that is a real, user-visible difference.
- **Against tuned rclone**, DCTL fetches **7.3x more** for a 4 KiB read
  (1.08 MB against 147 KB) and about 2x more for an unaligned 1 MiB read. DCTL
  cannot fetch less than one 1 MiB chunk; rclone's 64 KiB blocks let it fetch
  less. **For small random reads rclone is strictly better.**
- The two converge above ~8 MiB.
- **rclone is 2.4x faster in wall time in every single case**
  (0.088–0.129 s against DCTL's 0.226–0.267 s), and ~143 ms of DCTL's time is
  the Argon2id unlock (§5.5), not the read.

So this is a **chunk-size trade**, not a DCTL win: 1 MiB chunks buy storage
efficiency and bulk throughput (§4.1, §4.2) and cost random-read granularity.
Both formats are internally consistent; which is better depends entirely on
whether the workload does bulk transfers or small random reads. A one-line
benchmark claim in either direction would be dishonest.

### 6.2 Defaults cannot be equalised

DCTL refuses `--transfers > 1` (§2.5). Every "matched concurrency" number in
this document is therefore matched by crippling rclone, not by tuning DCTL. The
`rclone-default` column is the one that describes what a user gets, and it is
the harsher of the two for DCTL in every cell.

### 6.3 Durability guarantees differ, so "bytes per second" is not the whole unit

rclone's local backend does not fsync; DCTL fsyncs four times per vault file
and verifies the read-back. These are not the same operation, and a throughput
number compares them as though they were. The SFTP result (§5.1) is the closest
thing to a controlled test of this: move the barrier to a remote server that
both tools must wait for, and the 34.9x becomes 1.49x.

---

## 7. The incremental sync — what a nightly job actually costs

This is the operation a backup tool performs every day, so it is called out
separately. **It is also where an earlier round's most quotable DCTL number
turned out not to survive scrutiny.**

### 7.1 The timing

Re-running the same `copy` over an unchanged source. Bytes written to the
destination store were instrumented by snapshotting the tree before and after.

| cell | DCTL | rclone-matched | rclone-default |
|---|---|---|---|
| many-small local enc **[R]** | 0.314 s | 0.286 s | **0.119 s** |
| many-small local plain **[R]** | 0.333 s | 0.095 s | **0.082 s** |
| one-large-rand local enc **[R]** | 0.175 s | **0.046 s** | 0.053 s |
| one-large-rand local plain **[R]** | **0.007 s** | 0.027 s | 0.027 s |
| many-small sftp enc **[R]** | **0.352 s** | 0.430 s | 0.811 s |
| **smoke b2 enc [I]** | **2.17 s** | 20.53 s | 4.82 s |

**Every no-op sync on both tools moved exactly 0 bytes on every backend.**
Neither tool re-uploads unchanged data, and the byte instrument was proven able
to detect a rewrite of identical content, so the zeroes are real.

On B2, DCTL's no-op sync was 9.5x faster than rclone at matched concurrency.
That was written up as DCTL's strongest operational win.

### 7.2 Why that comparison is not like-for-like

The two commands are not doing the same job. DCTL consults its local SQLite
index. rclone interrogates the remote — which is why rclone's B2 time scales
with `--checkers` (20.53 s at 1 checker, 4.82 s at 8), the signature of
per-object remote lookups.

So the question is what happens when the remote and the index disagree. Tested
directly: seed 150 files, delete one stored object behind the tool's back, then
ask each tool the same three questions in the same order.

| | DCTL vault | rclone crypt |
|---|---|---|
| Audit an **intact** store (control) | `verify` exit 0, "150 objects examined, 4.73 MiB (authenticated)" | `check` exit 0, "150 matching files" |
| **Q1** Audit after deletion | `verify` **exit 4 — detects**, 0.19 s · `scrub` **exit 4 — detects** · `check` **exit 0, "all match (size-and-modtime)" — misses** | `check` **exit 1 — detects** · `check --download` **exit 1 — detects** · `cryptcheck` **exit 1 — detects** |
| **Q2** Run the nightly `copy` | **exit 0**, `Checks: 150/150, Skipped: 150 (unchanged), Errors: 0` — **not repaired**, 0 objects written | **exit 0** — **repaired**, 1 object re-uploaded |
| **Q3** Restore everything | **exit 6, 149 of 150 files** — fails loudly, data is gone | exit 0, **150 of 150** — intact |

**DCTL's nightly job reported complete success over a backup that could no
longer be restored.** That is a false success, and it is the exact failure mode
this project's own engineering standard forbids. rclone, doing the slower thing,
noticed and fixed it.

Two mitigations, stated so the picture is not worse than it is:

- DCTL's `verify` and `scrub` **do** catch it, in 0.19 s, and unlike any rclone
  command they do it without the source data (§4.4). The capability exists; it
  is just not on the nightly path.
- In **plaintext** mode DCTL's `copy` *does* repair a deleted destination file
  — tested directly: it re-uploaded the one missing file (`Files: 1/1, Skipped:
  149 (unchanged)`) and the subsequent restore verified 150 of 150. The defect
  is specific to the vault, where the index is trusted in place of the
  destination listing.

Also worth flagging: `dctl check` reported "all match (size-and-modtime)" over a
store with a missing object. rclone's `check` at least says "150 hashes could
not be checked", which tells the operator what it *didn't* verify. DCTL's
message is the more misleading of the two.

### 7.3 Sync after one file genuinely changes

Both tools move only the changed file. On many-small local encrypted, DCTL
wrote 60,841 B and rclone 60,475 B for a 60,427 B file — DCTL's extra 366 B is
the encrypted name record.

---

## 8. Integrity under damage — the fair result

Separately from deletion (§7.2), the harder case: flip one byte in the middle of
a stored object and restore size and mtime to exactly their previous values, so
that no size-and-modtime comparison can see it. The harness proves the damage
changed the stored bytes and preserved size and mtime before measuring anything.

| | restore exit | bytes correct | **silently returned corrupt data?** |
|---|---|---|---|
| DCTL plain | 0 | No | **Yes** |
| rclone plain | 0 | No | **Yes** |
| DCTL vault | 6 | No (149/150) | No — fails loudly |
| rclone crypt | 1 | No (149/150) | No — fails loudly |

**The two tools behave identically.** In plaintext mode both silently restore
corrupted bytes with a success exit code, because neither re-verifies content
against a stored hash on the read path. In encrypted mode both fail loudly,
because the AEAD tag does not authenticate. This is a property of encryption,
not of either vendor, and it would be dishonest to present either half of this
table as a differentiator.

The one asymmetry is the audit path, already covered in §4.4 and §7.2: DCTL's
`verify`/`scrub` detect this damage without the source; rclone needs
`check --download` and the original files.

---

## 9. Findings from the earlier round that this round overturned

Recorded in full, because a benchmark that only publishes its final answers is
not reproducible and because two of these were flattering to DCTL.

| earlier claim | status | corrected |
|---|---|---|
| "DCTL fetches 4.80x fewer bytes than rclone crypt on ranged reads — architectural" | **Overturned** | It is one rclone flag (`--sftp-concurrency`, default 64). Tuned, rclone fetches 1.09x against DCTL's 1.03x — and **7.3x fewer** than DCTL on a 4 KiB read. §6.1 |
| Ranged read measured only at 1 MiB | **Unrepresentative** | 1 MiB is exactly DCTL's chunk size, its best possible case. The full sweep reverses the result for small reads. §6.1 |
| "DCTL's no-op sync on B2 is 9.5x faster — DCTL's strongest operational win" | **Not like-for-like** | DCTL never contacts the remote. Given a deleted object it reports success and does not repair; rclone repairs. §7.2 |
| DCTL 2.5x slower on plaintext 4 GiB upload | **Corrected to 1.79x** | The earlier figure was taken at higher load with a 3x spread (8.76–26.12 s). §5.2 |
| DCTL 32.5x slower than rclone-default on plaintext many-small | **Corrected to 41.0x — worse for DCTL** | rclone-default sped up from 3.54 s to 2.75 s on a quieter machine; DCTL barely moved. §3.2 |
| "rclone `check --download` misses corruption" | **Was wrong** | The injected corruption had not broken decryption; the test was void. rclone detects it. §8 |
| DCTL 35.6x / 94.0x slower on many-small local encrypted | **Confirmed** | Independently reproduced at 34.9x / 93.2x on a quieter machine. §5.1 |
| DCTL wins large encrypted upload | **Confirmed** | 0.77x reproduced over 5 repetitions with a tight spread. §4.1 |

---

## 10. What this means if you are considering a migration

**You would notice an improvement if:**

- Your data is a small number of large objects — VM images, disk images, media
  masters, database dumps. Encrypted upload is ~1.3x faster, CPU per GiB is
  9–100% lower, and stored ciphertext overhead is 15.8x smaller.
- You need to prove an encrypted backup is intact **without** the original
  files. `dctl verify` does this; no rclone command does (§4.4).
- You care that every stored object was fsynced and read back before the tool
  called it written. rclone's local backend does not fsync at all.

**You would notice a regression if:**

- You back up many files. A 10,000-file tree that rclone uploads in 2.2 s takes
  DCTL 200 s. Scaled to a real backup set, a job that finishes overnight with
  rclone will not finish overnight with DCTL. **This is the single fact most
  likely to make DCTL unusable for a given user today.**
- You restore many files. Every restore cell measured was slower, up to 45.4x.
- You do small random reads out of large encrypted objects. DCTL cannot read
  less than a 1 MiB chunk (§6.1).
- You rely on the nightly job to notice and repair a damaged destination. In
  vault mode DCTL does not; you must schedule `dctl verify` or `dctl scrub`
  separately (§7.2).
- You use B2, where DCTL was 4.3–16x slower (with the caveats in §11).

**The honest one-sentence summary:** rclone is faster at almost everything
involving more than a handful of files — by one to two orders of magnitude —
and the reasons are understood and fixable rather than fundamental; DCTL is
competitive-to-better on large objects, where it uses less CPU and less storage,
and it offers one thing rclone crypt does not, which is verifying an encrypted
backup without the original data — but today it buys its fast incremental sync
by not checking the destination at all, and that trade is not yet one a cautious
operator should accept.

---

## 11. Threats to validity

Listed plainly. Any of these could change a conclusion.

1. **Localhost SFTP is not a network.** There is no propagation delay, no packet
   loss, no bandwidth ceiling. The finding that DCTL's upload gap collapses from
   34.9x to 1.49x over SFTP (§5.1) is the most load-bearing claim resting on
   this, and it would move on a real link — probably in DCTL's favour, since
   real latency penalises rclone's extra round trips too, but that is an
   argument, not a measurement.
2. **The B2 results are the weakest data here.** They were taken over a VPN at
   ~8 MB/s with ~440 ms per-object round trips; rclone's B2 upload spread was
   50.97–235.37 s, a 4.6x range. They were **not** reproduced in the final round
   because the credentials are absent from this environment and the scratch
   buckets were deleted. Treat every B2 row as indicative only.
3. **The machine was shared.** Load average 2.2–5.4 during the final round,
   higher earlier, with another agent session, an antivirus and a VPN client
   resident. Loads are reported per cell; the plaintext 4 GiB result moved from
   2.5x to 1.79x purely from running quieter, which shows the sensitivity.
4. **A laptop thermally throttles.** No sustained-load soak was run and no
   thermal state was recorded. The 200 s DCTL runs are the most exposed, and
   they would be exposed in the direction that makes DCTL look worse.
5. **`sudo purge` was unavailable**, so the page cache was evicted by reading
   28 GiB rather than dropped. The evictor was proven effective (§2.6) but a
   read-based eviction is not identical to a true drop.
6. **The five B2 rows are inherited, not reproduced.** Everything marked
   **[I]** in §3.1 is a B2 row and comes from the earlier round; every local and
   SFTP cell was re-measured in the final round and reproduced. Where the two
   rounds disagreed, the final round is reported and the difference is noted
   (§9). The disagreements were not small — the plaintext 4 GiB figure moved
   from 2.5x to 1.79x and the plaintext many-small default-concurrency ratio
   moved *against* DCTL from 32.5x to 41.0x — so the B2 rows, which had no such
   second look, should be treated as the least reliable numbers here.
7. **DCTL is alpha and has not been profiled.** The `--transfers` refusal is
   documented and deliberate, not an oversight, and none of the costs in §5.1
   have had an optimisation pass. Comparing unprofiled alpha software against a
   decade-tuned tool measures the gap today, not the gap achievable.
8. **One machine, one OS, one filesystem.** `F_FULLFSYNC` is a macOS/APFS
   behaviour. On Linux with `fdatasync` the same code would pay a very different
   price and the many-small result could look substantially different. **No
   Linux measurement was taken.**
9. **Single-run B2 object anomaly.** During the earlier round, 13 vault-shaped
   objects appeared in a B2 bucket with no matching entry in DCTL's audit log
   and no attributable command. They were purged and a watcher saw no
   recurrence, but the possibility that those credentials were in concurrent use
   cannot be excluded, and it is one more reason to discount the B2 rows.
10. **Datasets are synthetic and incompressible.** Real trees have duplicate
    files, sparse files, compressible content and pathological names. None of
    those were exercised. The `mixed`, `one-large-zero`, SFTP-plaintext and
    B2-plaintext cells were planned and not run.

---

## 12. Defects this benchmark surfaced

| # | severity | defect |
|---|---|---|
| 1 | **High** | Vault `copy` reports success over a destination with a missing object: `Checks: 150/150, Skipped: 150 (unchanged), Errors: 0`, exit 0, no repair, and the subsequent restore fails. False success on the nightly path. §7.2 |
| 2 | **High** | `dctl check` reports "all match (size-and-modtime)" against a damaged store. The message asserts more than the check performed. §7.2 |
| 3 | **High** | Four serial `F_FULLFSYNC` barriers per vault file with concurrency refused — 20.04 ms/file, ~6% CPU utilisation. Batching directory syncs, journalling name records, or overlapping files would recover most of a 34.9x gap without weakening durability. §5.1 |
| 4 | Medium | `dctl init --force` fails against an existing **empty** B2 bucket configured `require_vault = true`: `object not found: bucket <name>`, exit 4. Succeeds against a fresh bucket and against a local base. Invalidated an entire benchmark cell. §3.1 |
| 5 | Medium | Restoring 10,000 files from SFTP (138.28 s) is **slower than uploading them** (91.01 s), inverting both tools' behaviour everywhere else and rclone's on the same backend (61.06 s up, 5.50 s down). Unexplained; the restore path has not been profiled. §5.3 |
| 6 | Medium | Plaintext listing costs 23.3 µs/entry against rclone's 1.8 µs — 13x, and 3x worse than DCTL's own vault listing. §5.4 |
| 7 | Low | `SftpDef.host` documents `user@host[:port]` but the port form is passed verbatim to `ssh` and fails. |
| 8 | Low | Restored files carry whole-second mtimes; rclone preserves sub-second precision on local backends (verified: DCTL restored `1785520229.0` where rclone restored `1785520532.540123`). Both truncate over SFTP, which is a protocol limit. |

---

## 13. Reproducing this

The harness is not in this repository — it was deliberately kept outside the
tree so that benchmarking could not touch the code under test. To rebuild it:

1. **Fixtures.** Generate the datasets in §2.3 as incompressible random data and
   record a BLAKE3 manifest of each (`hash \t size \t relpath` per line).
2. **Backends.** Configure the five backend pairs in §2.4 so that both tools
   write to the same physical device, and a local `sshd` for the SFTP arms.
3. **Per repetition**, for each arm in an A/B/B/A order: wipe the destination,
   reset DCTL's index, evict the page cache, time the upload, snapshot the
   destination tree, evict again, time the download, then hash the restored tree
   and compare against the manifest under the seven guards in §2.7. Record the
   load average at the start and end of every timed command.
4. **Prove the instruments first** (§2.8). At minimum: confirm the timer against
   `sleep`, confirm the cache evictor moves sequential read throughput by ~5x,
   confirm the verifier fails on a deliberate bit flip *and* on two empty
   listings, and confirm the whole harness detects an injected 5 s stall on a
   real transfer.
5. **Report the median and the min–max**, never a single run, and never a mean.

Anything in §3 that does not reproduce should be treated as this document's
error rather than the reader's. The measurements in this file were taken on
2026-07-31 against the DCTL build described in §2.2; DCTL is under active
development and these numbers have a short shelf life, particularly the ones in
§5.1 that a single concurrency change would move by an order of magnitude.
