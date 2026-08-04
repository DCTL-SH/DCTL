# DCTL — Project Plan

> A blazing-fast, secure, Rust-native alternative to rclone: transfer, back up,
> optionally encrypt, and **stream** data across cloud providers — with QMV-grade,
> post-quantum encryption, optimized for **huge video files**, and a hard
> "never report success unless the data is provably, durably stored" contract.
>
> Status: **planning (decisions locked)** · Last updated: 2026-07-26

---

## 0. Locked decisions

- **D1 — storage model:** private per-file overlay + encrypted index, tuned for
  large-file streaming (1 plaintext file ↔ 1 ciphertext object, chunked-AEAD
  inside, seek via HTTP Range). Dedup/backup-repo model **rejected** (kills
  streaming locality, useless on compressed video).
- **D2 — Google Photos:** **dropped** (API blocks reading existing libraries since
  2025-03-31). Launch providers = **Local** + **Backblaze B2** (both done) +
  **Cloudflare R2** (S3-compatible; one `s3` backend covers R2 and future S3-likes)
  + **Google Drive** (OAuth) + **SFTP**; more later. `mount` (FUSE/FSKit/WinFSP)
  and `serve` (HTTP/WebDAV, like `rclone serve`) are crates on top of `dctl-core`.
  The `Backend` trait makes each provider a new impl, not a rewrite.
- **D3 — crypto core:** **clean-room** `dctl-crypto`, streaming-first.
- **D4 — encryption is OPTIONAL:** a remote is **plain** or **vault-wrapped**.
  Plain copy/move/sync is fully supported (rclone-style). The verified-write
  contract (§6) applies to **both** modes. The encrypted form is a **vault**,
  not rclone's `crypt`, because it is not a stateless transformation over a base
  remote: it has identity — a `vault_id` in the envelope, revocable key slots, a
  root key that never changes, an encrypted index, and a hash-chained audit log —
  and borrowing rclone's word would invite the assumption that two remotes
  sharing a password are interchangeable. They are not.
- **D5 — auth:** **one password by default** + optional **second factor** (keyfile
  or hardware key) + a **BIP39 recovery key**. Never two memorized passwords (§8).
- **D6 — day-1 non-negotiables:** verified-write durability contract (§6) and
  strong structured logging + tamper-evident audit + typed error handling (§7)
  ship from the first release, not later.
- **D7 — language:** **Rust** — chosen for deterministic secret zeroization
  (impossible in Go's GC), GC-pause-free streaming latency, and hot-path control.
  *Not* because transfers are "much faster" (those are network-bound in any
  language).
- **D8 — 20-year restorability (day-1 principle):** the data must be restorable in
  two decades even if DCTL, its authors, and today's providers are gone. Rests on
  four pillars — keys survive, format outlives the software, corruption is
  *repairable* (not just detectable), providers are replaceable (§13).
- **D9 — brand-neutral frozen format + latest deps:** the product name is
  centralized (a `dctl-meta` crate) and freely renameable; on-disk format
  identifiers are brand-neutral and frozen forever (`docs/FORMAT.md`). Toolchain =
  Rust **edition 2024**, latest stable crates, kept current via `cargo update` +
  `cargo deny`.
- **D10 — enterprise scale (millions of files):** every operation is streaming and
  constant-memory — no design ever materializes the full file list in RAM. On-disk
  B-tree index, bounded-concurrency pipelines with backpressure, resumable WAL,
  rich CLI + structured progress/logs, professional typed errors (§16).
- **D11 — addressing invariants (I1–I4):** a vault has **two** remote names —
  `archive:` (sealed view) and `archive-store:` (object view) — because §13.3
  requires replicating ciphertext provider-to-provider with **no re-encryption**,
  which is only expressible if the objects have an address of their own. Four
  invariants follow, enforced in `crates/dctl-cli/src/addressing.rs`:
  - **I1** — a write through a vault remote is always sealed; no flag disables it.
  - **I2** — foreign plaintext is never written into a vault's object store.
  - **I3** — a write to an ordinary location is plaintext, fully supported.
  - **I4** — **DCTL never applies or omits encryption because of a destination's
    contents. What a command encrypts is determined solely by the remote name
    typed. A destination's contents may cause DCTL to REFUSE, never to change
    what it does.**

  The outcome space for any destination is `{sealed, plain, refused}`. Contents
  can only ever move an outcome to `refused`; they can never turn `plain` into
  `sealed` or `sealed` into `plain`. That is why the envelope check on an
  unconfigured location is safe, and why it is **not** auto-detection:
  auto-detection *changes behaviour*, this only ever *stops*. A weaker earlier
  wording ("behaviour is a function of the remote name typed, never of the
  destination's current contents") was false — the fallback does read contents —
  and is replaced by the above, which is both true of the code and a stronger
  promise. I4 is a claim about **path spelling** as much as contents: `vault`,
  `./vault`, `/srv/vault`, `staging/../vault`, a symlink and any subdirectory are
  one destination and get one answer. Proven, not asserted, by
  `crates/dctl-cli/tests/invariant_i4.rs`, which asserts on the bytes on disk.

**North star:** maximum security *and* maximum performance for huge video +
streaming, and **never lose or misreport data**. Where security and speed
conflict, expose a documented dial with a secure default.

**Quantum-resistance status (honest, 2026-07-26):** the at-rest path is **entirely
symmetric** (Argon2id + XChaCha20-Poly1305, 256-bit → 128-bit PQ security) and is
therefore **already quantum-resistant** — there is no public-key operation at rest
to break. **ML-KEM-768 is a design goal, NOT yet implemented**; it is only needed
once an asymmetric feature exists (blind backup / sharing). The one live gap is
**TLS in transit** (currently classical rustls), largely mitigated because data is
symmetric-encrypted before transit; enabling hybrid PQ-TLS (`rustls-post-quantum`)
closes it. Do not claim ML-KEM until it ships.

---

## 1. Vision & scope

A Rust CLI (GUI later) to copy/sync, back up, optionally encrypt, and mount/stream
data across a small provider set — like rclone, but with modern PQ, metadata-
private *optional* encryption, a format built for seeking into huge media, and
correctness guarantees rclone doesn't make by default.

**Not** a 70-backend rclone clone — we win on crypto + streaming speed +
correctness on a focused provider set, composing on proven transport (`opendal` /
custom Drive client), not rebuilding it.

---

## 2. Modes: plain vs encrypted (D4)

The transfer pipeline is `read → [hash] → [encrypt?] → [checksum] → upload →
verify → commit`. The encrypt stage is optional and per-remote:

| | Plain remote | Encrypted (vault) remote |
|---|---|---|
| Object names | preserved (overlay) | opaque, from encrypted index |
| Metadata privacy | none (like rclone) | filenames/structure hidden |
| Integrity check | plaintext hash vs provider checksum | ciphertext hash vs provider checksum **+** recorded plaintext BLAKE3 |
| Streaming seek | native Range | chunk-aware Range + decrypt |
| Verified-write contract (§6) | **yes** | **yes** |

Cross-mode transfers work: `plain→vault` encrypts on upload, `vault→plain`
decrypts on download. Encryption never weakens the durability contract.

---

## 3. Streaming-first storage model (encrypted remotes)

```
Plaintext video (50 GB)                 One ciphertext object in B2
┌───────────────────────┐   encrypt →   ┌────────────────────────────────────┐
│ bytes 0 … 50e9        │               │ [auth header][chunk 0]…[chunk N]     │
└───────────────────────┘               │  opaque name · per-file random DEK   │
Seek 45:00 → chunk_idx = off/CHUNK → HTTP Range fetch → decrypt → serve. No full DL.
```

- **One object per file** (contiguous → best sequential/seek behavior).
- **Chunked AEAD**, tunable (default **4 MiB** media profile; 64 KiB small-file).
- **Encrypted `redb` index**: `path → {opaque key, wrapped DEK, size, mtime,
  chunk layout, plaintext BLAKE3}` — hides names/structure, keeps seek O(1), and
  is the **source of truth for what is "really" stored** (see §6).
- **Read-first mount**; read-write POSIX is a later scoped phase.

---

## 4. Layered architecture

```
CLI (clap)  │  GUI later (Tauri)
────────────────────────────────────────────────────────────
copy · move · sync · backup · restore · mount · ls · verify · check
────────────────────────────────────────────────────────────
Sync/transfer engine   │  Mount/VFS (fuser)   │  Encrypted index (redb)
  verified-write SM,    │  streaming reader,   │  + local WAL/journal
  pacer, retry, resume  │  prefetch, Range,    │  + tamper-evident audit log
                        │  encrypted LRU cache │
────────────────────────────────────────────────────────────
dctl-crypto (optional, streaming-first, PQ)  │  Chunked AEAD engine
────────────────────────────────────────────────────────────
Backend trait: put/get(Range)/list/del/multipart + per-part & whole-object checksum
  ├─ Backblaze B2 (primary)   ├─ Google Drive (secondary)   └─ Local FS (dev/test)
```

Workspace crates: `dctl-crypto`, `dctl-store`, `dctl-core`, `dctl-mount`,
`dctl-cli`, (later) `dctl-gui`.

---

## 5. Crypto design (`dctl-crypto`, clean-room, streaming-first)

- **KDF:** Argon2id 128 MiB / t=3 / p=4 (desktop profile).
- **Keys:** random 32-byte root key (never changes), wrapped by password-KEK in an
  atomic envelope; **per-file random DEK**; HKDF-SHA512 domain-separated subkeys
  (index, cache, per-file, audit).
- **AEAD:** XChaCha20-Poly1305 default; cipher-agile **AES-256-GCM** on AES-NI.
  Algorithm id in the authenticated header.
- **Chunk format:** `nonce = base ⊕ counter`; `aad = file_id ‖ chunk_index`;
  authenticated header `{plaintext_len, chunk_size, chunk_count, algo, DEK-wrap,
  KDF params, plaintext_blake3}` → truncation/rollback detected without reading
  the file.
- **Streaming integrity:** per-chunk Poly1305 is the hot-path guarantee; whole-
  file BLAKE3 footer verified only on `verify`/download/backup, never while
  streaming.
- **Post-quantum:** ML-KEM-768 (FIPS 203) hybrid DEK wrap + `rustls-post-quantum`.
- **Encrypted on-disk cache** (default on); `--pad` optional size-bucketing.
- **Hygiene:** `zeroize`/`Zeroizing`, memlock, `subtle` const-time, key-
  fingerprints in logs only.

---

## 6. Verified-write durability contract (D6, day-1 — the core promise)

**Invariant: DCTL reports "copied/moved" ONLY after the data is checksum-verified
on the destination AND durably committed to the index. `move` NEVER deletes the
source before that.** No partial state is ever surfaced as success.

Per-file pipeline (both plain and encrypted):

1. **Preflight** — stream-read source, compute plaintext BLAKE3 + size.
2. **Encrypt** (if crypt remote) into chunks; compute the checksum the provider
   will verify (B2: per-part + whole SHA1; S3/B2-S3: per-part CRC32C/SHA256).
3. **Stage upload** to a *temporary* object key via multipart. Each part's
   checksum is verified by the provider on ingest; a bad part is rejected and
   retried — corrupt bytes can't land.
4. **Finalize & verify (mandatory)** — provider returns the stored object's
   checksum; compare to the locally computed value. **Mismatch ⇒ hard-abort:**
   delete the staged object, log a `checksum-mismatch` error, leave source
   untouched. We trust the provider's durable ACK *only after* the match.
5. **Optional strong verify** — `--verify`: `checksum` (default, step 4 only) ·
   `sample` (Range-read + decrypt N random chunks, confirm plaintext hash) ·
   `strict` (full read-back + decrypt, confirm whole-file BLAKE3).
6. **Durable commit** — write the index entry (path→object, DEK, hashes, size,
   mtime, chunk map) in a single **`redb` ACID transaction + fsync**; for a cloud
   index, bump a **monotonic generation** with a conditional put. *This commit is
   the only thing that makes the file count as "stored."*
7. **`move` only:** after the commit is durable, delete the source. `copy`: done.
8. **Emit success + append an audit-log entry** (§7).

**Supporting guarantees**
- **Atomicity:** visibility is gated by step 6; a crash anywhere in 1–5 leaves no
  "successful" record and no touched source. Staged temp objects and incomplete
  multiparts are GC'd/aborted on the next run (and by a bucket lifecycle rule).
- **Crash recovery / WAL:** an on-disk journal records in-flight ops so a restart
  resumes exactly or rolls back cleanly; re-runs are idempotent.
- **Concurrency:** an index lock (flock) + per-object leases prevent two DCTL
  processes from racing.
- **Local-FS destinations:** fsync the file *and* its directory before success
  (same discipline as the index write).
- **Read path:** every download/stream verifies per-chunk AEAD (+ plaintext hash
  on `verify`); an integrity failure is loud, never served as data.

---

## 7. Logging, audit & error handling (D6, day-1)

**Structured logging** (`tracing`): a span per operation/file, structured fields,
human + JSON sinks, levels. **Redaction is mandatory** — keys/tokens never logged;
secrets appear only as BLAKE3 fingerprints (e.g. `dek_fp=…`).

**Tamper-evident audit log:** append-only, **hash-chained** (each entry carries
the previous entry's hash) record of every copy/move/delete/verify — timestamp,
files, plaintext+ciphertext hashes, sizes, provider, result. Optionally mirrored
encrypted to the remote. Lets you *prove* what happened and detect log tampering.

**Typed error taxonomy** (`thiserror`), no silent failures:
- **Transient** (network, timeout, 429, 5xx) → exponential backoff + jitter,
  capped retries, then surface.
- **Permanent** (auth, quota exhausted, **checksum-mismatch**, decrypt/AEAD
  failure, corruption) → **hard fail, never swallowed**, source preserved.
- **Fatal** (config, disk full on cache) → stop with a clear message.
- Stable **error codes** + remediation hints (`docs/ERROR_CODES.md`), deterministic
  process **exit codes** for scripting.
- **Never** report partial/unverified work as success (this is enforced by §6).

---

## 8. Authentication & key model (D5)

- **Default: one password** → Argon2id → KEK, which only *wraps* the root key
  (cheap password change, never a re-encrypt).
- **Optional second *factor* (not a second password):** keyfile (64 B CSPRNG) or
  hardware key (YubiKey) → `KDF_input = password ‖ H(factor)`. True 2FA-at-rest
  ("know" + "have"), far more entropy than any password, better UX than two
  memorized secrets.
- **Recovery key (always):** a BIP39 mnemonic generated at init that independently
  unwraps the root key — a forgotten password ≠ permanent data loss. Store offline.
- **Separation:** the encryption password is client-side only and is **never** the
  same as any future account/login credential.
- **Provider secrets** (OAuth tokens, B2 app keys) stored via the OS keychain
  (`keyring`) + encrypted config — never plaintext on disk.

---

## 9. Tech stack

| Concern | Choice |
|---|---|
| Runtime / CLI | `tokio`, `clap` (derive) |
| HTTP / backends | `reqwest` (rustls, HTTP/2), `opendal` (B2/S3), custom Drive |
| OAuth | `yup-oauth2` |
| Crypto | `chacha20poly1305`, `aes-gcm`, `argon2`, `hkdf`, `sha2`, `blake3`, `zeroize`, `subtle`; PQ: `ml-kem` + `rustls-post-quantum` |
| Checksums | `sha1` (B2), `sha2`/`crc32c` (S3), `blake3` (plaintext) |
| Index / WAL | `redb` (ACID) as an AEAD blob + append-only journal |
| Mount | `fuser` (+ macFUSE/`fuse-t`, WinFSP) |
| Secrets | `keyring` + encrypted config |
| Logs / errors | `tracing`, `thiserror` + `anyhow` |
| Test / bench | `criterion`, `proptest`, `cargo-fuzz` |
| GUI (later) | `Tauri` |

---

## 10. Performance strategy (streaming huge video)

Range-based seek (fetch only needed chunks) · parallel prefetch/readahead ·
4 MiB media chunks · parallel resumable multipart · cipher-agility (ChaCha default,
AES-NI when present) · SIMD BLAKE3 · zero-copy `bytes` · encrypted LRU chunk cache
· quota-aware pacer · release profile `lto="thin"`, `codegen-units=1`,
`panic="abort"`.

---

## 11. Roadmap (durability + logging are day-1, not deferred)

**A phase is delivered when its capability works end to end.** A command that
parses its arguments and then refuses is not delivery; neither is a backend that
compiles but has never been pointed at the provider it names. The status column
below is written to that rule, because a roadmap that marks a phase done on the
strength of a refusal is the same misreport §6 forbids, moved up a level.

- **Phase 0 — Foundations:** workspace; `dctl-crypto` (clean-room streaming AEAD,
  KDF, envelope, recovery); **verified-write state machine + WAL + audit log +
  error taxonomy + `tracing`**; auth/key model; `Backend` trait w/ Range +
  checksums; local-FS backend; proptest + fuzz.
  → **Delivered, except the second factor.** The envelope, the verified-write
  state machine, the audit chain, the error taxonomy and the local-FS backend all
  work end to end, and §8's recovery key is real: `dctl init` issues a BIP-39
  phrase, `dctl vault recover` opens a vault with it, and `--recovery-phrase`
  unlocks any command. **`--key-file` is refused** — the engine still derives the
  key from the password alone, so the "know + have" half of §8 is outstanding and
  this phase is not closed.
- **Phase 1 — B2 MVP:** B2 backend (multipart + per-part checksums), `copy`/`move`/
  `sync` in **both plain and crypt** modes with the full §6 contract, encrypted
  index, `ls`/`verify`/`check`.
  → **Partially delivered, and the unverified part is the provider.** Against
  `local:` and a vault the phase is complete: the encrypted index, `ls`/`verify`/
  `check`, and `copy`/`move`/`sync` in both plain and crypt modes all work under
  the §6 contract, as do the listing, removal and audit families. **Nothing has
  been exercised against live B2, S3 or R2.** Those backends compile and are
  reachable, and a missing credential is the only thing that stops a run today —
  which is exactly the state that looks like success from inside the repository.
  Remote↔remote transfer is refused in both directions. Until one real bucket
  round-trips, this phase is not delivered.
- **Phase 2 — Streaming mount:** `fuser` read-first VFS, Range reader, prefetch,
  encrypted cache — play a huge encrypted video straight off B2.
  → **Not delivered, but no longer empty.** The **Range reader** exists and is
  used: `dctl_core`'s ranged read fetches only the chunks a window covers,
  authenticated per chunk, behind a bounded decrypted-chunk cache in the CLI — so
  `dctl cat --offset` on a large object no longer pays for the whole object. What
  is missing is the part the phase is named for: there is no `dctl-mount` crate
  and no FUSE/FSKit/WinFSP adapter, so `dctl mount` parses every argument it owns
  and then refuses. No file has been played off a mount, which is the test this
  phase has to pass.
- **Phase 3 — Google Drive:** OAuth, resumable, 750 GB/day pacer + quota/backoff.
  → **Not started.** `dctl config providers` lists `local`, `b2`, `s3` and `r2`
  only.
- **Phase 4 — Hardening:** `--pad`, snapshots/versioning (optional), crash-
  consistency test suite, format fuzzing, external-audit prep.
  → **Not delivered.** There is no `--pad` flag; `restore --at`/`--snapshot` and
  `backup --snapshot` refuse, naming the single-current-version index as the gap;
  `cleanup --class versions` reports `unsupported` on a backend that cannot
  enumerate versions.
- **Phase 5 — GUI + providers.**
  → **Not started.**

---

## 12. Risks & honest constraints

- **Security ⇄ speed dial (explicit):** per-chunk auth always on; whole-file verify,
  `--verify=strict`, and `--pad` cost bandwidth → opt-in / off the hot path;
  encrypted cache on by default.
- **Verify vs egress cost:** full read-back verify on huge video doubles egress →
  default is provider-checksum verify (still strong); `sample`/`strict` opt-in.
- **Google Drive weak for huge data:** 750 GB/day cap, per-file limits, quotas →
  B2 is the real home; Drive is interop.
- **Read-write encrypted mount is a filesystem project** → v1 is read/stream-first.
- **Clean-room crypto = new bug surface** → proptest, `cargo-fuzz`, KATs, planned
  third-party audit before wide release.
- **Rust ≠ faster transfers** (network-bound); its wins here are security
  determinism + latency + control. Don't sell speed we won't deliver.
- **Don't out-breadth rclone** — few providers, lean on `opendal`.

---

## 13. Long-term durability — 20-year restorability (D8, day-1 principle)

Encryption + AEAD **detect** corruption but cannot **repair** it, and strong crypto
makes **key loss** and **format/software obsolescence** the real long-term enemies —
not the algorithms (AES/ChaCha/SHA/Argon2 will still decode in 2046). Four pillars:

### 13.1 The data outlives DCTL (format independence)
- **Open, versioned, formally documented on-disk spec** (`docs/FORMAT.md`) — the
  data is reconstructable from documentation alone, with no DCTL binary.
- **Self-describing objects:** each object header carries magic, format version,
  algo ids, KDF params, chunk layout **and its own encrypted metadata** (original
  path, mtime, size, plaintext BLAKE3). Given only the key, a single object is
  decryptable **standalone, without the index.** The index is a fast cache +
  privacy layer, never a single point of failure.
- **Reference decoder — dependency-free C99 (decided 2026-07-26):** `dctl-decode`
  is a single self-contained C99 file with no build system and no external libs
  (crypto primitives inlined from public-domain reference code). Rationale: a lone
  `.c` file is the artifact most likely to still compile in 2046 — a C compiler is
  the most certain tool to exist, and it depends on nothing but libc, unlike a Rust
  build (rustup + edition + crates.io). Use C **exactly here and nowhere else** —
  the production tool stays Rust; the break-glass decoder is C, its unsafe surface
  tiny, read-only, and auditable. **Non-negotiable companion:** the C decoder is
  cross-validated against the Rust implementation via a **known-answer-test corpus**
  run in CI — two independent implementations agreeing on the KATs is the strongest
  proof the format spec is complete. Decode auth is per-chunk Poly1305 (which covers
  header + chunk index + data); the redundant BLAKE3 footer is not re-verified in C,
  keeping the file free of a BLAKE3 port. Primitives: XChaCha20-Poly1305 (always) +
  Argon2id (password→KEK). The ML-KEM PQ-wrap path is the one heavy piece and is
  handled by the classical password path first (blind/PQ objects: later).
  **STATUS: implemented + verified** (`crates/dctl-decode/`). Streams the object
  (constant memory), single-threaded Argon2id, params-from-envelope + clamped,
  const-time tag compare. KATs pass: Argon2id vs the official RFC 9106 vector
  (independent of both implementations), full-chain vs Rust across boundary sizes,
  and negative vectors rejected. TODO for maximum rigor: commit *frozen* DCTL
  vectors (not regenerated at test time) + one vector hand-derived from FORMAT.md.
- **Standardized primitives only** (RFC/FIPS): AES-256-GCM (FIPS), ChaCha20/
  XChaCha20-Poly1305 (RFC 8439), SHA-256/512, HKDF (RFC 5869), Argon2id (RFC 9106),
  ML-KEM (FIPS 203) — many independent implementations will exist in 20 years, so
  the data is decodable by non-DCTL code if ever needed. Archival mode may pin
  AES-256-GCM as the "maximally standard" cipher.

### 13.2 Keys survive 20 years (the #1 risk)
- One root key, several independent **unwrap paths** (any one recovers it):
  password (+optional factor), **BIP39 recovery mnemonic**, and **Shamir's Secret
  Sharing** (K-of-N shares to trusted people / safe-deposit / lawyer).
- **Paper backup** of the mnemonic/shares — paper outlives any specific token, app,
  or cloud account. Recovery is documented in the spec, so it never depends on DCTL.

### 13.3 Corruption is repairable, not just detected
- **Redundancy (3-2-1):** ≥2 independent providers + ≥1 offline/cold copy (drive /
  LTO). Objects are provider-neutral → replicate/migrate with no re-encryption.
- **Forward error correction:** optional par2-style Reed-Solomon parity per object
  now (repairs N bad chunks in place); **cross-provider erasure coding** (survive a
  provider vanishing at < full-replication cost) as a later phase.
- **Integrity manifest:** plaintext + ciphertext BLAKE3 recorded → end-to-end
  verification of any object at any time.

### 13.4 Proactive scrubbing (find rot early, not on restore day)
- Scheduled `dctl scrub`: re-read + verify checksums/AEAD across the whole dataset,
  **repair from redundancy/FEC** on mismatch, report health (ZFS-scrub / restic-
  check discipline). Never discover corruption for the first time during a restore.

### 13.5 Index & provider resilience
- Index is versioned (monotonic generation), replicated, snapshot-backed, and
  **rebuildable by scanning object headers** (each object self-describes) → a lost
  index never means lost data. Provider-agnostic objects + one-command migration.

### 13.6 Tested restore (a backup you never restored isn't a backup)
- First-class `restore` + `check`; periodic **full-restore drills**; CI restore
  tests against golden fixtures **and old-format fixtures** — backward-compatible
  readers are **never** dropped (unlike QMV's pre-prod v1 drop; a 20-year tool must
  read every format version it ever wrote, forever).

---

## 14. Configuration & secrets (yes — but not rclone.conf's plaintext model)

DCTL has a config file, but deliberately fixes rclone.conf's biggest weakness:
rclone stores provider creds and crypt passwords in the file, only *"obscured"*
with reversible obfuscation (anyone with the file recovers them). Unacceptable for
a security-first tool.

- **`~/.dctl/config.toml`** (TOML, one home for everything, `--config`/`DCTL_CONFIG`
  override, enforced `0600`, warns if world-readable): **non-secret** settings only
  — named remotes (type, endpoint, bucket, region), vault-remote wrapping, chunk
  sizes, cache dir/size, verify policy, mount defaults, pacer/quota limits.
  Human-editable, version-controllable.
- **Remotes model (rclone-like):** named remotes; a **vault remote wraps a base
  remote** (`b2prod` plain → `vault:` = a vault over `b2prod`; `type = "vault"`
  in the file, never `crypt`, per D4). Multiple vaults/profiles supported.
- **Secrets never in the config:**
  - Provider creds (OAuth tokens, B2 app keys) → **OS keychain** (`keyring`:
    macOS Keychain / Windows Credential Manager / Linux Secret Service). Headless
    fallback → an **encrypted secrets file** sealed with a dedicated key.
  - **Encryption password/keys are never stored** by default — prompted, or via
    env/keychain/an **unlock-agent** (ssh-agent-style, derived key held in mlock'd
    memory for a session).
- **Fully headless-capable:** every setting has a CLI flag + env var, so servers
  run DCTL non-interactively (no interactive config step required).
- **Documented in the FORMAT spec** so a 20-year restore never depends on
  reverse-engineering the config.

---

## 15. Cross-platform encrypted mount + performance (mac / Windows / Linux)

Honest framing: **decryption is not the bottleneck** (ChaCha/AES-NI push multi-
GB/s); backend **latency/bandwidth** is. So mount performance = **latency hiding**,
and the design optimizes the **sequential/streaming** case (video) hard. Random
4K-heavy workloads (DBs, many tiny files) over a network mount will never rival
local SSD — not the target.

**Per-platform filesystem backend**

| OS | Backend | Notes |
|---|---|---|
| Linux | FUSE3 (`fuser`) | writeback cache, large `max_read`/`max_write`, multithreaded, big readahead; `io_uring` cache layer later |
| macOS | **macFUSE** (shipped) → FSKit (15+) → fuse-t | macFUSE 5 works and is what this build mounts with — see below. FSKit = Apple-sanctioned userspace FS, no kext = 20-year-safe, but has no Rust binding; fuse-t (NFS-loopback, no kext) likewise |
| Windows | **WinFSP** (Dokan alt) | mature FUSE-like layer; **ProjFS** an option for read-first streaming virtualization |

**The macOS ranking, re-stated (2026-07-31)**

This table used to read *FSKit → fuse-t → macFUSE*, on the reasoning that a kext
is a liability worth paying to avoid. That order was written before anything had
been mounted on a Mac, and the code now contradicts it, so it is re-stated here
rather than left to be discovered.

**macFUSE is first because it is the one that works, and the reason the others
were ranked above it does not apply to a decision this build can take.** FSKit
and fuse-t are both preferable in the abstract and neither has a Rust binding: to
reach FSKit DCTL would have to ship a Swift extension in an app bundle, and
fuse-t speaks NFS loopback rather than the FUSE protocol `fuser` implements. So
the choice was never macFUSE *versus* those two; it was macFUSE or no mount on
macOS at all.

What changed is that the obstacle turned out to be a dependency setting rather
than a wall. `fuser`'s `build.rs` gates its pure-Rust mount to a hardcoded OS list
that excludes macOS and falls through to a macFUSE-4 path that fails against
macFUSE 5. Its **`macos-no-mount`** feature compiles the protocol and session
layers with no mount implementation at all, and DCTL performs the mount itself
through macFUSE's own setuid helper — which is the interface, not a workaround:
`mount(2)` is root-only on macOS and macFUSE's argument struct is private, so
macFUSE's own libfuse does exactly this. `#![forbid(unsafe_code)]` is intact.

Verified live on macOS 27 / macFUSE 5.3.3 (arm64), 64 MiB and 256 MiB objects in
a real vault: correct listings and sizes; byte-identical reads; the seek test
below; `EROFS` on every mutating operation; clean detach under `SIGINT`,
`SIGTERM`, `umount` and `diskutil unmount`, including with a read in flight.

FSKit stays on the list. It remains the right long-term answer for the same
reason it always was, and the work it needs is a Swift extension and an app
bundle, not a mount fix.

**What the seek test measures on macOS**

The property the format exists for, measured at the store rather than inferred
from a clock: a 1 MiB read at offset 32 MiB of a 64 MiB object, read-ahead off,
costs **1.031 MiB of store traffic — 1.6% of the object**. With the default 16 MiB
`--buffer-size` the mount additionally warms exactly sixteen chunks, once, which
is the read-ahead the flag names and not a whole-object fetch.

Two macOS-specific findings worth carrying, because neither is visible on Linux:

- **A repeated read never reaches the filesystem.** macFUSE lets the kernel hold
  the pages, so "the second read is faster" is the page cache, not DCTL's chunk
  cache — measured as **0** FUSE `READ` operations arriving for an identical
  re-read. The chunk cache is real and is worth what it claims, but it has to be
  measured where the page cache cannot answer: a read 8 MiB further into the
  warmed window costs **0.000 MiB** from the store, against 1.016 MiB with
  read-ahead off.
- **Finder needs `--allow-root`.** At the default ACL every shell operation
  works and `open` fails with `error -36`, because opening a volume goes through
  LaunchServices and LaunchServices reaches the mount as root. Widening the
  default would widen who can read an unlocked vault, so the flag documents it
  instead.

**Streaming-mount performance (all platforms)**
- **Aggressive prefetch/readahead:** serve chunk _k_ while fetching _k+1…k+P_;
  window sized to bandwidth-delay product, adaptive to observed throughput.
- **Chunk↔read alignment:** 4 MiB AEAD chunks aligned to kernel readahead so a
  player's sequential reads map to whole-chunk fetches (no partial-chunk waste).
- **Two-tier cache:** bounded **mlock'd in-RAM LRU of decrypted hot chunks** (cuts
  re-decrypt on rewind/seek) over an **encrypted on-disk LRU** (persists across
  mounts; plaintext never hits disk).
- **Zero-copy** decrypted buffers into FUSE/WinFSP replies; multithreaded so
  parallel opens/seeks don't serialize.
- **Per-platform kernel knobs:** Linux `max_readahead`/BDI; macFUSE `iosize`;
  WinFSP cache sizing.
- **Read-first for v1**; full random-write encrypted mount (re-chunk + journaled
  writes) is a later scoped phase.

---

## 16. Engineering principles — scale, structure, extensibility (D9, D10)

Built as an enterprise tool from day one: handle millions of files smoothly,
extend to new storages and native GUIs without rewrites, and fail professionally.

### 16.1 Code organization (scalable workspace)
Clear crate boundaries with a one-way dependency direction, so features/storages/
UIs bolt on without touching the core:
```
dctl-meta    branding (app/bin name, config dir, env prefix) — single source, renameable
dctl-crypto  encryption core (done)                    ← depends on nothing app-specific
dctl-store   Backend trait + provider impls (B2, Drive, local)
dctl-index   encrypted on-disk index + WAL + audit log
dctl-core    sync/transfer engine, verified-write state machine, VFS logic
dctl-mount   FUSE/FSKit/WinFSP adapters
dctl-cli     the `dctl` binary
dctl-ffi     UniFFI bindings  ─┐  (later — GUIs reuse the exact same core)
dctl-gui     Tauri app        ─┘
```
Extensibility via **traits, not branches**: `Backend`, `Cipher` (algo-agility),
`Index`, and `Vfs` are trait objects — adding a provider or cipher is a new impl,
never an edit to the engine (open/closed principle).

### 16.2 Scaling to millions of files
- **Streaming everything:** directory walks, listings, sync diffs, and transfers
  are iterators/streams — the full file set is **never** held in RAM. Memory stays
  ~O(concurrency), not O(files).
- **On-disk index:** `redb` B-tree with cursors/pagination; range scans, not full
  loads. Index writes are batched ACID transactions; the index is generation-
  versioned and shardable.
- **Bounded-concurrency pipeline:** a work-stealing scheduler with a fixed worker
  pool + **backpressure** (bounded channels) so a 10M-file job uses steady memory
  and never overwhelms a provider; a quota-aware pacer throttles per-remote.
- **Resumable + idempotent:** a WAL journals in-flight work; interrupt a 10M-file
  run and it resumes exactly where it stopped.

### 16.3 Rich CLI
`clap` subcommand tree; every command supports `--json`/`--format` machine output
(pipeable, scriptable), live `--progress` (indicatif: rates, ETA, per-file +
aggregate), `--quiet`/`-v/-vv`, `--dry-run`, stable **exit codes**, and generated
shell completions. Long jobs stream structured progress events consumable by the
future GUI.

### 16.4 Observability
`tracing` spans per operation with structured fields; human **and** JSON log sinks;
counters/metrics (bytes, files, retries, throughput); the hash-chained audit log
(§7). Mandatory secret redaction — only BLAKE3 fingerprints, never keys.

### 16.5 Professional error handling
`thiserror` typed errors per crate, `anyhow` context at the app edge; stable error
codes + remediation (`docs/ERROR_CODES.md`); **zero `unwrap`/`panic`/`expect` in
library code**, enforced by `#![deny(clippy::unwrap_used, clippy::expect_used,
clippy::panic)]`. Partial-batch failures are reported precisely (which file, which
stage) and never rolled up into a false success.

### 16.6 Quality gates (CI from the start)
`cargo clippy -- -D warnings`, `cargo fmt --check`, unit + property tests +
`cargo-fuzz` on the format + known-answer vectors, `cargo deny`/audit for supply
chain, pinned MSRV/edition, and a scheduled external crypto audit before GA.
