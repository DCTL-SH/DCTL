# DCTL — Feature & Completion Status

> **Verified 2026-07-27** against commit `534218b` (`main`, pushed) **plus the current
> working tree**, which builds clean (`cargo build --workspace` → 0 warnings; all test
> binaries compile). This document is descriptive of what the code *actually does today*,
> not aspirational. For design rationale see [PLAN.md](../PLAN.md); for the byte format see
> [FORMAT.md](FORMAT.md); for the plain-storage build plan see
> [PLAIN_STORAGE_PLAN.md](PLAIN_STORAGE_PLAN.md).

## Legend

| Mark | Meaning |
|------|---------|
| ✅ | **Complete & committed** — implemented, tested, on `main`. |
| 🟢 | **Working, uncommitted** — implemented and building in the working tree, not yet on `main`. |
| 🟡 | **Partial** — some paths work; others are refused loudly or pending. |
| ⬜ | **Not started** — planned, no implementation. |
| 🧊 | **Reserved** — an id/slot exists in the frozen format but no code path yet. |

> **Two-speed reality.** The four **library crates are complete and committed**. The
> **CLI (`dctl-cli`) is mid-flight**: the committed CLI is author-flagged WIP, and the
> functionality marked 🟢 below (most plain-remote support) lives in a ~12k-line
> **uncommitted** working-tree delta that builds and tests clean but is not yet on `main`.

---

## 1. What DCTL is

A Rust, rclone-style tool to **copy / sync / move / list / mount / serve** data across
storage backends, where any remote is either **plain** (stored as-is) or a **Vault**
(sealed client-side before it ever leaves the machine). Design promises: a *verified-write*
durability contract ("never report stored until provably stored"), post-quantum-capable
encryption, and **20-year restorability** (data decodable from the format spec alone).

**Workspace:** 8 crates — `dctl-secmem`, `dctl-crypto`, `dctl-meta`, `dctl-store`,
`dctl-index`, `dctl-core`, `dctl-cli`, `dctl-decode`.

---

## 2. Encryption & Vault platform  — ✅ complete (committed)

| Feature | Status | Notes |
|---|---|---|
| XChaCha20-Poly1305 AEAD (buffered **and** constant-memory streaming) | ✅ | `dctl-crypto` `object/`, `object/stream.rs` |
| AES-256-GCM archival profile | 🧊 | `algo`/`wrap_algo = 2` reserved in the frozen format |
| Argon2id KDF envelope (DKE1), **key-committing** slots | ✅ | bounded cost params, anti-downgrade AAD |
| Multiple unlock paths: password **and** BIP-39 mnemonic | ✅ | `Vault::init` writes both slots and returns the phrase; `dctl init` prints it once, `--recovery-phrase` opens any command, `dctl vault recover` rotates the password without disturbing it (`FORMAT.md` §2.1/§2.2) |
| Device-key unlock slot | 🧊 | `slot_type = 0` reserved; no platform-keystore integration exists, and nothing reads or writes one |
| Shamir shared slots | 🧊 | `slot_type = 3` reserved, not specified |
| HKDF-SHA512 domain-separated sub-keys | ✅ | immutable random root key |
| Per-object random DEK, wrapped | ✅ | |
| BLAKE3 integrity (per-chunk AAD + whole-object footer) | ✅ | |
| **Hybrid post-quantum** recipient mode — X25519 + ML-KEM-768 (`kem_id=1`) | ✅ | recipient identity `DRK1`, registry `DRR1`, `put_file_shared` |
| Grants — share/revoke via sidecar (`DGS1`) | ✅ | `kem/sidecar.rs`, `g/<file_id>` |
| Imported external keypairs (`DIK1`) | ✅ | `k/<key_id>`, self-consistency enforced |
| Shared-object discovery (`DGD1`) | ✅ | `d/<recipient>/<file_id>` (findability, not read access) |
| Delegated-upload presign (S3/R2 SigV4, B2 upload-url ticket) | ✅ | offline KAT reproduces AWS's vector byte-for-byte |
| Locked secret memory (mlock / VirtualLock) | ✅ | all `unsafe` FFI quarantined in `dctl-secmem` |

---

## 3. On-disk format & durability  — ✅ complete (committed)

| Feature | Status | Notes |
|---|---|---|
| **v1 format, DESIGN-FROZEN (2026-07-26)** — DKE1 envelope, DSF1 object | ✅ | after 5 adversarial review rounds (11→0 defects) |
| Self-describing objects (embedded wrapped DEK + encrypted metadata) | ✅ | decode from `{secret, envelope, object}` with no index |
| Rename-stable storage (random `file_id`, not path-hash) | ✅ | O(1) renames |
| Name records + UCD-15.1-pinned NFC path validation | ✅ | cross-platform-stable keys; Zip-Slip defense |
| Standalone **C99 reference decoder** + byte-exact KATs | ✅ | `dctl-decode/reference/dctl-decode.c`; the 20-year guarantee (symmetric `kem_id=0` path) |
| Verified-write contract (hash-before-commit; index commit = "it exists") | ✅ | library; CLI wiring 🟢 |
| Anti-rollback / tamper-evident audit log | ✅ | `dctl audit`; tamper-**evident**, not authenticated — integrity and order always, length with an anchor, **authorship never** ([`AUDIT_LOG.md` §11](AUDIT_LOG.md)) |

---

## 4. Index & metadata  — ✅ complete (committed)

| Feature | Status | Notes |
|---|---|---|
| Encrypted index (**SQLCipher**, vendored, no system libs) | ✅ | three-layer keying: keyed-hash + per-row AEAD + whole-DB page cipher |
| Multi-process sharing (WAL) | ✅ | |
| Constant-memory streaming decrypt / `get_file_to_path` | ✅ | O(chunk) atomic write-then-rename |

---

## 5. Storage backends

| Backend | Status | Notes |
|---|---|---|
| Local filesystem | ✅ | verified writes (temp → fsync → read-back → atomic rename) |
| S3 (+ generic S3-compatible) | ✅ | SigV4, streaming `put_from_path`/`get_to_path`, presign |
| Backblaze B2 | ✅ | native API, streaming, upload-url ticket |
| Cloudflare R2 | ✅ | via shared S3 client |
| **SFTP / SSH** | ⬜ | the core plain-storage goal — not started |
| **FTP / FTPS** | ⬜ | not started |
| **WebDAV** | ⬜ | not started |
| **HTTP (read-only)** | ⬜ | not started |

Library-level streaming (`dctl-store/src/streaming.rs`) already moves multi-TiB objects at
O(part-size) memory for the cloud backends — **one** part size, on B2 measured rather than
argued (`B2Backend::upload_peak_bytes()`, HANDOVER §25), and settable per remote with
`chunk_size`.

---

## 6. CLI commands

Status reflects the **working tree** (plain-remote support is 🟢 = uncommitted).
"Single-endpoint" = operates on one remote; cross-remote (remote↔remote) transfer is a
separate gap (§7).

| Command(s) | Status | Notes / blocking capability |
|---|---|---|
| `config`, `version`, `completion` | ✅ | |
| `init` | ✅ | creates a Vault, writes envelope to the base store |
| `ls` `lsd` `lsl` `lsjson` `tree` `size` | 🟢 | plain + Vault enumeration, single-endpoint |
| `cat` | 🟢 | ranged on plain **and** on Vault — a window fetches only its covering chunks (M9) |
| `delete` `deletefile` `rm` `purge` `rmdir` `rmdirs` | 🟢 | plain + Vault |
| `verify` `check` `scrub` `hashsum` | 🟢 | `check` gained read-only remote↔remote; `hashsum` downloads-and-hashes (no remote-native hash yet) |
| `about` | 🟢 | usage / quota / capability |
| `audit`, `index` | ✅ | tamper-evident log (unkeyed — see `AUDIT_LOG.md` §11); index rebuild |
| `rcat` | 🟡 | plain **filesystem** + Vault (spooled); plain object-store streaming write pending |
| `copy` `put` `get` | 🟡 | **local ↔ plain-FS and local ↔ Vault only**; no remote↔remote; >1 GiB refused |
| `sync` | 🟡 | = copy + destination reap; same limits as `copy` |
| `move` `copyto` `moveto` | 🟡 | copy-then-delete; no server-side move |
| `replicate` | 🟢 | ciphertext remote↔remote, **no Vault password** (3-2-1 backups); buffers whole object |
| `cleanup` | 🟡 | staging + orphan sweep; no multipart-abort / version sweep |
| `mkdir` `touch` | 🟡 | real on filesystem; no-op / refused on object stores (prefix-only by design) |
| `backup` `restore` | 🟡 | **Vault only**; `--snapshot` / point-in-time not implemented |
| **`mount`** | ⬜ | **stub** — validates flags then errors `unimplemented`; needs FUSE (VFS) layer |
| **`serve`** | ⬜ | **absent** — no `serve` command; needs a server layer (http/webdav/sftp/ftp/nfs) |

---

## 7. Data movement — transfer engine

| Capability | Status | Notes |
|---|---|---|
| local ↔ local | 🟢 | |
| local → Vault (seal) / Vault → local (open) | 🟢 | verified write + index commit |
| local ↔ plain remote | 🟢 | `PlainUpload` / `PlainDownload` directions |
| **remote ↔ remote (general)** | ⬜ | refused loudly at connect; only ciphertext `replicate` works today |
| Streaming transfers > 1 GiB | 🟢 | constant-memory both directions under a 512 MiB cgroup cap: peak RSS flat at 139–144 MiB from 256 MiB to 4 GiB on `local:` and `sftp:` (HANDOVER §21), and flat at 147 MiB from 99 MiB to 4 GiB on live B2 (HANDOVER §25, where it was 213–218 MiB before B2 stopped holding two parts per upload) |
| Server-side copy / move | ⬜ | needs a backend capability model |
| Parallel transfers / bandwidth limit / retries | 🟡 | `--bwlimit` paces per window inside a file (HANDOVER §21.8); parallelism and request-level retries outside B2 are still open |

---

## 8. Mount & Serve  — ⬜ not started

- **`mount`** (FUSE): stub only. Needs a VFS layer over the backend + `fuser` adapter
  (per-OS: macFUSE / libfuse / WinFSP). The ranged Vault decrypt a Vault mount needs is done (§ M9).
- **`serve`** (http / webdav / sftp / ftp / nfs): no command exists yet.

---

## 9. Cross-cutting  — ✅ / 🟢

| Feature | Status | Notes |
|---|---|---|
| FFI-stable numeric error codes (1xxx crypto / 2xxx store / 3xxx index / 4xxx core) | ✅ | `docs/ERROR_CODES.md` |
| Config & secrets — **no plaintext credentials on disk** (OS keyring + encrypted config) | ✅ | |
| Structured output / `--json` / progress bars | 🟢 | honest per-stage progress |
| Addressing safety (invariant I4: symlink-aware total-path resolution; drive-letter/UNC rules) | 🟢 | dedicated test suite |

---

## 10. Plain-storage rclone parity — milestone status

Against [PLAIN_STORAGE_PLAN.md](PLAIN_STORAGE_PLAN.md) (M1–M10). Note: the current plain
work is an **ad-hoc `dctl-cli`-local implementation** (a `Place` enum + `PlainRemote` fork),
*not yet* the blueprint's `Backend`-capability model — that reconciliation is the M4 pivot.

| Milestone | Status | Notes |
|---|---|---|
| M1 unified resolution + Plain/Vault classification | 🟡 | goals met off-blueprint (`Place` enum, not `classify.rs`) |
| M2 plain enumeration (`ls` family) | 🟢 | paginated `Source` over `Backend::list_page` |
| M3 plain copy/move/cat/delete + remote↔remote | 🟡 | local↔plain done; remote↔remote refusal **still in place** |
| M4 `dctl-ops` + `VaultBackend` (one engine) | ⬜ | the pivot; nothing depends-below it exists yet |
| M5 SFTP/FTP/WebDAV/HTTP backends | ⬜ | the actual rclone plain-storage parity |
| M6 capability-aware server copy/move + track-renames | ⬜ | |
| M7 streaming — retire the 1 GiB limit | ⬜ | |
| M8 `dctl-vfs` + `dctl-mount` (FUSE) | ⬜ | |
| M9 ranged Vault crypto (efficient huge-file mount) | ✅ | `dctl_core::range` — a window fetches only its covering chunks, per-chunk authenticated; bounded decrypted-chunk cache in the CLI. Measured: a 10-byte window costs +1.9 MiB peak RSS above baseline against +97.6 MiB for the whole-object read it replaced (96 MiB object), and stays flat at +2.1 MiB on a 512 MiB object where the whole-object read costs +1025 MiB |
| M10 `dctl serve` | ⬜ | |

---

## 11. Summary — complete vs. not

**Complete & shipped (committed, `main`):**
- The entire **encrypted-Vault platform** — frozen v1 format, streaming AEAD, Argon2id
  envelope, hybrid post-quantum recipient mode, grants/imported-keys/discovery, SQLCipher
  index, locked secret memory, FFI error contract, and a standalone C reference decoder
  with byte-exact KATs.
- Storage backends **local, S3, B2, R2** with streaming and presign.

**Working but not yet committed (working tree):**
- The **plain-local CLI**: enumeration, `cat`, removal, verify/check/scrub/hashsum, and
  `copy`/`sync`/`move` for local↔plain and local↔Vault — builds and tests clean.

**Not done:**
- **Network plain backends (SFTP/FTP/WebDAV/HTTP)** — none exist.
- **General remote↔remote transfer** (only ciphertext `replicate`).
- **`mount`** (stub) and **`serve`** (absent).
- **Streaming beyond 1 GiB in the CLI copy path**, server-side move/copy, snapshots.

**Nearest high-leverage step toward the goal:** commit the in-flight CLI work, then **M4**
(`dctl-ops` + capability model + `VaultBackend`) — every remaining milestone, including the
network backends and mount/serve, depends on it.

---

## Repository state (2026-07-27)

- `main` = `534218b`, pushed to origin; nothing unpushed.
- ~168 uncommitted working-tree entries (the 🟢 CLI work above) — builds/tests clean; pending a clean commit.
- Two accidental scratch dirs at the repo root (`a:site-a/`, `a:site-b/`) awaiting cleanup — not source.
- Wiki published at `…/XSIS/DCTL/wiki` (mirrors `docs/`).
