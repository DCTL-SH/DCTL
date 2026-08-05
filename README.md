# DCTL

> ## ⚠️ Not ready for production
>
> **DCTL is under active development and is pre-1.0. Do not use it as the only
> copy of data you cannot afford to lose.**
>
> This is not a disclaimer of the ordinary kind. The specific things you should
> know before trusting it with anything:
>
> - **The cryptography has had no independent audit.** The design is documented
>   in full and the implementation is open to inspection, but nobody outside
>   this project has reviewed it. Until someone has, treat the security
>   properties as claimed rather than verified.
> - **Mounted vaults are read-only.** Every write operation through a mount is
>   refused explicitly; the read-write path is not implemented yet.
> - **Windows has never been executed.** The code exists and compiles in CI, but
>   no release has been run on Windows by anyone.
> - **Interfaces will change.** Commands, flags and output formats are not
>   stable before 1.0.
>
> **What is stable is the on-disk format.** It is frozen, specified in full in
> [`docs/FORMAT.md`](docs/FORMAT.md), and licensed under Apache 2.0 together
> with a standalone C reference decoder — so data written today stays readable
> with or without this tool, and with or without the company behind it. That
> separation is deliberate: the format is a promise, the tool is still software
> being written.
>
> Keep independent backups. Verify restores before you rely on them —
> `dctl restore` and `dctl verify` exist for exactly that, and
> [`docs/RESTORE_DRILL.md`](docs/RESTORE_DRILL.md) is the drill.


**Encrypted multi-cloud backup and transfer that never reports a file stored until it provably is.**

DCTL copies, syncs and streams data between local disks and cloud object
storage — S3, Backblaze B2, Cloudflare R2, SFTP — encrypting every byte on your
own machine before it leaves it. Each write is read back and checked at the
destination before it counts, so a run that reports success has demonstrated it,
and a run that could not finish says so with an exit code rather than leaving a
silent gap.

Its command surface is **inspired by rclone** — `copy`, `sync`, `check`, `ls`,
`mount`, and filter and addressing rules that behave the way you would expect if
you have used it. What differs is underneath: a self-describing encrypted object
format, a tamper-evident audit chain over what was done, and post-quantum key
wrapping for data that has to stay confidential for decades.

Written in Rust, built for large media — multi-gigabyte video, disk images —
and around a single hard promise: *a run that says a file is stored is telling
the truth.*

> The name **DCTL** is a working title, centralized in one crate (`dctl-meta`) so
> it can be changed later. On-disk **format identifiers are deliberately
> brand-neutral and frozen** (see
> [`crates/dctl-decode/FORMAT.md`](crates/dctl-decode/FORMAT.md)) — renaming
> the product never touches the format, and a vault written today stays readable
> whatever the tool ends up called.

---

## What DCTL is

The verbs and the addressing will be familiar to anyone who has used `rclone`,
which is deliberate — there is no reason to make people relearn `copy`, `sync`,
`cat`, `mount` and a filter syntax that already works. The difference is what
happens to the bytes: every one written to a provider is **encrypted
client-side** in a frozen, self-describing format, and every write is
**verified at the destination before it is reported as done**.

**Who it is for.** People who want provider-independent, end-to-end-encrypted
backup and transfer with a durability contract they can audit — homelab and
self-hosting operators, media archivists, and anyone who needs their data to
still decrypt in 20 years and to survive the day a large quantum computer exists.

## Headline guarantees

- **Verified-write** — nothing is reported stored until its bytes are
  checksum-verified at the destination *and* durably committed to the local
  index; a mismatch hard-aborts, deletes the staged object, and commits nothing
  (no half-stored files, no false "copied").
- **Constant-memory streaming** — files of any size upload and download in
  bounded memory via chunked AEAD and constant-memory multipart, so a 50 GB video
  never has to fit in RAM.
- **Cross-device restore** — the backend is authoritative; a fresh machine with
  *only the password* runs `dctl index rebuild vault:` to rescan the backend's
  encrypted name records and reconstruct the path→object map, then restores
  byte-exact. Proven by a real CLI smoke test.
- **20-year restorability** — a dependency-free C99 reference decoder plus
  Known-Answer-Test cross-validation prove the frozen format can be decoded with
  no Rust, no DCTL, and no network far into the future.
- **Post-quantum ready** — the asymmetric sharing layer wraps recipients with an
  X25519 + ML-KEM-768 hybrid (X-Wing-style combiner), giving harvest-now,
  decrypt-later resistance today.

## Feature status

Honest status — `Done` means implemented and exercised, `WIP` means partial or
under active refactor, `Planned` means specified but not built.

| Area | What it is | Status |
|------|-----------|--------|
| **Crypto core** (`dctl-crypto`) | Argon2id (RFC 9106, calibrated), XChaCha20-Poly1305, HKDF-SHA512, BLAKE3, key-committing AEAD | Done (`#![forbid(unsafe_code)]`, unit + property tested) |
| **Frozen v1 format** | DKE1 envelope, DSF1 streaming object, §5 name records — design-locked | Done — see [`crates/dctl-decode/FORMAT.md`](crates/dctl-decode/FORMAT.md) |
| **Local backend** | `LocalFs` provider, verified writes | Done (fully exercised) |
| **B2 / S3 / R2 backends** | `Backend` trait, constant-memory multipart, presigned uploads | Implemented — **live end-to-end NOT yet verified** (integration tests are `#[ignore]` + env-gated) |
| **Encrypted index** (`dctl-index`) | SQLCipher (bundled), metadata-private, WAL, multi-process | Done |
| **CLI** (`dctl-cli`) | `init`, `copy`/`copyto`/`sync`, `cat`, `ls*`, `verify`, `index rebuild`, … | **WIP** — happy path smoke-tested; some verbs partial, 1 known WIP-failing test |
| **Asymmetric sharing** | `kem_id=1` hybrid recipient wrap, grant sidecars (add/remove without re-upload) | Done (assumes a **shared** backend) |
| **Shared-object discovery** | DGD1 discovery (`discover_shared` / `get_shared`) | Done |
| **Imported keys** | DIK1 imported-key store, multi-identity open | Done |
| **`mount`** | Read-only FUSE mount of a vault: chunk-ranged reads, inferred directories, `EROFS` on every write | Implemented on Linux (FUSE3) and macOS (macFUSE); Windows refuses by name (needs WinFSP). **Attached against a live kernel on macOS**: macFUSE 5.3.3 / macOS 27, mounted, listed, read byte-for-byte including a mid-file seek, writes refused, and unmounted with the mountpoint confirmed free. The Linux path is unit-tested end to end over a real backend |
| **Reference decoder + KAT** (`dctl-decode`) | Dependency-free C99 decoder + cross-validation | Done |

See [the project status](https://doc.dctl.sh/project/status) for the current
per-area detail and the full list of known caveats.

## Quick start

Requires a recent stable Rust toolchain (edition 2024, `rust-version = 1.85`;
`rustup update` for the latest).

```sh
# Build the workspace and the `dctl` binary
cargo build --release
export PATH="$PWD/target/release:$PATH"
```

The sequence below mirrors the verified smoke test: create a vault on a local
backend, store a file, read it back, then **throw the index away and rebuild it
from the backend alone** — the cross-device restore path.

```sh
# Password comes from the environment; config + index are kept out of the way
# in a scratch dir so the example is self-contained.
export DCTL_PASSWORD='correct horse battery staple'
D=$(mktemp -d)
FLAGS="--config $D/config.toml --index $D/index.redb"

# 1. Create a vault backed by a local directory.
#    This registers two remotes: `vault:` (sealed/encrypted view) and
#    `vault-store:` (the raw ciphertext objects on the backend).
dctl $FLAGS init --name vault --base "local:$D/store"

# 2. Store a file under an exact name (everything through `vault:` is encrypted).
echo 'hello, encrypted world' > "$D/hello.txt"
dctl $FLAGS copyto "$D/hello.txt" vault:notes/hello.txt

# 3. Read it back to stdout (stdout is byte-exact; progress goes to stderr).
dctl $FLAGS cat vault:notes/hello.txt

# 4. CROSS-DEVICE RESTORE: simulate a wiped machine — delete the local index,
#    then rebuild it from the backend using nothing but the password.
rm "$D/index.redb"
dctl $FLAGS index rebuild vault:

# 5. The path→object map is back. Restore the file byte-exact.
dctl $FLAGS copyto vault:notes/hello.txt "$D/restored.txt"
diff "$D/hello.txt" "$D/restored.txt" && echo "byte-exact restore OK"
```

For unattended jobs, add `--no-ask-password` so a missing credential fails fast
instead of hanging on an invisible prompt. Every global flag (auth sources,
verify modes, filters, output) is documented in
[the global-flag reference](https://doc.dctl.sh/reference/global-flags).

## Architecture at a glance

Eight crates, layered so the crypto core stays free of `unsafe` and the on-disk
format stays independent of any single backend or CLI.

| Crate | Role |
|-------|------|
| [`dctl-crypto`](https://doc.dctl.sh/reference/crates) | Frozen v1 format + all primitives; `#![forbid(unsafe_code)]` |
| `dctl-secmem` | The **one** audited home for `unsafe` FFI (mlock/madvise, `LockedSecret`) |
| `dctl-meta` | Single renameable source of app name, paths, and env prefix |
| `dctl-store` | Provider-neutral `Backend` trait + `LocalFs`, `B2`, `S3`, `R2` |
| `dctl-index` | SQLCipher encrypted, metadata-private local index |
| `dctl-core` | `Vault` — composes crypto + store + index (init/unlock, put/get, sharing, restore) |
| `dctl-cli` | The `dctl` binary |
| `dctl-decode` | Dependency-free C99 reference decoder + KAT cross-validation |

```mermaid
graph TD
    CLI[dctl-cli · the binary]
    CORE[dctl-core · Vault]
    CRYPTO[dctl-crypto · format + primitives]
    STORE[dctl-store · Backend trait]
    INDEX[dctl-index · SQLCipher index]
    META[dctl-meta · name/paths/env]
    SECMEM[dctl-secmem · audited unsafe FFI]
    DECODE[dctl-decode · C99 decoder + KAT]

    CLI --> CORE
    CLI --> STORE
    CLI --> META
    CORE --> CRYPTO
    CORE --> STORE
    CORE --> INDEX
    INDEX --> CRYPTO

    SECMEM -. locked-secret memory .-> CRYPTO
    DECODE -. validates .-> CRYPTO
```

See [the architecture reference](https://doc.dctl.sh/reference/architecture) for
the full picture and [the crate reference](https://doc.dctl.sh/reference/crates)
for the per-crate API surface.

## Documentation

| Doc | What it covers |
|-----|----------------|
| [doc.dctl.sh](https://doc.dctl.sh) | Documentation index / map |
| [Architecture](https://doc.dctl.sh/reference/architecture) | How the crates fit together |
| [Threat model](https://doc.dctl.sh/security/threat-model) | Threat model, guarantees, and honest limits |
| [Guide](https://doc.dctl.sh/guide) | Task-oriented user guide |
| [Crates](https://doc.dctl.sh/reference/crates) | Per-crate roles and APIs |
| [Development](https://doc.dctl.sh/project/development) | Building, testing, contributing |
| [`crates/dctl-decode/FORMAT.md`](crates/dctl-decode/FORMAT.md) | Normative, frozen on-disk format spec |
| [Global flags](https://doc.dctl.sh/reference/global-flags) | Every global flag and env var |
| [Commands](https://doc.dctl.sh/commands) | Per-command reference pages |
| [Exit codes](https://doc.dctl.sh/reference/exit-codes) | Exit-code contract |
| [Error codes](https://doc.dctl.sh/reference/error-codes) | FFI-stable error codes |
| [Audit log](https://doc.dctl.sh/reference/audit-log) | Audit-log format |
| [Project status](https://doc.dctl.sh/project/status) | Current status and caveats |
| [Plan](https://doc.dctl.sh/project/plan) | Vision, locked decisions, roadmap |

## Security summary

DCTL encrypts **both paths and content** client-side under a password-wrapped
root key, uses key-committing AEAD (partitioning-oracle defense), and derives
every subkey from the envelope so losing the envelope makes stored objects
permanently unreadable. Its asymmetric layer is post-quantum hybrid
(X25519 + ML-KEM-768).

Known limits, stated up front: there is **no forward secrecy** against
root-/recipient-key compromise (static-recipient at-rest, by design); **no sender
authentication** in v1 (confidentiality + integrity, not origin auth); the
sharing graph and object sizes are **metadata surfaces** visible to the backend;
`--key-file` (second factor) is **not yet supported** and is refused rather than
silently ignored. Full threat model in the
[threat-model page](https://doc.dctl.sh/security/threat-model).

## Build & test

```sh
cargo build                                   # workspace
cargo test                                    # unit + property tests
cargo clippy --all-targets -- -D warnings     # lints as errors
cargo +nightly fuzz run stream_open           # from crates/dctl-crypto/fuzz
```

Live B2/S3/R2 integration tests are `#[ignore]` and gated on credential env vars
(`DCTL_B2_KEY_ID`, `DCTL_S3_*`, `DCTL_R2_*`); they are not part of the default
`cargo test` run and have **not** been verified end-to-end yet.

## License

Proprietary. See [`Cargo.toml`](Cargo.toml) (`license = "Proprietary"`).
