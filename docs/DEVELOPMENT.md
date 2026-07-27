# DCTL — Development Guide

A contributor's guide to building, testing, linting, and (most importantly) the
non-negotiable engineering rules a reviewer will hold you to. If you are here to
*use* DCTL rather than hack on it, start with the [User Guide](GUIDE.md); for the
byte-level format see [FORMAT.md](FORMAT.md); for what is and isn't done yet see
[PROJECT_STATUS.md](PROJECT_STATUS.md).

> **Honest status up front.** The four **library crates are complete and
> committed**; the **CLI (`dctl-cli`) is an active refactor** with a known-failing
> WIP test (see [§ Known WIP](#known-wip-read-before-you-panic)). Live cloud
> backends (B2 / S3 / R2) are **implemented but not yet verified end-to-end** —
> their integration tests are `#[ignore]` + env-gated pending real credentials.
> Read [PROJECT_STATUS.md](PROJECT_STATUS.md) before assuming any behavior.

---

## Toolchain

| Setting | Value | Where |
|---|---|---|
| Rust edition | **2024** | `[workspace.package]` in the root `Cargo.toml` |
| Minimum supported Rust (MSRV) | **1.85** | `rust-version = "1.85"` |
| Cargo resolver | **3** | `resolver = "3"` |
| Release profile | `lto = "thin"`, `codegen-units = 1`, `panic = "abort"` | `[profile.release]` |

Edition 2024 and resolver 3 require a toolchain at or above the MSRV; a recent
stable `rustc` (install via [rustup](https://rustup.rs)) is sufficient for the
whole workspace. The one exception is fuzzing (see below), which needs nightly and
`cargo-fuzz`. Building the index crate compiles **SQLCipher and OpenSSL from
vendored source**, so a working **C toolchain** (a C compiler + `make`) must be on
`PATH`; no system `libsqlite3` or OpenSSL is required.

---

## Repository & workspace layout

DCTL is a single Cargo workspace of **8 crates**. Each has a one-line summary here;
for the full dependency graph and per-crate module maps see
[CRATES.md](CRATES.md) and [ARCHITECTURE.md](ARCHITECTURE.md).

```
DCTL/
├── Cargo.toml            # workspace root (resolver 3, edition 2024, shared deps)
├── Cargo.lock            # committed — this is an application workspace
├── crates/
│   ├── dctl-secmem/      # the ONE home for unsafe FFI: mlock/VirtualLock, LockedSecret
│   ├── dctl-crypto/      # #![forbid(unsafe_code)] — frozen v1 format + all crypto
│   ├── dctl-meta/        # single source of app name / paths / env prefix
│   ├── dctl-store/       # provider-neutral Backend trait; LocalFs, B2, S3, R2
│   ├── dctl-index/       # SQLCipher encrypted, metadata-private index (WAL, multi-proc)
│   ├── dctl-core/        # Vault: composes crypto + store + index
│   ├── dctl-cli/         # the `dctl` binary (ACTIVE REFACTOR — WIP)
│   └── dctl-decode/      # dependency-free C99 reference decoder + KAT cross-validation
└── docs/                 # you are here
```

| Crate | One-liner |
|---|---|
| [`dctl-secmem`](../crates/dctl-secmem) | The single audited home for `unsafe` FFI (`mlock`/`madvise`/`VirtualLock`, `PT_DENY_ATTACH`) and `LockedSecret`; keeps `dctl-crypto` unsafe-free. |
| [`dctl-crypto`](../crates/dctl-crypto) | `#![forbid(unsafe_code)]`. The frozen v1 on-disk format and all cryptography: Argon2id, XChaCha20-Poly1305, HKDF-SHA512, BLAKE3, key-committing AEAD, X25519 + ML-KEM-768 hybrid. |
| [`dctl-meta`](../crates/dctl-meta) | Single renameable source of the app name, on-disk paths, and env-var prefix. |
| [`dctl-store`](../crates/dctl-store) | The provider-neutral `Backend` trait (put/get/range/head/delete/list + streaming path I/O + presign). Backends: LocalFs, B2, S3, R2. |
| [`dctl-index`](../crates/dctl-index) | SQLCipher-encrypted, metadata-private index; whole-DB raw key plus per-row keyed-hash + AEAD; WAL, multi-process. |
| [`dctl-core`](../crates/dctl-core) | The `Vault` — composes crypto + store + index: init/unlock, put/get (buffered + streaming), cross-device restore, asymmetric sharing, discovery, imported keys. |
| [`dctl-cli`](../crates/dctl-cli) | The `dctl` binary (see [docs/commands](commands/README.md)). **Active refactor.** |
| [`dctl-decode`](../crates/dctl-decode) | A dependency-free **C99** reference decoder (`kem_id=0` path) plus KAT cross-validation — the machinery behind the 20-year restorability claim. |

The `crates/dctl-crypto/fuzz` directory is deliberately **excluded** from the
workspace (`exclude = [...]` in the root manifest): fuzz targets are nightly-only
and must not perturb the stable build.

---

## Building

```bash
# Whole workspace, debug
cargo build --workspace

# Optimized binary (thin-LTO, single codegen unit, panic=abort)
cargo build --workspace --release

# Just the CLI binary
cargo build -p dctl-cli --release
```

The working tree builds clean — **zero warnings** on `cargo build --workspace`
(see the verification note atop [PROJECT_STATUS.md](PROJECT_STATUS.md)). If your
first build is slow, it is compiling vendored SQLCipher + OpenSSL; that cost is
paid once and cached.

---

## Testing

```bash
# Everything
cargo test --workspace

# A single crate (library crates are fast)
cargo test -p dctl-crypto
cargo test -p dctl-core

# The CLI end-to-end suite (slow — see below)
cargo test -p dctl-cli
```

A few things worth knowing before you run the suite:

- **The `dctl-cli` suite is slow by design.** Each CLI test spins up a real vault,
  and vault init runs **Argon2id** — an intentionally expensive, memory-hard KDF.
  Per-test key derivation dominates the wall-clock time. This is expected; the
  library crates run quickly by comparison.

- **The C reference-decoder KAT proves format stability.** `dctl-decode` cross-
  validates the Rust encoder against a standalone **C99** decoder using
  known-answer tests. Because the C decoder shares no code with the Rust crates, a
  passing KAT is independent evidence that the frozen v1 format decodes exactly as
  specified — this is the concrete mechanism behind the **20-year restorability**
  guarantee (see [§ How 20-year restorability is guaranteed](#how-20-year-restorability-is-guaranteed)).

- **Live cloud-backend tests are gated off by default.** Integration tests against
  **B2 / S3 / R2** are marked `#[ignore]` and read their endpoints/credentials from
  environment variables (`DCTL_B2_*`, `DCTL_S3_*`). They do **not** run under a
  plain `cargo test --workspace`, and — to be explicit — **live cloud backends have
  not yet been verified end-to-end**. The **local filesystem backend is fully
  exercised** by the default suite. To attempt the gated tests you must supply real
  credentials and opt in:

  ```bash
  # Requires real, chargeable credentials. Currently UNVERIFIED end-to-end.
  export DCTL_S3_BUCKET=... DCTL_S3_KEY_ID=... DCTL_S3_SECRET=... DCTL_S3_REGION=...
  cargo test -p dctl-store --  --ignored
  ```

- **Property tests** (`proptest`) run as part of the normal suite for the crates
  that use them; no extra flags needed.

- **Fuzzing** is out-of-tree and nightly-only:

  ```bash
  rustup toolchain install nightly
  cargo install cargo-fuzz
  cargo +nightly fuzz run <target>   # from crates/dctl-crypto/fuzz
  ```

---

## Linting & formatting

```bash
cargo fmt --all
cargo clippy --all-targets -- -D warnings
```

The crates are **clippy-clean**: `clippy` runs with `-D warnings` (warnings are
errors) and the tree passes. Several crates additionally opt into stricter lints in
their `lib.rs` — for example `dctl-secmem` sets
`#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]` and
`#![deny(clippy::undocumented_unsafe_blocks)]`. Do not silence these with blanket
`#[allow(...)]`; if a lint fires, fix the code.

---

## Engineering rules reviewers enforce

These are not style preferences — they are the invariants that make DCTL's security
and durability claims true. A change that violates one will be rejected.

1. **`dctl-crypto` is `#![forbid(unsafe_code)]`.** The cryptographic core must
   never contain `unsafe`. This is enforced at compile time by the crate-level
   attribute — it cannot be worked around, only relocated.

2. **All `unsafe` lives in `dctl-secmem`, and only there.** `dctl-secmem` is the
   single audited home for platform FFI (`mlock`/`madvise`/`VirtualLock`,
   `PT_DENY_ATTACH`). Every `unsafe` block carries a `// SAFETY:` justification, and
   the crate `#![deny(clippy::undocumented_unsafe_blocks)]` so a missing note fails
   the build. New `unsafe` anywhere else is a hard no; find a way to route the need
   through `dctl-secmem`. (All seven other crates carry
   `#![forbid(unsafe_code)]`.)

3. **No `unwrap` / `expect` / `panic!` in library code.** Library crates must return
   typed errors, never panic on a recoverable condition — a panicking library is
   useless to the FFI and iOS consumers. Use `Result` and the crate error enums.
   (Test code and the release `panic = "abort"` profile are separate concerns.)

4. **The verified-write contract is sacred.** Nothing is reported as stored until
   its bytes have been **checksum-verified at the destination *and* durably
   committed to the index**. A successful return means "it provably exists,"
   full stop. Do not add a fast path that reports success before verification, and
   do not weaken the "index commit == it exists" equivalence.

5. **Error codes are FFI-stable.** The numeric error codes (1xxx crypto / 2xxx store
   / 3xxx index / 4xxx core) are a public contract documented in
   [ERROR_CODES.md](ERROR_CODES.md); process exit codes are documented in
   [EXIT_CODES.md](EXIT_CODES.md). You may **add** new codes; you may **never**
   renumber or repurpose an existing one. Update the doc in the same change.

6. **The v1 format is DESIGN-FROZEN — additive changes only.** [FORMAT.md](FORMAT.md)
   is design-locked. Reserved ids/slots (e.g. `algo = 2` archival, `slot_type = 3`
   Shamir) may be *filled in*, but you may not change the meaning, layout, or
   framing of anything already specified. If a change would alter how existing bytes
   decode, it is wrong by definition. `FORMAT.md`, `PLAN.md`,
   `PLAIN_STORAGE_PLAN.md`, and the command reference are **not** edited casually.

7. **Accuracy over polish in docs and claims.** Never state that live B2/S3/R2 has
   been verified end-to-end (it has not), and never describe the CLI as complete
   (it is a WIP refactor). If you are unsure whether something is implemented, read
   the code or mark it clearly as WIP/planned.

---

## How 20-year restorability is guaranteed

The claim is: *given only the password (and the backend bytes), the data is
recoverable decades from now, even if this Rust codebase no longer builds.* Two
mechanisms make that concrete:

- **An independent C99 reference decoder.** `dctl-decode/reference/dctl-decode.c`
  is a single, **dependency-free** C99 file that decodes the symmetric (`kem_id=0`)
  path of the frozen format from first principles. C99 is about as close to a
  "will still compile in 2045" substrate as exists. Because it shares no code with
  the Rust encoder, agreement between them is meaningful.

- **Byte-exact known-answer tests (KATs).** The decoder is cross-validated against
  fixed vectors, so any drift between the Rust encoder and the format spec is caught
  as a test failure rather than discovered years later. As long as the frozen format
  stays additive (rule 6 above), the KAT keeps proving that the reference decoder —
  and therefore anyone with the spec — can read what DCTL writes.

Self-describing objects reinforce this: a DSF1 object embeds its own wrapped DEK and
encrypted metadata, so with `{secret, envelope, object}` it decodes without the
index at all. Cross-device restore (rebuilding a fresh index from the backend with
only the password) is smoke-tested against the local backend.

---

## Known WIP (read before you panic)

**No known-failing test.** This section previously named one —
`the_key_file_refusal_names_the_flag_and_never_calls_a_working_command_missing`
in `crates/dctl-cli/tests/cli.rs` — because the `--key-file` refusal chokepoint in
`main.rs` built its message from the command name alone and so reported that
`init` "is not implemented in this build", which was false. The chokepoint now
appends the flag itself, the message names the flag and the layer that owes it,
and the test passes:

```
error: dctl init: the --key-file second factor (missing in dctl-core: Vault::init
and ::unlock take a password and no factor parameter) is not implemented in this
build
```

`--key-file` is still refused everywhere — multi-factor key material is owed by
`dctl-core` (`PLAN.md` §8) — but the *message* is no longer a false statement
about a working command.

For the full,
regularly-verified feature matrix — what is committed, what is working-but-
uncommitted, and what is not started (mount, serve, network plain backends,
general remote↔remote) — see [PROJECT_STATUS.md](PROJECT_STATUS.md).

---

## See also

- [README](../README.md) · [docs index](README.md)
- [ARCHITECTURE.md](ARCHITECTURE.md) — how the crates compose at runtime
- [CRATES.md](CRATES.md) — per-crate module maps and dependency graph
- [SECURITY.md](SECURITY.md) — threat model and honest caveats
- [FORMAT.md](FORMAT.md) — the frozen v1 byte format
- [ERROR_CODES.md](ERROR_CODES.md) · [EXIT_CODES.md](EXIT_CODES.md) · [GLOBAL_FLAGS.md](GLOBAL_FLAGS.md)
- [AUDIT_LOG.md](AUDIT_LOG.md) · [PROJECT_STATUS.md](PROJECT_STATUS.md) · [command reference](commands/README.md)
