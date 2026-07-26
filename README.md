# DCTL

A fast, secure, Rust-native tool to transfer, back up, encrypt, and **stream**
data across cloud providers — optional QMV-grade, post-quantum encryption,
optimized for huge media, with a "never report success unless the data is
provably, durably stored" contract and 20-year restorability as a design goal.

> The name **DCTL** is a working title and is centralized so it can be changed
> later. On-disk **format identifiers are deliberately brand-neutral and frozen**
> (see `docs/FORMAT.md`) — renaming the product never touches the format.

## Status

Early scaffolding. Working today:

- `crates/dctl-crypto` — clean-room, streaming-first encryption core
  (Argon2id KDF, envelope root key, HKDF sub-keys, XChaCha20-Poly1305 chunked
  AEAD with seekable random access, BLAKE3 integrity). Fully unit- and
  property-tested.

## Layout

```
Cargo.toml                 workspace
PLAN.md                    full architecture + roadmap
docs/FORMAT.md             normative on-disk format spec (20-year decodability)
crates/dctl-crypto/        encryption core (+ tests, fuzz)
```

## Build & test

```sh
cargo build            # workspace
cargo test             # unit + property tests
cargo clippy --all-targets -- -D warnings
cargo +nightly fuzz run stream_open   # (from crates/dctl-crypto/fuzz)
```

Requires a recent stable Rust (edition 2024; `rustup update` for the latest).

## Documentation

- **`PLAN.md`** — vision, locked decisions, security/durability contracts,
  scalability principles, roadmap.
- **`docs/FORMAT.md`** — the byte-level on-disk format.
