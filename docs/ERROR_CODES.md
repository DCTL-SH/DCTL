# DCTL FFI-stable error codes (FROZEN)

The DCTL library crates expose a **stable numeric error-code contract** so the
GUI/Tauri and iOS FFI layers can branch on a code, not on fragile message
strings. Every library error answers two stable questions:

- `code() -> u32` — a precise, frozen number identifying the exact variant.
- `kind() -> ErrorKind` — a coarse retry/UX classification (on `CoreError`).

`CoreError::code()` delegates through its wrapper variants
(`Crypto`/`Store`/`Index`) into the underlying sub-error's `code()`, so a single
call on the top-level library error yields the precise code from anywhere in the
tree. This is the code an FFI boundary should surface. (`docs/FORMAT.md` §9
rule 11 points here.)

## STABILITY CONTRACT

Modeled on the format's frozen one-way door (`docs/FORMAT.md` §8):

- **Codes are frozen.** Once a number ships, its meaning never changes.
- **Never renumbered, never reused.** A retired variant's number is burned, not
  recycled for a new meaning.
- **Additive only.** New error variants get new, unused numbers. New numbers may
  only extend the table; they never re-scope an existing entry.
- **`0` is reserved** for success / "no error" and is never returned by `code()`.
- **Domain ranges are fixed:** `1xxx` crypto · `2xxx` store · `3xxx` index ·
  `4xxx` core/vault. New variants take the next free number in their domain.
- **`ErrorKind` is stable and additive-only.** Its variants
  (`Transient`, `Permanent`, `Usage`, `Integrity`, `Auth`, `NotFound`) and their
  meanings never change; a variant may be added but never removed or re-scoped.

FFI consumers may hard-code these numbers. Unit tests in each crate assert the
representative numbers below and that codes are unique within a crate; a
`dctl-core` test asserts the wrapper delegation and the `kind()` mapping.

## `ErrorKind` (retry/UX classification)

| Kind | Meaning / host action |
|---|---|
| `Transient` | Worth retrying — transient I/O, backend/network, or DB busy/locked contention. |
| `Permanent` | A retry cannot succeed — malformed input or an internal derivation/parse failure. |
| `Usage` | The caller passed something invalid — bad object key, KDF params, or read range. |
| `Integrity` | Stored bytes failed authentication/checksum — tampering or corruption. |
| `Auth` | Wrong password/factor — re-prompt for credentials. |
| `NotFound` | The requested object/path does not exist. |

## `1xxx` — crypto (`dctl_crypto::CryptoError`)

| Code | Symbolic name | Meaning | Kind* |
|---|---|---|---|
| 1001 | `CRYPTO_KDF` | Argon2id key derivation failed (bad params, etc.). | Permanent |
| 1002 | `CRYPTO_INVALID_KDF_PARAMS` | KDF cost parameters outside the mandatory ceilings (rejected before the KDF runs). | Usage |
| 1003 | `CRYPTO_AEAD` | AEAD authentication failed — wrong key, tampered ciphertext, or wrong context (deliberately non-distinguishing). | Integrity |
| 1004 | `CRYPTO_FORMAT` | A container/header did not parse or failed a structural invariant. | Permanent |
| 1005 | `CRYPTO_HKDF` | HKDF-SHA512 expansion failed (output length out of range). | Permanent |

## `2xxx` — store (`dctl_store::StoreError`)

| Code | Symbolic name | Meaning | Kind* |
|---|---|---|---|
| 2001 | `STORE_NOT_FOUND` | The requested object does not exist. | NotFound |
| 2002 | `STORE_CHECKSUM_MISMATCH` | Stored bytes did not match the expected content hash (verified read/write refused corruption). | Integrity |
| 2003 | `STORE_INVALID_KEY` | The object key is malformed or unsafe (e.g. path traversal). | Usage |
| 2004 | `STORE_RANGE_OUT_OF_BOUNDS` | A requested read range starts beyond the object's size. | Usage |
| 2005 | `STORE_IO` | Underlying I/O failure. | Transient |
| 2006 | `STORE_BACKEND` | Backend-specific failure (network, auth, quota, provider error). | Transient |
| 2007 | `STORE_SHORT_WRITE` | Fewer bytes reached the destination than were written to it. Deliberately **not** `2002`: a file shorter than what was sent is a write that stopped (full filesystem, exhausted quota), not content that changed, and the two send an operator to opposite places. | Transient |

## `3xxx` — index (`dctl_index::IndexError`)

| Code | Symbolic name | Meaning | Kind* |
|---|---|---|---|
| 3001 | `INDEX_DB` | Underlying embedded-database failure (also the wrong whole-DB key case: SQLite reports `SQLITE_NOTADB`). | Transient |
| 3002 | `INDEX_SERIALIZE` | Record could not be (de)serialized. | Permanent |
| 3003 | `INDEX_CRYPTO` | Record decryption/authentication failed (wrong key or tampered entry). | Integrity |

## `4xxx` — core / vault (`dctl_core::CoreError` own variants)

`CoreError`'s wrapper variants (`Crypto`/`Store`/`Index`) do **not** get their own
`4xxx` numbers — they delegate to the wrapped sub-error's code (`1xxx`/`2xxx`/
`3xxx`). Only `CoreError`'s own variants live here. Sub-ranges are reserved so
related conditions cluster:

- `41xx` = unlock / auth / whether a vault is there at all
- `42xx` = not-found
- `43xx` = integrity
- `44xx` = config *(reserved — no variant yet)*

| Code | Symbolic name | Meaning | Kind |
|---|---|---|---|
| 4101 | `CORE_UNLOCK` | The envelope is present and either unreadable or opened by no slot this secret holds. One answer for both, so an attacker holding the envelope cannot learn whether a password was close. | Auth |
| 4102 | `CORE_NO_VAULT` | There is **no envelope object** at this location — a plain object store, not a vault. Split out of `4101` because no password is involved and none can help; a plain remote has no envelope by definition, and reporting the unlock wording sent operators to check a secret and restore a file that cannot exist there. Leaks nothing `4101` protects: there is no password to be close to. | NotFound |
| 4201 | `CORE_NOT_FOUND` | No index record for the given logical path. | NotFound |
| 4301 | `CORE_INTEGRITY` | A stored object failed its integrity check on read. | Integrity |

\* The Kind column for `1xxx`/`2xxx`/`3xxx` is how `CoreError::kind()` classifies
that sub-error when it surfaces through a `CoreError` wrapper variant.

## See also

- [Documentation index](README.md)
- [Exit codes](EXIT_CODES.md)
- [Crate reference](CRATES.md)
