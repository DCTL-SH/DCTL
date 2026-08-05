# DCTL On-Disk Format Specification — v1 (FROZEN — design-locked)

> **Normative & standalone.** DCTL data must be decodable from this document alone,
> with no DCTL binary. **This is version 1 — the first and only DCTL format**
> (`DKE1`/`DSF1`); nothing shipped before it. The **byte layout is DESIGN-FROZEN** (2026-07-26)
> after five adversarial multi-agent review rounds (11→9→2→1→1→0 defects). The sole
> remaining lock is the encoder-generated **byte-exact KAT** proving code↔document
> parity, produced during implementation — no further layout changes. Additive features
> route only through new `version`/`algo`/`kem_id`/`slot_type`/`schema_version`/
> `hybrid_suite` ids per §8. Readers accept every published version forever and never
> drop support.
>
> All multi-byte integers are **little-endian**. Default AEAD is **XChaCha20-Poly1305**
> (24-byte nonce, 16-byte tag; `algo`/`wrap_algo = 2` reserves AES-256-GCM, 12-byte
> nonce). Hash **BLAKE3-256**; KDF **Argon2id** (RFC 9106); sub-keys **HKDF-SHA512**
> (RFC 5869); mnemonic **BIP-39**; asymmetric recipients (§12) **X25519** (RFC 7748) +
> **ML-KEM-768** (FIPS 203) hybrid.
>
> **Design invariants:**
> 1. **Multiple unlock paths** — the envelope is a self-delimiting *slot list*, so
>    password + mnemonic + (reserved) Shamir + device/Secure-Enclave keys each
>    recover the same root.
> 2. **Self-describing objects** — each object embeds its own wrapped DEK and
>    encrypted metadata, decoding standalone from `{unlock secret, envelope, object}`
>    with **no index**.
> 3. **Rename-stable storage** — the backend storage key is a **random per-object id**
>    (`file_id`), never a hash of the path, so moves/renames are O(1) index updates,
>    not re-uploads. The **authoritative** path↔object mapping lives in small,
>    rewritable **name records** (§5); the object's embedded `path_hint` is only an
>    advisory creation-time copy (§4) and MAY be stale after a rename.
> 4. **Cross-platform-stable naming** — index/name keys derive from **NFC-normalized,
>    case-sensitive, `/`-separated UTF-8** paths of **assigned** code points only, with
>    the normalization repertoire pinned to Unicode 15.1 (§5).

---

## 1. Key hierarchy

```
unlock secret (password / mnemonic / Shamir set / device key)
        │  KEK = Argon2id(NFC(secret) [‖ H(factor)], salt, params)   (or platform key)
        ▼
   envelope: N slots, each AEAD-wraps the SAME 32-byte root key
        ▼  root key (random once, never changes)  ── N ≥ 2 as written by v1: §2.1
        │  SUBKEY(root, info)   (see "HKDF construction" below)
        ├─ index-key       "index-key-v1"      (SQLCipher row key; path→record)
        ├─ name-hash-key   "name-hash-key-v1"  (BLAKE3-keyed → public name-record key)
        ├─ name-value-key  "name-value-key-v1" (AEAD of the name-record value)
        ├─ object-keying   "object-keying-v1"  (reserved; content-addressed dedup)
        ├─ cache-key       "cache-key-v1"
        └─ audit-key       "audit-key-v1"     (RESERVED — derivable, used by nothing; §11)
   per-object DEK: random, wrapped by the root (or a §12 recipient hybrid key),
   embedded in the object. Chunks and metadata are both sealed under the DEK,
   in disjoint nonce spaces (§3; algo=1).
```

**HKDF construction (FROZEN — pins every sub-key so a clean-room decoder reproduces
them bit-for-bit):** `SUBKEY(ikm, info)` = **RFC 5869 HKDF-SHA512** performed in full
(Extract **then** Expand) with **salt = 64 zero bytes** (the all-zero HashLen salt),
`IKM = ikm`, `info = <ASCII label>`, and output length **L = 32 bytes**. Extract is
**not** skipped. The same construction is used for every root sub-key above and for the
recipient KEM wrap (§12). (A distinct, explicitly-salted HKDF is used only where §12
states its own `salt`.)

The name path-hash and the name-value AEAD use **separate** sub-keys so that publishing
the `n/*` keys (which are public backend object names) never exposes any value-
encryption key material (§5).

**The root key never changes, and that is what makes the slot list useful.** Every
object's DEK is wrapped to it, so it cannot be rotated without rewriting the whole
dataset — and does not need to be, because the *ways in* rotate independently. Changing
a password rewrites one slot (§2.2); the other slots, and therefore every other way to
recover the same root key, are untouched. A recovery phrase issued when the vault was
created keeps working after any number of password changes.

---

## 2. Envelope `DKE1` — self-delimiting key-slot list

```
Off   Size  Field
0     4     Magic         "DKE1" (0x44 0x4B 0x45 0x31)
4     1     Version       0x01
5     16    vault_id      random UUID; binds all slots to this vault
21    2     slot_count    u16 — MUST be ≥ 1 and ≤ 64
23    …     slots[slot_count]
```

Each **slot** is self-delimiting (readers can skip unknown types by `slot_len`):

```
Off       Size  Field
0         4     slot_len      u32 — total bytes of this slot (incl. these 4)
4         1     slot_type     0 device · 1 password · 2 mnemonic · 3 shamir (RESERVED)
5         1     flags         bit0 = factor-required; all other bits reserved-critical
6         1     kdf_id        0 none/platform · 1 Argon2id
7         1     wrap_algo     1 XChaCha20-Poly1305 · 2 AES-256-GCM (reserved)
8         4     m_cost        Argon2id KiB   (MUST be 0 iff kdf_id=0)
12        4     t_cost        Argon2id iters (MUST be 0 iff kdf_id=0)
16        4     p_lanes       Argon2id lanes (MUST be 0 iff kdf_id=0)
20        32    commit        key-commitment = SUBKEY(KEK, "dctl-slot-commit-v1")
52        1     salt_len      u8
53        s     salt
53+s      2     aux_len       u16   (Shamir index/threshold, device-key ref, KEM data…)
55+s      a     aux
55+s+a    2     wrap_len      u16   (length of wrapped_root)
57+s+a    w     wrapped_root  AEAD(KEK, root_key) in wrap_algo: nonce(24, fresh CSPRNG per
                              write) ‖ ct(32) ‖ tag(16)
```

- All slots wrap the **same** root key. **Wrap AAD** (length-framed and header-bound):
  ```
  "dctl-slot-v1::" ‖ vault_id(16) ‖ slot_type(1) ‖ flags(1) ‖ kdf_id(1) ‖ wrap_algo(1)
                   ‖ salt_len(u8) ‖ salt ‖ aux_len(u16 LE) ‖ aux
  ```
  This binds slot identity, the wrap/KDF **selectors** (anti-downgrade), and the
  **length-prefixed** salt+aux to this vault — defeating cross-slot / cross-vault
  substitution. The Argon2id **cost params** (`m/t/p`) are *not* in the AAD; they are
  bound **implicitly** — they are inputs to the KEK, so tampering them yields a
  different KEK and the unwrap simply fails. Folding the fixed header is essential for
  **device slots**, whose KEK is independent of the salt.
- **Key commitment (S2 — defeats partitioning-oracle / multi-key attacks):** because
  every slot wraps the *same* root under a *different* KEK, a non-committing AEAD would
  let an attacker craft one blob that decrypts under many candidate passwords. The
  `commit` field = `SUBKEY(KEK, "dctl-slot-commit-v1")` binds a slot to **exactly one
  KEK**. After deriving a KEK, a reader MUST recompute the commitment and compare it in
  **constant time**; only on match does it attempt `unwrap_root`. `commit` is a one-way
  HKDF image of the KEK, so it reveals nothing about the KEK and does not lower the
  offline Argon2id work factor. It is present for **every** slot type (for device slots
  it commits the platform KEK). A reader MUST NOT treat a commitment match as proof of
  anything but "this KEK is the one this slot was written under": it is a fast reject,
  and the AEAD tag over `wrapped_root` is still the authority.
- **Slot structural bounds (MANDATORY, checked before any crypto):** a reader MUST
  verify `slot_len == 57 + salt_len + aux_len + wrap_len` and that the whole slot lies
  within the envelope; a slot that fails this is **rejected, not silently skipped**. For
  `wrap_algo=1`, `wrap_len` MUST equal `24 + 32 + 16 = 72`. These checks bound every
  variable-width field against `slot_len`, so no `u8`/`u16` length can overrun the slot.
- **KEK derivation** (passphrase/mnemonic secrets are **NFC-normalized, UTF-8** first,
  so the same secret typed on any OS yields identical bytes):
  - `type=1` password: `Argon2id(NFC(password) ‖ BLAKE3(factor)?, salt, params)`.
  - `type=2` mnemonic: `Argon2id(BIP39_seed(mnemonic), salt, params)`, where
    `BIP39_seed` is **BIP-39 exactly as published, with an EMPTY passphrase**:
    `PBKDF2-HMAC-SHA512(P = NFKD(mnemonic sentence), S = "mnemonic", c = 2048,
    dkLen = 64)`. The 64-byte seed — not the 32 bytes of entropy, and not the word
    indices — is the Argon2id input. Pinned to the byte because a clean-room decoder
    that used the entropy, a non-empty passphrase, or a different iteration count
    would derive a plausible-looking key that opens nothing.
    The mnemonic sentence is the words separated by single U+0020 spaces; BIP-39
    derives the seed from the canonical word list entries, so line breaks, repeated
    spaces and a trailing newline in a transcribed phrase are immaterial.
  - `type=0` device: `kdf_id=0`; KEK comes from the platform key store (Secure
    Enclave / TPM / OS keychain) — **no Argon2 runs**, so mobile unlocks cheaply.
  - `type=3` shamir: **RESERVED** — the sharing scheme is not yet specified; writers
    MUST NOT emit it and readers treat it as an unknown skippable slot until a future
    version pins the field, share encoding, interpolation, and aux layout.
  - A **v1 writer emits neither `type=0` nor `type=3`.** It writes exactly one `type=1`
    and one `type=2` slot; §2.1 gives their bytes. Both reserved types are specified
    here for readers, which must skip them, not for writers.
- **KDF-parameter ceilings (MANDATORY, enforced BEFORE running Argon2id** — the
  envelope is on untrusted storage, and params are read pre-authentication):
  `8 ≤ m_cost ≤ 1 048 576` (≤ 1 GiB), `1 ≤ t_cost ≤ 16`, `1 ≤ p_lanes ≤ 8`. A slot
  violating these (or non-zero params with `kdf_id=0`) is **skipped** without invoking
  the KDF — the reader tries the other slots (§8). Only a structural `slot_len`/bounds
  failure rejects the whole envelope; a bad-ceiling slot is a per-slot skip, so one
  corrupt slot cannot deny access when a valid portable slot still exists.
- **Unlock:** for each slot the host can satisfy (whose structural bounds and KDF
  ceilings validate), derive the KEK, check `commit`, and `unwrap_root`; first success
  yields the root. A slot whose `slot_type`, `wrap_algo`, or `kdf_id` the reader does
  not support is **skipped (via `slot_len`) and the reader tries the other slots** — it
  MUST NOT reject the whole envelope, so a capable portable slot still unlocks a vault
  that also contains slots using a newer algorithm (§8).
- **Portability invariant (CRITICAL):** every vault MUST keep **≥1 portable slot**
  (password `type=1` or mnemonic `type=2`) that the reader can actually satisfy with a
  currently-supported `wrap_algo`/`kdf_id`. Device slots are additive per-device
  conveniences and MUST NEVER be the only slot. A v1 host creates **two** portable
  slots at `init` — password and mnemonic (§2.1) — and refuses to remove the last one.
  Two rather than one is the point: a single portable slot satisfies the letter of this
  invariant while leaving a forgotten password as permanent, total data loss, with the
  ciphertext intact and unreadable. Portable slots live in the **shared-backend**
  envelope so every device can read them.
- Written atomically (tmp + fsync + rename).

### 2.1 What a v1 writer emits at `init` (NORMATIVE)

The layout above is the general form; this is the exact envelope DCTL v1 creates, and it
is what a restore in twenty years will be handed. **Two slots — both `kdf_id=1` Argon2id
and `wrap_algo=1` XChaCha20-Poly1305 — wrapping the same root key:**

```
Off  Size  Field                Value written by v1
0    4     magic                "DKE1"
4    1     version              0x01
5    16    vault_id             16 CSPRNG bytes
21   2     slot_count           2                      (0x02 0x00)
23   145   slots[0] password    table below
168  145   slots[1] mnemonic    table below
                                total envelope = 313 bytes
```

Each slot is **145 bytes**, because `slot_len = 57 + salt_len(16) + aux_len(0) +
wrap_len(72)`:

| field       | slots[0] password      | slots[1] mnemonic             |
|-------------|------------------------|-------------------------------|
| `slot_len`  | 145                    | 145                           |
| `slot_type` | 1                      | 2                             |
| `flags`     | 0                      | 0                             |
| `kdf_id`    | 1 (Argon2id)           | 1 (Argon2id)                  |
| `wrap_algo` | 1 (XChaCha20-Poly1305) | 1 (XChaCha20-Poly1305)        |
| `m_cost`    | 131072 (128 MiB)       | 131072                        |
| `t_cost`    | 3                      | 3                             |
| `p_lanes`   | 4                      | 4                             |
| `commit`    | 32 bytes               | 32 bytes                      |
| `salt_len`  | 16                     | 16                            |
| `salt`      | 16 CSPRNG bytes        | 16 **different** CSPRNG bytes |
| `aux_len`   | 0                      | 0                             |
| `wrap_len`  | 72                     | 72                            |

What a decoder should take from this:

- **Order is written but carries no meaning.** The password slot is emitted first, the
  mnemonic slot second. A reader MUST try every slot it can satisfy rather than assume a
  position; §2.2 preserves order across a rotation only so that a byte-level diff of two
  envelopes stays legible to a human.
- **The two salts are drawn independently.** Sharing one would tie both KEKs to a single
  random value and make the pair no stronger than its weaker half — the exact property
  the second slot exists to provide.
- **`aux` is empty for both.** No `type=1`/`type=2` slot written by v1 carries `aux`.
- **The mnemonic is 24 English BIP-39 words** encoding 256 bits of CSPRNG entropy,
  matched to the 32-byte root key it protects so the recovery path is not the cheaper
  thing to attack. It is shown to the operator exactly once, when the vault is created,
  and is stored **nowhere**: it cannot be reproduced from the envelope, the vault, or
  the host. An envelope therefore does not reveal the phrase's length or language — the
  values here describe the writer, not a requirement on a reader.
- **`m/t/p` are read back from the slot**, never assumed. They are policy defaults, not
  frozen identifiers; a later build may raise them for new vaults, and a slot written
  today keeps the values in the table and must keep unlocking forever.

### 2.2 Rotating one way in (NORMATIVE)

Because the root key never changes, replacing a secret rewrites **one slot** and leaves
every other byte of the slot list untouched:

1. Recover the root key through any slot (§2 *Unlock*).
2. Derive a new KEK from the new secret with a **fresh salt** and the writer's current
   cost parameters.
3. Re-serialize the envelope with the replacement slot in the position of the first slot
   of that `slot_type`. Every other slot — **including slot types this writer does not
   understand** — is carried through byte-identical. `vault_id` is unchanged: it is
   bound into every slot's wrap AAD, so a new one would invalidate the slots being
   preserved.
4. Write atomically (tmp + fsync + rename), as a single object replacement, so a failure
   leaves the previous envelope intact rather than a partial one.

A password change removes **every** pre-existing `type=1` slot and installs exactly one,
so the old password stops working immediately. It does not touch `type=2`, so a recovery
phrase issued at `init` still opens the vault afterwards, and after any number of
subsequent password changes. This procedure is the operational meaning of "several
independent unwrap paths": creating them is easy, and *keeping* them is a property of
this step.

**A rotation binds the envelope, not the root key.** Any copy of the *previous* envelope
— a replica of the object store, a snapshot, a backup taken before the change — still
carries the old slot and is still opened by the old secret, because the root key it
wraps did not change and cannot. Retiring a compromised password therefore means
rotating it **and** replacing every stored copy of the envelope; retiring a compromised
*root key* is not possible at all and would mean re-encrypting the dataset. This is the
cost of an immutable root, and it is the same cost that buys rename-stable objects and a
recovery phrase that never expires.

---

## 3. Object `DSF1` — self-describing encrypted file

Storage key = `"o/" ‖ hex(file_id)` (random per object → rename-stable; the path is
*not* in the storage key). Sequential layout:

```
── fixed head (68 bytes; bound into EVERY object AAD — chunks, DEK wrap, metadata) ──
0     4     Magic         "DSF1" (0x44 0x53 0x46 0x31)
4     1     Version       0x01
5     1     algo          1 XChaCha20-Poly1305 (2 AES-256-GCM, reserved) — CHUNK cipher
6     1     kem_id        0 root-wrapped DEK · 1 recipient hybrid (X25519+ML-KEM-768, §12)
7     1     flags         bit0 = FOOTER present; ALL other bits CRITICAL (see §8)
8     4     chunk_size    u32 — MUST satisfy 0 < chunk_size ≤ 16 777 216 (16 MiB)
12    8     plaintext_len u64
20    8     chunk_count   u64 — MUST equal ceil(plaintext_len / chunk_size)
28    24    base_nonce    chunk-stream base nonce; CSPRNG-random, byte[23] MUST = 0x00
52    16    file_id       random per object (also the storage id)

── key + metadata ──
68    2     kem_ct_len    u16 (0 iff kem_id=0; else the §12 recipient-wrap block length)
70    K     kem_wrap      recipient-wrap block (present iff kem_id≠0; layout in §12)
70+K  72    wrapped_dek   AEAD(wrapping_key, DEK): nonce(24) ‖ ct(32) ‖ tag(16)
                          AAD = "dctl-dek-v1::" ‖ fixed_head(68)
                          ALWAYS XChaCha20-Poly1305, independent of `algo`.
                          wrapping_key = root                         (kem_id=0)
                                       = the §12 recipient hybrid key (kem_id=1)
142+K 4     meta_len      u32 — 116 ≤ meta_len ≤ 262 144. Metadata is MANDATORY
                          (invariant 2); 116 = nonce(24)+min §4 plaintext(76)+tag(16)
146+K M     enc_metadata  XChaCha20-Poly1305(DEK): nonce(24) ‖ ct ‖ tag(16)
                          nonce is CSPRNG-random with byte[23] MUST = 0x01
                          AAD = "dctl-meta-v1::" ‖ fixed_head(68)
                          (ALWAYS XChaCha20-Poly1305, independent of `algo`)

── payload ──
…     C     chunks        chunk_count chunks; chunk i on wire = ct(this_pt) ‖ tag(16)
End-32 32   footer        BLAKE3(all preceding bytes); present iff flags bit0
```

**Head-bound AAD (why it matters):** `wrapped_dek` and `enc_metadata` both fold the
entire 68-byte head into their AAD (which already contains `file_id`), so *every* header
field is authenticated by a key the attacker lacks. A header edit is detected even on an
**empty, footer-less** object. For `kem_id=1` the recipient-wrap block is additionally
bound through the wrapping-key derivation (§12).

**Nonce spaces are disjoint by construction (algo=1):** with XChaCha20 (24-byte nonce),
`base_nonce` has `byte[23]=0x00` and the metadata nonce has `byte[23]=0x01`, so although
chunks and metadata share the DEK their nonces can never collide — no second key, no
probabilistic argument. `base_nonce` MUST be freshly CSPRNG-generated per object.
(Metadata is ALWAYS XChaCha20; if the reserved `algo=2` is ever activated, its 12-byte
chunk nonce cannot use this scheme, so that activation MUST first define its own chunk-
nonce construction and chunk/metadata key-or-nonce separation.)

**Chunk crypto:** `chunk_nonce_i = base_nonce with bytes[0..8] XOR= (i as u64 LE)`
(byte[23] stays 0x00); `chunk_aad_i = fixed_head(68) ‖ (i as u64 LE)`. Per-chunk
Poly1305 authenticates every byte and (via the head) `plaintext_len`/`chunk_count`/
`file_id`, so truncation and reorder are caught without the footer. The footer is a
redundant whole-object check (verify/download only; the C reference decoder omits it).

**Random-access:** chunk i's ciphertext starts at
`146 + K + M + i·(chunk_size + 16)`; O(1) seek via one Range request.

**Reader validation (MANDATORY, before any allocation):** reject `chunk_size` outside
`(0, 16 MiB]`; reject `chunk_count ≠ ceil(plaintext_len/chunk_size)`; require `116 ≤
meta_len ≤ 262144` and `kem_ct_len ≤ 65535`; use checked/saturating offset arithmetic
(`i·(chunk_size+16)` must not overflow). Metadata is **always present** (`meta_len ≥ 116`);
a reader MUST decrypt it, and **for a supported `schema_version` (0x01)** MUST verify
`meta.size == head.plaintext_len` (both DEK-authenticated) and reject on mismatch. An
unknown `schema_version` skips metadata parsing (§8) but still serves the payload.

---

## 4. Per-item metadata (§3 `enc_metadata` plaintext)

Positional, C-parseable, with a trailing extension region for forward growth.

```
Off       Size  Field
0         1     schema_version 0x01
1         1     flags          bit0 mtime · bit1 birthtime · bit2 is-directory ·
                               bit3 tombstone (deletion marker) · bits4-7 reserved
2         8     mtime_unix     i64 (0 if flags.mtime clear)
10        8     birthtime_unix i64 (0 if flags.birthtime clear)
18        8     size           u64 (plaintext bytes)
26        32    content_blake3 BLAKE3 of plaintext — the "content version"
58        8     metadata_gen   u64 — ADVISORY metadata version (authoritative copy is
                               in the name record, §5)
66        4     mode           POSIX mode/flags (0 if n/a)
70        2     path_hint_len  u16 — 0 only for a tombstone (flags bit3); else ≥ 1
72        P     path_hint      ADVISORY creation-time NFC UTF-8 path (§5 rules). Used
                               only for disaster-recovery scavenging when name records
                               are lost; MAY be stale after a rename. NOT authoritative.
72+P      2     ct_len         u16
74+P      T     content_type   optional MIME (UTF-8)
74+P+T    2     ext_len        u16 — length of the trailing extension region
76+P+T    E     ext            zero or more TLVs: [type u8][len u16][value]; unknown
                               TLV types are ignored
```

- **`path_hint` is advisory, not authoritative.** The authoritative current path lives
  in the rewritable name-record value (§5); the object is never rewritten on rename, so
  `path_hint` records only where the object was first created. A full-vault rebuild
  reads paths from name records; `path_hint` is a fallback used solely when name records
  are lost, and any consumer MUST treat it as possibly-stale. It MUST still obey every
  §5 path rule and be non-empty for every non-tombstone object.
- `flags` bit2 (is-directory) and bit3 (tombstone) are **distinct**: a directory always
  carries a real `path_hint`; a tombstone is a pure deletion marker (`size=0`, and it
  is the only case permitted to carry an empty `path_hint`).
- `content_blake3` + `metadata_gen` map onto iOS `NSFileProviderItemVersion` (content
  and metadata halves); the name record's `metadata_gen` (§5) is the authority.
- Readers MUST bounds-check every field and verify `76 + P + T + E == meta plaintext
  length`; unknown `schema_version` → **skip metadata, still serve payload**.

---

## 5. Names, paths & normalization (FROZEN)

**Name record** (authoritative path→object map; rewritable → O(1) rename):
- key = `"n/" ‖ hex(BLAKE3_keyed(name-hash-key, NFC(path)))`
- value = `nonce(24) ‖ ct ‖ tag(16)` where
  `ct = XChaCha20-Poly1305(name-value-key, plaintext)`,
  `plaintext = file_id(16) ‖ metadata_gen(8) ‖ path_len(u16 LE) ‖ NFC(path)`,
  `AAD = "dctl-name-v1::" ‖ vault_id ‖ key_bytes`. The value length is
  `24 + (26 + path_len) + 16 = 66 + path_len` bytes.
- The record carries the **authoritative** current path *inside* its AEAD plaintext, so
  a rename is a single O(1) rewrite (new record at `hash(NFC(new_path))`, delete the old)
  with the content object untouched. It is also authoritative for `metadata_gen`.
- **Fresh-nonce rule (CRITICAL):** name records are **rewritten in place** on every
  `metadata_gen` bump (rename or metadata change), all under the single `name-value-key`.
  The 24-byte nonce MUST be drawn from the CSPRNG **anew on every write** — a static or
  derived nonce would repeat a `(key, nonce)` pair and catastrophically break the AEAD.
  `key_bytes` is the full ASCII `n/…` object-key string.
- The **public** BLAKE3-keyed hash and the **secret** value AEAD use distinct sub-keys
  (`name-hash-key`, `name-value-key`; §1); the `n/*` names are public, so they never
  expose value-encryption key material.
- **Index-free rebuild (rename-safe):** list `n/*`; for each record decrypt the value
  (AEAD verifies the record is bound to its own key + vault), obtain
  `{file_id, metadata_gen, path}`, and **verify
  `"n/" ‖ hex(BLAKE3_keyed(name-hash-key, NFC(path))) == the key it was found under`**
  (self-consistency; rejects a record written under a wrong key). Map `path → file_id`.
  The content object need not be read for the path at all; `path_hint` (§4) is consulted
  only if the name records themselves are lost.

**Index key** (SQLCipher row): `BLAKE3_keyed(index-key, NFC(path))`.

**Path rules (writers MUST enforce; readers MUST re-validate on materialize):**
- **UTF-8, `/`-separated**, a **non-empty path with ≥ 1 non-empty segment**, no
  leading/trailing `/`, no empty segments (`a//b`), no `.`/`..` segments, no `\\`, no
  drive-letter (`C:`) or UNC prefix.
- **No control code points** (banned by **code point**, not byte): reject
  `U+0000–U+001F` (C0), `U+007F` (DEL), and `U+0080–U+009F` (C1).
- **Assigned code points only; normalization repertoire pinned.** The NFC algorithm
  data — canonical decomposition mappings and canonical combining classes — is pinned to
  the **Unicode Character Database 15.1.0** repertoire. By Unicode's Normalization
  Stability Policy the NFC image of any 15.1-assigned string is byte-identical under
  every UCD ≥ 15.1, so an implementation MAY use newer UCD data but MUST **reject any
  code point first assigned in Unicode 16.0 or later** (i.e. unassigned as of 15.1),
  every **noncharacter** (`U+FDD0..U+FDEF`, `U+nFFFE`/`U+nFFFF`), and any **surrogate**
  (`U+D800..U+DFFF`). This closes the NFC-stability hole. (PUA is permanently assigned
  and allowed.)
- **NFC-normalize before hashing** (Unicode Normalization Form C, UAX #15). Naming is
  **case-sensitive** — never case-fold (folding tables are version-dependent). Hosts
  **warn on case-collision** and SHOULD warn on zero-width/bidi/confusable siblings at
  write time; these warnings are host behavior, not format bytes.
- **Length caps, measured on the NFC-normalized UTF-8 encoding (after normalization):**
  each segment ≤ 255 bytes; total path ≤ 4096 bytes, **inclusive of the `/` separators**.
- **Reader-side (Zip-Slip defense):** the decrypted `path_hint` is only DEK-
  authenticated, not trusted — before joining it to any base directory a reader MUST
  re-apply **all** the above: reject an empty path, leading/trailing `/`, `.`/`..` or
  empty segments, C0/DEL/C1 control points, `\\`, drive/UNC prefixes,
  unassigned/noncharacter/surrogate code points, and any over-cap length.

---

## 6. Standalone decode (reference decoder)

Given `{envelope bytes, one unlock secret, object bytes}`:
1. Parse envelope (§2); validate slot structural bounds and KDF ceilings; for each
   satisfiable slot derive KEK, **check `commit`**, and `unwrap_root` → **root key**.
2. Parse object head (§3); validate bounds; unknown `algo`/`kem_id`/critical flag →
   reject (§8). Compute the DEK wrapping key (root for `kem_id=0`; §12 for `kem_id=1`);
   `unwrap_dek` (AAD = head) → **DEK**.
3. Decrypt & bounds-check metadata (§4; AAD = head) — **always present**, `meta_len ≥ 116`.
   For a supported `schema_version` (0x01), verify `meta.size == head.plaintext_len`; an
   unknown `schema_version` skips parsing (§8) but still serves payload. A single-object
   decode uses the advisory `path_hint` for the output name; a full-vault restore uses name
   records (§5). (A decoder needing only payload bytes MAY skip step 3.)
4. Decrypt each chunk (AAD = head ‖ index) → plaintext; re-validate the path (§5) before
   materializing to disk.

The minimal C reference decoder targets the **symmetric** path (`kem_id=0`) — Argon2id +
XChaCha20-Poly1305 only — which is the recommended mode for long-term self-restorable
archives. Objects written to asymmetric recipients (`kem_id=1`, §12) require an
implementation that also provides X25519 + ML-KEM-768 + SHAKE256.

---

## 7. Chunking

- **Media/default 1 MiB** (small player probes/seeks fetch ≤ 1 MiB; low per-chunk
  memory for FUSE/File-Provider; throughput ≈ 4 MiB at real bandwidths).
- **Small-file 64 KiB.** `chunk_size` is per-object and **hard-bounded `(0, 16 MiB]`**
  (§3), so it can evolve within that frozen ceiling.

---

## 8. Registries & unknown-handling matrix (FROZEN)

| Magic | Meaning |  | AEAD `algo`/`wrap_algo` | |
|---|---|---|---|---|
| `DKE1` | envelope v1 |  | 1 | XChaCha20-Poly1305 |
| `DSF1` | object v1 |  | 2 | AES-256-GCM (reserved) |

`kem_id`: 0 none (root-wrapped) · 1 recipient hybrid X25519+ML-KEM-768 (§12).
`kdf_id`: 0 none/platform · 1 Argon2id v0x13. Slot types: 0 device · 1 password ·
2 mnemonic · 3 shamir (reserved).

**Backend key namespaces (FROZEN):** `o/<hex file_id>` object (§3) · `n/<hex path-hash>`
name record (§5) · `r/<hex key_id>` public recipient registry `DRR1` (§12.3 — public-key
bytes only, no secrets) · `g/<hex file_id>` grant sidecar `DGS1` (§12.6) · `k/<hex key_id>`
imported-key store `DIK1` (§13 — root-sealed private key material) ·
`d/<hex recipient_key_id>/<hex file_id>` shared-object discovery record `DGD1` (§14 —
sealed to the recipient) · the fixed envelope object key (§2). A backend object under an
unrecognized namespace prefix is **ignored**. New namespaces get new prefixes; these never
change.

**Unknown-value handling (a frozen one-way door — decided now):**

| Unknown | Reader behavior |
|---|---|
| container **version** | **reject** (explicit error) |
| object **flags** bit set (beyond FOOTER) | **reject** — flags are CRITICAL; additive features route through `algo`/`kem_id`/`version`, never flag bits |
| object **algo** / **kem_id** | **reject** the object ("unsupported algorithm/KEM"), never attempt-and-fail |
| **slot_type** the reader can't satisfy | **skip this slot** (via `slot_len`), try other slots |
| slot **wrap_algo** / **kdf_id** unsupported | **skip this slot** (via `slot_len`), try other slots — never reject the envelope |
| slot **KDF params** outside the ceilings (or params≠0 with `kdf_id=0`) | **skip this slot** (never invoke the KDF), try other slots |
| slot **flags** bit set | **skip this slot**, try other slots |
| structurally invalid slot (`slot_len` mismatch / out of bounds) | **reject** the envelope, never skip |
| metadata **schema_version** | **skip metadata**, still serve payload |
| metadata **ext TLV** type | **ignore** the TLV |
| unknown `DIK1` **version** / **hybrid_suite** (a `k/*` entry, §13) | **skip that entry**, never the vault |
| unknown `DGD1` **version** / **hybrid_suite** (a `d/*` record, §14) | **skip that record**, never other objects |

New ids get new numbers; the above rules never change.

---

## 9. Normative engineering rules (bind before FFI/CLI harden)

1. **Streaming, not whole-buffer** — seal/open/range and `Backend::put/get` operate on
   readers/streams or an on-disk sealed file; whole-buffering is a crash in a File-
   Provider extension.
2. **Bounded parallelism** — chunk seal/open MAY run over a bounded in-flight window of
   worker threads (chunks are independently keyed), but MUST emit/consume chunks **in
   order** and hold only the window in memory (never the whole file). Parallelism is a
   host optimization; wire bytes are identical to the sequential encoder, and the C
   reference decoder stays single-threaded.
3. **Delegated transfers** — `Backend` exposes `prepare_upload → {url, method, headers}`
   (SigV4 presign / B2 upload URL) for iOS `URLSession` background uploads.
4. **Cancellation** — every long transfer/engine call takes a cancellation token.
5. **Multi-process index** — engine is **SQLite/SQLCipher** (App + File-Provider share
   an App-Group container; records stay AEAD-encrypted, keyed by hash(NFC(path))).
6. **Paths only at the edge** — only the CLI/host derives filesystem paths; core/store/
   index take explicit paths.
7. **Runtime-agnostic core** — no `tokio::spawn` in `dctl-core`; CPU-bound fan-out uses
   a thread pool (e.g. rayon), not the async runtime.
8. **Locked key memory** — long-lived key material (root, sub-keys, DEKs, KEK during
   derivation) is held in `mlock`/`VirtualLock`-ed, zeroize-on-drop pages so it cannot
   page to swap; best-effort where the platform restricts locking.
9. **Unlock never in an extension** — main app runs Argon2id → root → shared Keychain
   (`kSecAttrAccessibleAfterFirstUnlock`); the extension reads the key / uses the device
   slot and never runs the KDF.
10. **Adaptive KDF calibration** — Argon2id params are per-slot; hosts calibrate to a
    target unlock time (clamped to §2 ceilings). A **portable** slot MUST be calibrated
    for the *weakest* device expected to unlock it (mobile-affordable), not the strongest
    that created it, or that device cannot open the vault.
11. **FFI-stable errors** — stable enum variants + frozen numeric codes so
    GUI/Tauri and iOS FFI layers branch on a code, never on message strings.
    Each library error exposes `code() -> u32` (`1xxx` crypto · `2xxx` store ·
    `3xxx` index · `4xxx` core; `CoreError::code()` delegates into wrapped
    sub-errors) plus `CoreError::kind() -> ErrorKind` for retry/UX. The numbers
    are a frozen one-way door like §8 — never renumbered or reused, additive
    only. Full frozen table: **[the error-code reference](https://doc.dctl.sh/reference/error-codes)**.

---

## 10. Cross-device portability (normative)

Data written by ANY device MUST be readable by EVERY other (iOS/Android/mac/Linux/
Windows), no re-encryption. Guaranteed by: little-endian bytes; UTF-8 + NFC everywhere
it feeds a key (paths §5 and passphrases §2) with a **pinned Unicode 15.1 repertoire**;
only public-standard primitives; one shared root reachable via a portable slot (§2
invariant); self-describing objects + shared-backend envelope + rebuildable index
(§3–§5); no clock/locale/endian assumptions (timestamps unix `i64`, counts fixed-width
LE). **GA gate:** seal on device A, wipe device B, unlock with the password on B,
byte-for-byte recover every object — across an Apple, a Linux/Windows, and an Android
target.

---

## 11. Security considerations

- **Root is immutable; slot changes are not key rotation.** Removing/rotating a slot
  or password does not revoke a *captured old envelope + a previously-valid secret*:
  that pair re-derives the same root (hence all DEKs) forever. This is standard
  envelope-encryption behavior (LUKS/KMS). True root rotation / crypto-periods require
  re-sealing under a new root and are a future container-version feature.
- **Key-committing slots** (§2 `commit`) prevent partitioning-oracle / multi-key
  attacks that non-committing AEAD (XChaCha-Poly1305, GCM) would otherwise allow when
  the same root is wrapped under many KEKs.
- **Metadata `path_hint` and any decrypted path are attacker-influenceable** (only
  DEK-authenticated); always re-validate reader-side (§5/§6) before filesystem use. The
  authoritative path/metadata_gen come from the name record, whose value AEAD binds its
  own key and the vault (§5).
- **Nonce hygiene (algo=1).** Chunk nonces are unique by construction (random `base_nonce`
  + counter, `byte[23]=0x00`) and the metadata nonce is disjoint (`byte[23]=0x01`); the
  slot `wrapped_root`, DEK-wrap, name-record, and §12 wrap nonces are fresh CSPRNG 24-byte
  values that collide only with negligible probability. No nonce is reused under a fixed
  key. (A future `algo=2` must establish its own chunk-nonce separation, §3.)
- **Post-quantum posture.** At-rest under a symmetric root (`kem_id=0`) is already
  quantum-resistant (all-symmetric: Argon2id + XChaCha20-Poly1305, 256-bit; Grover only
  halves the margin). The X25519+ML-KEM-768 hybrid (§12) exists for the **asymmetric
  recipient** path (sharing / write-only backup), where a public-key KEM is the part a
  quantum adversary could otherwise harvest-now-decrypt-later.
- **The audit log is unkeyed, and `audit-key-v1` is not what keys it.** The sub-key label
  is reserved in §1 and is derivable by any conforming implementation, but **nothing in
  this build consumes it**: [the audit-log reference](https://doc.dctl.sh/reference/audit-log) §3's chain hash is plain, unkeyed BLAKE3
  over a canonical string whose every input is already in the log file. The consequence is
  normative and is stated here because the §1 diagram would otherwise imply the opposite:
  **a valid chain proves integrity and order — and, with an anchor, length — but never
  authorship.** Anyone who can append a line to `audit.jsonl` can append a correctly linked
  one, so a conforming verifier MUST NOT report or imply that a chain attributes its
  records to any particular writer. [The audit-log reference](https://doc.dctl.sh/reference/audit-log) §11 carries the argument for why a
  key the writing process must itself be able to read would not change this, the two
  mechanisms that would, and the operating procedure that bounds — rather than closes — the
  exposure. A future keyed or signed profile is a **new** record version under [the audit-log reference](https://doc.dctl.sh/reference/audit-log) §2.1's
  rule, not a re-interpretation of this one — records already written are unkeyed and stay
  unkeyed, and a reader MUST NOT assume otherwise from the presence of the label.
- **Doc↔code parity** is enforced by an encoder-generated byte-exact KAT vector checked
  against this document; the format is frozen only once that passes.

---

## 12. Asymmetric recipients & post-quantum KEM (kem_id = 1) — FROZEN

`kem_id=1` activates the reserved §3 carrier fields (`kem_ct_len`, `kem_wrap`) so an
uploader holding only **public** keys can seal objects that only a **private**-key
holder can read. It serves two launch use cases: **(a) write-only backup** — the agent
cannot decrypt what it wrote; **(b) sharing** — grant specific recipient(s) read access
to specific objects. The symmetric owner path (`kem_id=0`, root-wrapped DEK) is the
unchanged default; **`kem_id=1` changes no §3 framing byte** — it only fills `kem_wrap`
and repoints the *wrapping key* of the existing `wrapped_dek` field.

Core construction: a per-object random 32-byte **KW** (object wrapping key) **is** the
"§12 recipient hybrid key" that §3's `wrapped_dek` already names. The DEK is wrapped
**once** — `wrapped_dek = XChaCha20-Poly1305(KW, DEK)`, `AAD = "dctl-dek-v1::" ‖
fixed_head(68)` — identical to `kem_id=0`, only the key differs. **KW** (not the DEK) is
then independently wrapped to each of *N* recipients inside `kem_wrap`, so every
recipient unwraps the **same KW → same DEK → same payload**. Each recipient wrap is a
hybrid X25519 + ML-KEM-768 KEM; break either primitive and a non-root adversary still
cannot derive the wrapping key.

### 12.1 Suite & hybrid combiner (FROZEN)

`hybrid_suite = 0x01` = **X25519** (RFC 7748; little-endian u-coordinates, basepoint
u=9) + **ML-KEM-768** (FIPS 203, k=3). Sizes (bytes): X25519 pk/sk/shared = 32/32/32;
ML-KEM-768 `ek`=1184, `dk`=2400, `ct`=1088, shared `K_m`=32.

**Per-recipient encapsulation** — encoder needs only the recipient **public** key
`R = { x_pk(32), ek(1184) }`:

1. `eph_sk` = 32 fresh CSPRNG bytes; `eph_pk = X25519(eph_sk, 9)`.
2. `ss_x = X25519(eph_sk, R.x_pk)` (classical leg). **MANDATORY contributory check:** if
   `ss_x` is all-zero, discard and regenerate `eph_sk` (RFC 7748 low-order/all-zero
   guard); a recipient `x_pk` that is a known low-order point is rejected. This prevents
   a malicious recipient key silently nulling the classical leg with no signal.
3. `(K_m, ct_m) = ML-KEM-768.Encaps_internal(R.ek, m)`, `m` = 32 fresh CSPRNG bytes
   (PQ leg). The **derandomized internal** function is used so KATs reproduce.
4. **Hybrid combine — the pinned §1 `SUBKEY` verbatim** (RFC 5869 HKDF-SHA512,
   salt = 64 zero bytes, Extract-then-Expand, L = 32; no custom salt):
   ```
   ikm  = ss_x(32) ‖ K_m(32)                     (PINNED ORDER: classical, then PQ)
   info = "dctl-kem-hybrid-x25519-mlkem768-v1"    (34 ASCII bytes, no NUL)
        ‖ hybrid_suite(1)=0x01
        ‖ fixed_head(68)
        ‖ key_id(32)
        ‖ eph_pk(32)
        ‖ ct_m(1088)
        ‖ R.x_pk(32)                              (recipient static X25519 pub)
        ‖ R.ek(1184)                              (recipient static ML-KEM ek)
   wrapping_key_i = SUBKEY(ikm, info)             (info total = 2471 bytes, L=32)
   ```
   `info` binds the **full KEM transcript** — both ciphertexts (`eph_pk`, `ct_m`), the
   suite selector, the 68-byte head, and **both recipient static public keys directly**
   (not merely via the `key_id` hash), giving an X-Wing-style robust concatenation
   combiner that does **not** rest on BLAKE3 collision resistance. Breaking one primitive
   leaves the other 256-bit shared secret unknown in `ikm`, so `wrapping_key_i` stays
   PRF-indistinguishable.
5. Per object, `KW` = 32 fresh CSPRNG bytes.
   `wrapped_kw_i = XChaCha20-Poly1305(wrapping_key_i, nonce24_fresh, KW, AAD_kw)` =
   `nonce(24) ‖ ct(32) ‖ tag(16)` (72 bytes), where
   `AAD_kw = "dctl-kem-kw-v1::"(16) ‖ fixed_head(68) ‖ hybrid_suite(1) ‖ key_id(32)`
   (117 bytes).
6. Zeroize `eph_sk, ss_x, K_m, m, wrapping_key_i` (and `KW, DEK` after object write, for
   a write-only agent).

**Decapsulation** — recipient holding static `(x_sk, dk)`: find the sub-record whose
`key_id` matches an identity it holds; `ss_x = X25519(x_sk, eph_pk)`; `K_m =
ML-KEM-768.Decaps_internal(dk, ct_m)` (FIPS 203 **implicit rejection** — always returns
32 bytes; a wrong/tampered `ct_m` yields a pseudo-random `K_m`); recompute
`wrapping_key = SUBKEY(ss_x ‖ K_m, info)` (rebuilding `info` from the head, the
sub-record fields, and the recipient's own `x_pk, ek`); `KW =
XChaCha20-Poly1305.Open(wrapping_key, wrapped_kw, AAD_kw)`. **The AEAD tag is the ONLY
accept gate** — ML-KEM never signals failure, so implementers MUST NOT add any
decapsulation-failure oracle. Then `DEK = Open(KW, wrapped_dek, "dctl-dek-v1::" ‖ head)`,
then decrypt per §3.

**Why it holds if either primitive breaks:** `wrapping_key_i` needs **both** `ss_x` and
`K_m`. An adversary who algorithmically breaks ML-KEM learns `K_m` but not `ss_x`
(needs the discarded `eph_sk` or `x_sk`); breaking X25519 yields `ss_x` but not `K_m`.
The two shared secrets come from **independent** per-object randomness (`eph_sk` vs `m`)
and **independent** root-derived static secrets (separate `SUBKEY` labels, §12.4), so no
single per-message seed yields both. The only joint point is the **root** (derives both
static secrets) — but root compromise is total by definition (§11) and is explicitly
outside this hybrid's threat model, whose job is to survive an *algorithmic* break of one
primitive by a party **without** the root (e.g. a quantum harvester).

**Anti-downgrade:** `hybrid_suite` is bound in **both** the HKDF `info` and the
`wrapped_kw` AAD, and the literal primitive names live in the `info` domain string; both
`eph_pk` and `ct_m` are mandatory and both feed `ikm`, so no primitive can be stripped
and no cross-suite confusion is possible. `kem_id` (head byte 6) is bound into every AAD
via `fixed_head`. Unknown `hybrid_suite`/`kw_version` ⇒ **reject the object** (§8), never
attempt-and-fail.

### 12.2 `kem_wrap` byte layout `DKW1` (FROZEN)

DSF1 framing is **unchanged**. At object offset 68, `kem_ct_len` (u16 LE) = `K` = total
`kem_wrap` length; `kem_wrap` (`K` bytes, offset 70) is present iff `kem_id=1`. All
integers **little-endian**; every field self-delimiting and standalone-decodable.

**`kem_wrap` block header (10 bytes):**
```
Off   Size  Field
0     4     kw_magic      "DKW1" (0x44 0x4B 0x57 0x31)
4     1     kw_version    0x01
5     1     hybrid_suite  0x01 = X25519+ML-KEM-768 (unknown ⇒ reject object, §8)
6     1     kw_flags      bit0 = a grant SIDECAR (key "g/"‖hex(file_id), §12.6) MAY
                          carry additional recipients; ALL other bits reserved-CRITICAL
                          (unknown bit set ⇒ reject object)
7     1     reserved      0x00 — MUST be 0 (reject if nonzero)
8     2     recip_count   u16 — N inline recipients, 1 ≤ N ≤ 53
10    …     recipients[N]
```

**Recipient sub-record (length-prefixed; suite-1 total = 1234 bytes):**
```
Off    Size  Field
0      4     rec_len       u32 — total bytes incl. these 4 (= 1234 for suite 1)
4      32    key_id        recipient long-term hybrid pubkey id (§12.3)
36     2     ct_m_len      u16 = 1088 for suite 1
38     1088  ct_m          ML-KEM-768 ciphertext (Encaps_internal output, FIPS 203 bytes)
1126   2     eph_pk_len    u16 = 32 for suite 1
1128   32    eph_pk        ephemeral X25519 public key (RFC 7748 LE u-coordinate)
1160   2     wrapped_len   u16 = 72 for suite 1
1162   72    wrapped_kw    XChaCha20-Poly1305(wrapping_key_i, KW): nonce(24)‖ct(32)‖tag(16)
                           AAD = "dctl-kem-kw-v1::" ‖ fixed_head(68) ‖ hybrid_suite(1)
                                 ‖ key_id(32)
```
`rec_len` = 4+32+2+1088+2+32+2+72 = **1234**. `K = 10 + 1234·N`. The §3 cap
`kem_ct_len ≤ 65535` ⇒ **N ≤ 53** for suite 1 (`floor((65535−10)/1234) = 53`).

At object offset `70+K`, the §3 trailing field is **unchanged**:
```
70+K  72    wrapped_dek   XChaCha20-Poly1305(KW, DEK): nonce(24)‖ct(32)‖tag(16)
                          AAD = "dctl-dek-v1::" ‖ fixed_head(68).  KW IS the §3
                          "§12 recipient hybrid key".
```

**Reader structural validation (MANDATORY, before any crypto or allocation** — same
discipline as §2 slot bounds):
- `kw_magic == "DKW1"`, `kw_version == 0x01`, `hybrid_suite` supported, `reserved == 0`,
  no unknown `kw_flags` bit set; else **reject the object**.
- `1 ≤ recip_count ≤ 53`; `kem_ct_len == 10 + Σ rec_len`; every sub-record lies wholly
  within `[70, 70+K)`; for suite 1 each `rec_len == 1234`, `ct_m_len == 1088`,
  `eph_pk_len == 32`, `wrapped_len == 72` **exactly**; any deviation ⇒ **reject**.
- Recipients are matched by `key_id`; **order is not significant**. A reader that
  supports the suite but finds no matching `key_id` cannot decrypt (expected — it is not
  a recipient); if `kw_flags.bit0` is set it MAY then consult the sidecar (§12.6).

**Recipient-set framing is DoS-only, by frozen decision.** `recip_count`/`kem_ct_len`
sit at/after offset 68, **outside** the 68-byte head, so they are not AEAD-bound to any
key holder. This is accepted: every per-recipient wrap is AEAD-bound to `head + key_id`
and the DEK wrap fails closed, so a truncated/reordered/injected recipient list can only
**deny service** to a recipient (inherent for public objects) — it can never break
confidentiality or integrity, nor make a wrong `KW` open. The structural checks above
catch every malformed block before any crypto runs. (No length field is
unauthenticated *in effect*: each is a pinned constant, cross-checked against `rec_len`
and `kem_ct_len`, and every framed payload is additionally AEAD- or transcript-bound.)

### 12.3 Recipient identity `DRK1` & key-id (FROZEN)

Encoded long-term hybrid **public** key (`DRK1`, 1222 bytes):
```
Off   Size  Field
0     4     magic         "DRK1" (0x44 0x52 0x4B 0x31)
4     1     version       0x01
5     1     hybrid_suite  0x01
6     32    x_pk          static X25519 public (RFC 7748 LE u-coordinate)
38    1184  ek            ML-KEM-768 encapsulation key (FIPS 203 canonical bytes)
```
**Stable key-id (32 bytes):** `key_id = BLAKE3-256("dctl-recip-id-v1\x00"(17) ‖
DRK1(1222))` — unkeyed BLAKE3, domain-prefixed, full 32-byte output (no truncation
ambiguity). Because `key_id` hashes **both** static pubkeys, binding it into the HKDF
`info` and `wrapped_kw` AAD binds the recipient's complete identity. (Combiner
robustness does **not** depend on this hash — the two static pubkeys are also bound
verbatim in `info`, §12.1.)

**Where public keys live** (so a write-only agent can obtain them; three sources, any
suffices, all self-verified by `key_id`):
1. **Local config** — the agent is provisioned out-of-band with the `key_id`s it must
   encrypt to (the **trust anchor**), optionally with the `DRK1` bytes inline.
2. **Public registry object `DRR1`** at backend key `"r/" ‖ hex(key_id)`, **unencrypted**
   (public-key material needs no confidentiality):
   ```
   Off   Size  Field
   0     4     magic       "DRR1" (0x44 0x52 0x52 0x31)
   4     1     version     0x01
   5     1     reserved    0x00
   6     2     pubkey_len  u16 = 1222
   8     1222  DRK1        recipient public key
   1230  2     label_len   u16
   1232  L     label       UTF-8, advisory only
   ```
3. **Out-of-band** (paste/QR of `DRK1` or `key_id`) for ad-hoc sharing.

**Trust anchor (NORMATIVE):** before encrypting to any obtained `DRK1`, a writer MUST
recompute `key_id = BLAKE3-256("dctl-recip-id-v1\x00" ‖ DRK1)` and require it **equals a
`key_id` it trusts out-of-band** (config allowlist). This makes the id self-certifying: a
hostile backend cannot substitute a different pubkey under a pinned `key_id`, so the
registry needs no signature. Labels are advisory and unauthenticated; recipient selection
is **by `key_id`, never by label**. The registry is authoritative only for *discovering*
the `DRK1` bytes of an **already-pinned** `key_id`, not for discovering a genuinely new
recipient without an out-of-band anchor.

### 12.4 Recipient private-key storage (via the §2 envelope) (FROZEN)

Recipient private keys are **deterministically derived from the vault root** — no new
`DKE1` slot type, no stored private-key object, **zero new persisted bytes**. Given
`root(32)` and identity index `idx(u32 LE, 0 = default vault identity)`:
```
rseed = SUBKEY(root,  "dctl-recip-seed-v1"(18) ‖ idx(u32 LE))     (32B)
x_sk  = SUBKEY(rseed, "dctl-recip-x25519-v1"(20))                 (32B; X25519 clamps internally)
d     = SUBKEY(rseed, "dctl-recip-mlkem-d-v1"(21))                (32B)
z     = SUBKEY(rseed, "dctl-recip-mlkem-z-v1"(21))                (32B)
(ek, dk) = ML-KEM-768.KeyGen_internal(d, z)                       (FIPS 203 Alg. 16 — seed
                                                                   order (d, z), deterministic)
x_pk  = X25519(x_sk, 9);  DRK1 = magic‖ver‖suite‖x_pk‖ek;  key_id per §12.3
```
Each label is a distinct pinned §1 `SUBKEY` call, so a side-channel on one derivation
does not expose the others. `idx=0` is the only launch identity; `idx ≥ 1` is **reserved**
for rotation / multiple identities per vault (discovery of which `idx` a device holds is
unspecified at launch).

**Composition with §2 + portability invariant:** the recipient keypair is a pure function
of `root`, and §2 guarantees **≥1 portable slot** (password/mnemonic) recovers `root` on
**every** device. So cross-device recovery is automatic: unlock the vault anywhere →
`root` → re-derive `(x_sk, dk)` bit-for-bit (`ML-KEM-768.KeyGen_internal` is deterministic
in `(d, z)`; X25519 clamping is fixed). No new slot type, the envelope and portability
invariant are untouched, and the identity rotates only when the root does (§11).

**Basic sharing needs no imported keys:** a share recipient reads with **their own**
vault's root-derived private key; the writer needs only their `DRK1`. Write-only backup is
read by the restore operator's own root-derived identity. **Imported/external keypairs**
(e.g. a key generated elsewhere, or a shared team key) are held in the root-sealed
`"k/" ‖ hex(key_id)` imported-key store **`DIK1` (§13)**, so a vault can also decrypt
objects sealed to those identities (multi-identity — the identity set is the root-derived
`idx=0` plus every valid `DIK1`). A `"k/*"` object whose `DIK1` `version`/`hybrid_suite` is
unknown is **rejected as an entry** (one-way door, §8), never affecting the vault.

### 12.5 Multi-recipient (FROZEN)

One object → *N* recipients all recovering the **same DEK**, via one indirection: the DEK
is wrapped **once** under the per-object random `KW` (the §3 trailing `wrapped_dek`,
unchanged); `KW` — not the DEK — is what each recipient sub-record independently wraps.
Recipient *i* unwraps `wrapping_key_i → KW → the single shared DEK`. Cost: `N·1234` bytes
of `kem_wrap` (dominated by the 1088-byte ML-KEM ct) + one 72-byte DEK wrap, versus *N*
full DEK wraps; each per-recipient wrap covers only the 32-byte `KW`. Recipients never
interact; injected/duplicate/reordered sub-records are harmless (an attacker cannot forge
a valid `KW` wrap without a recipient private key). A grant is **standalone-decodable**
from `{recipient private key, fixed_head, that one sub-record}`.

**Write-only backup (a):** the agent holds **only** public keys. It generates
`DEK + KW + per-recipient ephemerals/encapsulations`, writes inline recipients for each
backup `key_id` **plus the vault owner's root-derived `key_id`** (durability mitigation,
§12.8), then **MUST zeroize** `DEK, KW, eph_sk, m`. Nothing it persists (public keys + the
written object) can re-derive `KW` or `DEK` — that needs a recipient private key it does
not hold — so it cannot read back what it wrote.

**Sharing (b):** grant read to specific recipients by including their sub-records. Adding
or removing a recipient **in place** would change `K` and shift every downstream payload
offset (`70+K`, `146+K`, all chunks) — forcing a full re-upload of a possibly multi-GB
object. Launch therefore adds a **rewritable grant sidecar** (§12.6) so recipient-set
edits touch only a small separate object and never the payload. **Revocation caveat
(§11):** removing a recipient blocks *future* `KW` recovery but cannot un-decrypt a copy
an ex-recipient already downloaded; true revocation requires re-sealing under a fresh
`DEK` (re-encrypt payload).

### 12.6 Grant sidecar `DGS1` (FROZEN)

A separate, rewritable object at backend key `"g/" ‖ hex(file_id)` carries **additional**
recipients for an existing object **without re-uploading its payload** — in the spirit of
§5's rewritable name records. The main DSF1 object (`file_id`/`DEK`/`KW`/head/payload) is
untouched.
```
Off   Size  Field
0     4     magic         "DGS1" (0x44 0x47 0x53 0x31)
4     1     version       0x01
5     1     hybrid_suite  0x01
6     2     reserved      0x0000 — MUST be 0
8     16    file_id       MUST equal the DSF1 file_id (binds sidecar to object)
24    32    head_hash     BLAKE3-256 of the DSF1 fixed 68-byte head (binds to exact head)
56    8     grant_gen     u64 monotonic (higher wins on rewrite races)
64    2     grant_count   u16 — G grants, 0 ≤ G ≤ 4096
66    …     grants[G]     identical recipient sub-record format as §12.2 (rec_len=1234)
```
Each grant **still folds `fixed_head(68)`** into its `wrapping_key` `info` and its
`wrapped_kw` AAD (§12.1), so it is cryptographically bound to the exact object regardless
of storage location; `file_id + head_hash` give fast structural binding and detect a
sidecar attached to the wrong object. A reader MUST verify `magic`/`version`/
`hybrid_suite`, `file_id == object.file_id`, and `head_hash == BLAKE3-256(head)` — reject
the sidecar on any mismatch — then scan `grants` for its `key_id`. The **first**
successful `KW` recovery (inline or sidecar) wins.

**Add (share):** a manager holding a valid grant recovers `KW` (open its own grant →
`wrapping_key → KW`), encapsulates `KW` to the new recipient (fresh `eph_pk` + Encaps),
appends a sub-record, bumps `grant_gen`, and rewrites `g/<file_id>` — O(1) even for
multi-GB video. **Remove (revoke future access):** rewrite the sidecar omitting the grant,
bump `grant_gen` (same §11 captured-copy caveat as §12.5). **Guidance:** put **durable**
recipients (owner, permanent backup key) **inline** — they cannot be removed without
re-uploading the object — and put **revocable** recipients in the **sidecar**.

**Rollback (residual, benign):** a replayed old sidecar can only re-add a
previously-valid grant, which grants an outsider nothing new (it never learns `KW`) and,
since captured copies are unrevocable anyway (§11), is not a new capability. Defenses are
`grant_gen` monotonicity plus a recommendation to use backend conditional-PUT / object-
lock; a non-root recipient cannot cryptographically verify sidecar freshness (flagged).

### 12.7 Forward secrecy (stated precisely)

This is **static-recipient at-rest** encryption, so FS against recipient-key compromise is
fundamentally impossible (the recipient must decrypt at an arbitrary later time with a
long-term secret):
- **ML-KEM leg — fully static.** Recipient `ek/dk` are long-term (root-derived). **No
  forward secrecy:** anyone who later obtains `dk` (or the `root` that derives it) recovers
  `K_m` from the stored `ct_m` for **every** past object encrypted to that recipient.
- **X25519 leg — fresh ephemeral per (object, recipient).** `eph_sk` is destroyed after
  wrapping. This gives FS **only** against theft of that discarded ephemeral state; it does
  **not** protect `ss_x` against compromise of the recipient's static `x_sk` (root-derived)
  — an attacker with the stored `eph_pk` and `x_sk` recomputes `ss_x = X25519(x_sk,
  eph_pk)`.
- **Net:** because `wrapping_key` needs both shared secrets and both static secrets are
  root-derived, **recipient/root compromise breaks confidentiality of all past objects**
  to that recipient — there is **no** forward secrecy against it (by design; durable
  offline recoverability and rotating recipient keys are mutually exclusive).
- **Sender/agent side:** a write-only agent holds only public keys and zeroizes
  `DEK/KW/eph_sk/m` after upload, so **uploader compromise reveals nothing** about any
  object it wrote (a forward-secrecy-like property against agent theft).
- **What this layer does buy:** harvest-now-decrypt-later resistance against a purely
  **quantum** adversary **without the root** — the ML-KEM leg keeps harvested public
  objects secret even if X25519 later falls (consistent with §11's PQ posture). True
  ratcheting / receiver-side FS is out of scope and would need a future ephemeral-recipient
  suite (a new `hybrid_suite`).

**Sender authentication (gap, documented):** `kem_id=1` v1 provides **confidentiality +
AEAD integrity but NOT origin authentication** — anyone with a recipient's public key can
seal an object that recipient will accept, and a recipient cannot tell **who** sealed it.
This is acceptable for write-only backup and is a known limitation for sharing. A future
**signed-sender** suite (`hybrid_suite ≥ 2`: hybrid Ed25519 + ML-DSA-65 signature over
`fixed_head ‖ kem_wrap`) is reserved.

### 12.8 AAD binding, anti-transplant & C-decoder scope (FROZEN)

**AAD binding** — every wrap binds the 68-byte head **and** the recipient `key_id` (and
the suite), at both the KDF and the AEAD layer:
1. **Per-recipient `wrapped_kw`:** `AAD = "dctl-kem-kw-v1::" ‖ fixed_head(68) ‖
   hybrid_suite(1) ‖ key_id(32)`. The head already contains `file_id` and `kem_id=1`
   (byte 6), so a valid sub-record cannot be transplanted to another **object** (different
   head → tag fails) or another **recipient** (different `key_id` → tag fails).
2. **`wrapping_key` derivation `info`** additionally folds `hybrid_suite`, `fixed_head`,
   `key_id`, `eph_pk`, `ct_m`, and **both** recipient static pubkeys, so even the *key* is
   object/recipient/transcript-specific and any tamper of `eph_pk`/`ct_m` yields a
   different key (Open fails).
3. **Trailing `wrapped_dek`:** `AAD = "dctl-dek-v1::" ‖ fixed_head(68)` — **identical to
   §3/`kem_id=0`**, only the key is `KW`. No wrap omits the head; no per-recipient block
   omits `key_id`.

**Nonce/key hygiene:** `KW` is fresh CSPRNG **per object**, wraps exactly **one** plaintext
(the trailing `wrapped_dek`) and is never reused across objects; every `wrapped_kw` and
`wrapped_dek` nonce is a fresh 24-byte CSPRNG value; per-recipient `wrapping_key_i` are all
distinct (distinct ephemerals/encapsulations), so no `(key, nonce)` pair ever repeats.

**Unknown-handling (consistent with §8):** `kw_version` / `hybrid_suite` route through the
**one-way "reject unknown `kem_id`/algo"** door — an unsupported value ⇒ **reject the
object** ("unsupported KEM suite"), never attempt-and-fail. `kw_flags` unknown bit,
non-zero `reserved`, or any structural mismatch (§12.2) ⇒ **reject**. A `"k/*"` (`DIK1`,
§13) entry or a `"d/*"` (`DGD1`, §14) record whose `version`/`hybrid_suite` is unknown is
**rejected as that entry/record** (one-way door), never affecting the vault or other
objects. Registry additions to §8 namespaces: `r/<hex key_id>` = public recipient registry
(`DRR1`, no secrets); `g/<hex file_id>` = grant sidecar (`DGS1`); `k/<hex key_id>` =
imported-key store (`DIK1`, §13, root-sealed private keys);
`d/<hex recipient_key_id>/<hex file_id>` = shared-object discovery record (`DGD1`, §14,
sealed to the recipient).

**C-reference-decoder scope — DECISION:** the minimal, frozen-forever C99 reference
decoder covers **only `kem_id=0`** (symmetric owner path: Argon2id + XChaCha20-Poly1305 +
BLAKE3). `kem_id=1` is **out of scope**; a C reader lacking KEM support MUST **reject** a
`kem_id=1` object per §8, never attempt-and-fail. **Justification:** (1) §6 already commits
the minimal decoder to `kem_id=0`; this is consistent, not a new burden. (2) The 20-year
self-restorable-archive guarantee is the **symmetric** path — a lone survivor with the
password/mnemonic and this document recovers data with a few hundred lines of C; adding
ML-KEM-768 + SHAKE256/Keccak + X25519 (~1500+ lines carrying constant-time and FIPS-203
correctness burden that can never be patched under a freeze) would multiply the auditable
surface for two decades. (3) `kem_id=1` is inherently an **online, multi-party** feature
(sharing / write-only backup); only a private-key holder can read such an object, and that
holder necessarily runs a full implementation that already has the KEM stack (ML-KEM-768 is
a FIPS standard, so validated implementations remain available). No one is ever stranded
needing the KEM in the minimal decoder. **Durability mitigation (NORMATIVE):** because a
write-only backup has no symmetric fallback, a writer MUST include the **vault owner's
root-derived recipient identity** among the recipients of every `kem_id=1` object, so the
owner can always re-derive keys via a portable §2 slot and recover the object (with a
standard ML-KEM-768 implementation).

### 12.9 Delegated-upload ticket (transient capability; NOT a stored format)

A **Backend** capability (the §9-rule-3 `prepare_upload`) that hands a constrained client a
short-lived authorization to upload **one** object key **directly to the backend**, so a
mobile/background client (e.g. iOS `URLSession` background upload) transfers ciphertext
without routing the bytes through a DCTL server. **Transient — no magic, no on-disk bytes,
no `version`/`hybrid_suite`; it is never persisted** and rides the app's ordinary IPC/JSON
transport. It changes **no** §2/§3/§12 byte layout.

**Seal-then-delegate (security property, NORMATIVE).** The client seals the whole `DSF1`
object **locally first** (§3; `kem_id=0` root-wrapped, or `kem_id=1` §12 recipient-hybrid).
The `DEK`, the per-object `KW`, and all plaintext are generated and consumed entirely
client-side; the finished object is already ciphertext before any ticket is requested. The
ticket delegates **only TRANSPORT** — the single HTTP request that writes those bytes to a
backend key. **The presigner/issuer never sees plaintext, the `DEK`, or `KW`.** It signs a
URL/headers with **backend** credentials (S3/R2 secret key, or a B2 account/app-key auth),
so a fully compromised presigner can authorize only *where* ciphertext is written — it can
never read any object's contents. This is the strongest form of the "server moves bytes,
never keys" separation.

**`UploadTicket` wire contract** (transient; a field contract, not a byte layout):

| Field | Type | Meaning |
|---|---|---|
| `method` | ASCII | `"PUT"` for S3/R2 (SigV4 presigned PUT); `"POST"` for B2 (`b2_get_upload_url`) |
| `url` | UTF-8 | absolute URL the client sends the request to, verbatim, including any query string |
| `headers` | ordered list of (name, value) | headers the client **MUST** send **verbatim and in the given order**; it MUST NOT add, drop, reorder, or re-case a signed header, or the backend rejects the write |
| `expires_unix` | optional `i64` | absolute expiry (present for SigV4; **absent for B2**, whose token is scope- not time-bounded) |

**S3 / R2 — SigV4 presigned PUT (query-auth).** `method = "PUT"`; `url` carries the SigV4
query parameters `X-Amz-Algorithm=AWS4-HMAC-SHA256`, `X-Amz-Credential`, `X-Amz-Date`,
`X-Amz-Expires` (seconds, `1 ≤ e ≤ 604800`), `X-Amz-SignedHeaders`, and `X-Amz-Signature`;
the path key is `o/<hex file_id>` (§3). `headers` lists exactly the `X-Amz-SignedHeaders`
the client must reproduce (at minimum `host`, implied by `url`). `expires_unix =
X-Amz-Date + X-Amz-Expires`. **Content-hash binding (choice, trade-off noted):** the issuer
MAY bind the exact body by signing `x-amz-content-sha256 = <hex SHA-256 of the sealed
ciphertext>` as a signed header — pinning the upload to the exact bytes (tamper-evident at
write) — **or** sign `x-amz-content-sha256 = UNSIGNED-PAYLOAD`, which does not bind the body
(simpler for a streaming background upload, but the signature then attests only the key, not
the bytes). Both are acceptable because DCTL objects are self-verifying on open (below);
binding is preferred whenever the client can precompute the ciphertext hash.

**B2 — `b2_get_upload_url` result (token-scoped).** The issuer calls `b2_get_upload_url` and
returns `method = "POST"`, `url =` the returned `uploadUrl`, and `headers` (ordered,
verbatim): `Authorization: <authorizationToken>` · `X-Bz-File-Name: <percent-encoded
o/<hex file_id>>` · `Content-Type: b2/x-auto` (or `application/octet-stream`) ·
`Content-Length: <ciphertext length>` · `X-Bz-Content-Sha1: <hex SHA-1 of the sealed
ciphertext>` (the literal `do_not_verify` is permitted but discouraged — it drops B2's own
write check). **No time expiry:** a B2 upload URL + token is a bearer capability scoped to
one bucket/upload endpoint with **no `expires_unix`**; it stays usable until B2 retires it
or an upload fails (one in-flight upload per URL — a client needing parallelism requests
multiple tickets). Treat the token as short-lived by policy even without a hard timestamp.

**Verified-write caveat (NORMATIVE).** A delegated PUT/POST goes straight to the backend, so
DCTL cannot run its usual whole-file **server-side** verify — there is no server in the byte
path. Responsibility shifts to the **client**, which MUST send the exact sealed bytes and
check the HTTP result (2xx + `ETag`/`fileId`). The **owner SHOULD** perform a follow-up
`HEAD` (size/`ETag`) or `GET`+verify to confirm the object landed intact and complete.
Regardless, the object is **self-verifying on any later open**: `DSF1` per-chunk Poly1305
tags with head-bound AAD (§3), the optional BLAKE3 footer, and the §4 `content_blake3` all
fail closed against a truncated/corrupted/substituted body, so a bad delegated upload can
never be silently opened as valid — it simply fails to open. A missed follow-up check is
therefore a **durability/availability** risk, never a confidentiality/integrity one.

### 12.10 Cross-device & freeze gate

All new bytes are little-endian and fixed-width; only public-standard primitives are used
(RFC 7748 X25519, FIPS 203 ML-KEM-768 via the deterministic `KeyGen_internal`/
`Encaps_internal`/`Decaps_internal`, RFC 5869 HKDF-SHA512 = the pinned §1 `SUBKEY`,
XChaCha20-Poly1305, BLAKE3-256); no clock, locale, endianness, or floating-point
assumptions; no timestamps in this layer. Every ASCII domain/AAD label is pinned verbatim
with its exact byte length (`"dctl-kem-hybrid-x25519-mlkem768-v1"`=34, `"dctl-kem-kw-v1::"`
=16, `"dctl-recip-id-v1\x00"`=17, `"dctl-recip-seed-v1"`=18, `"dctl-recip-x25519-v1"`=20,
`"dctl-recip-mlkem-d-v1"`=21, `"dctl-recip-mlkem-z-v1"`=21; `"dctl-dek-v1::"`=13 is the
unchanged §3 label), with `idx` as `u32 LE`. Recipient keypairs are a pure deterministic
function of the already-portable `root`, so any device that unlocks the vault reproduces
the same `key_id, x_pk, ek, dk` bit-for-bit; two clean-room implementers given `root`, a
`DEK`, a `KW`, per-recipient `(eph_sk, m)`, **every per-wrap AEAD nonce** (`wrapped_kw`
and `wrapped_dek`), and a head produce identical `kem_wrap` and `wrapped_dek` bytes.

**Freeze gate (§11 doc↔code parity — MANDATORY before this section is frozen):** publish
encoder-generated byte-exact KAT vectors covering, at minimum, one **1-recipient** and one
**N-recipient** `kem_id=1` object; the root-derived `(rseed → x_sk, d, z → ek, dk,
key_id)` derivation; and deterministic ML-KEM-768 `KeyGen_internal(d,z)` /
`Encaps_internal(ek,m)` / `Decaps_internal(dk,ct)` and X25519 vectors. The format is frozen
only once these pass.

---

## 13. Imported-key store `DIK1` (`k/<hex key_id>`) — FROZEN

Activates the reserved `k/*` namespace (§8/§12.8). Besides its root-derived identity (§12.4,
`idx=0`), a vault MAY hold one or more **imported** external recipient keypairs — a key
generated elsewhere, or a shared team key — so it can also decrypt objects sealed to those
identities (multi-identity). Each imported keypair is one `DIK1` container at backend key
`"k/" ‖ hex(key_id)`. **This adds no §2/§3/§12 byte change and no new primitive:** the
private material is sealed with the pinned §1 `SUBKEY` + XChaCha20-Poly1305, exactly like
every other DCTL wrap, and is offline-restorable from the vault root alone.

```
Off    Size  Field  (cleartext header)
0      4     magic          "DIK1" (0x44 0x49 0x4B 0x31)
4      1     version        0x01
5      1     hybrid_suite   0x01 = X25519 + ML-KEM-768 (unknown ⇒ reject THIS entry, §8)
6      2     reserved       0x0000 — MUST be 0 (reject the entry if nonzero)
8      32    key_id         §12.3 key_id recomputed from the imported PUBLIC keys; MUST
                            equal the "k/…" path component and the body recompute (below)

── sealed body: XChaCha20-Poly1305(k_wrap, plaintext); k_wrap root-derived (below) ──
40     24    nonce          fresh CSPRNG per write (24-byte XChaCha20 nonce)
64     3648  ct             AEAD ciphertext of the 3648-byte sealed plaintext below
3712   16    tag            Poly1305 tag
```
`DIK1` total = `40 + 24 + 3648 + 16` = **3728** bytes.

**Sealed plaintext (3648 bytes; visible only after the root-key AEAD opens):**
```
Off    Size  Field
0      32    x_sk    imported static X25519 secret (RFC 7748; StaticSecret clamps on use)
32     2400  dk      imported ML-KEM-768 decapsulation key (FIPS 203 canonical bytes)
2432   32    x_pk    matching static X25519 public (RFC 7748 LE u-coordinate)
2464   1184  ek      matching ML-KEM-768 encapsulation key (FIPS 203 canonical bytes)
```

**Root-derived wrapping key (parallel to §12.4 — this is the `k/*` wrapping key):**
```
k_wrap = SUBKEY(root, "dctl-ik-wrap-v1"(15) ‖ key_id(32))     (32B; pinned §1 SUBKEY)
```
Folding `key_id` (as §12.4 folds `idx`) makes `k_wrap` **entry-specific**, so distinct
imported keys never share a wrapping key and a fresh 24-byte nonce per write can never form
a repeated `(key, nonce)` pair. `k_wrap` is a pure function of the vault `root`, so an
imported key is recoverable offline through any portable §2 slot — like everything else.

**Sealed-body AEAD:** `nonce(24) ‖ ct(3648) ‖ tag(16) = XChaCha20-Poly1305(k_wrap, nonce,
plaintext, AAD)`, where
`AAD = "dctl-ik-v1::"(12) ‖ magic(4) ‖ hybrid_suite(1) ‖ key_id(32)` (49 bytes). The AAD
binds the body to its `magic`, suite, and `key_id`, so a body cannot be lifted into a
container claiming a different identity (the tag fails).

**Load semantics (one-way door — §8).** On unlock the vault MAY list `k/*` and, for each:
1. Parse the cleartext header; if `magic ≠ "DIK1"`, or `version`/`hybrid_suite`
   unsupported, or `reserved ≠ 0` ⇒ **reject THIS entry** (skip it), **never the vault**.
2. Derive `k_wrap = SUBKEY(root, "dctl-ik-wrap-v1" ‖ header.key_id)` and AEAD-open the body
   (AAD above); an AEAD failure ⇒ reject the entry (the tag is the sole accept gate).
3. **Self-consistency (MANDATORY):** recompute
   `key_id′ = BLAKE3-256("dctl-recip-id-v1\x00" ‖ DRK1(x_pk, ek))` (§12.3) from the body's
   **public** keys and require `key_id′ == header.key_id == the "k/…" path component`; else
   reject the entry. A writer SHOULD additionally verify `x_pk == X25519(x_sk, 9)` and that
   `ek` matches `dk`'s embedded encapsulation key (FIPS 203) before importing.
4. Add `{key_id, x_sk, dk, x_pk, ek}` to the vault's **identity set**. §12.5
   `open_as_recipient` tries every identity in the set (root-derived `idx=0` plus each valid
   `DIK1`) when opening a `kem_id=1` object, so the vault opens objects sealed to any
   identity it holds.

**Trust / sender-auth caveat (inherited from §12.7).** An imported key is trusted only
because the owner chose to import it (out-of-band provenance). `kem_id=1` still provides
**no origin authentication** in v1 — a key that a third party also holds (a shared team key)
can seal objects the vault will accept, and the vault cannot tell **who** sealed them. Like
all §12 asymmetric material, `DIK1` is **out of the minimal C reference decoder's scope**
(§6/§12.8, `kem_id=0` only). `DSF1`/`DKE1`/`DGS1`/`DRR1` bytes are unchanged.

---

## 14. Shared-object discovery `DGD1` (`d/<hex recipient_key_id>/<hex file_id>`) — FROZEN

Adds the new `d/*` namespace (§8/§12.8). A recipient can **decrypt** a shared object once it
knows the `file_id` (its inline `kem_wrap` sub-record §12.2, or a `DGS1` grant §12.6), but
it cannot **enumerate** which objects are shared to it: name records (`n/*`, §5) are keyed to
the **owner's** name keys, which a recipient does not hold. A per-recipient **discovery
record** solves enumeration — consistent with the shared-backend model that `r/*` and `g/*`
already assume (the recipient reads the owner's backend). The owner writes one `DGD1` per
(recipient, object) at `"d/" ‖ hex(recipient_key_id) ‖ "/" ‖ hex(file_id)`; the recipient
lists `d/<its key_id>/*` to learn the set of `file_id`s shared to it, then opens each.
**No §3/§12.2/§12.6 byte change and no new primitive** — the record is sealed with the same
§12 hybrid machinery as a §12.2 grant.

```
Off    Size  Field  (cleartext header)
0      4     magic             "DGD1" (0x44 0x47 0x44 0x31)
4      1     version           0x01
5      1     hybrid_suite      0x01 (unknown ⇒ reject THIS record, §8)
6      2     reserved          0x0000 — MUST be 0
8      32    recipient_key_id  §12.3 key_id this record is sealed to; MUST equal the
                               "d/<recipient_key_id>/…" path component
40     16    file_id           MUST equal the DSF1 file_id and the ".../<file_id>" component
56     32    head_hash         BLAKE3-256 of the DSF1 fixed 68-byte head (binds the exact
                               object head, like §12.6 DGS1)

── wrapped_dw: ONE §12.2 recipient sub-record (rec_len = 1234) sealing DW to recipient ──
88     1234  wrapped_dw        byte-identical §12.2 sub-record, bound to the object's
                               fixed_head(68) and recipient_key_id (§12.1); wraps the fresh
                               per-record 32-byte discovery key DW (the discovery analogue
                               of the object KW, §12.5)

── sealed_body: XChaCha20-Poly1305(DW, disc_plaintext) ──
1322   24    nonce             fresh CSPRNG per write
1346   D     ct                AEAD ciphertext of the disc_plaintext below
1346+D 16    tag               Poly1305 tag
```
`DGD1` total = `1362 + D` bytes, where `D = 62 + path_len + ext_len`.

**Discovery plaintext (`disc_plaintext`; visible only to the recipient after `DW` opens):**
```
Off    Size  Field
0      1     disc_schema     0x01 (unknown ⇒ skip parsing this record, cf. §4 schema_version)
1      1     obj_suite       object hybrid_suite echo (0x01) — cross-check
2      16    file_id         MUST equal header.file_id and the fetched object
18     8     size            u64 — object plaintext size (== head.plaintext_len / §4 size)
26     32    content_hash    BLAKE3-256 of object plaintext (== §4 content_blake3)
58     2     path_len        u16 — authoritative NFC UTF-8 path length (§5); ≥ 1
60     P     path            authoritative NFC UTF-8 path (§5 rules; reader RE-validates)
60+P   2     ext_len         u16 — trailing extension region length (forward growth)
62+P   E     ext             TLVs [type u8][len u16][value]; unknown types ignored
```
`disc_plaintext` = `62 + P + E` bytes. Its AEAD binds the whole header:
`AAD = "dctl-disc-v1::"(14) ‖ dgd1_header(88)` (folds `magic`, `version`, `hybrid_suite`,
`recipient_key_id`, `file_id`, `head_hash`).

**Seal (owner).** Generate `DW` = 32 fresh CSPRNG bytes. `wrapped_dw` = the §12.2 encaps of
`DW` to the recipient's `DRK1` bound to the object's `fixed_head(68)` — the **identical**
call used for a §12.6 grant, so `wrapped_dw` IS a `rec_len = 1234` sub-record.
`sealed_body = XChaCha20-Poly1305(DW, disc_plaintext, AAD)`. Zeroize `DW`. Because the §12.2
sub-record already folds `fixed_head(68)` (which contains `file_id` and `kem_id`) and the
recipient `key_id` into both its combiner `info` and its `wrapped_kw` AAD (§12.1/§12.8), and
the body AAD folds the whole `DGD1` header, the seal binds **recipient_key_id + file_id +
the object head** at the crypto layer — only that recipient recovers `DW`, hence the
path/size/hash.

**Read (recipient).** List `d/<own key_id>/*` → the `file_id` set. For each record:
1. Verify `magic`/`version`/`hybrid_suite`/`reserved`; `recipient_key_id == own key_id ==
   path component`; `file_id == path component`; and the `wrapped_dw` sub-record `key_id`
   (bytes `[4..36]`, validated per §12.2) `== recipient_key_id`. Any mismatch ⇒ reject THIS
   record.
2. Fetch the object head `o/<hex file_id>` (68 bytes, one Range request); verify
   `head_hash == BLAKE3-256(head)` and `head.file_id == header.file_id`, else reject
   (anti-transplant — the record cannot be moved to another object).
3. Decapsulate `DW` from `wrapped_dw` using the object's `fixed_head(68)` and the
   recipient's private key (§12.1 decaps; the AEAD tag is the sole accept gate). A key that
   is not this recipient's ⇒ tag fails.
4. Open `sealed_body` under `DW` (AAD = `"dctl-disc-v1::" ‖ header(88)`); verify
   `body.file_id == header.file_id`; RE-validate `path` per §5 before any filesystem use.

**Anti-tamper / anti-transplant.** The seal binds the **recipient** (only that `key_id`
recovers `DW`) and the **object** (the sub-record folds the object head; `head_hash` +
`file_id` give fast structural binding, both re-checked against the fetched object). So a
record cannot be transplanted to another recipient (wrong `key_id` ⇒ no `DW`) or another
object (wrong head ⇒ `head_hash`/decap/`file_id` mismatch). A hostile backend that merely
stores `DGD1`s cannot read **paths** or **content hashes** — both stay encrypted under `DW` —
but it does learn an **accepted metadata surface**: the storage key
`d/<recipient_key_id>/<file_id>` exposes the recipient↔object **sharing-graph edge** in
cleartext, so a `LIST` reveals which `key_id` may discover which `file_id`, each recipient's
object count, and co-recipient sets. This is the **same class** already exposed by the
cleartext `key_id`s in inline §12.2 sub-records and `DGS1` sidecars — `DGD1` adds no new leak
class, only elevates the edge to `LIST`-visible metadata. The `size` in `disc_plaintext` is
likewise **not** confidential from the backend: it equals the cleartext `plaintext_len` of the
DSF1 fixed head (§3), which a backend can `Range`-fetch from `o/<file_id>` directly — it is
carried under `DW` purely for enumeration convenience, not as a confidentiality guarantee.

**Discovery grants no read access by itself.** `DGD1` wraps only `DW` — a pointer/index key
— never the object `KW`/`DEK`. A recipient still needs a valid inline sub-record (§12.2) or
`DGS1` grant (§12.6) to recover the object `KW` and read content, so a discovery record is
purely an enumeration aid.

**Lifecycle.** The owner writes `d/<key_id>/<file_id>` **during share**, alongside the
`DGS1` grant (§12.6), and **DELETES it on revoke**. Same §11 **captured-copy caveat**: a
recipient that already fetched a `DGD1` retains the path/size it revealed (as it retains any
downloaded copy) — deletion stops *future* discovery, not past. **Rollback note (as
§12.6):** `DGD1` carries no generation counter — it is a single per-(recipient, object)
pointer, rewritten/deleted wholesale rather than an appended grant list — so a replayed old
record only re-lists an object whose *actual* read access is still gated by the object's
`kem_wrap`/`DGS1` (revoking those is what removes access). Freshness otherwise relies on the
owner's delete-on-revoke plus a backend conditional-PUT / object-lock recommendation, and a
non-owner cannot cryptographically verify a discovery record's freshness (flagged, benign).

Like all §12 asymmetric material, `DGD1` is **out of the minimal C reference decoder's
scope** (§6/§12.8, `kem_id=0` only). `DSF1`/`DKE1`/`DGS1`/`DRR1` bytes are unchanged.
