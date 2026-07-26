/*
 * dctl-decode.c — dependency-free C99 reference decoder for the DCTL v1 format.
 *
 * Build:  cc -O2 -std=c99 -Wall -Wextra -Werror -o dctl-decode dctl-decode.c
 *         (no libraries, no build system — just libc)
 *
 * This single file is the 20-year "break-glass" decoder (see PLAN.md §13). It
 * decodes the FROZEN v1 on-disk format described in docs/FORMAT.md: the `DKE1`
 * slot-list key envelope (§2) and the `DSF1` self-describing object (§3-§4). It
 * inlines its crypto from public-domain reference code and depends only on libc,
 * and is cross-validated against the Rust implementation by known-answer tests
 * (crates/dctl-decode/tests/kat.rs) so the two independent implementations are
 * proven to agree byte-for-byte.
 *
 * Scope — the SYMMETRIC owner path only (`kem_id=0`: Argon2id + XChaCha20-Poly1305).
 * Per FORMAT.md §6/§12.8 this minimal decoder is deliberately limited to `kem_id=0`;
 * a `kem_id=1` recipient-hybrid object is REJECTED (it needs X25519 + ML-KEM-768,
 * which a private-key holder runs from a full implementation).
 *
 * Primitives: XChaCha20-Poly1305 (ChaCha20 + Poly1305 + HChaCha20) for every AEAD
 * wrap, and Argon2id (+ BLAKE2b) for the password->KEK step. These primitives are
 * UNCHANGED from the pre-v1 decoder — only the parsing/framing, the AAD strings, and
 * the CLI were rewritten for the DKE1/DSF1 layout.
 *
 * Two integrity checks defined by the format are intentionally SKIPPED here, and it
 * is safe to do so because a stronger check already covers the same bytes:
 *   - The per-slot `commit` field (§2 key-commitment) is NOT recomputed. It is an
 *     online-partitioning-oracle defense; the AEAD tag on `wrapped_root` is the
 *     actual correctness gate (a wrong KEK fails the tag). Skipping it keeps this
 *     decoder to Argon2id + XChaCha20-Poly1305 only — no SHA-512/HKDF port needed.
 *   - The whole-object BLAKE3 `footer` (§3) is NOT re-verified. Per-chunk Poly1305
 *     already authenticates every payload byte plus the head (via the AAD) and the
 *     chunk index, so truncation/reorder are caught without it — keeping this file
 *     free of a BLAKE3 port.
 *
 * Usage:
 *   dctl-decode --root HEX64  --in OBJECT --out PLAINTEXT
 *   dctl-decode --envelope ENV --password UTF8  --in OBJECT --out PLAINTEXT
 *   dctl-decode --argon2-kat
 *
 *   Root selection:
 *     --root HEX64            use the 32-byte root key directly (skips Argon2/envelope).
 *     --envelope + --password derive the root from a DKE1 envelope: for each password
 *                            slot, Argon2id(NFC(password), salt, params) -> KEK, then
 *                            AEAD-unwrap the root; the first slot whose tag verifies wins.
 *                            The password is passed as already-UTF-8/NFC bytes on argv.
 *   The object is SELF-DESCRIBING (embeds its own wrapped DEK + metadata), so no
 *   wrapped-DEK or object-key argument is needed.
 *   --in "-" reads stdin, --out "-" writes stdout; the object PAYLOAD is STREAMED one
 *   chunk at a time, never fully buffered, so multi-gigabyte files decode in ~chunk_size
 *   memory.
 *   --argon2-kat runs the RFC 9106 Argon2id self-test (prints the tag hex) so the KAT
 *   harness can validate the KDF port against the official spec, independent of DCTL.
 *
 * Provenance / licensing of the inlined primitives (recorded for a 2046 reader):
 *   - ChaCha20 / Poly1305 / HChaCha20 : D. J. Bernstein's designs; the Poly1305
 *     code follows Andrew Moon's public-domain "poly1305-donna" 32-bit reference.
 *   - Argon2id / BLAKE2b : follow the Password-Hashing-Competition reference
 *     (CC0 / Apache-2.0) and RFC 9106 / RFC 7693.
 *   These are all freely embeddable in a proprietary product; the attribution is
 *   kept here so the origin is knowable decades from now.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ helpers */

static uint16_t load16_le(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}
static uint32_t load32_le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint64_t load64_le(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= (uint64_t)p[i] << (8 * i);
    return v;
}
static void store32_le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static void store64_le(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}

/* ----------------------------------------------------------------- ChaCha20 */

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define QR(a, b, c, d)                                    \
    x[a] += x[b]; x[d] ^= x[a]; x[d] = ROTL32(x[d], 16);  \
    x[c] += x[d]; x[b] ^= x[c]; x[b] = ROTL32(x[b], 12);  \
    x[a] += x[b]; x[d] ^= x[a]; x[d] = ROTL32(x[d], 8);   \
    x[c] += x[d]; x[b] ^= x[c]; x[b] = ROTL32(x[b], 7);

static void chacha20_rounds(uint32_t x[16]) {
    for (int i = 0; i < 10; i++) {
        QR(0, 4, 8, 12) QR(1, 5, 9, 13) QR(2, 6, 10, 14) QR(3, 7, 11, 15)
        QR(0, 5, 10, 15) QR(1, 6, 11, 12) QR(2, 7, 8, 13) QR(3, 4, 9, 14)
    }
}

static void chacha20_block(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12], uint8_t out[64]) {
    uint32_t s[16], x[16];
    s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
    for (int i = 0; i < 8; i++) s[4 + i] = load32_le(key + 4 * i);
    s[12] = counter;
    s[13] = load32_le(nonce + 0); s[14] = load32_le(nonce + 4); s[15] = load32_le(nonce + 8);
    memcpy(x, s, sizeof x);
    chacha20_rounds(x);
    for (int i = 0; i < 16; i++) store32_le(out + 4 * i, x[i] + s[i]);
}

static void chacha20_xor(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12],
                         const uint8_t *in, uint8_t *out, size_t len) {
    uint8_t blk[64];
    size_t off = 0;
    while (len) {
        chacha20_block(key, counter, nonce, blk);
        size_t n = len < 64 ? len : 64;
        for (size_t i = 0; i < n; i++) out[off + i] = in[off + i] ^ blk[i];
        counter++; off += n; len -= n;
    }
}

static void hchacha20(const uint8_t key[32], const uint8_t nonce[16], uint8_t out[32]) {
    uint32_t x[16];
    x[0] = 0x61707865; x[1] = 0x3320646e; x[2] = 0x79622d32; x[3] = 0x6b206574;
    for (int i = 0; i < 8; i++) x[4 + i] = load32_le(key + 4 * i);
    for (int i = 0; i < 4; i++) x[12 + i] = load32_le(nonce + 4 * i);
    chacha20_rounds(x);
    for (int i = 0; i < 4; i++) store32_le(out + 4 * i, x[i]);
    for (int i = 0; i < 4; i++) store32_le(out + 16 + 4 * i, x[12 + i]);
}

/* ----------------------------------------------------------------- Poly1305 */
/* Based on the public-domain poly1305-donna 32-bit reference (Andrew Moon). */

typedef struct {
    uint32_t r[5], h[5], pad[4];
    uint8_t buf[16];
    size_t leftover;
    uint8_t final;
} poly1305;

static void poly1305_init(poly1305 *st, const uint8_t key[32]) {
    st->r[0] = (load32_le(key + 0)) & 0x3ffffff;
    st->r[1] = (load32_le(key + 3) >> 2) & 0x3ffff03;
    st->r[2] = (load32_le(key + 6) >> 4) & 0x3ffc0ff;
    st->r[3] = (load32_le(key + 9) >> 6) & 0x3f03fff;
    st->r[4] = (load32_le(key + 12) >> 8) & 0x00fffff;
    for (int i = 0; i < 5; i++) st->h[i] = 0;
    st->pad[0] = load32_le(key + 16); st->pad[1] = load32_le(key + 20);
    st->pad[2] = load32_le(key + 24); st->pad[3] = load32_le(key + 28);
    st->leftover = 0; st->final = 0;
}

static void poly1305_blocks(poly1305 *st, const uint8_t *m, size_t bytes) {
    const uint32_t hibit = st->final ? 0 : (1u << 24);
    uint32_t r0 = st->r[0], r1 = st->r[1], r2 = st->r[2], r3 = st->r[3], r4 = st->r[4];
    uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    uint32_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2], h3 = st->h[3], h4 = st->h[4];
    while (bytes >= 16) {
        uint64_t d0, d1, d2, d3, d4; uint32_t c;
        h0 += (load32_le(m + 0)) & 0x3ffffff;
        h1 += (load32_le(m + 3) >> 2) & 0x3ffffff;
        h2 += (load32_le(m + 6) >> 4) & 0x3ffffff;
        h3 += (load32_le(m + 9) >> 6) & 0x3ffffff;
        h4 += (load32_le(m + 12) >> 8) | hibit;
        d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * s4 + (uint64_t)h2 * s3 + (uint64_t)h3 * s2 + (uint64_t)h4 * s1;
        d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 + (uint64_t)h2 * s4 + (uint64_t)h3 * s3 + (uint64_t)h4 * s2;
        d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 + (uint64_t)h2 * r0 + (uint64_t)h3 * s4 + (uint64_t)h4 * s3;
        d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 + (uint64_t)h2 * r1 + (uint64_t)h3 * r0 + (uint64_t)h4 * s4;
        d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 + (uint64_t)h2 * r2 + (uint64_t)h3 * r1 + (uint64_t)h4 * r0;
        c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffff;
        d1 += c; c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffff;
        d2 += c; c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffff;
        d3 += c; c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffff;
        d4 += c; c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffff;
        h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;
        m += 16; bytes -= 16;
    }
    st->h[0] = h0; st->h[1] = h1; st->h[2] = h2; st->h[3] = h3; st->h[4] = h4;
}

static void poly1305_update(poly1305 *st, const uint8_t *m, size_t bytes) {
    if (st->leftover) {
        size_t want = 16 - st->leftover;
        if (want > bytes) want = bytes;
        for (size_t i = 0; i < want; i++) st->buf[st->leftover + i] = m[i];
        bytes -= want; m += want; st->leftover += want;
        if (st->leftover < 16) return;
        poly1305_blocks(st, st->buf, 16);
        st->leftover = 0;
    }
    if (bytes >= 16) {
        size_t want = bytes & ~(size_t)15;
        poly1305_blocks(st, m, want);
        m += want; bytes -= want;
    }
    for (size_t i = 0; i < bytes; i++) st->buf[st->leftover + i] = m[i];
    st->leftover += bytes;
}

static void poly1305_finish(poly1305 *st, uint8_t mac[16]) {
    if (st->leftover) {
        size_t i = st->leftover;
        st->buf[i++] = 1;
        for (; i < 16; i++) st->buf[i] = 0;
        st->final = 1;
        poly1305_blocks(st, st->buf, 16);
    }
    uint32_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2], h3 = st->h[3], h4 = st->h[4], c;
    c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
    c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
    c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffff; h0 += c * 5;
    c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;
    uint32_t g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    uint32_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    uint32_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    uint32_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    uint32_t g4 = h4 + c - (1u << 26);
    uint32_t mask = (g4 >> 31) - 1;
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0; h1 = (h1 & mask) | g1; h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3; h4 = (h4 & mask) | g4;
    h0 = (h0 | (h1 << 26));
    h1 = ((h1 >> 6) | (h2 << 20));
    h2 = ((h2 >> 12) | (h3 << 14));
    h3 = ((h3 >> 18) | (h4 << 8));
    uint64_t f;
    f = (uint64_t)h0 + st->pad[0]; h0 = (uint32_t)f;
    f = (uint64_t)h1 + st->pad[1] + (f >> 32); h1 = (uint32_t)f;
    f = (uint64_t)h2 + st->pad[2] + (f >> 32); h2 = (uint32_t)f;
    f = (uint64_t)h3 + st->pad[3] + (f >> 32); h3 = (uint32_t)f;
    store32_le(mac + 0, h0); store32_le(mac + 4, h1); store32_le(mac + 8, h2); store32_le(mac + 12, h3);
}

/* ------------------------------------------------------- XChaCha20-Poly1305 */

static const uint8_t poly_pad[16] = {0};

static void poly1305_aead(const uint8_t polykey[32], const uint8_t *aad, size_t aad_len,
                          const uint8_t *ct, size_t ct_len, uint8_t tag[16]) {
    poly1305 st;
    poly1305_init(&st, polykey);
    poly1305_update(&st, aad, aad_len);
    if (aad_len % 16) poly1305_update(&st, poly_pad, 16 - (aad_len % 16));
    poly1305_update(&st, ct, ct_len);
    if (ct_len % 16) poly1305_update(&st, poly_pad, 16 - (ct_len % 16));
    uint8_t lens[16];
    store64_le(lens, (uint64_t)aad_len);
    store64_le(lens + 8, (uint64_t)ct_len);
    poly1305_update(&st, lens, 16);
    poly1305_finish(&st, tag);
}

static int ct_verify16(const uint8_t a[16], const uint8_t b[16]) {
    uint8_t d = 0;
    for (int i = 0; i < 16; i++) d |= a[i] ^ b[i];
    return d == 0;
}

/* Open detached: verify tag over aad+ct, then decrypt ct into out (ct_len bytes). */
static int xchacha_open(const uint8_t key[32], const uint8_t nonce[24],
                        const uint8_t *ct, size_t ct_len, const uint8_t tag[16],
                        const uint8_t *aad, size_t aad_len, uint8_t *out) {
    uint8_t subkey[32];
    hchacha20(key, nonce, subkey);
    uint8_t n12[12] = {0, 0, 0, 0};
    memcpy(n12 + 4, nonce + 16, 8);
    uint8_t block0[64];
    chacha20_block(subkey, 0, n12, block0);
    uint8_t computed[16];
    poly1305_aead(block0, aad, aad_len, ct, ct_len, computed);
    if (!ct_verify16(computed, tag)) return -1;
    chacha20_xor(subkey, 1, n12, ct, out, ct_len);
    return 0;
}

/* Open a `nonce(24) || ct || tag(16)` blob. */
static int xchacha_open_blob(const uint8_t key[32], const uint8_t *blob, size_t blob_len,
                             const uint8_t *aad, size_t aad_len, uint8_t *out, size_t *out_len) {
    if (blob_len < 24 + 16) return -1;
    size_t ct_len = blob_len - 24 - 16;
    if (xchacha_open(key, blob, blob + 24, ct_len, blob + blob_len - 16, aad, aad_len, out) != 0) return -1;
    *out_len = ct_len;
    return 0;
}

/* ----------------------------------------- Argon2id (implemented below main) */
int argon2id_hash(const uint8_t *pwd, size_t pwd_len, const uint8_t *salt, size_t salt_len,
                  uint32_t m_cost, uint32_t t_cost, uint32_t parallelism,
                  uint8_t *out, size_t out_len);
static int argon2id_raw(const uint8_t *pwd, size_t pwd_len, const uint8_t *salt, size_t salt_len,
                        const uint8_t *secret, size_t secret_len, const uint8_t *ad, size_t ad_len,
                        uint32_t m_cost, uint32_t t_cost, uint32_t lanes, uint8_t *out, uint32_t out_len);

/* ============================================================ DCTL v1 decoding */

#define FAIL(msg) do { fprintf(stderr, "%s\n", (msg)); return -1; } while (0)

/* ── FROZEN format constants (docs/FORMAT.md §2-§4) ── */
#define KEY_LEN          32
#define NONCE_LEN        24
#define TAG_LEN          16
#define WRAP_LEN         72   /* nonce(24) + ct(32) + tag(16) — wrapped_root / wrapped_dek */
#define OBJ_HEAD_LEN     68   /* DSF1 fixed head, folded into every object AAD */

/* Envelope DKE1 fixed header: magic(4)+ver(1)+vault_id(16)+slot_count(2). */
#define ENV_HEADER_LEN   23
#define VAULT_ID_LEN     16
#define MAX_SLOT_COUNT   64
/* slot_len == 57 + salt_len + aux_len + wrap_len (§2). */
#define SLOT_FIXED_PREFIX_LEN 57

/* Supported selectors (this decoder is the symmetric owner path only). */
#define SLOT_TYPE_PASSWORD 1
#define WRAP_ALGO_XCHACHA  1
#define KDF_ID_ARGON2ID    1
#define ALGO_XCHACHA       1
#define KEM_ID_NONE        0
#define FLAG_FOOTER        0x01

/* Argon2id parameter ceilings (§2) — enforced BEFORE running the KDF. */
#define ARGON2_MIN_M_COST  8u
#define ARGON2_MAX_M_COST  1048576u
#define ARGON2_MAX_T_COST  16u
#define ARGON2_MAX_P_LANES 8u

/* Object framing bounds (§3). */
#define MAX_CHUNK_SIZE   (16u * 1024u * 1024u)   /* 16 MiB */
#define META_MIN_LEN     116                     /* nonce(24)+min-plaintext(76)+tag(16) */
#define META_MAX_LEN     262144
#define META_MIN_PLAINTEXT_LEN 76
#define META_SCHEMA_V1   0x01

/* Frozen AAD domain prefixes. Lengths pinned (no trailing NUL is copied). */
static const char SLOT_AAD_PREFIX[] = "dctl-slot-v1::";  /* 14 */
static const char DEK_AAD_PREFIX[]  = "dctl-dek-v1::";   /* 13 */
static const char META_AAD_PREFIX[] = "dctl-meta-v1::";  /* 14 */
#define SLOT_AAD_PREFIX_LEN 14
#define DEK_AAD_PREFIX_LEN  13
#define META_AAD_PREFIX_LEN 14

/* ---------------------------------------------------------- envelope (DKE1) */

typedef struct {
    uint8_t slot_type, flags, kdf_id, wrap_algo;
    uint32_t m_cost, t_cost, p_lanes;
    const uint8_t *salt; size_t salt_len;
    const uint8_t *aux;  size_t aux_len;
    const uint8_t *wrapped_root; size_t wrap_len;
} slot_t;

/* Parse one self-delimiting slot at `off`, enforcing every §2 structural bound.
 * On success fills `*s` (pointers alias into `env`) and sets `*next` to the offset
 * just past this slot. A structural failure means REJECT THE ENVELOPE (§8). */
static int parse_slot(const uint8_t *env, size_t env_len, size_t off, slot_t *s, size_t *next) {
    if (off + SLOT_FIXED_PREFIX_LEN > env_len) FAIL("slot truncated (prefix)");
    uint32_t slot_len = load32_le(env + off);
    s->slot_type = env[off + 4];
    s->flags     = env[off + 5];
    s->kdf_id    = env[off + 6];
    s->wrap_algo = env[off + 7];
    s->m_cost    = load32_le(env + off + 8);
    s->t_cost    = load32_le(env + off + 12);
    s->p_lanes   = load32_le(env + off + 16);
    /* commit occupies env[off+20 .. off+52] — deliberately NOT read (see header). */
    size_t salt_len = env[off + 52];

    size_t salt_start   = off + 53;
    size_t aux_len_pos  = salt_start + salt_len;
    if (aux_len_pos + 2 > env_len) FAIL("slot truncated (aux_len)");
    size_t aux_len      = load16_le(env + aux_len_pos);
    size_t wrap_len_pos = aux_len_pos + 2 + aux_len;
    if (wrap_len_pos + 2 > env_len) FAIL("slot truncated (wrap_len)");
    size_t wrap_len     = load16_le(env + wrap_len_pos);

    /* Frozen structural identity: slot_len == 57 + salt_len + aux_len + wrap_len. */
    size_t expected = SLOT_FIXED_PREFIX_LEN + salt_len + aux_len + wrap_len;
    if ((size_t)slot_len != expected) FAIL("slot_len != 57 + salt_len + aux_len + wrap_len");
    size_t slot_end = off + slot_len;
    if (slot_end > env_len) FAIL("slot overruns envelope");
    if (s->wrap_algo == WRAP_ALGO_XCHACHA && wrap_len != WRAP_LEN)
        FAIL("wrap_len != 72 for XChaCha20-Poly1305 slot");

    s->salt = env + salt_start;         s->salt_len = salt_len;
    s->aux  = env + aux_len_pos + 2;    s->aux_len  = aux_len;
    s->wrapped_root = env + wrap_len_pos + 2; s->wrap_len = wrap_len;
    *next = slot_end;
    return 0;
}

/* Build the §2 slot wrap-AAD into `aad` (caller sizes it):
 *   prefix ‖ vault_id(16) ‖ slot_type ‖ flags ‖ kdf_id ‖ wrap_algo
 *          ‖ salt_len(u8) ‖ salt ‖ aux_len(u16 LE) ‖ aux
 * Returns the total AAD length. */
static size_t build_slot_aad(uint8_t *aad, const uint8_t *vault_id, const slot_t *s) {
    size_t o = 0;
    memcpy(aad + o, SLOT_AAD_PREFIX, SLOT_AAD_PREFIX_LEN); o += SLOT_AAD_PREFIX_LEN;
    memcpy(aad + o, vault_id, VAULT_ID_LEN);               o += VAULT_ID_LEN;
    aad[o++] = s->slot_type;
    aad[o++] = s->flags;
    aad[o++] = s->kdf_id;
    aad[o++] = s->wrap_algo;
    aad[o++] = (uint8_t)s->salt_len;
    memcpy(aad + o, s->salt, s->salt_len); o += s->salt_len;
    aad[o++] = (uint8_t)(s->aux_len & 0xff);
    aad[o++] = (uint8_t)((s->aux_len >> 8) & 0xff);
    memcpy(aad + o, s->aux, s->aux_len); o += s->aux_len;
    return o;
}

/* Derive the 32-byte root from a DKE1 envelope + password (§2/§6 step 1).
 * The password is already-UTF-8/NFC bytes. Validates every slot structurally
 * (reject-on-failure), then for each satisfiable password slot derives the KEK
 * with Argon2id and attempts the AEAD unwrap; the first slot whose tag verifies
 * yields the root. The per-slot `commit` gate is skipped (the AEAD tag is the
 * correctness gate — see the file header). */
static int derive_root(const uint8_t *env, size_t env_len,
                       const uint8_t *pw, size_t pw_len, uint8_t root[KEY_LEN]) {
    if (env_len < ENV_HEADER_LEN) FAIL("envelope too short");
    if (!(env[0] == 'D' && env[1] == 'K' && env[2] == 'E' && env[3] == '1'))
        FAIL("bad envelope magic");
    if (env[4] != 1) FAIL("unsupported envelope version");
    const uint8_t *vault_id = env + 5;
    uint16_t slot_count = load16_le(env + 21);
    if (slot_count < 1 || slot_count > MAX_SLOT_COUNT) FAIL("slot_count out of range (1..=64)");

    slot_t slots[MAX_SLOT_COUNT];
    size_t off = ENV_HEADER_LEN;
    for (uint16_t i = 0; i < slot_count; i++) {
        size_t next;
        if (parse_slot(env, env_len, off, &slots[i], &next) != 0) return -1;
        off = next;
    }
    if (off != env_len) FAIL("trailing bytes after slots");

    for (uint16_t i = 0; i < slot_count; i++) {
        slot_t *s = &slots[i];
        /* Skip (via slot_len) any slot this decoder cannot satisfy — try the rest (§8). */
        if (s->slot_type != SLOT_TYPE_PASSWORD) continue;
        if (s->wrap_algo != WRAP_ALGO_XCHACHA)  continue;
        if (s->kdf_id    != KDF_ID_ARGON2ID)    continue;
        if (s->flags != 0)                      continue;   /* unknown slot flag → skip */
        /* KDF-parameter ceilings — enforced BEFORE running Argon2id (§2). */
        if (s->m_cost < ARGON2_MIN_M_COST || s->m_cost > ARGON2_MAX_M_COST) continue;
        if (s->t_cost < 1 || s->t_cost > ARGON2_MAX_T_COST)                 continue;
        if (s->p_lanes < 1 || s->p_lanes > ARGON2_MAX_P_LANES)              continue;

        uint8_t kek[KEY_LEN];
        if (argon2id_hash(pw, pw_len, s->salt, s->salt_len,
                          s->m_cost, s->t_cost, s->p_lanes, kek, KEY_LEN) != 0)
            continue;

        size_t aad_cap = SLOT_AAD_PREFIX_LEN + VAULT_ID_LEN + 4 + 1 + s->salt_len + 2 + s->aux_len;
        uint8_t *aad = malloc(aad_cap);
        if (!aad) FAIL("out of memory (slot aad)");
        size_t aad_len = build_slot_aad(aad, vault_id, s);

        uint8_t out[64]; size_t out_len;
        int ok = (xchacha_open_blob(kek, s->wrapped_root, s->wrap_len,
                                    aad, aad_len, out, &out_len) == 0) && out_len == KEY_LEN;
        free(aad);
        if (ok) {
            memcpy(root, out, KEY_LEN);
            return 0;
        }
        /* Tag mismatch on this slot: wrong password for it — try the next slot. */
    }
    FAIL("no envelope slot unlocked (wrong password, or only unsupported slots)");
}

/* ------------------------------------------------------------- object (DSF1) */

/* Metadata plaintext (§4) bounds check: verifies the positional framing and, for
 * the supported schema 0x01, that meta.size == plaintext_len. An unknown
 * schema_version is skipped-and-served (§8), so a future schema never breaks decode. */
static int check_metadata(const uint8_t *m, size_t len, uint64_t plaintext_len) {
    if (len < META_MIN_PLAINTEXT_LEN) FAIL("metadata plaintext too short");
    if (m[0] != META_SCHEMA_V1) return 0; /* unknown schema: skip parsing, still serve payload */
    if (load64_le(m + 18) != plaintext_len) FAIL("meta.size != plaintext_len");
    size_t path_len = load16_le(m + 70);
    if (72 + path_len + 2 > len) FAIL("metadata truncated (ct_len)");
    size_t ct_off = 72 + path_len;
    size_t ct_len = load16_le(m + ct_off);
    if (ct_off + 2 + ct_len + 2 > len) FAIL("metadata truncated (ext_len)");
    size_t ext_off = ct_off + 2 + ct_len;
    size_t ext_len = load16_le(m + ext_off);
    if (ext_off + 2 + ext_len != len) FAIL("metadata length != 76 + P + T + E");
    return 0;
}

/* chunk_nonce_i = base_nonce with bytes[0..8] XOR= (i as u64 LE); byte[23] stays 0x00. */
static void chunk_nonce(const uint8_t base[NONCE_LEN], uint64_t index, uint8_t out[NONCE_LEN]) {
    memcpy(out, base, NONCE_LEN);
    uint8_t c[8];
    store64_le(c, index);
    for (int i = 0; i < 8; i++) out[i] ^= c[i];
}

/* Stream-decode a DSF1 object (§3): read the head + wrapped_dek + metadata, then
 * process one (this_pt + 16) chunk at a time. Never buffers the whole payload, so a
 * 50 GB file decodes in ~chunk_size memory. Authentication is per-chunk Poly1305
 * over head ‖ index; the BLAKE3 footer is intentionally not re-verified (see header). */
static int decode_object_stream(const uint8_t root[KEY_LEN], FILE *in, FILE *out) {
    /* ── fixed head (68 bytes) ── */
    uint8_t head[OBJ_HEAD_LEN];
    if (fread(head, 1, OBJ_HEAD_LEN, in) != OBJ_HEAD_LEN) FAIL("object truncated (head)");
    if (!(head[0] == 'D' && head[1] == 'S' && head[2] == 'F' && head[3] == '1'))
        FAIL("bad object magic");
    if (head[4] != 1) FAIL("unsupported object version");
    if (head[5] != ALGO_XCHACHA) FAIL("unsupported algo (this decoder is XChaCha20-Poly1305 only)");
    if (head[6] != KEM_ID_NONE)
        FAIL("unsupported kem_id (C reference decoder is kem_id=0 only; kem_id=1 needs the full X25519+ML-KEM-768 implementation)");
    if (head[7] & (uint8_t)~FLAG_FOOTER) FAIL("unknown critical object flag");

    uint32_t chunk_size   = load32_le(head + 8);
    uint64_t plaintext_len = load64_le(head + 12);
    uint64_t chunk_count   = load64_le(head + 20);
    const uint8_t *base    = head + 28;
    if (chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE) FAIL("chunk_size out of range (0, 16 MiB]");
    uint64_t cs = chunk_size;
    uint64_t expected_count = plaintext_len / cs + ((plaintext_len % cs) != 0 ? 1 : 0);
    if (chunk_count != expected_count) FAIL("chunk_count != ceil(plaintext_len / chunk_size)");

    /* ── kem_ct_len(u16) — MUST be 0 for kem_id=0 ── */
    uint8_t kct[2];
    if (fread(kct, 1, 2, in) != 2) FAIL("object truncated (kem_ct_len)");
    if (load16_le(kct) != 0) FAIL("kem_ct_len must be 0 for kem_id=0");

    /* ── wrapped_dek(72) → DEK = XChaCha20-Poly1305(root); AAD = "dctl-dek-v1::" ‖ head ── */
    uint8_t wdek[WRAP_LEN];
    if (fread(wdek, 1, WRAP_LEN, in) != WRAP_LEN) FAIL("object truncated (wrapped_dek)");
    uint8_t dek_aad[DEK_AAD_PREFIX_LEN + OBJ_HEAD_LEN];
    memcpy(dek_aad, DEK_AAD_PREFIX, DEK_AAD_PREFIX_LEN);
    memcpy(dek_aad + DEK_AAD_PREFIX_LEN, head, OBJ_HEAD_LEN);
    uint8_t dek[KEY_LEN]; size_t dek_len;
    if (xchacha_open_blob(root, wdek, WRAP_LEN, dek_aad, sizeof dek_aad, dek, &dek_len) != 0
        || dek_len != KEY_LEN)
        FAIL("failed to unwrap DEK (wrong root, or tampered header)");

    /* ── meta_len(u32) then enc_metadata = nonce(24) ‖ ct ‖ tag(16) ── */
    uint8_t ml[4];
    if (fread(ml, 1, 4, in) != 4) FAIL("object truncated (meta_len)");
    uint32_t meta_len = load32_le(ml);
    if (meta_len < META_MIN_LEN || meta_len > META_MAX_LEN) FAIL("meta_len out of range [116, 262144]");

    uint8_t *meta_blob = malloc(meta_len);
    uint8_t *meta_pt   = malloc(meta_len); /* plaintext is meta_len-40 bytes; this is ample */
    if (!meta_blob || !meta_pt) { free(meta_blob); free(meta_pt); FAIL("out of memory (metadata)"); }
    if (fread(meta_blob, 1, meta_len, in) != meta_len) {
        free(meta_blob); free(meta_pt); FAIL("object truncated (enc_metadata)");
    }
    uint8_t meta_aad[META_AAD_PREFIX_LEN + OBJ_HEAD_LEN];
    memcpy(meta_aad, META_AAD_PREFIX, META_AAD_PREFIX_LEN);
    memcpy(meta_aad + META_AAD_PREFIX_LEN, head, OBJ_HEAD_LEN);
    size_t meta_pt_len;
    if (xchacha_open_blob(dek, meta_blob, meta_len, meta_aad, sizeof meta_aad,
                          meta_pt, &meta_pt_len) != 0) {
        free(meta_blob); free(meta_pt); FAIL("failed to decrypt metadata (wrong DEK or tampered)");
    }
    free(meta_blob);
    if (check_metadata(meta_pt, meta_pt_len, plaintext_len) != 0) { free(meta_pt); return -1; }
    free(meta_pt);

    /* ── payload: chunk_count chunks, each ct(this_pt) ‖ tag(16), AAD = head ‖ i(u64 LE) ── */
    uint8_t aad[OBJ_HEAD_LEN + 8];
    memcpy(aad, head, OBJ_HEAD_LEN);

    uint8_t *ct = malloc((size_t)cs + TAG_LEN);
    uint8_t *pt = malloc((size_t)cs);
    if (!ct || !pt) { free(ct); free(pt); FAIL("out of memory (chunk buffer)"); }

    uint64_t written = 0;
    int rc = 0;
    for (uint64_t idx = 0; idx < chunk_count; idx++) {
        uint64_t remaining = plaintext_len - written;
        size_t this_pt = remaining < cs ? (size_t)remaining : (size_t)cs;
        size_t need = this_pt + TAG_LEN;
        if (fread(ct, 1, need, in) != need) { rc = -1; break; }
        uint8_t nonce[NONCE_LEN];
        chunk_nonce(base, idx, nonce);
        store64_le(aad + OBJ_HEAD_LEN, idx);
        if (xchacha_open(dek, nonce, ct, this_pt, ct + this_pt, aad, sizeof aad, pt) != 0) {
            rc = -1; break;
        }
        if (fwrite(pt, 1, this_pt, out) != this_pt) { rc = -1; break; }
        written += this_pt;
    }
    free(ct);
    free(pt);
    if (rc != 0) FAIL("chunk decode/authentication failed (tampered, truncated, or short read)");
    if (written != plaintext_len) FAIL("decoded length != plaintext_len");
    /* A trailing BLAKE3 footer, if present, is intentionally not re-verified (see header). */
    return 0;
}

/* ------------------------------------------------------------------- I/O + CLI */

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_decode(const char *hex, uint8_t *out, size_t out_cap, size_t *out_len) {
    size_t n = strlen(hex);
    if (n % 2) return -1;
    if (n / 2 > out_cap) return -1;
    for (size_t i = 0; i < n / 2; i++) {
        int hi = hexval((unsigned char)hex[2 * i]);
        int lo = hexval((unsigned char)hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    *out_len = n / 2;
    return 0;
}

static uint8_t *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return NULL; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }
    uint8_t *buf = malloc((size_t)sz ? (size_t)sz : 1);
    if (!buf) { fclose(f); return NULL; }
    if (sz > 0 && fread(buf, 1, (size_t)sz, f) != (size_t)sz) { free(buf); fclose(f); return NULL; }
    fclose(f);
    *len = (size_t)sz;
    return buf;
}

static void usage(void) {
    fprintf(stderr,
        "usage:\n"
        "  dctl-decode --root HEX64 --in OBJECT --out PLAINTEXT\n"
        "  dctl-decode --envelope ENV --password UTF8 --in OBJECT --out PLAINTEXT\n"
        "  dctl-decode --argon2-kat\n"
        "  (--in \"-\" reads stdin, --out \"-\" writes stdout)\n");
}

/* Self-test: reproduce the RFC 9106 §5.3 Argon2id test vector and print its hex
 * tag. Lets the KAT harness validate the KDF port against the official spec,
 * independently of DCTL and of the Rust implementation. */
static int argon2_rfc9106_selftest(void) {
    uint8_t pwd[32], salt[16], secret[8], ad[12], tag[32];
    memset(pwd, 0x01, sizeof pwd);
    memset(salt, 0x02, sizeof salt);
    memset(secret, 0x03, sizeof secret);
    memset(ad, 0x04, sizeof ad);
    if (argon2id_raw(pwd, sizeof pwd, salt, sizeof salt, secret, sizeof secret, ad, sizeof ad,
                     32, 3, 4, tag, 32) != 0)
        return 1;
    for (int i = 0; i < 32; i++) printf("%02x", tag[i]);
    printf("\n");
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--argon2-kat")) return argon2_rfc9106_selftest();

    const char *root_hex = NULL, *env_path = NULL, *password = NULL,
               *in_path = NULL, *out_path = NULL;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--root") && i + 1 < argc) root_hex = argv[++i];
        else if (!strcmp(argv[i], "--envelope") && i + 1 < argc) env_path = argv[++i];
        else if (!strcmp(argv[i], "--password") && i + 1 < argc) password = argv[++i];
        else if (!strcmp(argv[i], "--in") && i + 1 < argc) in_path = argv[++i];
        else if (!strcmp(argv[i], "--out") && i + 1 < argc) out_path = argv[++i];
        else { fprintf(stderr, "unknown or incomplete argument: %s\n", argv[i]); usage(); return 2; }
    }
    if (!in_path || !out_path || (!root_hex && !(env_path && password))) {
        usage();
        return 2;
    }

    /* Establish the 32-byte root: either given directly, or derived from the envelope. */
    uint8_t root[KEY_LEN];
    if (root_hex) {
        size_t n;
        if (hex_decode(root_hex, root, KEY_LEN, &n) != 0 || n != KEY_LEN) {
            fprintf(stderr, "invalid --root hex (need 64 hex chars)\n");
            return 1;
        }
    } else {
        size_t env_len;
        uint8_t *env = read_file(env_path, &env_len);
        if (!env) { fprintf(stderr, "cannot read envelope file\n"); return 1; }
        int rc = derive_root(env, env_len, (const uint8_t *)password, strlen(password), root);
        free(env);
        if (rc != 0) return 1; /* derive_root already printed a specific reason */
    }

    FILE *in = (!strcmp(in_path, "-")) ? stdin : fopen(in_path, "rb");
    if (!in) { fprintf(stderr, "cannot read object file\n"); return 1; }
    FILE *out = (!strcmp(out_path, "-")) ? stdout : fopen(out_path, "wb");
    if (!out) {
        fprintf(stderr, "cannot open output file\n");
        if (in != stdin) fclose(in);
        return 1;
    }
    int rc = decode_object_stream(root, in, out);
    if (in != stdin) fclose(in);
    if (out != stdout) fclose(out);
    if (rc != 0) return 1; /* decode_object_stream already printed a specific reason */
    return 0;
}

/* ============================================================ BLAKE2b (RFC 7693) */

typedef struct {
    uint64_t h[8], t[2], f[2];
    uint8_t buf[128];
    size_t buflen, outlen;
} blake2b_state;

static const uint64_t blake2b_iv[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL,
};
static const uint8_t blake2b_sigma[12][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
};

static uint64_t rotr64(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }

#define B2B_G(a, b, c, d, x, y)                              \
    a = a + b + x; d = rotr64(d ^ a, 32); c = c + d;         \
    b = rotr64(b ^ c, 24); a = a + b + y; d = rotr64(d ^ a, 16); \
    c = c + d; b = rotr64(b ^ c, 63);

static void blake2b_compress(blake2b_state *S, const uint8_t block[128]) {
    uint64_t m[16], v[16];
    for (int i = 0; i < 16; i++) m[i] = load64_le(block + 8 * i);
    for (int i = 0; i < 8; i++) v[i] = S->h[i];
    for (int i = 0; i < 8; i++) v[8 + i] = blake2b_iv[i];
    v[12] ^= S->t[0]; v[13] ^= S->t[1]; v[14] ^= S->f[0]; v[15] ^= S->f[1];
    for (int r = 0; r < 12; r++) {
        const uint8_t *s = blake2b_sigma[r];
        B2B_G(v[0], v[4], v[8], v[12], m[s[0]], m[s[1]])
        B2B_G(v[1], v[5], v[9], v[13], m[s[2]], m[s[3]])
        B2B_G(v[2], v[6], v[10], v[14], m[s[4]], m[s[5]])
        B2B_G(v[3], v[7], v[11], v[15], m[s[6]], m[s[7]])
        B2B_G(v[0], v[5], v[10], v[15], m[s[8]], m[s[9]])
        B2B_G(v[1], v[6], v[11], v[12], m[s[10]], m[s[11]])
        B2B_G(v[2], v[7], v[8], v[13], m[s[12]], m[s[13]])
        B2B_G(v[3], v[4], v[9], v[14], m[s[14]], m[s[15]])
    }
    for (int i = 0; i < 8; i++) S->h[i] ^= v[i] ^ v[8 + i];
}

static void blake2b_init(blake2b_state *S, size_t outlen) {
    for (int i = 0; i < 8; i++) S->h[i] = blake2b_iv[i];
    S->h[0] ^= 0x01010000ULL ^ (uint64_t)outlen; /* fanout=1, depth=1, keylen=0 */
    S->t[0] = S->t[1] = S->f[0] = S->f[1] = 0;
    S->buflen = 0; S->outlen = outlen;
}

static void blake2b_update(blake2b_state *S, const uint8_t *in, size_t inlen) {
    for (size_t i = 0; i < inlen; i++) {
        if (S->buflen == 128) {
            S->t[0] += 128; if (S->t[0] < 128) S->t[1]++;
            blake2b_compress(S, S->buf);
            S->buflen = 0;
        }
        S->buf[S->buflen++] = in[i];
    }
}

static void blake2b_final(blake2b_state *S, uint8_t *out) {
    S->t[0] += S->buflen; if (S->t[0] < S->buflen) S->t[1]++;
    S->f[0] = ~0ULL;
    for (size_t i = S->buflen; i < 128; i++) S->buf[i] = 0;
    blake2b_compress(S, S->buf);
    uint8_t full[64];
    for (int i = 0; i < 8; i++) store64_le(full + 8 * i, S->h[i]);
    memcpy(out, full, S->outlen);
}

static void blake2b(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen) {
    blake2b_state S;
    blake2b_init(&S, outlen);
    blake2b_update(&S, in, inlen);
    blake2b_final(&S, out);
}

/* ============================================================== Argon2id (RFC 9106) */

#define ARGON2_BLOCK_WORDS 128
#define ARGON2_ADDRESSES_PER_BLOCK 128
#define ARGON2_SYNC_POINTS 4
#define ARGON2_TYPE_ID 2u
#define ARGON2_VERSION 0x13u

/* Variable-length hash H' (BLAKE2b-based). */
static void argon2_hprime(uint8_t *out, uint32_t out_len, const uint8_t *in, size_t in_len) {
    uint8_t len_le[4];
    store32_le(len_le, out_len);
    if (out_len <= 64) {
        blake2b_state S;
        blake2b_init(&S, out_len);
        blake2b_update(&S, len_le, 4);
        blake2b_update(&S, in, in_len);
        blake2b_final(&S, out);
        return;
    }
    uint8_t V[64];
    blake2b_state S;
    blake2b_init(&S, 64);
    blake2b_update(&S, len_le, 4);
    blake2b_update(&S, in, in_len);
    blake2b_final(&S, V);
    uint32_t pos = 0;
    memcpy(out + pos, V, 32); pos += 32;
    uint32_t remaining = out_len - 32;
    while (remaining > 64) {
        blake2b(V, 64, V, 64);
        memcpy(out + pos, V, 32); pos += 32;
        remaining -= 32;
    }
    blake2b(out + pos, remaining, V, 64);
}

/* Argon2 compression G with the BlaMka round (data-dependent multiplication). */
#define TRUNC(x) ((uint64_t)(uint32_t)(x))
#define GB(a, b, c, d)                                        \
    a += b + 2ULL * TRUNC(a) * TRUNC(b); d = rotr64(d ^ a, 32); \
    c += d + 2ULL * TRUNC(c) * TRUNC(d); b = rotr64(b ^ c, 24); \
    a += b + 2ULL * TRUNC(a) * TRUNC(b); d = rotr64(d ^ a, 16); \
    c += d + 2ULL * TRUNC(c) * TRUNC(d); b = rotr64(b ^ c, 63);
#define P(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15) \
    GB(v0, v4, v8, v12) GB(v1, v5, v9, v13) GB(v2, v6, v10, v14) GB(v3, v7, v11, v15) \
    GB(v0, v5, v10, v15) GB(v1, v6, v11, v12) GB(v2, v7, v8, v13) GB(v3, v4, v9, v14)

static void fill_block(const uint64_t *prev, const uint64_t *ref, uint64_t *next, int with_xor) {
    uint64_t R[128], Z[128];
    for (int i = 0; i < 128; i++) R[i] = prev[i] ^ ref[i];
    memcpy(Z, R, sizeof R);
    for (int i = 0; i < 8; i++) {
        P(Z[16 * i + 0], Z[16 * i + 1], Z[16 * i + 2], Z[16 * i + 3], Z[16 * i + 4], Z[16 * i + 5],
          Z[16 * i + 6], Z[16 * i + 7], Z[16 * i + 8], Z[16 * i + 9], Z[16 * i + 10], Z[16 * i + 11],
          Z[16 * i + 12], Z[16 * i + 13], Z[16 * i + 14], Z[16 * i + 15])
    }
    for (int i = 0; i < 8; i++) {
        P(Z[2 * i + 0], Z[2 * i + 1], Z[2 * i + 16], Z[2 * i + 17], Z[2 * i + 32], Z[2 * i + 33],
          Z[2 * i + 48], Z[2 * i + 49], Z[2 * i + 64], Z[2 * i + 65], Z[2 * i + 80], Z[2 * i + 81],
          Z[2 * i + 96], Z[2 * i + 97], Z[2 * i + 112], Z[2 * i + 113])
    }
    if (with_xor)
        for (int i = 0; i < 128; i++) next[i] ^= Z[i] ^ R[i];
    else
        for (int i = 0; i < 128; i++) next[i] = Z[i] ^ R[i];
}

static void next_addresses(uint64_t *address_block, uint64_t *input_block, const uint64_t *zero_block) {
    input_block[6]++;
    fill_block(zero_block, input_block, address_block, 0);
    fill_block(zero_block, address_block, address_block, 0);
}

static uint32_t index_alpha(uint32_t pass, uint32_t slice, uint32_t index, uint32_t pseudo_rand,
                            int same_lane, uint32_t segment_length, uint32_t lane_length) {
    uint32_t reference_area_size;
    if (pass == 0) {
        if (slice == 0) reference_area_size = index - 1;
        else if (same_lane) reference_area_size = slice * segment_length + index - 1;
        else reference_area_size = slice * segment_length + (index == 0 ? (uint32_t)-1 : 0);
    } else {
        if (same_lane) reference_area_size = lane_length - segment_length + index - 1;
        else reference_area_size = lane_length - segment_length + (index == 0 ? (uint32_t)-1 : 0);
    }
    uint64_t relative = pseudo_rand;
    relative = (relative * relative) >> 32;
    relative = reference_area_size - 1 - ((reference_area_size * relative) >> 32);
    uint32_t start = 0;
    if (pass != 0) start = (slice == ARGON2_SYNC_POINTS - 1) ? 0 : (slice + 1) * segment_length;
    return (uint32_t)((start + relative) % lane_length);
}

/* Core Argon2id (single-threaded; sequential lanes = byte-identical to threaded). */
static int argon2id_raw(const uint8_t *pwd, size_t pwd_len, const uint8_t *salt, size_t salt_len,
                        const uint8_t *secret, size_t secret_len, const uint8_t *ad, size_t ad_len,
                        uint32_t m_cost, uint32_t t_cost, uint32_t lanes, uint8_t *out, uint32_t out_len) {
    if (lanes < 1 || t_cost < 1) return -1;
    uint32_t memory_blocks = m_cost;
    if (memory_blocks < 8 * lanes) memory_blocks = 8 * lanes;
    uint32_t segment_length = memory_blocks / (lanes * ARGON2_SYNC_POINTS);
    if (segment_length < 1) return -1;
    memory_blocks = segment_length * lanes * ARGON2_SYNC_POINTS;
    uint32_t lane_length = segment_length * ARGON2_SYNC_POINTS;

    uint64_t (*B)[128] = malloc((size_t)memory_blocks * 128 * sizeof(uint64_t));
    if (!B) return -1;

    /* H0 = BLAKE2b-512(params) */
    uint8_t H0[64];
    {
        blake2b_state S;
        blake2b_init(&S, 64);
        uint8_t b[4];
        store32_le(b, lanes); blake2b_update(&S, b, 4);
        store32_le(b, out_len); blake2b_update(&S, b, 4);
        store32_le(b, m_cost); blake2b_update(&S, b, 4);
        store32_le(b, t_cost); blake2b_update(&S, b, 4);
        store32_le(b, ARGON2_VERSION); blake2b_update(&S, b, 4);
        store32_le(b, ARGON2_TYPE_ID); blake2b_update(&S, b, 4);
        store32_le(b, (uint32_t)pwd_len); blake2b_update(&S, b, 4);
        blake2b_update(&S, pwd, pwd_len);
        store32_le(b, (uint32_t)salt_len); blake2b_update(&S, b, 4);
        blake2b_update(&S, salt, salt_len);
        store32_le(b, (uint32_t)secret_len); blake2b_update(&S, b, 4);
        if (secret_len) blake2b_update(&S, secret, secret_len);
        store32_le(b, (uint32_t)ad_len); blake2b_update(&S, b, 4);
        if (ad_len) blake2b_update(&S, ad, ad_len);
        blake2b_final(&S, H0);
    }

    /* First two blocks of each lane. */
    uint8_t prehash[72], blockbytes[1024];
    memcpy(prehash, H0, 64);
    for (uint32_t lane = 0; lane < lanes; lane++) {
        store32_le(prehash + 64, 0); store32_le(prehash + 68, lane);
        argon2_hprime(blockbytes, 1024, prehash, 72);
        for (int w = 0; w < 128; w++) B[lane * lane_length + 0][w] = load64_le(blockbytes + 8 * w);
        store32_le(prehash + 64, 1); store32_le(prehash + 68, lane);
        argon2_hprime(blockbytes, 1024, prehash, 72);
        for (int w = 0; w < 128; w++) B[lane * lane_length + 1][w] = load64_le(blockbytes + 8 * w);
    }

    uint64_t zero_block[128] = {0};
    uint64_t input_block[128], address_block[128];

    for (uint32_t pass = 0; pass < t_cost; pass++) {
        for (uint32_t slice = 0; slice < ARGON2_SYNC_POINTS; slice++) {
            for (uint32_t lane = 0; lane < lanes; lane++) {
                int data_independent = (pass == 0 && slice < 2); /* argon2id */
                if (data_independent) {
                    memset(input_block, 0, sizeof input_block);
                    input_block[0] = pass; input_block[1] = lane; input_block[2] = slice;
                    input_block[3] = memory_blocks; input_block[4] = t_cost; input_block[5] = ARGON2_TYPE_ID;
                }
                uint32_t starting_index = 0;
                if (pass == 0 && slice == 0) {
                    starting_index = 2;
                    if (data_independent) next_addresses(address_block, input_block, zero_block);
                }
                for (uint32_t index = starting_index; index < segment_length; index++) {
                    uint32_t col = slice * segment_length + index;
                    uint64_t cur = lane * lane_length + col;
                    uint64_t prev = (col == 0) ? (lane * lane_length + lane_length - 1) : (cur - 1);

                    uint64_t pseudo_rand;
                    if (data_independent) {
                        if (index % ARGON2_ADDRESSES_PER_BLOCK == 0)
                            next_addresses(address_block, input_block, zero_block);
                        pseudo_rand = address_block[index % ARGON2_ADDRESSES_PER_BLOCK];
                    } else {
                        pseudo_rand = B[prev][0];
                    }

                    uint32_t ref_lane = (uint32_t)(pseudo_rand >> 32) % lanes;
                    if (pass == 0 && slice == 0) ref_lane = lane;
                    uint32_t ref_index = index_alpha(pass, slice, index, (uint32_t)pseudo_rand,
                                                     ref_lane == lane, segment_length, lane_length);
                    uint64_t ref = (uint64_t)ref_lane * lane_length + ref_index;

                    fill_block(B[prev], B[ref], B[cur], pass != 0);
                }
            }
        }
    }

    /* Final: XOR the last column across lanes, then H' to out_len. */
    uint64_t final_block[128];
    memcpy(final_block, B[lane_length - 1], sizeof final_block);
    for (uint32_t lane = 1; lane < lanes; lane++)
        for (int w = 0; w < 128; w++) final_block[w] ^= B[lane * lane_length + lane_length - 1][w];

    uint8_t final_bytes[1024];
    for (int w = 0; w < 128; w++) store64_le(final_bytes + 8 * w, final_block[w]);
    argon2_hprime(out, out_len, final_bytes, 1024);

    free(B);
    return 0;
}

int argon2id_hash(const uint8_t *pwd, size_t pwd_len, const uint8_t *salt, size_t salt_len,
                  uint32_t m_cost, uint32_t t_cost, uint32_t parallelism,
                  uint8_t *out, size_t out_len) {
    return argon2id_raw(pwd, pwd_len, salt, salt_len, NULL, 0, NULL, 0,
                        m_cost, t_cost, parallelism, out, (uint32_t)out_len);
}
