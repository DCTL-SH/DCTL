# Reporting a vulnerability

DCTL is a product of KONG GROUP LLC.

Report security issues **privately**, not as a public issue.

Use GitHub private vulnerability reporting on this repository
(Security -> Report a vulnerability), which is the preferred route because it
keeps the report, the fix and the disclosure in one place.

Please include what you did, what happened, and what you expected — and, if the
finding concerns stored data, the smallest vault or object that reproduces it.
Do not include real credentials or real data in a report.

## What to expect

An acknowledgement that the report was received and read, an assessment of
whether it is exploitable and what it affects, and a fix or a written statement
of why it is not one. If a finding is real and affects stored data, it is
recorded honestly in the changelog when fixed, including what was at risk.

## Automated scanner findings, and why they are what they are

Static analysis flags eleven things in this repository. All eleven are expected,
and each is recorded here rather than silenced in the code, so that a reviewer
gets an answer without having to re-derive it — and so that a *new* finding still
stands out instead of hiding among suppression comments.

If you believe any of these reasons is wrong, that is exactly the kind of report
this document is asking for.

### "Hard-coded cryptographic value" in nonce and salt generation

  crates/dctl-crypto/src/object/nonce.rs   (base_nonce, metadata_nonce)
  crates/dctl-crypto/src/kdf/salt.rs       (generate_salt)

These allocate a zero-filled buffer and immediately overwrite it from the
CSPRNG:

    let mut n = [0u8; NONCE_LEN];
    crate::rng::fill(&mut n);

The literal the scanner sees is the buffer, not the value. Nonces and Argon2id
salts are random. The domain byte written afterwards (`0x00` for chunk streams,
`0x01` for metadata) is a separation marker, not key material; it exists so a
chunk nonce and a metadata nonce can never collide.

### "Hard-coded cryptographic value" when parsing an object header

  crates/dctl-crypto/src/object/head.rs

The same shape in the other direction: a buffer is zeroed, then
`copy_from_slice` reads the base nonce *out of* a stored header. The flagged
literal is the destination of a parse.

### A fixed salt in KDF calibration

  crates/dctl-crypto/src/kdf/calibrate.rs

This one really is a constant all-zero salt, and it is deliberate. The function
runs Argon2id once to measure how long it takes on this machine, so the tool can
choose cost parameters that hit a target duration. The derived key is discarded
— only the elapsed time is used. A salt's *value* does not affect how long the
derivation takes, and a random one would make the measurement less reproducible
without making anything safer. Vaults are keyed with `generate_salt()`, above.

### "Hard-coded cryptographic value" in tests

  crates/dctl-crypto/tests/kat.rs, tests/roundtrip.rs
  crates/dctl-core/tests/vault.rs

These are Known Answer Test vectors, and hard-coding them is the entire point. A
KAT asserts that this implementation still produces the exact bytes the frozen
format specifies. They are the guard behind the promise that an object written
today is readable in twenty years; removing them would remove the only thing
that proves the format has not drifted.

### "Amazon AWS Temporary Access Key ID"

  crates/dctl-cli/src/config/secrets.rs

`ASIAIOSFODNN7EXAMPLE` is the example key published in Amazon's own
documentation. It appears here in a test asserting that credentials are
**redacted** from output — the test exists so that a real key can never be
printed. A value scanners recognise is arguably the right one to test with. No
live credential has ever been committed to this repository; every blob in its
history was checked before publication.


## Scope

This project encrypts data at rest and in transit, so the findings that matter
most are those that would let someone read, alter, or silently lose stored
bytes: key handling, the authenticated-encryption paths, the integrity checks
that decide whether a write is reported as durable, and anything that causes a
success to be reported for work that did not happen.

<https://doc.dctl.sh/security/threat-model> is the security and threat model — what is protected, how,
and explicitly what is not. Read it before reporting: several properties people
expect are deliberately *not* claimed there, and it says so plainly.

## Status

This is alpha software under active development. It has not had an independent
cryptographic audit. Do not rely on it as the only copy of data you cannot lose.
