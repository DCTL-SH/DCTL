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

## Scope

This project encrypts data at rest and in transit, so the findings that matter
most are those that would let someone read, alter, or silently lose stored
bytes: key handling, the authenticated-encryption paths, the integrity checks
that decide whether a write is reported as durable, and anything that causes a
success to be reported for work that did not happen.

`docs/SECURITY.md` is the security and threat model — what is protected, how,
and explicitly what is not. Read it before reporting: several properties people
expect are deliberately *not* claimed there, and it says so plainly.

## Status

This is alpha software under active development. It has not had an independent
cryptographic audit. Do not rely on it as the only copy of data you cannot lose.
