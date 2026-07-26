//! The tamper-evident audit log: one format, one chain rule, both halves.
//!
//! `PLAN.md` §7 makes an append-only, hash-chained record of every operation a
//! day-1 non-negotiable, and §6 step 8 puts the append at the end of the
//! verified-write pipeline. It is the mechanism by which DCTL can *prove* to an
//! auditor, an insurer or a client what happened to their data — and prove that
//! the account has not been altered since.
//!
//! ## Why this lives outside `commands::audit`
//!
//! Because both halves have to agree, exactly, forever. `dctl audit verify`
//! reads what the engine writes, so the record shape, the canonical byte string
//! and the chain rule are shared code rather than a writer's definition and a
//! reader's restatement of it. Two definitions of a format that must round-trip
//! is how a log becomes unverifiable: the day they drift, every record written
//! after the drift reads as a forgery, and nothing in either half is wrong
//! enough to notice. `commands::audit` re-exports [`chain`] and [`record`] from
//! here; it does not redefine them.
//!
//! ## The layout
//!
//! * [`record`] — one entry, and [`record::Entry`], the only way to build one.
//! * [`redaction`] — the mandatory scrub every field passes through first.
//! * [`chain`] — how an entry's hash is computed, and how a chain is walked.
//! * [`serialize`] — the on-disk encoding and its framing rules.
//! * [`mod@write`] — the append path: open, append one entry, fsync.
//!
//! The format is specified normatively in `docs/AUDIT_LOG.md`, in enough detail
//! to verify a chain with a short script and no DCTL binary. That is not
//! documentation courtesy: a tamper-evidence claim that can only be checked by
//! the tool that produced the evidence is not tamper-evidence at all, and the
//! same twenty-year-decodability discipline governs `docs/FORMAT.md`.

pub mod chain;
pub mod record;
pub mod redaction;
pub mod serialize;
pub mod write;
