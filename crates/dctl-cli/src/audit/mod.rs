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
//! * [`anchor`] — the head hash kept *outside* the log, which is the only thing
//!   that can attest to the chain's **length**. The chain detects every edit
//!   made inside it and none made to its end; [`anchor`] is the half that closes
//!   that, and it is deliberately a separate module because it answers a
//!   different question from a different place — one the writer cannot reach.
//! * [`serialize`] — the on-disk encoding and its framing rules.
//! * [`mod@write`] — the append path: open, append one entry, fsync.
//! * [`sink`] — the run's one handle: where the log is, when it is opened, and
//!   what a failure to write one means for the command being recorded.
//! * `coverage` — which commands append and which do not, checked against the
//!   command tree so that a new verb cannot join without the decision being
//!   made. It exists because three commands moved data and recorded nothing,
//!   and an absence is the one defect reading the code cannot find. A test and
//!   nothing else, like `crate::cli::mentions`, so it is compiled only under
//!   `cargo test`; the normative statement of the same policy is
//!   `docs/AUDIT_LOG.md` §9.1.
//!
//! The format is specified normatively in `docs/AUDIT_LOG.md`, in enough detail
//! to verify a chain with a short script and no DCTL binary. That is not
//! documentation courtesy: a tamper-evidence claim that can only be checked by
//! the tool that produced the evidence is not tamper-evidence at all, and the
//! same twenty-year-decodability discipline governs `docs/FORMAT.md`.

pub mod anchor;
pub mod chain;
// A test and nothing else; see the layout note above.
#[cfg(test)]
pub mod coverage;
pub mod record;
pub mod redaction;
pub mod serialize;
pub mod sink;
pub mod write;
