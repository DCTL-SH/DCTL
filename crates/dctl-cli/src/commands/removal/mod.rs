//! The removal family: `delete`, `deletefile`, `purge`, `rmdir`, `rmdirs` and
//! `cleanup`.
//!
//! The six commands differ in *what* they remove and almost nothing else. They
//! all resolve a `REMOTE:PATH`, they all pass through the same destructive gate,
//! they all owe the user the same `--dry-run` answer, they all remove through
//! the same ordered loop, and they all report in the same three formats. Those
//! parts live here so that a fix to any of them is one fix rather than six —
//! and, more importantly, so that a *lapse* in any of them is impossible to make
//! in only one command.
//!
//! One concern per file:
//!
//! | file | concern |
//! |------|---------|
//! | [`target`] | what `REMOTE:PATH` means, and what it refuses to mean |
//! | [`filters`] | which objects a removal narrows to, validated up front |
//! | [`age`] | the "old enough to be abandoned" margin `cleanup` needs |
//! | [`operation`] | the one dimension the six verbs actually differ in |
//! | [`plan`] | what a removal *would* do, in text, JSON and JSON Lines |
//! | [`flow`] | the fixed order: validate, confirm, cancel or execute |
//! | [`engine`] | open the store, resolve the set, remove it, report it |
//! | [`medium`] | where a removal reads and where it deletes |
//! | [`selection`] | exactly which objects each verb resolves to |
//! | [`dirs`] | what "empty directory" means when there are no directories |
//! | [`remove`] | the ordered loop, and what a crash mid-way leaves behind |
//! | [`reclaim`] | `cleanup`'s classes, and which of them can be swept |
//! | [`report`] | one record per object, written as it happens |
//!
//! ## `delete` versus `purge`
//!
//! The distinction rclone users expect, preserved exactly: **`delete` honours
//! filters and leaves the directory structure standing; `purge` ignores filters
//! and removes the tree.** `delete --include '*.tmp' vault:project` removes the
//! scratch files and nothing else; `purge vault:project` removes the project.
//! Because those two blast radii are so different, `purge` additionally refuses
//! to run without `--force` or an interactive confirmation.
//!
//! ## The three promises the family keeps
//!
//! 1. **`--dry-run` changes nothing and lists everything.** The branch that
//!    mutates is a single `if` in [`remove`], above the store, so there is no
//!    code path from a rehearsal to a deletion — and the records it prints say
//!    `would-remove`, never `removed`, so a log cannot be misread later.
//! 2. **A partial failure is never a success.** Each failure is counted at the
//!    moment it is observed, the run finishes the objects behind it, and the
//!    process exits [`ExitCode::PartialFailure`](crate::exit::ExitCode::PartialFailure)
//!    (`PLAN.md` §7). Nothing rolls up.
//! 3. **Nothing is reported removed until the store confirms it.** For a vault
//!    that means after the index row is committed away, which is what makes a
//!    file count as gone. [`remove`] documents the ordering in full, including
//!    what a crash at each point leaves behind and which command repairs it.

pub mod dirs;
pub mod engine;
pub mod filters;
pub mod flow;
pub mod medium;
pub mod operation;
pub mod plan;
pub mod reclaim;
pub mod remove;
pub mod report;
pub mod selection;
pub mod target;

pub use filters::Filters;
pub use flow::{Removal, execute};
pub use operation::Operation;
// `Plan` itself is addressed as `plan::Plan`. It is built in exactly two
// places — [`engine::run`], and each command's own test of its rendering — and
// keeping it off the facade is what says so: a command that constructed its own
// plan would be printing a second description of the request beside the one the
// shared engine already prints.
pub use plan::{NoOptions, PlanOptions, Row, yes_no};
pub use reclaim::Class;
pub use target::Target;
