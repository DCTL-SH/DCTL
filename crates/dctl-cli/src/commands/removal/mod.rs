//! Shared vocabulary for the removal family: `delete`, `deletefile`, `purge`,
//! `rmdir`, `rmdirs` and `cleanup`.
//!
//! The six commands differ in *what* they remove and almost nothing else. They
//! all resolve a `REMOTE:PATH`, they all pass through the same destructive
//! gate, they all owe the user the same `--dry-run` answer, and they all report
//! in the same three formats. Those parts live here so that a fix to any of
//! them is one fix rather than six — and, more importantly, so that a *lapse*
//! in any of them is impossible to make in only one command.
//!
//! One concern per file:
//!
//! | file | concern |
//! |------|---------|
//! | [`target`] | what `REMOTE:PATH` means, and what it refuses to mean |
//! | [`filters`] | which objects a removal narrows to, validated up front |
//! | [`age`] | the "old enough to be abandoned" margin `cleanup` needs |
//! | [`plan`] | what a removal *would* do, in text, JSON and JSON Lines |
//! | [`flow`] | the fixed order: confirm, report, cancel or execute |
//! | [`engine`] | the single, honest admission of what cannot run yet |
//!
//! ## `delete` versus `purge`
//!
//! The distinction rclone users expect, preserved exactly: **`delete` honours
//! filters and leaves the directory structure standing; `purge` ignores filters
//! and removes the tree.** `delete --include '*.tmp' vault:project` removes the
//! scratch files and nothing else; `purge vault:project` removes the project.
//! Because those two blast radii are so different, `purge` additionally refuses
//! to run without `--force` or an interactive confirmation.

pub mod age;
pub mod engine;
pub mod filters;
pub mod flow;
pub mod plan;
pub mod target;

pub use age::parse_age;
pub use filters::Filters;
pub use flow::{Removal, execute};
// `Plan` itself is addressed as `plan::Plan`. It is built in exactly two
// places — [`flow::execute`], and each command's own test of its rendering —
// and keeping it off the facade is what says so: a command that constructed
// its own plan would be printing a second description of the request beside
// the one the shared flow already prints.
pub use plan::{NoOptions, PlanOptions, Row, yes_no};
pub use target::Target;
