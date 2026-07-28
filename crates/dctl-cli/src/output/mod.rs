//! The presentation layer: where every byte the user sees is written.
//!
//! One rule governs the whole module, and commands depend on it:
//!
//! > **stdout carries data; stderr carries everything else.**
//!
//! Listings, file contents and JSON go to stdout. Progress bars, logs, warnings,
//! prompts and the final summary go to stderr. That is what makes
//! `dctl cat vault:film.mkv | ffplay -` and `dctl lsjson vault: | jq` work while
//! a progress bar is still animating on the terminal.
//!
//! One concern per submodule, so a change to how a number is *chosen* never
//! forces a change to how it is *painted*:
//!
//! * [`format`] — which serialisation a run uses, and what that implies.
//! * [`sink`] — [`Out`], the writers, and the stdout/stderr split above.
//! * [`summary`] — which rows the end-of-run report contains, and why.
//! * [`color`], [`progress`], [`size`], [`stats`], [`table`] — the palette, the
//!   live display, human-readable quantities, the counters they read, and
//!   column alignment.
//! * [`paint`] — which meaning gets which style, for the renderers that build a
//!   line themselves instead of handing rows to [`table`].
//! * [`hex`] — how a digest is spelled. Presentation, but the machine-readable
//!   kind: `sha256sum -c` and a `--checksum` comparison both depend on it.
//!
//! This file deliberately contains no logic: it declares the submodules and
//! re-exports the handful of types commands actually name, so a command writes
//! `use crate::output::{Out, Table}` rather than reciting a path per type.
//! [`summary`]'s own types stay behind its module path — they are the report's
//! internals, not vocabulary every command needs.

pub mod color;
pub mod format;
pub mod hex;
pub mod paint;
pub mod progress;
pub mod sink;
pub mod size;
pub mod stats;
pub mod summary;
pub mod table;

pub use color::ColorChoice;
pub use format::Format;
pub use progress::{FileHandle, Mode as ProgressMode, Progress};
pub use sink::Out;
pub use size::Units;
pub use stats::{Stage, Stats};
pub use table::{Align, Border, Column, Table};
