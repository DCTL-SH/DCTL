//! DCTL reference decoder.
//!
//! The decoder itself is a single, dependency-free **C99** file at
//! [`REFERENCE_C_PATH`] — chosen because a lone `.c` file compiled with nothing
//! but `cc` is the artifact most likely to still build in 2046, which is the
//! whole point of a 20-year reference decoder
//! ([the plan](https://doc.dctl.sh/project/plan) §13).
//!
//! This crate exists only to house that file and to cross-validate it against the
//! Rust implementation via known-answer tests (see `tests/kat.rs`), so the two
//! independent implementations are proven to agree on every commit.
#![forbid(unsafe_code)]

/// Absolute path to the standalone C99 reference decoder.
pub const REFERENCE_C_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/reference/dctl-decode.c");
