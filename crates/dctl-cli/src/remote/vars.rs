//! Where a backend's credentials and endpoints are read from.
//!
//! One trait with one shipped implementation, which is not indirection for its
//! own sake. [`registry::build`](super::registry::build) reads five providers'
//! credentials out of the process environment, and under Rust 2024
//! `std::env::set_var` is `unsafe` — a rule this crate keeps rather than works
//! around, because a test that mutates the environment of a multi-threaded test
//! binary is a test that changes another test's answer.
//!
//! So the arms of that match had **no way in from a test at all**, and what
//! lives in them is the last step of every per-remote setting's journey: the
//! configuration file's `chunk_size` becomes a `Target` field, and one line in
//! one arm passes it to the constructor. That line was measured: dropping it on
//! the B2 arm left `cargo test --workspace` entirely green, while the *helper*
//! it calls has been covered for two passes. The setting parses, round-trips
//! through `config show`, reaches the resolver, and then an operator's memory
//! ceiling is silently ignored.
//!
//! [`Vars`] is the seam that ends that. Production passes [`ProcessVars`] and
//! behaves exactly as before; a test passes a map and can then assert what came
//! out of the arm.

use std::env::VarError;

/// A source of environment variables.
///
/// The signature is [`std::env::var`]'s, including its error type, so that
/// [`ProcessVars`] is a one-line delegation and the three failure shapes
/// [`super::registry`] classifies — absent, empty, not UTF-8 — stay exactly the
/// ones the standard library reports.
pub trait Vars {
    /// The value of `variable`, as [`std::env::var`] would report it.
    ///
    /// # Errors
    /// [`VarError::NotPresent`] when it is unset and [`VarError::NotUnicode`]
    /// when it is set to bytes that are not UTF-8.
    fn get(&self, variable: &str) -> Result<String, VarError>;
}

/// The process environment: what every run uses.
pub struct ProcessVars;

impl Vars for ProcessVars {
    fn get(&self, variable: &str) -> Result<String, VarError> {
        std::env::var(variable)
    }
}

/// A fixed set of variables, for driving the construction arms from a test.
///
/// `#[cfg(test)]` and no way to build one outside a test, which is the point:
/// this exists so the arms can be *asserted*, not so a command can be handed a
/// different environment from the one it is running in.
#[cfg(test)]
pub struct FixedVars(std::collections::BTreeMap<String, String>);

#[cfg(test)]
impl FixedVars {
    /// The variables named, and nothing else set.
    pub fn of(pairs: &[(&str, &str)]) -> Self {
        Self(
            pairs
                .iter()
                .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
                .collect(),
        )
    }
}

#[cfg(test)]
impl Vars for FixedVars {
    fn get(&self, variable: &str) -> Result<String, VarError> {
        self.0.get(variable).cloned().ok_or(VarError::NotPresent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_variable_that_was_not_named_is_absent_rather_than_empty() {
        // The distinction the registry classifies on: absent and empty are two
        // different diagnoses, and a fake that answered `Ok("")` for an unset
        // variable would make every "is not set" test assert the wrong sentence.
        let vars = FixedVars::of(&[("DCTL_B2_KEY_ID", "k")]);
        assert_eq!(vars.get("DCTL_B2_KEY_ID").as_deref(), Ok("k"));
        assert!(matches!(
            vars.get("DCTL_B2_APP_KEY"),
            Err(VarError::NotPresent)
        ));
    }
}
