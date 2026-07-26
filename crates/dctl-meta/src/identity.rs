//! Product identity constants and environment-variable naming.
//!
//! Change [`APP_NAME`] / [`BINARY_NAME`] to rebrand; everything else derives.

/// Human-facing application name (used in help text, banners, logs).
pub const APP_NAME: &str = "DCTL";

/// Executable / command name (lowercase). Also names the config directory.
pub const BINARY_NAME: &str = "dctl";

/// Uppercase prefix for environment variables, e.g. `DCTL_`.
#[must_use]
pub fn env_prefix() -> String {
    format!("{}_", BINARY_NAME.to_uppercase())
}

/// Full environment-variable name for a setting, e.g.
/// `env_var("CONFIG")` → `DCTL_CONFIG`.
#[must_use]
pub fn env_var(setting: &str) -> String {
    format!("{}{}", env_prefix(), setting.to_uppercase())
}
