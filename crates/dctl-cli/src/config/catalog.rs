//! Presenting the configuration as a lookup table of named remotes.
//!
//! [`crate::remote::resolve`] turns a spec into something buildable, and it does
//! that against a [`RemoteCatalog`]. This module is the one that answers with the
//! user's actual configuration.
//!
//! It lives here rather than in a command module because *every* command needs
//! it. It previously sat in `commands::config::settings`, reachable only from the
//! `config` verb, and the consequence was that `session::open` and
//! `remote::registry::build_backend` both resolved against the **empty** catalog
//! — the one that knows only the `local:`/`b2:`/`s3:`/`r2:` shorthands. Every
//! configured remote was therefore unaddressable, and DCTL would print a refusal
//! naming `archive:` as the remedy and then reject `archive:` as unknown. Putting
//! the catalog in the configuration layer is what makes "resolve against what the
//! user configured" the path of least resistance instead of a thing each caller
//! has to remember.

use crate::constants::CONFIG_REMOTE_TYPE_KEY;
use crate::remote::resolve::{RemoteCatalog, RemoteEntry};

use super::model::{Config, RemoteDef};

/// The settings of one remote, flattened to `key = value` pairs.
///
/// The `type` key is dropped because [`RemoteEntry::provider`] already carries
/// it; leaving it in both places would let a hand-edited section contradict
/// itself.
fn entry(remote: &RemoteDef) -> RemoteEntry {
    let settings = crate::commands::config::settings::flatten(remote)
        .into_iter()
        .filter(|(key, _)| key != CONFIG_REMOTE_TYPE_KEY)
        .collect();

    RemoteEntry {
        provider: remote.type_name().to_string(),
        settings,
    }
}

/// A [`Config`] is a catalog of named remotes.
///
/// Implemented on the type itself so a caller writes `resolve(&spec, config)`
/// and cannot accidentally reach for `&()` — the empty catalog that silently
/// hides every configured remote.
impl RemoteCatalog for Config {
    fn lookup(&self, name: &str) -> Option<RemoteEntry> {
        self.remotes.get(name).map(entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::model::LocalDef;

    fn config_with(name: &str, path: &str) -> Config {
        let mut config = Config::default();
        config.remotes.insert(
            name.to_string(),
            RemoteDef::Local(LocalDef {
                path: path.into(),
                require_vault: false,
                verify: None,
            }),
        );
        config
    }

    #[test]
    fn a_configured_remote_is_found_by_name() {
        let config = config_with("archive-store", "/srv/vault");
        let found = config.lookup("archive-store").expect("configured remote");
        assert_eq!(found.provider, "local");
    }

    #[test]
    fn an_unconfigured_name_is_not_found() {
        let config = config_with("archive-store", "/srv/vault");
        assert!(config.lookup("nosuch").is_none());
    }

    #[test]
    fn the_type_key_is_not_duplicated_into_the_settings() {
        // `provider` already carries it; two copies could disagree.
        let config = config_with("store", "/srv/v");
        let found = config.lookup("store").expect("configured remote");
        assert!(
            !found.settings.contains_key(CONFIG_REMOTE_TYPE_KEY),
            "settings must not repeat the type: {:?}",
            found.settings
        );
    }

    #[test]
    fn an_empty_config_finds_nothing_but_is_still_a_catalog() {
        let config = Config::default();
        assert!(config.lookup("anything").is_none());
    }
}
