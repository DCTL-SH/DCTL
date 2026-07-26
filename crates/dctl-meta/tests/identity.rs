use dctl_meta::{APP_NAME, BINARY_NAME, env_prefix, env_var, paths};

#[test]
fn identity_is_present() {
    assert!(!APP_NAME.is_empty());
    assert_eq!(BINARY_NAME, "dctl");
}

#[test]
fn env_naming_derives_from_binary() {
    assert_eq!(env_prefix(), "DCTL_");
    assert_eq!(env_var("config"), "DCTL_CONFIG");
    assert_eq!(env_var("LOG_LEVEL"), "DCTL_LOG_LEVEL");
}

#[test]
fn paths_are_named_after_the_binary() {
    for dir in [paths::config_dir(), paths::data_dir(), paths::cache_dir()] {
        assert!(
            dir.to_string_lossy().contains(BINARY_NAME),
            "path {dir:?} should contain the binary name"
        );
    }
    assert!(paths::config_file().ends_with("config.toml"));
}
