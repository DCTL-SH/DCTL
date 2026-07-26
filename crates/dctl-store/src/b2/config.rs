//! Backblaze B2 credentials. Not `Debug` — the application key is secret.

/// A B2 application key pair.
#[derive(Clone)]
pub struct B2Credentials {
    pub(crate) key_id: String,
    pub(crate) app_key: String,
}

impl B2Credentials {
    #[must_use]
    pub fn new(key_id: impl Into<String>, app_key: impl Into<String>) -> Self {
        Self {
            key_id: key_id.into(),
            app_key: app_key.into(),
        }
    }
}
