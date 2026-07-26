//! TLS with hybrid post-quantum key exchange (X25519MLKEM768).
//!
//! DCTL data is already encrypted with quantum-safe *symmetric* crypto before it
//! ever enters TLS, so at-rest confidentiality does not depend on the handshake.
//! This adds hybrid PQ key exchange as defense-in-depth against "harvest-now,
//! decrypt-later" on the transport. If the server does not support the hybrid
//! group, rustls negotiates a classical group automatically (no failure).

use std::sync::Arc;

use crate::error::{Result, StoreError};

/// Build a reqwest client that offers hybrid post-quantum TLS, verifying servers
/// against the Mozilla root set (webpki-roots).
pub(crate) fn post_quantum_client() -> Result<reqwest::Client> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config =
        rustls::ClientConfig::builder_with_provider(Arc::new(rustls_post_quantum::provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| StoreError::Backend(format!("tls config: {e}")))?
            .with_root_certificates(roots)
            .with_no_client_auth();

    reqwest::Client::builder()
        .use_preconfigured_tls(config)
        .build()
        .map_err(|e| StoreError::Backend(format!("http client init: {e}")))
}
