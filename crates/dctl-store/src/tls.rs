//! TLS with hybrid post-quantum key exchange (X25519MLKEM768), and the one
//! deadline that has to be set where the client is built.
//!
//! DCTL data is already encrypted with quantum-safe *symmetric* crypto before it
//! ever enters TLS, so at-rest confidentiality does not depend on the handshake.
//! This adds hybrid PQ key exchange as defense-in-depth against "harvest-now,
//! decrypt-later" on the transport. If the server does not support the hybrid
//! group, rustls negotiates a classical group automatically (no failure).

use std::sync::Arc;

use crate::deadline::Deadlines;
use crate::error::{Result, StoreError};

/// Build a reqwest client that offers hybrid post-quantum TLS, verifying servers
/// against the Mozilla root set (webpki-roots), and gives up on a host that will
/// not answer after `deadlines.connect`.
///
/// # Why only half of the pair is set here
///
/// `--contimeout` belongs to the client because establishing a connection is the
/// client's own affair: `connect_timeout` bounds the TCP connect **and** the TLS
/// handshake, which together are what rclone bounds with a single number too:
/// one value covers its TLS handshake limit and its dialer's own.
///
/// `--timeout` is deliberately **not** set here, and the omission is the whole
/// design. reqwest offers two client-level knobs and both are the wrong shape:
/// `timeout` is documented as "a total deadline", and `read_timeout` is armed
/// once per request and never re-armed until the response headers arrive
/// (`reqwest-0.12.28/src/async_impl/client.rs:2637`). Either would kill a large
/// upload that was succeeding. rclone does not set a client deadline either — it
/// builds its HTTP client with no total timeout at all — and instead re-arms a
/// deadline on the socket as bytes move. `crate::deadline` is where DCTL does
/// the equivalent, at the closest seam reqwest leaves open.
pub(crate) fn post_quantum_client(deadlines: &Deadlines) -> Result<reqwest::Client> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config =
        rustls::ClientConfig::builder_with_provider(Arc::new(rustls_post_quantum::provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| StoreError::Backend(format!("tls config: {e}")))?
            .with_root_certificates(roots)
            .with_no_client_auth();

    let mut builder = reqwest::Client::builder().use_preconfigured_tls(config);
    if let Some(connect) = deadlines.connect {
        builder = builder.connect_timeout(connect);
    }
    builder
        .build()
        .map_err(|e| StoreError::Backend(format!("http client init: {e}")))
}
