//! AWS Signature Version 4 request signing (the shared S3 protocol crux).
//!
//! Verified against AWS's official `aws-sig-v4-test-suite` "get-vanilla" vector in
//! the unit test below — independently of any live endpoint.

use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Lowercase hex SHA-256 of `data` (used for the payload hash and canonical-request hash).
pub(crate) fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// HMAC-SHA256. `new_from_slice` is infallible for HMAC (any key length is valid).
#[allow(clippy::expect_used)]
fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> [u8; 32] {
    let k_date = hmac(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let k_region = hmac(&k_date, region.as_bytes());
    let k_service = hmac(&k_region, service.as_bytes());
    hmac(&k_service, b"aws4_request")
}

/// The SigV4 credential scope: `<yyyymmdd>/<region>/<service>/aws4_request`, where the
/// date is the leading `YYYYMMDD` of `amz_date`.
pub(crate) fn credential_scope(amz_date: &str, region: &str, service: &str) -> String {
    format!("{}/{region}/{service}/aws4_request", &amz_date[0..8])
}

/// Lowercase-and-trim `headers`, sort by name, and return
/// `(signed_headers, canonical_headers)`: the `;`-joined signed-header name list and the
/// `name:value\n` canonical-headers block. Shared by both the header-signed request and
/// the query-string presigned request, which canonicalize headers identically.
pub(crate) fn canonicalize_headers(headers: &[(String, String)]) -> (String, String) {
    let mut hs: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    hs.sort_by(|a, b| a.0.cmp(&b.0));

    let signed_headers = hs
        .iter()
        .map(|(k, _)| k.clone())
        .collect::<Vec<_>>()
        .join(";");
    let canonical_headers: String = hs.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
    (signed_headers, canonical_headers)
}

/// The signing crux shared by the header-based [`authorization`] and the query-string
/// presign (delegated upload): given the fully-assembled `canonical_request`, derive the
/// lowercase-hex signature (string-to-sign → signing key → HMAC-SHA256).
///
/// Reads **no clock** — `amz_date` is supplied by the caller. That is what makes
/// presigning deterministic and unit-testable offline.
pub(crate) fn sign_canonical_request(
    canonical_request: &str,
    secret_key: &str,
    region: &str,
    service: &str,
    amz_date: &str,
) -> String {
    let scope = credential_scope(amz_date, region, service);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );
    let key = signing_key(secret_key, &amz_date[0..8], region, service);
    hex::encode(hmac(&key, string_to_sign.as_bytes()))
}

/// Compute the `Authorization` header value for a request.
///
/// `headers` must include every header to be signed (host, x-amz-date,
/// x-amz-content-sha256, and any others). `amz_date` is `YYYYMMDDTHHMMSSZ`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn authorization(
    method: &str,
    canonical_uri: &str,
    canonical_query: &str,
    headers: &[(String, String)],
    payload_sha256: &str,
    access_key: &str,
    secret_key: &str,
    region: &str,
    service: &str,
    amz_date: &str,
) -> String {
    let (signed_headers, canonical_headers) = canonicalize_headers(headers);
    let canonical_request = format!(
        "{method}\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{payload_sha256}"
    );

    let scope = credential_scope(amz_date, region, service);
    let signature =
        sign_canonical_request(&canonical_request, secret_key, region, service, amz_date);

    format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AWS `aws-sig-v4-test-suite` / "get-vanilla": a GET with only host + x-amz-date
    /// signed. The expected signature is published by AWS, so this validates the
    /// signer independently of DCTL and of any live endpoint.
    #[test]
    fn matches_aws_get_vanilla_vector() {
        let payload = sha256_hex(b"");
        let headers = vec![
            ("host".to_string(), "example.amazonaws.com".to_string()),
            ("x-amz-date".to_string(), "20150830T123600Z".to_string()),
        ];
        let auth = authorization(
            "GET",
            "/",
            "",
            &headers,
            &payload,
            "AKIDEXAMPLE",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "us-east-1",
            "service",
            "20150830T123600Z",
        );
        assert!(
            auth.ends_with(
                "Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
            ),
            "unexpected authorization: {auth}"
        );
    }
}
