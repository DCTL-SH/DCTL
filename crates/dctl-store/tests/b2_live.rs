//! Live B2 round-trip test. Ignored by default; runs only when the environment
//! provides real credentials:
//!
//! ```sh
//! DCTL_B2_KEY_ID=... DCTL_B2_APP_KEY=... DCTL_B2_BUCKET=... \
//!   cargo test -p dctl-store --test b2_live -- --ignored --nocapture
//! ```
//!
//! It exercises the small-file path (put → verify → head/exists → get → range →
//! list → delete). The large-file (multipart) path shares the same code but is
//! not exercised here to avoid uploading >100 MiB.

use bytes::Bytes;
use dctl_store::b2::{B2Backend, B2Credentials};
use dctl_store::{Backend, ByteRange, ContentHash, ObjectKey};

fn creds_from_env() -> Option<(String, String, String)> {
    Some((
        std::env::var("DCTL_B2_KEY_ID").ok()?,
        std::env::var("DCTL_B2_APP_KEY").ok()?,
        std::env::var("DCTL_B2_BUCKET").ok()?,
    ))
}

#[tokio::test]
#[ignore = "requires live B2 credentials via DCTL_B2_* env vars"]
async fn b2_full_round_trip() {
    let Some((key_id, app_key, bucket)) = creds_from_env() else {
        eprintln!("skipping b2_full_round_trip: DCTL_B2_* not set");
        return;
    };

    let b2 = B2Backend::new(B2Credentials::new(key_id, app_key), bucket).unwrap();
    let key = ObjectKey::new(format!("dctl-test/roundtrip-{}.bin", std::process::id()));
    let data = Bytes::from((0u8..=255).cycle().take(5000).collect::<Vec<u8>>());
    let expected = ContentHash::sha1(&data);

    // put (verified)
    let outcome = b2.put(&key, data.clone(), &expected).await.unwrap();
    assert_eq!(outcome.size, data.len() as u64);

    // head / exists
    assert!(b2.exists(&key).await.unwrap());
    assert_eq!(b2.head(&key).await.unwrap().size, data.len() as u64);

    // get (full)
    assert_eq!(b2.get(&key).await.unwrap(), data);

    // get_range (streaming seek)
    let mid = b2
        .get_range(&key, ByteRange::new(100, Some(50)))
        .await
        .unwrap();
    assert_eq!(&mid[..], &data[100..150]);

    // list_page sees it under its prefix
    let page = b2.list_page("dctl-test/", None).await.unwrap();
    assert!(page.items.iter().any(|m| m.key == key));

    // delete (idempotent)
    b2.delete(&key).await.unwrap();
    assert!(!b2.exists(&key).await.unwrap());
    b2.delete(&key).await.unwrap();

    eprintln!("b2_full_round_trip: OK");
}
