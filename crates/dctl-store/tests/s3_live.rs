//! Live S3-compatible round-trip. Ignored by default; runs only with real creds:
//!
//! ```sh
//! DCTL_S3_ENDPOINT=... DCTL_S3_REGION=... DCTL_S3_BUCKET=... \
//!   DCTL_S3_ACCESS_KEY=... DCTL_S3_SECRET_KEY=... \
//!   cargo test -p dctl-store --test s3_live -- --ignored --nocapture
//! ```
//!
//! Works against any S3-compatible endpoint (AWS, R2, Wasabi, MinIO, or
//! Backblaze's S3 API). Exercises put -> head/exists -> get -> range -> list ->
//! delete (small-file path; multipart shares the same code).

use bytes::Bytes;
use dctl_store::{Backend, ByteRange, ContentHash, ObjectKey, S3Backend, S3Config};

fn config_from_env() -> Option<S3Config> {
    Some(S3Config::new(
        std::env::var("DCTL_S3_ENDPOINT").ok()?,
        std::env::var("DCTL_S3_REGION").ok()?,
        std::env::var("DCTL_S3_BUCKET").ok()?,
        std::env::var("DCTL_S3_ACCESS_KEY").ok()?,
        std::env::var("DCTL_S3_SECRET_KEY").ok()?,
    ))
}

#[tokio::test]
#[ignore = "requires live S3 credentials via DCTL_S3_* env vars"]
async fn s3_full_round_trip() {
    let Some(config) = config_from_env() else {
        eprintln!("skipping s3_full_round_trip: DCTL_S3_* not set");
        return;
    };

    let s3 = S3Backend::new(config).unwrap();
    let key = ObjectKey::new(format!("dctl-s3-test/roundtrip-{}.bin", std::process::id()));
    let data = Bytes::from((0u8..=255).cycle().take(5000).collect::<Vec<u8>>());
    let expected = ContentHash::blake3(&data);

    let outcome = s3.put(&key, data.clone(), &expected).await.unwrap();
    assert_eq!(outcome.size, data.len() as u64);

    assert!(s3.exists(&key).await.unwrap());
    assert_eq!(s3.head(&key).await.unwrap().size, data.len() as u64);
    assert_eq!(s3.get(&key).await.unwrap(), data);

    let mid = s3
        .get_range(&key, ByteRange::new(100, Some(50)))
        .await
        .unwrap();
    assert_eq!(&mid[..], &data[100..150]);

    let page = s3.list_page("dctl-s3-test/", None).await.unwrap();
    assert!(page.items.iter().any(|m| m.key == key));

    s3.delete(&key).await.unwrap();
    assert!(!s3.exists(&key).await.unwrap());

    eprintln!("s3_full_round_trip: OK");
}
