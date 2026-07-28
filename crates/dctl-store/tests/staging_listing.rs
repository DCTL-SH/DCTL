//! What every backend answers when asked what it abandoned.
//!
//! `Backend::list_staging` exists because `Backend::list_page` could not answer
//! this question: it omits staging files on purpose, so the sweep that reclaims
//! them searched a list they had already been removed from and reported
//! `OK removed: 0 object(s), 0 B` over a store holding a killed upload's
//! leftovers. The trait method has **no default**, deliberately, so that a
//! backend added later cannot inherit that silence — and these are the
//! assertions that pin what each of the existing five says.
//!
//! Four of the five are here. The fifth, sftp, needs a real server: its
//! selection and its paging are pinned in the crate's own unit tests, and the
//! end-to-end behaviour over a live `sshd` is verified separately. Nothing here
//! opens a socket — the three object stores answer this question without a
//! request, which is itself part of what is asserted.

use std::sync::Arc;

use dctl_store::b2::{B2Backend, B2Credentials};
use dctl_store::{
    Backend, LocalFs, R2Backend, S3Backend, S3Config, STAGING_NAME_PREFIX, StagingListing,
};

/// A staging file exactly as an interrupted verified write leaves one.
fn plant(directory: &std::path::Path, name_suffix: &str) -> std::path::PathBuf {
    std::fs::create_dir_all(directory).expect("create the store directory");
    let path = directory.join(format!("{STAGING_NAME_PREFIX}{name_suffix}"));
    std::fs::write(&path, b"half a write").expect("plant the staging file");
    path
}

/// Every key one page of a listing holds.
async fn staging_keys(backend: &dyn Backend, prefix: &str) -> Vec<String> {
    match backend
        .list_staging(prefix, None)
        .await
        .expect("the enumeration works")
    {
        StagingListing::Page(page) => page
            .items
            .iter()
            .map(|meta| meta.key.as_str().to_string())
            .collect(),
        StagingListing::NotStaged(reason) => panic!("expected a page, got: {reason}"),
    }
}

#[tokio::test]
async fn a_local_store_enumerates_the_debris_a_killed_write_left_and_nothing_else() {
    // The defect, at the layer that could not see it. Three files in the store:
    // a committed object, a user's file whose name merely reads temporary, and
    // one piece of real debris.
    let store = tempfile::TempDir::new().expect("a temporary store");
    std::fs::create_dir_all(store.path().join("o")).expect("the object directory");
    std::fs::write(store.path().join("o/8f14e45f"), b"committed").expect("an object");
    std::fs::write(store.path().join("report.tmp.2024.csv"), b"a user's file").expect("a file");
    let debris = plant(&store.path().join("o"), "4711.0");

    let backend = LocalFs::new(store.path());
    assert_eq!(
        staging_keys(&backend, "").await,
        vec![format!(
            "o/{}",
            debris.file_name().expect("a name").to_string_lossy()
        )],
    );

    // And the object listing still omits it, which is the other half of the
    // contract: a half-written upload is not an object.
    let page = backend
        .list_page("", None)
        .await
        .expect("the object listing");
    let mut objects: Vec<String> = page
        .items
        .iter()
        .map(|meta| meta.key.as_str().to_string())
        .collect();
    objects.sort();
    assert_eq!(objects, ["o/8f14e45f", "report.tmp.2024.csv"]);
}

#[tokio::test]
async fn a_clean_local_store_enumerates_nothing_and_says_it_looked() {
    // The honest empty answer, which is what makes a non-empty one mean
    // something — and it is a `Page`, not a `NotStaged`: this backend does
    // stage, it looked, and there was nothing there.
    let store = tempfile::TempDir::new().expect("a temporary store");
    std::fs::write(store.path().join("a.bin"), b"committed").expect("an object");

    let backend = LocalFs::new(store.path());
    assert!(staging_keys(&backend, "").await.is_empty());
}

#[tokio::test]
async fn a_local_staging_listing_is_scoped_by_the_prefix_it_was_given() {
    // `dctl cleanup remote:photos --class staging` must not sweep the debris of
    // a different subtree. The prefix rule is the object listing's, applied to
    // the same walk.
    let store = tempfile::TempDir::new().expect("a temporary store");
    plant(&store.path().join("photos"), "1.0");
    plant(&store.path().join("videos"), "2.0");

    let backend = LocalFs::new(store.path());
    let keys = staging_keys(&backend, "photos").await;
    assert_eq!(keys.len(), 1, "{keys:?}");
    assert!(keys[0].starts_with("photos/"), "{keys:?}");
}

#[tokio::test]
async fn the_three_object_stores_say_they_never_stage_rather_than_reporting_zero() {
    // They upload straight to the object's final key, so there is no temporary
    // key for a killed process to abandon — measured on a live B2 bucket, where
    // a `SIGKILL` mid-copy leaves `system/envelope.bin` and nothing else.
    //
    // `removed: 0` would be a true number and an untrue answer: it is exactly
    // what `local:` and `sftp:` printed while holding megabytes of debris. So
    // the backend returns the reason instead, and no request is made to learn
    // it — these constructions carry credentials that would be refused.
    let b2: Arc<dyn Backend> = Arc::new(
        B2Backend::new(B2Credentials::new("nobody", "nothing"), "no-such-bucket")
            .expect("a client is built without contacting anything"),
    );
    let s3: Arc<dyn Backend> = Arc::new(
        S3Backend::new(S3Config::new(
            "https://s3.invalid",
            "us-east-1",
            "bucket",
            "key",
            "secret",
        ))
        .expect("a client is built without contacting anything"),
    );
    let r2: Arc<dyn Backend> = Arc::new(
        R2Backend::new("account", "bucket", "key", "secret")
            .expect("a client is built without contacting anything"),
    );

    let mut reasons = Vec::new();
    for backend in [&b2, &s3, &r2] {
        match backend
            .list_staging("", None)
            .await
            .expect("answering costs no request")
        {
            StagingListing::NotStaged(reason) => {
                assert!(
                    !reason.is_empty(),
                    "{}: the answer is the sentence, so it may not be empty",
                    backend.name()
                );
                reasons.push(reason);
            }
            StagingListing::Page(_) => panic!(
                "{} claimed to have a staging namespace it does not have",
                backend.name()
            ),
        }
    }

    // One sentence, not three: an operator sweeping B2 and R2 on the same night
    // must not be told two different things about one fact.
    assert_eq!(reasons[0], reasons[1]);
    assert_eq!(reasons[1], reasons[2]);
}
