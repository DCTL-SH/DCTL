//! The sealed source: a vault, read through its encrypted index.
//!
//! Everything here goes through [`dctl_core::Vault`], which means every read is
//! authenticated before it is returned and a listing shows *plaintext* paths and
//! *plaintext* sizes rather than the opaque object keys those files are actually
//! stored under. That translation is the whole reason `dctl ls archive:` and
//! `dctl ls archive-store:` show two completely different things about one
//! directory of bytes, and it is why the sealed view has to be a source of its
//! own rather than a filter over the plain one.
//!
//! ## The buffering here is the core's, and this is where it will disappear
//!
//! `PLAN.md` §16.2 forbids materialising a full file list, and this
//! implementation does exactly that — once, in [`VaultSource::enumerate`],
//! because [`Vault::list`](dctl_core::Vault::list) returns a `Vec<Record>`. Its
//! own documentation is candid about it: it enumerates the index in constant
//! memory internally and then materialises the result "for caller convenience".
//! So the records are built, sorted and handed over in full before this file
//! sees any of them, and nothing that can be written on this side of the crate
//! boundary changes that.
//!
//! What *is* in this file's gift is refusing to spread the problem. The cursor
//! below hands out one [`Entry`] at a time and is the only thing any caller
//! ever holds, so every listing verb in the binary is already written against a
//! stream. The fix, when it comes, is one function: `dctl-core` grows a
//! `Vault::for_each`-shaped or range-cursor API over
//! [`dctl_index::Index::for_each`] — which already streams — and
//! [`Buffered`] is replaced by a cursor that pulls from it. No call site
//! changes. Structuring it the other way round, with the renderers over a slice
//! and "we will stream it later", is how a tool ends up unable to list its own
//! dataset.
//!
//! ## Reads are whole-object, and that is the core's shape too
//!
//! [`Vault::get_file`](dctl_core::Vault::get_file) decrypts and authenticates an
//! entire object and hands back the plaintext. There is no narrower call, so
//! [`VaultSource::read_range`] reads the whole object and slices it: the bytes
//! it returns are correct, and the cost is O(object) in memory and in egress
//! rather than O(window). That is stated rather than hidden because the
//! alternative — a `read_range` that quietly downloads 40 GB to serve a 4 KB
//! window — is the sort of thing that is discovered on a bill.
//!
//! It is not faked, and it is not capped. Returning a short read or refusing
//! above some size would trade a documented cost for an undocumented wrong
//! answer, and `PLAN.md` §6 is unambiguous about which of those is worse.

use std::collections::VecDeque;

use async_trait::async_trait;
use dctl_core::Record;
use zeroize::Zeroizing;

use crate::ctx::Ctx;
use crate::error::Result;
use crate::platform::path;
use crate::remote::RemoteSpec;
use crate::session::{self, Session};

use super::entry::Entry;
use super::{Assurance, Entries, Sizes, Source};

/// A vault, unlocked, presented as a readable source.
pub struct VaultSource {
    /// The unlocked vault plus the context that identified it.
    ///
    /// Held whole rather than reduced to its `vault` field: the session also
    /// carries the remote name and the index path, which are what an error
    /// raised from here has to quote for an operator to know *which* vault
    /// refused them.
    session: Session,
}

impl VaultSource {
    /// Unlock the vault `spec` addresses.
    ///
    /// Delegates to [`session::open`], which is the one place that follows a
    /// vault chain to the remote actually holding bytes, acquires the password
    /// through the full fallback ladder, and refuses a second factor this build
    /// cannot apply. None of that is re-implemented here, and that is the point:
    /// a second copy of the unlock sequence is a second copy that can forget
    /// `--no-ask-password` and hang an unattended backup on an invisible prompt.
    ///
    /// # Errors
    /// Whatever [`session::open`] reported — an unresolvable remote, a missing
    /// password, or an envelope that will not unwrap.
    pub async fn open(ctx: &Ctx, spec: &RemoteSpec) -> Result<Self> {
        Ok(Self::new(session::open(ctx, spec).await?))
    }

    /// Wrap an already-unlocked session.
    ///
    /// Separate from [`VaultSource::open`] so a test can drive a real vault over
    /// a temporary directory without a config file, a password prompt or an
    /// environment variable — and so a future command that already holds a
    /// session does not unlock a second time to read from it.
    #[must_use]
    pub const fn new(session: Session) -> Self {
        Self { session }
    }

    /// The plaintext of one object, whole.
    ///
    /// Shared by [`Source::read`] and [`Source::read_range`] because there is
    /// only one way to get bytes out of a vault; see the module documentation.
    async fn whole(&self, path: &str) -> Result<Zeroizing<Vec<u8>>> {
        Ok(self.session.vault.get_file(path).await?)
    }
}

#[async_trait]
impl Source for VaultSource {
    async fn enumerate(&self, prefix: &str) -> Result<Box<dyn Entries>> {
        // Sorted ascending by path by the core, which is the ordering contract
        // on `Entries` — restated here because a change in `Vault::list` that
        // dropped the sort would break `lsd` and `tree` silently rather than
        // loudly.
        let records = self.session.vault.list(prefix)?;

        let entries = records
            .into_iter()
            // The index matches a prefix by bytes, so listing `photos` also
            // sees `photos-backup`. Comparing whole components is what stops
            // `dctl ls archive:photos` from reporting a neighbouring tree as if
            // it were inside the one that was named.
            .filter(|record| path::is_under(prefix, &record.path))
            .map(from_record)
            .collect();

        Ok(Box::new(Buffered { entries }))
    }

    fn sizes(&self) -> Sizes {
        // `Record::size` is the length of the file that was sealed, never of the
        // object holding it: the index is written from the plaintext, and the
        // ciphertext length would have to be asked of the provider one object at
        // a time. Saying so is what keeps `dctl size archive:` from being read
        // as a storage bill.
        Sizes::Plaintext
    }

    async fn read(&self, path: &str) -> Result<Zeroizing<Vec<u8>>> {
        self.whole(path).await
    }

    async fn read_range(
        &self,
        path: &str,
        offset: u64,
        length: Option<u64>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let plaintext = self.whole(path).await?;
        Ok(slice(&plaintext, offset, length))
    }

    async fn stat(&self, path: &str) -> Result<Option<Entry>> {
        // Answered from the local index, which is the only thing that can answer
        // it without reading the object: a vault's sizes live in its index, and
        // the object header would have to be fetched and decrypted to learn them
        // any other way.
        //
        // A path the index has never seen therefore reports `None` even when the
        // backend holds it — the cross-device case, where `Vault::get_file`
        // still succeeds by way of the authoritative §5 name record. That is a
        // real gap, and the honest place to fix it is `dctl-core`, with a `stat`
        // that consults the same name record. Callers are told to reach for
        // `dctl index rebuild`, which populates the index from the backend and
        // makes this answer true again.
        let query = path::normalize_unicode(path);
        let records = self.session.vault.list(&query)?;
        let Some(entry) = records
            .into_iter()
            .find(|record| record.path == query)
            .map(from_record)
        else {
            return Ok(None);
        };

        if !unmeasured(&entry) {
            return Ok(Some(entry));
        }

        // A rebuilt row: real, and carrying a size nobody has ever measured.
        // Returning its zero would make `dctl cat` write no bytes and exit 0 for
        // a file that is plainly there, which is the one failure this project
        // may not have. So the size is *established* rather than guessed, at the
        // cost of a read — see [`unmeasured`] for why this case is
        // distinguishable and why it cannot fire for a genuinely empty file.
        let plaintext = self.whole(&entry.path).await?;
        Ok(Some(
            Entry::new(entry.path, plaintext.len() as u64)
                .with_modified(entry.modified_unix)
                // Now known, because the bytes are in hand and were
                // authenticated on the way through.
                .with_content_hash(blake3::hash(&plaintext).as_bytes().to_vec()),
        ))
    }

    async fn verify(&self, path: &str) -> Result<()> {
        // The one read on this side that is *not* O(object):
        // `Vault::verify_file` stream-decrypts into a sink, so every chunk tag
        // and the footer are checked at O(chunk) plaintext memory. That is what
        // makes a scrub of a vault full of multi-gigabyte videos possible at
        // all, and it is why this method exists instead of `read`-and-discard.
        Ok(self.session.vault.verify_file(path).await?)
    }

    fn assurance(&self) -> Assurance {
        // The vault recorded a plaintext BLAKE3 under the object's own DEK at
        // write time, and every chunk carries an authentication tag. A pass here
        // is a statement about the bytes that were written, not merely about the
        // bytes that came back.
        Assurance::Authenticated
    }
}

/// A cursor over records the core already materialised.
///
/// Named for what it is. See the module documentation for why the buffer is
/// here, whose limitation it is, and what replacing it looks like.
struct Buffered {
    /// Remaining entries in path order. A [`VecDeque`] so that taking the front
    /// is O(1) rather than an O(n) shift out of a `Vec` on every single entry.
    entries: VecDeque<Entry>,
}

#[async_trait]
impl Entries for Buffered {
    async fn next(&mut self) -> Result<Option<Entry>> {
        Ok(self.entries.pop_front())
    }
}

/// Translate one index record into the provider-neutral entry.
///
/// Deliberately drops `object_key`. It is the opaque name the ciphertext is
/// stored under, and printing it beside the plaintext path — which is what a
/// listing does — would hand an observer exactly the mapping the metadata-
/// privacy design exists to withhold (`PLAN.md` §2, §7). A type that cannot
/// carry it is a type no renderer can leak it through.
fn from_record(record: Record) -> Entry {
    Entry::new(record.path, record.size)
        .with_modified(record.modified_unix)
        .with_content_hash(record.content_hash)
}

/// Whether this record's size was never measured.
///
/// [`Vault::rebuild_index`](dctl_core::Vault::rebuild_index) recovers a machine
/// from the backend alone by listing and decrypting the §5 name records. That is
/// a **list-only pass** by design — it must not cost a full read of the dataset
/// — so the rows it writes carry `size: 0` and an *empty* content hash, and the
/// core's own comment says the sizes populate on first read.
///
/// The two conditions together are what make the case identifiable. A file
/// written through the ordinary path always has a 32-byte BLAKE3 recorded, and
/// that is true of a genuinely empty file too: `blake3::hash(b"")` is a full
/// digest, not nothing. So `size == 0` with *no* hash cannot be an empty file
/// that was written here; it can only be a row nobody has measured yet.
///
/// Distinguishing them matters because the alternative is silent: a caller that
/// believed the zero would read no bytes and report success.
fn unmeasured(entry: &Entry) -> bool {
    entry.size == 0 && entry.content_hash.is_none()
}

/// Copy the window `[offset, offset + length)` out of `plaintext`.
///
/// Clamps rather than fails: an offset at or past the end yields no bytes, which
/// is what a `seek` plus a bounded read does on a local file. Refusing instead
/// would make `dctl cat --offset` behave differently on the two sides of a
/// transfer for no reason a user could act on.
fn slice(plaintext: &[u8], offset: u64, length: Option<u64>) -> Zeroizing<Vec<u8>> {
    // `usize` on a 32-bit host is narrower than the `u64` the flags parse into,
    // so a saturating conversion is what keeps an absurd `--offset` from
    // wrapping to a small one and returning the wrong bytes.
    let start = usize::try_from(offset)
        .unwrap_or(usize::MAX)
        .min(plaintext.len());
    let available = plaintext.len() - start;
    let taken = length
        .map_or(available, |len| usize::try_from(len).unwrap_or(usize::MAX))
        .min(available);

    Zeroizing::new(plaintext[start..start + taken].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Arc;

    use dctl_core::Vault;
    use dctl_store::{Backend, LocalFs};
    use tempfile::TempDir;

    /// A real vault over two temporary directories, with `files` written into
    /// it. Nothing is mocked: the objects are sealed, stored and indexed exactly
    /// as `dctl copy` would have stored them.
    struct Fixture {
        _store: TempDir,
        _index: TempDir,
        source: VaultSource,
    }

    async fn vault_with(files: &[(&str, &[u8])]) -> Fixture {
        let store = TempDir::new().expect("a temporary store");
        let index = TempDir::new().expect("a temporary index");
        let backend: Arc<dyn Backend> = Arc::new(LocalFs::new(store.path()));
        let index_path: PathBuf = index.path().join("index.redb");

        let vault = Vault::init(Arc::clone(&backend), &index_path, "pw")
            .await
            .expect("a fresh vault initialises");
        for (path, bytes) in files {
            vault.put_file(path, bytes).await.expect("a verified write");
        }

        let session = Session {
            vault,
            remote: "archive:".to_string(),
            index: index_path,
        };
        Fixture {
            _store: store,
            _index: index,
            source: VaultSource::new(session),
        }
    }

    async fn paths(source: &VaultSource, prefix: &str) -> Vec<String> {
        let mut cursor = source.enumerate(prefix).await.expect("a listing opens");
        let mut out = Vec::new();
        while let Some(entry) = cursor.next().await.expect("a page cannot fail") {
            out.push(entry.path);
        }
        out
    }

    #[tokio::test]
    async fn every_stored_file_is_enumerated_once_in_path_order() {
        let fixture = vault_with(&[
            ("b/second.txt", b"22"),
            ("a.txt", b"1"),
            ("b/first.txt", b"333"),
        ])
        .await;

        assert_eq!(
            paths(&fixture.source, "").await,
            ["a.txt", "b/first.txt", "b/second.txt"]
        );
    }

    #[tokio::test]
    async fn a_prefix_scopes_the_listing_to_whole_components() {
        // `photos` is not the parent of `photos-backup`. The index matches
        // prefixes by bytes and would report both.
        let fixture = vault_with(&[
            ("photos/a.jpg", b"a"),
            ("photos-backup/b.jpg", b"b"),
            ("other/c.jpg", b"c"),
        ])
        .await;

        assert_eq!(paths(&fixture.source, "photos").await, ["photos/a.jpg"]);
    }

    #[tokio::test]
    async fn an_empty_vault_enumerates_to_nothing_without_failing() {
        // "There is nothing here" is an answer, not an error — and an exhausted
        // cursor keeps saying so rather than looping.
        let fixture = vault_with(&[]).await;
        let mut cursor = fixture
            .source
            .enumerate("")
            .await
            .expect("an empty listing still opens");
        assert!(cursor.next().await.expect("no failure").is_none());
        assert!(cursor.next().await.expect("no failure").is_none());
    }

    #[tokio::test]
    async fn a_prefix_that_matches_nothing_is_empty_rather_than_everything() {
        // The failure mode worth guarding: a prefix filter that silently fell
        // through would list the whole vault for `dctl ls archive:nowhere`.
        let fixture = vault_with(&[("a.txt", b"1")]).await;
        assert!(paths(&fixture.source, "nowhere").await.is_empty());
    }

    #[tokio::test]
    async fn an_entry_carries_the_plaintext_size_and_hash() {
        let fixture = vault_with(&[("a.txt", b"hello")]).await;
        let mut cursor = fixture.source.enumerate("").await.expect("a listing");
        let entry = cursor.next().await.expect("no failure").expect("one entry");

        // The plaintext length, not the sealed object's — otherwise `ls` and
        // `cat | wc -c` disagree about the same file.
        assert_eq!(entry.size, 5);
        assert_eq!(
            entry.content_hash.as_deref(),
            Some(blake3::hash(b"hello").as_bytes().as_slice()),
            "the recorded hash must be of the plaintext"
        );
    }

    #[tokio::test]
    async fn a_read_returns_the_plaintext() {
        let fixture = vault_with(&[("notes/today.md", b"sealed and returned")]).await;
        let bytes = fixture
            .source
            .read("notes/today.md")
            .await
            .expect("the object reads back");
        assert_eq!(bytes.as_slice(), b"sealed and returned");
    }

    #[tokio::test]
    async fn a_missing_path_is_reported_rather_than_read_as_empty() {
        // Returning zero bytes for an object that is not there is the misreport
        // `PLAN.md` §6 forbids: a redirected `dctl cat` would leave a file that
        // looks like a successful, empty download.
        let fixture = vault_with(&[("a.txt", b"1")]).await;
        let error = fixture
            .source
            .read("nope.txt")
            .await
            .expect_err("a missing object must fail");
        assert_eq!(error.code(), crate::exit::ExitCode::FileNotFound);
        assert!(error.hint().is_some(), "a refusal must say what to do next");
    }

    #[tokio::test]
    async fn a_range_read_returns_exactly_its_window() {
        let fixture = vault_with(&[("a.bin", b"0123456789")]).await;
        let source = &fixture.source;

        assert_eq!(
            source
                .read_range("a.bin", 4, Some(3))
                .await
                .unwrap()
                .as_slice(),
            b"456"
        );
        // No length means "to the end".
        assert_eq!(
            source
                .read_range("a.bin", 7, None)
                .await
                .unwrap()
                .as_slice(),
            b"789"
        );
        // A window longer than what is left is clamped, not refused.
        assert_eq!(
            source
                .read_range("a.bin", 8, Some(999))
                .await
                .unwrap()
                .as_slice(),
            b"89"
        );
        // An offset at or past the end yields nothing, exactly as a seek would.
        assert!(
            source
                .read_range("a.bin", 10, Some(5))
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            source
                .read_range("a.bin", 4_000, None)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn stat_describes_a_stored_object_and_answers_none_for_a_missing_one() {
        let fixture = vault_with(&[("photos/a.jpg", b"12345")]).await;

        let found = fixture
            .source
            .stat("photos/a.jpg")
            .await
            .expect("the lookup succeeds")
            .expect("the object is there");
        assert_eq!(found.path, "photos/a.jpg");
        assert_eq!(found.size, 5);

        // Absent is an answer, not a failure — the caller distinguishes "not
        // there" from "could not look" by which channel it arrived on.
        assert!(
            fixture
                .source
                .stat("photos/missing.jpg")
                .await
                .expect("the lookup still succeeds")
                .is_none()
        );
    }

    #[tokio::test]
    async fn stat_does_not_mistake_a_sibling_for_the_object_asked_for() {
        // `vault.list` is a byte-wise prefix scan, so a naive "first record"
        // would answer `a.jpg.bak` for a query about `a.jpg`.
        let fixture = vault_with(&[("a.jpg.bak", b"old"), ("a.jpg", b"new")]).await;
        let found = fixture
            .source
            .stat("a.jpg")
            .await
            .expect("the lookup succeeds")
            .expect("the object is there");
        assert_eq!(found.path, "a.jpg");
        assert_eq!(found.size, 3);
    }

    #[tokio::test]
    async fn a_rebuilt_row_is_measured_rather_than_reported_as_empty() {
        // The failure this guards, seen for real: `dctl index rebuild` writes
        // rows with no size, and a `stat` that believed the zero made
        // `dctl cat archive:a.txt` print nothing and exit 0 for a file that was
        // plainly there.
        let fixture = vault_with(&[("a.txt", b"hello world")]).await;
        fixture
            .source
            .session
            .vault
            .rebuild_index()
            .await
            .expect("the index rebuilds from the backend");

        // The listing shows what the index holds, which is genuinely nothing.
        let mut cursor = fixture.source.enumerate("").await.unwrap();
        let listed = cursor.next().await.unwrap().expect("the row is there");
        assert_eq!(listed.size, 0, "a rebuild records no size");
        assert!(unmeasured(&listed));

        // `stat` refuses to pass that on as a fact.
        let found = fixture
            .source
            .stat("a.txt")
            .await
            .unwrap()
            .expect("the object is there");
        assert_eq!(found.size, 11);
        assert_eq!(
            found.content_hash.as_deref(),
            Some(blake3::hash(b"hello world").as_bytes().as_slice())
        );
    }

    #[tokio::test]
    async fn a_genuinely_empty_file_is_not_mistaken_for_an_unmeasured_row() {
        // `blake3::hash(b"")` is a full digest, so a file written here always
        // has one — which is exactly what keeps the two cases apart.
        let fixture = vault_with(&[("empty.txt", b"")]).await;
        let found = fixture
            .source
            .stat("empty.txt")
            .await
            .unwrap()
            .expect("an empty object is still an object");
        assert_eq!(found.size, 0);
        assert!(found.content_hash.is_some());
        assert!(!unmeasured(&found));
    }

    #[tokio::test]
    async fn a_verify_authenticates_the_stored_bytes_and_notices_when_they_change() {
        // The claim this source is allowed to make, proved: the object is
        // overwritten behind DCTL's back and the check catches it.
        let fixture = vault_with(&[("a.txt", b"sealed")]).await;
        fixture
            .source
            .verify("a.txt")
            .await
            .expect("an intact object authenticates");

        let objects = fixture._store.path().join("o");
        for entry in std::fs::read_dir(&objects).expect("the object directory exists") {
            let path = entry.expect("a directory entry").path();
            let length = std::fs::metadata(&path).expect("readable").len();
            std::fs::write(&path, vec![0xA5; length as usize]).expect("overwritten");
        }

        let error = fixture
            .source
            .verify("a.txt")
            .await
            .expect_err("altered bytes must not pass");
        assert_eq!(error.code(), crate::exit::ExitCode::IntegrityFailure);

        // And the claim itself, which is what separates this source from a
        // plain store that would have read the same garbage back happily.
        assert_eq!(fixture.source.assurance(), Assurance::Authenticated);
        assert!(fixture.source.assurance().detects_corruption());
    }

    #[tokio::test]
    async fn a_verify_of_a_missing_object_is_reported_as_missing() {
        let fixture = vault_with(&[("a.txt", b"1")]).await;
        let error = fixture
            .source
            .verify("nope.txt")
            .await
            .expect_err("a missing object cannot be verified");
        assert_eq!(error.code(), crate::exit::ExitCode::FileNotFound);
    }

    #[test]
    fn a_window_never_reads_outside_the_buffer() {
        // The arithmetic on its own, including the values a `u64` flag can hold
        // that a `usize` index cannot.
        assert_eq!(slice(b"abcdef", 0, None).as_slice(), b"abcdef");
        assert_eq!(slice(b"abcdef", 2, Some(2)).as_slice(), b"cd");
        assert!(slice(b"abcdef", 6, Some(1)).is_empty());
        assert!(slice(b"abcdef", u64::MAX, None).is_empty());
        assert_eq!(slice(b"abcdef", 1, Some(u64::MAX)).as_slice(), b"bcdef");
        assert!(slice(b"", 0, None).is_empty());
    }
}
