//! The backend's end of the pipe: windows out, and one promise at the end.
//!
//! Two ways to take bytes, because the two families of backend want different
//! shapes and neither should have to pay for the other's:
//!
//! * [`window`](ObjectStream::window) hands over whatever window is next, without
//!   copying it. `local:` and `sftp:` write it straight out.
//! * [`fill`](ObjectStream::fill) tops up a caller's buffer to exactly the size it
//!   asked for. The object stores use it because a multipart part is a fixed
//!   length and has to be one contiguous request body.
//!
//! Both fold the digest over what they hand out, and [`agreed`](ObjectStream::agreed)
//! is what turns that into permission to commit.

use bytes::Bytes;
use tokio::sync::mpsc::Receiver;

use super::Window;
use crate::checksum::{ContentHash, HashAlgo, Hasher};
use crate::error::{Result, StoreError};

/// What a channel that closed with no terminal message means.
///
/// The producer's task panicked, or was cancelled, or its handle was dropped
/// without [`ObjectWriter::finish`](super::ObjectWriter::finish). Every one of
/// those is a failure, and none of them may be read as "the object ended here" —
/// that reading is precisely how a killed sealer would commit a truncated object
/// and be reported as a success.
const PRODUCER_VANISHED: &str =
    "the process producing this object stopped before it finished, so nothing was stored";

/// The bytes of one object, arriving in bounded windows.
///
/// Consumed once. There is no rewind and no second pass: see the module docs of
/// [`super`] for what that means for retry.
pub struct ObjectStream {
    /// The exact length the producer declared. Not a hint — [`agreed`](Self::agreed)
    /// refuses an object that did not turn out to be this long.
    len: u64,
    algo: HashAlgo,
    rx: Receiver<Window>,
    /// The tail of a window a [`fill`](Self::fill) did not use up.
    pending: Bytes,
    /// Folded over every byte handed out, and compared at the end against the
    /// digest the producer folded over every byte it wrote.
    hasher: Option<Hasher>,
    /// Bytes handed out so far.
    consumed: u64,
    /// The producer's own digest, once its terminal message has arrived.
    declared: Option<ContentHash>,
    /// Whether the end of the object has been seen.
    ended: bool,
}

impl ObjectStream {
    /// Wrap the receiving half of a window channel.
    pub(super) fn new(len: u64, algo: HashAlgo, rx: Receiver<Window>) -> Self {
        Self {
            len,
            algo,
            rx,
            pending: Bytes::new(),
            hasher: Some(Hasher::new(algo)),
            consumed: 0,
            declared: None,
            ended: false,
        }
    }

    /// The exact number of bytes this object will be.
    ///
    /// Declared by the producer before the first window, which is what lets a
    /// multipart backend choose its part size and its part count up front rather
    /// than discovering half way through that it has run out of parts.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.len
    }

    /// Whether this object is empty. (Present because clippy asks for it beside
    /// [`len`](Self::len); an empty object is legal and stores as zero bytes.)
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The digest algorithm this stream is folded under.
    #[must_use]
    pub const fn algo(&self) -> HashAlgo {
        self.algo
    }

    /// The next window, or [`None`] once the object has ended.
    ///
    /// # Errors
    /// [`StoreError::Backend`] when the producer failed and said why, or when it
    /// stopped without saying anything at all.
    pub async fn window(&mut self) -> Result<Option<Bytes>> {
        if !self.pending.is_empty() {
            let out = std::mem::replace(&mut self.pending, Bytes::new());
            self.take(&out);
            return Ok(Some(out));
        }
        match self.next_message().await? {
            Some(bytes) => {
                self.take(&bytes);
                Ok(Some(bytes))
            }
            None => Ok(None),
        }
    }

    /// Fill `buf` from the stream, returning how many bytes landed in it.
    ///
    /// Short only at the end of the object, exactly like a `read` that loops
    /// internally: a caller that gets fewer bytes than it asked for has reached
    /// the last part.
    ///
    /// # Errors
    /// As [`window`](Self::window).
    pub async fn fill(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut filled = 0usize;
        while filled < buf.len() {
            if self.pending.is_empty() {
                match self.next_message().await? {
                    Some(bytes) => self.pending = bytes,
                    None => break,
                }
            }
            let take = self.pending.len().min(buf.len() - filled);
            buf[filled..filled + take].copy_from_slice(&self.pending[..take]);
            self.take(&self.pending.slice(..take));
            self.pending = self.pending.slice(take..);
            filled += take;
        }
        Ok(filled)
    }

    /// The digest of this object, once every byte of it has been handed out and
    /// the two ends agree about what those bytes were.
    ///
    /// **This is the permission to commit**, and a backend that has not obtained
    /// it has nothing to put in its [`PutOutcome`](crate::PutOutcome). Three
    /// things have to hold, checked in this order:
    ///
    /// 1. the object ended — the producer sent its terminal message rather than
    ///    disappearing;
    /// 2. it was as long as it said it would be — length before content, because
    ///    a short object is a write that stopped and a differing hash is a
    ///    different sentence with a different remedy;
    /// 3. the digest folded over what was handed out matches the digest folded
    ///    over what was written.
    ///
    /// # Errors
    /// [`StoreError::ShortWrite`] for a length that does not match the
    /// declaration, [`StoreError::ChecksumMismatch`] for a digest that does not,
    /// and [`StoreError::Backend`] for a stream that was never read to its end.
    pub fn agreed(&mut self) -> Result<ContentHash> {
        if !self.ended {
            return Err(StoreError::Backend(
                "this object's digest was asked for before all of its bytes had been \
                 read, so nothing about it has been established"
                    .into(),
            ));
        }
        if self.consumed != self.len {
            return Err(StoreError::ShortWrite {
                expected: self.len,
                actual: self.consumed,
            });
        }
        let computed = self
            .hasher
            .take()
            .ok_or_else(|| StoreError::Backend("this object's digest was already taken".into()))?
            .finalize();
        let declared = self.declared.as_ref().ok_or_else(|| {
            StoreError::Backend("the object ended without declaring a digest".into())
        })?;
        if !computed.matches(declared) {
            return Err(StoreError::ChecksumMismatch {
                expected: declared.hex(),
                actual: computed.hex(),
            });
        }
        Ok(computed)
    }

    /// Confirm the producer had nothing left to send, then [`agreed`](Self::agreed).
    ///
    /// The call a backend that reads with [`fill`](Self::fill) has to make, and
    /// the reason it exists is a defect this method was written to fix: `fill`
    /// stops the instant the caller's buffer is full, so a backend that planned N
    /// parts and filled all N has **never touched the stream's terminal
    /// message** — it does not yet know whether the producer stopped where it
    /// said it would, and [`agreed`](Self::agreed) rightly refuses to answer.
    /// This reads exactly one message further.
    ///
    /// A producer that has more to send at that point declared a length it did
    /// not keep to, and the object is refused rather than committed at the length
    /// the backend happened to plan for.
    ///
    /// # Errors
    /// [`StoreError::Backend`] for a producer with bytes left over, plus every
    /// refusal [`agreed`](Self::agreed) can make.
    pub async fn sealed(&mut self) -> Result<ContentHash> {
        if self.window().await?.is_some() {
            return Err(StoreError::Backend(
                "the producer had more bytes to send than the length it declared, \
                 so nothing has been committed"
                    .into(),
            ));
        }
        self.agreed()
    }

    /// Fold `bytes` into the running digest and count them as handed out.
    fn take(&mut self, bytes: &Bytes) {
        if let Some(hasher) = self.hasher.as_mut() {
            hasher.update(bytes);
        }
        self.consumed += bytes.len() as u64;
    }

    /// The next window from the channel, or [`None`] at a clean end of object.
    async fn next_message(&mut self) -> Result<Option<Bytes>> {
        if self.ended {
            return Ok(None);
        }
        match self.rx.recv().await {
            Some(Window::Bytes(bytes)) => Ok(Some(bytes)),
            Some(Window::Done(digest)) => {
                self.declared = Some(digest);
                self.ended = true;
                Ok(None)
            }
            Some(Window::Failed(why)) => Err(StoreError::Backend(why)),
            None => Err(StoreError::Backend(PRODUCER_VANISHED.into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::object_stream;
    use crate::checksum::{ContentHash, HashAlgo};
    use std::io::Write as _;

    /// Produce `data` into a stream from a blocking task, exactly as the vault
    /// does, and hand back the consumer end.
    fn produced(data: Vec<u8>) -> (tokio::task::JoinHandle<()>, super::ObjectStream) {
        let (mut writer, stream) = object_stream(data.len() as u64, HashAlgo::Blake3);
        let handle = tokio::task::spawn_blocking(move || {
            writer.write_all(&data).expect("the pipe takes the bytes");
            writer.finish().expect("and the end of them");
        });
        (handle, stream)
    }

    #[tokio::test]
    async fn every_byte_arrives_in_order_across_many_windows() {
        // Several windows plus a short one, so both the boundary and the tail are
        // exercised rather than assumed.
        let data: Vec<u8> = (0..(super::super::WINDOW_LEN * 3 + 1234))
            .map(|i| (i % 251) as u8)
            .collect();
        let expected = ContentHash::blake3(&data);
        let (task, mut stream) = produced(data.clone());

        let mut got = Vec::new();
        while let Some(window) = stream.window().await.expect("the stream is healthy") {
            got.push(window.len());
        }
        task.await.expect("the producer finished");

        assert_eq!(got.iter().sum::<usize>(), data.len());
        assert!(
            got.iter().all(|n| *n <= super::super::WINDOW_LEN),
            "a window larger than the bound: {got:?}"
        );
        assert!(
            stream
                .agreed()
                .expect("the two ends agree")
                .matches(&expected)
        );
    }

    #[tokio::test]
    async fn fill_hands_back_exactly_the_part_size_until_the_last_one() {
        let data: Vec<u8> = (0..2_500_000u32).map(|i| (i % 251) as u8).collect();
        let (task, mut stream) = produced(data.clone());

        let part = 1_000_000usize;
        let mut lens = Vec::new();
        loop {
            let mut buf = vec![0u8; part];
            let n = stream.fill(&mut buf).await.expect("the stream is healthy");
            if n == 0 {
                break;
            }
            lens.push(n);
        }
        task.await.expect("the producer finished");

        assert_eq!(lens, vec![1_000_000, 1_000_000, 500_000]);
        assert!(
            stream
                .agreed()
                .expect("the two ends agree")
                .matches(&ContentHash::blake3(&data))
        );
    }

    #[tokio::test]
    async fn a_producer_that_stops_without_finishing_is_never_a_complete_object() {
        // The defect this variant exists to prevent: a sealer killed mid-object
        // closes the channel, and a consumer that read that as end-of-stream would
        // commit whatever arrived and report a success.
        let sent = super::super::WINDOW_LEN;
        let (mut writer, mut stream) = object_stream(sent as u64 * 4, HashAlgo::Blake3);
        let task = tokio::task::spawn_blocking(move || {
            // A whole window, so the consumer really does receive bytes before the
            // producer disappears — a test in which nothing arrived would pass on a
            // consumer that reported an error for any reason at all.
            writer
                .write_all(&vec![7u8; sent])
                .expect("the pipe takes them");
            drop(writer);
        });

        let mut total = 0usize;
        let error = loop {
            match stream.window().await {
                Ok(Some(window)) => total += window.len(),
                Ok(None) => panic!("a vanished producer must not look like a clean end"),
                Err(e) => break e,
            }
        };
        task.await.expect("the producer ran");

        assert_eq!(total, sent);
        assert!(
            error.to_string().contains("stopped before it finished"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn a_producer_that_failed_reports_its_own_reason() {
        let (writer, mut stream) = object_stream(10, HashAlgo::Blake3);
        tokio::task::spawn_blocking(move || writer.fail("the source file could not be read"))
            .await
            .expect("the producer ran");

        let error = stream.window().await.expect_err("a failure must propagate");
        assert!(
            error.to_string().contains("source file could not be read"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn an_object_shorter_than_it_declared_is_refused_rather_than_committed() {
        // Length before content: the producer wrote a well-formed, correctly
        // hashed 4 KiB and *said* it would be a megabyte. Every byte agrees; the
        // object is still not the object.
        let (mut writer, mut stream) = object_stream(1_000_000, HashAlgo::Blake3);
        let task = tokio::task::spawn_blocking(move || {
            writer.write_all(&[7u8; 4096]).expect("the pipe takes them");
            writer.finish().expect("and the end of them");
        });
        while stream
            .window()
            .await
            .expect("the stream is healthy")
            .is_some()
        {}
        task.await.expect("the producer finished");

        let error = stream.agreed().expect_err("a short object must be refused");
        assert!(
            matches!(error, crate::error::StoreError::ShortWrite { expected, actual }
                if expected == 1_000_000 && actual == 4096),
            "{error}"
        );
    }

    #[tokio::test]
    async fn a_digest_asked_for_early_is_refused_rather_than_answered() {
        // A backend that committed on this would be committing on the hash of the
        // prefix it happened to have read.
        let (task, mut stream) = produced(vec![1u8; 4096]);
        let error = stream
            .agreed()
            .expect_err("nothing is established before the end");
        task.await.expect("the producer finished");
        assert!(
            error.to_string().contains("before all of its bytes"),
            "{error}"
        );
    }
}
