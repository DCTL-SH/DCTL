//! Draining a whole object into one buffer, for the arms that send one request.
//!
//! Every multipart backend has a sub-threshold arm: an object at or below one
//! part is bounded by the part size by definition, so it is drained into a single
//! buffer and takes the same verified single-request path a buffered
//! [`put`](crate::Backend::put) takes. B2 and S3 both have one, they were
//! written separately, and they carried the same nine lines twice — a shape
//! this codebase has met before, where a guarantee with N copies is a guarantee
//! a test covering one copy leaves deletable in the other N-1.
//!
//! # Why the length check here needs a seam to be reachable
//!
//! The arm asks the producer's end of the pipe two questions and both have to be
//! answered before anything is committed:
//!
//! 1. `fill` — hand over exactly `size` bytes;
//! 2. `sealed` — confirm the object ended, at the length it declared, with the
//!    digest the producer folded over what it wrote.
//!
//! Against the concrete [`ObjectStream`](crate::ObjectStream) the second
//! disposes of the first: `fill` over a buffer of exactly the declared length
//! returns short **only** when the stream ended short, and `sealed` refuses that
//! case one line earlier with the same
//! [`ShortWrite`](crate::StoreError::ShortWrite) and the same two numbers. So
//! the arm's own comparison cannot fire, and deleting it left the whole workspace
//! gate green — measured, not argued.
//!
//! Leaving it there as unreachable code defended by a comment is what this
//! project calls a claim nobody can check. Deleting it is worse: it is the only
//! thing standing between the two answers if they ever stop agreeing, and they
//! agree today because of an invariant that lives in **another module**. A
//! `fill` that returned early on a partial window — the way [`std::io::Read`]
//! is allowed to, and the way a future optimisation might — would hand this arm a
//! short buffer with a clean seal, and a backend that trusted `sealed` alone
//! would upload the zero padding the buffer was allocated with and commit it
//! under the object's own name.
//!
//! So the two answers are compared, and the comparison is put behind a trait
//! narrow enough that a fake can disagree with itself. That is the fourth time
//! this codebase has used a seam for a path no real component can reach — after
//! B2's pagination, the mount's detach and the two protocol mocks — and it is
//! what makes the comparison a line a test can turn red rather than a line a
//! reader has to take on faith.

use bytes::Bytes;

use crate::checksum::ContentHash;
use crate::error::{Result, StoreError};

use super::constants::WHOLE_OBJECT_TOO_LARGE;

/// The two things a whole-object arm asks of the producer's end of the pipe.
///
/// A trait rather than [`ObjectStream`](crate::ObjectStream) directly, for the
/// reason the module documentation gives: through the concrete type the two
/// answers cannot disagree, and a check no input can reach is a check no test can
/// hold.
pub(crate) trait WholeSource {
    /// Top up `buf` to exactly its length, as
    /// [`ObjectStream::fill`](crate::ObjectStream::fill).
    fn fill(&mut self, buf: &mut [u8]) -> impl Future<Output = Result<usize>> + Send;

    /// Confirm the producer had nothing left and the object agrees with its own
    /// declaration, as [`ObjectStream::sealed`](crate::ObjectStream::sealed).
    fn sealed(&mut self) -> impl Future<Output = Result<ContentHash>> + Send;
}

impl WholeSource for super::ObjectStream {
    fn fill(&mut self, buf: &mut [u8]) -> impl Future<Output = Result<usize>> + Send {
        Self::fill(self, buf)
    }

    fn sealed(&mut self) -> impl Future<Output = Result<ContentHash>> + Send {
        Self::sealed(self)
    }
}

/// Drain exactly `size` bytes out of `source`, or refuse and commit nothing.
///
/// The permission to commit is the [`ContentHash`] that comes back: a caller
/// holding one has been told, by the producer's own end of the pipe, that the
/// object ended where it said it would with the digest it folded over what it
/// wrote — and, by the comparison below, that the buffer in its hand is that
/// whole object rather than a prefix of it followed by the zeroes it was
/// allocated with.
///
/// # Errors
/// [`StoreError::Backend`] for an object too large for this machine's address
/// space, whatever [`WholeSource::fill`] and [`WholeSource::sealed`] reported,
/// and [`StoreError::ShortWrite`] when the two answers disagree about how much
/// arrived.
///
/// The first of those has **no test**, and that is said here rather than left to
/// be discovered: `u64` to `usize` is infallible on every 64-bit target, so the
/// branch is unreachable on the machines this ships to and the only input that
/// could reach it on one of them is a length no allocator would satisfy either.
/// A test asserting it would have to run on a 32-bit target to assert anything,
/// and a `#[cfg]`-gated one that never runs here would read as coverage while
/// being none.
pub(crate) async fn drain_whole<S: WholeSource>(
    source: &mut S,
    size: u64,
) -> Result<(Bytes, ContentHash)> {
    let want =
        usize::try_from(size).map_err(|_| StoreError::Backend(WHOLE_OBJECT_TOO_LARGE.into()))?;
    let mut whole = vec![0u8; want];
    let filled = source.fill(&mut whole).await?;

    // `sealed` rather than `agreed`, for the reason that method gives: `fill`
    // stops the instant the buffer is full and has not yet seen the stream's
    // terminal message, so a producer with bytes left over is caught here rather
    // than after an upload. It runs **before** the comparison below, so that when
    // both can speak the stricter refusal is the one that fires.
    let sealed = source.sealed().await?;

    // And the arm's own comparison, which is not the same question. `sealed`
    // asks the producer whether it kept to its declaration; this asks whether
    // what reached *this buffer* is what the producer says it handed over. They
    // agree through an `ObjectStream` and they are not obliged to agree through
    // anything else — see the module documentation.
    if filled as u64 != size {
        return Err(StoreError::ShortWrite {
            expected: size,
            actual: filled as u64,
        });
    }
    Ok((Bytes::from(whole), sealed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checksum::HashAlgo;

    /// A source that answers the two questions independently, which is the whole
    /// point: an [`ObjectStream`](crate::ObjectStream) cannot.
    struct Fake {
        /// Bytes to put in the caller's buffer, however many it asked for.
        supply: Vec<u8>,
        /// What `sealed` says. `Ok` means the producer kept its promise,
        /// which is exactly the lie this fake exists to tell.
        seal: Option<StoreError>,
    }

    impl Fake {
        fn sealing_cleanly(supply: Vec<u8>) -> Self {
            Self { supply, seal: None }
        }
    }

    impl WholeSource for Fake {
        fn fill(&mut self, buf: &mut [u8]) -> impl Future<Output = Result<usize>> + Send {
            let take = self.supply.len().min(buf.len());
            buf[..take].copy_from_slice(&self.supply[..take]);
            std::future::ready(Ok(take))
        }

        fn sealed(&mut self) -> impl Future<Output = Result<ContentHash>> + Send {
            std::future::ready(match self.seal.take() {
                Some(error) => Err(error),
                None => Ok(ContentHash::blake3(&self.supply)),
            })
        }
    }

    #[tokio::test]
    async fn a_whole_object_comes_back_with_the_digest_that_permits_committing_it() {
        let data = vec![b'w'; 4096];
        let mut source = Fake::sealing_cleanly(data.clone());
        let (bytes, digest) = drain_whole(&mut source, 4096)
            .await
            .expect("a source that supplied what it promised");
        assert_eq!(bytes.as_ref(), data.as_slice());
        assert!(digest.matches(&ContentHash::blake3(&data)));
    }

    #[tokio::test]
    async fn a_source_that_seals_cleanly_over_a_short_fill_is_still_refused() {
        // **The defect this module exists to make reachable.** The seal succeeds
        // — the producer's end is satisfied — and only `filled != size` is left
        // to notice that the buffer holds 512 bytes of object and 3 584 bytes of
        // the zeroes `vec![0u8; want]` allocated. Without the comparison those
        // zeroes are uploaded and committed under the object's own name, and
        // nothing anywhere says the object is short.
        let mut source = Fake::sealing_cleanly(vec![b'i'; 512]);
        let error = drain_whole(&mut source, 4096)
            .await
            .expect_err("a buffer that is mostly padding is not the object");
        assert!(
            matches!(error, StoreError::ShortWrite { expected, actual }
                if expected == 4096 && actual == 512),
            "a short read is a write that stopped, and it must say by how much: {error:?}"
        );
    }

    #[tokio::test]
    async fn the_seal_is_asked_before_the_length_is_compared() {
        // The ordering the module documentation argues for, and the one this
        // seam exists to make testable: with both able to speak, the **seal's**
        // refusal is the one that reaches the caller. It is the stricter of the
        // two — it has seen the terminal message and this comparison has not —
        // and an edit that moved it below the check would silently downgrade
        // every one of its refusals to `ShortWrite`.
        let mut source = Fake {
            supply: vec![b'i'; 512],
            seal: Some(StoreError::ChecksumMismatch {
                expected: "the producer's digest".into(),
                actual: "what arrived".into(),
            }),
        };
        let error = drain_whole(&mut source, 4096)
            .await
            .expect_err("a source that failed its seal commits nothing");
        assert!(
            matches!(error, StoreError::ChecksumMismatch { .. }),
            "the length check answered a question the seal had already answered              better: {error:?}"
        );
    }

    #[tokio::test]
    async fn an_empty_object_is_legal_and_still_has_to_be_sealed() {
        // Zero is a length like any other: `fill` over an empty buffer touches
        // nothing, so the seal is the only thing that runs at all.
        let mut source = Fake::sealing_cleanly(Vec::new());
        let (bytes, digest) = drain_whole(&mut source, 0)
            .await
            .expect("an empty object stores as zero bytes");
        assert!(bytes.is_empty());
        assert!(digest.matches(&ContentHash::blake3(&[])));

        let mut refused = Fake {
            supply: Vec::new(),
            seal: Some(StoreError::Backend("the producer vanished".into())),
        };
        assert!(drain_whole(&mut refused, 0).await.is_err());
    }

    #[tokio::test]
    async fn the_concrete_stream_is_driven_through_the_same_function() {
        // The trait is not a parallel implementation: the real
        // `ObjectStream` reaches the same code, so an impl that drifted from
        // `ObjectStream`'s own semantics fails here rather than in production.
        let (mut writer, mut stream) = super::super::object_stream(4096, HashAlgo::Blake3);
        let producing = tokio::task::spawn_blocking(move || {
            use std::io::Write as _;
            writer.write_all(&[b'p'; 4096]).expect("the pipe takes it");
            writer.finish().expect("and the producer closes");
        });
        let (bytes, digest) = drain_whole(&mut stream, 4096)
            .await
            .expect("a producer that kept its word");
        producing.await.expect("the producer ran");
        assert_eq!(bytes.len(), 4096);
        assert!(digest.matches(&ContentHash::blake3(&[b'p'; 4096])));
    }

    #[tokio::test]
    async fn a_real_producer_that_stops_short_is_refused_by_the_seal() {
        // And the same input through the concrete type, which is the case the
        // module documentation works through: the seal gets there first, with
        // the whole object's declaration and what really arrived.
        let (mut writer, mut stream) = super::super::object_stream(4096, HashAlgo::Blake3);
        let producing = tokio::task::spawn_blocking(move || {
            use std::io::Write as _;
            writer.write_all(&[b'j'; 700]).expect("the pipe takes it");
            writer.finish().expect("and the producer closes");
        });
        let error = drain_whole(&mut stream, 4096)
            .await
            .expect_err("a short object is refused");
        producing.await.expect("the producer ran");
        assert!(
            matches!(error, StoreError::ShortWrite { expected, actual }
                if expected == 4096 && actual == 700),
            "{error:?}"
        );
    }
}
