//! Where an HTTP request tells the watchdog it is still moving.
//!
//! # Why the body is framed at all
//!
//! rclone arms its deadline on the socket and re-arms it inside `Read` and
//! `Write`, so a transfer's progress is observed at the last possible moment.
//! That seam does not exist here: `reqwest` builds its own connector and the
//! connection type it hands to hyper — `reqwest::connect::Conn` — is
//! `pub(crate)` inside a private module, so `ClientBuilder::connector_layer`
//! can wrap the *act of connecting* and cannot wrap the connection.
//!
//! The next seam down that DCTL does own is the request body. hyper asks for a
//! frame only while its write buffer has room (`can_buffer`,
//! `hyper/src/proto/h1/io.rs:152`), and the buffer only has room once the socket
//! has taken what was queued before it. So **hyper asking for another frame is a
//! statement about the connection**, made one buffer upstream of the wire. That
//! is what [`ReportingBody`] reports, and the imprecision is bounded by that
//! buffer — hundreds of kilobytes, against a deadline measured in minutes.
//!
//! It is stated this precisely because the alternative was available and is
//! wrong: `reqwest`'s own `ClientBuilder::read_timeout` is armed once when the
//! request is dispatched and is never re-armed until the response *headers*
//! arrive (`reqwest-0.12.28/src/async_impl/client.rs:2637`, polled at `:3053`).
//! For a `GET` that is an idle timeout. For a `PUT` carrying a 100 MiB part it
//! is a deadline on the whole upload, so `--timeout 300` would fail every part
//! that took longer than five minutes to send **while it was succeeding** — the
//! exact failure an idle timeout exists not to have.
//!
//! # And the length still travels
//!
//! A framed body would ordinarily become `Transfer-Encoding: chunked`, which
//! neither provider accepts: B2's `b2_upload_file` requires `Content-Length`,
//! and S3 signs a payload whose length is part of the canonical request.
//! [`ReportingBody::size_hint`] therefore reports the exact number of bytes
//! remaining, which hyper turns back into a `Content-Length` header exactly as
//! it does for a whole-buffer body. `crate::deadline` has a test for that and so
//! do both mock providers, because it is the one property of this module whose
//! failure would look like a provider problem rather than a DCTL one.

use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use http_body::{Body as HttpBody, Frame, SizeHint};

use super::activity::Activity;
use super::constants::UPLOAD_FRAME_LEN;
use super::watch::{Expired, IdleWatch};

/// A response, and the watch the request that produced it was made under.
///
/// The two travel together because one HTTP exchange is **one** deadline. A
/// request whose headers arrived promptly and whose body then stopped arriving
/// is precisely the stall `--timeout` exists for, and a watch that ended when
/// `send` returned would never see it. Reading the body under a second, fresh
/// watch would be worse than either: every response touched would hand a stalled
/// transfer a whole new deadline, and a download that delivered one chunk per
/// `--timeout` would run forever while never once being late.
pub struct Answered {
    /// The clock the request has been measured against so far, still running.
    pub watch: IdleWatch,
    /// What the provider sent back, headers read and body not yet touched.
    pub response: reqwest::Response,
}

impl Answered {
    /// The status the provider answered with.
    #[must_use]
    pub fn status(&self) -> reqwest::StatusCode {
        self.response.status()
    }

    /// The response headers.
    #[must_use]
    pub fn headers(&self) -> &reqwest::header::HeaderMap {
        self.response.headers()
    }

    /// The whole body, read chunk by chunk under this exchange's deadline.
    ///
    /// # Errors
    ///
    /// The outer [`Expired`] is "it stopped arriving"; the inner
    /// `reqwest::Error` is "it arrived wrongly". They are kept apart rather than
    /// merged because the caller's answer to them differs — a stall is the
    /// operator's `--timeout` and a decode failure is the provider's — and
    /// because a single flattened error would have to be told apart later by
    /// reading its words, which is what [`crate::retry::observed`] exists to
    /// avoid.
    pub async fn bytes(self) -> Result<reqwest::Result<Bytes>, Expired> {
        let Self { watch, response } = self;
        watch.collect(response).await
    }

    /// The whole body as text, read under this exchange's deadline.
    ///
    /// Decoded as UTF-8 lossily, which is what both providers' XML is and what
    /// `reqwest::Response::text` would have produced for it.
    pub async fn text(self) -> Result<reqwest::Result<String>, Expired> {
        Ok(self
            .bytes()
            .await?
            .map(|body| String::from_utf8_lossy(&body).into_owned()))
    }

    /// The response and its watch, separately, for a body that is streamed
    /// rather than collected.
    ///
    /// The watch travels with it because a download to a file is exactly the
    /// case where the body outlives the headers by hours — see
    /// `crate::streaming::stream_to_file`, which touches it per chunk.
    #[must_use]
    pub fn into_parts(self) -> (IdleWatch, reqwest::Response) {
        (self.watch, self.response)
    }
}

/// A request body that reports progress as the connection takes it.
///
/// Holds the payload it was given and hands it out in [`UPLOAD_FRAME_LEN`]
/// slices. `Bytes::split_to` is a view rather than a copy, so a 100 MiB part
/// framed this way is still one 100 MiB allocation and the memory contract in
/// `crate::b2::constants` is untouched.
pub(crate) struct ReportingBody {
    /// What has not yet been handed to hyper.
    remaining: Bytes,
    /// How much to hand over at a time.
    frame_len: usize,
    /// The clock every frame touches.
    activity: Arc<Activity>,
}

impl HttpBody for ReportingBody {
    type Data = Bytes;
    /// Nothing here can fail: the payload is already in memory and framing it is
    /// arithmetic. Saying so in the type means no call site has to invent a
    /// behaviour for an error that cannot happen.
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        // Safe without projection because every field is `Unpin`; `get_mut`
        // demands exactly that and the compiler checks it.
        let this = self.get_mut();
        if this.remaining.is_empty() {
            return Poll::Ready(None);
        }
        let take = this.frame_len.min(this.remaining.len());
        let frame = this.remaining.split_to(take);
        // After the split, not before: the touch means "the connection took
        // this", and hyper only asked because it had somewhere to put it.
        this.activity.touch();
        Poll::Ready(Some(Ok(Frame::data(frame))))
    }

    fn is_end_stream(&self) -> bool {
        self.remaining.is_empty()
    }

    /// The exact number of bytes still to come.
    ///
    /// Exact rather than a hint, because it is what stops this body from being
    /// sent with `Transfer-Encoding: chunked` — see the module documentation.
    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.remaining.len() as u64)
    }
}

impl IdleWatch {
    /// `data` as a request body that keeps this watch's clock fed.
    ///
    /// The one way a request body should be built in this crate. A plain
    /// `.body(bytes)` is not wrong so much as *silent*: it moves exactly the
    /// same bytes and tells the watchdog nothing, so the deadline degenerates
    /// into a stopwatch on the whole upload without anything indicating it.
    #[must_use]
    pub fn body(&self, data: Bytes) -> reqwest::Body {
        reqwest::Body::wrap(ReportingBody {
            remaining: data,
            frame_len: UPLOAD_FRAME_LEN,
            activity: self.activity(),
        })
    }

    /// Read a whole response body under this watch, one network chunk at a time.
    ///
    /// Replaces `reqwest::Response::bytes`, which buffers the whole body inside
    /// one future this layer cannot see into: a body that stopped arriving
    /// halfway would look identical to one that was still arriving, and the
    /// deadline would be measured from the request rather than from the last
    /// chunk.
    ///
    /// # Errors
    ///
    /// [`Expired`] when the body stopped arriving. The inner result is
    /// `reqwest`'s own, unclassified, because the caller knows which backend it
    /// is talking to and this does not.
    pub async fn collect(
        &self,
        mut resp: reqwest::Response,
    ) -> Result<reqwest::Result<Bytes>, Expired> {
        self.guard(async move {
            let mut body = BytesMut::new();
            loop {
                match resp.chunk().await {
                    Ok(Some(chunk)) => {
                        self.touch();
                        body.extend_from_slice(&chunk);
                    }
                    Ok(None) => return Ok(body.freeze()),
                    Err(e) => return Err(e),
                }
            }
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Drain a body the way hyper does, collecting what it produced.
    async fn drain(mut body: ReportingBody) -> Vec<Bytes> {
        let mut frames = Vec::new();
        std::future::poll_fn(|cx| {
            loop {
                match Pin::new(&mut body).poll_frame(cx) {
                    Poll::Ready(Some(Ok(frame))) => {
                        if let Ok(data) = frame.into_data() {
                            frames.push(data);
                        }
                    }
                    Poll::Ready(Some(Err(_))) | Poll::Ready(None) => return Poll::Ready(()),
                    Poll::Pending => return Poll::Pending,
                }
            }
        })
        .await;
        frames
    }

    fn body_of(data: Bytes, activity: Arc<Activity>) -> ReportingBody {
        ReportingBody {
            remaining: data,
            frame_len: UPLOAD_FRAME_LEN,
            activity,
        }
    }

    #[tokio::test]
    async fn the_body_delivers_every_byte_it_was_given_in_order() {
        // Framing is invisible to the provider or it is a corruption bug, not a
        // timeout feature.
        let payload: Bytes = (0..UPLOAD_FRAME_LEN * 3 + 17)
            .map(|i| (i % 251) as u8)
            .collect::<Vec<u8>>()
            .into();
        let frames = drain(body_of(payload.clone(), Activity::started())).await;
        assert!(
            frames.len() > 1,
            "a body larger than a frame must be framed"
        );
        let rejoined: Vec<u8> = frames.iter().flat_map(|f| f.iter().copied()).collect();
        assert_eq!(rejoined, payload.to_vec());
    }

    #[tokio::test]
    async fn the_declared_length_is_exact_so_the_request_is_not_chunked() {
        // The property that keeps B2's uploader and S3's signature working. An
        // inexact hint here becomes `Transfer-Encoding: chunked` on the wire and
        // a provider error nobody would trace back to this file.
        let payload: Bytes = vec![0u8; UPLOAD_FRAME_LEN * 2 + 5].into();
        let body = body_of(payload.clone(), Activity::started());
        assert_eq!(body.size_hint().exact(), Some(payload.len() as u64));
    }

    #[tokio::test]
    async fn an_empty_body_ends_immediately_and_declares_zero() {
        let body = body_of(Bytes::new(), Activity::started());
        assert!(body.is_end_stream());
        assert_eq!(body.size_hint().exact(), Some(0));
        assert!(drain(body).await.is_empty());
    }

    #[tokio::test]
    async fn every_frame_taken_resets_the_deadline() {
        // The mechanism the whole module exists for, asserted on the clock
        // itself rather than inferred from a transfer that happened to succeed.
        let activity = Activity::started();
        let payload: Bytes = vec![0u8; UPLOAD_FRAME_LEN * 4].into();
        let mut body = body_of(payload, Arc::clone(&activity));

        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(activity.quiet_for() >= Duration::from_millis(25));

        std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx))
            .await
            .expect("a body with four frames left yields one")
            .expect("framing is infallible");

        assert!(
            activity.quiet_for() < Duration::from_millis(25),
            "taking a frame must be progress"
        );
    }

    #[tokio::test]
    async fn a_body_nobody_reads_lets_the_watch_expire() {
        // The complement, and the reason the touch is inside `poll_frame` rather
        // than at construction: a body that was built and never taken from is a
        // stalled upload, and must read as one.
        let watch = IdleWatch::new(
            Some(Duration::from_millis(150)),
            crate::deadline::RunDeadline::unbounded(),
        );
        let _body = watch.body(vec![0u8; UPLOAD_FRAME_LEN * 4].into());
        let out = watch.guard(std::future::pending::<()>()).await;
        assert!(out.is_err(), "an untouched body is not progress");
    }
}
