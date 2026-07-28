//! How a test observes what a run actually logged.
//!
//! Test-only, and here rather than beside any one test because it answers a
//! question about the *logging layer*: not "did this function call `info!`" but
//! "does a run at this verbosity emit this record". Those are different claims,
//! and only the second is what `--log-level` promises. Asserting on a macro call
//! would pass while the level filter discarded every record the flag exists to
//! produce.
//!
//! The formatting layer is the same one [`super::init`] installs, so a record
//! that appears here is a record an operator would see, field renderings and all.
//!
//! # One global subscriber, and why the obvious design is wrong
//!
//! The obvious design is `tracing::subscriber::set_default` per test: a
//! thread-local dispatcher, installed for the duration of the closure. It was
//! written that way first and it **flaked** — the same test passed alone, failed
//! in the suite roughly one run in three, and when it failed the capture was
//! completely empty, warnings and all.
//!
//! `tracing` caches each callsite's interest, and the maximum enabled level, in
//! process-global state. Both are recomputed when a dispatcher is registered or
//! goes away, folded over every dispatcher alive at that instant. Tests run in
//! parallel, so a capture on one thread could have its callsites recomputed
//! against a moment when only the no-op global remained — marking them `never`
//! for everyone, including the capture already running. Serialising the captures
//! narrowed the window without closing it.
//!
//! So there is exactly **one** subscriber for the whole test binary, installed
//! once, at `TRACE`, and it never goes away. The global caches are therefore
//! computed once and are correct forever. Which records a given capture keeps is
//! decided per event, on the emitting thread, by [`ACTIVE`] — a thread-local that
//! [`Capture::of`] sets and clears. A test that is not capturing routes to a sink
//! that discards.
//!
//! A capture that can silently record nothing is the same defect as a test that
//! skips and reports `ok`, one layer in, so this is worth the extra machinery.
//! [`tests::a_capture_sees_only_its_own_thread`] is what holds it.

use std::cell::RefCell;
use std::io;
use std::sync::{Arc, Mutex, Once};

use tracing::Metadata;
use tracing_subscriber::fmt::MakeWriter;

use super::LogLevel;

thread_local! {
    /// The capture this thread is filling, and the level it asked for.
    ///
    /// Thread-local rather than global because tests run in parallel and each
    /// must see its own run and nothing else — a capture that collected another
    /// test's records would fail in ways that depend on scheduling.
    static ACTIVE: RefCell<Option<(LogLevel, Capture)>> = const { RefCell::new(None) };
}

/// Installs the one subscriber, once.
static INSTALLED: Once = Once::new();

/// An in-memory log sink, and the records written into it.
#[derive(Clone, Default)]
pub struct Capture(Arc<Mutex<Vec<u8>>>);

impl Capture {
    /// Run `body` with every record at or below `level` captured, and return
    /// what was written.
    ///
    /// The level is the *filter*, so this answers the question the flag asks:
    /// `Capture::of(LogLevel::Info, …)` sees exactly what `--log-level info`
    /// would show.
    ///
    /// `body` must do its work on this thread. Anything polled elsewhere — a
    /// `tokio::spawn`, a multi-threaded runtime — writes to whatever that thread
    /// is capturing, which is nothing.
    pub fn of<T>(level: LogLevel, body: impl FnOnce() -> T) -> (Self, T) {
        install();
        let sink = Self::default();
        ACTIVE.with(|active| *active.borrow_mut() = Some((level, sink.clone())));
        // Cleared before the value is returned, and before any panic in `body`
        // could escape with it still set — a leaked routing would send the next
        // test's records into this test's buffer.
        let outcome = Guard.hold(body);
        (sink, outcome)
    }

    /// Everything written, as text.
    #[must_use]
    pub fn text(&self) -> String {
        self.0
            .lock()
            .map(|buf| String::from_utf8_lossy(&buf).into_owned())
            .unwrap_or_default()
    }

    /// The records whose rendered form contains `needle`.
    ///
    /// One line per record: the `fmt` layer emits a record as a line, so
    /// counting matches counts records — which is what "one record per file"
    /// means and what a caller wants to assert.
    #[must_use]
    pub fn records_containing(&self, needle: &str) -> Vec<String> {
        self.text()
            .lines()
            .filter(|line| line.contains(needle))
            .map(ToString::to_string)
            .collect()
    }
}

/// Clears [`ACTIVE`] however the closure ends.
struct Guard;

impl Guard {
    fn hold<T>(self, body: impl FnOnce() -> T) -> T {
        body()
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        ACTIVE.with(|active| *active.borrow_mut() = None);
    }
}

/// Install the one subscriber for this test binary.
///
/// At `TRACE`, unconditionally: the level a capture wants is applied per event by
/// [`Router`], so the subscriber itself must never be the thing that filters — a
/// global maximum below a capture's level would discard the records before the
/// router ever saw them, which is the failure this whole arrangement exists to
/// rule out.
fn install() {
    INSTALLED.call_once(|| {
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(Router)
            .without_time()
            .with_ansi(false)
            .finish();
        // A second installer would mean two subscribers and the race this design
        // removes, so the result is deliberately not ignored silently: `Once`
        // already guarantees one call, and a failure here means something else in
        // the binary installed one first, which the captures could not then see.
        assert!(
            tracing::subscriber::set_global_default(subscriber).is_ok(),
            "a subscriber was already installed; log captures would observe nothing"
        );
    });
}

/// Sends each event to whatever the emitting thread is capturing.
struct Router;

impl<'a> MakeWriter<'a> for Router {
    type Writer = Routed;

    /// Only reached for records with no metadata to route by, which the `fmt`
    /// layer does not produce for events.
    fn make_writer(&'a self) -> Self::Writer {
        Routed(None)
    }

    fn make_writer_for(&'a self, meta: &Metadata<'_>) -> Self::Writer {
        Routed(ACTIVE.with(|active| {
            active
                .borrow()
                .as_ref()
                .filter(|(level, _)| meta.level() <= &tracing::Level::from(*level))
                .map(|(_, sink)| sink.clone())
        }))
    }
}

/// A writer aimed at one capture, or at nothing.
struct Routed(Option<Capture>);

impl io::Write for Routed {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Some(sink) = &self.0 {
            if let Ok(mut out) = sink.0.lock() {
                out.extend_from_slice(buf);
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl From<LogLevel> for tracing::Level {
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::Error => Self::ERROR,
            LogLevel::Warn => Self::WARN,
            LogLevel::Info => Self::INFO,
            LogLevel::Debug => Self::DEBUG,
            LogLevel::Trace => Self::TRACE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_capture_keeps_what_its_level_admits_and_drops_the_rest() {
        let (log, ()) = Capture::of(LogLevel::Info, || {
            tracing::warn!("a warning");
            tracing::info!("an informational record");
            tracing::debug!("detail nobody asked for");
        });
        assert!(log.text().contains("a warning"), "got: {}", log.text());
        assert!(
            log.text().contains("an informational record"),
            "got: {}",
            log.text()
        );
        assert!(
            !log.text().contains("detail nobody asked for"),
            "got: {}",
            log.text()
        );
    }

    #[test]
    fn nothing_is_captured_outside_a_capture() {
        // Otherwise every test in the binary would accumulate into the next
        // capture's buffer and the counts would depend on scheduling.
        tracing::info!("emitted with no capture active");
        let (log, ()) = Capture::of(LogLevel::Trace, || {});
        assert!(log.text().is_empty(), "got: {}", log.text());
    }

    #[test]
    fn a_capture_sees_only_its_own_thread() {
        // The property the whole design exists for. If this ever fails, a test
        // asserting "one record per file" is counting other tests' records, and
        // the number it agrees with is a coincidence.
        let (log, ()) = Capture::of(LogLevel::Trace, || {
            std::thread::spawn(|| tracing::error!("from somewhere else"))
                .join()
                .expect("the other thread finishes");
            tracing::error!("from here");
        });
        assert!(log.text().contains("from here"), "got: {}", log.text());
        assert!(
            !log.text().contains("from somewhere else"),
            "got: {}",
            log.text()
        );
    }

    #[test]
    fn a_panic_inside_a_capture_does_not_leave_it_routing() {
        // A leaked routing would send the next test's records here, which is a
        // failure that only appears under a particular ordering.
        let escaped = std::panic::catch_unwind(|| {
            let _ = Capture::of(LogLevel::Trace, || panic!("the body fails"));
        });
        assert!(escaped.is_err());
        ACTIVE.with(|active| assert!(active.borrow().is_none()));
    }
}
