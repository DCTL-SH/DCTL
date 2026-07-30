//! How much is actually there — measured, not asked for.
//!
//! rclone's `about` asks the provider three questions: how much is stored, how
//! much the account is allowed, and how much is left. DCTL can answer the first
//! and not the other two, and the split is not an oversight to be smoothed over:
//!
//! * **Stored** is knowable, because DCTL can enumerate the remote itself. That
//!   is what this module does — walk [`crate::source`] and count. For a sealed
//!   vault the walk is the local encrypted index, so it is fast and exact and
//!   the bytes are *plaintext* lengths; for a plain store it is the provider's
//!   own listing, so the bytes are the objects as stored.
//! * **Allowed** and **left** are not knowable. `dctl_store::Backend` has `put`,
//!   `get`, `head`, `list_page` — and no usage or quota call on any provider, as
//!   the `usage_reporting` and `quota_reporting` rows of the capability table
//!   already say. There is no request to make. A local filesystem *does* know
//!   its own free space, but reaching it needs a `statvfs` syscall, the standard
//!   library exposes no safe equivalent, and this crate is
//!   `#![forbid(unsafe_code)]` — so it is unreachable from here by a rule the
//!   crate applies to itself. Both facts are reported as facts
//!   ([`ABOUT_LIMITS_NOTE`]) rather than as blanks, because a zero in a capacity
//!   report gets believed and then gets used to decide whether a backup fits.
//!
//! ## What the count is a count of
//!
//! Everything the addressed remote can enumerate, from its root — not what the
//! provider is billing for. A bucket may hold objects DCTL did not write, and a
//! vault's plaintext total is smaller than the ciphertext it costs to store. The
//! same vault measured through its store remote (`dctl about archive-store:`)
//! gives the sealed figure, which is what makes the two reconcilable rather than
//! merely different. [`Sizes`] travels with the number so a reader never has to
//! infer which of the two they are holding.
//!
//! ## Cost
//!
//! One listing pass, and memory for two `u64`s however large the remote is —
//! the cursor is pulled one entry at a time (`PLAN.md` §16.2). On a vault that
//! is a local index scan; on a bucket it is a real paged listing, which is the
//! honest price of an exact answer and is why the notice says the figure was
//! measured.

use crate::ctx::Ctx;
use crate::error::Result;
use crate::remote::RemoteSpec;
use crate::source::{self, Sizes};

/// What one remote is holding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Usage {
    /// Objects enumerated under the remote's root.
    pub objects: u64,
    /// Their total size, on the basis named by `sizes` — or [`None`] when any
    /// object carried no recorded size.
    ///
    /// A vault index rebuilt from object headers holds no sizes at all (see
    /// [`crate::source::Entry::size`]), and this figure is read to decide
    /// whether a backup fits. The module note above says a zero in a capacity
    /// report gets believed and then gets acted on; that is exactly what a
    /// rebuilt vault produced here, so the absence is carried rather than
    /// summed away.
    pub bytes: Option<u64>,
    /// Total of the objects that did carry a recorded size — the honest lower
    /// bound, always a number.
    pub measured_bytes: u64,
    /// How many enumerated objects carried no recorded size.
    pub unmeasured: u64,
    /// Which basis that was: plaintext lengths, or objects as stored.
    pub sizes: Sizes,
}

/// Measure `spec` by enumerating it.
///
/// ## The path is part of the question
///
/// The prefix comes from the spec, not from a hard-coded root. It used to be
/// `enumerate("")` — the whole remote — while the report's header row echoed back
/// the path the operator had typed:
///
/// ```text
/// $ dctl size  archive:2024      Total objects: 1     2 B
/// $ dctl about archive:2024      remote  archive:2024
///                                objects 3
///                                bytes   6 B          <- the whole vault
/// ```
///
/// A capacity check on `b2:bucket/2024` reported the whole bucket's forty
/// terabytes under the label `2024`, and the module note above says exactly what
/// happens next: a figure in a capacity report gets believed and then gets used
/// to decide whether a backup fits. It applies to a wrong non-zero figure as
/// surely as to a wrong zero.
///
/// # Errors
/// [`ExitCode::VaultLocked`](crate::exit::ExitCode::VaultLocked) when a sealed
/// remote will not unlock, and whatever the index or the provider reported while
/// listing. A failure is never reported as a zero: "the backup is empty" is a
/// conclusion people act on.
pub async fn measure(ctx: &Ctx, spec: &RemoteSpec) -> Result<Usage> {
    // Before anything is enumerated. The doc comment above promises a failure is
    // never reported as a zero, and an unmounted volume was the case where it
    // was: the walk treats `ENOENT` on the root as the end of the walk, so
    // `dctl about backups:` answered `objects 0 / bytes 0 B` and exited 0 for a
    // volume nobody had mounted. That is the exact figure this module's own note
    // says gets believed and then gets used to decide whether a backup fits.
    readable_tree(ctx, spec)?;
    let opened = source::open(ctx, spec).await?;
    let mut entries = opened.enumerate().await?;

    let mut usage = Usage {
        objects: 0,
        // A known zero: an empty remote holds nothing. Only an object with no
        // recorded size may turn this into `None`.
        bytes: Some(0),
        measured_bytes: 0,
        unmeasured: 0,
        // Taken from the source rather than decided here: this command must not
        // become a second place that works out what a remote is.
        sizes: opened.source().sizes(),
    };

    while let Some(entry) = entries.next().await? {
        usage.objects = usage.objects.saturating_add(1);
        // Saturating rather than wrapping: a remote whose total overflows u64 is
        // not something DCTL will meet, and u64::MAX is at least visibly wrong
        // where a wrapped value would look plausible.
        match entry.size {
            Some(size) => {
                usage.measured_bytes = usage.measured_bytes.saturating_add(size);
                usage.bytes = usage.bytes.map(|total| total.saturating_add(size));
            }
            None => {
                usage.unmeasured = usage.unmeasured.saturating_add(1);
                usage.bytes = None;
            }
        }
    }

    Ok(usage)
}

/// Refuse a spec whose filesystem root is not there.
///
/// One implementation, on [`Place`], shared with the listing family and the
/// removal family — see [`Place::require_readable_tree`] for the account. A
/// remote that will not classify is left to [`crate::source::open`], which gives
/// a better diagnosis of the same typo.
fn readable_tree(ctx: &Ctx, spec: &RemoteSpec) -> Result<()> {
    match spec {
        RemoteSpec::Local(path) => crate::remote::Place::Filesystem {
            root: path.clone(),
            path: String::new(),
        }
        .require_readable_tree(),
        RemoteSpec::Named { .. } => match crate::remote::Place::of(ctx, spec) {
            Ok(place) => place.require_readable_tree(),
            Err(_) => Ok(()),
        },
    }
}

// `prefix_of` used to live here: a spec's path component, or the empty string
// for a bare local path. It is gone rather than kept, because it was one of nine
// copies of a rule that was **wrong on the provider shorthands** — `b2:DCTL001`
// carries the bucket in that path, so `dctl about b2:DCTL001` measured a subtree
// that could not exist and reported `objects 0 / bytes 0 B`. This module's own
// documentation says a failure is never reported as a zero; that was one.
// `crate::source::open` now returns the scope beside the source, from the
// resolver that split the bucket off — see `crate::source::Opened`.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::GlobalArgs;
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn ctx(args: &[&str]) -> Ctx {
        let argv = std::iter::once("dctl")
            .chain(args.iter().copied())
            .chain(std::iter::once("--quiet"));
        Ctx::new(Harness::parse_from(argv).globals)
    }

    #[tokio::test]
    async fn a_local_directory_is_counted_exactly_and_labelled_as_stored() {
        let root = tempfile::tempdir().expect("a temporary directory");
        std::fs::write(root.path().join("a.bin"), vec![7u8; 4096]).expect("a fixture file");
        std::fs::create_dir(root.path().join("sub")).expect("a subdirectory");
        std::fs::write(root.path().join("sub/b.bin"), b"ten bytes!").expect("a fixture file");

        let usage = measure(&ctx(&[]), &RemoteSpec::Local(root.path().to_path_buf()))
            .await
            .expect("a directory can be measured");

        assert_eq!(usage.objects, 2);
        assert_eq!(usage.bytes, Some(4096 + 10));
        // A plain store's numbers are the provider's own, so there is nothing to
        // reconcile and the label says so.
        assert_eq!(usage.sizes, Sizes::Stored);
    }

    #[tokio::test]
    async fn a_path_narrows_the_measurement_to_the_path() {
        // The defect: `enumerate("")` measured the whole remote while the report
        // printed back the path the operator typed. A capacity check on
        // `b2:bucket/2024` answered with the whole bucket's forty terabytes,
        // labelled `2024`, and a figure in a capacity report gets acted on.
        let dir = tempfile::tempdir().expect("a temporary directory");
        // The remote's root is a subdirectory, so the fixture's own config file
        // does not become a third object inside the thing being measured.
        let root = dir.path().join("root");
        std::fs::create_dir_all(root.join("2024")).expect("a subdirectory");
        std::fs::write(root.join("2024/a.bin"), b"12").expect("a fixture file");
        std::fs::write(root.join("elsewhere.bin"), vec![0u8; 4096]).expect("a fixture file");

        let config = dir.path().join("config.toml");
        std::fs::write(
            &config,
            format!(
                "[remotes.store]\ntype = \"local\"\npath = {:?}\n",
                root.to_string_lossy()
            ),
        )
        .expect("a fixture configuration");
        let context = ctx(&["--config", &config.to_string_lossy()]);

        let scoped = measure(
            &context,
            &RemoteSpec::Named {
                remote: "store".into(),
                path: "2024".into(),
            },
        )
        .await
        .expect("a scoped remote can be measured");
        assert_eq!(scoped.objects, 1, "only what is under the path");
        assert_eq!(scoped.bytes, Some(2));

        // And the whole remote still measures the whole remote.
        let whole = measure(
            &context,
            &RemoteSpec::Named {
                remote: "store".into(),
                path: String::new(),
            },
        )
        .await
        .expect("the whole remote can be measured");
        assert_eq!(whole.objects, 2);
        assert_eq!(whole.bytes, Some(4098));
    }

    #[tokio::test]
    async fn an_empty_remote_reports_zero_rather_than_failing() {
        // "Zero objects" is an answer; an error here would be wrong.
        let root = tempfile::tempdir().expect("a temporary directory");
        let usage = measure(&ctx(&[]), &RemoteSpec::Local(root.path().to_path_buf()))
            .await
            .expect("an empty directory can be measured");
        assert_eq!(usage.objects, 0);
        assert_eq!(usage.bytes, Some(0));
    }

    #[tokio::test]
    async fn an_unreachable_remote_is_an_error_and_never_a_zero() {
        // A reported zero would be indistinguishable from an empty remote, and
        // an operator would conclude their data is gone.
        let error = measure(
            &ctx(&["--no-ask-password"]),
            &RemoteSpec::Named {
                remote: "nosuchremote".into(),
                path: String::new(),
            },
        )
        .await
        .expect_err("an unconfigured remote cannot be measured");
        assert_ne!(error.code(), crate::exit::ExitCode::Success);
    }
}
