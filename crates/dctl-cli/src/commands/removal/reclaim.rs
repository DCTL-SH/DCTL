//! `cleanup`: reclaiming the storage nothing refers to any more.
//!
//! The other five removals take things a person put there. This one takes the
//! debris DCTL and the provider leave behind — invisible in every listing, and
//! billed for every month.
//!
//! ## The classes, and what each one really is
//!
//! * **staging** — an object left under a temporary key by a write that never
//!   reached its commit. `PLAN.md` §6 step 3 stages an upload under a key
//!   carrying [`CLEANUP_STAGING_MARKER`] and only makes it live once the
//!   checksum matches, so this litter is a *consequence* of the durability
//!   guarantee rather than a bug in it.
//! * **orphans** — a content object no index row refers to. This is exactly what
//!   a verified write that aborted after storing the ciphertext leaves behind
//!   (`PLAN.md` §6 steps 3–6: the object is written, then the name record, then
//!   the index row that makes the file count as stored). It is also what a failed
//!   overwrite GC leaves, which `Vault::put_file` itself warns is a storage leak.
//! * **multipart** — an upload begun and never finished. The parts are stored
//!   and charged for and no listing shows them.
//! * **versions** — a superseded object still alive on a versioned bucket.
//!
//! ## Two of the four cannot be swept, and say so
//!
//! [`dctl_store::Backend`] exposes `put`, `get`, `head`, `delete` and
//! `list_page`. There is no API for in-progress multipart uploads and none for
//! object versions, on any provider, because the trait does not have one. A
//! sweep that reported "0 reclaimed" for a class it was never able to *look* at
//! would be the misreport `PLAN.md` §6 forbids — so those two classes emit an
//! explicit `unsupported` record instead, naming the capability that is missing.
//!
//! Whether that is an *error* depends on what was asked for, and the rule is one
//! sentence: **a class that could not be swept is an error only when the user
//! named it.** `dctl cleanup archive:` means "reclaim what you can" and stays
//! exit 0; `dctl cleanup archive: --class multipart` asked for one thing, got
//! none of it, and exits 6. Anything else would either cry wolf on every default
//! run or silently swallow a request.
//!
//! ## A blind spot in the staging sweep on `local:`, stated rather than hidden
//!
//! Discovery of debris can only go through [`Backend::list_page`], and
//! [`LocalFs`](dctl_store::LocalFs) **deliberately omits keys containing
//! `.tmp.`** from its listing — its walker calls them "in-flight verified-write
//! temp files" and skips them. So on a `local:` store the transfer engine's
//! staged keys (which carry `.tmp.` as an infix) are invisible to this sweep,
//! and to `dctl ls archive-store:`, and to everything else in the binary. The
//! `rcat` staging spelling, which merely *ends* with
//! [`LOCAL_STAGING_SUFFIX`], is listed and is swept.
//!
//! This layer cannot fix that and does not pretend to: it reclaims exactly what
//! the backend was willing to show it, and reports exactly what it reclaimed.
//! The fix belongs in `dctl-store` — either the walker stops filtering, or
//! `Backend` grows a way to ask for staged keys on purpose. Special-casing the
//! backend's name here would be a second, contradictory opinion about which keys
//! exist, which is worse than the gap.
//!
//! ## Why the orphan sweep proves the index is complete first
//!
//! An orphan is defined by an *absence* — no index row refers to this object —
//! and an absence is only evidence if the index is known to be complete. On a
//! machine that has just been restored from a password alone, the index is
//! **empty** and every object in the vault would qualify. Deleting them would
//! destroy the entire dataset while reporting a successful cleanup.
//!
//! So the sweep proves completeness before it trusts the absence: every stored
//! file has exactly one §5 name record on the backend ([`VAULT_NAME_KEY_PREFIX`])
//! and exactly one index row, so the two counts are equal on a healthy vault.
//! If they differ, the index does not describe this vault and the class is
//! refused with [`CLEANUP_STALE_INDEX_HINT`], which names the command that
//! repairs it. The check is cheap — one prefix listing — and it is what turns
//! "delete what the index does not mention" from a footgun into an operation.
//!
//! ## Why `--min-age` is load-bearing rather than a tuning knob
//!
//! There is a window during an overwrite in which the *new* object has been
//! written and the index still points at the *old* one. For that instant the new
//! object matches the definition of an orphan exactly, and nothing in the object
//! says otherwise. [`CLEANUP_DEFAULT_MIN_AGE`](crate::constants::CLEANUP_DEFAULT_MIN_AGE)
//! is a day, which is longer than any single verified write by orders of
//! magnitude — and lowering it towards zero re-opens that window. An object
//! whose age cannot be established at all is never swept, for the same reason:
//! unknown is not old.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::ValueEnum;
use dctl_store::{Backend, ObjectKey};
use serde::Serialize;

use crate::audit::record::Entry as AuditEntry;
use crate::audit::sink;
use crate::constants::{
    CLEANUP_STAGING_MARKER, CLEANUP_STALE_INDEX_HINT, LOCAL_STAGING_SUFFIX, REMOVAL_ENGINE_HINT,
    REMOVAL_ENGINE_MISSING, REMOVAL_KIND_ORPHAN, REMOVAL_KIND_STAGING, UNKNOWN_VALUE,
    VAULT_NAME_KEY_PREFIX, VAULT_OBJECT_KEY_PREFIX,
};
use crate::ctx::Ctx;
use crate::error::Result;
use crate::source::plain::PlainSource;
use crate::source::{Entry, Source as _};

use super::report::Report;
use super::selection::Item;
use super::target::Target;

/// A class of reclaimable debris.
///
/// Selectable individually because the four carry very different risks:
/// sweeping staging keys is nearly free, while pruning versions destroys the
/// only remaining copy of an overwritten file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
#[value(rename_all = "kebab-case")]
pub enum Class {
    /// Multipart uploads that were started and never finished.
    Multipart,
    /// Objects left under a temporary staging key by an interrupted write.
    Staging,
    /// Content objects no index record refers to.
    Orphans,
    /// Superseded object versions on a versioned bucket.
    Versions,
}

impl Class {
    /// Every class, used when `--class` was not given.
    pub const ALL: &'static [Self] = &[
        Self::Multipart,
        Self::Staging,
        Self::Orphans,
        Self::Versions,
    ];

    /// The name this class is written as, on the command line and in the JSON.
    ///
    /// Read back from clap rather than spelled a second time, so the flag value
    /// and the serialised value cannot drift apart.
    #[must_use]
    pub fn slug(self) -> String {
        self.to_possible_value().map_or_else(
            || UNKNOWN_VALUE.to_string(),
            |value| value.get_name().to_string(),
        )
    }

    /// The capability this class would need, in the user's vocabulary.
    ///
    /// [`None`] for the classes this build can sweep. Returning the sentence
    /// rather than a boolean means the refusal cannot be worded twice.
    const fn missing_capability(self) -> Option<&'static str> {
        match self {
            Self::Multipart => Some("listing a provider's in-progress multipart uploads"),
            Self::Versions => Some("listing an object's superseded versions"),
            Self::Staging | Self::Orphans => None,
        }
    }
}

/// What a sweep was asked to reclaim.
///
/// The three fields of [`super::operation::Operation::Cleanup`], carried
/// together because they are one request and always travel as one. Grouping them
/// is not cosmetic: they are decided in a single place — the command line — and a
/// signature that took them apart would let a caller pass a `min_age` from one
/// request beside the `classes` of another.
pub struct Request<'a> {
    /// Which classes of debris to sweep.
    pub classes: &'a [Class],
    /// How old debris must be before it counts as abandoned.
    pub min_age: Duration,
    /// Whether the user selected these classes explicitly; see the module
    /// documentation for why that decides the exit code and nothing else.
    pub named: bool,
}

/// Who a reclaimed object is attributed to in the chained log.
///
/// The two fields every record needs and nothing else does, so the sweep's
/// internals can carry them as one value rather than as a pair that has to stay
/// in step through four call layers.
struct Attribution<'a> {
    /// The verb the user typed — the record's `op`.
    op: &'static str,
    /// The remote the sweep ran against — the record's `remote`.
    remote: &'a str,
}

/// The age test every piece of debris is put to.
///
/// `now` and `min_age` are meaningless apart: one is a reading of the clock and
/// the other a policy, and only their difference decides anything. Sampled once
/// per sweep so that a long run cannot judge its first object against a
/// different "now" from its last.
#[derive(Clone, Copy)]
struct Aging {
    /// Unix seconds at the moment the sweep started.
    now: i64,
    /// How old debris must be before it counts as abandoned.
    min_age: Duration,
}

/// Sweep every requested class.
///
/// # Errors
/// Whatever building the backend, listing it, or writing the report reported. A
/// failure to delete one object is recorded and the sweep continues, exactly as
/// on the object side.
pub async fn sweep(
    ctx: &Ctx,
    op: &'static str,
    medium: &super::medium::Medium,
    target: &Target,
    request: &Request<'_>,
    report: &mut Report<'_>,
) -> Result<()> {
    let Request {
        classes,
        min_age,
        named,
    } = *request;
    let attribution = Attribution {
        op,
        remote: &target.remote,
    };
    let store = Store::over(medium.store(ctx)?);

    // Debris has no logical path, so a path cannot scope a sweep of a vault: the
    // keys on the backend are opaque and bear no relation to `photos/2024`. For
    // a plain store the path *is* a key prefix and scopes exactly. Saying so is
    // better than quietly sweeping more than was asked for.
    let prefix = if medium.is_vault() {
        if !target.path.is_empty() {
            ctx.out.warn(format!(
                "'{target}' names a path, but a vault's debris has no plaintext \
                 path — the whole store is swept"
            ));
        }
        String::new()
    } else {
        target.path.clone()
    };

    let Some(now) = unix_now() else {
        // Without a clock there is no age, and without an age nothing here can
        // be shown to be abandoned. Refusing is the only honest answer.
        ctx.out
            .error("the system clock is unreadable, so no debris can be shown to be abandoned");
        ctx.stats.error();
        return Ok(());
    };

    let aging = Aging { now, min_age };

    for class in classes {
        if let Some(capability) = class.missing_capability() {
            report.unsupported(
                class_name(*class),
                format!("{REMOVAL_ENGINE_MISSING} {capability}. {REMOVAL_ENGINE_HINT}"),
            )?;
            // Only an error if this is what was asked for. See the module docs.
            if named {
                ctx.stats.error();
            }
            continue;
        }

        match class {
            Class::Staging => staging(ctx, &attribution, aging, &store, &prefix, report).await?,
            Class::Orphans => {
                orphans(ctx, &attribution, aging, medium, &store, named, report).await?;
            }
            // Answered above, exhaustively, so a class added later is a compile
            // error here rather than a silent no-op.
            Class::Multipart | Class::Versions => {}
        }
    }

    Ok(())
}

/// Sweep objects whose key marks them as staged rather than committed.
async fn staging(
    ctx: &Ctx,
    attribution: &Attribution<'_>,
    aging: Aging,
    store: &Store,
    prefix: &str,
    report: &mut Report<'_>,
) -> Result<()> {
    let mut cursor = store.source.enumerate(prefix).await?;
    while let Some(entry) = cursor.next().await? {
        if !is_staged(&entry.path) {
            continue;
        }
        reclaim(
            ctx,
            attribution,
            aging,
            store,
            entry,
            REMOVAL_KIND_STAGING,
            report,
        )
        .await?;
    }
    Ok(())
}

/// Sweep content objects no index row refers to.
async fn orphans(
    ctx: &Ctx,
    attribution: &Attribution<'_>,
    aging: Aging,
    medium: &super::medium::Medium,
    store: &Store,
    named: bool,
    report: &mut Report<'_>,
) -> Result<()> {
    let Some(indexed) = medium.indexed_object_keys()? else {
        report.unsupported(
            class_name(Class::Orphans),
            "a plain object store has no index, so no object can be shown to be \
             unreferenced"
                .to_string(),
        )?;
        if named {
            ctx.stats.error();
        }
        return Ok(());
    };

    // The completeness proof. One §5 name record per stored file, one index row
    // per stored file; equal counts mean the index describes this vault, and
    // only then is "absent from the index" evidence of anything.
    let name_records = count_under(store, VAULT_NAME_KEY_PREFIX).await?;
    if name_records != indexed.len() {
        report.unsupported(
            class_name(Class::Orphans),
            format!(
                "the vault holds {name_records} name record(s) but the index has \
                 {} row(s). {CLEANUP_STALE_INDEX_HINT}",
                indexed.len()
            ),
        )?;
        if named {
            ctx.stats.error();
        }
        return Ok(());
    }

    let referenced: BTreeSet<String> = indexed.into_iter().collect();
    let mut cursor = store.source.enumerate(VAULT_OBJECT_KEY_PREFIX).await?;
    while let Some(entry) = cursor.next().await? {
        if referenced.contains(&entry.path) {
            continue;
        }
        reclaim(
            ctx,
            attribution,
            aging,
            store,
            entry,
            REMOVAL_KIND_ORPHAN,
            report,
        )
        .await?;
    }
    Ok(())
}

/// Delete one piece of debris, if it is old enough to be abandoned.
async fn reclaim(
    ctx: &Ctx,
    attribution: &Attribution<'_>,
    aging: Aging,
    store: &Store,
    entry: Entry,
    kind: &'static str,
    report: &mut Report<'_>,
) -> Result<()> {
    let Some(age) = age_of(&entry, aging.now) else {
        // Unknown is not old. A provider that reports no modification time gives
        // no basis for calling anything abandoned, and guessing here would mean
        // deleting another process's live work.
        ctx.out.info(format!(
            "'{}' has no modification time, so its age cannot be established",
            entry.path
        ));
        return Ok(());
    };
    if age < aging.min_age {
        return Ok(());
    }

    let item = Item {
        path: entry.path,
        size: entry.size,
        kind,
    };

    if ctx.is_dry_run() {
        return report.would_remove(&item);
    }

    // Straight to the backend: debris has no logical path, so there is no index
    // row and no name record to take with it. `Backend::delete` returning `Ok`
    // means the object is gone, which is what the record claims — and it was
    // listed a moment ago, so it was there to go.
    let outcome = store.delete(&item.path).await;
    match &outcome {
        Ok(()) => report.removed(&item)?,
        Err(error) => report.failed(&item, error.message())?,
    }

    // Debris is still data the operator paid to store, and a sweep is still a
    // deletion somebody may have to account for later. The record names the
    // backend key rather than a logical path because that is all debris has —
    // an object nothing refers to has no plaintext name to give.
    ctx.audit.record(
        &AuditEntry::new(attribution.op, sink::outcome(&outcome))
            .path(&item.path)
            .size(item.size.unwrap_or_default())
            .remote(attribution.remote),
    )
}

/// How many objects lie under `prefix`.
async fn count_under(store: &Store, prefix: &str) -> Result<usize> {
    let mut cursor = store.source.enumerate(prefix).await?;
    let mut total = 0usize;
    while cursor.next().await?.is_some() {
        total += 1;
    }
    Ok(total)
}

/// The object store a sweep reads and deletes in.
///
/// Two views of **one** backend handle, built from a single [`Arc`] so they can
/// never come to describe different remotes: [`PlainSource`] supplies the paged
/// enumeration `PLAN.md` §16.2 requires, and the backend supplies the `delete`
/// that the read abstraction deliberately does not have. Keeping the `Arc` here
/// rather than reaching into the source is what lets the read side stay
/// read-only for every other caller in the binary.
struct Store {
    source: PlainSource,
    backend: Arc<dyn Backend>,
}

impl Store {
    /// Both views over one handle.
    fn over(backend: Arc<dyn Backend>) -> Self {
        Self {
            source: PlainSource::new(Arc::clone(&backend)),
            backend,
        }
    }

    /// Delete one key.
    async fn delete(&self, key: &str) -> Result<()> {
        self.backend.delete(&ObjectKey::new(key)).await?;
        Ok(())
    }
}

/// Whether a backend key marks a staged, uncommitted object.
///
/// Two spellings because two writers produce them: a remote staged upload
/// carries [`CLEANUP_STAGING_MARKER`] as an infix, and a local staging file
/// carries [`LOCAL_STAGING_SUFFIX`] at the end. Both mean the same thing — the
/// rename or the commit that would have made these bytes real never happened —
/// so both are swept by one class rather than by two the user has to know about.
fn is_staged(key: &str) -> bool {
    key.contains(CLEANUP_STAGING_MARKER) || key.ends_with(LOCAL_STAGING_SUFFIX)
}

/// How long ago `entry` was last written, or [`None`] if that is not knowable.
///
/// A modification time in the future yields [`Duration::ZERO`] rather than an
/// error: clock skew between a provider and this machine is ordinary, and the
/// effect of clamping is that a skewed object is treated as brand new — the
/// conservative direction, since the alternative is sweeping live work.
fn age_of(entry: &Entry, now: i64) -> Option<Duration> {
    let modified = entry.modified_unix?;
    Some(Duration::from_secs(
        now.saturating_sub(modified).max(0).unsigned_abs(),
    ))
}

/// The current time in unix seconds, or [`None`] if the clock is unreadable.
fn unix_now() -> Option<i64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|since| i64::try_from(since.as_secs()).ok())
}

/// A class's name as a `'static` string, for a report record.
///
/// The slug is built by clap at run time, so it has to be interned to be carried
/// in a `&'static str` field. The match is exhaustive, which is what guarantees
/// the interned spelling and the flag spelling stay the same — the test below
/// pins them together.
const fn class_name(class: Class) -> &'static str {
    match class {
        Class::Multipart => "multipart",
        Class::Staging => "staging",
        Class::Orphans => "orphans",
        Class::Versions => "versions",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_flag_spelling_and_the_json_spelling_are_the_same() {
        // The drift guard: `--class staging` and `"staging"` in a report must
        // stay one name, not two that happen to match today.
        for class in Class::ALL {
            let serialised = serde_json::to_value(class).unwrap();
            assert_eq!(serialised, serde_json::Value::String(class.slug()));
            assert_eq!(class.slug(), class_name(*class));
        }
    }

    #[test]
    fn exactly_the_two_provider_classes_are_unavailable() {
        // Stated as a test rather than a comment: the day the storage trait
        // grows a multipart listing, this is what fails and points at the arm
        // to delete.
        assert!(Class::Multipart.missing_capability().is_some());
        assert!(Class::Versions.missing_capability().is_some());
        assert!(Class::Staging.missing_capability().is_none());
        assert!(Class::Orphans.missing_capability().is_none());
    }

    #[test]
    fn a_staged_key_is_recognised_in_both_spellings() {
        assert!(is_staged(&format!("o/ab12{CLEANUP_STAGING_MARKER}9182")));
        assert!(is_staged(&format!("photos/a.jpg{LOCAL_STAGING_SUFFIX}")));
        // And an ordinary object is not, however suggestive its name.
        assert!(!is_staged("o/abcdef0123456789"));
        assert!(!is_staged("notes/tmp/a.txt"));
        assert!(!is_staged("archive.tmpfile"));
    }

    #[test]
    fn age_is_measured_from_the_modification_time() {
        let entry = Entry::new("o/a", 10).with_modified(Some(1_000));
        assert_eq!(age_of(&entry, 1_060), Some(Duration::from_secs(60)));
    }

    #[test]
    fn an_object_with_no_modification_time_has_no_age() {
        // Unknown is not old. Anything else would sweep another run's live work.
        assert_eq!(age_of(&Entry::new("o/a", 10), 1_000), None);
    }

    #[test]
    fn a_future_timestamp_is_clamped_to_brand_new_rather_than_wrapping() {
        // Provider clock skew is ordinary; a wrapped age would read as ancient
        // and sweep an object written seconds ago.
        let entry = Entry::new("o/a", 10).with_modified(Some(i64::MAX));
        assert_eq!(age_of(&entry, 0), Some(Duration::ZERO));
    }

    #[test]
    fn every_class_has_a_distinct_name() {
        let names: Vec<&str> = Class::ALL.iter().map(|class| class_name(*class)).collect();
        for (index, name) in names.iter().enumerate() {
            assert!(!names[index + 1..].contains(name), "'{name}' twice");
        }
        assert_eq!(names.len(), 4);
    }
}
