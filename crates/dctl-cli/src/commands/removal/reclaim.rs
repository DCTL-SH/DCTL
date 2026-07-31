//! `cleanup`: reclaiming the storage nothing refers to any more.
//!
//! The other five removals take things a person put there. This one takes the
//! debris DCTL and the provider leave behind — invisible in every listing, and
//! billed for every month.
//!
//! ## The classes, and what each one really is
//!
//! * **staging** — an object left under a temporary key by a write that never
//!   reached its commit. `PLAN.md` §6 step 3 stages an upload under a name
//!   `dctl_store::staging` reserves and only makes it live once the checksum
//!   matches, so this litter is a *consequence* of the durability guarantee
//!   rather than a bug in it.
//! * **orphans** — a content object no index row refers to. This is exactly what
//!   a verified write that aborted after storing the ciphertext leaves behind
//!   (`PLAN.md` §6 steps 3–6: the object is written, then the name record, then
//!   the index row that makes the file count as stored). It is also what a failed
//!   overwrite GC leaves, which `Vault::put_file` itself warns is a storage leak.
//! * **multipart** — an upload begun and never finished. The parts are stored
//!   and charged for and no listing shows them.
//! * **versions** — a superseded object still alive on a versioned bucket.
//!
//! ## One of the four cannot be swept, and says so
//!
//! [`dctl_store::Backend`] has no API for object versions, on any provider,
//! because the trait does not have one. A sweep that reported "0 reclaimed" for a
//! class it was never able to *look* at would be the misreport `PLAN.md` §6
//! forbids — so that class emits an explicit `unsupported` record instead, naming
//! the capability that is missing.
//!
//! **`multipart` used to be the second, and is not.** The two calls this module
//! named as what would close it —
//! [`Backend::list_incomplete_uploads`](dctl_store::Backend::list_incomplete_uploads)
//! and [`Backend::abort_incomplete_upload`](dctl_store::Backend::abort_incomplete_upload)
//! — exist, on all five backends, with no default implementation, in the shape
//! the staging enumeration already had. `b2_list_unfinished_large_files` plus
//! `b2_cancel_large_file` answer it on B2; `ListMultipartUploads` plus
//! `AbortMultipartUpload` answer it on S3 and R2; `local:` and `sftp:` answer
//! [`IncompleteUploads::NotMultipart`](dctl_store::IncompleteUploads::NotMultipart),
//! because they write one stream to a staging file and have no parts to abandon.
//!
//! Whether that is an *error* depends on what was asked for, and the rule is one
//! sentence: **a class that could not be swept is an error only when the user
//! named it.** `dctl cleanup archive:` means "reclaim what you can" and stays
//! exit 0; `dctl cleanup archive: --class multipart` asked for one thing, got
//! none of it, and exits 6. Anything else would either cry wolf on every default
//! run or silently swallow a request.
//!
//! ## The staging sweep can see a filesystem backend's debris — CLOSED
//!
//! This section used to say the opposite, at length, and it was the only entry
//! on `HANDOVER.md`'s pre-production list that already admitted its own defect
//! in the source: *"that report is a false all-clear, and it is not fixed
//! here."* Discovery went through [`Backend::list_page`](dctl_store::Backend::list_page),
//! and the filesystem-shaped backends **deliberately omit staging files** from
//! their listings, because a staging file is a write that never committed and
//! listing one would offer a half-written upload as an object. So the sweep
//! searched a list its quarry had already been removed from. A `SIGKILL` three
//! seconds into a `copy` leaves `o/.dctl-staging.<pid>.<seq>` — 10 MiB of it on
//! `local:`, 12 MiB on `sftp:`, measured — and
//! `dctl cleanup v: --class staging --min-age 0s` reported
//! `OK removed: 0 object(s), 0 B` over both.
//!
//! The fix is the one this module named: a `Backend` method that enumerates
//! staging keys *on purpose*, separate from the object listing, so "what is
//! stored?" and "what did we abandon?" stop sharing one answer. It is
//! [`Backend::list_staging`](dctl_store::Backend::list_staging), and this layer
//! sweeps what it returns. Special-casing a backend's name *here* would still be
//! wrong, and is still not done: a second opinion about which keys exist is what
//! put a user's `report.tmp.2024.csv` in the bin, so the only predicate applied
//! here is [`dctl_store::is_staging_key`] — the same function the backends
//! select with — used as a guard on the way to `delete` and not as a filter.
//!
//! ## What the object stores answer, and why it is not zero
//!
//! b2, s3 and r2 **do not stage at all**: they upload straight to the object's
//! final key with a checksum the provider verifies, so there is no temporary key
//! for a killed process to abandon. (This module used to say they "stage under a
//! key their own listing returns". That was wrong about the mechanism while
//! being right about the outcome, and it is corrected here because the reason a
//! number is right is part of the number.) Measured, not argued: a `SIGKILL`
//! three seconds into a copy to a live B2 bucket leaves the bucket holding
//! `system/envelope.bin` and nothing else.
//!
//! They therefore answer [`StagingListing::NotStaged`], which is reported as the
//! sentence it carries rather than as `removed: 0` — a true number that reads
//! exactly like the false all-clear this work removed. What an interrupted
//! *large* upload leaves on those providers is an unfinished multipart upload,
//! which is billed, which no listing shows, and which is the `multipart` class
//! above, already refused by name.
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
//!
//! **The staging class now depends on it too, and that is new.** While the sweep
//! could not see staging files it could not delete another run's *live* one
//! either; now that it can see them, `--min-age 0s` over a store that a
//! concurrent backup is writing into will delete the file that backup is part
//! way through. Nothing is corrupted by that — the writer's `rename` fails and
//! the object is simply not committed, which is the same outcome as any other
//! interrupted write, and the next run stores it — but a run reported as failed
//! for no reason an operator can see is a bad trade for a few reclaimed bytes.
//! The default of a day is the answer, and `0s` remains available for the case
//! it was asked for: an operator standing in front of a store they know nothing
//! is writing to.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::ValueEnum;
use dctl_store::{Backend, IncompleteUpload, IncompleteUploads, ObjectKey, StagingListing};
use serde::Serialize;

use crate::audit::record::Entry as AuditEntry;
use crate::audit::sink;
use crate::constants::{
    CLEANUP_STALE_INDEX_HINT, REMOVAL_ENGINE_HINT, REMOVAL_ENGINE_MISSING, REMOVAL_KIND_MULTIPART,
    REMOVAL_KIND_ORPHAN, REMOVAL_KIND_STAGING, UNKNOWN_VALUE, VAULT_NAME_KEY_PREFIX,
    VAULT_OBJECT_KEY_PREFIX,
};
use crate::ctx::Ctx;
use crate::error::Result;
use crate::output::size;
use crate::platform::path;
use crate::source::plain::PlainSource;
use crate::source::{Entry, Source as _};

use super::report::Report;
use super::selection::Item;
use super::target::Scoped;

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
            Self::Versions => Some("listing an object's superseded versions"),
            Self::Multipart | Self::Staging | Self::Orphans => None,
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

/// Why a piece of debris was held when the provider would not say how old it is.
///
/// Spelled once because it is the reason field of a machine-readable record as
/// well as a sentence a person reads, and two spellings of one refusal is how a
/// consumer ends up matching on the wrong one.
const AGE_UNKNOWN_REASON: &str = "its age cannot be established, and unknown is not old";

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

/// What a sweep may do with one piece of debris, once its age has been read.
///
/// The whole of the decision, and the reason it is a value rather than two
/// `return`s inside a loop: the two things a sweep enumerates — staged and
/// orphaned *objects*, and unfinished multipart *uploads* — reach it down
/// different paths, and the decision used to be written out separately in each.
/// Two copies of a rule are two rules the day one is edited, and a test covering
/// one copy leaves the other deletable with the gate staying green. That is
/// exactly what had happened: deleting the "unknown is not old" arm from both
/// left `cargo test --workspace` entirely green (`HANDOVER.md` §35.3).
#[derive(Clone, Debug, PartialEq, Eq)]
enum Sweepable {
    /// Old enough that nothing living can plausibly still be using it.
    Reclaim,
    /// Left where it is, carrying the sentence that says why — which is
    /// reported rather than swallowed, because debris that was seen and left is
    /// not debris that was not there.
    Held(String),
}

impl Aging {
    /// How long ago something last written at `modified_unix` was written, or
    /// [`None`] when the provider would not say.
    ///
    /// A modification time in the future yields [`Duration::ZERO`] rather than
    /// an error: clock skew between a provider and this machine is ordinary, and
    /// the effect of clamping is that a skewed object is treated as brand new —
    /// the conservative direction, since the alternative is sweeping live work.
    fn age_of(self, modified_unix: Option<i64>) -> Option<Duration> {
        let modified = modified_unix?;
        Some(Duration::from_secs(
            self.now.saturating_sub(modified).max(0).unsigned_abs(),
        ))
    }

    /// The verdict on one piece of debris last written at `modified_unix`.
    fn verdict(self, modified_unix: Option<i64>) -> Sweepable {
        let Some(age) = self.age_of(modified_unix) else {
            // Unknown is not old. A provider that reports no modification time
            // gives no basis for calling anything abandoned, and guessing here
            // would mean deleting another process's live work. Held rather than
            // passed over: the object is real, it is being paid for, and a sweep
            // that decided not to touch it has to say which object and why.
            return Sweepable::Held(AGE_UNKNOWN_REASON.to_string());
        };
        if age < self.min_age {
            // The first sweep after any interruption lands here — the default
            // `--min-age` is a day and the debris is minutes old — so this is
            // the branch a real operator actually meets, and it used to return
            // in silence, which is what let `no reclaimable debris found` be
            // printed over a full-size staging file.
            return Sweepable::Held(format!(
                "younger than {}",
                size::duration(self.min_age.as_secs())
            ));
        }
        Sweepable::Reclaim
    }
}

/// Sweep every requested class.
///
/// # Errors
/// Whatever building the backend, listing it, or writing the report reported. A
/// failure to delete one object is recorded and the sweep continues, exactly as
/// on the object side.
/// Takes a [`Scoped`] rather than a [`Target`], because a sweep addresses inside
/// a store the remote has already named — see [`Scoped`] for what the two mean
/// and what swapping them costs.
pub async fn sweep(
    ctx: &Ctx,
    op: &'static str,
    medium: &super::medium::Medium,
    scoped: &Scoped,
    request: &Request<'_>,
    report: &mut Report<'_>,
) -> Result<()> {
    let target = scoped.inside();
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
            Class::Multipart => {
                multipart(ctx, &attribution, aging, &store, &prefix, report).await?;
            }
            Class::Orphans => {
                orphans(ctx, &attribution, aging, medium, &store, named, report).await?;
            }
            // Answered above, exhaustively, so a class added later is a compile
            // error here rather than a silent no-op.
            Class::Versions => {}
        }
    }

    Ok(())
}

/// Sweep the debris a write abandoned before its commit.
///
/// Asks the backend the second question — [`Backend::list_staging`] — rather
/// than filtering the object listing, which omits exactly these keys and is why
/// this sweep used to report a clean store over a killed upload's leftovers.
///
/// Paged, and the pager is believed only as far as it moves: a backend that
/// returned nothing and handed back the cursor it was given has nothing further
/// to say, and looping on it would hang a command whose whole job is to finish
/// and report. The same guard [`crate::source::plain`] applies to the object
/// listing, for the same reason.
async fn staging(
    ctx: &Ctx,
    attribution: &Attribution<'_>,
    aging: Aging,
    store: &Store,
    prefix: &str,
    report: &mut Report<'_>,
) -> Result<()> {
    let mut cursor: Option<String> = None;
    loop {
        let page = match store.backend.list_staging(prefix, cursor.clone()).await? {
            StagingListing::Page(page) => page,
            StagingListing::NotStaged(reason) => {
                // Not an error and not a zero. The operator asked a question
                // with a clean answer and is told the answer, because
                // `removed: 0` on its own is indistinguishable from the report
                // this whole change exists to have stopped printing.
                return report.not_staged(class_name(Class::Staging), reason);
            }
        };

        let stalled = page.items.is_empty() && page.next_cursor == cursor;
        for meta in page.items {
            let key = meta.key.as_str().to_string();
            // Whole components, never bytes. A backend matches a prefix the way
            // a provider does, so `photos` brings back `photos-backup/…` too —
            // and this command deletes what it is handed. The rule is the one
            // [`crate::source::plain`] applies to the object listing, so the two
            // classes of debris are scoped identically; a vault sweeps under an
            // empty prefix, which admits everything by definition.
            if !path::is_under(prefix, &key) {
                continue;
            }
            if !is_staged(&key) {
                // The guard, not a filter. `list_staging` promises staging keys
                // and this is the one call in the binary whose answer becomes a
                // `delete`, so a key that fails the promise is reported as the
                // backend defect it is rather than quietly deleted or quietly
                // dropped.
                ctx.out.error(format!(
                    "'{key}' was offered as abandoned debris but is not a staging key; \
                     it has been left alone"
                ));
                ctx.stats.error();
                continue;
            }
            let entry = Entry::new(&key, meta.size).with_modified(meta.modified_unix);
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

        if stalled || page.next_cursor.is_none() {
            return Ok(());
        }
        cursor = page.next_cursor;
    }
}

/// Sweep the multipart uploads a provider is still holding open.
///
/// The third question, after "what is stored?" and "what did we abandon under a
/// temporary key?". Its subject is the only class of debris that **no object
/// listing can show**: a part a provider has accepted is stored and billed and
/// belongs to no object until the finish call arrives, so `b2_list_file_names`
/// and `ListObjectsV2` both step over it. A 4 GiB upload killed at its third part
/// leaves three hundred megabytes on somebody's monthly invoice, invisible, for
/// as long as the bucket exists.
///
/// Age is load-bearing here more than anywhere else in this file. An upload four
/// seconds old is *indistinguishable* from one another process is half way
/// through — there is no lock, no owner and no name to compare — so `--min-age`
/// is the only thing standing between a sweep and cancelling a live backup. An
/// upload whose start time the provider will not give is held rather than
/// guessed at, for the same reason, and B2 and S3 both give one.
///
/// Paged, with the same stall guard the staging sweep applies: a backend that
/// returned nothing and handed back the cursor it was given has nothing further
/// to say, and looping on it would hang a command whose whole job is to finish
/// and report.
async fn multipart(
    ctx: &Ctx,
    attribution: &Attribution<'_>,
    aging: Aging,
    store: &Store,
    prefix: &str,
    report: &mut Report<'_>,
) -> Result<()> {
    let mut cursor: Option<String> = None;
    loop {
        let page = match store
            .backend
            .list_incomplete_uploads(prefix, cursor.clone())
            .await?
        {
            IncompleteUploads::Page(page) => page,
            IncompleteUploads::NotMultipart(reason) => {
                // Not an error and not a zero: the operator asked a question with
                // a clean answer and is told the answer.
                return report.not_staged(class_name(Class::Multipart), reason);
            }
        };

        let stalled = page.items.is_empty() && page.next_cursor == cursor;
        for upload in page.items {
            // Whole components, never bytes — the same rule the object listing and
            // the staging sweep are scoped by. A provider matches a prefix the way
            // a provider does, so `photos` brings back `photos-backup/…` too.
            if !path::is_under(prefix, upload.key.as_str()) {
                continue;
            }
            reclaim_upload(ctx, attribution, aging, store, &upload, report).await?;
        }

        if stalled || page.next_cursor.is_none() {
            return Ok(());
        }
        cursor = page.next_cursor;
    }
}

/// Cancel one open upload, if it is old enough to be abandoned.
///
/// The sibling of [`reclaim`] for the class whose removal is not a `delete`. Two
/// things differ and both are honest rather than convenient:
///
/// * **The size is unknown.** Neither provider reports how many bytes an
///   unfinished upload is holding — B2's `b2_list_unfinished_large_files` and
///   S3's `ListMultipartUploads` both name the upload and not its parts, and
///   asking would be one further billed request per upload (`ListParts`). So the
///   report carries no size and the reclaimed-bytes total does not move. That is
///   an understatement of what a sweep freed, which is the right direction to be
///   wrong in: an invented figure would be a number an operator could put in a
///   cost report.
/// * **The record names the key.** An upload has a destination key and an opaque
///   provider handle; the handle means nothing to anybody reading an audit trail
///   a year later, and the key is what the object *would* have been.
async fn reclaim_upload(
    ctx: &Ctx,
    attribution: &Attribution<'_>,
    aging: Aging,
    store: &Store,
    upload: &IncompleteUpload,
    report: &mut Report<'_>,
) -> Result<()> {
    let item = Item {
        path: upload.key.as_str().to_string(),
        // See the doc comment: no provider reports it, and inventing one would put
        // a fabricated figure in a report somebody bills against.
        size: None,
        kind: REMOVAL_KIND_MULTIPART,
    };

    if let Sweepable::Held(reason) = aging.verdict(upload.started_unix) {
        return report.held(&item, reason);
    }

    if ctx.is_dry_run() {
        return report.would_remove(&item);
    }

    let outcome = store.abort(upload).await;
    match &outcome {
        Ok(()) => report.removed(&item)?,
        Err(error) => report.failed(&item, error.message())?,
    }

    ctx.audit.record(
        &AuditEntry::new(attribution.op, sink::outcome(&outcome))
            .path(&item.path)
            .objects(1)
            .remote(attribution.remote),
    )
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
    let verdict = aging.verdict(entry.modified_unix);

    let item = Item {
        path: entry.path,
        size: entry.size,
        kind,
    };

    if let Sweepable::Held(reason) = verdict {
        return report.held(&item, reason);
    }

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
            .objects(1)
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
/// enumeration `PLAN.md` §16.2 requires for the orphan class, and the backend
/// supplies both the `delete` that the read abstraction deliberately does not
/// have and the staging enumeration it deliberately does not offer. Keeping the
/// `Arc` here rather than reaching into the source is what lets the read side
/// stay read-only for every other caller in the binary.
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

    /// Cancel one open upload, releasing the parts it holds.
    async fn abort(&self, upload: &IncompleteUpload) -> Result<()> {
        self.backend.abort_incomplete_upload(upload).await?;
        Ok(())
    }
}

/// Whether a backend key marks a staged, uncommitted object.
///
/// One line, delegating to [`dctl_store::is_staging_key`], which is the one
/// place in the workspace that decides what a staging file is called. This
/// function used to hold a second opinion — `key.contains(".tmp.")` — and a
/// second opinion about which keys are DCTL's own is precisely how a user's
/// `report.tmp.2024.csv` came to be swept up as debris by one half of the tool
/// and hidden from listings by the other.
///
/// It survives the move of discovery into the backend because it is no longer a
/// *filter* but a *guard*: the backend selects, and this is the last thing that
/// runs before a `delete`. Asking the same function twice is not a second
/// opinion; it is the one opinion, checked where the irreversible thing happens.
fn is_staged(key: &str) -> bool {
    dctl_store::is_staging_key(key)
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
    fn exactly_one_provider_class_is_unavailable() {
        // Stated as a test rather than a comment. It used to name two, and the
        // day the storage trait grew a multipart listing this is what failed and
        // pointed at the arm to delete — which is what it is for.
        assert!(Class::Versions.missing_capability().is_some());
        assert!(
            Class::Multipart.missing_capability().is_none(),
            "the multipart class is enumerable now: `Backend::list_incomplete_uploads`"
        );
        assert!(Class::Staging.missing_capability().is_none());
        assert!(Class::Orphans.missing_capability().is_none());
    }

    #[test]
    fn a_staged_key_is_recognised_in_both_spellings() {
        assert!(is_staged(&format!(
            "o/{}",
            dctl_store::staging::staging_name()
        )));
        assert!(is_staged(&dctl_store::staging::staging_name()));
        // And the defect this class used to carry in the other direction: a
        // user's file must never be swept as debris because its name happens to
        // read like one. `dctl cleanup` deletes what it matches.
        for real in [
            "report.tmp.2024.csv",
            "db.tmp.2024-07-27.sql",
            "photos/~$notes.tmp.docx",
            "photo.jpg.tmp.4711.0",
        ] {
            assert!(!is_staged(real), "{real} would be deleted as debris");
        }
        // And an ordinary object is not, however suggestive its name.
        assert!(!is_staged("o/abcdef0123456789"));
        assert!(!is_staged("notes/tmp/a.txt"));
        assert!(!is_staged("archive.tmpfile"));
    }

    #[test]
    fn the_guard_before_a_delete_is_the_backends_own_rule_and_not_a_second_one() {
        // Two rules is how a key ends up hidden by one half of the tool and
        // deleted by the other. Asserted directly against the storage crate's
        // function so a divergence is a failure here rather than a support call.
        for key in [
            "o/.dctl-staging.4711.0",
            ".dctl-staging.1.0",
            "report.tmp.2024.csv",
            "o/8f14e45fceea167a5a36dedd4bea2543",
            "system/envelope.bin",
        ] {
            assert_eq!(is_staged(key), dctl_store::is_staging_key(key), "{key}");
        }
    }

    /// A sweep started at `now`, refusing to touch anything younger than a day.
    const fn aging(now: i64) -> Aging {
        Aging {
            now,
            min_age: Duration::from_secs(24 * 60 * 60),
        }
    }

    #[test]
    fn age_is_measured_from_the_modification_time() {
        assert_eq!(
            aging(1_060).age_of(Some(1_000)),
            Some(Duration::from_secs(60))
        );
    }

    #[test]
    fn an_object_with_no_modification_time_has_no_age() {
        // Unknown is not old. Anything else would sweep another run's live work.
        assert_eq!(aging(1_000).age_of(None), None);
    }

    #[test]
    fn a_future_timestamp_is_clamped_to_brand_new_rather_than_wrapping() {
        // Provider clock skew is ordinary; a wrapped age would read as ancient
        // and sweep an object written seconds ago.
        assert_eq!(aging(0).age_of(Some(i64::MAX)), Some(Duration::ZERO));
    }

    #[test]
    fn debris_whose_age_the_provider_will_not_state_is_held_and_the_reason_says_so() {
        // **The arm nothing in the workspace could turn red.** Both call sites
        // used to spell it out for themselves, and deleting it from both — so
        // that a sweep silently passed over debris it could not age — left
        // `cargo test --workspace --no-fail-fast` entirely green.
        //
        // What deleting it costs is not a missing line of output. `report.held`
        // is what stops `note_empty` printing `no reclaimable debris found`, so
        // a sweep that passed over an unageable object in silence reports a
        // clean store over debris it had just looked at and declined to touch —
        // the false all-clear this family exists not to print.
        assert_eq!(
            aging(1_000).verdict(None),
            Sweepable::Held(AGE_UNKNOWN_REASON.to_string()),
            "unknown is not old, and it is not nothing either"
        );
    }

    #[test]
    fn debris_younger_than_the_minimum_is_held_and_the_reason_names_the_minimum() {
        // The branch a real operator meets: the first sweep after an interrupted
        // transfer, minutes after it. The reason has to carry the number,
        // because the operator's next move is to decide whether to lower it.
        let verdict = aging(1_000).verdict(Some(940));
        let Sweepable::Held(reason) = verdict else {
            panic!("an hour-old file must not be swept under a day's minimum");
        };
        assert!(reason.contains("younger than"), "{reason}");
        assert!(
            reason.contains("1d"),
            "the minimum has to be in it: {reason}"
        );
    }

    #[test]
    fn debris_older_than_the_minimum_is_what_a_sweep_is_for() {
        // The control that makes the two above mean something: with the same
        // `Aging`, something genuinely old is reclaimable — so a `verdict` that
        // held everything would fail here rather than read as caution.
        assert_eq!(aging(1_000_000).verdict(Some(1_000)), Sweepable::Reclaim);
        // And exactly at the boundary, which is the one an operator setting
        // `--min-age` to match their transfer timeout is relying on.
        let day = 24 * 60 * 60;
        assert_eq!(aging(day).verdict(Some(0)), Sweepable::Reclaim);
        assert!(matches!(
            aging(day - 1).verdict(Some(0)),
            Sweepable::Held(_)
        ));
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
