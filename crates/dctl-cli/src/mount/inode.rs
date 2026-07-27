//! The mapping between kernel inode numbers and vault paths.
//!
//! A vault has no inodes. It stores one record per file, keyed by a logical path,
//! and the kernel addresses everything by a 64-bit number — so the mount has to
//! invent the numbers and remember which path each one stands for. That table is
//! this module, and it is the only thing in the mount that must never be wrong:
//! an inode number handed to the kernel and then reused for a different path
//! makes `cat a.txt` return the contents of `b.txt`, with no error anywhere.
//!
//! ## The protocol this implements
//!
//! FUSE reference-counts inodes and tells the filesystem when it is done with
//! one. Every `lookup` reply increments the kernel's count for that inode; a
//! later `forget(ino, n)` says it has dropped `n` of them. When the count reaches
//! zero the kernel holds no reference and the number may be recycled.
//!
//! The mount honours that exactly: **a record with a live reference is never
//! evicted**, whatever the cache bound says. What [`MOUNT_INODE_CACHE_MAX`]
//! bounds is the residue — records created by a `readdir` (which does *not* take
//! a reference; the kernel looks a name up before it uses it) and records the
//! kernel has since released. Those are kept on the chance they come back,
//! because handing out the same number for the same path spares the kernel an
//! invalidation, and they are dropped least-recently-used once there are too
//! many. Dropping one is always safe: by construction nothing on the other side
//! remembers it.
//!
//! Without that bound a `find` over a ten-million-object vault would retain every
//! path it walked past for the life of the mount, which is the shape of leak
//! nobody notices until a machine with a mount up runs out of memory overnight.
//!
//! ## Why numbers are never re-issued for a different path
//!
//! Allocation is monotonic. A recycled *number* would need a matching generation
//! bump to stay safe over NFS, and getting that wrong is silent — so the mount
//! does not recycle numbers at all. It recycles *records*: a path whose record
//! was dropped simply gets the next unused number when it is next seen. Sixty-four
//! bits at one allocation per lookup outlasts any plausible mount by a margin
//! that makes the alternative not worth its risk.

use std::collections::{BTreeMap, HashMap};

use fuser::INodeNo;

use crate::constants::MOUNT_INODE_CACHE_MAX;

/// What kind of thing an inode stands for.
///
/// Carried on the record rather than looked up, because `getattr` on a directory
/// and `getattr` on a file take different paths — one is synthesised, the other
/// comes from the parent's listing — and asking the source which it was would
/// cost a round trip to answer a question the mount already knew.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A stored object.
    File,
    /// A prefix that objects live under. Nothing stores it; see
    /// [`super::tree`] for the inference.
    Directory,
}

/// One inode's record.
struct Record {
    /// Full logical path within the vault, including the mount's root prefix.
    path: String,
    kind: Kind,
    /// How many references the kernel currently holds. Zero means evictable.
    lookups: u64,
    /// Monotonic tick stamped on every use, so eviction can pick the least
    /// recently touched. A counter rather than a clock: it is only ever
    /// compared, and a counter cannot be reordered by a clock adjustment.
    used: u64,
}

/// The inode table.
///
/// Not internally synchronised — [`super::state`] owns it behind the mount's one
/// lock, so that a `lookup` cannot allocate a number that a concurrent `forget`
/// then drops between the allocation and the reply.
///
/// ## Finding the victim is a lookup, not a search
///
/// The obvious eviction — scan every record for the least recently used one — is
/// what this table had first, and it is quietly quadratic: at a cap of tens of
/// thousands, every allocation past the cap walks every record, so a `find` over
/// a large vault spends its time choosing what to forget rather than answering.
/// It is the same shape as the whole-object read this project replaced with a
/// ranged one, and it showed up the same way: a test that should take
/// milliseconds took over a minute.
///
/// So the evictable records are kept in recency order, in [`Evictable`]. Choosing
/// a victim is taking the first entry of an ordered map, and the cost of an
/// allocation stops depending on how much has been browsed.
pub struct InodeTable {
    /// By number.
    records: HashMap<u64, Record>,
    /// By path, so the same path yields the same number while it is remembered.
    numbers: HashMap<String, u64>,
    /// Records the kernel holds no reference to, in recency order.
    evictable: Evictable,
    /// Next number to hand out. Monotonic; see the module docs.
    next: u64,
    /// Recency counter for eviction.
    tick: u64,
}

/// The unreferenced records, ordered by how recently they were touched.
///
/// A `BTreeMap` keyed by the recency tick, which is unique per operation, so the
/// least recently used record is `first_key_value` and eviction is `O(log n)`
/// rather than a walk. Only records with no kernel reference are ever in here,
/// which is what makes taking the first one unconditionally safe.
type Evictable = BTreeMap<u64, u64>;

impl InodeTable {
    /// A table holding just the mount root.
    ///
    /// The root is inode 1 — fixed by the FUSE protocol, not chosen — and is
    /// never evicted: the kernel holds it for the life of the mount and a
    /// filesystem that lost it could not answer anything.
    #[must_use]
    pub fn new(root: String) -> Self {
        let mut records = HashMap::new();
        let mut numbers = HashMap::new();
        records.insert(
            INodeNo::ROOT.0,
            Record {
                path: root.clone(),
                kind: Kind::Directory,
                // Pinned, which is also what keeps it out of `evictable`. The
                // kernel never forgets the root, and a bug that dropped it would
                // take the whole mount with it.
                lookups: 1,
                used: 0,
            },
        );
        numbers.insert(root, INodeNo::ROOT.0);
        Self {
            records,
            numbers,
            evictable: Evictable::new(),
            next: INodeNo::ROOT.0.saturating_add(1),
            tick: 0,
        }
    }

    /// The number for `path`, allocating one if it is not remembered.
    ///
    /// Does **not** take a kernel reference: `readdir` calls this for every entry
    /// it reports, and those entries are informational until the kernel looks one
    /// up. [`InodeTable::remember`] is what records a reference.
    pub fn intern(&mut self, path: &str, kind: Kind) -> INodeNo {
        let tick = self.tick();
        if let Some(&number) = self.numbers.get(path) {
            if let Some(record) = self.records.get_mut(&number) {
                let was = record.used;
                record.used = tick;
                // A path that was a directory and is now a file — or the reverse
                // — is a real state after a rewrite. The record follows the
                // source rather than the other way round.
                record.kind = kind;
                let unreferenced = record.lookups == 0;
                if unreferenced {
                    self.touch(was, tick, number);
                }
                return INodeNo(number);
            }
            // The two maps disagreed, which cannot happen through this API. Fall
            // through and re-allocate rather than hand back a number with no
            // record behind it.
            self.numbers.remove(path);
        }

        let number = self.next;
        self.next = self.next.saturating_add(1);
        self.records.insert(
            number,
            Record {
                path: path.to_string(),
                kind,
                lookups: 0,
                used: tick,
            },
        );
        self.numbers.insert(path.to_string(), number);
        // Nothing references it yet — `readdir` interns without looking up — so
        // it is a candidate from the moment it exists.
        self.evictable.insert(tick, number);
        self.evict();
        INodeNo(number)
    }

    /// Record that the kernel now holds one more reference to `ino`.
    ///
    /// Called once per successful `lookup` reply, which is what the protocol
    /// counts. Saturating rather than wrapping: a count that wrapped to zero
    /// would make a live inode evictable, and the alternative — pinning it
    /// forever after 2^64 lookups of one file — costs nothing anybody will meet.
    pub fn remember(&mut self, ino: INodeNo) {
        let Some(record) = self.records.get_mut(&ino.0) else {
            return;
        };
        let was_free = record.lookups == 0;
        let used = record.used;
        record.lookups = record.lookups.saturating_add(1);
        if was_free {
            // Now referenced, so it must leave the candidate list: the whole
            // guarantee is that nothing the kernel holds is ever evicted.
            self.evictable.remove(&used);
        }
    }

    /// Drop `count` of the kernel's references to `ino`.
    ///
    /// The record is not removed at zero. It becomes *evictable*, and is kept
    /// until the cache bound needs the room — a path the kernel has released is
    /// very often looked up again moments later, and re-issuing the same number
    /// saves the kernel an invalidation.
    pub fn forget(&mut self, ino: INodeNo, count: u64) {
        // The root is pinned: forgetting it would leave the mount unable to
        // answer for its own top level.
        if ino == INodeNo::ROOT {
            return;
        }
        let tick = self.tick();
        if let Some(record) = self.records.get_mut(&ino.0) {
            let was_free = record.lookups == 0;
            record.lookups = record.lookups.saturating_sub(count);
            if record.lookups == 0 && !was_free {
                // Just released. Stamped with the current tick so it goes to the
                // back of the queue rather than being evicted for having been
                // interned long ago.
                record.used = tick;
                self.evictable.insert(tick, ino.0);
            }
        }
        self.evict();
    }

    /// The path and kind behind `ino`, or [`None`] if it is not remembered.
    ///
    /// `None` is a real answer rather than an error: a request for an inode the
    /// mount has evicted is answered `ENOENT`, which is what the kernel expects
    /// for a stale reference.
    pub fn resolve(&mut self, ino: INodeNo) -> Option<(String, Kind)> {
        let tick = self.tick();
        let record = self.records.get_mut(&ino.0)?;
        let was = record.used;
        record.used = tick;
        let unreferenced = record.lookups == 0;
        let answer = (record.path.clone(), record.kind);
        if unreferenced {
            self.touch(was, tick, ino.0);
        }
        Some(answer)
    }

    /// How many records are held.
    ///
    /// Never zero — the root is pinned — so there is deliberately no `is_empty`
    /// beside it: the question it would answer has one answer. What this is for
    /// is the log line at the end of a mount, which is how a "why did this use so
    /// much memory" question gets an answer.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Move an evictable record from one recency position to another.
    ///
    /// The two operations have to happen together or the ordered index and the
    /// records disagree — and an index that disagrees is one that either evicts
    /// the wrong record or cannot evict at all.
    fn touch(&mut self, from: u64, to: u64, number: u64) {
        self.evictable.remove(&from);
        self.evictable.insert(to, number);
    }

    /// The next recency stamp.
    ///
    /// Wrapping rather than `+ 1` because a plain increment panics on overflow in
    /// a debug build, and a panic reached from a filesystem callback wedges the
    /// mount rather than failing one operation. One tick per operation exhausts a
    /// `u64` after longer than the hardware will exist; which of the two failure
    /// modes a theoretical case gets is not theoretical.
    fn tick(&mut self) -> u64 {
        self.tick = self.tick.wrapping_add(1);
        self.tick
    }

    /// Drop least-recently-used records until the table is within its bound.
    ///
    /// Only records the kernel holds no reference to are candidates — that is the
    /// invariant [`Evictable`] carries — so this can never invalidate a number the
    /// other side is still using. A table made entirely of live references simply
    /// grows, which is correct: what bounds it then is what the kernel itself is
    /// willing to hold open.
    fn evict(&mut self) {
        while self.records.len() > MOUNT_INODE_CACHE_MAX {
            let Some((&oldest, &victim)) = self.evictable.first_key_value() else {
                // Everything left is referenced. Nothing may be dropped, and
                // looping would spin.
                return;
            };
            self.evictable.remove(&oldest);
            if let Some(record) = self.records.remove(&victim) {
                // Only clear the reverse mapping if it still points at the record
                // being dropped: a path re-interned after an eviction owns its
                // own, newer number.
                if self.numbers.get(&record.path) == Some(&victim) {
                    self.numbers.remove(&record.path);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> InodeTable {
        InodeTable::new(String::new())
    }

    #[test]
    fn the_root_is_inode_one_and_is_a_directory() {
        // Fixed by the FUSE protocol; the kernel addresses the mount's top level
        // by this number before it has looked anything up.
        let mut table = table();
        assert_eq!(
            table.resolve(INodeNo::ROOT),
            Some((String::new(), Kind::Directory))
        );
    }

    #[test]
    fn a_subtree_mount_roots_at_its_own_prefix() {
        let mut table = InodeTable::new("photos".into());
        assert_eq!(
            table.resolve(INodeNo::ROOT),
            Some(("photos".to_string(), Kind::Directory))
        );
    }

    #[test]
    fn the_same_path_keeps_the_same_number_while_it_is_remembered() {
        // The property that makes a re-lookup free for the kernel, and the one
        // whose absence would make an open file handle point at nothing.
        let mut table = table();
        let first = table.intern("a.txt", Kind::File);
        let second = table.intern("a.txt", Kind::File);
        assert_eq!(first, second);
        assert_ne!(first, INodeNo::ROOT);
    }

    #[test]
    fn different_paths_never_share_a_number() {
        let mut table = table();
        let a = table.intern("a.txt", Kind::File);
        let b = table.intern("b.txt", Kind::File);
        assert_ne!(a, b);
        assert_eq!(table.resolve(a).map(|(path, _)| path), Some("a.txt".into()));
        assert_eq!(table.resolve(b).map(|(path, _)| path), Some("b.txt".into()));
    }

    #[test]
    fn a_number_is_never_re_issued_for_a_different_path() {
        // Recycling numbers needs a generation bump to stay safe, and getting
        // that wrong is silent. Monotonic allocation removes the question.
        let mut table = table();
        let first = table.intern("a.txt", Kind::File);
        table.forget(first, 1);
        // Fill past the bound so `a.txt` is certainly evicted.
        for index in 0..=MOUNT_INODE_CACHE_MAX {
            table.intern(&format!("filler/{index}.bin"), Kind::File);
        }
        let reissued = table.intern("a.txt", Kind::File);
        assert_ne!(
            reissued, first,
            "a recycled number would alias two different paths"
        );
    }

    #[test]
    fn a_referenced_inode_survives_the_cache_bound() {
        // The rule the whole module exists for: the kernel's references are
        // authoritative, and the bound may never break one.
        let mut table = table();
        let pinned = table.intern("keep-me.txt", Kind::File);
        table.remember(pinned);

        for index in 0..(MOUNT_INODE_CACHE_MAX * 2) {
            table.intern(&format!("bulk/{index}.bin"), Kind::File);
        }

        assert_eq!(
            table.resolve(pinned).map(|(path, _)| path),
            Some("keep-me.txt".into()),
            "an inode the kernel still holds was evicted"
        );
    }

    #[test]
    fn unreferenced_records_are_dropped_once_the_table_is_over_its_bound() {
        // The leak this bound exists to stop: a `find` over a huge vault must
        // not retain every path it walked past.
        let mut table = table();
        for index in 0..(MOUNT_INODE_CACHE_MAX * 2) {
            table.intern(&format!("bulk/{index}.bin"), Kind::File);
        }
        assert!(
            table.len() <= MOUNT_INODE_CACHE_MAX,
            "table grew to {} records",
            table.len()
        );
    }

    #[test]
    fn forgetting_the_last_reference_makes_a_record_evictable_but_not_gone() {
        // Re-issuing the same number for a path the kernel just released saves
        // an invalidation, so the record is kept until the room is needed.
        let mut table = table();
        let ino = table.intern("a.txt", Kind::File);
        table.remember(ino);
        table.forget(ino, 1);
        assert_eq!(table.resolve(ino).map(|(path, _)| path), Some("a.txt".into()));
        assert_eq!(table.intern("a.txt", Kind::File), ino);
    }

    #[test]
    fn a_forget_larger_than_the_reference_count_does_not_wrap() {
        // A wrapped count would make a live inode look evictable — and the
        // kernel is allowed to batch forgets, so over-counting is not exotic.
        let mut table = table();
        let ino = table.intern("a.txt", Kind::File);
        table.remember(ino);
        table.forget(ino, u64::MAX);
        // Still resolvable, and now evictable rather than pinned at u64::MAX.
        assert!(table.resolve(ino).is_some());
    }

    #[test]
    fn the_root_cannot_be_forgotten() {
        // A mount that lost its own root could not answer anything, and the
        // kernel is within its rights to send a forget for any inode.
        let mut table = table();
        table.forget(INodeNo::ROOT, u64::MAX);
        assert!(table.resolve(INodeNo::ROOT).is_some());
    }

    #[test]
    fn an_unknown_inode_resolves_to_nothing_rather_than_a_wrong_path() {
        let mut table = table();
        assert_eq!(table.resolve(INodeNo(999_999)), None);
    }

    #[test]
    fn a_path_that_changed_kind_is_reported_as_what_it_is_now() {
        // Real after a rewrite: `photos` was a directory, and is now a file with
        // that name. Serving the stale kind would make `readdir` fail oddly.
        let mut table = table();
        let ino = table.intern("photos", Kind::Directory);
        assert_eq!(table.intern("photos", Kind::File), ino);
        assert_eq!(table.resolve(ino).map(|(_, kind)| kind), Some(Kind::File));
    }

    #[test]
    fn a_fresh_table_holds_only_its_root() {
        // Never empty: a mount that lost its own root could answer nothing.
        assert_eq!(table().len(), 1);
    }

    #[test]
    fn the_eviction_index_never_holds_a_referenced_record() {
        // The invariant that makes "take the first candidate" safe. Checked
        // through the operations that move a record between the two states,
        // because that is where an index and its records come apart.
        let mut table = table();
        let ino = table.intern("a.txt", Kind::File);
        assert!(
            table.evictable.values().any(|number| *number == ino.0),
            "a freshly interned record is a candidate"
        );

        table.remember(ino);
        assert!(
            !table.evictable.values().any(|number| *number == ino.0),
            "a record the kernel holds is still a candidate"
        );

        // Touching it while referenced must not smuggle it back in.
        table.resolve(ino);
        table.intern("a.txt", Kind::File);
        assert!(!table.evictable.values().any(|number| *number == ino.0));

        table.forget(ino, 1);
        assert!(
            table.evictable.values().any(|number| *number == ino.0),
            "a released record must become a candidate again"
        );
    }

    #[test]
    fn the_index_and_the_records_stay_the_same_size() {
        // A leak in either direction is silent: entries the index lost can never
        // be evicted, and entries the records lost make eviction pick a victim
        // that is not there.
        let mut table = table();
        let mut referenced = 0usize;
        for index in 0..1_000 {
            let ino = table.intern(&format!("f{index}.bin"), Kind::File);
            if index % 3 == 0 {
                table.remember(ino);
                referenced += 1;
            }
            if index % 7 == 0 {
                table.resolve(ino);
            }
        }
        // Every record except the referenced ones and the pinned root.
        assert_eq!(table.evictable.len(), table.len() - referenced - 1);
    }

    #[test]
    fn filling_the_table_many_times_over_is_not_quadratic() {
        // This is a *cost* assertion, and it is here because the first version of
        // this table failed it: choosing a victim by scanning every record made
        // each allocation past the cap walk the whole table, and a `find` over a
        // large vault spent its time deciding what to forget. The wall-clock
        // limit is deliberately loose — it is an order-of-magnitude check, not a
        // benchmark — because what it has to catch is quadratic, not slow.
        let start = std::time::Instant::now();
        let mut table = table();
        for index in 0..(MOUNT_INODE_CACHE_MAX * 4) {
            table.intern(&format!("bulk/{index}.bin"), Kind::File);
        }
        assert!(table.len() <= MOUNT_INODE_CACHE_MAX);
        assert!(
            start.elapsed() < std::time::Duration::from_secs(10),
            "interning {} paths took {:?}; eviction is scanning rather than \
             looking up",
            MOUNT_INODE_CACHE_MAX * 4,
            start.elapsed()
        );
    }
}
