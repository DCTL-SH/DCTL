//! A vault must be recoverable without its password (`PLAN.md` §13.2).
//!
//! Everything here asserts the same property from a different angle: the root
//! key has **more than one independent way out of the envelope**, and the ways
//! do not depend on each other. That is the difference between a forgotten
//! password costing an afternoon and costing the entire dataset, which §13.2
//! calls the #1 risk of a twenty-year tool.
//!
//! The first test reads the envelope's frozen header bytes rather than asking
//! the code that wrote them. `docs/FORMAT.md` §2 fixes `slot_count` at offset 21
//! as a little-endian `u16`, and a restore in 2046 will be performed by
//! something that reads those bytes, not by this build — so a test that agreed
//! with whatever the encoder currently believes would confirm nothing.

use std::sync::Arc;

use dctl_core::{Modified, UnlockKey, Vault};
use dctl_store::{Backend, LocalFs, ObjectKey};
use tempfile::TempDir;

/// Where a vault's `DKE1` envelope lives in the backend (`FORMAT.md` §2).
/// Spelled out rather than imported so the test pins the stored layout instead
/// of following the constant that produced it.
const ENVELOPE_KEY: &str = "system/envelope.bin";

/// Offset of `slot_count` in the envelope header: `magic(4)+ver(1)+vault_id(16)`.
/// FROZEN by `FORMAT.md` §2.
const SLOT_COUNT_OFFSET: usize = 21;

/// The password every fixture uses. Its whole role in this file is to be
/// *discarded*.
const PASSWORD: &str = "correct horse battery staple";

struct Env {
    _store: TempDir,
    _index: TempDir,
    backend: Arc<dyn Backend>,
    index_path: std::path::PathBuf,
}

fn env() -> Env {
    let store = TempDir::new().unwrap();
    let index = TempDir::new().unwrap();
    let backend: Arc<dyn Backend> = Arc::new(LocalFs::new(store.path()));
    let index_path = index.path().join("vault.redb");
    Env {
        _store: store,
        _index: index,
        backend,
        index_path,
    }
}

/// A second index path in the same temporary directory, so a vault can be
/// re-opened as a machine that has never seen it would.
fn other_index(e: &Env) -> std::path::PathBuf {
    e.index_path.with_file_name("second.redb")
}

/// `slot_count` as the header actually records it.
async fn slot_count(e: &Env) -> u16 {
    let bytes = e
        .backend
        .get(&ObjectKey::new(ENVELOPE_KEY))
        .await
        .expect("the envelope must be on the store");
    u16::from_le_bytes([bytes[SLOT_COUNT_OFFSET], bytes[SLOT_COUNT_OFFSET + 1]])
}

#[tokio::test]
async fn a_new_vault_has_more_than_one_way_in() {
    // The defect this file exists for: `init` wrote one password slot, so a
    // forgotten password was permanent, total data loss. Read off the frozen
    // header, because that is what a future decoder will read.
    let e = env();
    // Dropped explicitly: this test is about the *envelope*, and `NewVault` is
    // `#[must_use]` precisely so that discarding a recovery phrase has to be
    // written down rather than happening by omission.
    drop(
        Vault::init(e.backend.clone(), &e.index_path, PASSWORD)
            .await
            .unwrap(),
    );

    assert!(
        slot_count(&e).await >= 2,
        "a vault with one key slot has exactly one way in; a forgotten password \
         is then permanent, total data loss (PLAN.md §13.2)"
    );
}

#[tokio::test]
async fn the_phrase_alone_opens_a_vault_and_returns_its_bytes() {
    // The whole promise, at the library boundary: write a file, throw the
    // password away, open with the phrase, read the bytes back unchanged.
    const CONTENTS: &[u8] = b"the bytes that must survive a forgotten password";

    let e = env();
    let phrase = {
        let created = Vault::init(e.backend.clone(), &e.index_path, PASSWORD)
            .await
            .unwrap();
        created
            .vault
            .put_file("photos/a.jpg", CONTENTS, Modified::Now)
            .await
            .unwrap();
        created.recovery_phrase.to_string()
    };

    // A fresh index, so nothing about this unlock can be served from state the
    // first vault left behind.
    let recovered = Vault::unlock(
        e.backend.clone(),
        &other_index(&e),
        UnlockKey::RecoveryPhrase(&phrase),
    )
    .await
    .expect("the recovery phrase must open the vault with no password at all");

    recovered.rebuild_index().await.unwrap();
    assert_eq!(
        recovered.get_file("photos/a.jpg").await.unwrap().as_slice(),
        CONTENTS
    );
}

#[tokio::test]
async fn both_slots_unwrap_the_same_root_key() {
    // Two ways in are only useful if they are ways into the *same* vault. Proved
    // through the name keys and the index sub-key rather than by comparing the
    // root directly, which the type system will not hand out: a file written
    // under the password path is addressable and readable under the phrase path
    // only if every root-derived key matches.
    const CONTENTS: &[u8] = b"written under the password, read under the phrase";

    let e = env();
    let created = Vault::init(e.backend.clone(), &e.index_path, PASSWORD)
        .await
        .unwrap();
    created
        .vault
        .put_file("shared.bin", CONTENTS, Modified::Now)
        .await
        .unwrap();
    let phrase = created.recovery_phrase.to_string();
    drop(created);

    let by_password = Vault::unlock(
        e.backend.clone(),
        &e.index_path,
        UnlockKey::Password(PASSWORD),
    )
    .await
    .unwrap();
    let by_phrase = Vault::unlock(
        e.backend.clone(),
        &other_index(&e),
        UnlockKey::RecoveryPhrase(&phrase),
    )
    .await
    .unwrap();

    // Same recipient identity ⇒ same root key: the identity is a deterministic
    // function of the root (§12.4), so a different root would produce a
    // different key-id.
    assert_eq!(
        by_password.identity_key_id(),
        by_phrase.identity_key_id(),
        "the two slots must wrap the same root key"
    );

    by_phrase.rebuild_index().await.unwrap();
    assert_eq!(
        by_phrase.get_file("shared.bin").await.unwrap().as_slice(),
        CONTENTS
    );
}

#[tokio::test]
async fn a_password_never_opens_the_mnemonic_slot_and_a_phrase_never_opens_the_password_slot() {
    // The offered secret decides which slots are even attempted. Without that,
    // a caller could hand a password to the recovery path and have it silently
    // succeed — which would make the two paths one path with two names.
    let e = env();
    let created = Vault::init(e.backend.clone(), &e.index_path, PASSWORD)
        .await
        .unwrap();
    let phrase = created.recovery_phrase.to_string();
    drop(created);

    assert!(
        Vault::unlock(
            e.backend.clone(),
            &other_index(&e),
            UnlockKey::Password(&phrase)
        )
        .await
        .is_err(),
        "the phrase offered as a password must not open the password slot"
    );
    assert!(
        Vault::unlock(
            e.backend.clone(),
            &other_index(&e),
            UnlockKey::RecoveryPhrase(PASSWORD)
        )
        .await
        .is_err(),
        "a password offered as a phrase must not open the mnemonic slot"
    );
}

#[tokio::test]
async fn changing_the_password_leaves_the_recovery_phrase_working() {
    // `PLAN.md` §13.2's whole point: one root key, wrapped several independent
    // ways. Rotating one wrapper must not disturb any other — otherwise the
    // first password change silently destroys the paper backup, and nobody finds
    // out until the day they need it.
    const NEW_PASSWORD: &str = "a completely different secret entirely";
    const CONTENTS: &[u8] = b"still readable after the password changed";

    let e = env();
    let created = Vault::init(e.backend.clone(), &e.index_path, PASSWORD)
        .await
        .unwrap();
    created.vault.put_file("kept.bin", CONTENTS, Modified::Now).await.unwrap();
    let phrase = created.recovery_phrase.to_string();

    created.vault.change_password(NEW_PASSWORD).await.unwrap();
    drop(created);

    // The old password is gone …
    assert!(
        Vault::unlock(
            e.backend.clone(),
            &other_index(&e),
            UnlockKey::Password(PASSWORD)
        )
        .await
        .is_err(),
        "a changed password must actually stop working"
    );
    // … the new one works …
    Vault::unlock(
        e.backend.clone(),
        &other_index(&e),
        UnlockKey::Password(NEW_PASSWORD),
    )
    .await
    .expect("the new password must open the vault");
    // … and the phrase issued before the change still opens the same data.
    let recovered = Vault::unlock(
        e.backend.clone(),
        &other_index(&e),
        UnlockKey::RecoveryPhrase(&phrase),
    )
    .await
    .expect("a password change must not invalidate the recovery phrase");
    recovered.rebuild_index().await.unwrap();
    assert_eq!(
        recovered.get_file("kept.bin").await.unwrap().as_slice(),
        CONTENTS
    );
}

#[tokio::test]
async fn a_password_change_rewrites_exactly_one_slot() {
    // Stated on the stored bytes, because "the phrase still works" would also
    // hold for an implementation that appended a second password slot and left
    // the old one live — which would mean the old password still worked too.
    let e = env();
    let created = Vault::init(e.backend.clone(), &e.index_path, PASSWORD)
        .await
        .unwrap();
    let before = e
        .backend
        .get(&ObjectKey::new(ENVELOPE_KEY))
        .await
        .unwrap()
        .to_vec();

    created
        .vault
        .change_password("another long secret")
        .await
        .unwrap();

    let after = e
        .backend
        .get(&ObjectKey::new(ENVELOPE_KEY))
        .await
        .unwrap()
        .to_vec();
    assert_ne!(before, after, "the envelope must have been rewritten");
    assert_eq!(
        slot_count(&e).await,
        u16::from_le_bytes([before[SLOT_COUNT_OFFSET], before[SLOT_COUNT_OFFSET + 1]]),
        "a password change must not add or drop a slot"
    );
    // The vault identity is part of every slot's AAD, so it must survive.
    assert_eq!(before[5..21], after[5..21], "vault_id must not change");
}

#[tokio::test]
async fn every_generated_phrase_is_different() {
    // Two vaults created a second apart must not share a recovery phrase. A
    // generator seeded from the clock would pass every other test in this file.
    let first = env();
    let second = env();
    let a = Vault::init(first.backend.clone(), &first.index_path, PASSWORD)
        .await
        .unwrap();
    let b = Vault::init(second.backend.clone(), &second.index_path, PASSWORD)
        .await
        .unwrap();
    assert_ne!(a.recovery_phrase.as_str(), b.recovery_phrase.as_str());

    // And one vault's phrase must not open another's — the slot AAD binds
    // `vault_id`, and this is what proves the binding is live.
    assert!(
        Vault::unlock(
            second.backend.clone(),
            &other_index(&second),
            UnlockKey::RecoveryPhrase(&a.recovery_phrase)
        )
        .await
        .is_err(),
        "a phrase must open only the vault it was issued for"
    );
}

/// One slot, decoded straight from the envelope bytes by `FORMAT.md` §2's field
/// offsets — never by `dctl-crypto`'s parser.
///
/// The point is to read the envelope the way a clean-room decoder in 2046 will:
/// from the published table alone. A test that used the encoder's own parser
/// would agree with whatever the encoder currently believes, including a shared
/// misunderstanding of the document.
struct DecodedSlot {
    len: u32,
    slot_type: u8,
    flags: u8,
    kdf_id: u8,
    wrap_algo: u8,
    m_cost: u32,
    t_cost: u32,
    p_lanes: u32,
    salt: Vec<u8>,
    aux_len: u16,
    wrap_len: u16,
}

/// Decode the envelope's slots by hand from `FORMAT.md` §2.
fn decode_slots(bytes: &[u8]) -> Vec<DecodedSlot> {
    let rd_u16 = |o: usize| u16::from_le_bytes([bytes[o], bytes[o + 1]]);
    let rd_u32 =
        |o: usize| u32::from_le_bytes([bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]]);

    assert_eq!(&bytes[0..4], b"DKE1", "magic");
    assert_eq!(bytes[4], 1, "version");

    let mut slots = Vec::new();
    let mut off = 23; // magic(4)+ver(1)+vault_id(16)+slot_count(2)
    for _ in 0..rd_u16(SLOT_COUNT_OFFSET) {
        let salt_len = bytes[off + 52] as usize;
        let aux_len_at = off + 53 + salt_len;
        let aux_len = rd_u16(aux_len_at);
        let wrap_len_at = aux_len_at + 2 + aux_len as usize;
        slots.push(DecodedSlot {
            len: rd_u32(off),
            slot_type: bytes[off + 4],
            flags: bytes[off + 5],
            kdf_id: bytes[off + 6],
            wrap_algo: bytes[off + 7],
            m_cost: rd_u32(off + 8),
            t_cost: rd_u32(off + 12),
            p_lanes: rd_u32(off + 16),
            salt: bytes[off + 53..off + 53 + salt_len].to_vec(),
            aux_len,
            wrap_len: rd_u16(wrap_len_at),
        });
        off += rd_u32(off) as usize;
    }
    assert_eq!(off, bytes.len(), "trailing bytes after the slot list");
    slots
}

#[tokio::test]
async fn the_envelope_matches_the_table_the_format_document_publishes() {
    // `docs/FORMAT.md` §2.1 states, field by field, exactly what a v1 writer
    // emits. A restore twenty years from now is performed against that document
    // and nothing else, so it is worth as much as the code — and a document that
    // has silently drifted from the encoder is worse than no document, because
    // it will be believed.
    let e = env();
    drop(
        Vault::init(e.backend.clone(), &e.index_path, PASSWORD)
            .await
            .unwrap(),
    );
    let bytes = e
        .backend
        .get(&ObjectKey::new(ENVELOPE_KEY))
        .await
        .unwrap()
        .to_vec();

    // The whole envelope: header(23) + two 145-byte slots.
    assert_eq!(bytes.len(), 313, "§2.1 publishes a 313-byte envelope");

    let slots = decode_slots(&bytes);
    assert_eq!(slots.len(), 2);

    // Order is written, even though a reader must not depend on it.
    assert_eq!(slots[0].slot_type, 1, "slots[0] is the password slot");
    assert_eq!(slots[1].slot_type, 2, "slots[1] is the mnemonic slot");

    for (index, slot) in slots.iter().enumerate() {
        assert_eq!(slot.len, 145, "slot {index} slot_len");
        assert_eq!(slot.flags, 0, "slot {index} flags");
        assert_eq!(slot.kdf_id, 1, "slot {index} kdf_id (Argon2id)");
        assert_eq!(slot.wrap_algo, 1, "slot {index} wrap_algo (XChaCha20)");
        assert_eq!(slot.m_cost, 131_072, "slot {index} m_cost");
        assert_eq!(slot.t_cost, 3, "slot {index} t_cost");
        assert_eq!(slot.p_lanes, 4, "slot {index} p_lanes");
        assert_eq!(slot.salt.len(), 16, "slot {index} salt_len");
        assert_eq!(slot.aux_len, 0, "slot {index} aux_len");
        assert_eq!(slot.wrap_len, 72, "slot {index} wrap_len");
        // The frozen structural identity, restated from the document rather
        // than from the encoder: slot_len == 57 + salt + aux + wrap.
        assert_eq!(
            slot.len as usize,
            57 + slot.salt.len() + slot.aux_len as usize + slot.wrap_len as usize
        );
    }

    // Independent salts. A shared one would tie both KEKs to a single random
    // value and make the pair no stronger than its weaker half — the exact
    // property the second slot exists to provide.
    assert_ne!(
        slots[0].salt, slots[1].salt,
        "the two slots must not share a salt"
    );
}

#[tokio::test]
async fn a_password_slot_written_today_is_the_shape_an_older_reader_expects() {
    // The on-disk compatibility claim, stated where it can fail. Adding the
    // mnemonic slot must not change one byte of what a reader that predates it
    // needs: such a reader walks the slot list, skips anything whose
    // `slot_type`/`flags`/`wrap_algo`/`kdf_id` it does not support, and unwraps
    // the first password slot it can. That reader must still open a vault this
    // build creates.
    //
    // Asserted structurally — the fields that reader branches on — and then
    // behaviourally, by unlocking with the password alone.
    let e = env();
    drop(
        Vault::init(e.backend.clone(), &e.index_path, PASSWORD)
            .await
            .unwrap(),
    );
    let bytes = e
        .backend
        .get(&ObjectKey::new(ENVELOPE_KEY))
        .await
        .unwrap()
        .to_vec();

    let satisfiable = decode_slots(&bytes)
        .into_iter()
        .filter(|slot| {
            slot.slot_type == 1 && slot.flags == 0 && slot.wrap_algo == 1 && slot.kdf_id == 1
        })
        .count();
    assert_eq!(
        satisfiable, 1,
        "exactly one slot an older, password-only reader can satisfy"
    );

    Vault::unlock(
        e.backend.clone(),
        &other_index(&e),
        UnlockKey::Password(PASSWORD),
    )
    .await
    .expect("the password path must be untouched by the mnemonic slot");
}
