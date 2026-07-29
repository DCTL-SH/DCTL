//! What a DKE1 envelope refuses — the structural bounds of the one file that
//! stands between a passphrase and a vault's root key.
//!
//! # Why these were unreached
//!
//! `tests/envelope.rs` already edits four bytes of a serialized envelope — the
//! magic, the version, `slot_count`, and the low byte of `slot_len` — and those
//! four checks are covered. What it never does is make the file **shorter than
//! it says it is**, and that is the whole of what was left: `envelope too
//! short`, `slot truncated (prefix)`, `slot truncated (aux_len)`, `slot
//! truncated (wrap_len)`, `slot overruns envelope`, `wrap_len != 72`, `trailing
//! bytes after slots`, and the writer's own `slot_count` bound. Deleting any of
//! them left `cargo test --workspace` green.
//!
//! Seven of the eight are the case where the file stops early. That is not an
//! exotic input: the tail is the last thing to reach the disk, so it is the
//! shape a `vault.dke` written by a process that was killed actually has.
//!
//! The envelope is not an object. An object has an unkeyed footer and, behind
//! it, an AEAD tag on every chunk; a malformed one is refused by cryptography
//! whether or not the parser looks. The envelope has **no integrity tag over
//! its framing at all** — the commitment and the AEAD cover a slot's *contents*,
//! not the `slot_len`, `salt_len`, `aux_len` and `wrap_len` fields that say
//! where one slot ends and the next begins. Those four numbers are read from the
//! file and believed. The checks in `envelope::serialize` are therefore the
//! entire defence, and a build without them indexes wherever the file says.
//!
//! # What a missing bound costs
//!
//! Two things, and neither is theoretical for a file that lives on the same disk
//! a backup is restored to.
//!
//! * **A panic**, which `PLAN.md` forbids outside `#[cfg(test)]`: every slice in
//!   `parse_slot` is taken at an offset computed from the file's own numbers.
//!   `dctl unlock` on a truncated `vault.dke` would abort the process instead of
//!   saying the envelope is damaged — and the operator reaching for it is,
//!   by definition, already having a bad day.
//! * **A slot that is not the slot that was written.** `salt`, `aux` and
//!   `wrapped_root` are three variable-length runs with no separator; move a
//!   length and the next slot is read from the middle of this one. Argon2 over
//!   the wrong salt yields a KEK that fails the commitment, so the failure
//!   surfaces as *wrong passphrase* — the one message that makes a user believe
//!   their own memory is at fault rather than the file.
//!
//! Every case below is a byte edit to a *valid* envelope, because that is the
//! only way to prove the refusal comes from the check rather than from the
//! bytes happening to be nonsense.

use dctl_crypto::constants::{
    KDF_ID_ARGON2ID, MAX_SLOT_COUNT, SLOT_FIXED_PREFIX_LEN, SLOT_TYPE_PASSWORD,
    WRAP_ALGO_XCHACHA20_POLY1305,
};
use dctl_crypto::{envelope, keys};

/// Where the slot list starts: `magic(4) + version(1) + vault_id(16) +
/// slot_count(2)`.
const ENV_HEADER_LEN: usize = 23;

/// Salt length every slot here carries — the sixteen bytes `dctl init` writes.
const SALT_LEN: usize = 16;

/// `wrap_len` for `wrap_algo=1`: `nonce(24) + ct(32) + tag(16)`.
const WRAP_LEN: usize = 72;

/// Offsets inside one slot, relative to its start, for the envelope this file
/// builds (`salt_len = 16`, `aux_len = 0`).
mod at {
    use super::{SALT_LEN, SLOT_FIXED_PREFIX_LEN};
    /// `slot_len`, a u32 that must equal `57 + salt_len + aux_len + wrap_len`.
    pub const SLOT_LEN: usize = 0;
    /// The single byte that says how long the salt is.
    pub const SALT_LEN_FIELD: usize = 52;
    /// `aux_len`, a u16 immediately after the salt.
    pub const AUX_LEN: usize = 53 + SALT_LEN;
    /// `wrap_len`, a u16 immediately after the (here empty) aux.
    pub const WRAP_LEN_FIELD: usize = AUX_LEN + 2;
    /// The length one whole slot occupies on the wire.
    pub const TOTAL: usize = SLOT_FIXED_PREFIX_LEN + SALT_LEN + super::WRAP_LEN;
}

/// One real slot, wrapped under a real KEK — not a hand-built struct, so every
/// case below starts from bytes this crate itself would write.
fn one_slot_envelope() -> Vec<u8> {
    let vault_id = envelope::generate_vault_id();
    let root = keys::generate_key();
    let kek = keys::generate_key();
    let slot = envelope::wrap_slot(
        &kek,
        &root,
        &vault_id,
        SLOT_TYPE_PASSWORD,
        KDF_ID_ARGON2ID,
        131_072,
        3,
        4,
        vec![7u8; SALT_LEN],
        vec![],
    )
    .expect("a slot wraps");
    let bytes = envelope::serialize(&envelope::Envelope {
        vault_id,
        slots: vec![slot],
    })
    .expect("the envelope serializes");
    // The arithmetic every offset in this file depends on, checked once here
    // rather than trusted in eight places.
    assert_eq!(bytes.len(), ENV_HEADER_LEN + at::TOTAL);
    assert!(
        envelope::parse(&bytes).is_ok(),
        "the control must parse, or nothing below is about the edit"
    );
    bytes
}

/// The text of the refusal, or a panic naming what was accepted.
fn refusal(bytes: &[u8]) -> String {
    match envelope::parse(bytes) {
        Ok(env) => panic!(
            "the envelope was accepted and yielded {} slot(s)",
            env.slots.len()
        ),
        Err(error) => error.to_string(),
    }
}

/// Overwrite the u16 at `offset`.
fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

/// Overwrite the u32 at `offset`.
fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[test]
fn an_envelope_too_short_to_hold_its_own_header_is_refused_before_it_is_indexed() {
    // The first bound, and the one that decides whether every offset after it is
    // a read or a panic. `vault_id` is copied from `bytes[5..21]` and
    // `slot_count` from `bytes[21..23]` with no further check — this is what
    // makes those two slices legal.
    //
    // A file this short is not exotic: it is what a `dctl init` killed between
    // `create` and `write_all` leaves, and it is what a filesystem that lost a
    // tail hands back.
    let full = one_slot_envelope();
    for length in [0, 4, 22] {
        assert!(
            refusal(&full[..length]).contains("envelope too short"),
            "{length} bytes must be refused as short"
        );
    }
    // …and 23 is enough to read the header, so the bound is exactly where it is
    // claimed to be rather than merely generous.
    assert!(!refusal(&full[..ENV_HEADER_LEN]).contains("envelope too short"));
}

#[test]
fn bytes_after_the_last_slot_are_refused_rather_than_ignored() {
    // A self-delimiting list whose end is not checked is a list that can carry a
    // passenger. `slot_count` says how many slots to read; anything after the
    // last one was written by something that is not this crate, and the two
    // plausible authors are both bad: a build with a slot type this one does not
    // implement (whose slots would be silently dropped, so `dctl unlock` would
    // report the *only* recovery path missing), or an editor appending a slot it
    // hopes will be picked up.
    //
    // Refusing costs nothing — a legitimate extension bumps `slot_count`, which
    // is a number this parser already reads.
    let mut bytes = one_slot_envelope();
    bytes.push(0);
    assert!(refusal(&bytes).contains("trailing bytes after slots"));
}

#[test]
fn a_slot_count_the_file_cannot_hold_is_refused_at_each_end() {
    // Zero is not an empty envelope, it is an envelope with no way in — and
    // `parse` would return it happily for `dctl unlock` to search. The upper
    // bound is the §2 constant; the number is a u16, so without it a file may
    // ask for 65,535 slots and the `Vec::with_capacity` below it obliges before
    // a single one is read.
    let mut bytes = one_slot_envelope();
    put_u16(&mut bytes, 21, 0);
    assert!(refusal(&bytes).contains("slot_count out of range"));

    let mut bytes = one_slot_envelope();
    put_u16(&mut bytes, 21, MAX_SLOT_COUNT + 1);
    assert!(refusal(&bytes).contains("slot_count out of range"));

    // The writer holds the same bound, from the other side: an in-memory
    // envelope with no slots is a file that could never be opened, and writing
    // one over a working `vault.dke` is the way a caller destroys a vault
    // without touching a key.
    let vault_id = envelope::generate_vault_id();
    let empty = envelope::serialize(&envelope::Envelope {
        vault_id,
        slots: vec![],
    })
    .expect_err("an envelope with no way in is not serialized");
    assert!(empty.to_string().contains("slot_count out of range"));
}

#[test]
fn a_slot_that_stops_inside_its_own_fixed_prefix_is_refused_at_each_field() {
    // `parse_slot` reads eleven fixed fields — `slot_len`, four flag bytes,
    // three costs, a 32-byte commitment and `salt_len` — by direct indexing,
    // because a prefix that is present is a prefix that can be sliced. This is
    // the check that makes "is present" true. Every truncation between the
    // header and a whole prefix must land here.
    let full = one_slot_envelope();
    for cut in [1, SLOT_FIXED_PREFIX_LEN / 2, SLOT_FIXED_PREFIX_LEN - 1] {
        let short = &full[..ENV_HEADER_LEN + cut];
        assert!(
            refusal(short).contains("slot truncated (prefix)"),
            "a slot with {cut} of its {SLOT_FIXED_PREFIX_LEN}-byte prefix must be refused"
        );
    }
}

#[test]
fn a_salt_that_runs_past_the_file_is_refused_before_aux_len_is_read() {
    // `salt_len` is one byte the file supplies, and `aux_len` is read at
    // `53 + salt_len`. Nothing else bounds it: the salt is opaque, so there is no
    // shape to check it against. Point it past the end and the next read is off
    // the end of the buffer.
    //
    // The value used is 0xFF rather than something enormous on purpose — the
    // largest a `u8` can carry is only 255, which is the point: the smallest
    // possible overrun still has to be caught.
    let mut bytes = one_slot_envelope();
    bytes[ENV_HEADER_LEN + at::SALT_LEN_FIELD] = 0xFF;
    assert!(refusal(&bytes).contains("slot truncated (aux_len)"));
}

#[test]
fn an_aux_run_that_runs_past_the_file_is_refused_before_wrap_len_is_read() {
    // The same rule one field along. `aux` is the slot's extension area and is
    // genuinely variable, so its length is genuinely the file's to state — and
    // `wrap_len`, the length of the wrapped root key itself, is read at
    // `55 + salt_len + aux_len`.
    let mut bytes = one_slot_envelope();
    put_u16(&mut bytes, ENV_HEADER_LEN + at::AUX_LEN, u16::MAX);
    assert!(refusal(&bytes).contains("slot truncated (wrap_len)"));
}

#[test]
fn a_slot_whose_declared_length_disagrees_with_its_fields_is_refused() {
    // `slot_len` is redundant with `57 + salt_len + aux_len + wrap_len`, and
    // redundancy in a format is only worth its bytes if somebody compares the
    // two. This is the comparison. It is what stops a file whose `slot_len`
    // walks the reader into the middle of the following slot — where the next
    // `slot_len` is 32 bytes of commitment read as a length, and the envelope
    // becomes whatever those bytes say.
    let mut bytes = one_slot_envelope();
    put_u32(
        &mut bytes,
        ENV_HEADER_LEN + at::SLOT_LEN,
        at::TOTAL as u32 + 1,
    );
    assert!(refusal(&bytes).contains("slot_len != 57"));
}

#[test]
fn a_slot_that_claims_more_bytes_than_the_file_holds_is_refused() {
    // Consistent fields, an honest `slot_len`, and a file that simply stops
    // early — the shape a half-written `vault.dke` really has, since the tail is
    // the last thing to reach the disk. `wrapped_root` is sliced at
    // `wrap_len_pos + 2 .. + wrap_len`, and only this check stands in front of
    // it.
    let full = one_slot_envelope();
    let short = &full[..full.len() - 8];
    assert!(refusal(short).contains("slot overruns envelope"));
}

#[test]
fn an_xchacha_slot_whose_wrapped_root_is_not_seventy_two_bytes_is_refused() {
    // `wrap_algo = 1` fixes the wrapped root at `nonce(24) + ct(32) + tag(16)`,
    // and the AEAD open below splits those three runs by position. A shorter
    // blob that is otherwise self-consistent reaches it, and what happens then
    // is an argument about which slice panics first — so the length is settled
    // here, while it is still a number rather than an offset.
    //
    // Built to be *internally consistent*: `wrap_len` and `slot_len` are both
    // reduced and a byte is dropped, so every other check in `parse_slot` is
    // satisfied and this one is the only thing left to refuse it.
    let full = one_slot_envelope();
    let mut bytes = full[..full.len() - 1].to_vec();
    put_u16(
        &mut bytes,
        ENV_HEADER_LEN + at::WRAP_LEN_FIELD,
        WRAP_LEN as u16 - 1,
    );
    put_u32(
        &mut bytes,
        ENV_HEADER_LEN + at::SLOT_LEN,
        at::TOTAL as u32 - 1,
    );
    assert!(refusal(&bytes).contains("wrap_len != 72"));
}

#[test]
fn a_salt_too_long_to_describe_is_refused_rather_than_written_truncated() {
    // The writer's side of the same frame, and the only one of these that
    // corrupts a file rather than refusing to read one. `salt_len` is a single
    // byte; a 256-byte salt written as `len as u8` would record **zero**, and
    // the envelope would then parse cleanly into a slot whose salt is empty and
    // whose `aux` is the salt. Argon2 over that yields a KEK that fails the
    // commitment, so the vault reports a wrong passphrase forever, for a file
    // that was written by this crate and is internally consistent.
    //
    // `wrap_slot` holds the same bound one layer up, and refuses first for
    // anything it builds. That is why this case builds the [`envelope::Slot`]
    // directly — every field on it is `pub`, so a slot may legitimately reach
    // `serialize` without passing through `wrap_slot` (a future slot type, a
    // migration, a slot read from one envelope and written into another), and
    // this is the check that covers all of them. Two independent bounds is the
    // right number for a length that silently truncates when it is wrong.
    let vault_id = envelope::generate_vault_id();
    let error = envelope::serialize(&envelope::Envelope {
        vault_id,
        slots: vec![slot_with_salt(vec![0u8; 256])],
    })
    .expect_err("a salt that cannot be described must not be written");
    assert!(error.to_string().contains("slot salt too long"));

    // And 255 — the largest that *can* be described — is written and read back
    // as itself, so the refusal is about the frame and not about the size.
    let bytes = envelope::serialize(&envelope::Envelope {
        vault_id,
        slots: vec![slot_with_salt(vec![0u8; 255])],
    })
    .expect("a 255-byte salt serializes");
    assert_eq!(
        envelope::parse(&bytes).expect("and parses").slots[0]
            .salt
            .len(),
        255
    );

    // The same, one field along: `aux` is described by a u16, so 65,536 bytes of
    // it wraps to zero and swallows `wrapped_root` into the aux run.
    let mut wide = slot_with_salt(vec![0u8; SALT_LEN]);
    wide.aux = vec![0u8; usize::from(u16::MAX) + 1];
    let error = envelope::serialize(&envelope::Envelope {
        vault_id,
        slots: vec![wide],
    })
    .expect_err("an aux run that cannot be described must not be written");
    assert!(error.to_string().contains("slot aux too long"));
}

/// A structurally complete slot carrying `salt`, built field by field.
///
/// Not `wrap_slot`, because that refuses an over-long salt itself and this file
/// is about the bound below it. The wrapped root is the right *length* and is
/// not a real wrap — nothing here unwraps it, and a slot that never reaches a
/// KEK is exactly what `serialize` has to frame correctly anyway.
fn slot_with_salt(salt: Vec<u8>) -> envelope::Slot {
    envelope::Slot {
        slot_type: SLOT_TYPE_PASSWORD,
        flags: 0,
        kdf_id: KDF_ID_ARGON2ID,
        wrap_algo: WRAP_ALGO_XCHACHA20_POLY1305,
        m_cost: 131_072,
        t_cost: 3,
        p_lanes: 4,
        commit: [0u8; 32],
        salt,
        aux: vec![],
        wrapped_root: vec![0u8; WRAP_LEN],
    }
}
