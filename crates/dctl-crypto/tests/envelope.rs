//! DKE1 slot-list envelope: framing round-trip, multi-slot recovery of one root,
//! key-committing unwrap, vault/downgrade binding, and structural validation.

use dctl_crypto::constants::{KDF_ID_ARGON2ID, SLOT_TYPE_MNEMONIC, SLOT_TYPE_PASSWORD};
use dctl_crypto::{envelope, keys};

#[test]
fn multi_slot_roundtrip_recovers_same_root() {
    let vault_id = envelope::generate_vault_id();
    let root = keys::generate_key();
    let kek_pw = keys::generate_key();
    let kek_mn = keys::generate_key();

    let slot_pw = envelope::wrap_slot(
        &kek_pw,
        &root,
        &vault_id,
        SLOT_TYPE_PASSWORD,
        KDF_ID_ARGON2ID,
        131_072,
        3,
        4,
        vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        vec![],
    )
    .unwrap();
    let slot_mn = envelope::wrap_slot(
        &kek_mn,
        &root,
        &vault_id,
        SLOT_TYPE_MNEMONIC,
        KDF_ID_ARGON2ID,
        131_072,
        3,
        4,
        vec![9; 16],
        vec![],
    )
    .unwrap();

    let env = envelope::Envelope {
        vault_id,
        slots: vec![slot_pw, slot_mn],
    };
    let bytes = envelope::serialize(&env).unwrap();
    let parsed = envelope::parse(&bytes).unwrap();
    assert_eq!(parsed.vault_id, vault_id);
    assert_eq!(parsed.slots.len(), 2);

    // Both slots independently recover the SAME root key.
    let r_pw = envelope::unwrap_slot(&parsed.slots[0], &kek_pw, &vault_id).unwrap();
    let r_mn = envelope::unwrap_slot(&parsed.slots[1], &kek_mn, &vault_id).unwrap();
    assert_eq!(*r_pw, *root);
    assert_eq!(*r_mn, *root);
}

#[test]
fn wrong_kek_fails_commit_and_vault_binding() {
    let vault_id = envelope::generate_vault_id();
    let root = keys::generate_key();
    let kek = keys::generate_key();
    let slot = envelope::wrap_slot(
        &kek,
        &root,
        &vault_id,
        SLOT_TYPE_PASSWORD,
        KDF_ID_ARGON2ID,
        64,
        1,
        1,
        vec![7; 16],
        vec![],
    )
    .unwrap();

    // Wrong KEK → commitment gate rejects.
    let wrong = keys::generate_key();
    assert!(envelope::unwrap_slot(&slot, &wrong, &vault_id).is_err());

    // Correct KEK but substituted vault_id → framed AAD rejects.
    let other_vault = envelope::generate_vault_id();
    assert!(envelope::unwrap_slot(&slot, &kek, &other_vault).is_err());

    // Correct KEK + vault → succeeds.
    assert_eq!(
        *envelope::unwrap_slot(&slot, &kek, &vault_id).unwrap(),
        *root
    );
}

#[test]
fn structural_validation_rejects_tampering() {
    let vault_id = envelope::generate_vault_id();
    let root = keys::generate_key();
    let kek = keys::generate_key();
    let slot = envelope::wrap_slot(
        &kek,
        &root,
        &vault_id,
        SLOT_TYPE_PASSWORD,
        KDF_ID_ARGON2ID,
        64,
        1,
        1,
        vec![1; 8],
        vec![],
    )
    .unwrap();
    let env = envelope::Envelope {
        vault_id,
        slots: vec![slot],
    };
    let good = envelope::serialize(&env).unwrap();
    assert!(envelope::parse(&good).is_ok());

    // slot_count = 0 → reject.
    let mut zero_slots = good.clone();
    zero_slots[21] = 0;
    zero_slots[22] = 0;
    assert!(envelope::parse(&zero_slots).is_err());

    // Corrupt slot_len (first slot, offset 23) → identity mismatch.
    let mut bad_len = good.clone();
    bad_len[23] = bad_len[23].wrapping_add(1);
    assert!(envelope::parse(&bad_len).is_err());

    // Bad magic / version.
    let mut bad_magic = good.clone();
    bad_magic[0] = b'X';
    assert!(envelope::parse(&bad_magic).is_err());
    let mut bad_ver = good.clone();
    bad_ver[4] = 0x03;
    assert!(envelope::parse(&bad_ver).is_err());
}

#[test]
fn empty_salt_and_aux_roundtrip() {
    let vault_id = envelope::generate_vault_id();
    let root = keys::generate_key();
    let kek = keys::generate_key();
    let slot = envelope::wrap_slot(
        &kek,
        &root,
        &vault_id,
        SLOT_TYPE_PASSWORD,
        KDF_ID_ARGON2ID,
        64,
        1,
        1,
        vec![],
        vec![],
    )
    .unwrap();
    let env = envelope::Envelope {
        vault_id,
        slots: vec![slot],
    };
    let bytes = envelope::serialize(&env).unwrap();
    let parsed = envelope::parse(&bytes).unwrap();
    assert_eq!(
        *envelope::unwrap_slot(&parsed.slots[0], &kek, &vault_id).unwrap(),
        *root
    );
}
