//! §12.3 recipient identity `DRK1` + §12.4 root-derived recipient keypair.
//!
//! A recipient is a hybrid public key `R = { x_pk(32), ek(1184) }`. Its `DRK1`
//! encoding and the derived `key_id = BLAKE3-256("dctl-recip-id-v1\x00" ‖ DRK1)` are
//! the stable, self-certifying handle a writer encrypts to (§12.3 trust anchor). Every
//! recipient private key is a pure deterministic function of the vault `root` and an
//! identity `idx` (§12.4), so any device that unlocks the vault reproduces the same
//! `key_id, x_pk, ek, dk` bit-for-bit — no new persisted bytes.

use ml_kem::{B32, EncodedSizeUser, KemCore, MlKem768};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::constants::{
    DRK1_LEN, KEM_SUITE_X25519_MLKEM768, KEY_ID_LEN, KEY_LEN, MLKEM768_EK_LEN, RECIP_ID_LABEL,
    RECIP_ID_MAGIC, RECIP_ID_VERSION, RECIP_MLKEM_D_LABEL, RECIP_MLKEM_Z_LABEL, RECIP_SEED_LABEL,
    RECIP_X25519_LABEL, X25519_PK_LEN,
};
use crate::error::{CryptoError, Result};
use crate::keys::derive_subkey;

/// ML-KEM-768 decapsulation key (private). Zeroized on drop (ml-kem `zeroize` feature).
pub type MlKemDecapKey = <MlKem768 as KemCore>::DecapsulationKey;
/// ML-KEM-768 encapsulation key (public).
pub type MlKemEncapKey = <MlKem768 as KemCore>::EncapsulationKey;

/// A recipient long-term **public** hybrid key `R = { x_pk, ek }` (§12.3).
#[derive(Clone)]
pub struct Drk1Public {
    /// Static X25519 public key (RFC 7748 little-endian u-coordinate).
    pub x_pk: [u8; X25519_PK_LEN],
    /// ML-KEM-768 encapsulation key (FIPS 203 canonical bytes).
    pub ek: [u8; MLKEM768_EK_LEN],
}

impl Drk1Public {
    /// Serialize to the fixed 1222-byte `DRK1` container (§12.3).
    #[must_use]
    pub fn encode(&self) -> [u8; DRK1_LEN] {
        let mut out = [0u8; DRK1_LEN];
        out[0..4].copy_from_slice(&RECIP_ID_MAGIC);
        out[4] = RECIP_ID_VERSION;
        out[5] = KEM_SUITE_X25519_MLKEM768;
        out[6..6 + X25519_PK_LEN].copy_from_slice(&self.x_pk);
        out[6 + X25519_PK_LEN..DRK1_LEN].copy_from_slice(&self.ek);
        out
    }

    /// Parse + structurally validate a `DRK1` container (§12.3). Rejects bad
    /// magic/version/suite before returning; length must be exactly 1222.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != DRK1_LEN {
            return Err(CryptoError::Format("DRK1 wrong length".into()));
        }
        if bytes[0..4] != RECIP_ID_MAGIC {
            return Err(CryptoError::Format("bad DRK1 magic".into()));
        }
        if bytes[4] != RECIP_ID_VERSION {
            return Err(CryptoError::Format("unsupported DRK1 version".into()));
        }
        if bytes[5] != KEM_SUITE_X25519_MLKEM768 {
            return Err(CryptoError::Format("unsupported DRK1 hybrid_suite".into()));
        }
        let mut x_pk = [0u8; X25519_PK_LEN];
        x_pk.copy_from_slice(&bytes[6..6 + X25519_PK_LEN]);
        let mut ek = [0u8; MLKEM768_EK_LEN];
        ek.copy_from_slice(&bytes[6 + X25519_PK_LEN..DRK1_LEN]);
        Ok(Self { x_pk, ek })
    }

    /// Stable 32-byte key-id: `BLAKE3-256("dctl-recip-id-v1\x00" ‖ DRK1)` (§12.3).
    /// Unkeyed BLAKE3, domain-prefixed, full 32-byte output.
    #[must_use]
    pub fn key_id(&self) -> [u8; KEY_ID_LEN] {
        let mut h = blake3::Hasher::new();
        h.update(RECIP_ID_LABEL);
        h.update(&self.encode());
        *h.finalize().as_bytes()
    }

    /// Reconstruct the ML-KEM encapsulation key handle for encapsulation.
    pub(crate) fn ml_ek(&self) -> Result<MlKemEncapKey> {
        let enc = ml_kem::Encoded::<MlKemEncapKey>::try_from(&self.ek[..])
            .map_err(|_| CryptoError::Format("bad ML-KEM ek length".into()))?;
        Ok(MlKemEncapKey::from_bytes(&enc))
    }
}

/// A root-derived recipient keypair (§12.4): the public identity plus the private
/// `(x_sk, dk)` needed to open objects sealed to it. All fields are a pure function of
/// `(root, idx)`; the private material is held only in memory.
pub struct RecipientKeypair {
    /// Public hybrid key.
    pub public: Drk1Public,
    /// Stable key-id (§12.3), also the recipient-matching handle in `kem_wrap`.
    pub key_id: [u8; KEY_ID_LEN],
    x_sk: StaticSecret,
    dk: MlKemDecapKey,
}

impl RecipientKeypair {
    /// Borrow the static X25519 secret (for [`crate::kem::open_as_recipient`]).
    #[must_use]
    pub fn x_sk(&self) -> &StaticSecret {
        &self.x_sk
    }

    /// Borrow the ML-KEM decapsulation key.
    #[must_use]
    pub fn dk(&self) -> &MlKemDecapKey {
        &self.dk
    }
}

/// Derive the recipient keypair for identity `idx` from the vault `root` (§12.4).
///
/// ```text
/// rseed = SUBKEY(root,  "dctl-recip-seed-v1" ‖ idx(u32 LE))
/// x_sk  = SUBKEY(rseed, "dctl-recip-x25519-v1")           (X25519 clamps internally)
/// d     = SUBKEY(rseed, "dctl-recip-mlkem-d-v1")
/// z     = SUBKEY(rseed, "dctl-recip-mlkem-z-v1")
/// (dk, ek) = ML-KEM-768.KeyGen_internal(d, z)             (FIPS 203, seed order (d, z))
/// ```
///
/// `idx = 0` ([`crate::constants::RECIP_IDX_DEFAULT`]) is the only launch identity.
/// Deterministic: identical `(root, idx)` ⇒ identical `key_id, x_pk, ek, dk` bit-for-bit.
pub fn derive_recipient(root: &[u8; KEY_LEN], idx: u32) -> Result<RecipientKeypair> {
    // rseed = SUBKEY(root, label ‖ idx(u32 LE)).
    let mut seed_info = Vec::with_capacity(RECIP_SEED_LABEL.len() + 4);
    seed_info.extend_from_slice(RECIP_SEED_LABEL);
    seed_info.extend_from_slice(&idx.to_le_bytes());
    let rseed = derive_subkey(root, &seed_info)?;

    // Classical leg: x_sk = SUBKEY(rseed, x25519 label). StaticSecret clamps on use.
    let x_sk_bytes = derive_subkey(&rseed, RECIP_X25519_LABEL)?;
    let x_sk = StaticSecret::from(*x_sk_bytes);
    let x_pk = PublicKey::from(&x_sk).to_bytes();

    // PQ leg: deterministic ML-KEM-768 KeyGen_internal(d, z).
    let d = derive_subkey(&rseed, RECIP_MLKEM_D_LABEL)?;
    let z = derive_subkey(&rseed, RECIP_MLKEM_Z_LABEL)?;
    let mut d_b32 = B32::from(*d);
    let mut z_b32 = B32::from(*z);
    let (dk, ek) = MlKem768::generate_deterministic(&d_b32, &z_b32);
    d_b32.as_mut_slice().zeroize();
    z_b32.as_mut_slice().zeroize();

    let mut ek_bytes = [0u8; MLKEM768_EK_LEN];
    ek_bytes.copy_from_slice(ek.as_bytes().as_slice());

    let public = Drk1Public { x_pk, ek: ek_bytes };
    let key_id = public.key_id();
    Ok(RecipientKeypair {
        public,
        key_id,
        x_sk,
        dk,
    })
}
