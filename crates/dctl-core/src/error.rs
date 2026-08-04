//! Typed core errors, wrapping the layer errors beneath.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CoreError {
    /// Wrong password/factor, or the envelope is present and unreadable.
    ///
    /// One answer for both, deliberately: telling somebody holding the envelope
    /// *which* of them happened tells them whether a password was close. What it
    /// no longer covers is the case where there is no envelope at all — see
    /// [`CoreError::NoVault`], which is a fact about the location and not about
    /// any secret.
    #[error("unlock failed: wrong password or corrupted envelope")]
    Unlock,

    /// There is no vault at this location — the envelope object is not there.
    ///
    /// Split out of [`CoreError::Unlock`] because the two send a reader to
    /// opposite places and only one of them is about a secret. A plain remote
    /// has no envelope **by definition**, so every command that opens a vault
    /// used to greet one with *"wrong password or corrupted envelope"* and a
    /// remedy naming `system/envelope.bin` — a file that cannot exist there —
    /// which is `docs/HANDOVER.md` §16.2.
    ///
    /// It leaks nothing that the constant answer above protects. There is no
    /// password to be close to: an attacker who can ask this question can
    /// already list the store and see for themselves that no envelope is in it.
    #[error("no vault at this location: '{0}' is not there")]
    NoVault(String),

    /// No index record for the given logical path.
    #[error("not found in vault: {0}")]
    NotFound(String),

    /// A stored object failed its integrity check on read.
    #[error("integrity check failed: {0}")]
    Integrity(String),

    #[error(transparent)]
    Crypto(#[from] dctl_crypto::CryptoError),

    #[error(transparent)]
    Store(#[from] dctl_store::StoreError),

    #[error(transparent)]
    Index(#[from] dctl_index::IndexError),
}

/// Stable, FFI-safe classification of an error for host retry/UX decisions.
///
/// This is a coarse, **stable** signal (`docs/ERROR_CODES.md`): the GUI/Tauri
/// and iOS FFI layers branch on it instead of parsing message strings. The set
/// is intentionally small and additive-only — like the numeric [`CoreError::code`]
/// scheme, existing meanings never change.
///
/// - [`Transient`](ErrorKind::Transient): worth retrying (I/O, backend/network, DB busy).
/// - [`Permanent`](ErrorKind::Permanent): a retry cannot succeed (malformed/parse failure).
/// - [`Usage`](ErrorKind::Usage): the caller passed something invalid (bad key/params/range).
/// - [`Integrity`](ErrorKind::Integrity): stored bytes failed authentication/checksum (tamper/corruption).
/// - [`Auth`](ErrorKind::Auth): wrong password/factor — re-prompt for credentials.
/// - [`NotFound`](ErrorKind::NotFound): the requested object/path does not exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    Transient,
    Permanent,
    Usage,
    Integrity,
    Auth,
    NotFound,
}

impl CoreError {
    /// Stable, FFI-safe numeric error code for this error.
    ///
    /// Codes are **FROZEN** (`docs/ERROR_CODES.md`): a number is never
    /// renumbered or reused, and new variants only ever take new, unused
    /// numbers — a one-way door like `docs/FORMAT.md` §8. `0` is reserved for
    /// success/none and is never returned here.
    ///
    /// `CoreError`'s own variants occupy the `4xxx` range; the wrapper variants
    /// **delegate** to the wrapped sub-error's `code()`, so a single call on the
    /// top-level error yields the precise stable code from anywhere in the tree
    /// (`1xxx` crypto, `2xxx` store, `3xxx` index).
    pub fn code(&self) -> u32 {
        match self {
            CoreError::Unlock => 4101,
            CoreError::NoVault(_) => 4102,
            CoreError::NotFound(_) => 4201,
            CoreError::Integrity(_) => 4301,
            CoreError::Crypto(e) => e.code(),
            CoreError::Store(e) => e.code(),
            CoreError::Index(e) => e.code(),
        }
    }

    /// Stable, FFI-safe classification for host retry/UX decisions.
    ///
    /// Own variants map directly; wrapper variants classify the underlying
    /// sub-error (honoring `StoreError`'s transient-vs-permanent split). Stable
    /// and additive-only — see [`ErrorKind`] and `docs/ERROR_CODES.md`.
    pub fn kind(&self) -> ErrorKind {
        match self {
            CoreError::Unlock => ErrorKind::Auth,
            // Not `Auth`. An app that re-prompts for a password here would ask
            // for a secret that cannot help: there is nothing at this location
            // for any secret to open.
            CoreError::NoVault(_) => ErrorKind::NotFound,
            CoreError::NotFound(_) => ErrorKind::NotFound,
            CoreError::Integrity(_) => ErrorKind::Integrity,
            CoreError::Crypto(e) => crypto_kind(e),
            CoreError::Store(e) => store_kind(e),
            CoreError::Index(e) => index_kind(e),
        }
    }
}

/// Classify a crypto-layer error. A bare AEAD failure that reaches the top is a
/// data-path tamper/corruption (unlock-time AEAD failures are converted to
/// [`CoreError::Unlock`] before they surface here).
fn crypto_kind(e: &dctl_crypto::CryptoError) -> ErrorKind {
    use dctl_crypto::CryptoError as C;
    match e {
        C::InvalidKdfParams(_) => ErrorKind::Usage,
        C::Aead => ErrorKind::Integrity,
        C::Kdf(_) | C::Format(_) | C::Hkdf => ErrorKind::Permanent,
    }
}

/// Classify a store-layer error, honoring the transient-vs-permanent split:
/// I/O and backend/network faults are retriable; key/range misuse is usage;
/// a checksum mismatch is an integrity failure; a missing object is NotFound.
///
/// A **short write** is deliberately not [`ErrorKind::Integrity`]. The two look
/// alike from here — both are a verified write refusing to commit — but the FFI
/// consumers of this signal branch on it, and `Integrity` is the one that makes
/// an app tell somebody their data may be damaged. Fewer bytes arriving than
/// were sent says nothing about the bytes; it says the destination ran out of
/// room, which is transient in the only sense that matters: free some and it
/// works.
fn store_kind(e: &dctl_store::StoreError) -> ErrorKind {
    use dctl_store::StoreError as S;
    match e {
        S::NotFound(_) => ErrorKind::NotFound,
        S::ChecksumMismatch { .. } => ErrorKind::Integrity,
        // A bucket the credentials cannot list is configuration, not a lost
        // object: `Usage` sends the caller to their settings, where the fix
        // is, rather than hunting for data that was never touched.
        S::InvalidKey(_) | S::RangeOutOfBounds { .. } | S::BucketNotFound { .. } => {
            ErrorKind::Usage
        }
        // A store that moved or vanished is transient in the same practical
        // sense a short write is: nothing about the bytes is in doubt, and the
        // remedy is to put the volume back and run it again. Emphatically not
        // `Integrity` — an app must not tell somebody their data may be damaged
        // because a disk was unplugged mid-run.
        S::ShortWrite { .. }
        | S::Io(_)
        | S::Backend(_)
        | S::RootChanged { .. }
        | S::Provider { .. }
        | S::Transport { .. } => ErrorKind::Transient,
        // The run's own `--max-duration`. **Permanent**, and deliberately not
        // `Transient`: an FFI consumer branching on this must not re-drive an
        // operation inside a run whose window has already closed, which is
        // exactly the multiplication `HANDOVER.md` §32.9 measured. What is
        // transient about it is the *next invocation*, which is the caller's
        // decision and not this classification's.
        S::RunDeadline { .. } => ErrorKind::Permanent,
        // The run stopped asking a link that answered nothing for a whole
        // schedule of attempts. **Permanent**, and for the same reason as the
        // line above rather than a different one: an FFI consumer that re-drove
        // the operation would spend a second schedule on the silence this one
        // was raised to end, which is the multiplication `HANDOVER.md` §36.5
        // measured at 288.7 s. What is transient about it is the *next
        // invocation*, which is the caller's decision and not this
        // classification's.
        S::Stalled { .. } => ErrorKind::Permanent,
        // The server received the request and refused it without naming a
        // cause. **Permanent**, following this module's own rule for anything
        // nobody has classified: guessing `Transient` would have an FFI consumer
        // re-drive a write that a read-only mount or an exhausted quota will
        // refuse identically every time.
        //
        // A full disk does not arrive here. The SFTP write path establishes that
        // case by asking the far end for its free space and raises
        // `ErrorKind::StorageFull` instead, which reaches `S::Io(_)` above and is
        // classified `Transient` - because for that one, freeing space really
        // does make it work.
        S::Refused { .. } => ErrorKind::Permanent,
        // A retry record says how often something was attempted, never what went
        // wrong, so the classification is the wrapped failure's. An FFI consumer
        // branching on this must see the same kind whether or not the operation
        // happened to be retried.
        S::Retried { source, .. } => store_kind(source),
    }
}

/// Classify an index-layer error. `Db` is treated as transient because the
/// common multi-process case (App + File-Provider sharing one SQLCipher WAL DB)
/// is a busy/locked contention that a retry clears; record decryption failure is
/// an integrity failure; a serialize failure is permanent.
fn index_kind(e: &dctl_index::IndexError) -> ErrorKind {
    use dctl_index::IndexError as I;
    match e {
        I::Db(_) => ErrorKind::Transient,
        I::Serialize => ErrorKind::Permanent,
        I::Crypto => ErrorKind::Integrity,
    }
}

pub type Result<T> = std::result::Result<T, CoreError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn own_codes_are_frozen() {
        assert_eq!(CoreError::Unlock.code(), 4101);
        assert_eq!(CoreError::NotFound(String::new()).code(), 4201);
        assert_eq!(CoreError::Integrity(String::new()).code(), 4301);
    }

    #[test]
    fn own_codes_are_unique_and_in_domain() {
        let codes = [
            CoreError::Unlock.code(),
            CoreError::NotFound(String::new()).code(),
            CoreError::Integrity(String::new()).code(),
        ];
        assert!(codes.iter().all(|c| (4000..5000).contains(c)));
        let mut sorted = codes;
        sorted.sort_unstable();
        assert!(sorted.windows(2).all(|w| w[0] != w[1]));
    }

    #[test]
    fn code_delegates_into_wrapped_sub_errors() {
        // Store delegation: top-level code equals the underlying StoreError code.
        let store = dctl_store::StoreError::NotFound("x".into());
        let store_code = store.code();
        assert_eq!(CoreError::Store(store).code(), store_code);
        assert_eq!(
            CoreError::Store(dctl_store::StoreError::NotFound("x".into())).code(),
            2001
        );

        // Crypto delegation.
        assert_eq!(
            CoreError::Crypto(dctl_crypto::CryptoError::Aead).code(),
            1003
        );

        // Index delegation.
        assert_eq!(
            CoreError::Index(dctl_index::IndexError::Serialize).code(),
            3002
        );
    }

    #[test]
    fn kind_classifies_representative_variants() {
        assert_eq!(CoreError::Unlock.kind(), ErrorKind::Auth);
        assert_eq!(
            CoreError::NotFound(String::new()).kind(),
            ErrorKind::NotFound
        );
        assert_eq!(
            CoreError::Integrity(String::new()).kind(),
            ErrorKind::Integrity
        );

        // A transient store error classifies as Transient.
        let transient = CoreError::Store(dctl_store::StoreError::Io(std::io::Error::other("net")));
        assert_eq!(transient.kind(), ErrorKind::Transient);

        // A store checksum mismatch is an integrity failure.
        let corrupt = CoreError::Store(dctl_store::StoreError::ChecksumMismatch {
            expected: String::new(),
            actual: String::new(),
        });
        assert_eq!(corrupt.kind(), ErrorKind::Integrity);
    }
}
