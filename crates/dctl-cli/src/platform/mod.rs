//! Cross-platform behaviour that must be identical on macOS, Linux and Windows.
//!
//! Six problems bite a sync tool the moment it crosses an OS boundary, and all
//! six are handled here rather than being sprinkled through the commands:
//!
//! 1. **Path spelling.** Windows uses `\`, everyone else uses `/`; Windows also
//!    has drive letters, UNC shares and extended-length prefixes. Logical vault
//!    paths are always `/`-separated UTF-8 — see [`path`], including its
//!    backslash rule, which is the one place the platforms disagree about what a
//!    *filename* even is.
//! 2. **Unicode spelling.** macOS hands out decomposed (NFD) filenames, Linux
//!    stores whatever bytes it was given, Windows uses UTF-16 that round-trips
//!    to NFC. The same file must hash to the same index key on every OS, so
//!    every logical path is normalised to NFC before it is used — see
//!    [`path::to_logical`].
//! 3. **Legal names.** Windows forbids characters and whole filenames that are
//!    perfectly legal elsewhere, so a tree synced from Linux can be impossible
//!    to write on Windows. [`names`] detects this *before* a transfer starts
//!    rather than failing halfway through.
//! 4. **Modification times.** A transfer's job is to make the destination hold
//!    what the source holds, and that includes *when it last changed* — the fact
//!    every incremental run compares. Writing a file is not enough; it has to be
//!    stamped, and exactly one place knows how. See [`times`].
//! 5. **Path *identity*.** `./vault`, `vault`, `staging/../vault` and a symlink
//!    to it are four spellings of one directory, and every platform lets an
//!    operator type any of them. [`resolve`] reduces them to one answer, which
//!    is what lets [`crate::addressing`] give the same answer to all four —
//!    invariant I4 is a claim about spellings as much as about contents.
//! 6. **Two local names, one logical path.** The NFC rule in (2) has a sharp
//!    edge: on a byte-oriented filesystem two files whose names differ only in
//!    normalisation are two files, and one vault path. Storing both keeps the
//!    last and reports every one of them as stored, which is data loss with a
//!    clean exit code. [`collision`] finds them and the run refuses.

pub mod collision;
pub mod names;
pub mod path;
pub mod resolve;
pub mod times;

/// True when the target platform's filesystem is case-insensitive by default.
///
/// Windows (NTFS) and macOS (APFS/HFS+ in their default configuration) compare
/// filenames case-insensitively; Linux does not. DCTL always treats *logical*
/// vault paths as case-sensitive — the index key is a hash of the exact bytes —
/// but a case-insensitive local filesystem cannot represent `A.txt` and `a.txt`
/// side by side, so commands warn instead of silently clobbering one with the
/// other.
#[must_use]
pub const fn local_fs_is_case_insensitive() -> bool {
    cfg!(any(target_os = "windows", target_os = "macos"))
}

/// Short platform name used in `--json` output, `dctl about`, and bug reports.
#[must_use]
pub const fn os_name() -> &'static str {
    if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "freebsd") {
        "freebsd"
    } else {
        "unknown"
    }
}
