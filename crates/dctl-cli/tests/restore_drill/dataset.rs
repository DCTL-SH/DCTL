//! The tree the drill backs up, and why each entry is in it.
//!
//! A drill over a directory of three text files proves that bytes survive a
//! round trip. It does not prove a *restore* works, because a restore does not
//! fail on bytes — it fails on names, on sizes that cross a chunk boundary, and
//! on the entries nobody thought to include. So every file below is here to make
//! one specific failure possible:
//!
//! | Entry | What its absence would hide |
//! |---|---|
//! | [`LARGE_BYTES`]-byte binary | a size below one chunk never exercises multi-chunk streaming, the footer, or the streaming hash |
//! | empty file | zero-length objects are the classic special case a length check divides by |
//! | name with spaces | quoting and argument handling, in the plan and on the way back |
//! | directory with a space in it | the same, one level up, where a path is *joined* rather than passed |
//! | NFC-spelled unicode name | the ordinary case on Linux and Windows |
//! | NFD-spelled unicode name | the ordinary case on macOS, and the one that comes back respelled — see [`super::drill`] |
//! | NFD-spelled unicode **directory** | normalisation applies per component, not only to the leaf |
//! | non-Latin name | a name outside the range a Latin-1 assumption would survive |
//! | deep path | the nesting a recursive restore has to recreate before it can write |
//!
//! The two spellings are of **different words**, not two spellings of one. That
//! is deliberate and it is the difference between testing a behaviour and
//! testing a collision: two spellings of the same word are two files on Linux
//! and one file on macOS, so a dataset built that way would be a *different
//! dataset* on each platform and the drill's manifest would stop being
//! comparable. The collision is a real case and it has its own test in
//! [`super::normalisation`]; the drill itself keeps the dataset platform-stable.
//!
//! Contents are deterministic, so a failure is reproducible and the manifest of
//! a fresh dataset is always the same manifest.

use std::path::Path;

/// How many files [`build`] writes.
///
/// Asserted by the drill before anything is stored. A dataset that quietly lost
/// an entry — an editor normalising a path, a `write` call deleted in a
/// refactor — would make every later count agree with a smaller truth, and the
/// drill would pass having tested less than it claims.
pub const FILE_COUNT: usize = 10;

/// Size of the binary object, in bytes.
///
/// Twelve mebibytes: comfortably past the ten the drill calls for, and — more to
/// the point — past the 1 MiB chunk the object format streams in, so the object
/// spans twelve chunks and the restore has to reassemble them in order. An
/// eight-megabyte file would satisfy "large" and still exercise fewer paths than
/// this one.
pub const LARGE_BYTES: usize = 12 * 1024 * 1024;

/// A directory component spelled NFD: `me` + `U+0301` + `dia`.
///
/// Written with an explicit escape rather than as literal source text, because a
/// source file can be normalised by an editor, a merge tool or a patch program
/// without anyone noticing — and a test whose input silently became NFC would
/// pass while testing nothing.
const NFD_DIRECTORY: &str = "me\u{301}dia";

/// A leaf spelled NFD: `nai` + `U+0308` + `ve.txt`.
const NFD_LEAF: &str = "nai\u{308}ve.txt";

/// A leaf spelled NFC: `caf` + `U+00E9` + `.txt`.
const NFC_LEAF: &str = "caf\u{e9}.txt";

/// The deep path, as a single logical spelling.
///
/// Eight components below the root. Chosen because a restore has to create every
/// intermediate directory before it can write the leaf, and a bug in that walk
/// only shows up past the depth somebody tested by hand.
const DEEP: &str = "archive/2024/q1/reports/regional/north/summary/final notes.txt";

/// Build the dataset under `root`.
///
/// Returns nothing: what was written is discovered by walking the tree, exactly
/// as the manifest does, so the drill can never compare a tree against a list of
/// what somebody intended to write.
pub fn build(root: &Path) {
    write(root, "README.md", b"DCTL restore drill dataset.\n");
    write(root, "empty.txt", b"");
    write(
        root,
        "a name with spaces.txt",
        b"spaces are a legal filename\n",
    );
    write(
        root,
        "reports/quarterly summaries/q1 2024.txt",
        b"a space in a directory name, not only in a leaf\n",
    );
    write(
        root,
        &format!("notes/{NFC_LEAF}"),
        "precomposed: caf\u{e9}\n".as_bytes(),
    );
    write(
        root,
        &format!("notes/{NFD_LEAF}"),
        "decomposed: nai\u{308}ve\n".as_bytes(),
    );
    write(
        root,
        &format!("{NFD_DIRECTORY}/photo.txt"),
        b"the directory component is the decomposed one\n",
    );
    write(
        root,
        "notes/\u{3a9}mega.txt",
        "outside Latin-1 entirely\n".as_bytes(),
    );
    write(root, DEEP, b"eight components below the root\n");
    write(root, "media/large.bin", &large_bytes());
}

/// The paths [`build`] writes in NFD, relative to the dataset root.
///
/// Exactly these must come back respelled in NFC, and nothing else. Returned as
/// data rather than restated in the drill so the two cannot drift: a name added
/// here in decomposed form and forgotten there would make the drill assert a
/// smaller claim than it prints.
pub fn decomposed_paths() -> Vec<String> {
    vec![
        format!("notes/{NFD_LEAF}"),
        format!("{NFD_DIRECTORY}/photo.txt"),
    ]
}

/// Deterministic filler for the binary object.
///
/// A repeating byte pattern rather than random data: a drill that failed has to
/// be reproducible, and a random fixture turns "the restore corrupted byte
/// 7 340 032" into an unrepeatable anecdote. The stride is coprime with the
/// chunk size, so no chunk boundary lands on the same offset within the pattern
/// twice — a chunk that was fetched, decrypted and written in the wrong order
/// therefore changes the hash instead of coinciding with its neighbour.
fn large_bytes() -> Vec<u8> {
    (0..LARGE_BYTES)
        .map(|i| ((i * 7 + 3) % 251) as u8)
        .collect()
}

/// Write one file, creating the directories above it.
fn write(root: &Path, relative: &str, bytes: &[u8]) {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create parent directory");
    }
    std::fs::write(&path, bytes).expect("write dataset file");
}
