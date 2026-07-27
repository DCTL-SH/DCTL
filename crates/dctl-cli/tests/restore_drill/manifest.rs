//! The record the drill is judged against: every path, its size, its BLAKE3.
//!
//! A restore is only proved by comparing what came back against what went in,
//! and the comparison has to be made against something recorded *before* the
//! backup ran. Reading the source tree afterwards would compare the restore
//! against whatever the source happens to be now, which is the same mistake as
//! verifying a backup by reading the backup.
//!
//! Three properties this comparison is written for.
//!
//! **Content, not size.** Two files of the same length are not the same file.
//! Sizes are recorded too, because a truncated restore that happened to hash
//! differently would otherwise be reported as a generic mismatch rather than as
//! a short file — but the hash is the claim.
//!
//! **Streamed.** The hash is computed a block at a time, so the drill's own
//! fixture never contradicts what DCTL promises about a 12 MiB object by holding
//! it in memory to check it.
//!
//! **Respelling is a category, not a failure.** A path that comes back in a
//! different Unicode normalisation, with identical bytes, is neither "the same
//! path" nor "a missing file", and collapsing it into either would lie. It gets
//! its own bucket, [`Comparison::respelled`], which the drill asserts on
//! explicitly. See [`super::drill`] for why that behaviour is correct and must
//! not be "fixed".

use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use unicode_normalization::UnicodeNormalization as _;

/// Block size for the streaming hash. One mebibyte, matching the object format's
/// chunk, so the fixture reads the file the same way DCTL writes it.
const HASH_BLOCK: usize = 1024 * 1024;

/// What was recorded about one file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub size: u64,
    pub hash: String,
}

/// Every file under one tree, keyed by its path relative to that tree.
///
/// A `BTreeMap` so two manifests iterate in the same order and a failure message
/// is stable between runs.
#[derive(Debug)]
pub struct Manifest {
    entries: BTreeMap<String, Record>,
}

impl Manifest {
    /// Walk `root` and record every file below it.
    pub fn of(root: &Path) -> Self {
        let mut entries = BTreeMap::new();
        let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];

        while let Some(directory) = stack.pop() {
            let listing = std::fs::read_dir(&directory)
                .unwrap_or_else(|error| panic!("read {}: {error}", directory.display()));
            for child in listing {
                let child = child.expect("a directory entry").path();
                let metadata = std::fs::symlink_metadata(&child).expect("stat a dataset entry");
                if metadata.is_dir() {
                    stack.push(child);
                    continue;
                }
                let relative = child
                    .strip_prefix(root)
                    .expect("a child of the tree being walked")
                    .to_str()
                    .expect("the drill's dataset is UTF-8 by construction")
                    .replace('\\', "/");
                entries.insert(
                    relative,
                    Record {
                        size: metadata.len(),
                        hash: hash_file(&child),
                    },
                );
            }
        }

        Self { entries }
    }

    /// How many files were recorded.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// The recorded paths, in order.
    pub fn paths(&self) -> impl Iterator<Item = &String> {
        self.entries.keys()
    }

    /// Total bytes recorded.
    pub fn total_bytes(&self) -> u64 {
        self.entries.values().map(|record| record.size).sum()
    }

    /// Compare a restored tree against this one.
    ///
    /// `self` is what went in; `restored` is what came back.
    pub fn compare(&self, restored: &Self) -> Comparison {
        let mut comparison = Comparison::default();
        let mut matched: Vec<&String> = Vec::new();

        for (path, expected) in &self.entries {
            if let Some(actual) = restored.entries.get(path) {
                matched.push(path);
                if actual == expected {
                    comparison.identical.push(path.clone());
                } else {
                    comparison.differing.push(Difference {
                        path: path.clone(),
                        expected: expected.clone(),
                        actual: actual.clone(),
                    });
                }
                continue;
            }

            // No exact match. A path that is the same sequence of characters
            // under NFC is the *same name*, spelled differently — a distinct
            // outcome from a file that did not come back, and the drill is
            // entitled to know which it got.
            match restored.find_equivalent(path) {
                Some((actual_path, actual)) => {
                    matched.push(actual_path);
                    if actual == expected {
                        comparison.respelled.push(Respelling {
                            stored_as: path.clone(),
                            restored_as: actual_path.clone(),
                        });
                    } else {
                        comparison.differing.push(Difference {
                            path: format!("{path} (restored as {actual_path})"),
                            expected: expected.clone(),
                            actual: actual.clone(),
                        });
                    }
                }
                None => comparison.missing.push(path.clone()),
            }
        }

        for path in restored.entries.keys() {
            if !matched.contains(&path) {
                comparison.unexpected.push(path.clone());
            }
        }

        comparison
    }

    /// A path in this manifest that normalises to the same NFC string as `path`.
    fn find_equivalent(&self, path: &str) -> Option<(&String, &Record)> {
        let wanted: String = path.nfc().collect();
        self.entries
            .iter()
            .find(|(candidate, _)| candidate.nfc().collect::<String>() == wanted)
    }
}

/// A path that came back under a different spelling of the same name.
#[derive(Debug)]
pub struct Respelling {
    pub stored_as: String,
    pub restored_as: String,
}

/// A path whose contents or length did not survive.
#[derive(Debug)]
pub struct Difference {
    pub path: String,
    pub expected: Record,
    pub actual: Record,
}

/// The verdict on one restore.
#[derive(Debug, Default)]
pub struct Comparison {
    /// Same path, same size, same hash.
    pub identical: Vec<String>,
    /// Same name and same bytes, different Unicode spelling of the path.
    pub respelled: Vec<Respelling>,
    /// Came back, but not intact.
    pub differing: Vec<Difference>,
    /// Did not come back at all, under any spelling.
    pub missing: Vec<String>,
    /// Came back without having been stored.
    pub unexpected: Vec<String>,
}

impl Comparison {
    /// Fail unless every file came back intact, under its own name or a
    /// respelling of it.
    ///
    /// The message names every problem rather than the first: an operator who
    /// fixes one and re-runs a six-hour restore to meet the next one has been
    /// told the truth twice and helped once. That is the same rule
    /// `dctl restore`'s own pre-flight follows.
    pub fn assert_recovered(&self) {
        if self.differing.is_empty() && self.missing.is_empty() && self.unexpected.is_empty() {
            return;
        }

        let mut report = String::from("the restored tree does not match the manifest:\n");
        for difference in &self.differing {
            report.push_str(&format!(
                "  CORRUPT   {}\n            stored   {} bytes, blake3 {}\n            restored {} \
                 bytes, blake3 {}\n",
                difference.path,
                difference.expected.size,
                difference.expected.hash,
                difference.actual.size,
                difference.actual.hash,
            ));
        }
        for path in &self.missing {
            report.push_str(&format!("  MISSING   {path}\n"));
        }
        for path in &self.unexpected {
            report.push_str(&format!("  UNEXPECTED {path}\n"));
        }
        report.push_str(&format!(
            "  ({} identical, {} respelled)\n",
            self.identical.len(),
            self.respelled.len()
        ));
        panic!("{report}");
    }
}

/// BLAKE3 of a file, streamed.
fn hash_file(path: &Path) -> String {
    let mut file = std::fs::File::open(path)
        .unwrap_or_else(|error| panic!("open {}: {error}", path.display()));
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0_u8; HASH_BLOCK];
    loop {
        let read = file
            .read(&mut buffer)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    hasher.finalize().to_hex().to_string()
}
