//! Two local files that would become one object.
//!
//! A logical vault path is Unicode-NFC, decided once in [`super::path`], because
//! the index key and the object key are both keyed hashes of the path's bytes.
//! macOS hands back decomposed filenames while Linux and Windows hand back
//! precomposed ones, so without that rule one file backed up from a Mac and from
//! a Linux box would produce two different objects under two different keys — a
//! silent duplicate nobody could see or explain. That rule is correct and this
//! module does not question it.
//!
//! It has a sharp edge on a byte-oriented filesystem. `re\u{301}sume\u{301}.txt`
//! and `r\u{e9}sum\u{e9}.txt` are two different files on ext4 or XFS: different
//! byte sequences, both returned by `read_dir`, free to hold different contents.
//! Under NFC they are one logical path, and a vault can hold one of them.
//!
//! ## What used to happen, and why it is the worst possible defect here
//!
//! Both were stored, in walk order, the second overwriting the first. The run
//! printed `Files: 2 / 2`, `Errors: 0`, and exited **0**. Twenty-three bytes were
//! gone and the tool said it had them. That is the failure [the plan](https://doc.dctl.sh/project/plan) §6 forbids
//! by name — never report work as done that did not happen — and a backup tool
//! is the one place it cannot be tolerated, because the report is the only thing
//! anybody looks at until restore day. Both `dctl backup` and `dctl copy` did
//! it. It was found by the restore drill in
//! `crates/dctl-cli/tests/restore_drill`, which is what a drill is for.
//!
//! ## Why refusing, rather than storing one and warning
//!
//! There is no correct file to keep. Whichever is stored, the other is lost, and
//! the operator's own filesystem says both exist. So the run stops before
//! anything is written, names every colliding file, and leaves the choice where
//! it belongs. That is the same answer `dctl restore` already gives to a case
//! collision on a case-insensitive volume, for the same reason: a partial result
//! that looks complete is worse than a refusal.
//!
//! Renaming one file at the source takes seconds. Discovering on restore day
//! that a backup silently held one of the two takes the data.
//!
//! ## Why only non-ASCII names are tracked
//!
//! [`Detector::observe`] ignores a logical path that is pure ASCII, and that is
//! exact rather than an approximation. Normalisation composes and reorders
//! combining marks; it never turns a non-ASCII character into an ASCII one, so a
//! non-ASCII name always has a non-ASCII logical form and can never equal a
//! pure-ASCII one. Two ASCII names cannot collide either, since ASCII is
//! NFC-stable and their logical forms are themselves. Collisions therefore occur
//! only among non-ASCII names.
//!
//! It matters because the source enumeration a transfer runs is deliberately
//! thin — it keeps a logical path per file and *not* the native one — and a map
//! from every logical path to its native spelling would roughly double the
//! memory a four-million-file walk costs. Keeping only the non-ASCII minority
//! makes the check free on the trees where it would have been expensive, and no
//! weaker on the trees where it fires.
//!
//! ## Why the message escapes the names
//!
//! The colliding names render **identically** in every terminal, file manager
//! and editor — that is what makes the bug invisible. A message naming them as
//! they display would print the same string twice and help nobody, so each
//! non-ASCII character is shown as `\u{…}`: the difference an operator has to
//! act on is in bytes they cannot see.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::commands::recovery::preflight::Finding;
use crate::constants::{PREFLIGHT_PROBLEM_NORMALISATION_COLLISION, PREFLIGHT_SEVERITY_BLOCKING};
use crate::error::{CliError, Result};
use crate::exit::ExitCode;

/// Several local files that share one logical vault path.
///
/// `Serialize` because the walks that produce these are themselves rendered as
/// documents: collisions must not be the one part of a walk a machine-readable
/// consumer cannot see.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Collision {
    /// The single logical path all of them normalise to.
    pub logical: String,
    /// Where they live on this machine, sorted. Always at least two.
    pub natives: Vec<PathBuf>,
}

/// Accumulates names as a walk produces them and reports what collided.
///
/// A type rather than a function over a finished list, because the two walks
/// that need it are shaped differently: `dctl backup` holds every native path in
/// its scan already, while a transfer's source enumeration throws them away as
/// it goes and could only offer them one at a time. One detector fed by both is
/// what keeps the two commands from disagreeing about what a collision is.
#[derive(Debug, Default)]
pub struct Detector {
    /// First native spelling seen for each non-ASCII logical path.
    first: HashMap<String, PathBuf>,
    /// Every native spelling seen for a path that has collided.
    groups: HashMap<String, Vec<PathBuf>>,
}

impl Detector {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `native` will be stored under `logical`.
    pub fn observe(&mut self, logical: &str, native: &Path) {
        // Exact, not a heuristic — see the module documentation.
        if logical.is_ascii() {
            return;
        }

        if let Some(group) = self.groups.get_mut(logical) {
            group.push(native.to_path_buf());
            return;
        }

        match self.first.get(logical) {
            Some(first) => {
                self.groups.insert(
                    logical.to_string(),
                    vec![first.clone(), native.to_path_buf()],
                );
            }
            None => {
                self.first.insert(logical.to_string(), native.to_path_buf());
            }
        }
    }

    /// Everything that collided, ordered so two runs over one tree agree.
    ///
    /// Sorted rather than left in walk order: a directory walk that does not
    /// sort its children — and the transfer walk does not — would otherwise
    /// produce a differently ordered report on each run, and a report that
    /// cannot be diffed cannot be acted on with confidence.
    #[must_use]
    pub fn finish(self) -> Vec<Collision> {
        let mut collisions: Vec<Collision> = self
            .groups
            .into_iter()
            .map(|(logical, mut natives)| {
                natives.sort();
                Collision { logical, natives }
            })
            .collect();
        collisions.sort_by(|a, b| a.logical.cmp(&b.logical));
        collisions
    }
}

/// Turn collisions into pre-flight findings, so they reach `--json` and the
/// printed report alongside every other reason a name may not survive.
///
/// Blocking, always, and on every platform. This is not a portability warning
/// about a machine that does not exist yet: the loss would happen here, now, in
/// the run being planned.
#[must_use]
pub fn findings(collisions: &[Collision]) -> Vec<Finding> {
    collisions
        .iter()
        .map(|collision| Finding {
            path: collision.logical.clone(),
            problem: PREFLIGHT_PROBLEM_NORMALISATION_COLLISION,
            severity: PREFLIGHT_SEVERITY_BLOCKING,
            detail: describe(collision),
        })
        .collect()
}

/// One collision, written out with its names escaped.
#[must_use]
pub fn describe(collision: &Collision) -> String {
    format!(
        "{} local files normalise to this one vault path, so storing them all would keep only \
         the last: {}",
        collision.natives.len(),
        collision
            .natives
            .iter()
            .map(|native| format!("'{}'", escaped(native)))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// Stop the run, unless there is nothing to stop it for.
///
/// `listed` says whether the caller has already printed the collisions in a
/// report the operator can see. A backup prints them as pre-flight findings; a
/// transfer has no pre-flight table to put them in, so the refusal carries them
/// itself. Neither may leave the operator with a count and no names: the two
/// files look identical on screen, so a message without escapes is unactionable.
///
/// # Errors
/// [`ExitCode::FatalError`] when any collision was found — the same code the
/// name pre-flight already uses for a refusal made before anything is stored.
pub fn refuse(collisions: &[Collision], listed: bool) -> Result<()> {
    if collisions.is_empty() {
        return Ok(());
    }

    let files: usize = collisions
        .iter()
        .map(|collision| collision.natives.len())
        .sum();

    let mut hint = String::new();
    if listed {
        hint.push_str("Each group is listed above with its names spelled out escape by escape, ");
    } else {
        for collision in collisions {
            hint.push_str(&format!(
                "'{}': {}\n",
                collision.logical,
                describe(collision)
            ));
        }
        hint.push_str("The names are spelled out escape by escape ");
    }
    hint.push_str(
        "because they look identical on screen. A vault path is Unicode-NFC so that one file has \
         one key on every platform, which means these can only be stored as one object — and \
         storing them would keep the last while reporting every one of them as transferred. \
         Rename all but one at the source, then run the command again. Nothing has been stored.",
    );

    Err(CliError::new(
        ExitCode::FatalError,
        format!(
            "{files} local file(s) share {} vault path(s) once their names are normalised",
            collisions.len()
        ),
    )
    .with_hint(hint))
}

/// A path with every non-ASCII character shown as an escape.
///
/// The whole difficulty is that the colliding names display identically, so the
/// message has to show the bytes rather than the glyphs. ASCII is left alone: an
/// entirely escaped path would be unreadable, and the differing characters are
/// never ASCII.
fn escaped(path: &Path) -> String {
    path.to_string_lossy()
        .chars()
        .map(|character| {
            if character.is_ascii() {
                character.to_string()
            } else {
                format!("\\u{{{:04x}}}", character as u32)
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    /// `caf` + `U+00E9` + `.txt`, precomposed — the logical spelling of both
    /// files below.
    const NFC: &str = "caf\u{e9}.txt";

    fn detect(pairs: &[(&str, &str)]) -> Vec<Collision> {
        let mut detector = Detector::new();
        for (logical, native) in pairs {
            detector.observe(logical, Path::new(native));
        }
        detector.finish()
    }

    #[test]
    fn distinct_logical_paths_are_not_a_collision() {
        assert!(
            detect(&[
                ("caf\u{e9}.txt", "/src/caf\u{e9}.txt"),
                ("th\u{e9}.txt", "/src/th\u{e9}.txt"),
            ])
            .is_empty()
        );
    }

    #[test]
    fn two_spellings_of_one_name_are_one_collision_naming_both_files() {
        // The defect this module exists for: two files on disk, one logical
        // path, and a run that used to store one over the other and report two
        // successes.
        let collisions = detect(&[(NFC, "/src/cafe\u{301}.txt"), (NFC, "/src/caf\u{e9}.txt")]);

        assert_eq!(collisions.len(), 1);
        assert_eq!(collisions[0].logical, NFC);
        assert_eq!(collisions[0].natives.len(), 2);
    }

    #[test]
    fn more_than_two_spellings_group_together_rather_than_pairwise() {
        // Three is not "one collision plus another": it is one path that three
        // files want, and reporting it twice would have the operator rename one
        // file and hit the same refusal again.
        let collisions = detect(&[
            (NFC, "/src/one"),
            (NFC, "/src/two"),
            (NFC, "/src/three"),
            ("z\u{e9}.txt", "/src/z\u{e9}.txt"),
        ]);

        assert_eq!(collisions.len(), 1);
        assert_eq!(collisions[0].natives.len(), 3);
    }

    #[test]
    fn the_natives_are_sorted_so_two_runs_report_the_same_thing() {
        // The transfer walk does not sort its children, so without this the
        // report would differ between runs over an unchanged tree.
        let forwards = detect(&[(NFC, "/src/b"), (NFC, "/src/a")]);
        let backwards = detect(&[(NFC, "/src/a"), (NFC, "/src/b")]);
        assert_eq!(forwards, backwards);
        assert_eq!(
            forwards[0].natives,
            vec![PathBuf::from("/src/a"), PathBuf::from("/src/b")]
        );
    }

    #[test]
    fn an_ascii_path_seen_twice_is_not_tracked_at_all() {
        // Not merely "not reported": ASCII names are never entered into the map,
        // which is what makes the check free on an ordinary tree. Two identical
        // ASCII logical paths cannot arise from two different files anyway — the
        // walk would have to return one name twice.
        assert!(detect(&[("a.txt", "/src/a.txt"), ("a.txt", "/src/a.txt")]).is_empty());
    }

    #[test]
    fn the_finding_is_blocking_and_names_every_colliding_file() {
        let findings = findings(&detect(&[
            (NFC, "/src/cafe\u{301}.txt"),
            (NFC, "/src/caf\u{e9}.txt"),
        ]));

        assert_eq!(findings.len(), 1);
        assert!(findings[0].is_blocking());
        // Escaped, because the two names are the same glyphs: a message that
        // printed them as they display would print one string twice.
        assert!(
            findings[0].detail.contains("cafe\\u{0301}.txt"),
            "{}",
            findings[0].detail
        );
        assert!(
            findings[0].detail.contains("caf\\u{00e9}.txt"),
            "{}",
            findings[0].detail
        );
    }

    #[test]
    fn a_clean_walk_is_not_refused() {
        refuse(&[], false).expect("nothing to refuse");
        refuse(&[], true).expect("nothing to refuse");
    }

    #[test]
    fn a_collision_is_refused_with_the_exit_code_a_script_branches_on() {
        let collisions = detect(&[(NFC, "/src/cafe\u{301}.txt"), (NFC, "/src/caf\u{e9}.txt")]);

        let error = refuse(&collisions, true).expect_err("a collision stops the run");

        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.to_string().contains("2 local file(s)"), "{error}");
    }

    #[test]
    fn a_caller_with_no_report_of_its_own_gets_the_names_in_the_hint() {
        // The transfer path has no pre-flight table to print findings into, so
        // a refusal that only counted them would leave the operator with two
        // names that look identical and no way to tell which to rename.
        let collisions = detect(&[(NFC, "/src/cafe\u{301}.txt"), (NFC, "/src/caf\u{e9}.txt")]);

        let error = refuse(&collisions, false).expect_err("a collision stops the run");
        let hint = error.hint().unwrap_or_default().to_string();

        assert!(hint.contains("cafe\\u{0301}.txt"), "{hint}");
        assert!(hint.contains("caf\\u{00e9}.txt"), "{hint}");
    }

    #[test]
    fn ascii_survives_the_escaping_unchanged() {
        // An entirely escaped path is unreadable, and the differing characters
        // are never ASCII.
        assert_eq!(escaped(Path::new("/src/a b.txt")), "/src/a b.txt");
    }
}
