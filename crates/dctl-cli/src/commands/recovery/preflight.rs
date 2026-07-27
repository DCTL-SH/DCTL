//! Everything that could stop a name from being written, found before anything
//! is (`PLAN.md` §13.6).
//!
//! A backup you never restored is not a backup, and the way a restore fails is
//! never the way you expect. It is not the network: it is `report:final.pdf`
//! arriving on Windows, or `README.md` and `readme.md` arriving on the same
//! case-insensitive volume, or a path four characters past `MAX_PATH` — and it
//! happens 3.9 TB into a 4 TB run, leaving a tree that is neither the old one
//! nor the new one.
//!
//! So the whole path set is inspected up front and **every** problem is
//! reported, not the first. An operator who fixes one name, re-runs for six
//! hours and hits the next one has been told the truth three times and helped
//! zero times.
//!
//! Nothing here rewrites a name. DCTL stores the bytes it was given and reports
//! the conflict; silently mangling a filename would break the promise that a
//! restore reproduces exactly what was backed up.
//!
//! ## Two audiences
//!
//! The same finding means different things depending on who is asking.
//! [`Audience::ThisPlatform`] is a restore about to write here, where an illegal
//! name is fatal. [`Audience::AnyPlatform`] is a backup storing names for a
//! restore that might one day happen anywhere, where the same name is a warning
//! about a machine that does not exist yet. Only [`Audience::ThisPlatform`] can
//! produce a blocking finding on the platform it is running on — except for
//! control characters, which no filesystem anywhere accepts.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Serialize;

use crate::constants::{
    PATH_SEPARATOR, PREFLIGHT_PROBLEM_CASE_COLLISION, PREFLIGHT_PROBLEM_ILLEGAL_NAME,
    PREFLIGHT_PROBLEM_PATH_TOO_LONG, PREFLIGHT_PROBLEM_TYPE_CONFLICT, PREFLIGHT_SEVERITY_BLOCKING,
    PREFLIGHT_SEVERITY_PORTABILITY, WINDOWS_MAX_PATH_LEN,
};
use crate::platform::names::{self, NameIssue};
use crate::platform::{local_fs_is_case_insensitive, os_name, path as logical};

/// Who the inspection is being run for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Audience {
    /// A restore that is about to create these names on the machine it is
    /// running on. What this platform refuses is fatal.
    ThisPlatform,
    /// A backup storing these names for a restore that may happen on any
    /// platform. What some other platform refuses is a warning, not a refusal —
    /// the bytes are perfectly storable, and refusing to back up a legal local
    /// file because Windows dislikes its name would lose data to protect a
    /// hypothetical.
    AnyPlatform,
}

/// One reason a path may not arrive intact.
///
/// `problem` and `severity` are stable slugs from [`crate::constants`] because
/// they land in `--json` and a script branches on them; `detail` is prose for a
/// person and may be reworded freely.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// The logical path the problem belongs to.
    pub path: String,
    /// Stable slug naming the kind of problem.
    pub problem: &'static str,
    /// Stable slug: blocking here, or a portability warning.
    pub severity: &'static str,
    /// Human explanation, including the offending component where there is one.
    pub detail: String,
}

impl Finding {
    /// Whether this finding stops the run.
    #[must_use]
    pub fn is_blocking(&self) -> bool {
        self.severity == PREFLIGHT_SEVERITY_BLOCKING
    }
}

/// The result of inspecting a whole path set.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Report {
    /// Every finding, ordered by path so two runs over the same set produce
    /// byte-identical output — a report you can diff is a report you can act on.
    pub findings: Vec<Finding>,
}

impl Report {
    /// Whether nothing at all was found.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }

    /// Findings that stop the run on the platform it is running on.
    pub fn blocking(&self) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(|f| f.is_blocking())
    }

    /// How many findings stop the run.
    #[must_use]
    pub fn blocking_count(&self) -> usize {
        self.blocking().count()
    }

    /// The distinct paths that cannot be written here.
    ///
    /// Distinct, because one path can fail for several reasons at once and
    /// "4 paths cannot be written" is the number an operator needs — not
    /// "9 findings".
    #[must_use]
    pub fn blocked_paths(&self) -> Vec<&str> {
        let mut paths: Vec<&str> = self.blocking().map(|f| f.path.as_str()).collect();
        paths.sort_unstable();
        paths.dedup();
        paths
    }

    /// Whether this exact path is blocked.
    #[must_use]
    pub fn blocks(&self, path: &str) -> bool {
        self.blocking().any(|f| f.path == path)
    }

    /// Take in findings raised somewhere other than [`inspect`].
    ///
    /// One caller today: a backup's scan is the only thing that can see two
    /// *local* files collapsing onto one logical path, because by the time a
    /// path set reaches [`inspect`] both spellings have already become the same
    /// string and the collision is invisible. The finding still belongs in this
    /// report rather than in a channel of its own — it is a reason a name will
    /// not arrive intact, which is what this type is — so it reaches `--json`,
    /// the printed table and [`Report::blocking_count`] the same way every other
    /// finding does.
    ///
    /// Re-sorted afterwards, through the same ordering [`inspect`] uses, so a
    /// merged report is still byte-identical between two runs over one tree.
    pub fn absorb(&mut self, findings: Vec<Finding>) {
        self.findings.extend(findings);
        order(&mut self.findings);
    }
}

/// Inspect a set of logical paths for everything that could stop them being
/// written.
///
/// `root` is the local directory a restore would write into, used to measure the
/// full native path length. Pass `None` when there is no root yet — a backup
/// storing names for an unknown future restore — in which case the logical path
/// is measured on its own, which is the shortest any root could make it.
#[must_use]
pub fn inspect(paths: &[String], root: Option<&Path>, audience: Audience) -> Report {
    let mut findings = Vec::new();

    for path in paths {
        collect_name_issues(path, audience, &mut findings);
        collect_length(path, root, audience, &mut findings);
    }
    collect_case_collisions(paths, audience, &mut findings);
    collect_type_conflicts(paths, &mut findings);

    order(&mut findings);

    Report { findings }
}

/// Sort and de-duplicate a finding list.
///
/// Determinism: the same input must always produce the same report, or two runs
/// cannot be compared. Shared with [`Report::absorb`] so a merged report is
/// ordered by the same rule rather than by a second copy of it that could drift.
fn order(findings: &mut Vec<Finding>) {
    findings.sort_by(|a, b| {
        a.path
            .cmp(&b.path)
            .then_with(|| a.problem.cmp(b.problem))
            .then_with(|| a.detail.cmp(&b.detail))
    });
    findings.dedup();
}

/// Windows-reserved characters, reserved device names, trailing dots and
/// control characters, from [`crate::platform::names`].
fn collect_name_issues(path: &str, audience: Audience, out: &mut Vec<Finding>) {
    for (component, issue) in names::check_logical_path(path) {
        let severity = match audience {
            // No filesystem anywhere accepts a control character, so it is fatal
            // for both audiences; everything else is a Windows rule, and a
            // backup running on Linux must not refuse a legal local file for it.
            Audience::AnyPlatform if !matches!(issue, NameIssue::ControlCharacter(_)) => {
                PREFLIGHT_SEVERITY_PORTABILITY
            }
            Audience::AnyPlatform => PREFLIGHT_SEVERITY_BLOCKING,
            Audience::ThisPlatform => {
                if names::issue_blocks_here(&issue) {
                    PREFLIGHT_SEVERITY_BLOCKING
                } else {
                    PREFLIGHT_SEVERITY_PORTABILITY
                }
            }
        };

        out.push(Finding {
            path: path.to_string(),
            problem: PREFLIGHT_PROBLEM_ILLEGAL_NAME,
            severity,
            // Component first, then the reason: the path column shows *which*
            // file, and this says which part of it and why.
            detail: format!("'{component}': {issue}"),
        });
    }
}

/// Paths whose native spelling would exceed Win32's `MAX_PATH`.
fn collect_length(path: &str, root: Option<&Path>, audience: Audience, out: &mut Vec<Finding>) {
    let native_len = match root {
        Some(root) => logical::from_logical(root, path).as_os_str().len(),
        None => path.len(),
    };
    if native_len <= WINDOWS_MAX_PATH_LEN {
        return;
    }

    // Long paths are a Windows limit. On a platform that does not have it, the
    // finding is still worth making — it is the classic "restores fine on the
    // Linux box, fails on the laptop" defect — but it is not blocking here.
    let severity = if audience == Audience::ThisPlatform && cfg!(target_os = "windows") {
        PREFLIGHT_SEVERITY_BLOCKING
    } else {
        PREFLIGHT_SEVERITY_PORTABILITY
    };

    out.push(Finding {
        path: path.to_string(),
        problem: PREFLIGHT_PROBLEM_PATH_TOO_LONG,
        severity,
        detail: format!(
            "the destination path is {native_len} characters, past the \
             {WINDOWS_MAX_PATH_LEN}-character Windows limit"
        ),
    });
}

/// Paths that differ only in case.
///
/// The vault is case-sensitive — its key is a hash of the exact bytes — but a
/// case-insensitive local filesystem cannot hold `README.md` and `readme.md`
/// side by side. Restoring both would silently write one over the other and
/// report two successes.
fn collect_case_collisions(paths: &[String], audience: Audience, out: &mut Vec<Finding>) {
    let mut seen: BTreeMap<String, &String> = BTreeMap::new();
    let severity = match audience {
        Audience::ThisPlatform if local_fs_is_case_insensitive() => PREFLIGHT_SEVERITY_BLOCKING,
        _ => PREFLIGHT_SEVERITY_PORTABILITY,
    };

    for path in paths {
        let folded = path.to_lowercase();
        match seen.get(&folded) {
            Some(first) if *first != path => {
                let detail = format!(
                    "differs from '{first}' only in case, which {} cannot represent",
                    if severity == PREFLIGHT_SEVERITY_BLOCKING {
                        os_name()
                    } else {
                        "a case-insensitive filesystem"
                    }
                );
                out.push(Finding {
                    path: path.to_string(),
                    problem: PREFLIGHT_PROBLEM_CASE_COLLISION,
                    severity,
                    detail,
                });
            }
            Some(_) => {}
            None => {
                seen.insert(folded, path);
            }
        }
    }
}

/// Paths where one entry needs a directory and another needs a file of the same
/// name.
///
/// Always blocking: no filesystem in existence lets `a/b` be a file while
/// `a/b/c` exists, so this one is not a portability nicety.
fn collect_type_conflicts(paths: &[String], out: &mut Vec<Finding>) {
    let files: std::collections::BTreeSet<&str> = paths.iter().map(String::as_str).collect();

    for path in paths {
        let mut prefix_end = 0;
        while let Some(offset) = path[prefix_end..].find(PATH_SEPARATOR) {
            let boundary = prefix_end + offset;
            let ancestor = &path[..boundary];
            if files.contains(ancestor) {
                out.push(Finding {
                    path: path.to_string(),
                    problem: PREFLIGHT_PROBLEM_TYPE_CONFLICT,
                    severity: PREFLIGHT_SEVERITY_BLOCKING,
                    detail: format!(
                        "needs '{ancestor}' to be a directory, but '{ancestor}' is \
                         itself a file in this set"
                    ),
                });
            }
            prefix_end = boundary + 1;
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn paths(list: &[&str]) -> Vec<String> {
        list.iter().map(|p| (*p).to_string()).collect()
    }

    fn inspect_here(list: &[&str]) -> Report {
        inspect(&paths(list), None, Audience::ThisPlatform)
    }

    #[test]
    fn an_ordinary_tree_produces_no_findings() {
        let report = inspect_here(&["photos/2024/a.jpg", "photos/2024/b.jpg", "notes.txt"]);
        assert!(report.is_clean());
        assert_eq!(report.blocking_count(), 0);
    }

    #[test]
    fn every_illegal_name_is_reported_not_just_the_first() {
        // The failure this exists to prevent: fix one name, wait six hours,
        // discover the next one.
        let report = inspect_here(&[
            "reports/report:final.pdf",
            "reports/aux.txt",
            "reports/data.",
            "reports/what?.txt",
        ]);
        assert_eq!(report.findings.len(), 4, "{:#?}", report.findings);
        assert!(
            report
                .findings
                .iter()
                .all(|f| f.problem == PREFLIGHT_PROBLEM_ILLEGAL_NAME)
        );
    }

    #[test]
    fn a_finding_names_the_offending_component() {
        let report = inspect_here(&["photos/report:final/a.jpg"]);
        assert_eq!(report.findings.len(), 1);
        assert!(report.findings[0].detail.contains("report:final"));
        assert_eq!(report.findings[0].path, "photos/report:final/a.jpg");
    }

    #[test]
    fn a_control_character_blocks_on_every_platform() {
        // The one name no filesystem anywhere accepts, so it is fatal for a
        // backup too — storing it would guarantee an unrestorable object.
        for audience in [Audience::ThisPlatform, Audience::AnyPlatform] {
            let report = inspect(&paths(&["bad\u{7}name.txt"]), None, audience);
            assert_eq!(report.blocking_count(), 1, "{audience:?}");
        }
    }

    #[test]
    fn a_backup_warns_where_a_restore_would_refuse() {
        // Windows rules must not stop a Linux backup: the bytes are storable,
        // and refusing would lose data to protect a machine that may not exist.
        let report = inspect(
            &paths(&["reports/report:final.pdf"]),
            None,
            Audience::AnyPlatform,
        );
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].severity, PREFLIGHT_SEVERITY_PORTABILITY);
        assert_eq!(report.blocking_count(), 0);
    }

    #[test]
    fn the_blocking_rule_agrees_with_the_platform_module() {
        // A drift between the two would make the report claim a write will fail
        // when it would have succeeded — or, far worse, the reverse.
        for name in [
            "report:final.pdf",
            "aux.txt",
            "data.",
            "what?.txt",
            "bad\u{7}name",
        ] {
            let report = inspect(&paths(&[name]), None, Audience::ThisPlatform);
            assert_eq!(
                report.blocking_count() > 0,
                names::check_logical_path(name)
                    .iter()
                    .any(|(_, issue)| names::issue_blocks_here(issue)),
                "'{name}' classified inconsistently"
            );
        }
    }

    #[test]
    fn paths_differing_only_in_case_are_reported_once() {
        let report = inspect_here(&["docs/README.md", "docs/readme.md"]);
        let collisions: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.problem == PREFLIGHT_PROBLEM_CASE_COLLISION)
            .collect();
        assert_eq!(collisions.len(), 1);
        // The *second* path is the one reported, and it names the first.
        assert_eq!(collisions[0].path, "docs/readme.md");
        assert!(collisions[0].detail.contains("docs/README.md"));
    }

    #[test]
    fn a_case_collision_blocks_only_where_it_actually_would() {
        let report = inspect_here(&["A.txt", "a.txt"]);
        let collision = report
            .findings
            .iter()
            .find(|f| f.problem == PREFLIGHT_PROBLEM_CASE_COLLISION)
            .unwrap();
        assert_eq!(collision.is_blocking(), local_fs_is_case_insensitive());
    }

    #[test]
    fn a_file_that_another_path_needs_as_a_directory_is_blocking() {
        // No filesystem allows this, so it is not a portability nicety.
        let report = inspect_here(&["a/b", "a/b/c.txt"]);
        let conflicts: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.problem == PREFLIGHT_PROBLEM_TYPE_CONFLICT)
            .collect();
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].path, "a/b/c.txt");
        assert!(conflicts[0].is_blocking());
    }

    #[test]
    fn a_deep_path_is_measured_against_the_real_destination_root() {
        // The bug this catches: a tree that fits under /tmp but not under
        // C:\Users\someone\Documents\restores\2026-07.
        let deep = format!("{}/file.txt", "d".repeat(WINDOWS_MAX_PATH_LEN));
        let report = inspect(
            &paths(&[deep.as_str()]),
            Some(Path::new("/very/long/destination/root")),
            Audience::ThisPlatform,
        );
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.problem == PREFLIGHT_PROBLEM_PATH_TOO_LONG)
        );
    }

    #[test]
    fn a_short_path_under_a_root_is_not_reported() {
        let report = inspect(
            &paths(&["a/b.txt"]),
            Some(Path::new("/tmp/restore")),
            Audience::ThisPlatform,
        );
        assert!(report.is_clean());
    }

    #[test]
    fn blocked_paths_are_counted_once_however_many_ways_they_fail() {
        // An operator needs "how many files", not "how many complaints".
        let report = inspect_here(&["aux\u{7}:x."]);
        assert!(report.findings.len() > 1, "expected several findings");
        assert_eq!(report.blocked_paths().len(), 1);
        assert!(report.blocks("aux\u{7}:x."));
        assert!(!report.blocks("something-else"));
    }

    #[test]
    fn the_report_is_deterministic() {
        // Two runs over the same set must be byte-identical, or the report
        // cannot be diffed between machines.
        let list = ["z:1", "a:2", "m:3"];
        let first = inspect_here(&list);
        let second = inspect_here(&list);
        assert_eq!(
            serde_json::to_string(&first).unwrap(),
            serde_json::to_string(&second).unwrap()
        );
        let ordered: Vec<&str> = first.findings.iter().map(|f| f.path.as_str()).collect();
        let mut sorted = ordered.clone();
        sorted.sort_unstable();
        assert_eq!(ordered, sorted);
    }
}
