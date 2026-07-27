//! The listing family and the transfer family must select the same files.
//!
//! This module contains nothing but the test that proves it, and it exists as a
//! file of its own because the property it pins belongs to neither family. It is
//! a statement *about the pair*, and a statement about a pair that lives inside
//! one of them is a statement the other can be changed without noticing.
//!
//! ## Why this is worth a module
//!
//! `dctl ls --exclude 'private/**' archive:` is what a person reads before
//! deciding what is safe to delete from the source, and `dctl copy --exclude
//! 'private/**' ./tree archive:` is what they run afterwards. If the two
//! disagree, one of two things happens:
//!
//! * the listing *shows* a file the copy omits — the operator deletes their only
//!   copy of something they were told had been stored;
//! * the listing *hides* a file the copy transfers — during a `sync`, the same
//!   divergence on the destination side makes the file an "extra" and deletes
//!   it.
//!
//! Both are data loss produced by two implementations of one flag. There is
//! therefore exactly one implementation ([`crate::filter`]), and both families
//! reach it through a thin adapter — [`super::filter`] here, `ListOptions` there.
//! An adapter is small enough to look obviously correct and small enough to be
//! quietly wrong: it decides which of an entry's two path spellings the engine
//! is offered, whether a directory is presented as a directory, and what a size
//! of zero means. This test is the thing that would catch it.
//!
//! ## What is compared, and what is deliberately not
//!
//! The **set of files selected**, over a real tree on disk, for rule sets that
//! exercise every dial: bare-name patterns, anchored patterns, component-suffix
//! patterns, the implicit exclusion that `--include` arms, size bounds, depth
//! limits, a rule file and a path list.
//!
//! Not compared: ordering (the transfer family sorts, the listing family follows
//! the source's order and both are deterministic), directory rows (only `lsd`
//! and `tree` synthesise them, and a transfer has no equivalent), or the
//! metadata each side carries. Those genuinely differ, for reasons the two
//! families document. The file set is the part that must not.

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::Path;
    use std::sync::Arc;

    use clap::Parser;
    use dctl_core::Vault;
    use dctl_store::{Backend, LocalFs};
    use tempfile::TempDir;

    use crate::cli::globals::GlobalArgs;
    use crate::commands::listing::{self, Filter, Target};
    use crate::commands::transfer::listing::{ListOptions, source as transfer_source};
    use crate::ctx::Ctx;
    use crate::remote::RemoteSpec;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn ctx(args: &[&str]) -> Ctx {
        Ctx::new(Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied())).globals)
    }

    /// The tree both families are pointed at.
    ///
    /// Chosen so that every rule below separates it differently: files at three
    /// depths, two extensions, a `tmp` directory both at the root and nested, a
    /// directory whose name merely *ends* in `tmp`, and a spread of sizes that
    /// straddles a 1 KiB bound.
    const TREE: &[(&str, usize)] = &[
        ("notes.txt", 10),
        ("a.jpg", 2048),
        ("photos/b.jpg", 4096),
        ("photos/small.jpg", 100),
        ("photos/2024/c.jpg", 8192),
        ("photos/2024/notes.txt", 20),
        ("photos/tmp/scratch.jpg", 512),
        ("photos-tmp/keep.jpg", 512),
        ("tmp/scratch.txt", 30),
        ("private/secret.txt", 40),
    ];

    /// Write [`TREE`] into a fresh temporary directory.
    fn tree() -> TempDir {
        let root = TempDir::new().expect("a temporary directory");
        for (relative, size) in TREE {
            let path = root.path().join(relative);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("the parent directory is created");
            }
            std::fs::write(&path, vec![b'x'; *size]).expect("the fixture file is written");
        }
        root
    }

    /// The files the **listing** family selects under `flags`.
    async fn listed(root: &Path, flags: &[&str]) -> BTreeSet<String> {
        let context = ctx(flags);
        let spelled = root.to_string_lossy().into_owned();
        let target = Target::parse(Some(&spelled), None).expect("the target parses");
        let filter = Filter::from_globals(&context.globals).expect("the flags compile");
        let mut stream = listing::open(&context, &target, filter)
            .await
            .expect("the directory lists");

        let mut selected = BTreeSet::new();
        stream
            .try_for_each(|entry| {
                selected.insert(entry.relative().to_string());
                Ok(())
            })
            .await
            .expect("the listing completes");
        selected
    }

    /// The files the **transfer** family selects under the same flags.
    async fn transferred(root: &Path, flags: &[&str]) -> BTreeSet<String> {
        let context = ctx(flags);
        let options = ListOptions::resolve(&context.globals, false).expect("the flags compile");
        let listing = transfer_source(&context, &RemoteSpec::Local(root.to_path_buf()), &options)
            .await
            .expect("the directory walks");

        listing
            .entries
            .into_iter()
            .filter(|entry| entry.is_file())
            .map(|entry| entry.path)
            .collect()
    }

    /// Every rule set the two families are held to.
    ///
    /// Each one is chosen because it is a way an adapter could plausibly be
    /// wrong: matching the wrong path spelling, forgetting the implicit
    /// exclusion, applying a size bound to the wrong thing, or counting depth
    /// from the wrong root.
    fn rule_sets() -> Vec<(&'static str, Vec<&'static str>)> {
        vec![
            ("no filters at all", vec![]),
            ("a bare-name include", vec!["--include", "*.jpg"]),
            ("a bare-name exclude", vec!["--exclude", "*.txt"]),
            ("an anchored include", vec!["--include", "/photos/**"]),
            ("an anchored exclude", vec!["--exclude", "/tmp/**"]),
            ("a component-suffix exclude", vec!["--exclude", "tmp/**"]),
            ("a directory-only exclude", vec!["--exclude", "tmp/"]),
            (
                "the mixed form that drops what neither names",
                vec!["--include", "*.jpg", "--exclude", "*.png"],
            ),
            (
                "an include and an exclude that overlap",
                vec!["--include", "**", "--exclude", "private/**"],
            ),
            (
                "two includes as a union",
                vec!["--include", "*.jpg", "--include", "notes.txt"],
            ),
            ("a minimum size", vec!["--min-size", "1K"]),
            ("a maximum size", vec!["--max-size", "1K"]),
            (
                "both size bounds",
                vec!["--min-size", "1K", "--max-size", "4K"],
            ),
            ("a depth limit", vec!["--max-depth", "1"]),
            ("a deeper depth limit", vec!["--max-depth", "2"]),
            (
                "every dial at once",
                vec![
                    "--include",
                    "*.jpg",
                    "--exclude",
                    "tmp/**",
                    "--min-size",
                    "1K",
                    "--max-depth",
                    "2",
                ],
            ),
        ]
    }

    #[tokio::test]
    async fn the_listing_family_and_the_transfer_family_select_the_same_files() {
        // The property this module exists for. A file included by `ls` and
        // excluded by the `copy` that follows it is data loss with a reporting
        // bug's shape.
        let root = tree();

        for (description, flags) in rule_sets() {
            let listed = listed(root.path(), &flags).await;
            let transferred = transferred(root.path(), &flags).await;
            assert_eq!(
                listed,
                transferred,
                "the two families disagree about {description} ({flags:?})\n\
                 only the listing showed: {:?}\n\
                 only the transfer took:  {:?}",
                listed.difference(&transferred).collect::<Vec<_>>(),
                transferred.difference(&listed).collect::<Vec<_>>(),
            );
        }
    }

    #[tokio::test]
    async fn the_rule_sets_actually_separate_the_tree() {
        // Guards the test above from passing vacuously. Two families that both
        // selected everything, or both selected nothing, would agree perfectly
        // and prove nothing at all.
        let root = tree();
        let everything = listed(root.path(), &[]).await;
        assert_eq!(everything.len(), TREE.len(), "the fixture is fully listed");

        for (description, flags) in rule_sets() {
            if flags.is_empty() {
                continue;
            }
            let selected = listed(root.path(), &flags).await;
            assert!(
                !selected.is_empty(),
                "{description} selected nothing, so it proves nothing"
            );
            assert!(
                selected.len() < everything.len(),
                "{description} selected everything, so it proves nothing"
            );
        }
    }

    #[tokio::test]
    async fn a_rule_file_and_a_path_list_agree_across_the_two_families() {
        // Separated from the table because both need a file on disk, and because
        // this pair is the one the listing family refused outright until the one
        // engine was wired in — the case most likely to have been left behind.
        let root = tree();
        let rules = root.path().join("dctl-rules.txt");
        std::fs::write(&rules, "- /photos/tmp/**\n+ /photos/**\n- **\n").expect("rules written");
        let list = root.path().join("dctl-list.txt");
        std::fs::write(&list, "notes.txt\nphotos/2024/c.jpg\n").expect("list written");

        // Both control files live in the tree, so they would themselves be
        // listed; the rule file's own patterns and the path list's contents
        // exclude them, which is what keeps the comparison about the fixture.
        let rules = rules.to_string_lossy().into_owned();
        let list = list.to_string_lossy().into_owned();

        for flags in [
            vec!["--filter-from", rules.as_str()],
            vec!["--files-from", list.as_str()],
        ] {
            let listed = listed(root.path(), &flags).await;
            let transferred = transferred(root.path(), &flags).await;
            assert!(!listed.is_empty(), "{flags:?} selected nothing");
            assert_eq!(
                listed, transferred,
                "the two families disagree on {flags:?}"
            );
        }
    }

    #[tokio::test]
    async fn the_two_families_agree_about_a_sealed_vault_too() {
        // The local walk and the remote listing are different code paths on the
        // transfer side, and only one of them is exercised above. A vault also
        // reports plaintext sizes from its index rather than from `stat`, which
        // is what the size bounds are applied to.
        let dir = TempDir::new().expect("a temporary directory");
        let store = dir.path().join("store");
        std::fs::create_dir_all(&store).expect("the store directory");
        let index = dir.path().join("index.redb");

        {
            let backend: Arc<dyn Backend> = Arc::new(LocalFs::new(&store));
            let vault = Vault::init(backend, &index, "pw")
                .await
                .expect("a fresh vault initialises")
                .vault;
            for (path, size) in TREE {
                vault
                    .put_file(path, &vec![b'x'; *size])
                    .await
                    .expect("a verified write");
            }
        }

        let config = dir.path().join("config.toml");
        std::fs::write(
            &config,
            format!(
                "[remotes.store]\ntype = \"local\"\npath = {:?}\nrequire_vault = true\n\n\
                 [remotes.archive]\ntype = \"vault\"\nbase = \"store\"\n",
                store.to_string_lossy()
            ),
        )
        .expect("the configuration is written");

        let config = config.to_string_lossy().into_owned();
        let index = index.to_string_lossy().into_owned();
        let credentials = [
            "--config",
            config.as_str(),
            "--index",
            index.as_str(),
            "--password",
            "pw",
        ];

        for (description, rules) in rule_sets() {
            let mut flags: Vec<&str> = credentials.to_vec();
            flags.extend_from_slice(&rules);

            let context = ctx(&flags);
            let target = Target::parse(Some("archive:"), None).expect("the target parses");
            let filter = Filter::from_globals(&context.globals).expect("the flags compile");
            let mut stream = listing::open(&context, &target, filter)
                .await
                .expect("the vault lists");
            let mut listed = BTreeSet::new();
            stream
                .try_for_each(|entry| {
                    listed.insert(entry.relative().to_string());
                    Ok(())
                })
                .await
                .expect("the listing completes");

            let context = ctx(&flags);
            let options = ListOptions::resolve(&context.globals, false).expect("the flags compile");
            let taken = transfer_source(
                &context,
                &RemoteSpec::Named {
                    remote: "archive".to_string(),
                    path: String::new(),
                },
                &options,
            )
            .await
            .expect("the vault walks");
            let transferred: BTreeSet<String> = taken
                .entries
                .into_iter()
                .filter(|entry| entry.is_file())
                .map(|entry| entry.path)
                .collect();

            assert_eq!(
                listed, transferred,
                "the two families disagree about {description} over a sealed vault ({rules:?})"
            );
        }
    }
}
