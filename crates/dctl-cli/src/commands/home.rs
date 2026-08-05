//! `dctl home` — everything DCTL keeps on this machine, and whether it is well.
//!
//! `~/.dctl` is the whole of what a client machine holds: the configuration,
//! the encrypted indexes, the tamper-evident audit chain, the logs. When
//! something is wrong, that directory is where the answer is — and until this
//! command there was no way to ask what was in it, where, or whether it was
//! healthy. An operator had to know the layout by heart and `ls` it.
//!
//! So this prints the layout as it *actually resolves on this machine*, not as
//! the documentation describes it, which is the distinction that matters when
//! the two have drifted apart — and they had: the audit chain was living inside
//! the index directory, and the home directory was world-readable.
//!
//! ## What it deliberately does not do
//!
//! It reads. It creates nothing, repairs nothing and asks for no password: a
//! command run *because* something is wrong must not be able to make it worse,
//! and a diagnostic that needs the vault to be openable is no use when the vault
//! is the thing that will not open. Every check here is a `stat` or a read.
//!
//! It also prints no secret. The configuration file is listed by path and size,
//! never by content — `dctl config redact` is the command for that, and it
//! exists so a bug report can carry the settings without carrying the keys.

use clap::Args;

use crate::constants::{
    HOME_ACCESS_OPEN, HOME_ACCESS_OWNER_ONLY, HOME_COLUMN_ACCESS, HOME_COLUMN_DETAIL,
    HOME_COLUMN_PATH, HOME_COLUMN_STATE, HOME_COLUMN_WHAT, HOME_DETAIL_ON_FIRST_USE,
    HOME_ROW_AUDIT, HOME_ROW_CACHE, HOME_ROW_CONFIG, HOME_ROW_HOME, HOME_ROW_INDEX, HOME_ROW_LOGS,
    HOME_STATE_ABSENT, HOME_STATE_PRESENT, HOME_STATE_WRONG_KIND,
};
use crate::ctx::Ctx;
use crate::error::Result;
use crate::output::{Align, Border, Column, Table, Units, size};

/// The verb this module implements.
const VERB: &str = "home";

/// Arguments for `dctl home`.
#[derive(Args, Debug)]
pub struct HomeArgs {
    /// Also report the size of each directory's contents.
    ///
    /// Off by default because it walks: an index directory is small, but a
    /// logs directory somebody has never rotated may not be, and a diagnostic
    /// should answer instantly.
    #[arg(long)]
    pub sizes: bool,
}

/// One thing DCTL keeps, and what was found at its path.
struct Entry {
    what: &'static str,
    path: std::path::PathBuf,
    /// What the filesystem says: present, missing, or the wrong shape.
    state: String,
    /// Mode, on platforms that have one, plus a warning when it is open.
    access: String,
    detail: String,
}

/// Report the layout.
///
/// # Errors
/// Only a failure to render. A missing directory is a *finding*, not an error:
/// a fresh machine has none of them, and reporting that as a failure would make
/// the first run of a diagnostic look like a fault.
pub fn run(ctx: &Ctx, args: &HomeArgs) -> Result<()> {
    let home = dctl_meta::paths::home_dir();
    let config = crate::config::resolve_path(ctx.globals.config.as_deref());
    let index = crate::session::index::path(ctx);
    let audit = crate::commands::audit::source::resolve_path(&ctx.globals, None);

    let entries = vec![
        describe(HOME_ROW_HOME, home.clone(), Shape::Directory, args.sizes),
        describe(HOME_ROW_CONFIG, config, Shape::File, args.sizes),
        describe(HOME_ROW_INDEX, index, Shape::File, args.sizes),
        describe(HOME_ROW_AUDIT, audit, Shape::File, args.sizes),
        describe(
            HOME_ROW_CACHE,
            dctl_meta::paths::cache_dir(),
            Shape::Directory,
            args.sizes,
        ),
        describe(
            HOME_ROW_LOGS,
            dctl_meta::paths::logs_dir(),
            Shape::Directory,
            args.sizes,
        ),
    ];

    let mut table = Table::new(vec![
        Column::new(HOME_COLUMN_WHAT, Align::Left),
        Column::new(HOME_COLUMN_PATH, Align::Left),
        Column::new(HOME_COLUMN_STATE, Align::Left),
        Column::new(HOME_COLUMN_ACCESS, Align::Left),
        Column::new(HOME_COLUMN_DETAIL, Align::Left),
    ])
    .with_border(Border::Header);
    for entry in &entries {
        table.push(vec![
            entry.what.to_string(),
            entry.path.display().to_string(),
            entry.state.clone(),
            entry.access.clone(),
            entry.detail.clone(),
        ]);
    }
    ctx.out.table(&table)?;

    // The one thing worth saying out loud rather than leaving in a column: a
    // home directory anyone can read is a list of which vaults this machine
    // can reach, and that is the fact the mode exists to keep.
    for entry in &entries {
        if entry.access.contains(HOME_ACCESS_OPEN) {
            ctx.out.warn(format!(
                "{} is readable by other users on this machine: {}",
                entry.what,
                entry.path.display()
            ));
        }
    }

    ctx.out.info(format!(
        "{VERB}: {} — set DCTL_HOME to keep all of it somewhere else",
        home.display()
    ));
    Ok(())
}

/// Whether a path is expected to be a directory or a file.
enum Shape {
    Directory,
    File,
}

/// Look at one path and say what is there.
fn describe(what: &'static str, path: std::path::PathBuf, shape: Shape, sizes: bool) -> Entry {
    let Ok(meta) = std::fs::metadata(&path) else {
        return Entry {
            what,
            path,
            state: HOME_STATE_ABSENT.to_string(),
            access: String::new(),
            // Absence is ordinary here and says so, because the first run of a
            // diagnostic on a fresh machine must not read as a fault.
            detail: HOME_DETAIL_ON_FIRST_USE.to_string(),
        };
    };

    let wrong_shape = match shape {
        Shape::Directory => !meta.is_dir(),
        Shape::File => !meta.is_file(),
    };
    let state = if wrong_shape {
        HOME_STATE_WRONG_KIND.to_string()
    } else {
        HOME_STATE_PRESENT.to_string()
    };

    let detail = match shape {
        Shape::File => size::bytes(meta.len(), Units::Binary),
        Shape::Directory if sizes => {
            let (files, bytes) = walk(&path);
            format!("{files} files, {}", size::bytes(bytes, Units::Binary))
        }
        Shape::Directory => String::new(),
    };

    Entry {
        what,
        path,
        state,
        access: access_of(&meta),
        detail,
    }
}

/// The mode, and whether it lets anybody else in.
#[cfg(unix)]
fn access_of(meta: &std::fs::Metadata) -> String {
    use std::os::unix::fs::PermissionsExt;

    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 == 0 {
        format!("{mode:o} {HOME_ACCESS_OWNER_ONLY}")
    } else {
        format!("{mode:o} {HOME_ACCESS_OPEN}")
    }
}

/// See the Unix definition. Access is an ACL here, not a mode.
#[cfg(not(unix))]
fn access_of(_meta: &std::fs::Metadata) -> String {
    String::new()
}

/// Count what is under `root`, without following links out of it.
fn walk(root: &std::path::Path) -> (u64, u64) {
    let (mut files, mut bytes) = (0, 0);
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(meta) = entry.metadata() else { continue };
            if meta.is_dir() {
                stack.push(entry.path());
            } else if meta.is_file() {
                files += 1;
                bytes += meta.len();
            }
        }
    }
    (files, bytes)
}
