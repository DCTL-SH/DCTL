//! One module per subcommand.
//!
//! Each module owns exactly one verb from [`crate::cli::Command`] and exposes
//! the same two items — an `Args` struct clap flattens into the command tree,
//! and an `async fn run(&Ctx, &Args) -> Result<()>` that [`crate::dispatch`]
//! calls. Nothing else is public, so a command can be rewritten from the inside
//! without touching the router.
//!
//! A verb that needs real helper logic gets a **directory** rather than a
//! grab-bag file: `verify/mod.rs` holds the arguments and the run body, and its
//! siblings hold the pieces that deserve their own tests. That keeps the
//! interesting logic — how two sides are compared, which objects a sample
//! selects, how a checksum line is spelled — reachable from a unit test without
//! a vault, a network, or a process.
//!
//! A module that carries no verb of its own is a **family**: logic several
//! commands must implement identically, kept in one place so a lapse in it is
//! impossible to make in only one command. [`removal`] is the first — the
//! destructive-gate, target and plan vocabulary shared by `delete`,
//! `deletefile`, `purge`, `rmdir`, `rmdirs` and `cleanup`. [`pipeline`] is the
//! second, and covers the two commands whose stdout and stdin *are* the payload:
//! `cat` and `rcat`. [`transfer`] is the third, and the largest: the endpoint
//! parsing, listing, comparison, plan and verified-write stage walk behind
//! `copy`, `move`, `sync`, `copyto` and `moveto`. Those five differ only in
//! whether the destination may lose files, whether the source is deleted
//! afterwards, and whether `DEST` names a container or an exact object —
//! everything else is one implementation, because a comparison rule fixed in
//! `copy` and missed in `sync` is a rule that deletes data. [`directory`] is the
//! smallest: the target, marker-naming and plan vocabulary behind `mkdir` and
//! `touch`, the two verbs that give an object store the directories and
//! modification times it does not have. [`listing`] is the fourth: the spec
//! grammar, glob filters, paged entry cursor and column vocabulary behind `ls`,
//! `lsd`, `lsl`, `lsjson`, `tree` and `size`. Those six answer the same question
//! and differ only in how they render it, so sharing the scope logic is what
//! stops `dctl size` and `dctl ls` from reporting different vaults.
//! [`recovery`] is the fifth: the vault-location parsing, point-in-time
//! spellings, snapshot naming, name pre-flight and plan vocabulary behind
//! `audit`, `backup` and `restore`. Its pre-flight is the reason it is shared —
//! a name check that runs on restore but not on backup would find the problem
//! years after the moment it could have been fixed (`PLAN.md` §13.6).
//!
//! Note that the module for `move` is [`mv`]: `move` is a Rust keyword. The verb
//! the user types and the `MoveArgs` type both keep the real name.

pub mod about;
pub mod audit;
pub mod backup;
pub mod cat;
pub mod check;
pub mod cleanup;
pub mod completion;
pub mod config;
pub mod copy;
pub mod copyto;
pub mod delete;
pub mod deletefile;
pub mod directory;
pub mod hashsum;
pub mod index;
pub mod init;
pub mod integrity;
pub mod listing;
pub mod ls;
pub mod lsd;
pub mod lsjson;
pub mod lsl;
pub mod mkdir;
pub mod mount;
pub mod moveto;
pub mod mv;
pub mod pipeline;
pub mod purge;
pub mod rcat;
pub mod recovery;
pub mod removal;
pub mod replicate;
pub mod restore;
pub mod rmdir;
pub mod rmdirs;
pub mod scrub;
pub mod size;
pub mod sync;
pub mod touch;
pub mod transfer;
pub mod tree;
pub mod verify;
pub mod version;
