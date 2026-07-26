//! From a command-line argument to a live storage backend.
//!
//! Three steps, each its own file, because each fails for a different reason and
//! is tested against a different kind of input:
//!
//! | Step | File | Question it answers | Failure |
//! |------|------|---------------------|---------|
//! | Parse | [`spec`] | Is this a remote or a path, and where does it split? | usage (exit 1) |
//! | Resolve | [`resolve`] | Which remote is that, and is it fully configured? | config (exit 7) |
//! | Build | [`registry`] | What backend implements it, with which credentials? | config (exit 7) |
//!
//! ```text
//!   "vault:photos/2024"
//!        │  RemoteSpec::parse      ← splitting rules, drive letters, NFC
//!        ▼
//!   RemoteSpec::Named { remote: "vault", path: "photos/2024" }
//!        │  resolve(&spec, &config) ← named remotes, provider shorthands
//!        ▼
//!   Resolved { name: "vault", target: Target::B2 { .. }, path: "photos/2024" }
//!        │  build(&resolved)       ← credentials from the environment
//!        ▼
//!   Arc<dyn Backend>
//! ```
//!
//! The split is what keeps the dangerous parts honest. Parsing is pure and has
//! no idea what a bucket is, so the Windows drive-letter rule — the one bug in
//! this area that silently writes data to the wrong place — is decided by a
//! function with no I/O and exhaustive tests. Resolution is pure too, taking the
//! configuration through the [`resolve::RemoteCatalog`] trait, so a command's
//! tests need a map literal rather than a TOML file. Only
//! [`registry::build`] touches the outside world, which is why a `--dry-run`
//! can name a remote it has no credentials for without failing.
//!
//! Callers normally run all three:
//!
//! ```ignore
//! let spec = RemoteSpec::parse(argument)?;
//! let resolved = remote::resolve::resolve(&spec, config)?;
//! let backend = remote::registry::build(&resolved)?;
//! ```
//!
//! A fourth module sits beside the pipeline rather than inside it. [`envelope`]
//! answers "does this store already hold a vault?" from a built backend, without
//! a password and without decrypting anything — the check `dctl init` needs
//! before it overwrites a root key, and the one `dctl config import` needs
//! before it writes addressing for a location that may hold nothing at all.
//!
//! Only the two names a command actually types are re-exported here:
//! [`RemoteSpec`], which every command parses its arguments with, and
//! [`build_backend`], which runs all three steps for the specs that need no
//! configuration. The middle of the pipeline is addressed through its own
//! module path, so a caller that reaches past `build_backend` says so at the
//! call site instead of looking like it took the ordinary route.

pub mod envelope;
pub mod registry;
pub mod resolve;
pub mod spec;

pub use registry::build_backend;
pub use spec::RemoteSpec;
