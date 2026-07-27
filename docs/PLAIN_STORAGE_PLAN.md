All twenty critique facts check out against the source (the empty-catalog `&()` resolve in `session/open.rs:127`, the `PROVIDER_VAULT` hard-error at `resolve.rs:285`, the index-driven `vault/get.rs`/`list.rs`, the `index_records → Ok(None)` stub at `listing/source.rs:173`, `vfs_cache_mode` defaulting `Off`, `TRANSFER_WHOLE_FILE_LIMIT = 1 GiB` at `constants.rs:1760`, `put_multipart(key, data: &[u8])` buffering the whole object, and `about/target.rs` already modeling plain-vs-Vault via `config::vault_chain`). Here is the folded, corrected blueprint.

---

# DCTL — Plain-Storage rclone Parity: Final Buildable Blueprint

**Architect's decision (unchanged, and confirmed dyn-safe by review).** Extend the existing `Backend` trait with optional capability traits, and make the Vault a `Backend` via a `VaultBackend` overlay, so plain and encrypted remotes are the same abstraction. The critique validated the trait model and capability dispatch (D8); it did **not** validate the *plumbing* the milestones sat on. This revision keeps the architecture and rebuilds the build plan around a new prerequisite milestone that unifies DCTL's two divergent resolution systems, re-specifies the `Backend` contract for the Vault overlay in a hash-domain-safe way, and fixes a concurrency seam that could not compile.

**What changed from the reviewed draft (traceability):**
- The two inconsistent resolvers (`about/target.rs` sees config + Vaults; `session/open.rs` resolves against the empty catalog `&()` and `resolve.rs` hard-errors on `type=vault`) are unified in a new **Milestone 1** — a prerequisite for listing a config remote and for not leaking plaintext (D1, D2, D15, D18).
- The `Backend` hash contract is redefined over the **logical object** (`get`'s return), which makes plain↔Vault comparison correct instead of comparing ciphertext-vs-plaintext (D3).
- `VaultBackend` is documented as **index-backed**, with ranged reads doing the mandatory `index→file_id` lookup and full-read integrity restored (D4, D5, D12).
- The non-object-safe `Spawner` is dropped for `buffer_unordered`; a separate object-safe `CpuOffload` seam handles CPU-bound crypto (D6, D7).
- `caps()` defaults to `Caps::empty()` (D8); version pins corrected and `deny.toml` mandated (D9, D10); mount default reconciled with the write-refusal rule (D11); `VaultBackend` pulled forward to Milestone 4 to collapse the dual-engine window (D16); FUSE captures the runtime `Handle` (D17); TLS/crypto-provider rationale corrected (D19); server-copy ceilings and real S3 multipart streaming scheduled as work, not wiring (D20).

---

## A. Trait model — extended `Backend` + optional capability traits

### A.1 The core trait stays; it is extended additively

The 8 methods (`name/put/get/get_range/head/exists/delete/list_page`) and the two invariants are unchanged for plain backends. We **redefine the hash domain** of those invariants precisely (resolves D3), then add one advertisement method and ten capability accessors, each defaulted so `local/s3/b2/r2` keep compiling.

> **Hash-domain contract (normative, resolves D3).** `expected`, `PutOutcome.verified`, and `ObjectMeta.hash` are hashes of the **logical object bytes that `get(key)` returns** — *not* the on-wire stored bytes. For plain backends `get` returns exactly the stored bytes, so nothing changes: the verified-write invariant still hashes what is physically stored. For `VaultBackend`, `get` returns plaintext, so its hash domain is plaintext. This is what makes `equal`/`common_hash` correct across a plain↔Vault transfer: both endpoints expose the hash of the *decrypted logical file*, never one plaintext vs one ciphertext. `dctl-ops` may therefore compare `common_hash` across any two `Backend`s without knowing whether either is a Vault.

```rust
// crates/dctl-store/src/backend.rs  (additions to the existing trait)
pub trait Backend: Send + Sync {
    // ... existing 8 methods unchanged; doc-comment updated to the hash-domain
    //     contract above (hash is over the logical object get() returns) ...

    /// Cheap static advertisement — the Rust port of rclone `fs.Features` bool
    /// flags, for *planning* before any network op. Must agree with which `as_*`
    /// accessors return `Some` (asserted per-backend by a unit test).
    fn caps(&self) -> Caps { Caps::empty() }   // opt-in; nothing implied by default (D8)

    fn as_server_copy(&self)  -> Option<&dyn ServerCopy>  { None }
    fn as_server_move(&self)  -> Option<&dyn ServerMove>  { None }
    fn as_dir_ops(&self)      -> Option<&dyn DirOps>      { None }
    fn as_set_modtime(&self)  -> Option<&dyn SetModTime>  { None }
    fn as_remote_hasher(&self)-> Option<&dyn RemoteHasher>{ None }
    fn as_stream_read(&self)  -> Option<&dyn StreamRead>  { None }
    fn as_stream_write(&self) -> Option<&dyn StreamWrite> { None }
    fn as_range_write(&self)  -> Option<&dyn RangeWrite>  { None }  // sequential write-in-place (SFTP)
    fn as_about(&self)        -> Option<&dyn About>       { None }
    fn as_purger(&self)       -> Option<&dyn Purger>      { None }
}
```

The default `caps()` is now `Caps::empty()` (D8): a backend that forgets to override advertises **nothing**, never a false flat-keyspace. `S3/B2/R2` explicitly set `Caps::OBJECT_STORE_MINIMUM` (= `BUCKET_BASED`); `LocalFs` explicitly sets its real capabilities.

### A.2 The capability traits — new module `crates/dctl-store/src/capability.rs`

```rust
use bitflags::bitflags;                       // bitflags 2, MIT/Apache-2.0
use crate::model::{ObjectKey, ByteRange, PutOutcome};
use crate::checksum::{ContentHash, HashAlgo};
use crate::error::Result;

/// futures-core stream of body chunks — the seam that retires the whole-buffer
/// limit for PLAIN remotes. Owned by dctl-store so backends and ops share it.
pub type ByteStream = std::pin::Pin<Box<dyn futures_core::Stream<Item = Result<bytes::Bytes>> + Send>>;

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Caps: u32 {
        const SERVER_COPY   = 1 << 0;
        const SERVER_MOVE   = 1 << 1;
        const REAL_DIRS     = 1 << 2;  // holds empty dirs; has mkdir/rmdir
        const SET_MODTIME   = 1 << 3;
        const REMOTE_HASH   = 1 << 4;
        const STREAM_READ   = 1 << 5;
        const STREAM_WRITE  = 1 << 6;
        const WRITABLE_RANGE= 1 << 7;  // sequential write-in-place; only SFTP
        const ABOUT         = 1 << 8;
        const PURGE         = 1 << 9;
        const BUCKET_BASED  = 1 << 10; // flat keyspace, no true dirs (s3/b2/r2)
        const INDEX_BACKED  = 1 << 11; // listing/head reflect a local index, not
                                       // backend ground truth (VaultBackend) — D4
    }
}
impl Caps {
    pub const OBJECT_STORE_MINIMUM: Caps = Caps::BUCKET_BASED;
    /// rclone `Features.Mask`: a capability is usable across a transfer only if
    /// BOTH endpoints advertise it.
    #[must_use] pub fn mask(self, other: Caps) -> Caps { self.intersection(other) }
}

#[derive(Clone, Copy, Debug)] pub enum Overwrite { Replace, Fail }

#[derive(Clone, Copy, Debug, Default)]
pub struct Usage { pub total: Option<u64>, pub used: Option<u64>, pub free: Option<u64>, pub objects: Option<u64> }

#[async_trait::async_trait] pub trait ServerCopy: Send + Sync {
    async fn copy_object(&self, from: &ObjectKey, to: &ObjectKey, ow: Overwrite) -> Result<()>;
}
#[async_trait::async_trait] pub trait ServerMove: Send + Sync {
    async fn move_object(&self, from: &ObjectKey, to: &ObjectKey, ow: Overwrite) -> Result<()>;
}
#[async_trait::async_trait] pub trait DirOps: Send + Sync {
    async fn mkdir(&self, dir: &str) -> Result<()>;       // recursive, idempotent
    async fn rmdir(&self, dir: &str) -> Result<()>;       // must be empty (rclone semantics)
    async fn dir_exists(&self, dir: &str) -> Result<bool>;
}
#[async_trait::async_trait] pub trait SetModTime: Send + Sync {
    async fn set_modtime(&self, key: &ObjectKey, modified_unix: i64) -> Result<()>;
}
#[async_trait::async_trait] pub trait RemoteHasher: Send + Sync {
    fn supported(&self) -> &[HashAlgo];                   // FTP returns &[]
    async fn hash(&self, key: &ObjectKey, algo: HashAlgo) -> Result<Option<ContentHash>>;
}
#[async_trait::async_trait] pub trait StreamRead: Send + Sync {
    async fn open(&self, key: &ObjectKey, range: ByteRange) -> Result<ByteStream>;
}
#[async_trait::async_trait] pub trait StreamWrite: Send + Sync {
    async fn put_streaming(&self, key: &ObjectKey, body: ByteStream,
                           size: Option<u64>, expected: Option<&ContentHash>) -> Result<PutOutcome>;
}
#[async_trait::async_trait] pub trait RangeWrite: Send + Sync {          // SFTP only
    async fn write_at(&self, key: &ObjectKey, offset: u64, data: bytes::Bytes) -> Result<()>;
}
#[async_trait::async_trait] pub trait About:  Send + Sync { async fn about(&self) -> Result<Usage>; }
#[async_trait::async_trait] pub trait Purger: Send + Sync { async fn purge(&self, prefix: &str) -> Result<()>; }
```

Re-export from `crates/dctl-store/src/lib.rs`. Add `StoreError::Unsupported(&'static str)` to `error.rs` for read-only backends (`http`) and for absent capabilities that must **fail loudly** (PLAN §6), never no-op.

### A.3 A backend advertises only what it supports

```rust
// crates/dctl-store/src/sftp/mod.rs
impl Backend for SftpBackend {
    fn caps(&self) -> Caps {
        Caps::SERVER_MOVE | Caps::REAL_DIRS | Caps::SET_MODTIME
            | Caps::STREAM_READ | Caps::STREAM_WRITE | Caps::WRITABLE_RANGE | Caps::ABOUT
            | if self.shell.hashes.is_empty() { Caps::empty() } else { Caps::REMOTE_HASH }
    }
    fn as_server_move(&self)  -> Option<&dyn ServerMove>  { Some(self) }
    fn as_dir_ops(&self)      -> Option<&dyn DirOps>      { Some(self) }
    // ... one accessor per bit above; the caps()⇔accessor invariant is unit-tested
}
```

`LocalFs`/`S3Backend`/`B2Backend`/`R2Backend` change **only** to override the accessors they satisfy (S3/B2/R2 → `SERVER_COPY|SERVER_MOVE`; Local → `SERVER_MOVE|REAL_DIRS|SET_MODTIME`). Everything else inherits `None` and an empty `caps()`.

### A.4 The ONE feature-detection mechanism, and why it is dyn-safe (confirmed)

`Option<&dyn Cap>` accessors on `Backend`, backed by the `Caps` bitset for cheap planning. Ops detects **and invokes** via the vtable:

```rust
async fn move_one(src: &Endpoint, dst: &Endpoint, from: &ObjectKey, to: &ObjectKey) -> Result<()> {
    if same_remote(src, dst) {
        if let Some(m) = dst.backend.as_server_move() {
            return m.move_object(from, to, Overwrite::Replace).await;
        }
    }
    copy_one(src, dst, from, to).await?;    // fallback: copy + delete
    src.backend.delete(from).await
}
```

Object-safety justification (validated by the review, D8): every accessor is `fn(&self) -> Option<&dyn Trait>` — no generics, no `Self` by value — so `Backend` stays object-safe and `Arc<dyn Backend>` (the runtime-chosen type) survives; each capability trait is itself object-safe (`#[async_trait]` desugars to `Pin<Box<dyn Future>>`). Rejected: `Any`+`downcast` (recouples ops to concrete backends), `Caps` alone (a flag hands you no vtable), generic `fn copy<B: ServerCopy>` (no monomorphization behind `dyn`). `caps()` = rclone's `Features` bool flags; `as_*()` = its func-pointers; `Caps::mask` = `Features.Mask`.

### A.5 Metadata enrichment (deferred, additive)

`ObjectMeta` (currently `{ key, size, modified_unix, ... }`) gains two optional fields only when a consumer needs them (Milestone 5/6), via new constructors to localize churn:

```rust
pub struct ObjectMeta {
    pub key: ObjectKey, pub size: u64, pub modified_unix: Option<i64>,
    pub is_dir: bool,                 // dir-native backends round-trip this; buckets set false
    pub hash: Option<ContentHash>,    // logical-object hash (A.1 domain); populated when cheap
}
impl ObjectMeta {
    pub fn file(key: ObjectKey, size: u64, modified_unix: Option<i64>) -> Self { /* is_dir:false, hash:None */ }
    pub fn dir(key: ObjectKey) -> Self { /* size:0, is_dir:true */ }
}
```

The enumeration milestone does **not** touch `ObjectMeta`; the fields land with `check --checksum`/`lsd`.

---

## B. Crates & modules

### B.1 Placement (one concern per module, mirroring `s3/`/`b2/`)

```
crates/
  dctl-store/                 EXTEND
    src/capability.rs           NEW — Caps, capability traits, ByteStream, Usage
    src/pool/mod.rs             NEW — generic ConnPool<C: Poolable> (shared by sftp+ftp)
    src/path_map.rs             NEW — ObjectKey <-> POSIX/URL path; root join; traversal reject
    src/sftp/{mod,config,constants,conn,pool,auth,hostkey,read,write,listing,ops,hash}.rs   NEW
    src/ftp/{mod,config,constants,conn,pool,tls,read,write,listing,ops}.rs                  NEW
    src/webdav/{mod,config,constants,vendor,client,path,propfind,listing,transfer,api}.rs   NEW
    src/http/{mod,config,constants,dirpage,read}.rs                                          NEW (read-only)
    src/{backend,model,lib,error}.rs  EDIT — accessors, ObjectMeta fields, Unsupported, re-exports

  dctl-ops/                   NEW crate — runtime-agnostic operations/sync/march/check
    src/{lib,endpoint,walk,march,equal,fingerprint,hashes,copy,move_,transfer,check,
         concurrency,cpu,progress,options,constants}.rs
    src/sync/{mod,delete,rename,dirs}.rs

  dctl-vfs/                   NEW crate — runtime-agnostic VFS policy (node tree, cache SM, read-ahead)
    src/{lib,fs,backend_fs,node,dir,file,attr,inode,range,options,constants}.rs
    src/handle/{read,write,rw}.rs
    src/vfscache/{mod,item,downloaders,writeback,sparse,rangeset}.rs

  dctl-mount/                 NEW crate — tokio-edge FUSE adapter (fuser)
    src/{lib,fs,attr,handles,unmount}.rs

  dctl-serve/                 NEW crate — tokio-edge protocol servers over dctl-vfs
    src/{lib,http,webdav,sftp,ftp,nfs}.rs

  dctl-crypto/               EXTEND
    src/object/reader.rs        NEW — chunk-aware ranged decrypt (ObjectReader), inside object/
    src/object/seal.rs          EDIT — pub(crate) data_start() helper (D12)

  dctl-core/                 EXTEND
    src/vault/backend.rs        NEW — VaultBackend: impl Backend over a Vault (the overlay)

  dctl-cli/                  EXTEND
    src/remote/{resolve,registry}.rs   EDIT — single config-aware resolver; Vault base+wrap
    src/remote/classify.rs             NEW — Plain vs Vault off config::vault_chain (shared w/ about)
    src/remote/endpoint.rs             NEW — RemoteEndpoint -> (Arc<dyn Backend>, prefix) incl. VaultBackend
    src/constants.rs                   EDIT — PROVIDER_*, ENV_*, CONFIG_KEY_*, support tables
    src/commands/transfer/*            REWIRE onto dctl-ops (single engine)
    src/commands/{listing,cat,delete,...}/*   REWIRE onto dctl-ops
    src/commands/mount/engine.rs       NEW — build FsView, drive dctl-mount
    src/commands/serve/*               NEW — Command::Serve
    src/edge/{concurrency,cpu,accounting}.rs  NEW — tokio-edge impls injected into dctl-ops/dctl-vfs
```

### B.2 Dependency graph (compile order)

```
dctl-secmem  dctl-crypto  dctl-meta
        \        |          /
         \       |         /
          dctl-store ──────────────┐  (Backend + capability + all plain backends)
          /    |       \           │
dctl-index  dctl-ops   dctl-vfs    │
     |         |          \        │
 dctl-core ────┘        dctl-mount dctl-serve
 (Vault +               (fuser)    (axum/dav-server/russh/libunftp)
  VaultBackend)             \        /
          \                  \      /
           \__________________\____/
                    dctl-cli  (tokio edge: concurrency driver, CpuOffload, Accounting, Ctx)
```

Invariants: **`dctl-ops` and `dctl-vfs` depend only on `dctl-store`**, never on `dctl-core` — the Vault reaches them as an `Arc<dyn Backend>` (`VaultBackend`). **Neither calls `tokio::spawn` and neither depends on tokio**; concurrency is `futures::stream…buffer_unordered(n)`, and CPU-bound crypto is offloaded through an injected `CpuOffload` (D6, D7). `dctl-store` may use `tokio::{sync,time,fs}` (already does — local backend) for pools; the no-spawn rule is scoped to `dctl-core`, `dctl-ops`, `dctl-vfs`.

### B.3 New workspace dependencies (all MIT/Apache-2.0 unless noted; **versions to be pinned via `cargo add` at build time**, D10)

```toml
futures            = "0.3"     # MIT/Apache — Stream + buffer_unordered for ops/vfs
futures-core       = "0.3"     # MIT/Apache — ByteStream type in dctl-store
pin-project-lite   = "0.2"     # MIT/Apache — stream adapters
bitflags           = "2"       # MIT/Apache — Caps
httpdate           = "1"       # MIT/Apache — WebDAV/HTTP Last-Modified parsing
percent-encoding   = "2"       # MIT/Apache — WebDAV/HTTP URL segment encoding
russh              = "0.62"    # Apache-2.0    (verify crypto-provider feature name via `cargo add`)
russh-sftp         = "2.3"     # Apache-2.0
suppaftp           = { version = "10", default-features = false, features = ["tokio","tokio-rustls-ring","async-secure"] } # MIT/Apache
tl                 = "0.7"     # MIT — HTML dir-index anchors (http backend); optional
http-auth          = "0.1"     # MIT/Apache — WebDAV Digest; optional
fuser              = "0.18"    # MIT      (was mis-pinned 0.15)
axum               = "0.8"     # MIT — serve http
hyper              = "1"       # MIT
tower-http         = "0.6"     # MIT
dav-server         = "0.11"    # MIT/Apache — serve webdav   (was mis-pinned 0.7)
libunftp           = "0.23"    # Apache-2.0 — serve ftp       (was mis-pinned 0.20)
unftp-sbe-fs       = "0.3"     # Apache-2.0 — libunftp storage backend
nfsserve           = "0.11"    # BSD-3-Clause (permissive; experimental for MATURITY, not license) — was mis-pinned 0.10
```

`dctl-store` feature-gates the heavy backends:

```toml
[features]                         # crates/dctl-store/Cargo.toml
default = ["webdav", "http"]       # zero-new-heavy-dep backends on by default
sftp = ["dep:russh", "dep:russh-sftp"]
ftp  = ["dep:suppaftp"]
webdav = ["dep:httpdate", "dep:percent-encoding", "dep:http-auth"]
http = ["dep:httpdate", "dep:percent-encoding", "dep:tl"]
```

**`deny.toml` is a new required file** (none exists today, D10). CI gates on `cargo deny check`. It must explicitly allow the non-copyleft, non-SPDX or bundled licenses in the tree (see the corrected ledger in §Licenses).

**Boundary de-duplication (D18):** the two `Target` types (`remote::registry::Target`, `commands::listing::target::Target`) and the two config-remote representations (`resolve::RemoteEntry` built only under `cfg(test)` vs `config::load`'s real definitions with `is_vault()`/`vault_chain`) are collapsed into the single resolver produced in Milestone 1; `about`'s static `BACKEND_CAPABILITIES` matrix is rewired to derive from `Backend::caps()` (single source of truth) once `Caps` exists.

---

## C. Per-backend plan (sftp, ftp, webdav, http)

Common shape: each backend is a directory mirroring `b2/` — `mod.rs` (thin `impl Backend` + capability accessors), `config.rs` (non-secret `Debug` config; secret half a separate non-`Debug` type), `constants.rs` (every literal), and split op files. Keys map to remote paths via the shared `path_map.rs` (rejects `..`/NUL/absolute; joins under configured root). `list_page` is the flat recursive walk + sorted-cursor pattern proven in `local/walk.rs`. Verified writes use the three-phase temp→verify→publish discipline; verification differs per protocol (below). All secrets arrive via `DCTL_*` env through `registry::build`, never config.

> **Corrected TLS/crypto rationale (D19).** The workspace's active provider is `rustls_post_quantum::provider()` (AWS-LC-rs backed — `crates/dctl-store/src/tls.rs:20`), and the lockfile **already contains both `aws-lc-rs 1.17` and `ring 0.17`**. Selecting `ring`/`tokio-rustls-ring` for russh/suppaftp does **not** "share the workspace provider" — it leans on the already-present `ring`. Preferred: if russh/suppaftp expose an `aws-lc-rs` feature, use it to consolidate on one backend; otherwise accept `ring` as a documented, already-present second backend. The old ledger's "no OpenSSL" is inaccurate: AWS-LC (via `aws-lc-sys`) vendors OpenSSL/SSLeay-licensed files — these are **permissive (BSD-style), not copyleft**, so not a blocker, but `deny.toml` must allow them. WebDAV/HTTP reusing `crate::tls::post_quantum_client()` (no new TLS dep) is the genuinely clean part.

### C.1 SFTP — `crates/dctl-store/src/sftp/`

- **Crates:** `russh 0.62` (Apache-2.0) + `russh-sftp 2.3` (Apache-2.0). No OpenSSL/libssh2 C FFI. Rejected `ssh2`/`async-ssh2-lite` (link libssh2+OpenSSL), `openssh-sftp-client` (spawns system `ssh`; keep only as an optional `--sftp-ssh` external path later).
- **Method → protocol op:** `put`→mkParentDir (Stat+Mkdir walk, serialized by a per-path `StringLock`) → `OpenFile(tmp, WRONLY|CREATE|TRUNC)` + chunked write → verify → `posix-rename@openssh.com` (atomic) else remove+rename. `get`/`get_range`→`open`+`seek(offset)`+read (native ranged). `head`→`stat`. `exists`→`stat`. `delete`→`remove` (swallow missing). `list_page`→recursive `read_dir` walk.
- **Pooling/auth:** generic `pool::ConnPool<SshConn>` (§C.5); `auth.rs` (password, keyboard-interactive, key-file/PEM+passphrase, cert signer, ssh-agent); `hostkey.rs` verifies `known_hosts` in `client::Handler::check_server_key`. **DCTL default = strict host-key** (loud divergence from rclone's accept-any); `AcceptNew`/`Insecure` are explicit opt-outs.
- **Verified write:** prefer `RemoteHasher` (remote `sha256sum`/`b3sum` over an exec channel; empty-digest probe to detect + cache the tool); fall back to read-back-and-hash when the algo (e.g. BLAKE3) is unavailable; strict mode may hard-fail. Never silently skip.
- **Capabilities:** `ServerMove`, `DirOps`, `SetModTime`, `RemoteHasher` (detected tool set), `StreamRead`, `StreamWrite`, `RangeWrite` (sequential), `About` (`statvfs@openssh.com`).

### C.2 FTP / FTPS — `crates/dctl-store/src/ftp/`

- **Crate:** `suppaftp 10` (MIT/Apache), `default-features=false, features=["tokio","tokio-rustls-ring","async-secure"]`. Must **not** enable `native-tls`/`*-vendored` (pulls OpenSSL).
- **Method → op:** `put`→caller-hash guard → MKD-walk parents → `STOR tmp` (stream) → verify → `RNFR`/`RNTO`. `get`/`get_range`→`REST offset`+`RETR`. `head`→`MLST` else parent `LIST`+match. `delete`→`DELE`. `list_page`→recursive `MLSD` (fallback `LIST`); handle "success for nonexistent dir" via a `dir_exists` recheck on empty listings.
- **Pooling/auth/tls:** generic `ConnPool<FtpConn>`; `tls.rs` builds per-connection rustls `ClientConfig` (implicit 990 vs explicit `AUTH TLS`).
- **Verified write:** FTP has **no server hash** — default verification = re-`RETR tmp` streamed into the expected hash. `SIZE`-only "trust" mode is opt-in + logged, never default.
- **Capabilities:** `ServerMove`, `DirOps`, `SetModTime` (MFMT/MDTM if supported), `StreamRead`, `StreamWrite`. `RemoteHasher::supported()` → `&[]`; no `ServerCopy`. Precision may be `NotSupported` ⇒ size-only compares (§D).

### C.3 WebDAV — `crates/dctl-store/src/webdav/`

- **Crates:** none new for transport — reuse `reqwest 0.12`+`quick-xml 0.37` through the mandatory `crate::tls::post_quantum_client()`. Add `httpdate`, `percent-encoding`, `http-auth` (Digest only). Rejected `reqwest_dav` (owns its client → breaks the PQ-TLS mandate + verified-write hook).
- **Verb map:** `head`/`exists`→`PROPFIND Depth:0`; `list_page`→`PROPFIND Depth:1` with a **BFS frontier cursor** (`postcard`-encoded `VecDeque<pending_dir>` as the opaque `next_cursor`) for constant-memory resumable recursive listing; `get`/`get_range`→`GET`(+`Range:`); `put`→`MKCOL` parents then `PUT`; `delete`→`DELETE`; `ServerCopy`→`COPY`; `ServerMove`→`MOVE` (absolute Destination, `Overwrite: T`).
- **Modules:** `client.rs` (reqwest wrapper: auth, headers, error mapping like `b2::parse_json`), `vendor.rs` (`setQuirks` port — Nextcloud/Owncloud/InfiniteScale/Sharepoint/Fastmail/Generic), `propfind.rs`+`api.rs` (207 Multistatus via the `s3/xml.rs` event-loop style, reusing `local_name`). Sharepoint cookie/NTLM out of scope v1 → `StoreError::Unsupported`.
- **Verified write:** Owncloud/Nextcloud → send `OC-Checksum: SHA1:<hex>` (2xx ⇒ verified); generic → `PROPFIND Depth:0` read-back of `getcontentlength` (+ `oc:checksums`/`ME:sha1hex` when present) vs `expected`; best-effort `DELETE` of partials on failure.
- **Capabilities:** `ServerCopy`, `ServerMove`, `DirOps`, `SetModTime` (X-OC-Mtime/PROPPATCH), `StreamRead`, `StreamWrite` (per vendor), `RemoteHasher` (Owncloud/Nextcloud SHA1/MD5 only).

### C.4 HTTP (read-only) — `crates/dctl-store/src/http/`

- **Crates:** reuse `reqwest`; `tl 0.7` (MIT) for `<a href>` dir-index parsing.
- **Verb map:** `get`/`get_range`→`GET`(+`Range:`); `head`→`HEAD` (or `GET` if `no_head`); `list_page`→`GET` the `/`-terminated dir URL, require `text/html`, extract same-host child anchors (reject `?`, scheme/host mismatch, not-under-base, embedded `/`), recurse with the WebDAV frontier cursor. **Mutating methods return `StoreError::Unsupported("http backend is read-only")`.** No capability accessors overridden; `caps()` = `Caps::empty()`.

### C.5 Shared connection pool — `crates/dctl-store/src/pool/mod.rs`

Port of rclone's `getSftpConnection`/`putSftpConnection`/`drainPool`, generic over `Poolable`:

```rust
#[async_trait] pub(crate) trait Poolable: Send + Sync + Sized + 'static {
    type Cfg: Send + Sync;
    async fn connect(cfg: &Self::Cfg) -> Result<Self>;
    async fn is_healthy(&mut self) -> bool;   // SFTP: realpath("."); FTP: NOOP
    async fn disconnect(self);
}
pub(crate) struct ConnPool<C: Poolable> {
    idle: tokio::sync::Mutex<Vec<C>>, permits: Option<tokio::sync::Semaphore>,
    cfg: Arc<C::Cfg>, idle_timeout: Duration, /* drain handle */ }
```

RAII `Checkout` returns the conn on drop; a transport error (`StoreError::Backend`/`Io`, not `NotFound`/`ChecksumMismatch`) triggers a health probe → discard-if-dead. Idle-drain via `tokio::time`. Concurrency bound = `Semaphore`, constant from config (default unlimited); document rclone's `connections ≥ transfers + checkers + 1` caveat. All literals in each backend's `constants.rs`.

---

## D. operations / sync layer — `dctl-ops` (runtime-agnostic)

Ports rclone `fs/operations`, `fs/sync`, `fs/march`. Generic over an `Endpoint` (a rooted `Arc<dyn Backend>`), driven from the tokio edge. **No `tokio::spawn`; no tokio dep.**

```rust
// dctl-ops::endpoint
pub struct Endpoint { pub backend: Arc<dyn Backend>, pub prefix: String }
impl Endpoint { fn key(&self, logical: &str) -> ObjectKey { /* join prefix + logical */ } }
```

### D.1 Concurrency and CPU seams (resolves D6, D7 — the seam that would not compile)

The reviewed `Spawner` had a **generic method parameter**, so `Arc<dyn Spawner>` was impossible. It is deleted. Two replacement seams:

**(1) I/O concurrency — no trait needed.** Ops expresses parallel I/O as a runtime-agnostic stream the CLI drives:

```rust
// dctl-ops::concurrency
pub fn run_jobs<J, F, T>(jobs: J, parallelism: usize)
    -> impl futures::Stream<Item = T>
where J: IntoIterator<Item = F>, F: std::future::Future<Output = T> {
    futures::stream::iter(jobs).buffer_unordered(parallelism)
}
```

`dctl-cli` consumes the stream (`while let Some(r) = s.next().await`) inside its tokio runtime. This is concurrency without spawning; it is the correct tool for network-bound copy/list/check.

**(2) CPU-bound crypto — an object-safe offload seam.** `buffer_unordered` gives concurrency, **not parallelism**: `object::seal`/`open` are synchronous CPU work and would block the reactor thread. A dedicated seam offloads them; it is deliberately **domain-fixed** (output is always `Result<Bytes>`) so it stays object-safe:

```rust
// dctl-ops::cpu   (also used by dctl-core's VaultBackend, re-exported)
pub type CpuJob = Box<dyn FnOnce() -> crate::Result<bytes::Bytes> + Send + 'static>;

#[async_trait::async_trait]
pub trait CpuOffload: Send + Sync {
    /// Run a CPU-bound crypto closure off the async reactor.
    async fn run(&self, job: CpuJob) -> crate::Result<bytes::Bytes>;
}
```

`Arc<dyn CpuOffload>` compiles (no generics, no `Self` by value). The tokio-edge impl (`dctl-cli/src/edge/cpu.rs`) uses `tokio::task::spawn_blocking` + `oneshot`; a trivial inline impl (`InlineCpu`, runs on the calling task) serves tests/headless. `VaultBackend` (dctl-core) takes an injected `Arc<dyn CpuOffload>` so `seal`/`open` parallelize on the blocking pool during large re-encryption/sync, while dctl-core still never calls `tokio::spawn`.

```rust
// dctl-ops::progress — bytes/objects/errors sink, impl at the CLI edge
pub trait Accounting: Send + Sync { fn transferred(&self, bytes: u64); fn checked(&self); fn error(&self, e: &OpError); }
```

### D.2 `copy` — server-side vs stream-through vs whole-buffer (port of `operations/copy.go`)

```
plan_copy(dst, src_obj):
  if same_remote(src,dst) && dst.backend.as_server_copy().is_some():
        ServerSide
  else match src_obj.size:
        None                                  -> StreamThrough(dst.as_stream_write())  # rcat/unknown length
        Some(n) if n > STREAM_CUTOFF          -> StreamThrough                           # avoid buffering big files
        Some(_)                               -> WholeBuffer(get -> put)                 # small: buffered + verified
```

`transfer.rs` runs the chosen strategy inside a `LOW_LEVEL_RETRIES` loop, then **verifies**: size must match, and if `common_hash(src,dst) != None` the (logical-domain, A.1) hashes must match — else the just-written object is `delete`d and the copy errors (PLAN §6). `StreamThrough` = `src.as_stream_read().open(all)` piped into `dst.as_stream_write().put_streaming(...)`; when either side lacks the stream capability, fall back to whole-buffer under a size guard. **Endpoints that advertise `INDEX_BACKED` (VaultBackend) are excluded from `StreamThrough` while no streaming sealer exists** — they always take `WholeBuffer` under the whole-file guard (D14; see §F, §G-M7).

### D.3 `equal` / `need_transfer` — the delta predicate (port of `operations.go`)

`need_transfer`: dst absent ⇒ transfer; `--ignore-existing` ⇒ skip; `--ignore-times` ⇒ transfer; `--update` ⇒ modtime compare in the modify-window; else `!equal`. `equal` ladder: size differs ⇒ differ (unless `--ignore-size`); `--size-only` ⇒ equal; `--checksum` ⇒ compare the single `common_hash` (warn+size-only if none); default = modtime+size within `modify_window = max(src.precision, dst.precision)`; either precision `NotSupported` (FTP) ⇒ size-only. `common_hash(a,b)` = overlap of the two backends' hash sets (from `RemoteHasher::supported()`/`ObjectMeta.hash`), BLAKE3-first. **Because both endpoints expose logical-domain hashes (A.1), `common_hash` is always a same-domain comparison — plain↔plain, plain↔Vault, and Vault↔Vault alike (resolves D3).**

### D.4 `march` — lockstep merge (port of `fs/march`)

`walk.rs` turns `Backend::list_page` pagination into an ordered stream of logical paths (object stores already return lexicographic keys → free ordering; dir-native backends' recursive walk is sorted per level then merged). `march.rs` merges src and dst streams by sorted key into `SrcOnly | DstOnly | Match(src,dst)`. `--no-traverse` skips the dst walk. NFC + case-fold applied when either side is case-insensitive.

### D.5 `sync` — delta + delete + track-renames (port of `fs/sync`)

`sync/mod.rs` wires three back-pressured stages via `buffer_unordered`: **checkers** (`need_transfer`) → **transferrers** (`copy`) → **renamers**. `SrcOnly` ⇒ copy; `Match` ⇒ copy-if-needed; `DstOnly` ⇒ delete-candidate. `sync/delete.rs`: `DeleteMode {Off, Before, During, After}` (copy/move use `Off`; sync deletes extras). `sync/rename.rs` **track-renames**: enabled only when `dst.caps().contains(SERVER_MOVE)` and delete-mode≠Off (forces `After`); builds a fingerprint map (`size|modtime|hash`, `SlowHash`-aware) over delete-candidates; a src-only file matching a dst-only fingerprint becomes a server-side `move_object`. `sync/dirs.rs`: empty-dir create/delete via `DirOps` gated on `REAL_DIRS`.

### D.6 `move` and `check`

`move_.rs`: same-remote ⇒ `as_server_move` (§A.4), else `copy` then `src.delete`. `check.rs`: enumerate two endpoints via `march`, compare per `equal` (`--checksum` forces hash compare), stream results to `Accounting`; no data movement. All knobs in `options.rs`; all defaults (retries, modify-window = 1s, stream cutoff, partial suffix, checker/transfer parallelism) in `constants.rs`.

**CLI edge:** `dctl-cli` supplies the concurrency driver, a `TokioCpu` (`edge/cpu.rs`), and a `CliAccounting` (progress bars), builds two `Endpoint`s (both `Arc<dyn Backend>`, one possibly a `VaultBackend`), and calls `dctl_ops::{copy,sync,move_,check}`. `transfer/engine.rs`'s bespoke `Direction`/`StageDriver`/`Reaper` collapse into thin adapters; `Named→Named` stops being a special case.

---

## E. mount + serve

### E.1 VFS — `dctl-vfs` (runtime-agnostic policy), maps rclone `vfs/`

- **`FsView`** is served by any `Arc<dyn Backend>` through **`PlainFs`** (`backend_fs.rs`): `readdir` collapses `list_page` pagination + synthesizes dir `Attr`s from prefixes; `open_read` → `BackendRangeReader` over `get_range` (byte-exact); `rename`→`as_server_move` or copy+delete; write → cache-staged.
- **Node tree / dir cache** (`node.rs`/`dir.rs`/`file.rs`): `Dir`/`File` with a TTL'd `DirCache`; an `InodeTable` (`AtomicU64` + bidirectional `VPath↔u64`) because FUSE/NFS address by inode.
- **Read handles + read-ahead** (`handle/read.rs`): cache-mode `off` = in-RAM ring of `MOUNT_DEFAULT_BUFFER_SIZE` with forward-sequential prefetch via `read_at`; cache-mode `full` = sparse `vfscache::Item` + `RangeSet` interval tracking + downloaders.
- **Write path** (`handle/write.rs`, `rw.rs`, `vfscache/`): because `Backend::put` is whole-object/atomic, **writable mounts on object-store remotes require ≥`writes` cache mode** — writes stage to a sparse local file, flush-on-close via `as_stream_write` (or whole-buffer `put`). **Cache-mode `off` writes are refused loudly** unless the backend advertises `WRITABLE_RANGE` (only SFTP, sequential-only) — never silently degraded (PLAN §6). The write-back queue is the one component needing `tokio::spawn`: `dctl-vfs` exposes `WriteBack::poll_next_expired()`/`Item::flush()` futures; the **loop lives in `dctl-mount`/`dctl-serve`**. LRU eviction is pure policy in `dctl-vfs`.

### E.2 `dctl mount` — FUSE adapter `dctl-mount`

Replace the terminal `Err(CliError::unimplemented)` in `commands/mount/mod.rs` with `commands/mount/engine.rs`: build the `FsView` (plain via `registry::build`; Vault via `session::open`+`VaultBackend`, §F) and hand it to `dctl-mount`. The flag surface, `Source`, `mountpoint::validate`, and per-OS `MountBackend` ordering already exist.

**Reconciled default (resolves D11).** Today `mount/mod.rs` defaults `--vfs-cache-mode off` with `read_only=false` — which collides with the write-refusal rule. Resolution: keep the `off` default, but at mount time, when the target is a non-`WRITABLE_RANGE` backend mounted writable in cache-mode `off`, emit a **startup warning** and honor the E.1 refusal (write `open`/`write` → `EROFS`, logged). This is the honest PLAN §6 behavior and changes no default flag value. Document that `--vfs-cache-mode writes` (or `full`) is required for a writable object-store mount.

**FUSE bridging (resolves D17).** Every crate carries `#![forbid(unsafe_code)]`; `fuser`'s `Filesystem` is a safe API, so no DCTL `unsafe` is needed (verify the sparse-file code in `dctl-vfs` uses safe seek/write, not raw `mmap`). Crucially, `fuser` runs each sync callback on **its own OS threads**, where `Handle::current()` is unavailable — `DctlFuse` must **capture a `tokio::runtime::Handle` at mount** and use `handle.block_on(async { vfs… })` in every callback. TTLs honor `attr_timeout`/`dir_cache_time`; SIGINT → `Session::unmount()` + write-back drain (**exit non-zero on dirty-flush failure**).

| OS | Crate | Version | License | Driver | Driver license |
|---|---|---|---|---|---|
| Linux | `fuser` | 0.18 | **MIT** | `/dev/fuse` (no libfuse link) | GPL = OS, not linked → clean |
| macOS | `fuser` over macFUSE / fuse-t | 0.18 | MIT | macFUSE kext / fuse-t (proprietary-but-free, kext-free) | flag; fuse-t preferred pre-FSKit |
| Windows | `winfsp`(-rs) or `dokan` | winfsp-rs 0.x / dokan 0.10 | Apache-2.0 / MIT (bindings) | **WinFSP GPLv3+linking-exception** ⚠ or **Dokany LGPL-2.1** ⚠ | **the one real copyleft blocker** — see below |

### E.3 `dctl serve` — NEW command `dctl-serve`

New `Command::Serve` + `dispatch.rs` arm + `commands/serve/` (mirrors `mount/`). Each protocol exposes the same `Arc<dyn FsView>`; read-only by default unless `--rw` (write path reuses §E.1).

| Protocol | Crate | Version | License | When |
|---|---|---|---|---|
| http (read) | `axum`+`hyper`+`tower-http` | 0.8 / 1 / 0.6 | **MIT** | realistic-now — GET/HEAD+Range → `RangeReader`; dir HTML from `readdir` |
| webdav (rw) | `dav-server` | 0.11 | **MIT/Apache** | realistic-now — `impl DavFileSystem for FsView`, served under axum |
| sftp (server) | `russh`+`russh-sftp` (server feature) | 0.62 / 2.3 | **Apache-2.0** | realistic-now — same crates as the SFTP backend |
| ftp (server) | `libunftp`+`unftp-sbe-fs` | 0.23 / 0.3 | **Apache-2.0** | realistic-now — `impl StorageBackend for FsView`, FTPS via workspace rustls |
| nfs (v3) | `nfsserve` | 0.11 | **BSD-3-Clause (permissive)** | **experimental for MATURITY** — kext-free macOS mounts via `mount_nfs 127.0.0.1`; fail-loud if it can't bind |
| dlna/restic/docker/s3 | — | — | — | out of scope |

**Windows story (resolves D9).** All `serve` crates are permissive. WinFSP (GPLv3) / Dokany (LGPL-2.1) are the only copyleft items, and they touch **mount only**. Ship Windows via **`serve` by default** (all-permissive); keep Windows `mount` behind a feature flag + legal-review gate (commercial WinFSP license, or Dokan with verified dynamic linking). `nfsserve` is permissive (BSD-3-Clause), so NFS is **not** license-blocked — it is maturity-gated and opt-in.

---

## F. How plain and Vault remotes share one pipeline

**The Vault becomes a `Backend`.** `crates/dctl-core/src/vault/backend.rs` adds `VaultBackend { vault: Vault, cpu: Arc<dyn CpuOffload> }` implementing `Backend` over the existing `Vault` API — the overlay that lets `dctl-ops`/`dctl-vfs` drive an encrypted remote identically to a plain one, with **no dependency from ops/vfs on dctl-core**.

```rust
#[async_trait] impl Backend for VaultBackend {
    fn name(&self) -> &'static str { "vault" }

    async fn put(&self, k, data, expected) -> Result<PutOutcome> {
        // A.1 hash domain: `expected` is blake3(PLAINTEXT). Guard it, then seal
        // (offloaded via self.cpu), verified-write ciphertext, commit index+name record.
        // Returns PutOutcome{ size: plaintext_len, verified: blake3(plaintext) }.
    }
    async fn get(&self, k) -> Result<Bytes> { /* Vault::get_file: index→file_id→open→verify */ }
    async fn get_range(&self, k, r) -> Result<Bytes> {
        // MUST do the index→file_id lookup first (D4), then ObjectReader (M9)
        // or whole-fetch-slice (M4 placeholder, correct-but-unoptimized).
    }
    async fn head(&self, k) -> Result<ObjectMeta> { /* from the redb index Record */ }
    async fn list_page(&self, prefix, cursor) -> Result<Page> { /* paginate Vault::list(prefix) */ }
    async fn delete(&self, k) -> Result<()> { /* Vault::delete_file: object + name record + index */ }

    fn caps(&self) -> Caps {
        // Logical paths, index-backed listing, ranged READ (M9); NO server copy/move
        // (would need re-encryption), NO stream WRITE until a streaming sealer exists (D14).
        Caps::REAL_DIRS | Caps::INDEX_BACKED | Caps::REMOTE_HASH | Caps::STREAM_READ
    }
    fn as_remote_hasher(&self) -> Option<&dyn RemoteHasher> { Some(self) } // BLAKE3 of plaintext, from index
    fn as_stream_read(&self)   -> Option<&dyn StreamRead>   { Some(self) } // ranged decrypt (M9)
    // as_stream_write / as_server_copy / as_server_move deliberately absent.
}
```

Consequences: **plain↔plain, plain↔Vault, Vault↔Vault, remote↔remote are all "two `Arc<dyn Backend>`"** in `dctl-ops`. The `Named→Named` refusal and the plain-vs-vault fork in `transfer/engine.rs` disappear. Vault↔Vault re-encryption is `src.get` (decrypt) → `dst.put` (re-seal), which the copy engine already does.

**Index-backed consistency, stated (resolves D4).** `VaultBackend` advertises `INDEX_BACKED` because `list`/`head`/`get` are driven by the **local redb index** (`vault/list.rs` enumerates the index, `vault/get.rs` maps `index.get(path) → object_key`), not backend ground truth. This differs from a plain `Backend` where `list_page` is ground truth. dctl-ops/vfs treat an `INDEX_BACKED` endpoint's listing as authoritative *for this machine's index*; a fresh machine or a divergent index must first **rebuild from the §5 name records** (existing scrub/reindex path). `get_range` performs the mandatory `index→file_id` lookup — the F.1 sketch that omitted it is corrected here.

**Vault↔Vault credentials & index (resolves D13).** `Vault::assemble` opens `Index::open(index_path, index_subkey)` keyed by that vault's root-derived subkey, and the default index path is a single `data_dir/index.redb` — two vaults **cannot** share it. Therefore a two-Vault transfer requires **two independent `Session`s**: per-endpoint password acquisition and per-endpoint index path. The unified resolver (Milestone 1) resolves each endpoint independently; the CLI adds `--index-src`/`--index-dst` (and per-endpoint password sources, e.g. `DCTL_PASSWORD_SRC`/`DCTL_PASSWORD_DST` or `--password-command` per side). `RemoteEndpoint::Vault` carries its own credential source and index path. "Vault↔Vault is just `src.get→dst.put`" holds **only after** this dual-session construction is in place — specified in Milestone 4, exercised in Milestone 9.

**Whole-file limit stays on Vault writes (resolves D14).** There is no chunk-incremental sealer today: `object::seal(&[u8]) -> Vec<u8>` is whole-buffer. `VaultBackend` therefore does **not** implement `StreamWrite`; `dctl-ops` routes Vault writes to `WholeBuffer` and continues to enforce `TRANSFER_WHOLE_FILE_LIMIT` (1 GiB, `constants.rs:1760`) for `INDEX_BACKED` endpoints. Retiring the limit (Milestone 7) is scoped to **plain remotes only**; lifting it for Vaults is a future streaming-sealer work item, flagged, not required for correctness.

### F.1 Ranged Vault reads for mount/serve — `dctl-crypto::object::reader` (resolves D5, D12)

DSF1 is chunk-seekable on disk; only the API is whole-buffer. `ObjectReader` lives **inside `crates/dctl-crypto/src/object/`** so it can reach the module-private per-chunk primitives (`chunk_nonce`/`chunk_aad`/`chunk_plaintext_len`/`aead::decrypt_with_nonce`) — this is feasible precisely because `reader.rs` is a sibling of `seal.rs`, not because nothing new is needed (correcting the "basically free" framing, D12). Required new surface:

- A `pub(crate) fn data_start(...)` helper on the seal side that computes the **variable** header length (`kem_ct_len + wrapped_dek + variable meta_len`) so the reader knows where chunk 0 begins.
- `open_head(wrapping_key, prefix_bytes)` — unwraps the DEK from a small `get_range([0..data_start])`.
- `chunk_span(off, len) -> ByteRange` — the backend range covering the touched chunks.
- `decrypt_span(first_chunk_index, ciphertexts, want) -> Bytes` — AEAD-decrypts them; per-chunk nonce+AAD folding head+index → **per-chunk tamper detection preserved on partial reads**.

**Restored whole-file integrity (resolves D5).** `cat` (`Vault::get_file`) verifies `blake3(plaintext) == record.content_hash`; a ranged read cannot, because the whole-object footer needs the whole object. The reader therefore tracks covered ranges: **when a handle's reads cumulatively cover `[0, size)`, it verifies the index `content_hash`** (accumulating a streaming BLAKE3 as chunks are decrypted in order, or a final full-object hash on close of a fully-read handle). Partial reads document the reduced guarantee (per-chunk AEAD only, no whole-file footer) explicitly rather than silently. `VaultBackend::get_range` uses `ObjectReader`, so mounting a 50 GiB Vault file fetches ~one chunk per read. Seal-on-write stays whole-object staged in the vfs-cache until a future streaming `seal_writer` lands (flagged; §F whole-file limit).

---

## G. Dependency-ordered build plan

Each milestone is a shippable, `cargo build && cargo test`-verifiable slice, ordered so the earliest change lights up the most commands. **Milestone 1 is the prerequisite the review demanded** (the former "M0"): without it, no command can list a config remote and copy would leak plaintext. Every not-yet-wired path keeps its honest `unimplemented` failure (PLAN §6).

### M1 — Unified resolution + Plain/Vault classification (prerequisite; resolves D1, D2, D15, D18)
DCTL has **two** resolvers: `about/target.rs` reads config + follows `config::vault_chain` + `is_vault()`; the transfer/listing/session path resolves against the **empty catalog `&()`** (`session/open.rs:127`) and `resolve.rs:285` **hard-errors** on `type=vault`. Unify them.
- **Touch:** `remote/resolve.rs` (accept a real `RemoteCatalog` from `ctx.config`; change the `PROVIDER_VAULT` arm to **build the base target + a Vault-wrap marker** instead of erroring); new `remote/classify.rs` (Plain vs Vault derived from `config::vault_chain`/`is_vault`, the single source of truth, shared with `about/target.rs`); `session/open.rs::build_backend` stops passing `&()`; fold `commands::listing::target::Target` into `remote::registry::Target`; promote `resolve::RemoteEntry` out of `cfg(test)` to `config::load`'s real definitions.
- **Shorthand-semantics decision (resolves D2 — a data-confidentiality fix):** `dctl copy ./x s3:bucket` today goes `session::open → Vault::unlock`, i.e. it reads/writes an **encrypted** envelope. It is decided and documented here that **provider shorthands (`s3:`, `b2:`, `sftp:`, …) are PLAIN**, and a Vault must be a `type=vault base=` config remote (or an explicit `vault:` scheme). This ships with a **migration note** and a one-time warning when a shorthand previously used as a Vault is detected. No later milestone may treat a shorthand as plain until this classification is in place.
- **Crates added:** none.
- **Commands lit:** none new yet — this is the seam. `about`/`session`/`resolve` now agree on one classification.
- **Tests:** resolve a config `type=vault base=b2prod` to `(build b2prod, wrap)`; resolve `type=s3` to a plain endpoint; shorthand `s3:bucket` classifies Plain; `about` and the new resolver produce identical classification for the same input; the old empty-catalog behaviors that these replace are updated (the `session/open.rs` tests at lines 229–261 move to the config-aware resolver).

### M2 — Plain-remote enumeration: `ls`/`lsd`/`lsl`/`lsjson`/`tree`/`size` (resolves D15)
Give listing commands an `Arc<dyn Backend>` for a Plain remote and page `list_page`. This is **not** "reuse the 4 backends verbatim": listing is Vault/index-shaped today (`Pager` over `Vec<Record>`, `index_records()` hard-stubbed to `Ok(None)` at `source.rs:173`, `Ctx` carries no backend). Real work:
- **Touch:** new `remote/endpoint.rs` (`RemoteEndpoint::{Local,Plain,Vault}`, `Plain` from `registry::build` + the M1 resolver's promoted `Resolved::path`); `Ctx`/`session::open` gain an `Arc<dyn Backend>` accessor; new `impl Pages` over `Backend::list_page` in `listing/source.rs`; new `Entry::from_meta(ObjectMeta)` alongside `Entry::from_record`; replace the `Named ⇒ unimplemented` arm in `transfer/listing.rs::enumerate`.
- **Crates:** none.
- **Commands lit:** `ls`, `lsd`, `lsl`, `lsjson`, `tree`, `size` against `local:`/`s3:`/`b2:`/`r2:`.
- **Tests:** unit `impl Pages` over a fake `Backend`; integration `dctl ls s3:bucket` (MinIO) and `dctl ls <localdir-as-remote>`; ascending-order, no-repeat property test.

### M3 — Plain-remote copy/move/cat/delete + remote↔remote
Minimal transfer over `Backend` for Plain endpoints; the plain↔plain `Named→Named` refusal is removed via `get→put`. **Vault transfers still route through the existing `session` engine here** (deleted in M4).
- **Touch:** `transfer/engine.rs` (add `(Plain,*)` directions; `get`/`put`/`delete`), `cat/source.rs` (remote arm → `get_range`), `delete`/`deletefile`/`purge`, `rcat`. Keep whole-buffer staging + `TRANSFER_WHOLE_FILE_LIMIT` for now.
- **Crates:** none.
- **Commands lit:** `copy`/`copyto`/`move`/`moveto`, `cat`, `rcat`, `delete`/`deletefile`/`purge`, `about` (if `as_about`) — Plain and remote↔remote.
- **Tests:** `copy local→s3`, `copy s3→b2` byte-identical round-trip; `cat --offset` fetches only a range (assert bytes-transferred); idempotent delete.

### M4 — `dctl-ops` crate + `VaultBackend` — ONE engine for plain and Vault (resolves D3, D4, D6, D7, D13, D16)
Introduce the runtime-agnostic ops layer **and** the Vault overlay together, so the dual-engine window never opens (the review's D16: unification is the pivot, not the tail).
- **Touch:** new crate `crates/dctl-ops/` (§D modules incl. `concurrency.rs`, `cpu.rs`); `dctl-cli/src/edge/{concurrency,cpu,accounting}.rs` (`TokioCpu` via `spawn_blocking`, `InlineCpu` for tests, `CliAccounting`); new `crates/dctl-core/src/vault/backend.rs` (`VaultBackend`, §F — `get_range` is whole-fetch-slice placeholder, documented, **not** a stub); `RemoteEndpoint::Vault` returns a `VaultBackend`; **delete** the plain-vs-vault fork and `Named→Named` special case from `transfer/engine.rs`; wire dual-session Vault↔Vault credential/index resolution (`--index-src`/`--index-dst`, per-side password sources).
- **Crates:** `futures`, `futures-core`, `pin-project-lite`, `bitflags` (+ `capability.rs` with `Caps` and the capability traits).
- **Commands lit:** `sync` (deletes, 3 delete-modes), `check`, `hashsum`, correct `move` semantics — across Plain **and** Vault, including Vault↔plain and Vault↔Vault (whole-buffer, under the size limit).
- **Tests:** march lockstep (SrcOnly/DstOnly/Match); sync deletes dst extras; `--size-only`/`--checksum`/`--update` equal-ladder; verify-on-copy removes a corrupt write; **`common_hash` compares logical-domain hashes for plain↔Vault (D3)**; Vault→Vault round-trip re-encrypts (distinct ciphertext, identical plaintext) via two sessions (D13); `CpuOffload` runs `seal`/`open` off-reactor (assert with a blocking probe).

### M5 — New plain backends: WebDAV + HTTP(ro), then SFTP, then FTP
Additive `dctl-store` modules; each is a `Target` variant + `build`/`resolve` arm + constants — zero command changes. Also rewire `about`'s `BACKEND_CAPABILITIES` matrix to **derive from `Backend::caps()`** (D18).
- **Touch:** `dctl-store/src/{webdav,http,sftp,ftp}/*`, `src/{pool,path_map,capability}.rs`, `src/{backend,model,lib}.rs`; `remote/registry.rs` (`Target::{Webdav,Http,Sftp,Ftp}` + build arms reading `DCTL_*`), `remote/resolve.rs` (arms), `constants.rs` (`PROVIDER_*`, `ENV_*`, `CONFIG_KEY_*`, support tables); `about/capabilities.rs` derives from `caps()`.
- **Crates:** `httpdate`, `percent-encoding`, `http-auth`, `tl` (webdav/http, default features); then `russh 0.62`/`russh-sftp 2.3` (`sftp`); then `suppaftp 10` (`ftp`).
- **Commands lit:** all of M1–M4 against `webdav:`/`http:`/`sftp:`/`ftp:`.
- **Tests:** per-backend integration against loopback servers (russh, libunftp, a WebDAV container, a static HTTP server); verified-write correctness (SFTP remote-hash + read-back fallback; FTP re-RETR; WebDAV OC-Checksum + PROPFIND read-back); **`caps()`⇔accessor consistency test per backend**; `about --capabilities` matches `caps()`.

### M6 — Capability-aware ops: server-side copy/move + track-renames (resolves D20 ceilings)
- **Touch:** implement `ServerCopy`/`ServerMove` on `S3/R2/B2` (CopyObject / `b2_copy_file`), WebDAV (COPY/MOVE), SFTP/FTP (rename); wire `as_server_copy`/`as_server_move` into `dctl_ops::{copy,move_}` and `sync/rename.rs`. **Provider ceilings (D20):** S3 `CopyObject` caps ~5 GiB and B2 `b2_copy_file` similarly — above the ceiling, fall back to multipart-copy (UploadPartCopy) or copy-through; the strategy planner picks per size.
- **Crates:** none.
- **Commands lit:** faster same-remote `move`/`moveto`; server-side `copy` on capable remotes; `sync` track-renames.
- **Tests:** same-remote move issues no GET/PUT (counting backend); track-rename → one `move_object`; over-ceiling copy uses multipart-copy; fallback to copy+delete when capability absent.

### M7 — Streaming I/O: retire the whole-file limit for PLAIN remotes (resolves D14, D20)
- **Touch:** implement `StreamRead`/`StreamWrite` on local/sftp/ftp/webdav natively and **S3/B2 via real multipart** — note `s3/client.rs:158 put_multipart(key, data: &[u8])` buffers then slices, so streaming multipart is **new work, not wiring** (D20); `dctl_ops::copy` routes `size==None`/large **plain** transfers to `StreamThrough`; delete the `TRANSFER_WHOLE_FILE_LIMIT` guard **for plain endpoints only**. **`INDEX_BACKED` (Vault) endpoints keep the limit** until a streaming sealer exists (D14).
- **Crates:** none.
- **Commands lit:** large-file `copy`/`sync`/`move`/`backup`/`restore` without the memory cap for plain remotes; unknown-length `rcat`.
- **Tests:** stream a file > former limit end-to-end at O(buffer) memory; multipart abort on failure leaves nothing committed; a Vault write > limit still fails loudly (limit intact).

### M8 — `dctl-vfs` + `dctl-mount`: wire the mount stub (plain remotes) (resolves D11, D17)
- **Touch:** new crates `crates/dctl-vfs/`, `crates/dctl-mount/`; `commands/mount/engine.rs` replaces the terminal `Err`; capture the tokio `Handle` at mount and `block_on` in callbacks (D17); reconcile the `off`+writable default via startup warning + `EROFS` refusal on non-`WRITABLE_RANGE` backends (D11).
- **Crates:** `fuser 0.18` (Linux/macOS); Windows `winfsp`/`dokan` behind a feature + legal gate.
- **Commands lit:** `mount` of a plain remote (read; write in `--vfs-cache-mode writes`).
- **Tests:** port rclone's `vfstest` conformance cases; real mount → read/seek (assert ranged `get_range` calls) → write-flush → unmount drains or exits non-zero; cache-mode `off` + write on S3 → `EROFS` + logged refusal.

### M9 — Ranged Vault crypto: efficient/huge Vault mount + full-read integrity (resolves D5, D12)
`VaultBackend` already exists (M4); this milestone makes its `get_range` chunk-ranged instead of whole-fetch-slice, and restores whole-file integrity on complete reads.

> **The chunk-ranged decrypt is DONE and shipped — do not rebuild it.** It landed as
> `dctl-crypto/src/object/range.rs` (`RangeHeader`/`ChunkSpan`: §3 covering-chunk
> arithmetic + per-chunk authentication) and `dctl-core/src/range.rs`
> (`Vault::open_range_reader` → `RangeReader`: one `Backend::get_range` per window),
> with a bounded decrypted-chunk cache at `dctl-cli/src/source/chunk_cache.rs`. Named
> `range.rs` rather than the `reader.rs`/`data_start()` sketched below, and it needed no
> change to `seal.rs`. `dctl cat --offset` against a Vault is already ranged. What is
> **still outstanding** in this milestone is D5: the full-read integrity check on handle
> close — a windowed read cannot evaluate the whole-object footer or `content_blake3`
> (stated on `dctl_core::range`), so a handle that has cumulatively covered `[0, size)`
> must fold a streaming BLAKE3 and check it. Nothing tracks coverage yet.

- **Touch:** ~~`crates/dctl-crypto/src/object/seal.rs` (`pub(crate) data_start()` helper), new `crates/dctl-crypto/src/object/reader.rs` (`ObjectReader`)~~ **done, as `object/range.rs`**; `VaultBackend::get_range`/`as_stream_read` use it; full-read integrity check on handle close (D5).
- **Crates:** none.
- **Commands lit:** Vault `mount`/`serve` of huge files (one chunk per read); Vault `cat --offset` becomes ranged.
- **Tests:** proptest ranged-decrypt == whole-object `open` at random offsets; per-chunk tamper detection on partial reads; a fully-read handle verifies the index `content_hash`; mounting a >1 GiB Vault file fetches O(chunk) not O(file) (assert `get_range` sizes).

### M10 — `dctl serve` (http/webdav/sftp/ftp; nfs experimental) (resolves D9)
- **Touch:** new crate `crates/dctl-serve/`; `Command::Serve` in `cli/` + `dispatch.rs`; `commands/serve/*`.
- **Crates:** `axum 0.8`+`hyper 1`+`tower-http 0.6`, `dav-server 0.11`, `russh`/`russh-sftp` (server), `libunftp 0.23`+`unftp-sbe-fs 0.3`; `nfsserve 0.11` (BSD-3-Clause) gated experimental.
- **Commands lit:** `serve http|webdav|sftp|ftp` over any Plain or Vault remote; `serve nfs` opt-in/experimental (fail-loud if unavailable); **Windows default = `serve` (all-permissive)**.
- **Tests:** mount each served endpoint with a stock client and round-trip; `--rw` seals-on-write through the same vfs-cache as `mount`.

### License ledger (corrected; verify with `cargo deny` at each integration — D10, D19)
**Permissive, confirmed:** russh **0.62 Apache-2.0**, russh-sftp **2.3 Apache-2.0**, suppaftp **10 MIT/Apache**, dav-server **0.11 Apache-2.0**, libunftp **0.23 Apache-2.0**, fuser **0.18 MIT**, nfsserve **0.11 BSD-3-Clause**, `futures`/`bitflags`/`httpdate`/`percent-encoding`/`http-auth`/`tl`/`pin-project-lite`, axum/hyper/tower-http (MIT). WebDAV/HTTP add **no** transport dep (reuse `reqwest`+`quick-xml`).
**`deny.toml` must explicitly allow (non-copyleft, but non-SPDX or bundled):** `ring`'s bespoke license (ISC/MIT/OpenSSL mix), `aws-lc-rs`/`aws-lc-sys` (ISC + vendored OpenSSL/SSLeay files — permissive, **the "no OpenSSL" claim is corrected**, D19), `webpki-roots` (MPL-2.0, per-file weak-copyleft, already accepted).
**Feature-flag discipline:** `suppaftp default-features=false` + `tokio-rustls-ring`; russh crypto-provider feature verified via `cargo add` (prefer `aws-lc-rs` to consolidate on one backend; else `ring` as a documented, already-present second backend); never select `ssh2`/`native-tls`.
**Blocker (Windows mount only):** **WinFSP GPLv3** / **Dokany LGPL-2.1** — resolve via commercial WinFSP license, Dokan (verify dynamic link), or ship Windows with `serve` instead of `mount`. NFS is permissive and **not** blocked — maturity-gated only.

---

## START HERE — Milestone 1: unify resolution (the prerequisite everything else needs)

This is the first thing engineers build. It fixes the two-resolver split that makes every later milestone unsound: today `session::open → build_backend` resolves against the **empty catalog `&()`** (`crates/dctl-cli/src/session/open.rs:127`) and `crates/dctl-cli/src/remote/resolve.rs:285` **hard-errors** on `type=vault`, so no config-defined remote can be listed and every shorthand is silently treated as an encrypted Vault.

**Exact files to create / edit:**
- `crates/dctl-cli/src/remote/classify.rs` — **NEW.** `enum EndpointKind { Plain, Vault }` derived from `config::vault_chain`/`is_vault`; the single classifier shared with `crates/dctl-cli/src/commands/about/target.rs` (which already models this correctly — reuse, don't duplicate).
- `crates/dctl-cli/src/remote/resolve.rs` — **EDIT.** Thread a real `RemoteCatalog` (from `ctx.config`) into `resolve`; change the `PROVIDER_VAULT` arm (currently `Err` at line 285) to build the base `Target` + a Vault-wrap marker; promote `RemoteEntry`/`Resolved::path` out of `cfg(test)`.
- `crates/dctl-cli/src/session/open.rs` — **EDIT.** `build_backend` resolves against the real catalog, not `&()` (line 127); move/adapt the resolution tests at lines 229–261.
- `crates/dctl-cli/src/remote/registry.rs` — **EDIT.** Fold `commands::listing::target::Target` into the one `Target`; keep `build(&Resolved) -> Arc<dyn Backend>`.
- `crates/dctl-cli/src/constants.rs` — **EDIT.** Add the shorthand-is-Plain decision constants + the migration-warning string (resolving the D2 confidentiality flip).

**Verify it:**
```
cargo test -p dctl-cli remote::
```
Green means one resolver classifies a config `type=vault base=…` remote as `Vault` (build-base-and-wrap, no error), a `type=s3` remote and every provider shorthand as `Plain`, and `about`'s classifier and the transfer/session classifier agree on identical input — the seam Milestone 2's enumeration and Milestone 4's single engine are built on.