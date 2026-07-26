# dctl

Encrypted, verified, metadata-private cloud storage.

## Synopsis

DCTL transfers, backs up, encrypts and streams data across cloud providers.

The vocabulary is deliberately rclone's, because that is the muscle memory of
the people this tool is for: `copy` skips identical files, `sync` makes the
destination match the source (and therefore deletes), `purge` removes a tree,
`lsd` lists directories. A script written against rclone should port with edits
to the remote names and little else.

What DCTL adds is a **durability contract**. No file is ever reported as stored
until its bytes have been checksum-verified at the destination *and* durably
committed to the index. A verification failure aborts the file before the
commit, exits **20** rather than the generic error code, and leaves nothing
behind that a later run could mistake for a success. [`verify`](dctl_verify.md)
and [`scrub`](dctl_scrub.md) let you re-establish that proof at any time, and
[`audit`](dctl_audit.md) makes the history of what happened tamper-evident.

Encryption is **optional and per-remote**: a remote is either plain or
vault-wrapped, and the durability contract applies identically to both.

```
dctl [GLOBAL OPTIONS] <COMMAND> [ARGS] [COMMAND OPTIONS]
```

Global options are accepted **before or after** the subcommand, so
`dctl copy a b --progress` and `dctl --progress copy a b` are the same command.

## Paths — `REMOTE:PATH`

Every path argument is either a **configured remote** with a logical path
inside it, or a **path on this machine**. One rule decides which, and it is the
same rule on every platform.

```
dctl copy ./photos vault:photos/2024     # local  → remote
dctl copy vault:photos/2024 ./photos     # remote → local
dctl ls vault:                           # the whole remote, at its root
```

A remote's path is a **logical path**: `/`-separated, UTF-8, Unicode-NFC, with
no leading slash and no `..` components. It reads the same on Linux, macOS and
Windows, which is what makes a vault written on one machine addressable from
another. Backslashes are accepted and folded to `/`, so `vault:a\b` and
`vault:a/b` are one path.

### An argument is a local path when it

1. is a UNC or extended-length path — `\\server\share`, `\\?\C:\...`;
2. starts with a **drive specifier** — `C:`, `c:/x`, `C:\x`, or the rare
   drive-relative `C:relative`;
3. contains no colon at all — `photos`, `./photos`, `/srv/data`;
4. has a candidate name that is really a path component: shorter than two
   characters, containing `/` or `\`, or beginning with `.`.

Otherwise it names a remote, and everything after the **first** colon is the
logical path — so `vault:a:b` is the remote `vault` holding the file `a:b`,
because a colon is a legal filename character and only the first one is
structural.

### The Windows drive-letter rule

**`C:\data` is a local path. It is never a remote named `C`.** Any
single-character prefix before a colon is read as a drive letter, so `C:`,
`c:/x`, `C:\Users\me` and `C:relative` are all filesystem paths.

Remote names are therefore required to be **at least two characters** — the
rule is enforced when the configuration is written, so a remote named `c` cannot
exist to be confused with drive `C:` in the first place. Names are 2–64
characters of ASCII letters, digits, `-`, `_` and `.`, and must **start** with a
letter or a digit — which is also why an argument beginning with `.` is read as a
relative path rather than a remote. Provider type names (`local`, `b2`, `s3`,
`r2`) are reserved, because each is also a shorthand: `b2:bucket` cannot be
allowed to mean both "the remote called b2" and "the b2 backend". `vault` is
**not** reserved — a vault stores nothing and so has no shorthand form, which
leaves `vault:photos/2024` free to mean the obvious thing. See
[dctl config](dctl_config.md) for the full rule.

This check runs on **every platform, not just Windows**. A `#[cfg(windows)]`
rule would make one string mean two different things depending on where it ran,
so a backup script written on a laptop would classify its arguments differently
on a Linux build agent — the class of bug that is only ever discovered during
the restore that mattered. `looks_like_windows_drive` and its tests live in
`crates/dctl-cli/src/platform/path.rs`; `RemoteSpec::parse` applies it in
`crates/dctl-cli/src/remote/spec.rs`.

The same reasoning covers colons that are not drive letters: `photos/holiday:2024`
is one relative directory, not a remote called `photos/holiday`, because the
candidate name contains a path separator.

### `local:` — the escape hatch

`local:` forces the rest of the argument to be read as a filesystem path. It is
the only way to name a directory that would otherwise parse as something else:

```
dctl ls local:/srv/data          # → /srv/data
dctl ls local:archive:2024       # → ./archive:2024, a directory with a colon
dctl ls "local:C:\Users\me"      # → C:\Users\me, said explicitly
```

### Unicode

macOS hands back decomposed filenames, so `café` arrives as `cafe` + a combining
acute while the same name typed on Linux or Windows is a single precomposed
character. Both display identically. Since the index key and the object key are
both derived from the path bytes, two spellings would produce two objects for
one file — a duplicate no user could see or explain.

Logical paths and remote names are therefore normalised to **NFC** on the way
in. Local paths are kept **byte-for-byte as typed**: they are handed back to the
operating system, which looks up exactly the bytes it was given. Canonicalising
the vault's namespace is required; canonicalising someone else's is corruption.

## Configuration

DCTL's configuration is a TOML file holding **non-secret settings only** —
named remotes with their type, bucket, endpoint, region and policy defaults.

### Where the file lives

| Platform | Default configuration file |
|----------|----------------------------|
| Linux / BSD | `$XDG_CONFIG_HOME/dctl/config.toml`, i.e. `~/.config/dctl/config.toml` |
| macOS | `~/Library/Application Support/dctl/config.toml` |
| Windows | `%APPDATA%\dctl\config\config.toml` |
| Fallback | `./.dctl/config.toml`, when no home directory can be determined |

Two related directories follow the same conventions: the encrypted index
(`vault.redb`) lives in the data directory — `~/.local/share/dctl`,
`~/Library/Application Support/dctl`, `%APPDATA%\dctl\data` — and the VFS cache
used by [`mount`](dctl_mount.md) lives in the cache directory — `~/.cache/dctl`,
`~/Library/Caches/dctl`, `%LOCALAPPDATA%\dctl\cache`.

Run [`dctl config file`](dctl_config.md) to print the path this machine actually
resolved, with no label and nothing else on the line, so it substitutes cleanly:

```
$EDITOR "$(dctl config file)"
```

### Which file wins

`--config` beats `DCTL_CONFIG` beats the platform default. The flag is the most
specific statement of intent available (it applies to one invocation), the
environment variable is next (it applies to a shell or a container), and the
platform default is the fallback that makes DCTL work with no configuration at
all. An *empty* `DCTL_CONFIG` is treated as unset rather than as a path.

A file you **named** and got wrong is an error. A **default** path that does not
exist is a fresh installation, and yields an empty configuration rather than a
complaint — DCTL runs fully headless from flags and environment variables.

### No credentials, ever

Provider credentials come from the environment (`DCTL_B2_KEY_ID`,
`DCTL_B2_APP_KEY`, `DCTL_S3_ACCESS_KEY`, `DCTL_S3_SECRET_KEY`,
`DCTL_R2_ACCESS_KEY`, `DCTL_R2_SECRET_KEY`), and the vault password is never
stored anywhere — it is prompted for, read from `--password-file`, or produced
by `--password-command`. A credential-shaped key pasted into `config.toml` makes
the file **fail to load**, by name, rather than being ignored; an ignored secret
stays on disk, in your backups, and in the next bug report. The file is also
warned about — never refused — when it is readable beyond its owner, since it
names buckets, endpoints and regions.

See [dctl config](dctl_config.md) for the file's full vocabulary, and
[dctl init](dctl_init.md) for creating a vault and registering the two remotes that address it.

## Getting help

```
dctl --help                # the tour: global options and every command
dctl <command> --help      # one command, its arguments and its exit codes
dctl help <command>        # the same thing, spelled the other way
dctl --version             # version and build metadata; see also `dctl version`
```

Subcommand names may be **abbreviated** as long as the prefix is unambiguous, so
`dctl cop ...` reaches `copy`. Prefer the full name in scripts: a future command
can make today's abbreviation ambiguous.

[`dctl completion`](dctl_completion.md) generates a shell completion script for
bash, zsh, fish, PowerShell and Elvish. The exit-code contract is in
[../EXIT_CODES.md](../EXIT_CODES.md); the on-disk container format is in
[../FORMAT.md](../FORMAT.md).

## Commands

Ordered by workflow rather than alphabetically, so this list reads as a tour of
the tool: set it up, look at it, move data, remove data, prove the data is
intact, mount it. This is the same order `dctl --help` prints.

### Setup

| Command | Description |
|---------|-------------|
| [dctl config](dctl_config.md) | Create and manage configuration and remotes. |
| [dctl init](dctl_init.md) | Create a vault and register both of its remotes. |

### Listing

| Command | Description |
|---------|-------------|
| [dctl ls](dctl_ls.md) | List objects with size and path. |
| [dctl lsd](dctl_lsd.md) | List directories only. |
| [dctl lsl](dctl_lsl.md) | List objects with size, modification time and path. |
| [dctl lsjson](dctl_lsjson.md) | List objects as JSON, one document per object. |
| [dctl tree](dctl_tree.md) | Show the object tree. |
| [dctl size](dctl_size.md) | Show total size and object count. |

### Transfer

| Command | Description |
|---------|-------------|
| [dctl copy](dctl_copy.md) | Copy files from source to destination, skipping identical files. |
| [dctl move](dctl_move.md) | Move files, deleting the source only after a verified, durable commit. |
| [dctl sync](dctl_sync.md) | Make the destination identical to the source. Deletes from destination. |
| [dctl copyto](dctl_copyto.md) | Copy a single file or directory to an exact destination name. |
| [dctl moveto](dctl_moveto.md) | Move a single file or directory to an exact destination name. |

### Content

| Command | Description |
|---------|-------------|
| [dctl cat](dctl_cat.md) | Write object contents to standard output. |
| [dctl rcat](dctl_rcat.md) | Read standard input and write it to an object. |

### Removal

| Command | Description |
|---------|-------------|
| [dctl delete](dctl_delete.md) | Delete objects in a path, honouring filters. |
| [dctl deletefile](dctl_deletefile.md) | Delete a single named object. |
| [dctl purge](dctl_purge.md) | Remove a path and all of its contents. |
| [dctl rmdir](dctl_rmdir.md) | Remove an empty directory. |
| [dctl rmdirs](dctl_rmdirs.md) | Remove empty directories under a path. |
| [dctl cleanup](dctl_cleanup.md) | Clean up a remote: abandoned uploads, stale temporary objects, old versions. |

### Directories

| Command | Description |
|---------|-------------|
| [dctl mkdir](dctl_mkdir.md) | Create a directory. |
| [dctl touch](dctl_touch.md) | Create an object, or update its modification time. |

### Integrity

| Command | Description |
|---------|-------------|
| [dctl verify](dctl_verify.md) | Verify that stored objects decrypt and match their recorded hashes. |
| [dctl check](dctl_check.md) | Compare source and destination without transferring. |
| [dctl scrub](dctl_scrub.md) | Re-read and verify the whole dataset, repairing from redundancy. |
| [dctl hashsum](dctl_hashsum.md) | Print content hashes for objects. |

### Audit & recovery

| Command | Description |
|---------|-------------|
| [dctl audit](dctl_audit.md) | Inspect and verify the tamper-evident audit log. |
| [dctl backup](dctl_backup.md) | Back up a local tree into a vault. |
| [dctl restore](dctl_restore.md) | Restore a vault, or part of one, to a local tree. |

### Mount

| Command | Description |
|---------|-------------|
| [dctl mount](dctl_mount.md) | Mount a remote as a filesystem. |

### Utility

| Command | Description |
|---------|-------------|
| [dctl about](dctl_about.md) | Show remote usage, quota and capability information. |
| [dctl version](dctl_version.md) | Show version and build information. |
| [dctl completion](dctl_completion.md) | Generate a shell completion script. |

### Compatibility aliases

Three verbs from the prototype CLI still parse, because scripts already use
them. They are hidden from `--help` and delegate to the modern command; write
the modern name in anything new.

| Alias | Use instead |
|-------|-------------|
| `dctl put` | [`dctl copy`](dctl_copy.md), local file into a vault |
| `dctl get` | [`dctl copy`](dctl_copy.md), vault into a local file |
| `dctl rm` | [`dctl deletefile`](dctl_deletefile.md) |

## Global options

Every flag below is accepted by every subcommand, before or after it. Each
command's own page documents the flags specific to that command.

### Configuration

| Flag | Environment | Description |
|------|-------------|-------------|
| `--config <PATH>` | `DCTL_CONFIG` | Path to the configuration file. |
| `--remote <SPEC>` | `DCTL_REMOTE` | Remote spec to operate on when a command takes no explicit path. |
| `--index <PATH>` | `DCTL_INDEX` | Path to the local encrypted index database. |

### Authentication

| Flag | Environment | Description |
|------|-------------|-------------|
| `--password <PASSWORD>` | `DCTL_PASSWORD` | Vault password. Prefer the alternatives: an argument is visible to every other process on the machine. |
| `--password-command <COMMAND>` | `DCTL_PASSWORD_COMMAND` | Command whose stdout is the vault password. |
| `--password-file <PATH>` | | File whose first line is the vault password. |
| `--key-file <PATH>` | | Second-factor keyfile: "know" plus "have". **Refused in this build** (exit 7) — the engine cannot apply the factor, and dropping it silently would be weaker protection than you asked for. |
| `--no-ask-password` | | Never prompt; fail instead. For unattended runs. |

`config`, `version`, `completion` and `about` never need an unlocked vault, and
never prompt for a password.

### Durability

| Flag | Default | Description |
|------|---------|-------------|
| `--verify <MODE>` | `checksum` | Verification strength after every write: `checksum` (compare the provider's stored checksum, no extra egress), `sample` (additionally Range-read and decrypt some chunks), `strict` (full read-back, decrypt, whole-file BLAKE3). Also settable per remote in `config.toml`. |
| `--verify-samples <N>` | `8` | Chunks sampled when `--verify sample`. |
| `--checksum` | | Compare by checksum rather than size and modification time. |
| `--size-only` | | Compare by size only. Conflicts with `--checksum`. |
| `--immutable` | | Refuse to modify or delete anything that already exists. |

### Transfer

| Flag | Default | Description |
|------|---------|-------------|
| `--transfers <N>` | `4` | Files transferred in parallel. |
| `--checkers <N>` | `8` | Metadata checks run in parallel. |
| `--bwlimit <RATE>` | | Bandwidth limit, e.g. `10M`. `off` for unlimited. |
| `--retries <N>` | `3` | Retries of a whole failed file. |
| `--low-level-retries <N>` | `10` | Retries of an individual network request. |
| `--timeout <SECONDS>` | `300` | Inactivity timeout on a transfer. |
| `--contimeout <SECONDS>` | `60` | Connection timeout. |
| `--max-transfer <SIZE>` | | Stop after transferring this much, e.g. `100G`. Exits **8**. |

### Filtering

| Flag | Default | Description |
|------|---------|-------------|
| `--include <PATTERN>` | | Include only paths matching this glob. Repeatable. |
| `--exclude <PATTERN>` | | Exclude paths matching this glob. Repeatable. |
| `--filter-from <PATH>` | | Read include/exclude rules from a file. Repeatable. |
| `--files-from <PATH>` | | Transfer only the paths listed in this file. |
| `--min-size <SIZE>` | | Skip files smaller than this. |
| `--max-size <SIZE>` | | Skip files larger than this. |
| `--max-depth <N>` | `-1` | Recursion depth limit; `-1` for unlimited. |

Commands that cannot yet honour the pattern filters **refuse** them rather than
ignoring them — see the note in [dctl sync](dctl_sync.md), where a dropped
`--exclude` deletes the files the rule was written to protect.

### Output

| Flag | Default | Description |
|------|---------|-------------|
| `--format <FORMAT>` | `text` | `text`, `json`, or `json-lines`. |
| `--json` | | Shorthand for `--format json`. Conflicts with `--format`. |
| `--units <UNITS>` | `binary` | `binary` (KiB, matches the OS) or `decimal` (kB, matches provider billing). |
| `--color <WHEN>` | `auto` | `auto`, `always`, `never`. |
| `--ascii` | | ASCII-only glyphs for bars and spinners. |
| `-P`, `--progress` | | Live progress bars, even when output is redirected. |
| `--stats <SECONDS>` | `60` | Emit a status line every N seconds. `0` disables. |
| `--stats-one-line` | | Condense periodic statistics onto a single line. |
| `-q`, `--quiet` | | Suppress all non-error output. |

### Logging & debugging

| Flag | Environment | Description |
|------|-------------|-------------|
| `-v`, `--verbose` | | Repeatable: `-v` info, `-vv` debug, `-vvv` trace. Default is warnings only. |
| `--log-level <LEVEL>` | `DCTL_LOG_LEVEL` | `error`, `warn`, `info`, `debug`, `trace`. Overrides `-v`. |
| `--log-format <FORMAT>` | `DCTL_LOG_FORMAT` | `human` (default), `json`, `plain`. |
| `--log-file <PATH>` | | Append logs to this file in addition to stderr. |
| `--log-source` | | Include source file and line in every log record. |
| `--dump <TARGET>` | | Repeatable protocol dump: `headers`, `bodies`, `requests`, `retries`, `filters`, `config`. Secrets are redacted regardless of what is asked for, and `bodies` never includes plaintext file content. |

### Safety

| Flag | Description |
|------|-------------|
| `-n`, `--dry-run` | Report what would happen without changing anything. |
| `-i`, `--interactive` | Prompt before each destructive action. Conflicts with `--force`. |
| `--force` | Skip confirmation prompts for destructive actions. |

The commands classified **destructive** — and therefore governed by
`--interactive` and `--force` — are `move`, `sync`, `moveto`, `delete`,
`deletefile`, `purge`, `rmdir`, `rmdirs` and `cleanup`.

## Exit codes

Codes 0–10 mirror rclone's taxonomy so existing automation ports across. Codes
20 and above are DCTL-specific and cover failures rclone has no concept of.

| Code | Name | Meaning |
|------|------|---------|
| 0 | `success` | Completed successfully. |
| 1 | `usage` | Command-line syntax or usage error. |
| 2 | `uncategorised` | Error not otherwise categorised. |
| 3 | `dir_not_found` | Directory not found. |
| 4 | `file_not_found` | File not found. |
| 5 | `temporary_error` | Temporary error; retries exhausted. |
| 6 | `partial_failure` | Some files failed to transfer. |
| 7 | `fatal_error` | Fatal error; cannot continue. |
| 8 | `transfer_limit_exceeded` | `--max-transfer` limit reached. |
| 9 | `no_files_transferred` | Succeeded, but no files were transferred. |
| 10 | `duration_limit_exceeded` | `--max-duration` limit reached. |
| 20 | `checksum_mismatch` | Verified write refused: checksum mismatch. Nothing was committed. |
| 21 | `integrity_failure` | AEAD authentication failed on read. The data was **not** served. |
| 22 | `vault_locked` | Vault locked: wrong password or corrupt envelope. |
| 23 | `index_error` | Encrypted index or journal error. |
| 24 | `audit_chain_broken` | Audit log hash-chain verification failed. |
| 25 | `cancelled` | Operation cancelled. Nothing was reported as successful. |

These are a public contract: a code's meaning never changes once released, and
new conditions get new numbers. The full text is in
[../EXIT_CODES.md](../EXIT_CODES.md); each command's page lists the subset it
can actually produce.

## Environment variables

| Variable | Equivalent |
|----------|------------|
| `DCTL_CONFIG` | `--config` |
| `DCTL_REMOTE` | `--remote` |
| `DCTL_INDEX` | `--index` |
| `DCTL_PASSWORD` | `--password` |
| `DCTL_PASSWORD_COMMAND` | `--password-command` |
| `DCTL_LOG_LEVEL` | `--log-level` |
| `DCTL_LOG_FORMAT` | `--log-format` |
| `DCTL_B2_KEY_ID`, `DCTL_B2_APP_KEY` | B2 credentials. Never in `config.toml`. |
| `DCTL_S3_ACCESS_KEY`, `DCTL_S3_SECRET_KEY` | S3 credentials. |
| `DCTL_R2_ACCESS_KEY`, `DCTL_R2_SECRET_KEY` | R2 credentials. |

Every flag has an environment equivalent or a file-based one, so DCTL runs
headless on a server with no interactive configuration step.

## See also

* [Command index](README.md) — every page, grouped as above.
* [dctl config](dctl_config.md) — where the file is and what may go in it.
* [dctl init](dctl_init.md) — create a vault before the first transfer.
* [dctl copy](dctl_copy.md) — the safe transfer verb, and the one to learn first.
* [dctl sync](dctl_sync.md) — the one that deletes. Read it before you run it.
* [../FORMAT.md](../FORMAT.md) — the on-disk container and index format.
* [../EXIT_CODES.md](../EXIT_CODES.md) — the exit-code contract in full.
