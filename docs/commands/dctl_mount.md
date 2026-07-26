# dctl mount

Mount a remote as a filesystem.

## Synopsis

**`dctl mount` cannot mount anything in this build.** It is `PLAN.md` §11
**Phase 2 (Streaming mount)**, and **every** run ends in an error with a real
exit code — there is no mode, `--dry-run` included, in which this command exits
0. Read *What runs today* below before anything else on this page; the rest
describes an interface that is final and an engine that is not yet attached.

When it lands, `mount` attaches a vault, or a subtree of one, to a directory on
this machine, so that ordinary programs — a file manager, a video player, `grep`,
a backup tool — read encrypted objects as files. Data is decrypted on the fly and
never lands in plaintext on disk except in the VFS cache, which is itself
encrypted (`PLAN.md` §15). The design goal that shapes every default below is
streaming: playing a large encrypted video straight off B2 without staging it
first. `PLAN.md` §12 is explicit that a read-write encrypted mount is a
filesystem project of its own, so v1 is read- and stream-first; `--read-only` is
the setting to reach for on a backup vault, and the one to expect to be
best-supported.

**The source is `REMOTE:` for the whole vault, or `REMOTE:PATH` for a subtree.**
An empty path is the normal case here, unlike the rest of the directory family —
`dctl mount vault: /mnt/vault` serves everything, `dctl mount vault:photos/2024
/mnt/photos` serves one branch. A local path is refused rather than guessed at:
attaching one local directory to another is a bind mount, a job for the operating
system, and silently accepting it would be a confusing way to find that out. The
usual disambiguation applies — a remote name is at least two characters, so
`C:\vault` is a Windows drive path and `\\server\share` is a UNC path, and both
are local. `..` components are refused; other path noise is cleaned and
NFC-normalised.

**The mountpoint must exist, be a directory, and be empty.** None of the three
backends creates a mountpoint, and DCTL does not create one either: a typo in a
path would otherwise leave a stray directory behind and attach an encrypted vault
somewhere nobody meant. Emptiness is the rule worth explaining, because it looks
like pedantry until you know what a mount does — **a mount hides whatever is
already in the directory**. The files are not deleted, but nothing can reach them
until the filesystem is detached, *including a backup running while the mount is
up*, which would record them as deleted. Linux FUSE refuses a non-empty
mountpoint outright; DCTL refuses it on every platform so the rule does not
change when a script moves machines. Hidden files count: a stray `.DS_Store` is
reported, with a count, rather than quietly ignored.

**Windows has one exception**: WinFSP can attach a filesystem to an unused
**drive letter** (`X:`), which by definition is not an existing directory. A
bare drive letter as the mountpoint therefore skips the three checks above — on
Windows only. The same string on Linux or macOS is an ordinary relative path with
a colon in it and is checked like any other.

**Which filesystem layer is used depends on the platform** (`PLAN.md` §15). The
order is a preference, not a detection result — nothing here probes the machine:

| OS | Backend, in preference order | Why that order |
|----|------------------------------|----------------|
| Linux | FUSE3 (via `fuser`) | The only real option, and a good one: writeback cache, large `max_read`/`max_write`, multithreaded, big readahead. |
| macOS | FSKit (macOS 15+) → fuse-t → macFUSE | FSKit is Apple-sanctioned and needs no kernel extension, which is what makes it the 20-year-safe default (`PLAN.md` §13.1). fuse-t also avoids a kext, by tunnelling over NFS loopback. macFUSE *is* a kext: highest throughput, and the one any macOS release can break, so it is last. |
| Windows | WinFSP | The mature FUSE-like layer. ProjFS is a later option for read-first streaming virtualisation. |

**Caching is two-tiered, and the flags choose how much of each you get.**
`--buffer-size` is per open file and lives in RAM: 16 MiB is four of the 4 MiB
AEAD chunks reads are aligned to, so a sequential reader always has whole chunks
queued. `--vfs-cache-mode` decides how much lands on local disk, and defaults to
`off` — a mount that silently filled a disk cache on first use would be a
surprise, so the expensive modes are opt-in. `--vfs-read-ahead` fetches past the
end of a read *into that on-disk cache*, so it does nothing while the cache is
off; asking for both prints a warning rather than an error, because the same
flags are correct in a mode this run did not ask for. `--dir-cache-time` (5m) is
tuned so browsing feels local while a file added by another machine still appears
without a remount, and `--attr-timeout` (1s) matches FUSE's own default: longer
risks a writer seeing a stale size, shorter turns every `stat` into a round trip.

**Relationship to the verified-write contract.** A mount is mostly a read path,
and the §6 read-path rule is the one that governs it: every chunk is
AEAD-verified as it is decrypted, and an integrity failure is loud — it is
reported, never served as data. There is no mode in which a mount hands a program
bytes that failed authentication. Writes through a mount, when they exist, are
governed by the same verified-write pipeline as [`copy`](dctl_copy.md): staged,
checksum-compared at the destination, and only then committed to the index.

**Output.** `mount` produces no structured result — it either runs a filesystem
in the foreground or fails — so `--format json` has nothing to render and emits
nothing. The resolved plan (source, mountpoint, backend, options) goes to
**stderr** at `-v`, where it belongs: stdout is reserved for data, and a mount's
data is the filesystem itself.

### What runs today

Everything except the filesystem adapter. In order, a run:

1. parses and validates the whole flag surface, including durations and sizes;
2. parses the source, refusing local paths;
3. validates the mountpoint — so a bad mountpoint is reported as a **bad
   mountpoint**, not as a missing feature the user would then wait for;
4. warns about combinations that parse but cannot do what they look like they do;
5. reports the mount it would have attached, at `-v`;
6. fails with exit **7** (`fatal_error`):

```
error: dctl mount is not implemented in this build
warning: The mountpoint checks, the flag surface and the per-platform backend
choice are final and have already run — only the filesystem adapter is missing.
It is PLAN.md phase 2 (§11, §15): FUSE3 on Linux, FSKit/fuse-t/macFUSE on macOS,
WinFSP on Windows.
```

The flag spellings and defaults on this page are final on purpose: `--help`, the
generated shell completions and this document are built from them now, and Phase
2 has to be able to wire an engine underneath them without renaming a flag or
moving a default. Running the command today is still useful for exactly one
thing — finding out that your mountpoint is missing, occupied or not a directory
now, rather than on the day the feature lands.

```
dctl mount REMOTE: MOUNTPOINT [flags]
```

## Examples

Mount a whole vault, with `-v` so the resolved plan is printed. Everything below
is stderr; the run ends at the engine boundary. This is a Linux machine, where
there is one backend and no fallback:

```console
$ dctl mount vault: /mnt/vault -v
would mount vault: at /mnt/vault
backend: Linux FUSE3 (fuser)
options: read-only=false, dir-cache=5m00s, attr-timeout=1s, vfs-cache=off, buffer=16.0 MiB, read-ahead=0 B, modtime=true
error: dctl mount is not implemented in this build
warning: The mountpoint checks, the flag surface and the per-platform backend
choice are final and have already run — only the filesystem adapter is missing. ...
$ echo $?
7
```

The same command on macOS names the fallback chain, which is the answer to "what
do I need to install":

```console
$ dctl mount vault:photos/2024 /Volumes/photos -v --read-only
would mount vault:photos/2024 at /Volumes/photos
backend: macOS FSKit (macOS 15+, no kernel extension) (falling back to fuse-t (no kernel extension, NFS loopback), macFUSE (kernel extension; opt-in, highest throughput))
options: read-only=true, dir-cache=5m00s, attr-timeout=1s, vfs-cache=off, buffer=16.0 MiB, read-ahead=0 B, modtime=true
error: dctl mount is not implemented in this build
```

A media subtree tuned for scrubbing back and forth through large files: the
on-disk cache is on, so read-ahead is worth paying for, and directory listings
are held longer because the tree does not change:

```console
$ dctl mount b2prod:bucket/media /mnt/media \
    --read-only \
    --vfs-cache-mode full \
    --vfs-read-ahead 128M \
    --buffer-size 32M \
    --dir-cache-time 30m \
    --volname Media -v
would mount b2prod:bucket/media at /mnt/media
backend: Linux FUSE3 (fuser)
options: read-only=true, dir-cache=30m00s, attr-timeout=1s, vfs-cache=full, buffer=32.0 MiB, read-ahead=128.0 MiB, modtime=true
error: dctl mount is not implemented in this build
```

Read-ahead without a cache to fill is a warning, not a refusal — the same flags
are correct under `--vfs-cache-mode full`:

```console
$ dctl mount vault: /mnt/vault --vfs-read-ahead 128M
warning: --vfs-read-ahead does nothing with --vfs-cache-mode off: read-ahead
fills the on-disk cache, and there is none. Use --buffer-size for in-memory
read-ahead, or turn the cache on.
error: dctl mount is not implemented in this build
```

A non-empty mountpoint is refused, with a count, because the mount would hide
what is in it. This is a **usage** error (1), not the engine refusal (7) — the
distinction is the whole reason the checks run in a build that cannot mount:

```console
$ dctl mount vault: /mnt/vault
error: '/mnt/vault' is not empty (3 entries)
warning: A mount hides whatever is already in the directory until it is
unmounted — the files are not lost, but nothing can reach them, including a
backup run while the mount is up. Use an empty directory.
$ echo $?
1
```

A missing mountpoint gets its own exit code, so a wrapper script can create it
and retry rather than parsing a message:

```console
$ dctl mount vault: /mnt/not-there
error: '/mnt/not-there' does not exist
warning: A mount attaches to an existing empty directory. Create it first.
$ echo $?
3
```

On **Windows**, an unused drive letter is a legitimate WinFSP mountpoint and
skips the existence and emptiness checks entirely — there is no directory to
inspect. A directory path such as `C:\mnt\vault` is checked exactly like a POSIX
one:

```console
C:\> dctl mount vault:photos X: -v
would mount vault:photos at X:
backend: WinFSP
options: read-only=false, dir-cache=5m00s, attr-timeout=1s, vfs-cache=off, buffer=16.0 MiB, read-ahead=0 B, modtime=true
error: dctl mount is not implemented in this build
```

Windows also warns about the POSIX-only dials, rather than failing a script that
is correct on Linux:

```console
C:\> dctl mount vault: X: --allow-other --daemon
warning: --allow-other and --allow-root are POSIX permission concepts and have
no effect on Windows, where access follows the drive's ACL.
warning: --daemon has no effect on Windows: a filesystem stays up as a service
there, not as a detached process.
error: dctl mount is not implemented in this build
```

A local path as the *source* is refused: mounting one local directory onto
another is a bind mount, not a job for an encrypted object-store client:

```console
$ dctl mount C:\vault X:
error: 'C:\vault' is a local path, not a remote
warning: mount serves a remote, written REMOTE:. Attaching one local directory
to another is a job for your operating system's own bind mount.
$ echo $?
1
```

## Options

```
      --allow-other                Let other users access the mount
      --allow-root                 Let root access the mount, without opening it to everyone
      --attr-timeout <DURATION>    How long the kernel may cache file attributes [default: 1s]
      --buffer-size <SIZE>         In-memory read-ahead buffer held per open file [default: 16M]
      --daemon                     Detach and run in the background
      --dir-cache-time <DURATION>  How long a directory listing is cached before it is re-read [default: 5m]
  -h, --help                       help for mount
      --no-modtime                 Do not read modification times, reporting the mount time instead
      --read-only                  Serve the filesystem read-only
      --vfs-cache-mode <MODE>      How much of a file the VFS keeps on local disk [default: off] [possible values: off, minimal, writes, full]
      --vfs-read-ahead <SIZE>      Extra data to fetch past the end of a read, when the VFS cache is on [default: 0]
      --volname <NAME>             Name shown for the volume in the desktop file manager
```

Both positionals are required, in order: `<REMOTE:>` — a bare `REMOTE:` for the
whole vault or `REMOTE:PATH` for a subtree — and `<MOUNTPOINT>`, an existing
empty directory (or, on Windows, an unused drive letter).

**Durations** (`--attr-timeout`, `--dir-cache-time`) accept `500ms`, `5s`, `5m`,
`2h`, `1d`, or a bare number meaning seconds, with fractions allowed (`1.5s`) and
suffixes matched case-insensitively. **Sizes** (`--buffer-size`,
`--vfs-read-ahead`) use the same ladder as every other size flag — `16M` is
binary (16 MiB), `1MB` is decimal — and here `0` or `off` means *allocate
nothing*, not "unlimited". All four are validated by the argument parser, so a
typo is a usage error naming the accepted spellings before anything is attempted.

**`--vfs-cache-mode`** in detail:

| Mode | Behaviour |
|------|-----------|
| `off` (default) | Stream everything, keep nothing on disk. Reads only, no rewrites. |
| `minimal` | Cache only what an application opens for writing. |
| `writes` | Cache written data, so a re-read after a write is served locally. |
| `full` | Cache read and written data. The only mode where seeking backwards in a large file is free the second time. |

**Platform notes.** `--allow-other` requires `user_allow_other` in
`/etc/fuse.conf` on Linux; it and `--allow-root` are POSIX concepts with no
meaning on Windows, where access follows the drive's ACL. `--daemon` has no
effect on Windows, where a filesystem stays up as a service rather than as a
detached process. `--no-modtime` saves one index lookup per file, at the cost of
every timestamp seen through the mount being the mount time — do not point a
timestamp-comparing backup tool at a mount that uses it.

## Options inherited from parent commands

Every global flag is accepted; see [../GLOBAL_FLAGS.md](../GLOBAL_FLAGS.md). The
ones that matter here:

| Flag | Effect here |
|------|-------------|
| `-v`, `--verbose` | Prints the resolved plan — source, mountpoint, backend and options — to stderr. Without it, a run is silent up to its warnings and its error. |
| `--quiet` | Suppresses the plan and the advisory warnings. Errors are still printed. |
| `-n`, `--dry-run` | **Has no effect.** It does not make this command exit 0, and it does not suppress the engine refusal; validation runs and the command fails either way. |
| `--format`, `--json` | Accepted and unused: a mount has no structured result to render. |
| `--units` | Chooses binary (`16.0 MiB`) or decimal (`16.8 MB`) rendering of the sizes in the reported plan. |

## Exit codes

See [../EXIT_CODES.md](../EXIT_CODES.md) for the full contract.

| Code | Name | When |
|------|------|------|
| 1 | `usage` | An unparseable command line; a malformed duration or size; a `--vfs-cache-mode` that is not one of the four; a local, UNC or drive-letter *source*; a remote name shorter than two characters or containing a separator; a `..` component; a mountpoint that exists but is a file, or is not empty. |
| 2 | `uncategorised` | The mountpoint could not be inspected or listed for a reason other than "missing" or "permission denied". |
| 3 | `dir_not_found` | The mountpoint does not exist. Distinct from 1 so a wrapper can create it and retry. |
| 7 | `fatal_error` | The mountpoint exists but cannot be read (permission denied); **and the engine boundary — every run that passes validation ends here today.** |
| 25 | `cancelled` | Ctrl-C or SIGTERM. |

**Exit code 0 is not reachable in this build, in any mode.** When Phase 2 lands,
a foreground mount exits 0 when it is cleanly unmounted, and the read path makes
21 (`integrity_failure`) reachable for data that fails AEAD authentication — such
data is reported, never served.

## See also

* [dctl cat](dctl_cat.md) — stream one object's contents without mounting anything.
* [dctl copy](dctl_copy.md) — materialise files locally instead of serving them through a filesystem.
* [dctl tree](dctl_tree.md) — browse the vault's structure without a mount.
* [dctl mkdir](dctl_mkdir.md) — create the empty directories a mounted subtree may need.
* [dctl about](dctl_about.md) — remote usage, quota and capability information.
* [dctl verify](dctl_verify.md) — prove that what a mount would serve still decrypts and matches its recorded hashes.
