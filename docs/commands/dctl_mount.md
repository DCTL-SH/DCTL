# dctl mount

Serve a vault as a read-only filesystem.

## Synopsis

`mount` attaches a vault, or a subtree of one, to a directory on this machine, so
that ordinary programs — a file manager, a video player, `grep`, a backup tool —
read encrypted objects as files. Data is decrypted on the fly and **never lands
in plaintext on disk**: this build has no on-disk cache at all, and the modes
that would create one are refused rather than ignored.

The design goal that shapes everything below is streaming (`PLAN.md` §15).
Decryption is not the bottleneck — ChaCha20-Poly1305 pushes multiple gigabytes a
second — so the mount is built to hide **latency**. A `read` of a byte window
fetches only the AEAD chunks covering it, so seeking to 45:00 in a fifty-gigabyte
film transfers those chunks and nothing else; decrypted chunks are kept in a
bounded in-memory cache so a kernel reading a 1 MiB chunk in 4 KiB steps costs one
request rather than 256; and `--buffer-size` warms the chunks *after* a read so a
sequential reader finds the next ones already fetched and authenticated. Random
4 KiB-heavy workloads over a network mount — databases, millions of tiny files —
will never rival a local SSD, and are not the target.

```
dctl mount REMOTE: MOUNTPOINT [flags]
```

**Read-only is the whole of v1, and it is enforced rather than assumed.** Every
`write`, `create`, `unlink`, `rename`, `mkdir`, `rmdir`, `truncate`, `chmod`,
`chown`, `utimes`, `setxattr` and `fallocate` through the mount is refused with
**`EROFS`** — "Read-only file system" — and the mount is additionally attached
with the kernel's own `ro` flag, so most of those never reach userspace at all.
Both defences, not either. `PLAN.md` §12 is explicit that a read-write encrypted
mount is a filesystem project of its own; what this command must never do in the
meantime is accept a write and drop it, because a program that saw success and
lost its data is worse off than one that was refused. `--read-only` is accepted
and is a statement of what is already true; a run that omits it is told so on
stderr.

**The source is `REMOTE:` for the whole vault, or `REMOTE:PATH` for a subtree.**
An empty path is the normal case here, unlike the rest of the directory family —
`dctl mount vault: /mnt/vault` serves everything, `dctl mount vault:photos/2024
/mnt/photos` serves one branch. A subtree mount cannot address anything above its
root, and not because a check refuses it: every path the filesystem builds is the
root prefix joined with what the kernel asked for, so no path outside it can be
constructed. A local path as the source is refused rather than guessed at —
attaching one local directory to another is a bind mount, a job for the operating
system. The usual disambiguation applies: a remote name is at least two
characters, so `C:\vault` is a Windows drive path and `\\server\share` is a UNC
path, and both are local. `..` components are refused; other path noise is cleaned
and NFC-normalised.

**The mountpoint must exist, be a directory, and be empty.** FUSE does not create
one and DCTL does not either: a typo in a path would otherwise leave a stray
directory behind and attach an encrypted vault somewhere nobody meant. Emptiness
is the rule worth explaining, because it looks like pedantry until you know what a
mount does — **a mount hides whatever is already in the directory**. The files are
not deleted, but nothing can reach them until the filesystem is detached,
*including a backup running while the mount is up*, which would record them as
deleted. Hidden files count: a stray `.DS_Store` is reported, with a count, rather
than quietly ignored.

**Directories are inferred, because a vault has none.** A vault stores one record
per file, keyed by its logical path, and nothing that says `photos/2024` was ever
a thing you made. Every directory the mount shows is a grouping of logical paths
by their leading components — the *same* grouping [`dctl lsd`](dctl_lsd.md) and
[`dctl tree`](dctl_tree.md) perform, reused rather than restated, so the three
views of a tree cannot disagree about its shape. Two consequences are visible
through the mount: there is no such thing as an empty directory in a vault, and
`mkdir` fails with `EROFS` rather than creating something the format cannot store.

**One password, for as long as the mount is up.** The vault is unlocked once, at
mount time, and the unwrapped root key stays in this process's memory until the
mount ends. That is what makes a mount usable, and it is a real security property
— see [Security](#security) below, which is worth reading before leaving a mount
attached on a shared or unattended machine.

## Platforms

| OS | Backend | State |
|----|---------|-------|
| Linux | FUSE3, via the `fuser` crate | **Works.** Built against the pure-Rust mount path, so no `libfuse` is needed to build; `fusermount3` and `/dev/fuse` are needed to run. |
| macOS | macFUSE, via the `fuser` crate | **Works.** macFUSE must be installed, and its system extension allowed in *System Settings → General → Login Items & Extensions* the first time it loads. |
| Windows | WinFSP | **Not built.** WinFSP is not a FUSE binding and cannot be reached through `fuser`; the command refuses by name with exit **7**. |

`PLAN.md` §15 prefers **FSKit** on macOS — Apple-sanctioned, needs no kernel
extension, and therefore the 20-year-safe option — with **fuse-t** (NFS loopback,
also kext-free) as the fallback and macFUSE last. Neither FSKit nor fuse-t has a
Rust binding, so this build attaches through macFUSE, which *is* a kernel
extension. The command says so on the `backend:` line rather than reporting the
preference as though it were the implementation: the whole difference between
those three options is whether a kext is involved, and a user deciding what to
install needs the true answer.

## Ending a mount

Three ways, and they are not the same:

* **`umount /mnt/vault`** (or `diskutil unmount` on macOS) — the mount ends on its
  own and `dctl mount` exits **0**.
* **Ctrl-C, or `SIGTERM`** — the filesystem is detached, the session is allowed to
  finish, and the command exits **25** (`cancelled`). Cancellation is not success
  anywhere in DCTL (`PLAN.md` §7), so a wrapper script can tell "the operator
  stopped it" from "it finished". A systemd unit stopping this way should set
  `SuccessExitStatus=25`.
* **`SIGKILL`** — no code runs, so nothing this command does can help. Where the
  session is wider than the owning user (`--allow-other`, `--allow-root`) the
  kernel is asked for `auto_unmount` and detaches the filesystem itself.

Every other path out — a failure while mounting, a mount whose filesystem thread
could not start, the command's own future being cancelled — unmounts before it
returns. A stale mount is a real operational problem: the mountpoint becomes a
directory that every process touching it blocks on, on macOS including Finder, so
"there is no path out of here that leaves a mount attached" is the property the
shutdown code is built around rather than a nicety.

## Security

The vault is unlocked once and stays unlocked for the life of the mount. What
follows from that:

* **Anyone who can read the mountpoint reads plaintext.** No password, no prompt.
  By default the FUSE session only accepts requests from the user who started it;
  `--allow-other` opens it to *every* local account and `--allow-root` to root.
* **A machine left unattended with a mount up is a machine with the vault open.**
  A screen lock does not close it. Anything running as that user — a backup agent,
  a search indexer, a browser extension with filesystem access — reads it too, and
  reads it as ordinary files.
* **The key material outlives the last read.** The root key, the unwrapped
  per-object keys and a bounded working set of decrypted chunks live in RAM until
  the mount ends. They are wiped when dropped and are never written to disk by
  this command.
* **The remedy is to unmount.** Ending the mount wipes the keys and returns the
  vault to needing a password. Leaving a mount up "so it is there when I need it"
  is a decision worth making deliberately rather than by default.

Files served through the mount are additionally attached `noexec`, `nosuid` and
`nodev`: a vault records no mode bits, so a binary read out of one has no
provenance a kernel could check.

## Integrity

Every byte served carries its chunk's Poly1305 tag, verified against data binding
the object's authenticated header and that chunk's own index — so substitution,
reordering, splicing from another object and truncation are all caught. A chunk
that fails authentication is reported as `EIO` and **no bytes are returned**;
there is no mode in which the mount hands a program data that did not verify, and
the reason is written to the log with the path and the failure class beside it.

What a *windowed* read cannot establish is the whole-object statement: the
trailing footer BLAKE3 and the recorded plaintext hash both cover bytes a seek
never fetched. [`dctl verify`](dctl_verify.md) and [`dctl scrub`](dctl_scrub.md)
stream an object end to end and remain the reads that make it.

## Caching, and what the flags control

Two caches, both in memory, both bounded, neither on disk:

* **Decrypted chunks**, keyed by the object's own random identifier and the chunk
  index — never by path, so a file rewritten under the same name can never be
  served from a stale entry. This is what makes a sequential read cost one request
  per chunk instead of one per 4 KiB.
* **Directory listings**, aged out by `--dir-cache-time` and bounded in number.
  Re-reading one is a listing of that directory, never a re-read of any object.

`--buffer-size` (16 MiB by default) is the read-ahead: after a read the mount
warms the chunks covering the next this-many bytes, and asks the kernel for the
same window. It is claimed once per window rather than once per read, so a player
stepping through a chunk in 4 KiB reads schedules one fetch and not two hundred
and fifty-six. `--buffer-size 0` (or `off`) disables it.

`--dir-cache-time` (5 minutes) is tuned so browsing feels local while a file added
by another machine still appears without a remount. `--attr-timeout` (1 second)
matches FUSE's own default: longer risks a stale size, shorter turns every `stat`
into a round trip.

**A `readdir` of the mount root costs a walk of the whole index.** That is
inherited, not introduced — the vault's own listing materialises every record
under a prefix — so `ls /mnt/vault` on a ten-million-object vault is a
ten-million-record read, exactly as `dctl ls vault:` is. Listing a subdirectory
costs only that subtree. `--dir-cache-time` is the dial that decides how often the
root pass is paid.

## Flags that are refused rather than ignored

A flag this build cannot honour is a **usage error** (exit 1) naming the flag, not
a warning. A warning on stderr is invisible to the systemd unit or cron job that
will be running the mount, and a user who believed a dial was connected when it
was not would have no way to tell that from a working one by looking at the mount.

| Flag | Why it is refused |
|------|-------------------|
| `--daemon` | Detaching means `fork()`, and this process holds a thread pool, live provider connections and an open encrypted database. Only async-signal-safe calls are legal in the child of a fork in a threaded process, so the fork would be a deadlock waiting for the wrong moment. Background it the way your system already does: `dctl mount … &`, a systemd unit, or a launchd job. |
| `--vfs-cache-mode minimal\|writes\|full` | There is no on-disk cache in this build, and all three of those modes describe caching *writes*, which v1 has none of. `off` — the default — is honoured. |
| `--vfs-read-ahead` | It fills the on-disk cache, which does not exist. `--buffer-size` is the in-memory read-ahead and is honoured. |
| `--volname` off macOS | Linux FUSE has no volume-name concept; there is nothing a file manager would show it in. |
| `--include`, `--exclude`, `--min-size`, and the rest of the filter family | A mount serves what is in the vault. A filtered mount would hide files that still exist, still cost storage and are still listed by every other DCTL command — which looks exactly like data loss. Filter at the point of use: [`dctl ls`](dctl_ls.md), [`dctl copy`](dctl_copy.md) and [`dctl sync`](dctl_sync.md) all take the same flags and apply them. |

## Examples

Mount a whole vault. The plan goes to stderr; the process stays in the foreground
until the filesystem is detached:

```console
$ dctl mount vault: /mnt/vault
mounting vault: at /mnt/vault
backend: Linux FUSE3 (fuser)
options: read-only=true, dir-cache=5m00s, attr-timeout=1s, buffer=16.0 MiB, modtime=true
the mount is read-only: PLAN.md §15 makes v1 read-first, so every write, rename,
delete and truncate through it is refused with EROFS. --read-only is accepted and
is the only mode there is.
mounted at /mnt/vault — press Ctrl-C, or run 'umount' on the mountpoint, to detach
```

The same command on macOS names the backend it really uses, and why that is not
the one `PLAN.md` prefers:

```console
$ dctl mount vault:photos/2024 /Volumes/photos --read-only --volname Photos
mounting vault:photos/2024 at /Volumes/photos
backend: macFUSE (kernel extension; opt-in, highest throughput) — PLAN.md §15
prefers FSKit, which needs no kernel extension; neither it nor fuse-t has a Rust
binding, so this build attaches through macFUSE
options: read-only=true, dir-cache=5m00s, attr-timeout=1s, buffer=16.0 MiB, modtime=true
mounted at /Volumes/photos — press Ctrl-C, or run 'umount' on the mountpoint, to detach
```

Playing a large video straight out of the vault. The player seeks, and each seek
fetches the covering chunks rather than the file:

```console
$ dctl mount vault:media /mnt/media --buffer-size 32M --dir-cache-time 30m &
$ mpv /mnt/media/films/interview.mkv
```

Writing through the mount is refused, every time, by name:

```console
$ echo hello > /mnt/vault/notes.txt
bash: /mnt/vault/notes.txt: Read-only file system
$ rm /mnt/vault/photos/a.jpg
rm: cannot remove '/mnt/vault/photos/a.jpg': Read-only file system
$ mkdir /mnt/vault/new
mkdir: cannot create directory '/mnt/vault/new': Read-only file system
```

A flag this build cannot honour stops the command rather than being dropped:

```console
$ dctl mount vault: /mnt/vault --vfs-cache-mode full
error: --vfs-cache-mode full cannot be honoured: this build has no on-disk cache
warning: The read-only mount streams from the vault and keeps a bounded working
set of decrypted chunks in memory; nothing is written to local disk. The other
three modes describe caching writes, and PLAN.md §15 makes the writable mount a
later phase. Use --buffer-size for in-memory read-ahead.
$ echo $?
1
```

A non-empty mountpoint is refused, with a count, because the mount would hide what
is in it — and it is refused *before* the password is asked for:

```console
$ dctl mount vault: /mnt/vault
error: '/mnt/vault' is not empty (3 entries)
warning: A mount hides whatever is already in the directory until it is
unmounted — the files are not lost, but nothing can reach them, including a
backup run while the mount is up. Use an empty directory.
$ echo $?
1
```

A missing mountpoint gets its own exit code, so a wrapper script can create it and
retry rather than parsing a message:

```console
$ dctl mount vault: /mnt/not-there
error: '/mnt/not-there' does not exist
warning: A mount attaches to an existing empty directory. Create it first.
$ echo $?
3
```

On **Windows** there is no FUSE layer, and the command says which one is missing:

```console
C:\> dctl mount vault:photos X:
error: dctl mount: a filesystem adapter for this platform (the read-only mount is
built on FUSE, which Windows does not have; attaching a filesystem there needs
WinFSP, and the WinFSP binding that dctl-mount would own does not exist) is not
implemented in this build
$ echo $?
7
```

## Options

```
      --read-only                  Serve the filesystem read-only
      --allow-other                Let other users access the mount
      --allow-root                 Let root access the mount, without opening it to everyone
      --daemon                     Detach and run in the background
      --volname <NAME>             Name shown for the volume in the desktop file manager
      --dir-cache-time <DURATION>  How long a directory listing is cached before it is re-read [default: 5m]
      --vfs-cache-mode <MODE>      How much of a file the VFS keeps on local disk [default: off] [possible values: off, minimal, writes, full]
      --vfs-read-ahead <SIZE>      Extra data to fetch past the end of a read, when the VFS cache is on [default: 0]
      --buffer-size <SIZE>         In-memory read-ahead buffer held per open file [default: 16M]
      --attr-timeout <DURATION>    How long the kernel may cache file attributes [default: 1s]
      --no-modtime                 Do not read modification times, reporting the mount time instead
  -h, --help                       Print help (see more with '--help')
  -V, --version                    Print version
```

Both positionals are required, in order: `<REMOTE:>` — a bare `REMOTE:` for the
whole vault or `REMOTE:PATH` for a subtree — and `<MOUNTPOINT>`, an existing empty
directory.

**Durations** (`--attr-timeout`, `--dir-cache-time`) accept `500ms`, `5s`, `5m`,
`2h`, `1d`, or a bare number meaning seconds, with fractions allowed (`1.5s`) and
suffixes matched case-insensitively. **Sizes** (`--buffer-size`,
`--vfs-read-ahead`) use the same ladder as every other size flag — `16M` is binary
(16 MiB), `1MB` is decimal — and here `0` or `off` means *allocate nothing*, not
"unlimited". All four are validated by the argument parser, so a typo is a usage
error naming the accepted spellings before anything is attempted.

**`--allow-other`** requires `user_allow_other` in `/etc/fuse.conf` on Linux, and
opens the unlocked vault to every local account — read the [Security](#security)
section first. **`--no-modtime`** reports the mount time for every file instead of
its recorded modification time; the flag saves no work in this engine, because the
times arrive with the directory listing anyway, but it is honoured because "do not
leak timestamps through the mount" is a real request. Do not point a
timestamp-comparing backup tool at a mount that uses it.

**What the mount reports about files it serves.** Sizes are **plaintext** lengths,
so `ls -l` through the mount and `dctl cat … | wc -c` agree. Files are `r--r--r--`
and directories `r-xr-xr-x`; the execute bit on a directory is *search*
permission, without which nothing could traverse the mount. Everything is owned by
the user running the mount, because a vault records no uid — that is deliberate
(`PLAN.md` §2 keeps machine metadata out of the stored form). A directory's
`st_size` is one block, not the recursive total beneath it: `dctl lsd` is the
command that answers "how big is this subtree", in a column nobody can mistake for
a POSIX field. `df` reports the total under the mount root with **zero free
space**, which is the one number on a read-only filesystem that is certainly right.

## Options inherited from parent commands

Every global flag is accepted; see [../GLOBAL_FLAGS.md](../GLOBAL_FLAGS.md). The
ones that matter here:

| Flag | Effect here |
|------|-------------|
| `-v`, `--verbose` | Raises the log level; the plan and the mount notice are printed either way. |
| `--quiet` | Suppresses the plan and the notices. Errors are still printed. |
| `-n`, `--dry-run` | **Has no effect.** A mount is not a data-changing operation, so there is nothing to simulate; validation runs and the filesystem is attached. |
| `--format`, `--json` | Accepted and unused: a mount has no structured result to render. |
| `--units` | Chooses binary (`16.0 MiB`) or decimal (`16.8 MB`) rendering of the sizes in the reported plan. |
| `--password-command`, `--no-ask-password` | How the one password is obtained. `--no-ask-password` fails rather than prompting, which is what an unattended unit wants. |
| `--include`, `--exclude`, … | **Refused**, with an explanation. See the table above. |

## Exit codes

See [../EXIT_CODES.md](../EXIT_CODES.md) for the full contract.

| Code | Name | When |
|------|------|------|
| 0 | `success` | The filesystem was unmounted — by `umount`, or by the kernel — and the command ended on its own. |
| 1 | `usage` | An unparseable command line; a malformed duration or size; a local, UNC or drive-letter *source*; a remote name shorter than two characters or containing a separator; a `..` component; a mountpoint that exists but is a file, or is not empty; **and every flag this build cannot honour**. |
| 2 | `uncategorised` | The mountpoint could not be inspected, or the connection between the filesystem and the kernel failed while it was running. |
| 3 | `dir_not_found` | The mountpoint does not exist. Distinct from 1 so a wrapper can create it and retry. |
| 7 | `fatal_error` | The mountpoint exists but cannot be read; the platform's FUSE layer is missing or refused the mount; **and the whole command on a platform with no FUSE layer**. |
| 22 | `vault_locked` | The vault would not unlock — no password, a wrong one, or an envelope that will not unwrap. |
| 25 | `cancelled` | Ctrl-C or `SIGTERM`. The filesystem is detached first. |

Failures *through* the mount are errnos, not exit codes: `EROFS` for anything that
would change something, `ENOENT` for a name that is not there, `EIO` for bytes
that failed authentication, and `EAGAIN` for a provider that did not answer.

## See also

* [dctl cat](dctl_cat.md) — stream one object's contents, with `--offset`, without mounting anything.
* [dctl copy](dctl_copy.md) — materialise files locally instead of serving them through a filesystem.
* [dctl lsd](dctl_lsd.md) — the directory grouping the mount's tree is built from, with recursive totals.
* [dctl tree](dctl_tree.md) — browse the vault's structure without a mount.
* [dctl verify](dctl_verify.md) — the whole-object integrity check a windowed read cannot make.
* [dctl scrub](dctl_scrub.md) — the same check across everything, in constant memory.
