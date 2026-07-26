# dctl rcat

Read standard input and write it to an object.

## Synopsis

`dctl rcat` consumes everything on standard input and stores it as a single
object at `REMOTE:PATH`. It is the mirror image of [`cat`](dctl_cat.md) and exists
for the case [`copy`](dctl_copy.md) cannot serve: data that is being *produced*
rather than data that is already a file. `pg_dump mydb | gzip | dctl rcat
vault:backups/db.sql.gz` never puts the dump on disk; `tar -cf - /etc | dctl rcat
vault:backups/etc.tar` never materialises the tarball. If the bytes are already a
file, use `dctl copy` — it can check sizes and checksums, resume, and skip work
that is already done, none of which is possible for a stream.

**The length is never required in advance.** `pg_dump` cannot say how large its
output will be, and buffering the stream to find out would hold an arbitrary
amount of the user's data in memory. `rcat` reads a fixed 256 KiB chunk at a
time, writes it, counts it, and stops at EOF. Memory is O(1) regardless of how
much is piped in, and `--progress`/`--stats` report a live byte count during the
run (bytes *transferred* — never bytes verified, which is a claim only the commit
can make).

**It refuses before it reads, or not at all.** A pipe cannot be rewound. Every
reason `rcat` might decline is therefore evaluated *before* the first read, so a
refusal leaves the producer's output intact and the producer itself blocked on a
full pipe rather than drained into nothing. The decision table, in the order a
user can act on it:

1. `vault:` or an empty path names no object → exit **1**.
2. Standard input is a terminal → exit **1** (see below).
3. The destination names a remote → exit **7**, not implemented in this build.
4. `--dry-run` → report the plan, read nothing, exit **0**.
5. The destination belongs to a vault's object namespace → exit **7**. The same
   rule the transfer family applies, asked through the same code: a store
   remote's location refuses by name (`'/srv/vault' is the object store for
   remote 'archive'`), and a directory holding an envelope that no configured
   remote describes refuses and says so. Streaming plaintext into a vault's
   object tree is never quietly promoted into a sealed write — what a command
   encrypts is decided by the remote name typed.
6. The destination exists and `--immutable` was given → exit **1**.
7. The destination exists and an `--interactive` confirmation was declined →
   warn, read nothing, exit **0** with outcome `declined`.
8. Otherwise, stream and store.

Note the order of 3 and 4: a `--dry-run` aimed at a remote is *refused* rather
than rehearsed, because announcing "would store" for an operation this build
cannot perform would be a promise the tool cannot keep.

**A terminal on standard input is a usage error, not an invitation to type.**
Without the refusal, `dctl rcat vault:notes.txt` would simply block, which reads
as a hang — the most confusing way for a byte-stream command to fail. The error
names the shape that works (`producer | dctl rcat vault:name`) and points at
`dctl copy` for a file that already exists. To store genuinely empty input,
redirect it explicitly: `dctl rcat out.bin < /dev/null` creates a zero-byte
object and reports it as such.

**This command replaces an existing object, and by default it does not ask.**
`rcat` overwrites whatever is at the destination. DCTL's confirmation gate is
consulted, but the gate's default for a non-interactive run is to treat the fact
that you typed the command as consent — so in a script, `producer | dctl rcat
/srv/backups/db.sql` replaces yesterday's backup without a prompt. Three flags
change that: `--interactive` prompts before replacing anything that already
exists (and fails rather than assuming consent when there is no terminal to
prompt on), `--immutable` refuses outright to touch an existing object, and
`--dry-run` reports what would be stored without reading or writing a byte. A
declined replacement is **not** an error: nothing was read, the destination is
untouched, and the run exits 0 with outcome `declined` — check the outcome, not
just the exit code, if a script needs to know whether the data actually landed.

**The commit is the last step.** For a local destination, `PLAN.md` §6's rule is
expressed on the filesystem: nothing is ever written to the destination name.
The bytes go to a hidden staging file *beside* it — `.<name>.dctl.<pid>.tmp` in
the destination's own directory, so the final step is a rename within a single
filesystem rather than a cross-device copy — and only when the data is on stable
storage is it published:

1. stream stdin into the staging file;
2. `fsync` the staging file, so the data is on the platter before any name
   promises it exists;
3. `rename` it onto the destination — atomic within a directory, so a concurrent
   reader sees either the previous object or the complete new one, never a
   half-written mixture;
4. `fsync` the containing directory (POSIX only; on Windows the metadata change
   is made durable through the file handle already flushed), because on POSIX the
   rename is not durable until the directory is synced too.

Any failure between steps — a full disk, a producer that dies, a Ctrl-C — removes
the staging file and leaves the destination exactly as it was. A partially
written object is never committed, and anything found afterwards still carrying
the `.tmp` suffix was by definition never reported as stored. Unlike `cat`, which
tolerates a broken pipe on the way out, `rcat` tolerates **no** write failure at
all: a short object must never reach the destination name.

**An existing non-file at the destination is refused, never replaced.** If the
destination exists and is a directory, device or socket, `rcat` stops with a
usage error rather than renaming over something DCTL did not put there.

**Relationship to the verified-write contract.** For the local path implemented
today, "stored" means fsynced and atomically renamed — durable, but not read back
and not checksum-compared, so exit 20 (`checksum_mismatch`) is not reachable and
`--verify`/`--verify-samples`/`--checksum`/`--size-only` are accepted but change
nothing. When storing into a remote lands, the full §6 contract applies: the
stream is uploaded, the destination's checksum is compared against the one
computed locally, and only a match commits the index record. A mismatch commits
**nothing**, leaves no object addressable, and exits 20 — which is precisely why
the command can promise that a byte count in its report corresponds to data that
is really there.

### What runs today

**A local destination is fully implemented**: the bounded stdin pump, the staging
file, both fsyncs, the atomic rename, the cleanup guard, the `--immutable` and
`--interactive` gates, `--dry-run` and the JSON record all work now.

**Storing a stream into a remote is not implemented in this build.** It needs the
verified-write engine to accept an upload of unknown length, which the command
context does not yet carry. The invocation is refused before standard input is
touched, with exit **7**:

```
error: storing a stream into a remote (dctl rcat) is not implemented in this build
warning: Storing a stream in a remote needs the verified-write engine to accept an
upload of unknown length (PLAN.md §6), which the command context does not yet
carry. Nothing was read from standard input, so the producing command's output is
intact — send it to a local path instead, or store the data with `dctl copy` once
it is on disk.
```

The engine and the B2 backend arrive with `PLAN.md` §11 **Phase 1 (B2 MVP)**,
which delivers `copy`/`move`/`sync` under the full §6 contract in both plain and
vault modes.

```
dctl rcat REMOTE:PATH [flags]
```

## Examples

Stream a database dump straight into a local backup object, never touching a
temporary file. The staging file lives beside the destination and is renamed into
place only after both fsyncs; the confirmation goes to stderr, so stdout stays
free for anything further down the pipeline:

```console
$ pg_dump mydb | gzip | dctl rcat /srv/backups/db-2026-07-26.sql.gz
✓ stored 412.7 MiB from standard input as /srv/backups/db-2026-07-26.sql.gz
```

Record the result for a script. The JSON document goes to stdout — safe here,
because for `rcat` the payload is stdin, not stdout. `bytes` is populated only
when `outcome` is `stored`:

```console
$ tar -cf - /etc | dctl rcat /srv/backups/etc.tar --json
{
  "dest": "/srv/backups/etc.tar",
  "remote": null,
  "path": "/srv/backups/etc.tar",
  "bytes": 24586240,
  "outcome": "stored"
}
```

Rehearse a run. Nothing is read from standard input and nothing is created, so
the producer is left blocked rather than drained:

```console
$ pg_dump mydb | dctl rcat /srv/backups/db.sql --dry-run
warning: [dry-run] would store standard input as: /srv/backups/db.sql
```

On Windows the destination is a drive path like any other local path — a
one-character prefix is always a drive letter, never a remote name, and a UNC
share is local too:

```console
C:\> pg_dump.exe mydb | dctl rcat C:\Backups\db-2026-07-26.sql
✓ stored 412.7 MiB from standard input as C:\Backups\db-2026-07-26.sql
C:\> type payload.bin | dctl rcat \\nas01\backups\payload.bin
```

Protect an existing object. `--immutable` refuses before reading anything, so the
producer's output survives the refusal:

```console
$ pg_dump mydb | dctl rcat /srv/backups/db-2026-07-26.sql.gz --immutable
error: '/srv/backups/db-2026-07-26.sql.gz' already exists and --immutable was given
warning: --immutable refuses to modify anything that already exists.
$ echo $?
1
```

Ask before replacing. Only the exact word `yes` proceeds; anything else declines,
and a decline is a clean exit 0 with nothing read and nothing changed — check the
`outcome` field, not the exit code, if that distinction matters to a script:

```console
$ pg_dump mydb | dctl rcat /srv/backups/db.sql --interactive
replace '/srv/backups/db.sql'? Type 'yes' to confirm: no
warning: /srv/backups/db.sql: not replaced — nothing was read from standard input
$ echo $?
0
```

A vault destination is refused before standard input is touched, which is the
whole point of checking the destination first — `pg_dump`'s output is still
sitting in the pipe, unconsumed, and can be redirected somewhere else:

```console
$ pg_dump mydb | dctl rcat vault:backups/db-2026-07-26.sql
error: storing a stream into a remote (dctl rcat) is not implemented in this build
warning: Storing a stream in a remote needs the verified-write engine to accept an
upload of unknown length (PLAN.md §6), which the command context does not yet
carry. Nothing was read from standard input, so the producing command's output is
intact — send it to a local path instead, or store the data with `dctl copy` once
it is on disk.
$ echo $?
7
```

Running it with a keyboard on standard input fails immediately instead of looking
like a hang:

```console
$ dctl rcat b2prod:bucket/media/notes.txt
error: nothing to read from standard input
warning: rcat stores what a pipeline produces: 'producer | dctl rcat vault:name'.
To store a file that already exists, use 'dctl copy' instead.
$ echo $?
1
```

## Options

```
  -h, --help   help for rcat
```

`rcat` has no command-specific flags. The single positional argument
`<REMOTE:PATH>` is required and names the object to create; a bare `vault:` is a
usage error because it addresses a whole vault rather than an object. Everything
else that changes behaviour is a global flag.

## Options inherited from parent commands

Every global flag is accepted on `dctl rcat`, before or after the verb; see
[../GLOBAL_FLAGS.md](../GLOBAL_FLAGS.md) for the full set. The ones that change
what `rcat` does:

| Flag | Effect here |
|------|-------------|
| `--immutable` | Refuse to replace an existing destination. Checked before standard input is read. |
| `-i`, `--interactive` | Prompt before replacing an existing destination; requires typing `yes`. Fails with exit 1 when there is no terminal to prompt on. Conflicts with `--force`. |
| `--force` | Approve the replacement without prompting. Redundant unless `--interactive` is also in play, since a non-interactive run does not prompt. |
| `-n`, `--dry-run` | Report the plan, read nothing from standard input, create nothing. Overrides `--force`. |
| `--format`, `--json` | Emit the one-object record on stdout instead of the human line on stderr. `json` and `json-lines` produce the same fields and differ only in indentation. |
| `-P`, `--progress`, `--stats` | Show live bytes read. There is no total, because a stream's length is unknowable until it ends. |
| `--units` | `binary` (MiB) or `decimal` (MB) in the stderr confirmation. The JSON record is always exact bytes. |
| `--quiet` | Silences the confirmation and the end-of-run summary; errors still print. |

`rcat` is classified as a transfer command, so an end-of-run summary is printed
to stderr unless `--quiet` or a JSON format is active.

`--verify`, `--verify-samples`, `--checksum` and `--size-only` are parsed but do
not apply to the local write path implemented today (nothing is read back or
compared). The filter flags (`--include`, `--exclude`, `--min-size`, `--max-size`,
`--max-depth`, …) do not apply at all: `rcat` writes exactly one named object and
never enumerates anything. `--transfers`, `--checkers`, `--bwlimit`, `--retries`
and `--max-transfer` are not consulted in this build — a single stream is copied
by a single loop over one reused 256 KiB buffer.

## Exit codes

See [../EXIT_CODES.md](../EXIT_CODES.md) for the full contract.

| Code | Name | When |
|-----:|------|------|
| 0 | `success` | The stream was stored (`outcome: "stored"`), or a `--dry-run` reported its plan (`planned`), or an interactive replacement was declined (`declined`). The last two read nothing and change nothing. |
| 1 | `usage` | Unknown flag, no destination, a bare `vault:` or empty path, a `..` component in a remote path, standard input is a terminal, `--immutable` with an existing destination, a destination that exists and is not a regular file, a destination that names no file (`.`, `/`), or `--interactive` with no terminal to prompt on. |
| 2 | `uncategorised` | An I/O failure while streaming, syncing or renaming — most commonly a full disk. The staging file is removed and the destination is untouched. |
| 4 | `file_not_found` | The destination's directory does not exist, so the staging file could not be created. |
| 7 | `fatal_error` | The destination names a remote (**not implemented in this build**; nothing was read from standard input), the destination belongs to a vault's object namespace — a store remote's location, or a directory holding a vault envelope — or the destination directory could not be written for lack of permission. |
| 25 | `cancelled` | Ctrl-C or SIGTERM. The staging file is discarded; nothing was reported as stored. |

Exit 20 (`checksum_mismatch`) is not reachable in this build and becomes reachable
when storing into a remote lands: a destination whose checksum does not match will
abort with 20, having committed nothing. Exit 6 (`partial_failure`) is not
reachable — one object either lands whole or does not land at all.

## See also

* [dctl cat](dctl_cat.md) — the mirror image: write object contents to standard output.
* [dctl copy](dctl_copy.md) — store data that is already a file, with skipping, resuming and the full verified-write contract.
* [dctl copyto](dctl_copyto.md) — copy a single file to an exact destination name.
* [dctl moveto](dctl_moveto.md) — the same, deleting the source after a verified commit.
* [dctl touch](dctl_touch.md) — create an empty object without a stream.
* [dctl verify](dctl_verify.md) — prove afterwards that what was stored still decrypts and matches its hash.
* [dctl backup](dctl_backup.md) — back up a whole local tree rather than one stream.
