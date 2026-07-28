# DCTL global flags

Every flag on this page is accepted by **every** subcommand, before or after the
subcommand name — `dctl --json ls vault:photos` and `dctl ls --json vault:photos`
are the same invocation. They are defined in one place,
`crates/dctl-cli/src/cli/globals.rs`, and grouped here under the same headings
`dctl --help` uses.

Which flags actually *change* a given command is documented on that command's
page under **Options inherited from parent commands**; a flag that is irrelevant
to a command is accepted and ignored rather than rejected.

**Resolution order.** For any setting that has more than one source, the most
specific statement of intent wins:

```
command-line flag  >  DCTL_* environment variable  >  config.toml  >  built-in default
```

Only two settings reach `config.toml` today: the remote definitions themselves,
and `verify` (per remote — see [Durability](#durability)). Every other default in
the tables below comes from `crates/dctl-cli/src/constants.rs`, which is the
single source of truth for them.

**Environment variables** are the `DCTL_`-prefixed spellings shown in each table.
An exported-but-empty variable is treated as unset wherever DCTL can tell the
difference, because a blank value is almost always a CI interpolation that
failed rather than a deliberate choice.

`-h`/`--help` and `-V`/`--version` are clap built-ins rather than members of the
global block, and are not repeated below.

> **Status.** Every flag on this page either **acts** or is **refused**. There is
> no third state. A flag this build cannot honour fails the run before anything
> is read or written, names itself, and says which layer owes the capability —
> the way `--key-file` always has. They are listed together under
> [Flags that are refused](#flags-that-are-refused).
>
> This replaces a *not yet honoured* category that eleven flags sat in, including
> `--bwlimit` and `--max-transfer`. Both are cost controls — the flags an operator
> sets so a runaway job cannot generate a bill — and both were accepted, listed
> here, and silently ignored: `--bwlimit 1k` moved 10 MiB at 32.9 MiB/s, and
> `--max-transfer 1M` moved the whole 10 MiB and exited 0. A flag in that state is
> worse than one that does not exist, because the operator believes they capped
> their egress. `crates/dctl-cli/src/cli/reach.rs` now holds the classification
> for every global flag and a test fails the build if a new one is added without
> either reaching an implementation or being explicitly refused.

---

## Configuration

| Flag | Value | Default | Environment |
|------|-------|---------|-------------|
| `--config` | `PATH` | platform config dir + `config.toml` | `DCTL_CONFIG` |
| `--remote` | `SPEC` | none | `DCTL_REMOTE` |
| `--index` | `PATH` | platform data dir + `vault.redb` | `DCTL_INDEX` |

### `--config PATH`

The configuration file this invocation uses. The default is `config.toml` inside
`~/.dctl/config.toml`. One directory holds everything DCTL writes, and the
layout is identical on macOS, Linux and Windows; `DCTL_HOME` relocates the whole
tree at once.
on Windows, and `./.dctl` where no home directory can be determined. A file you
*name* and get wrong is a hard error; the
*default* path being absent is a fresh installation and yields an empty
configuration, which is what lets DCTL run entirely from flags and environment
variables.

The file holds non-secret settings only — remote names, types, endpoints,
buckets, regions, policy defaults (`PLAN.md` §14). It is created `0600`, and DCTL
warns on stderr (but does not refuse to run) when it is group- or world-readable,
because what leaks is reconnaissance rather than credentials.

### `--remote SPEC`

The remote a command operates on when it is given no explicit target. Commands
still accept `REMOTE:PATH` positionally and that always wins; this is the setting
that lets a container or a cron job carry the destination in its environment
instead of in every command line. A spec is `name:path` (`vault:photos/2024`), and
a single ASCII letter before the colon is a drive letter on a platform that has
drives, so `C:\data` is a local path on Windows and the remote `C` elsewhere.

### `--index PATH`

The local encrypted index database (`redb`), which is the record of what is
actually stored: the durability contract's commit step (`PLAN.md` §6 step 6)
writes here, and nothing counts as stored until it does. The default is
`vault.redb` inside `~/.dctl/index/`.
Point it somewhere else to keep several vaults side by side on one machine, or to
put the index on a disk you actually back up.

---

## Authentication

| Flag | Value | Default | Environment |
|------|-------|---------|-------------|
| `--password` | `PASSWORD` | none | `DCTL_PASSWORD` |
| `--password-command` | `COMMAND` | none | `DCTL_PASSWORD_COMMAND` |
| `--password-file` | `PATH` | none | — |
| `--recovery-phrase` | `PHRASE` | none | `DCTL_RECOVERY_PHRASE` |
| `--recovery-phrase-file` | `PATH` | none | — |
| `--key-file` | `PATH` | none | — |
| `--no-ask-password` | — | off | — |

Sources are tried in a fixed order, most explicit first, so a scripted run is
never surprised by a prompt it did not ask for:

```
--password / DCTL_PASSWORD  →  --password-command  →  --password-file  →  interactive prompt
```

The recovery phrase is a **separate factor**, not another entry in that chain: it
unwraps its own slot in the envelope, so supplying it does not consult the
password sources at all.

Whatever the source, one trailing line ending is stripped and nothing else:
leading and interior whitespace are part of the passphrase, because trimming them
would make a correct password fail against the vault it created. An empty result
is refused rather than tried. Every failure on this path exits **22**
(`vault_locked`).

### `--password PASSWORD`

The vault password as a literal argument. Reach for it only in a throwaway shell:
an argument is visible in `ps` to every other process on the machine and lands in
shell history. `DCTL_PASSWORD` fills the same field and is the form to use for
containers and CI; `-v` reports which of the two supplied the value, since they
are otherwise indistinguishable at the point of use.

### `--password-command COMMAND`

A command whose stdout is the password — the flag to use with an existing secret
manager (`pass show vault`, `op read …`, a cloud secret fetch). It runs through
the platform shell (`sh -c`, or `cmd /C` on Windows) so a pipeline works without
quoting games, and it must exit 0. The helper's own stderr is deliberately not
echoed: it is attacker-influenceable text on a credential path, and a helper that
prints the secret on failure must not leak it into DCTL's logs.

### `--password-file PATH`

Reads the password from the first line of a file. Useful for a systemd unit or a
Kubernetes secret mounted at a path, where a command would be indirection for its
own sake. Protect the file yourself — DCTL reads whatever mode you left on it.

### `--recovery-phrase PHRASE`

The BIP-39 phrase `dctl init` prints once, used **instead of** the password. It
is global rather than a flag on `dctl vault recover`, and that is the point of the
recovery story: somebody who has lost their password needs their data, not a
receipt saying the phrase is valid. `dctl ls vault: --recovery-phrase "…"` and
`dctl cat`, `dctl copy`, `dctl restore` all run under it.

Same exposure warning as `--password` — an argument is visible in `ps` — with one
difference that makes it worse: **a phrase cannot be rotated by changing the
password.** Changing the password never invalidates the phrase, which is what
keeps a paper backup current for the vault's whole life and is also why leaking it
is permanent. Prefer `DCTL_RECOVERY_PHRASE` or the file form.

### `--recovery-phrase-file PATH`

The whole file is read and BIP-39's own whitespace rules are applied — not
`--password-file`'s first-line rule. Twenty-four words come off a sheet of paper,
and somebody transcribing them will break the lines where the paper breaks them;
reading only the first line would reject a correct phrase at the one moment it is
being used.

### `--key-file PATH`

The second-factor keyfile from `PLAN.md` §8: something you *have* mixed into the
KEK alongside something you *know*, so that a stolen password alone does not open
the vault.

**Not supported by the engine in this build**, and the layer is named because it
is not the CLI's: `dctl_core::Vault::init` and `::unlock` take a password and no
factor parameter, so there is no argument for a keyfile to become. The vault's
key-encryption key is derived from the password alone, the file this flag names
is never opened, and the factor cannot be applied to either creating a vault or
opening one. `PLAN.md` §8 — the auth/key model of phase 0 (§11) — is where the
missing half is specified: the password half shipped and the factor half did
not, so this is an unfinished foundation rather than a future feature.

Rather than proceed with one factor when you asked for two, the flag is refused
with exit **7** at both of the places a key is derived:

* **Creating a vault.** `dctl init --key-file` creates nothing — no envelope, no
  index.
* **Opening one.** Every unlock passes through a single refusal point, which
  runs *before* the password is read and before the remote is resolved. So
  `dctl copy ./src vault: --key-file kf.bin` exits 7 having transferred nothing
  and read nothing.

Both refusals name the flag, the capability, the crate that owes it, and what did
not happen. A run given a keyfile never exits **0**, so a success can never be a
run that silently dropped one.

The message is assembled in one place rather than at each call site, which is a
correctness property and not tidiness: the chokepoint every command passes
through used to compose it from the command name alone, and `dctl init
--key-file kf` therefore reported *"dctl init is not implemented in this
build"* — a false statement about a command that works.

(A command whose vault path is not implemented at all — the listings today —
fails with its own exit **7** before reaching the unlock. The reason differs;
the outcome, that nothing proceeds on one factor, does not.)

### `--no-ask-password`

Never prompt; fail instead. This is the flag that turns an unattended job's worst
outcome — hanging forever on an invisible prompt — into an immediate exit **22**
with a hint naming the non-interactive sources. Set it on every cron job and
container entrypoint; a run with no terminal fails the same way anyway, but not
before it has tried.

---

## Durability

| Flag | Value | Default | Environment |
|------|-------|---------|-------------|
| `--verify` | `checksum` \| `sample` \| `strict` | `checksum` | — |
| `--verify-samples` | `N` | **refused** | — |
| `--checksum` | — | off | — |
| `--size-only` | — | off | — |
| `--modify-window` | `SECONDS` | `1` | — |
| `--immutable` | — | off | — |

### `--verify MODE`

The cost/assurance dial of the verified-write contract (`PLAN.md` §6 step 5). It
sets how hard DCTL looks *after* a write, and it is the same dial `dctl verify`
and `dctl scrub` use when they re-ask the question later.

| Mode | What it does | What it proves | Extra egress |
|------|--------------|----------------|--------------|
| `checksum` (default) | Compares the provider's stored checksum against the one computed locally. | The provider still holds the ciphertext DCTL sent. | none |
| `sample` | Reads back and re-authenticates the object. **In this build it reads all of it**, so it costs what `strict` costs. | The stored object decrypts and authenticates. | **full** |
| `strict` | Reads and decrypts every object in full and confirms its whole-file BLAKE3. | The plaintext is intact, end to end. | **full — a second copy of the data** |

**Be clear about what `strict` costs.** A full read-back downloads everything it
just uploaded: a 50 GB video costs 50 GB up and 50 GB back down, and on a metered
bucket that is a doubled bill for the run, not a rounding error. Aimed at a
*tree* rather than a single object it is worse still — `--verify strict` over a
50 TB vault is a 50 TB download, so the integrity commands warn before starting
whenever a byte-reading mode meets a prefix. `sample` is the middle setting: it
pays for `--verify-samples` chunks per object instead of all of them, which
catches wholesale corruption without buying a second copy of the data — **which
is what `sample` is meant to be and is not yet**. In this build it reads the whole
object, so on a vault it costs the same egress as `strict` while proving less;
`--verify-samples` is refused rather than accepted into that gap.

**Why `checksum` is still a strong default.** It is not "no verification" — step 4
of the write pipeline is mandatory and runs whatever `--verify` says: the provider
returns the stored object's checksum, DCTL compares it with the value it computed
locally, and a **mismatch hard-aborts**. The staged object is deleted, a
`checksum-mismatch` error is logged, the source file is left untouched, and — the
part that matters — the index commit never happens. Since that commit is the only
thing that makes a file count as stored (`PLAN.md` §6 step 6), a failed
verification **commits nothing**: there is no half-stored file, no "copied"
report, and for `move`, no deleted source. Corrupt parts cannot land in the first
place either, since each multipart part's checksum is verified by the provider on
ingest and a bad part is rejected and retried.

What `checksum` does *not* prove is that the stored ciphertext still decrypts, or
that the plaintext hash matches end to end. That is the gap `sample` and `strict`
close, and it is why every integrity report names the mode that produced it —
"1,204 objects verified" is three different claims depending on this flag, and
readers assume the strongest one.

Verification strength is also a **per-remote** setting in `config.toml`
(`verify = "strict"`), because the trade-off belongs to the destination: a full
read-back is free against a local disk and expensive against a bucket. Both
spellings use the same lower-case words, and `--verify` on the command line
overrides the configured value.

### `--verify-samples N`

**Refused** (exit 7). There is no sampled read to set a depth on: the vault read
path reads and authenticates the whole object, so `--verify sample` costs a full
egress and this number would describe nothing. Use `--verify checksum` for the
metadata comparison, or `--verify strict`, which is what `sample` currently does.

It was previously accepted with a default of `8`, which published a sampling
depth this build has never applied.

### `--checksum`

Decide whether a file needs transferring by comparing content hashes instead of
size and modification time. Slower on the local side (the source must be read to
hash it) and correct in the cases the default misses — a file rewritten with
identical length and a preserved mtime. If either side cannot supply a hash, the
command **fails** rather than quietly falling back to a weaker comparison, since
a weaker answer dressed up as the one you asked for is exactly the misreporting
the durability contract exists to prevent.

Against a **plain object store** — a `local:`, `sftp:`, `b2:`, `s3:` or `r2:`
remote holding ordinary objects — DCTL reads each object back and hashes it. A
plain store holds the plaintext, so the hash of what it is holding is exactly the
digest the comparison needs. That is a **full pass over the destination**, which
on a metered provider is egress, and the run says so once on stderr rather than
letting you find it on an invoice. `--size-only`, or the default
size-and-modification-time comparison, reads nothing.

A vault destination answers for free, from the plaintext BLAKE3 its index
recorded at write time. The one object that still cannot answer is one nobody has
read: a row written by `dctl index rebuild` carries an empty digest, which is
*unknown* rather than a hash, and the command fails naming the file and the
remedy.

### `--size-only`

Compare by size alone, ignoring modification time. The fastest and weakest
comparison: it is the right choice against a destination whose timestamps are
untrustworthy, and the wrong one anywhere an in-place edit might preserve a file's
length. Conflicts with `--checksum` — the two ask for contradictory comparisons,
so passing both is a usage error rather than a silent precedence rule. With
neither flag, the default is size plus modification time within `--modify-window`.

**There is no longer an exception for vaults.** A sealed vault used to record the
moment each object was written rather than the source file's modification time,
so the default comparison could not mean anything against one, and DCTL
substituted a content comparison and warned about it. Both the cause and the
substitution are gone: a vault index row and a sealed object's own metadata carry
the *source's* time, so a vault answers the ordinary size-and-time question like
any other destination.

### `--modify-window SECONDS`

How far apart two modification times may be and still count as the same instant.
Defaults to `1`.

A tolerance is not optional, because the two sides of a comparison record time
differently and cannot be talked out of it. A local filesystem keeps
nanoseconds (ext4), 100 ns (NTFS) or two whole seconds (FAT); DCTL's own records
— the index row, a sealed object's metadata and every backend listing — keep
whole unix seconds; SFTP carries `mtime` as unsigned 32-bit seconds and cannot
return more; B2 stores milliseconds. With a zero tolerance every one of those
differences reads as "modified", and a nightly `sync` re-uploads the dataset for
a reason nobody can see.

Widen it for a destination that rounds: `--modify-window 2` is what a
FAT-formatted backup disk needs. **Narrowing it below `1` is refused**, with a
message saying why — DCTL stores whole seconds, so a smaller window cannot
express a real distinction and can only reject unchanged files. A flag that
parsed and then silently ignored its argument would be worse.

The same value is used by `copy`, `move`, `sync` and `check`, from one place, so
`check` cannot disagree with the `sync` that produced the tree it is checking.

### `--immutable`

Refuse to modify or delete anything that already exists; only additions are
allowed. It converts an overwrite into a hard failure (`dctl rcat` onto an
existing object, a `restore` that would replace files, a `touch` that would
re-stamp one) rather than a prompt, which is what makes it usable in a
write-once archival job. Combining it with a command flag that also forbids
creation — `dctl touch --no-create --immutable` — leaves the command unable to do
anything at all and is refused as a usage error.

**In the transfer family** (`copy`, `copyto`, `move`, `moveto`, `sync`) the
decision is made **at plan time**, against the same diff `--dry-run` prints. Any
entry whose action is `update` (an existing destination object being replaced) or
`delete` (a `sync` extra being removed) makes the whole run fail with exit **7**
(`fatal_error`) before a single byte moves, and the message names the paths that
caused it:

```console
$ dctl copy ./src ./archive --immutable
error: --immutable, but 2 existing destination object(s) would be replaced or removed: update a.txt, update photos/b.jpg
warning: --immutable allows only additions. Point the transfer at a destination
that does not already hold these objects, or drop --immutable. To see the full
list, re-run with --dry-run and without --immutable.
$ echo $?
7
```

Three consequences worth stating plainly:

* **A destination that does not exist yet is not an overwrite.** Additions still
  transfer normally — that is the whole point of "only additions are allowed".
* **`--dry-run --immutable` fails the same way a real run would.** That is why
  the check lives in the plan rather than in the write: a write-once archival job
  is verifiable *before* it is scheduled, instead of being discovered unsafe by
  the first file it ruins.
* **It governs the destination, not a `move`'s source.** Removing the source is
  what `move` means, so reading the flag that way would make `move --immutable` a
  contradiction rather than a safeguard; `copy` is the verb that leaves a source
  alone.

Long refusals are elided after ten paths (the count in the message is always
exact); re-run with `--dry-run` and without `--immutable` to see the full plan.

`--immutable` with `--no-traverse` is a **usage error** (exit **1**), for the
same reason `--no-create --immutable` is: `--no-traverse` never lists the
destination, so every source file is planned as a first-time copy and the
overwrite this flag exists to forbid is invisible to the planner. Honouring the
pair would silently downgrade a guarantee to a hope.

The exit code differs by command and each is a published contract: **7** from the
transfer family and from `restore`, **1** from `rcat` (a single named object,
checked before anything is listed).

---

## Transfer

| Flag | Value | Default | Environment |
|------|-------|---------|-------------|
| `--transfers` | `N` | `1` | — |
| `--checkers` | `N` | `1` | — |
| `--bwlimit` | `RATE` | unlimited | — |
| `--retries` | `N` | `3` | — |
| `--low-level-retries` | `N` | **refused** | — |
| `--timeout` | `SECONDS` | **refused** | — |
| `--contimeout` | `SECONDS` | **refused** | — |
| `--max-transfer` | `SIZE` | unlimited | — |

Every flag in this group used to parse and do nothing. Three now act
(`--bwlimit`, `--retries`, `--max-transfer`), two accept only the value that is
true of this build (`--transfers 1`, `--checkers 1`), and three are **refused**
with the reason — exit **7**, before anything is read or written, the way
[`--key-file`](#--key-file-path) is. There is no fourth outcome; see
[Flags that are refused](#flags-that-are-refused).

### `--transfers N`

Files transferred at once. **Only `1` is accepted.** This build's executor walks
the plan in plan order on a single task, so that the list `--dry-run` prints and
the list the machine performs are provably the same one; `--transfers 2` is
refused rather than accepted and ignored.

The default used to be `4`, which was the number a concurrent executor would have
wanted and which nothing read. Making it concurrent is a change to the durability
contract rather than to a number: the audit chain is appended in plan order, a
fatal error stops the run instead of failing every remaining file identically,
and both need an answer before a second file may be in flight.

### `--checkers N`

Metadata comparisons run at once. **Only `1` is accepted**, for a sharper reason
than `--transfers`: there is no checker stage to make parallel. Comparison happens
once, while the transfer plan is built, over two listings that are already in
hand. Parallel checking would be a different pipeline, not a larger number.

### `--bwlimit RATE`

Bandwidth ceiling, written with the usual size suffixes (`10M`, `1.5MiB`) or
`off` for unlimited. The rate is bytes per second, not bits — `10M` is roughly an
80 Mbit/s link fully used. A value that does not parse is a **usage error** (exit
1) before the command starts, never a silently unlimited run.

**Granularity: one file.** Each file is charged for the bytes it actually moved,
and the next **window** waits until that charge has been paid off at the
configured rate. A window is a few megabytes, so this shapes the wire rather than
merely spacing out files: `--bwlimit 1M` holds one 100 MiB object to about 100 s
*while it is being transferred*, instead of putting it on the link as fast as the
link will take it and waiting afterwards.

It did exactly that until the streaming engine landed, and the gap was the whole
width of the flag. The debt was charged once per **finished file**, because the
engine handed a whole object to the storage backend in one call and got a byte
count back at the end — there was no per-buffer seam to charge. So a run of one
object was not paced at all, and neither was the last file of any run: 8 MiB
moved as a single file at `--bwlimit 1M` took **47 ms**, while the same 8 MiB as
eight files took **7051 ms**. Bytes now move in bounded windows in both
directions, the limiter is installed as the storage layer's meter, and the same
8 MiB as one object takes **8497 ms** against an 8000 ms target.

Both uses of the flag are served:

* **Capping a bill or a metered link.** The average rate over the run is the
  limit, so the bytes per month are the limit.
* **Keeping a video call usable while a backup runs.** One enormous file is now
  paced for its duration rather than saturating the uplink until it finishes.

Two details worth knowing. The first window of a run is free — the charge is made
*after* bytes move, so that it is a measurement rather than an intention — which
costs a few megabytes of burst at the very start and nothing after. And a sealed
destination is charged for **ciphertext**, which is what actually crosses the
link and is a percent or so larger than the plaintext; that is why the measured
8497 ms sits just above the 8000 ms the plaintext alone would predict.

### `--retries N`

How many times a *whole failed file* is retried — the original attempt plus `N`
repeats, so `--retries 0` still transfers each file once. Everything inside is
re-attempted: a repeat re-reads the source, re-encrypts and re-verifies rather
than replaying a buffer.

Only failures a repeat can fix are repeated: a temporary error (a reset
connection, a 503, a dropped ssh session) and a checksum mismatch, which means
the destination stored something other than what was sent and where nothing was
committed. A missing file, a locked vault, an AEAD authentication failure and a
`--max-transfer` stop are **not** repeated — the first three will answer the same
way next time, and the fourth is the run being stopped on purpose.

There is no sleep between attempts, matching rclone, whose `--retries-sleep`
defaults to zero. Retries are counted and shown in the end-of-run summary, so a
run that succeeded only after fighting for it does not look identical to one that
did not.

### `--low-level-retries N`

**Refused** (exit 7). Request-level retries now exist on **every** backend, but
on a schedule this flag cannot reach: attempts, backoff, jitter and the total
waiting budget are chosen per provider and are not a single number. Accepting an
`N` that set one of the four and silently ignored the other three would be a dial
that half works, which is worse than one that says no.

What the schedule is, since the flag will not let you change it: six attempts for
`sftp`, `b2`, `s3` and `r2`, starting at half a second and doubling to eight,
honouring a server's `Retry-After` up to a minute, and never waiting more than
two minutes in total for one operation; three attempts over one second for
`local:`, where the errors worth repeating clear immediately or not at all. `5xx`,
`408` and `429` are temporary; `401` and `403` never are. A failure that is
retried says how many attempts were made; one that is not says nothing about
retrying, which is the fix for a hint that used to claim exhausted retries over a
single attempt.

Whole-file retries are separate and are what `--retries` controls.

### `--timeout SECONDS`

**Refused** (exit 7). No backend in this build applies an inactivity timeout: the
storage layer constructs its HTTP clients and its ssh session without one, so
there is nothing for this to set. It cannot honestly be approximated by a
deadline on the whole operation either — that would abort a large transfer that
is progressing perfectly, which is the opposite of what an idle timeout is for.

### `--contimeout SECONDS`

**Refused** (exit 7). No backend sets a connection-establishment timeout: the
HTTP clients take the default and the sftp backend takes `ssh`'s, neither of
which this flag is wired to.

### `--max-transfer SIZE`

Stop the run once this much has been transferred (`100G`, `500GB`, `off`). The
budget flag: it is how you cap what a single run can cost on a metered provider,
or stay under a daily cap. A run that stops for this reason is not a failure but
it is not a completed sync either — it exits **8** (`transfer_limit_exceeded`) so a
script can tell the difference.

**The limit is never exceeded, not by a byte.** A file is not *started* when
moving it would take the run past the ceiling. This is rclone's `cautious` cutoff
mode rather than its default `hard` one, and the choice follows from the
durability contract: this engine writes an object in one call, and a partial
object at the destination is exactly what verified writes exist to prevent.

The visible consequence, because somebody will meet it: `--max-transfer 1M`
against a single 10 MiB file transfers **nothing** and exits 8. rclone would have
moved 1 MiB of it and left that behind.

What counts against the budget is bytes *measured leaving*, including every
attempt of a retried file — because every attempt used the link and is on the
invoice. Everything already transferred is committed and verified, so re-running
the same command continues from where it stopped.

---

## Filtering

| Flag | Short | Value | Default | Repeatable |
|------|-------|-------|---------|------------|
| `--include` | | `PATTERN` | none | yes |
| `--exclude` | | `PATTERN` | none | yes |
| `--include-from` | | `PATH` | none | yes |
| `--exclude-from` | | `PATH` | none | yes |
| `--filter` | `-f` | `RULE` | none | yes |
| `--filter-from` | | `PATH` | none | yes |
| `--files-from` | | `PATH` | none | yes |
| `--min-size` | | `SIZE` | none | no |
| `--max-size` | | `SIZE` | none | no |
| `--min-age` | | `AGE` | none | no |
| `--max-age` | | `AGE` | none | no |
| `--max-depth` | | `N` | `-1` (unlimited) | no |

**One engine answers for every command that takes these flags.** The transfer
family (`copy`, `copyto`, `move`, `moveto`, `sync`), the recovery family
(`backup`, `restore`) and every listing verb evaluate them through
`crate::filter`, so a rule means exactly the same thing wherever it is typed.
Three implementations of one flag would eventually disagree, and the way they
disagree is that a listing shows a file the transfer then omits — or, in a
`sync`, that a rule reaching only one side turns an excluded destination file
into an "extra" and deletes it.

**A filter is applied to both sides of a diff.** That is the property that makes
`sync --exclude 'archive/**'` protect `archive/` at the destination rather than
empty it: the rule hides the tree on both sides, so it is neither transferred nor
deleted.

**What is refused is a filter that will not compile** — a malformed pattern, an
unreadable or unparseable rule file, a size without a unit, an age that does not
parse, a `--max-depth` that is not a depth, or a pair of bounds that cross. Those
are usage errors (exit **1**) raised before anything is listed, because a run
that proceeded with a rule the operator believes is in force is the data-loss
case this whole group exists to prevent.

`purge` is the exception that neither honours nor refuses: it removes a whole
tree by definition, so it **warns** that filters are being ignored and points at
`delete` instead. `replicate` refuses every one of them by name.

### Order: the rules are tried in rclone's order, and the first match wins

This is the part most worth reading before writing a filter, because the obvious
guess is wrong in both tools.

The rules are assembled **by flag kind**, not by position on the command line —
matching rclone's `parseRules` (`fs/filter/rules.go:212`):

1. every `--include`, in the order given;
2. every `--include-from` file, in file order;
3. every `--exclude`;
4. every `--exclude-from` file;
5. every `--filter` rule and every `--filter-from` file, interleaved in flag order;
6. an implicit `- **` at the end **if any inclusion was used**, from any of those flags.

They are then evaluated top to bottom and **the first rule that matches decides**.
So:

```
--include '**' --exclude 'private/**'      keeps private/a.jpg
```

because the inclusion is tried first. That surprises people, it is rclone's
behaviour, and rclone's own code prints a warning recommending `--filter` when it
sees both flags used together. Use `--filter` when the order matters:

```
--filter '- private/**' --filter '+ **'    drops private/a.jpg
```

A `--filter` argument is one line of a rule file: `+ pattern`, `- pattern`, or a
lone `!` that discards every rule accumulated so far. A rule file keeps its
**internal order exactly**, and unlike `--include` it does not append an implicit
`- **`: a rule file is an ordered program whose author writes their own final
rule.

**The asymmetry `--include` introduces.** With no `--include` or
`--include-from` anywhere, an unmatched file is *kept*. The moment one appears,
the implicit `- **` is appended and an unmatched file is *dropped* — so
`--include '*.jpg' --exclude '*.png'` means "the JPEGs only", and the `.txt`
files nobody mentioned are gone.

Three details of that rule are worth spelling out, because each one surprises
somebody and all three are rclone's:

* **The flag arms it, not the rules.** An `--include-from` file holding only
  comments still arms it; a `+` inside `--filter` or `--filter-from` does not.
  `--filter '+ *.jpg'` therefore keeps everything else, exactly as a rule file
  containing that one line does.
* **`!` clears the rules and leaves the implicit exclusion standing.** So
  `--include '*.jpg' --filter '!'` selects **nothing**: the inclusion is gone and
  the `- **` it armed is not. If you want a clean slate, do not pass an
  inclusion flag in the first place.
* **It is appended last**, after every rule from every flag, so any rule can beat
  it.

### Anchoring and the glob dialect

**Anchoring** follows rclone's rules, because rclone's patterns are the ones
users bring:

* A pattern beginning with `/` is anchored at the listing root: `/tmp/*` matches
  `tmp/a` but never `photos/tmp/a`.
* A pattern with no `/` at all matches the **file name** at any depth: `*.jpg`
  means what everyone assumes it means.
* Anything else matches the root-relative path and every component-aligned suffix
  of it, so `tmp/*` finds `photos/tmp/a` as well as `tmp/a`.
* A trailing `/` makes a rule match directories only. `--exclude 'cache/'` skips
  the tree; to name the contents by pattern, write `cache/**`.

**Glob dialect:** `*` within one path component, `**` across them, `?` for a
single character, `[a-z]` for a class and `[!a-z]` or `[^a-z]` for a negated one,
`{a,b}` for an alternation (which nests), `\` to escape any of them. A malformed
pattern is a usage error (exit **1**) naming the flag it came from and the
position.

Two differences from rclone worth knowing if you are bringing patterns across:

* rclone hands the inside of `[…]` to Go's regexp engine, so it accepts
  `[[:alnum:]]`, `[\d]`, `[\s]` and `[\w]`. DCTL **refuses** those by name and
  tells you the spelling to use (`[0-9a-zA-Z]`) rather than reading them as a set
  of literal characters, which is what silently selecting the wrong files would
  look like.
* In rclone a class negates only with `^`, so `[!a-z]` there matches `!` *or* a
  letter. Here `!` negates, as it does in a shell and in rsync.

### Sizes and ages

**Size syntax.** A unit is **required** for `--min-size` and `--max-size`: `100B`
is a hundred bytes and `100K` is a hundred kibibytes, and a bare `100` is a usage
error naming both readings. That refusal exists because rclone reads a bare
number as *kibibytes* (`fs/sizesuffix.go:141`) while every size DCTL prints is in
bytes — a factor of 1024 on the flag that decides which files move, and on a
`sync` the files in between are not merely absent from the copy but candidates
for deletion at the destination. `off` needs no unit and removes the limit.

An IEC spelling is binary (`10G` = `10Gi` = `10GiB` = 2³⁰ × 10) and an explicit
SI spelling is decimal (`10GB` = 10⁹ × 10), because someone writing
`--max-size 5TB` copied it off a provider's invoice and means the invoice's
terabyte. The same syntax, without the unit requirement, applies to `--bwlimit`
and `--max-transfer`.

**Age syntax.** `ms`, `s`, `m`, `h`, `d`, `w`, `M` (30 days), `y` (365 days), or
a bare number of seconds — rclone's table, including that `M` is a month and `m`
is a minute. `off` removes the limit.

Both pairs are **inclusive** at the boundary and both are refused if they cross
(`--min-size 10G --max-size 1G` can never match, so it is a usage error rather
than a run that reports success having moved nothing).

### `--include PATTERN` / `--exclude PATTERN`

Include only paths matching this glob, or drop paths matching it; repeat either
flag to accept several patterns. See the ordering section above before mixing
them — the two are not tried in the order you wrote them.

### `--include-from PATH` / `--exclude-from PATH`

The same, read from a file, one **bare pattern** per line — the flag supplies the
`+`/`-`. Blank lines and lines starting `#` or `;` are skipped. Use these when
the list is longer than a command line or wants version-controlling.

### `--filter RULE` / `--filter-from PATH`

`+ pattern`, `- pattern` or `!`, one rule per argument or per line. The only form
whose order is the order you wrote, which is why it is the one to reach for when
an exclusion has to beat an inclusion. A file that cannot be read or parsed is a
usage error rather than a run with the rules dropped, because a transfer whose
filter file was silently ignored *looks* complete.

### `--files-from PATH`

Transfer only the paths named in this file, one per line, skipping the directory
walk entirely — the right tool when an upstream process already knows exactly
which files changed. Repeatable; several lists are merged into one set.

It is more than a convenience in `backup` and `restore`, where it is the way to
give a restore drill an exact path set. Blank lines and `#` comments are skipped,
and every surviving line is canonicalised the same way an index key is
(`/`-separated, NFC), so a list written on Windows with backslashes selects the
same objects as one written on Linux. A line containing `..` is a usage error
(exit **1**) naming the file and line number, rather than a path quietly resolved
outside the transfer root.

Unlike rclone, which refuses `--files-from` combined with any other filter, DCTL
applies the **intersection**: the list narrows what a walk would have found and
the other rules narrow it further. That can only ever select a subset of the
list, which is recoverable by re-running.

A listing verb applies the list as an exact filter rather than as a way to skip
a walk: an index range scan and a provider listing are already flat, so there is
no directory recursion to be skipped. The **set of objects shown is the same set
a transfer would take**, which is the property that matters.

### `--min-size SIZE` / `--max-size SIZE`

Skip files smaller, or larger, than this. Applied to objects only, never to
directories: a directory's size is an aggregate, and filtering directories on it
would hide every small file inside a large one. A file whose size was never
measured — a row written by `dctl index rebuild`, which is a list-only pass — is
**not** filtered, because both ways of guessing at the size are wrong in a
direction the operator cannot see.

### `--min-age AGE` / `--max-age AGE`

`--min-age 7d` keeps files at least seven days old; `--max-age 7d` keeps files
modified within the last seven days. The window is fixed once when the run starts,
so a transfer that takes an hour selects the same set at the end as at the
beginning — and a `sync` sees the same window on both sides.

A file whose modification time nobody recorded is **kept**, not dropped. This is
a deliberate difference from rclone, which treats an absent time as older than
every floor: a vault index rebuilt from object headers records no times at all,
so rclone's rule would hide the entire vault from `--max-age`, including objects
that plainly qualify. Directories carry no time either — a directory's timestamp
moves when a child is added, which says nothing about the age of what is inside.

### `--max-depth N`

Limit recursion depth; `-1` (the default) means unlimited, `1` means the
immediate children of the target. Depth is counted from whatever the command was
pointed at, not from the vault root. The directory-oriented commands (`lsd`,
`tree`) apply the limit to the directories they synthesise rather than to the
objects they derive them from, so `dctl lsd --max-depth 1` reports top-level
directories properly instead of reporting them all as empty.

---

## Traversal

| Flag | Short | Value | Default | Repeatable |
|------|-------|-------|---------|------------|
| `--links` | | `skip` \| `follow` \| `in-tree` | `skip` | no |

Its own group, and deliberately not part of *Filtering*. A filter selects among
the things a walk found; this decides what the walk finds at all. `dctl
replicate` refuses every filtering flag — a filtered replica of a vault's object
store is a store with dangling references — and **honours** this one, because a
store on `local:` or `sftp:` is walked by the same code as any other tree.

### `--links skip|follow|in-tree`

What a walk does with the symbolic links it finds **inside** a tree. The root a
command is pointed at is a different question and is always resolved: `dctl ls
/srv/data` and `dctl backup /var/log/current vault:` name a path a person chose,
and refusing to look through it produced an empty listing that `sync --force`
read as permission to delete a destination.

| Value | What happens |
|-------|--------------|
| `skip` (default) | Nothing behind a link is read. Every link is counted, and `-v` names each one with the reason. |
| `follow` | A link is followed wherever it points, including out of the tree — which is the canonical layout, `/srv/data -> /mnt/bigdisk/data`. |
| `in-tree` | A link is followed only while its target stays under the walk root. One that would leave is reported and not followed. |

**The default skips, and says so.** Following by default would change what every
existing backup contains on its next run, and `sync` deletes on the difference —
so a machine whose links happened not to resolve one night would lose those files
at the destination. It would also let one link named `etc -> /etc` pull a
machine's whole configuration into an archive the operator believes holds
photographs, past every `--exclude` they wrote. rclone settled the same way: its
local backend ignores symlinks unless `-L`/`--copy-links` is given, and logs one
line per link it passes over.

What the default may not be is quiet, and that is the change. Every run prints
`skipped N symbolic link(s)` on stderr, with the flag that stores them; `-v`
names each link and what happened to it. A tree with no links prints nothing.

**It cannot loop.** When links are followed, the walk remembers the identity of
every directory on the path from the root down to the one it is reading —
`(st_dev, st_ino)` on Unix, the canonical path over SFTP, which carries no inode.
A link whose target is already on that path is reported as a cycle and not
followed. It is the *ancestors* and not "everywhere the walk has been", because
two links to one directory are two legitimate names for it: a global set would
walk the first and silently drop the second, which is the same class of loss.

**A broken link is counted and named, and it fails the run.** Under a policy that
follows, a link with nothing behind it is a path that was asked for and not
stored, so it raises the error count and the exit code (**6**, `partial_failure`)
while the rest of the tree still transfers. Under `skip` nothing looks behind a
link, so nothing can call one broken.

**On restore, a followed link comes back as a copy.** A vault is keyed by logical
path and has no record type for "this path is a link to that one", so
`srv/data -> /mnt/bigdisk/data` backed up with `--links follow` restores as a
real directory holding real files. Two links to one 400 GB directory restore as
800 GB. A link skipped by the default restores as nothing at all, because nothing
about it was ever stored. `tests/restore_drill/links.rs` proves both halves.

`dctl backup --follow-symlinks` is the older spelling of `--links follow` and
still works. Giving both is accepted when they agree and refused (exit **1**)
when they do not, rather than one silently winning.

---

## Output

| Flag | Short | Value | Default | Environment |
|------|-------|-------|---------|-------------|
| `--format` | | `text` \| `json` \| `json-lines` | `text` | — |
| `--json` | | — | off | — |
| `--units` | | `binary` \| `decimal` | `binary` | — |
| `--color` | | `auto` \| `always` \| `never` | `auto` | — |
| `--ascii` | | — | off | — |
| `--progress` | `-P` | — | off | — |
| `--stats` | | `SECONDS` | `60` | — |
| `--stats-one-line` | | — | off | — |
| `--quiet` | `-q` | — | off | — |

**stdout carries data; stderr carries everything else.** Progress, logs, warnings,
prompts and the end-of-run summary all go to stderr, which is what lets
`dctl cat vault:film.mkv | ffplay -` keep its progress bars while stdout stays
byte-exact.

### `--format FORMAT`

How structured results are serialised. `text` is aligned columns for a person;
`json` is one document for the whole result; `json-lines` is one JSON object per
line, which streams without buffering and is therefore the only sane choice on a
ten-million-object listing. Nothing about the work changes between them — only
the rendering — and machine formats suppress the human extras (summary,
separators, notes) that a parser would choke on.

### `--json`

Shorthand for `--format json`. Conflicts with `--format`: passing both is a usage
error rather than a silent precedence rule, since the two would otherwise
disagree about the same setting.

### `--units UNITS`

The byte-size convention used in every rendered size and rate. `binary` gives
KiB/MiB/GiB (powers of 1024), which is what the operating system reports;
`decimal` gives kB/MB/GB (powers of 1000), which is what providers bill in. Switch
to `decimal` when you are reconciling a DCTL report against an invoice or a quota
page. This affects output only — it never changes how a `--max-size` argument is
parsed.

### `--color WHEN`

Whether to emit ANSI styling. `auto` (the default) colours a terminal and stays
plain through a pipe, honouring `NO_COLOR` (disables), `CLICOLOR_FORCE`
(forces), and `TERM=dumb` (disables) along the way. `always` is for a CI system
that renders colour but does not look like a terminal to `isatty`. JSON output is
never coloured whatever this says, since escape sequences inside string values
break every downstream parser.

It reaches both streams and every command that renders anything: `ls`, `lsl`,
`lsd`, `tree`, `size`, `check`, `about`, the warnings and errors on stderr, and
the end-of-run summary. Sizes and counts are one colour, paths another,
directories bold, timestamps and structural chrome dimmed. Styling never changes
the layout — columns are measured before they are painted, so `--color always`
and `--color never` produce the same visible text.

### `--ascii`

Draw bars, spinners, tree branches and status marks from ASCII instead of Unicode
box-drawing and braille glyphs. DCTL already picks ASCII automatically on a
legacy Windows console and in a non-UTF-8 locale; this flag forces it for the
cases the detection cannot see, such as a log viewer or a terminal emulator that
renders the Unicode set as mojibake.

### `-P`, `--progress`

**Watch this run.** DCTL shows progress by default in every environment it can —
bars when stderr is a terminal, periodic status records when it is redirected — so
this flag does not switch progress on. It changes the two things a person standing
over a run wants changed:

* **The cadence.** A redirected run reports every `--stats` seconds, a minute by
  default: right for an unattended nightly job, useless to somebody watching.
  `-P` selects **one second**.
* **Machine output stops silencing it.** `--json` turns the display off by
  default, because a program is reading stdout. That is a courtesy rather than a
  constraint — progress is written to stderr and cannot reach the JSON — so `-P`
  brings it back, and stdout still carries exactly one JSON document.

`--stats 0` beats it: that is a direct instruction about this exact output.
`--quiet` beats everything.

It does **not** conjure bars through a pipe, and an earlier release's promise that
it would was worse than useless — bars draw through a terminal handle, so forcing
them off a terminal rendered nothing *and* stopped the periodic record, making
`-P` the only way to make a redirected run quieter. Off a terminal, "progress"
means the periodic record, and this flag makes it frequent.

One limit, stated plainly: progress is **per file**, not per byte. A single very
large file's bar moves once, at the end, because the storage layer takes a whole
buffer and returns a count. A tree of files behaves as expected.

### `--stats SECONDS`

How often the periodic status record is emitted when bars are unavailable — that
is, whenever output is redirected. `0` disables it entirely. Sixty seconds is a
readable cadence for a long transfer in a log file; shorten it if you are watching
a CI job and want more evidence of life, or pass `-P`, which shortens it to one
second for you.

The record is the **same report** the run prints at the end, taken mid-run: the
same rows, in the same order, in the same units. A watcher reading a log at 3 a.m.
should not have to learn a second format to find out how many errors there have
been.

### `--stats-one-line`

Condense each periodic status record onto a single line — percentage, bytes,
rate, ETA, files and errors — which is what makes the output greppable and keeps a
long-running job from dominating a log.

This used to be indistinguishable from its absence: the periodic record only ever
had the condensed shape, so asking for one line was asking for what you already
had. The block is now the default and this selects the condensed form, which is
also rclone's arrangement.

### `-q`, `--quiet`

Suppress all non-error output: no progress, no summary, no commentary. It also
pins the log level to `error`, so a quiet run stays quiet on both sinks, and it
beats `--progress` — a user who asked for silence gets it even if they also asked
for bars. Errors are never suppressed; a silent failure is the one outcome
`PLAN.md` §7 forbids outright.

---

## Logging & debugging

| Flag | Short | Value | Default | Environment |
|------|-------|-------|---------|-------------|
| `--verbose` | `-v` | repeatable | off (`warn`) | — |
| `--log-level` | | `error` \| `warn` \| `info` \| `debug` \| `trace` | `warn` | `DCTL_LOG_LEVEL` |
| `--log-format` | | `human` \| `json` \| `plain` | `human` | `DCTL_LOG_FORMAT` |
| `--log-file` | | `PATH` | none | — |
| `--dump` | | `headers` \| `bodies` \| `requests` \| `retries` \| `filters` \| `config` | none | — |
| `--log-source` | | — | off | — |

The effective level is resolved once: an explicit `--log-level` wins, then
`--quiet` (which forces `error`), then the `-v` count, otherwise `warn`.
`DCTL_LOG` overrides the whole filter — see
[The `DCTL_LOG` filter override](#the-dctl_log-filter-override).

**Redaction is not optional.** Keys and tokens are never logged at any level or
under any `--dump` target; secrets appear only as BLAKE3 fingerprints.

### `-v`, `--verbose`

Increase verbosity by repetition: `-v` is `info` (one record per file),
`-vv` is `debug` (per-stage detail and every retry decision), `-vvv` is `trace`
(per-chunk activity). `-vvv` is genuinely extreme — a 50 GB transfer at 4 MiB
chunks emits roughly 12,800 records — so prefer `DCTL_LOG` to raise one module to
trace rather than the whole program. `-v` is also what turns on the explanatory
commentary the integrity commands print about what they actually checked.

### `--log-level LEVEL`

Set the level explicitly, overriding any `-v` count. The named form is the one to
use in a script or a systemd unit, where `-vv` is a puzzle and `--log-level debug`
is not. `DCTL_LOG_LEVEL` sets the same thing for a whole shell or container.

### `--log-format FORMAT`

How records are rendered. `human` is aligned and colourised for a person at a
terminal; `json` is newline-delimited objects with structured fields preserved,
for ingestion by a log pipeline; `plain` is the human layout with no ANSI, for a
CI transcript where escape sequences are noise. A log *file* never receives ANSI
regardless — `--log-format human --log-file x.log` writes `plain` to the file and
keeps the colour on the console.

### `--log-file PATH`

Append records to this file **in addition to** stderr, creating parent
directories as needed. Existing content is never truncated, because the point of
the flag is an audit trail. Failing to open the file is fatal rather than a
warning: continuing without the trail you explicitly asked for would be a silent
downgrade of what you were promised.

### `--dump TARGET`

**Refused** (exit 7). The protocol tracing layer these targets select from is not
installed — nothing in the storage layer or the logging setup captures headers,
bodies, requests or retry decisions — so every one of them would produce silence.
Raise `-vvv` for the tracing this build does emit.

The targets remain in `--help` and are validated, so the vocabulary does not
change when the layer lands: `headers` (HTTP headers, `Authorization` always
redacted), `bodies` (request and response bodies, never plaintext file content),
`requests` (one line per request: method, URL, status, duration), `retries`
(every retry decision with its classification), `filters` (which rule included or
excluded each path), `config` (the resolved configuration with secrets redacted).

### `--log-source`

Include the source file and line in every log record. This is for reporting a bug
against DCTL itself — it turns "something in the transfer path warned" into a
line number — and is noise for everything else.

---

## Safety

| Flag | Short | Default |
|------|-------|---------|
| `--dry-run` | `-n` | off |
| `--interactive` | `-i` | off |
| `--force` | | off |

### `-n`, `--dry-run`

Report what would happen and change nothing. Every destructive decision declines
under it and prints the action it skipped, so the output is a plan rather than a
result. Note what it is *not*: a dry run of `dctl verify` proves nothing about
your data, because the check it would have performed never ran.

### `-i`, `--interactive`

Prompt before each destructive action; you must type `yes` exactly. Confirmation
is opt-in rather than the default, so an unattended job does not stall on a
question nobody can see — which also means that without this flag, destructive
commands proceed on their own authority once their own guards are satisfied. With
`--interactive` and no terminal to ask on, the command fails (exit **1**) rather
than assuming an answer. Conflicts with `--force`.

### `--force`

Approve destructive actions without asking. Beyond skipping `--interactive`
prompts, it is *required* by the operations that refuse on their own regardless of
this group: `dctl init` over an existing index, `dctl config create` over an
existing remote, and a `sync` whose source is empty and which would therefore
delete everything at the destination. `--dry-run` still wins — `--force --dry-run`
changes nothing.

`--force` is **not** an override for the addressing rule below. It approves work
you are allowed to do; it does not grant permission DCTL does not have.

### What no flag in this document does

**No flag on this page changes what a command encrypts.** Not `--force`, not
`--verify`, not `--remote`, not any combination of them. Encryption is decided by
the remote name typed — see
[the addressing invariants](commands/dctl.md#encryption-is-decided-by-the-name-you-type)
— and the matrix in `crates/dctl-cli/tests/invariant_i4/` crosses every flag here
with every write verb and asserts it on the bytes left on disk.

That extends to `--dry-run`, and deliberately so: a rehearsal reaches the *same*
addressing decision as the real run, so a plan you approved is a plan the run
will actually perform. A dry run that printed "would copy" for a destination the
real run refuses would be worse than no dry run, because it is trusted.

The one behaviour that is not decided by the name typed is a **refusal**. For a
bare path that no configured remote describes, DCTL inspects the destination for
a vault envelope and fails closed if it finds one — it can stop a command, and
that is all it can ever do. The reasoning, and the honest limits of it, are on
the [root command page](commands/dctl.md#the-residual-a-location-no-configured-remote-describes).

---

## Environment variables

Every `DCTL_*` name is derived from one prefix, so the whole set renames together
if the product ever does.

### Flag equivalents

| Variable | Equivalent to | Notes |
|----------|---------------|-------|
| `DCTL_CONFIG` | `--config` | Empty value is treated as unset. |
| `DCTL_REMOTE` | `--remote` | Default target when a command is given no path. |
| `DCTL_INDEX` | `--index` | |
| `DCTL_PASSWORD` | `--password` | Never echoed in help output. |
| `DCTL_PASSWORD_COMMAND` | `--password-command` | |
| `DCTL_LOG_LEVEL` | `--log-level` | |
| `DCTL_LOG_FORMAT` | `--log-format` | |

The command-line flag always wins over the variable.

### Provider credentials

Credentials live in the environment (and, later, the OS keychain), never in
`config.toml` — rclone's reversibly-obscured secrets are the specific mistake
`PLAN.md` §14 is avoiding. A missing, empty, or non-UTF-8 credential variable is a
**fatal** error (exit **7**), not a temporary one: no amount of retrying invents a
credential, and reporting it as transient would have a scheduled job back off for
an hour instead of failing loudly. An exported-but-empty variable counts as
missing, because sending an empty key to a provider produces an opaque 403
instead.

| Variable | Provider | Config alternative |
|----------|----------|--------------------|
| `DCTL_B2_KEY_ID` | B2 | — (secret) |
| `DCTL_B2_APP_KEY` | B2 | — (secret) |
| `DCTL_S3_ENDPOINT` | S3 | `endpoint` in the remote's section |
| `DCTL_S3_REGION` | S3 | `region` in the remote's section |
| `DCTL_S3_ACCESS_KEY` | S3 | — (secret) |
| `DCTL_S3_SECRET_KEY` | S3 | — (secret) |
| `DCTL_R2_ACCOUNT_ID` | R2 | `account` in the remote's section |
| `DCTL_R2_ACCESS_KEY` | R2 | — (secret) |
| `DCTL_R2_SECRET_KEY` | R2 | — (secret) |

The non-secret settings are read from the config when a named remote pins them
and from the environment otherwise, which is what lets a bare `s3:bucket` work
with no configuration at all.

### The `DCTL_LOG` filter override

`DCTL_LOG` replaces the computed log filter entirely with a
`tracing-subscriber` `EnvFilter` directive. It is the targeted-debugging escape
hatch: it lets you turn one module up to `trace` without drowning in everything
else, which `-vvv` cannot do.

```sh
DCTL_LOG=dctl_store::b2=trace        dctl copy ./photos vault:photos
DCTL_LOG=warn,dctl_cli::commands=debug  dctl sync ./src vault:src
```

Because it replaces the filter rather than adjusting it, it overrides
`--log-level`, `-v` and the level `--quiet` would have pinned. It does **not**
override `--quiet` on the *output* side: the progress display, the summary and
the stderr commentary stay suppressed, since those are a different sink from the
log. A directive that fails to parse is ignored and the computed filter is used
instead, so a typo degrades to normal logging rather than to no logging.

There is no flag equivalent; this variable exists only in the environment.

### Environment DCTL honours but does not own

| Variable | Effect |
|----------|--------|
| `NO_COLOR` | Set to anything: disables colour under `--color auto`. |
| `CLICOLOR_FORCE` | Set and non-zero: forces colour under `--color auto`. |
| `TERM=dumb` | Disables colour under `--color auto`. |
| `WT_SESSION` | Marks a modern Windows Terminal, which gets the Unicode glyph set. |
| `LC_ALL`, `LC_CTYPE`, `LANG` | Consulted in that order for a UTF-8 signal; without one, glyphs fall back to ASCII. |
| `VISUAL`, `EDITOR` | The editor `dctl config edit` launches; `VISUAL` wins. |

---

## Flags that are refused

These are accepted by the parser, shown by `--help`, and then **fail the run**
with exit **7** before anything is read, written or unlocked. The message names
the flag, what you were doing, why this build cannot do it, and what it does
instead. Nothing here is silently ignored.

* `--key-file` — the key-encryption key is derived from the password alone; there
  is no parameter through which a second factor could be mixed in. See
  [`--key-file PATH`](#--key-file-path).
* `--verify-samples` — there is no sampled read to set a depth on. `--verify
  sample` reads and authenticates the *whole* object on the vault path, so it
  costs a full egress and a depth would describe nothing.
* `--low-level-retries` — request-level retries exist for B2 only.
* `--timeout`, `--contimeout` — no backend applies an inactivity or connection
  timeout.
* `--dump` — the protocol tracing layer these select from is not installed, so
  every target would produce silence. Raise `-vvv` for the tracing this build
  does emit.

Two more are refused only for the values this build cannot deliver:

* `--transfers N` and `--checkers N` accept `1`, which is a true statement about
  a sequential executor, and refuse anything larger.

The filtering flags are deliberately **not** on this list, because none of them is
ever silently ignored: the transfer and recovery families evaluate all of them
through one engine, and a rule that will not compile is a usage error rather than
a run with the rule dropped. See [Filtering](#filtering).

The one place a filter is neither honoured nor refused is `purge`, which removes
a whole tree by definition and warns that it is ignoring them.

---

## See also

* [docs/commands/](commands/) — per-command pages, each listing the global flags
  that change that command's behaviour.
* [docs/EXIT_CODES.md](EXIT_CODES.md) — the exit-code contract.
* `PLAN.md` §6 (verified-write durability), §7 (logging and audit), §14
  (configuration and secrets).
