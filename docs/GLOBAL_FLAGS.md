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

> **Status.** Some flags below parse and validate but are not yet consumed by any
> command in this build. They are marked *not yet honoured* on the flag, and
> listed together under [Flags that parse but do not yet act](#flags-that-parse-but-do-not-yet-act).
> Nothing on that list silently degrades a guarantee: where honouring a flag
> matters for correctness (`--key-file`), the command **fails** rather than
> proceeding without it. `--filter-from` and `--files-from` used to be on that
> list for the listing verbs; they are now honoured by every command, through the
> same engine, so a listing and the transfer that follows it select the same
> files.

---

## Configuration

| Flag | Value | Default | Environment |
|------|-------|---------|-------------|
| `--config` | `PATH` | platform config dir + `config.toml` | `DCTL_CONFIG` |
| `--remote` | `SPEC` | none | `DCTL_REMOTE` |
| `--index` | `PATH` | platform data dir + `vault.redb` | `DCTL_INDEX` |

### `--config PATH`

The configuration file this invocation uses. The default is `config.toml` inside
the platform config directory — `~/.config/dctl` on Linux,
`~/Library/Application Support/dctl` on macOS, the roaming `%APPDATA%\dctl\config`
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
remote names are at least two characters so that `C:\data` can never parse as a
remote named `C`.

### `--index PATH`

The local encrypted index database (`redb`), which is the record of what is
actually stored: the durability contract's commit step (`PLAN.md` §6 step 6)
writes here, and nothing counts as stored until it does. The default is
`vault.redb` inside the platform data directory — `~/.local/share/dctl` on Linux,
`~/Library/Application Support/dctl` on macOS, `%APPDATA%\dctl\data` on Windows.
Point it somewhere else to keep several vaults side by side on one machine, or to
put the index on a disk you actually back up.

---

## Authentication

| Flag | Value | Default | Environment |
|------|-------|---------|-------------|
| `--password` | `PASSWORD` | none | `DCTL_PASSWORD` |
| `--password-command` | `COMMAND` | none | `DCTL_PASSWORD_COMMAND` |
| `--password-file` | `PATH` | none | — |
| `--key-file` | `PATH` | none | — |
| `--no-ask-password` | — | off | — |

Sources are tried in a fixed order, most explicit first, so a scripted run is
never surprised by a prompt it did not ask for:

```
--password / DCTL_PASSWORD  →  --password-command  →  --password-file  →  interactive prompt
```

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
| `--verify-samples` | `N` | `8` | — |
| `--checksum` | — | off | — |
| `--size-only` | — | off | — |
| `--immutable` | — | off | — |

### `--verify MODE`

The cost/assurance dial of the verified-write contract (`PLAN.md` §6 step 5). It
sets how hard DCTL looks *after* a write, and it is the same dial `dctl verify`
and `dctl scrub` use when they re-ask the question later.

| Mode | What it does | What it proves | Extra egress |
|------|--------------|----------------|--------------|
| `checksum` (default) | Compares the provider's stored checksum against the one computed locally. | The provider still holds the ciphertext DCTL sent. | none |
| `sample` | Additionally Range-reads and decrypts `--verify-samples` chunks per object. | Those chunks decrypt and authenticate. | partial |
| `strict` | Reads and decrypts every object in full and confirms its whole-file BLAKE3. | The plaintext is intact, end to end. | **full — a second copy of the data** |

**Be clear about what `strict` costs.** A full read-back downloads everything it
just uploaded: a 50 GB video costs 50 GB up and 50 GB back down, and on a metered
bucket that is a doubled bill for the run, not a rounding error. Aimed at a
*tree* rather than a single object it is worse still — `--verify strict` over a
50 TB vault is a 50 TB download, so the integrity commands warn before starting
whenever a byte-reading mode meets a prefix. `sample` is the middle setting: it
pays for `--verify-samples` chunks per object instead of all of them, which
catches wholesale corruption without buying a second copy of the data.

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

How many chunks per object `--verify sample` reads back. Meaningless under
`checksum` (nothing is read) and under `strict` (everything is). Raise it to buy
more assurance per object at a proportional cost in egress; the default of 8 is
chosen to catch wholesale corruption cheaply, not to be a statistical guarantee.
*Not yet honoured* — the sampling read path is not wired up in this build.

### `--checksum`

Decide whether a file needs transferring by comparing content hashes instead of
size and modification time. Slower on the local side (the source must be read to
hash it) and correct in the cases the default misses — a file rewritten with
identical length and a preserved mtime. If either side cannot supply a hash, the
command **fails** rather than quietly falling back to a weaker comparison, since
a weaker answer dressed up as the one you asked for is exactly the misreporting
the durability contract exists to prevent.

### `--size-only`

Compare by size alone, ignoring modification time. The fastest and weakest
comparison: it is the right choice against a destination whose timestamps are
untrustworthy, and the wrong one anywhere an in-place edit might preserve a file's
length. Conflicts with `--checksum` — the two ask for contradictory comparisons,
so passing both is a usage error rather than a silent precedence rule. With
neither flag, the default is size plus modification time within a one-second
window.

**One exception, and it is announced.** A sealed vault records the moment each
object was written rather than the source file's modification time, so the
default comparison cannot mean anything against one. When `copy`, `move`,
`sync` or `check` has a vault on either side and neither flag was given, the
default becomes a **content** comparison — the vault records a plaintext BLAKE3
and can answer the stronger question — and the run warns on stderr naming the
side that forced it. `--size-only` and `--checksum` are unaffected: both are
explicit, and neither depends on a timestamp. See
[dctl copy](commands/dctl_copy.md) for the cost and for what retires it.

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
| `--transfers` | `N` | `4` | — |
| `--checkers` | `N` | `8` | — |
| `--bwlimit` | `RATE` | unlimited | — |
| `--retries` | `N` | `3` | — |
| `--low-level-retries` | `N` | `10` | — |
| `--timeout` | `SECONDS` | `300` | — |
| `--contimeout` | `SECONDS` | `60` | — |
| `--max-transfer` | `SIZE` | unlimited | — |

Every flag in this group parses and validates but is *not yet honoured* by the
transfer engine in this build.

### `--transfers N`

Files transferred in parallel. Four keeps a single large-file stream near line
rate on a home connection without starving interactive use; raise it for
many-small-files workloads, where the win is large and the only thing you risk is
tripping a provider's rate limiter. Lower it when DCTL is sharing a link with
something latency-sensitive.

### `--checkers N`

Metadata comparisons run in parallel — the pipeline stage that decides which
files need transferring at all. Defaults higher than `--transfers` because a check
is one cheap round trip and the checker pipeline should stay ahead of the
transfers it feeds. Raising it speeds up the "nothing changed" case on a large
tree, which is most of what a repeated `sync` does.

### `--bwlimit RATE`

Bandwidth ceiling, written with the usual size suffixes (`10M`, `1.5MiB`) or
`off` for unlimited. The rate is bytes per second, not bits — `10M` is roughly an
80 Mbit/s link fully used. Use it to keep a long upload from making a shared
connection unusable rather than as a cost control; `--max-transfer` is the one
that bounds spend.

### `--retries N`

How many times a *whole failed file* is retried. This is the outer loop, and it
exists for failures that survive the inner one — a file that fails three times in
a row is usually failing for a reason that will not resolve on the fourth.
Retries are counted and reported in the end-of-run summary so a run that
succeeded only after fighting for it does not look identical to one that did not.

### `--low-level-retries N`

How many times an individual HTTP request is retried. Higher than `--retries`
because most failures at this layer are a single transient 5xx, a reset, or a 429
that succeeds immediately on repeat. Retries back off exponentially from 250 ms
with jitter, capped at 30 s, so a long provider outage does not stretch one file
into the next hour.

### `--timeout SECONDS`

Inactivity timeout on a transfer: how long a connection may produce no data
before DCTL gives up on it and retries. Five minutes is generous on purpose —
cloud providers stall mid-multipart under load, and a short timeout converts a
recoverable pause into a churn of retried parts. Shorten it when you would rather
fail fast than wait, for example inside a job with its own deadline.

### `--contimeout SECONDS`

Connection establishment timeout, separate from `--timeout` because the two
failures mean different things: a connection that never opens is usually DNS, a
firewall, or a wrong endpoint, none of which get better by waiting five minutes.
One minute is long enough to survive a slow TLS handshake on a bad link.

### `--max-transfer SIZE`

Stop the run once this much has been transferred (`100G`, `500GB`, `off`). The
budget flag: it is how you cap what a single run can cost on a metered provider,
or stay under a daily cap. A run that stops for this reason is not a failure but
it is not a completed sync either — it exits **8** (`transfer_limit_exceeded`) so a
script can tell the difference.

---

## Filtering

| Flag | Value | Default | Repeatable |
|------|-------|---------|------------|
| `--include` | `PATTERN` | none | yes |
| `--exclude` | `PATTERN` | none | yes |
| `--filter-from` | `PATH` | none | yes |
| `--files-from` | `PATH` | none | yes |
| `--min-size` | `SIZE` | none | no |
| `--max-size` | `SIZE` | none | no |
| `--max-depth` | `N` | `-1` (unlimited) | no |

**One engine answers for every command that takes these flags.** The transfer
family (`copy`, `copyto`, `move`, `moveto`, `sync`) and the recovery family
(`backup`, `restore`) both evaluate them through `crate::filter`, so a rule means
exactly the same thing wherever it is typed. Three implementations of one flag
would eventually disagree, and the way they disagree is that a listing shows a
file the transfer then omits — or, in a `sync`, that a rule reaching only one
side turns an excluded destination file into an "extra" and deletes it.

**A filter is applied to both sides of a diff.** That is the property that makes
`sync --exclude 'archive/**'` protect `archive/` at the destination rather than
empty it: the rule hides the tree on both sides, so it is neither transferred nor
deleted.

**What is refused is a filter that will not compile** — a malformed pattern, an
unreadable or unparseable rule file, a size that does not parse, a `--max-depth`
that is not a depth. Those are usage errors (exit **1**) raised before anything
is listed, because a run that proceeded with a rule the operator believes is in
force is the data-loss case this whole group exists to prevent.

`purge` is the exception that neither honours nor refuses: it removes a whole
tree by definition, so it **warns** that filters are being ignored and points at
`delete` instead. The listing family's own coverage is documented per command.

**Precedence: `--exclude` wins.** An entry matching any exclusion is gone
regardless of what else it matches, and `--include` then narrows whatever
survived. The two flags can be written into a contradiction, and of the two
possible readings, "showed less than asked" is recoverable by re-running while
"showed a file the user told us to hide" is not.

**Anchoring** follows rclone's rules, because rclone's patterns are the ones
users bring:

* A pattern beginning with `/` is anchored at the listing root: `/tmp/*` matches
  `tmp/a` but never `photos/tmp/a`.
* A pattern with no `/` at all matches the **file name** at any depth: `*.jpg`
  means what everyone assumes it means.
* Anything else matches the root-relative path and every component-aligned suffix
  of it, so `tmp/*` finds `photos/tmp/a` as well as `tmp/a`.

**Glob dialect:** `*` within one path component, `**` across them, `?` for a
single character, `[a-z]` and `[!abc]` for classes, `\` to escape. A malformed
pattern is a usage error (exit **1**) naming the flag it came from.

**Size syntax** for `--min-size`/`--max-size` (and `--bwlimit`, `--max-transfer`):
a bare number or an IEC spelling is **binary** (`10G` = `10Gi` = `10GiB` =
2³⁰ × 10), while an explicit SI spelling is **decimal** (`10GB` = 10⁹ × 10) —
because someone writing `--max-size 5TB` copied it off a provider's invoice and
means the invoice's terabyte. `off` (or `0`) disables a limit.

### `--include PATTERN`

Show or transfer only paths matching this glob; repeat the flag to accept several
patterns, and an entry matching any one of them is in scope. With no `--include`
at all, everything not excluded is in scope — an empty include list is not an
empty selection. Reach for it when the set you want is easier to describe than
the set you do not.

Honoured in full by the listing commands. The transfer commands and
`backup`/`restore` **refuse** it with exit **7** in this build rather than run
with the pattern dropped; narrow those runs with an explicit source path, or with
`--min-size`/`--max-size`/`--max-depth`.

### `--exclude PATTERN`

Drop paths matching this glob, repeatable in the same way, and applied before
`--include`. This is the flag to use for anything you must never touch, precisely
because it cannot be overridden by an include: caches, `node_modules`, editor
droppings, another tool's staging directory.

Honoured by exactly the same commands as `--include`.

### `--filter-from PATH`

Read include/exclude rules from a file, one per line — the form that scales past
what fits on a command line and can be version-controlled. Honoured by the
listing, transfer and recovery families. A rule file keeps its **internal order
exactly**,
because that order is the whole reason the form exists, and unlike the `--include`
flag it does **not** append an implicit `- **`: a rule file is an ordered program
whose author is expected to write their own final rule. A file that cannot be read
or parsed is a usage error rather than a run with the rules dropped, because a
transfer whose filter file was silently ignored *looks* complete.

### `--files-from PATH`

Transfer only the paths named in this file, one per line, skipping the directory
walk entirely — the right tool when an upstream process already knows exactly
which files changed. Repeatable; several lists are merged into one set.

Honoured by the listing, transfer and recovery families. It is more than a
convenience in `backup` and `restore`, where it is the way to give a restore
drill an exact path set. Blank lines and `#` comments are skipped, and every
surviving line is
canonicalised the same way an index key is (`/`-separated, NFC), so a list
written on Windows with backslashes selects the same objects as one written on
Linux. A line containing `..` is a usage error (exit **1**) naming the file and
line number, rather than a path quietly resolved outside the transfer root.

A listing verb applies the list as an exact filter rather than as a way to skip
a walk: an index range scan and a provider listing are already flat, so there is
no directory recursion to be skipped. The **set of objects shown is the same set
a transfer would take**, which is the property that matters.

### `--min-size SIZE`

Skip files smaller than this. Applied to objects only, never to directories: a
directory's size is an aggregate, and filtering directories on it would hide
every small file inside a large one. Useful for skipping the long tail of tiny
files whose per-file overhead dominates a transfer.

### `--max-size SIZE`

Skip files larger than this — the flag that keeps a video or a disk image out of
a run meant for documents, and a cheap way to bound what an unattended job can
cost. Directories are exempt for the same reason as `--min-size`.

### `--max-depth N`

Limit recursion depth; `-1` (the default) means unlimited, `1` means the
immediate children of the target. Depth is counted from whatever the command was
pointed at, not from the vault root. The directory-oriented commands (`lsd`,
`tree`) apply the limit to the directories they synthesise rather than to the
objects they derive them from, so `dctl lsd --max-depth 1` reports top-level
directories properly instead of reporting them all as empty.

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

### `--ascii`

Draw bars, spinners, tree branches and status marks from ASCII instead of Unicode
box-drawing and braille glyphs. DCTL already picks ASCII automatically on a
legacy Windows console and in a non-UTF-8 locale; this flag forces it for the
cases the detection cannot see, such as a log viewer or a terminal emulator that
renders the Unicode set as mojibake.

### `-P`, `--progress`

Force live progress bars on, even when stderr is not a terminal. Without it, bars
appear only when stderr really is a terminal and a redirected run falls back to
periodic plain-text status lines, since bar redraws would fill a log file with
megabytes of escape sequences. Use it inside a PTY wrapper or a CI job that
renders ANSI but fails the `isatty` test. `--quiet` beats it.

### `--stats SECONDS`

How often the periodic status line is emitted when bars are unavailable. `0`
disables it entirely. Sixty seconds is a readable cadence for a long transfer in a
log file; shorten it if you are watching a CI job and want more evidence of life.
*Not yet honoured.*

### `--stats-one-line`

Condense each periodic status report onto a single line, which is what makes the
output greppable and keeps a long-running job from dominating a log. *Not yet
honoured.*

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

Dump protocol detail for debugging. Repeatable, so `--dump headers --dump retries`
gives both. `headers` prints HTTP request and response headers with
`Authorization` always redacted; `bodies` prints request and response bodies and
never includes plaintext file content; `requests` gives one line per HTTP request
(method, URL, status, duration); `retries` gives every retry decision with the
classification that drove it; `filters` shows which rule included or excluded each
path; `config` prints the resolved configuration with all secrets redacted. The
tracing layer that produces this is not free and is installed only when at least
one target is requested. *Not yet honoured.*

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

## Flags that parse but do not yet act

These are accepted, validated and reported by `--help`, but no command consumes
them in this build. They are listed here so that nobody plans a job around one:

* `--verify-samples` — the sampling read path is not wired up. `--verify sample`
  itself is plumbed through to the integrity commands; the depth is not.
* `--transfers`, `--checkers`, `--bwlimit`, `--retries`, `--low-level-retries`,
  `--timeout`, `--contimeout`, `--max-transfer` — the transfer engine that would
  read them is not complete.
* `--stats`, `--stats-one-line` — the periodic status emitter is not installed.
* `--dump` — the protocol tracing layer is not installed.

The filtering flags are deliberately **not** on this list, because none of them is
ever silently ignored: the transfer and recovery families evaluate all of them
through one engine, and a rule that will not compile is a usage error rather than
a run with the rule dropped. See [Filtering](#filtering). `--key-file` is likewise absent: rather
than fall back to weaker protection than was asked for, it refuses everywhere
with exit **7** — when creating a vault *and* when opening one. See
[`--key-file PATH`](#--key-file-path).

The one place a filter is neither honoured nor refused is `purge`, which removes
a whole tree by definition and warns that it is ignoring them.

---

## See also

* [docs/commands/](commands/) — per-command pages, each listing the global flags
  that change that command's behaviour.
* [docs/EXIT_CODES.md](EXIT_CODES.md) — the exit-code contract.
* `PLAN.md` §6 (verified-write durability), §7 (logging and audit), §14
  (configuration and secrets).
