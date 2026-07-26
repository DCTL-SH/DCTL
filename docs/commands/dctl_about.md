# dctl about

Show remote usage, quota and capability information.

## Synopsis

`dctl about` answers the question "what is actually on the other end of this
name?". rclone's command of the same name answers three questions at once — how
much is stored, how much the account is allowed, and what the backend can do —
and DCTL deliberately splits them, because in this build only the third has an
honest answer.

**`dctl about --capabilities REMOTE` is the half that works, and it needs
nothing.** It reads `config.toml` and stops: no credential is looked up, no
backend is constructed, no HTTP request is made, no vault is unlocked and no
password is ever prompted for (`dctl about` is one of the four commands
`Command::requires_vault` excludes, alongside `config`, `version` and
`completion`). That makes it usable as a configuration check on a machine where
nothing has been set up yet — which is exactly when someone needs to know
whether `vault:` points where they think it does.

**`dctl about REMOTE` without `--capabilities` fails with exit 7.** See *Status
in this build* below. It does not print zeroes, an empty table or a cheerful
"0 B used": a number nobody measured is worse than no number, because it gets
believed and then gets used to decide whether a backup will fit.

### What a capability report tells you

Two tables in text, one JSON document in `--json`, the same facts in both.

The **summary** says what was addressed and what is really behind it:

| Row | Meaning |
|-----|---------|
| `remote` | the spec as it was *understood*, not as it was typed — `vault:./a//b` comes back canonicalised, `C:\data` comes back as a path |
| `provider` | the named remote's own type; `vault` for a vault wrapper |
| `storage_provider` | the provider at the far end of the vault chain — the one that will actually hold the bytes, and the one the capability rows describe |
| `encrypted` | whether anything in the chain encrypts on the way through |
| `chain` | the remote names walked, nearest first, joined with ` -> ` |

The chain row is **omitted from the text table** for a filesystem path, which is
not a named remote and has no chain; an empty cell there would read as a missing
value rather than an inapplicable one. The JSON keeps the `chain` key as `[]`,
because a machine consumer reads the shape once and must not have it change
between remotes.

The **capability matrix** lists every capability, supported or not, always all
seven rows. A report that listed only what a provider *can* do would leave a
reader unable to tell "this provider cannot" from "this build forgot to ask",
and for `usage_reporting` and `quota_reporting` that distinction is the entire
point of the command.

| Capability | `local` | `b2` | `s3` | `r2` |
|------------|:-------:|:----:|:----:|:----:|
| `range_reads` | yes | yes | yes | yes |
| `verified_writes` | yes | yes | yes | yes |
| `paged_listing` | yes | yes | yes | yes |
| `multipart_upload` | no | yes | yes | yes |
| `empty_directories` | yes | no | no | no |
| `usage_reporting` | no | no | no | no |
| `quota_reporting` | no | no | no | no |

Every row is a property of the **backend implementation** in `dctl-store`, not
of the provider's feature list: `range_reads` is claimed because
`Backend::get_range` is on the trait and every implementation honours it, and
`usage_reporting` is claimed by nobody because no such call exists on the trait
at all. That is what makes the answer knowable offline — it is a fact about this
binary, and this binary is right here. It is also the limit of the claim, which
the command says out loud on stderr at `-v`:

```
capabilities are declared by the backend implementation, not probed from the
provider: no request was made and no credential was read
```

Whether a particular bucket lets a particular key do these things is a different
question, and one DCTL cannot answer until it can talk to the provider. A
provider type that is not in the table at all — anything DCTL has not shipped a
backend for — is reported as supporting nothing, because an understated
capability produces a refusal and an overstated one produces a silent wrong
answer.

Text renders the middle column as the words `yes` and `no`, not glyphs: the
table is grepped at least as often as it is read. JSON carries a real boolean,
so a script branches on `true` and never on a human rendering that somebody
might translate.

### How the argument is resolved

Three ways a name resolves, tried in this order:

1. **A filesystem path** — `./photos`, `/srv/data`, `C:\data`, `\\server\share`,
   or anything written with the explicit `local:` prefix — is the local
   provider. The rule is applied identically on every platform, never under
   `#[cfg(windows)]`, so a drive letter is never mistaken for a remote called
   `C` even when a remote genuinely called `C` is configured.
2. **A configured remote** wins next, and its vault chain is followed to the
   remote that stores bytes. `vault:` reports `provider = vault` and
   `storage_provider = b2`, because a capability report that answered "vault"
   would describe a wrapper that stores nothing. Walking the chain is also what
   detects a cycle or a dangling `base`, so a broken config is diagnosed here
   rather than producing a confident answer about the wrong provider.
3. **A provider shorthand** — `b2:bucket`, `s3:bucket/prefix`, `r2:bucket` —
   resolves to that provider with no config file at all, which is the headless
   case `PLAN.md` §14 requires to keep working.

Anything else is an unknown remote and a hard failure (exit 7). It is never
quietly reinterpreted as a directory: reporting on the wrong thing is worse than
reporting on nothing.

**A name with no colon is a path, not a remote.** `dctl about b2` describes a
local directory called `b2`; `dctl about b2:` describes the Backblaze backend.
The colon is what makes a name a remote, and remote names must be at least two
characters — which is precisely what makes the drive-letter rule unambiguous.

### Where the default remote comes from

The positional `[REMOTE]` is optional, and falls back to the global
`--remote` / `DCTL_REMOTE` setting. One wrinkle is worth knowing before it
bites: on this subcommand the positional argument occupies the same clap
argument name as the global flag, so **`--remote` cannot be written after the
word `about`**. These two work:

```
dctl --remote b2:bucket about --capabilities
DCTL_REMOTE=b2:bucket dctl about --capabilities
```

and `dctl about --capabilities --remote b2:bucket` is rejected as an unexpected
argument (exit 1). Naming the remote positionally — `dctl about b2:bucket
--capabilities` — avoids the question entirely and is what the help text
suggests. When a positional argument *and* a default are both present, the
positional wins.

### Other behaviour worth knowing

* **Output goes to stdout, commentary to stderr.** `dctl about --capabilities
  vault: --json | jq -r .storage_provider` is a working pipeline. A closed pipe
  (`| head`) is a success, not a failure.
* **The remote is resolved before the unimplemented gate.** A user who typed a
  remote that does not exist is told about the typo, not about a missing engine.
* **`--dry-run` changes nothing.** The command only reads, so there is no
  mutation to withhold and a `[dry-run] would describe` line would be noise.
* If the configuration file is readable by anyone but its owner, a warning about
  that appears on stderr before the report — it names buckets, endpoints and
  regions, which is free reconnaissance.

### Status in this build

**Usage and quota reporting is not implemented, and says so.**
`dctl_store::Backend` has no usage or quota call — there is no method to invoke,
on any provider — so `dctl about REMOTE` cannot report either. A complete
invocation resolves the remote, validates the configuration, and then fails
with:

```
error: reading usage and quota from a remote is not implemented in this build
```

and exit code **7**. The refusal is not a special case bolted on:
`usage_reporting` and `quota_reporting` are rows in the capability matrix like
any other, unsupported by every provider, and a unit test fails the moment a
backend gains either — which is the reminder to delete the gate.

`PLAN.md` §11 does not schedule usage or quota reporting in any phase; it
becomes possible when the `Backend` trait gains the call, not before. If you
need to know how much a remote holds today, the honest answer is to count it by
listing — [dctl size](dctl_size.md), which reports a measured total rather than
a claimed one (and which is itself waiting on the vault handle in Phase 1).

The capability half is **complete**: `dctl about --capabilities` succeeds today
with no configuration, no credentials and no network.

```
dctl about [REMOTE] [flags]
```

## Examples

Find out what `vault:` really is before trusting a backup script to it. The
remote is a vault wrapper, so the report follows the chain and describes
`b2prod` — the remote that will actually hold the bytes — while recording that
everything passing through is encrypted:

```
dctl about --capabilities vault:photos/2024
remote            vault:photos/2024
provider          vault
storage_provider  b2
encrypted         true
chain             vault -> b2prod

Capability         Supported  Description
-----------------  ---------  ------------------------------------------------
range_reads        yes        Serve an arbitrary byte range without transferr...
verified_writes    yes        Refuse to report a write as stored until the st...
paged_listing      yes        Enumerate objects one bounded page at a time, s...
multipart_upload   yes        Split one large object across several requests,...
empty_directories  no         Hold a directory with no objects under it. An o...
usage_reporting    no         Report how many bytes and objects the remote cu...
quota_reporting    no         Report the account's storage allowance and what...
```

Ask a machine the same question. `--json` emits one document; the `capabilities`
array carries real booleans, so a deployment check can branch on them without
parsing a table:

```
dctl about --capabilities b2prod:bucket/media --json | jq -r '.storage_provider'
b2

dctl about --capabilities b2prod:bucket/media --json \
  | jq -r '.capabilities[] | select(.supported) | .name'
range_reads
verified_writes
paged_listing
multipart_upload
```

Address a provider directly, with no configuration file on the machine at all.
This is the headless case: the shorthand resolves to the backend without a
lookup, so it works on a fresh container before `dctl config` has ever run:

```
dctl about --capabilities s3:archive-cold/2019
```

A Windows path is a path, on every platform. `C:` is a drive specifier, so this
describes a directory on this machine and reports the `local` provider — even if
a remote called `C` exists in the config file. Note that `empty_directories` is
`yes` here and `multipart_upload` is `no`, which is the difference between a
filesystem and an object store:

```
dctl about --capabilities C:\Backups\photos
remote            C:\Backups\photos
provider          local
storage_provider  local
encrypted         false

Capability         Supported  Description
-----------------  ---------  ------------------------------------------------
range_reads        yes        Serve an arbitrary byte range without transferr...
verified_writes    yes        Refuse to report a write as stored until the st...
paged_listing      yes        Enumerate objects one bounded page at a time, s...
multipart_upload   no         Split one large object across several requests,...
empty_directories  yes        Hold a directory with no objects under it. An o...
usage_reporting    no         Report how many bytes and objects the remote cu...
quota_reporting    no         Report the account's storage allowance and what...
```

Ask for usage and quota, and be told plainly that nobody measured them. Nothing
is printed on stdout, so a pipeline reading this command never receives a
fabricated record:

```
dctl about vault:
error: reading usage and quota from a remote is not implemented in this build
warning: No provider in this build can be asked how much it is holding —
  `dctl_store::Backend` has no usage or quota call, which is why both appear as
  unsupported in the capability table. `dctl about --capabilities REMOTE`
  reports what the remote can do, offline and without credentials.
```

A typo is diagnosed as a typo, not as a missing feature, because the remote is
resolved before the gate:

```
dctl about --capabilities vualt:photos
error: unknown remote 'vualt'
warning: Run `dctl config list` to see configured remotes, or address a provider
  directly as one of local, b2, s3, r2.
```

## Options

```
      --capabilities   Report what the remote's backend can do, and stop
  -h, --help           help for about
```

The positional argument is `[REMOTE]` — a remote name, a `REMOTE:PATH` spec, or
a filesystem path. It is optional and falls back to `--remote` / `DCTL_REMOTE`;
see *Where the default remote comes from* for why the flag must precede the
subcommand here. Exactly one positional is accepted: `dctl about a: b:` is a
usage error rather than a silently ignored second argument.

## Options inherited from parent commands

Every global flag is accepted; see [../GLOBAL_FLAGS.md](../GLOBAL_FLAGS.md) for
the full list. `--json` is never redeclared on this command — it reaches it
through the global argument block like every other. The ones that change what
`dctl about` does:

| Flag | Effect here |
|------|-------------|
| `--config <PATH>` | Which `config.toml` is read to resolve the remote and its vault chain. |
| `--remote <SPEC>` | The default when no positional argument is given. Must appear **before** the subcommand on this command; `DCTL_REMOTE` works anywhere. |
| `--format`, `--json` | `text` (two tables), `json` (one document), `json-lines` (the same document on one line). |
| `-v`, `--verbose` | Shows the stderr notice explaining that capabilities are declared, not probed. |
| `--quiet` | Silences the notice and the config-permission warning. The report itself is data on stdout and survives. |
| `--color`, `--ascii` | Table styling only. |

The authentication flags are accepted and never used: this command does not
unlock a vault. The transfer, filtering and durability flags have no effect —
nothing is listed and nothing is written.

## Exit codes

| Code | Name | When |
|-----:|------|------|
| 0 | `success` | A capability report was produced. Only reachable with `--capabilities`. |
| 1 | `usage` | No remote given and no default configured; an empty or blank remote; a spec containing `..`; a second positional argument; `--remote` written after `about`; a config file whose remote name collides with a provider type. |
| 2 | `uncategorised` | A stdout write failed for a reason other than a broken pipe. |
| 7 | `fatal_error` | The usage/quota report itself (**every invocation without `--capabilities`**); an unknown remote; an unreadable, unparseable or internally inconsistent config file; a vault chain with a dangling `base` or a cycle. |
| 25 | `cancelled` | Ctrl-C or SIGTERM. |

Codes 0–10 mirror rclone's taxonomy; 20+ are DCTL's own. See
[../EXIT_CODES.md](../EXIT_CODES.md) for the full contract.

## See also

* [dctl size](dctl_size.md) — how much a remote holds, counted by listing rather
  than asked of the provider. The honest substitute for the missing usage
  report.
* [dctl config](dctl_config.md) — list, show and edit the remotes `about`
  resolves against.
* [dctl version](dctl_version.md) — the same question about the binary rather
  than about a remote.
* [dctl init](dctl_init.md) — create the vault that a `vault` remote in the
  chain refers to.
* [dctl ls](dctl_ls.md) — what is actually stored under the remote `about`
  describes.
