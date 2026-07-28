# dctl about

Show remote usage, quota and capability information.

## Synopsis

`dctl about` answers the question "what is actually on the other end of this
name?". rclone's command of the same name answers three questions at once — how
much is stored, how much the account is allowed, and what the backend can do —
and DCTL answers each of them as well as it honestly can, which is not equally
well:

| Question | Answer here | How |
|----------|-------------|-----|
| How much is stored? | **exact** | measured, by enumerating the remote |
| What is the allowance? | **not reported**, with the reason | there is no call to make |
| What can the backend do? | **exact** | a fact about this binary, read offline |

**Stored is measured, not asked for.** For a **vault** the walk is the local
encrypted index, so the object count and the total *plaintext* size are exact and
cost no provider request. For a **plain** remote — a local directory, a bucket,
or a vault's own object store — it is that remote's listing, so the figure is the
objects *as stored*. The basis is printed beside the number, because a plaintext
total and a stored total are both true, are not equal, and get reconciled against
invoices: the same data reads `195.3 KiB (plaintext)` through `archive:` and
`197.0 KiB (stored)` through `archive-store:`, and the difference is the
encryption overhead the provider bills for.

Measuring a vault means unlocking it, so **`dctl about archive:` asks for a
password**. `dctl about archive-store:` does not, and reports the ciphertext side
of the same data — which is one of the things `dctl init`'s two remotes exist
for. (`about` is therefore no longer in the set of commands that never need a
vault; `config`, `version` and `completion` still are.)

**The allowance is not reported, and the report says exactly why**, in the
`limits_note` row and in the JSON beside the two `null`s it explains:

```
total_bytes  not reported — nothing in this build can measure it
free_bytes   not reported — nothing in this build can measure it
limits_note  no allowance is reported: dctl_store::Backend exposes no usage or
             quota call on any provider (see the usage_reporting and
             quota_reporting rows), and a local filesystem's free space needs a
             statvfs syscall this crate cannot make under
             #![forbid(unsafe_code)]. The objects and bytes above are measured by
             listing the remote, not asked of it.
```

Two independent reasons, both named because they have different remedies. The
provider half is a missing trait method: `dctl_store::Backend` has `put`, `get`,
`head`, `list_page` and no usage or quota call at all — so there is no request to
make, on any provider, and a figure here would be invented. The local half is a
missing *safe* API: free space needs `statvfs`, the standard library exposes no
equivalent, and `dctl-cli` is `#![forbid(unsafe_code)]`, so the syscall is
unreachable from here by a rule the crate applies to itself.

The keys stay in the JSON as `null` rather than disappearing: a key that vanished
when the answer was unknown would make a consumer's `.total_bytes` silently
`undefined`, and a `0` would be believed and then used to decide whether a backup
will fit.

**`dctl about --capabilities REMOTE` still needs nothing.** It reads
`config.toml` and stops: no credential is looked up, no backend is constructed,
no HTTP request is made, no listing is performed, no vault is unlocked and no
password is ever prompted for. That makes it usable as a configuration check on a
machine where nothing has been set up yet — which is exactly when someone needs
to know whether `vault:` points where they think it does.

### What a capability report tells you

Two tables in text, one JSON document in `--json`, the same facts in both.

The **summary** says what was addressed, what is really behind it, and how much
is in it. Every row label is the JSON field name it corresponds to, so the two
renderings can be read against each other without a legend:

| Row | Meaning |
|-----|---------|
| `remote` | the spec as it was *understood*, not as it was typed — `vault:./a//b` comes back canonicalised, `C:\data` comes back as a path |
| `provider` | the named remote's own type; `vault` for a vault wrapper |
| `storage_provider` | the provider at the far end of the vault chain — the one that will actually hold the bytes, and the one the capability rows describe |
| `encrypted` | whether anything in the chain encrypts on the way through |
| `chain` | the remote names walked, nearest first, joined with ` -> ` |
| `objects` | how many objects the remote holds, counted by listing it |
| `bytes` | their total size, rounded for a human *and* exact in the same cell |
| `sizes` | which basis that total used: `plaintext` or `stored` |
| `total_bytes` | the allowance. Always unknown — see the note below it |
| `free_bytes` | what is left of it. Likewise |
| `limits_note` | why those two are unknown, in full |

The chain row is **omitted from the text table** for a filesystem path, which is
not a named remote and has no chain; an empty cell there would read as a missing
value rather than an inapplicable one. The JSON keeps the `chain` key as `[]`,
because a machine consumer reads the shape once and must not have it change
between remotes.

The six usage rows are omitted from the text table under `--capabilities`, which
measured nothing, for the same reason — a `0` there would be read as an empty
remote. Their JSON keys stay present and `null`, which is the difference between
"not measured" and "none".

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
   provider. The UNC half is applied identically on every platform; the drive
   half is applied where drives exist, which is where rclone applies it. On such
   a platform a drive letter wins over a remote of the same name, and
   `dctl config create` refuses to mint one there.
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
The colon is what makes a name a remote. A one-character name is legal, as
rclone's is; what decides `c:` is the platform, and on one with drives the drive
wins.

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
* **The remote is resolved before anything is measured.** A user who typed a
  remote that does not exist is told about the typo, not about a listing that
  failed.
* **A listing that fails is an error, never a zero.** "The backup is empty" is a
  conclusion people act on, so an unreachable bucket or an unreadable index ends
  the run with a non-zero code and no usage figures at all.
* **Measuring costs one listing pass.** On a vault that is a local index scan;
  on a bucket it is a real paged listing, which is the honest price of an exact
  answer. Memory is two integers however large the remote is.
* **`--dry-run` changes nothing.** The command only reads, so there is no
  mutation to withhold and a `[dry-run] would describe` line would be noise.
* If the configuration file is readable by anyone but its owner, a warning about
  that appears on stderr before the report — it names buckets, endpoints and
  regions, which is free reconnaissance.

### Status in this build

**Usage reporting works.** It is measured by listing rather than asked of the
provider, and the report says so on stderr at `-v`:

```
usage is measured by listing the remote — it counts what DCTL can see, not what
the provider is billing for
```

That distinction matters when the two disagree: a bucket may hold objects DCTL
did not write, and a vault's plaintext total is smaller than the ciphertext it
costs to store.

**Quota and free-space reporting do not, and cannot yet.** Both reasons are in
`limits_note` above, and neither is a missing branch in this command:
`usage_reporting` and `quota_reporting` are rows in the capability matrix like
any other, unsupported by every provider, and a unit test fails the moment a
backend gains either — which is the reminder to come back here. `PLAN.md` §11
does not schedule them in any phase; they become possible when the `Backend`
trait gains the call, not before.

The capability half is unchanged and **complete**: `dctl about --capabilities`
succeeds today with no configuration, no credentials, no listing and no network.

```
dctl about [REMOTE] [flags]
```

## Examples

Ask a vault how much it is holding. The remote is a vault wrapper, so the report
follows the chain and describes `archive-store` — the remote that actually holds
the bytes — while the totals come from the sealed side, in plaintext bytes:

```console
$ dctl about archive:
remote            archive:
provider          vault
storage_provider  local
encrypted         true
chain             archive -> archive-store
objects           4
bytes             195.3 KiB (200018 bytes)
sizes             plaintext
total_bytes       not reported — nothing in this build can measure it
free_bytes        not reported — nothing in this build can measure it
limits_note       no allowance is reported: dctl_store::Backend exposes no usage or quota call on any provider (see the usage_reporting and quota_reporting rows), and a local filesystem's free space needs a statvfs syscall this crate cannot make under #![forbid(unsafe_code)]. The objects and bytes above are measured by listing the remote, not asked of it.

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

The same data through the object view. No password is needed, the figure is the
*stored* size, and it is larger than the plaintext total by the encryption
overhead — which is exactly what makes the two reconcilable rather than merely
different:

```console
$ dctl about archive-store:
remote            archive-store:
provider          local
storage_provider  local
encrypted         false
chain             archive-store
objects           9
bytes             197.0 KiB (201734 bytes)
sizes             stored
total_bytes       not reported — nothing in this build can measure it
free_bytes        not reported — nothing in this build can measure it
...
```

Find out what `vault:` really is before trusting a backup script to it —
offline, with no password and no listing:

```console
$ dctl about --capabilities vault:photos/2024
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

Ask a machine for the totals. The two `null`s carry their explanation with them,
so a capacity script cannot mistake "not measurable" for "zero":

```console
$ dctl about archive: --json | jq '{objects, bytes, sizes, total_bytes, free_bytes}'
{
  "objects": 4,
  "bytes": 200018,
  "sizes": "plaintext",
  "total_bytes": null,
  "free_bytes": null
}
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

The authentication flags (`--password`, `--password-command`,
`--no-ask-password`) are used when a **sealed** remote's usage has to be
measured, and are ignored in every other case — including every
`--capabilities` run, which never unlocks anything. The transfer, filtering and
durability flags have no effect: the listing is always the whole remote, and
nothing is ever written.

## Exit codes

| Code | Name | When |
|-----:|------|------|
| 0 | `success` | A report was produced — capabilities alone with `--capabilities`, capabilities plus measured usage without it. |
| 1 | `usage` | No remote given and no default configured; an empty or blank remote; a spec containing `..`; a second positional argument; `--remote` written after `about`; a config file whose remote name collides with a provider type. |
| 2 | `uncategorised` | A stdout write failed for a reason other than a broken pipe. |
| 5 | `temporary_error` | The provider never answered the listing. Retries were already exhausted. |
| 7 | `fatal_error` | An unknown remote; an unreadable, unparseable or internally inconsistent config file; a vault chain with a dangling `base` or a cycle; a missing credential for a remote that had to be listed. |
| 22 | `vault_locked` | A sealed remote would not unlock, so its usage could not be measured. `--capabilities` never reaches this. |
| 23 | `index_error` | The vault's index could not be read. Nothing is reported as zero. |
| 25 | `cancelled` | Ctrl-C or SIGTERM. |

Codes 0–10 mirror rclone's taxonomy; 20+ are DCTL's own. See
[../EXIT_CODES.md](../EXIT_CODES.md) for the full contract.

## See also

* [dctl size](dctl_size.md) — the same measured totals, scoped to a path and
  honouring the filter flags. `about` reports the whole remote and adds the
  capability matrix; `size` answers "how much is under *here*".
* [dctl config](dctl_config.md) — list, show and edit the remotes `about`
  resolves against.
* [dctl version](dctl_version.md) — the same question about the binary rather
  than about a remote.
* [dctl init](dctl_init.md) — create the vault that a `vault` remote in the
  chain refers to.
* [dctl ls](dctl_ls.md) — what is actually stored under the remote `about`
  describes.
