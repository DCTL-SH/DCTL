# dctl config

Create and manage configuration and remotes.

## Synopsis

`dctl config` reads and changes DCTL's configuration file: a TOML document
holding **non-secret settings only** — named remotes with their type, bucket,
endpoint, region and policy defaults. It is the command you use to give
`b2:media-archive` the shorter name `b2prod`, to point a vault wrapper at the
remote it encrypts through, and to find out where the file lives when something
needs fixing by hand.

**No credential ever goes in this file.** That is the deliberate difference from
`rclone.conf`, which stores provider keys "obscured" with reversible
obfuscation that anyone holding the file can undo. In DCTL, provider
credentials come from the environment (`DCTL_B2_KEY_ID`, `DCTL_B2_APP_KEY`, and
the S3/R2 equivalents), and the vault password is never stored anywhere at all —
it is prompted for, or produced by `--password-command`. The rule is enforced
three ways rather than documented once:

* The configuration **model has no field** that could hold a credential, so
  `dctl config create b2prod b2 app_key=K001…` is refused, by name, before
  anything is written.
* A credential-shaped key **pasted into the file by hand** makes the file fail
  to load. Every subcommand that reads it — and every other DCTL command —
  stops with exit 7 and names the offending key. It is not ignored, because an
  ignored `secret_key` stays on disk, in your backups, and in the next bug
  report.
* Everything printed by [`show`](#show) and [`redact`](#redact) goes through a
  redaction pass on the way out, so even a credential that is legal in a legal
  field (a password inside an endpoint URL, a value indistinguishable from a
  generated token) is replaced by `<redacted>` rather than published.

**Every subcommand works headlessly.** `create` and `update` take their settings
as arguments rather than asking questions, so a provisioning tool can configure
a server with no terminal attached — rclone's interactive questionnaire has no
equivalent here and is not coming. `edit` is the one exception, and it *refuses*
rather than hanging when there is no terminal for an editor to attach to.

**The file is never left half-written and never written unloadable.** Writes are
staged through a temporary file and renamed into place, so an interrupted
`config create` cannot produce a truncated document that reads as "no remotes
configured". Validation runs before the save, not after: a `vault` remote naming
a base that does not exist, an `update` that would remove a required setting, a
`delete` that would orphan a wrapper — each fails with the file untouched. A
file DCTL creates is owner-only (mode `0600`) from its first byte and carries a
header explaining the no-secrets rule, because the moment someone is about to
paste an application key in is the moment they are looking at that header.

**A missing configuration file is not an error.** `PLAN.md` §14 requires DCTL to
run entirely from flags and environment variables, so a machine that has never
run `dctl config` must not be told it is misconfigured. Every read-side
subcommand treats an absent file as an empty configuration and succeeds —
including when the path was named explicitly with `--config`, so a typo in that
flag produces an empty listing rather than a complaint. `dctl config file -v`
says whether the file exists; `dctl config touch` creates it. A file that exists
but cannot be *read* (wrong owner, bad permissions, I/O error) is still a hard
failure, because silently continuing with an empty configuration there would
send a later transfer somewhere else entirely.

**How failures are classified, and why it matters.** A name you typed wrongly is
a usage error (exit **1**). The state of the file on disk being wrong is a fatal
error (exit **7**) — and that includes `no remote named 'x' is configured`,
which is raised by the configuration layer rather than by these subcommands
precisely so that a remote that does not exist produces the same exit code
whichever command noticed. Scripts branch on this, and a mistyped argument must
not be indistinguishable from a corrupted installation.

**`dctl config` never needs the vault password.** None of its subcommands
unlocks anything, so none of them will ever prompt.

Twelve subcommands, ordered as a workflow:

### list

`dctl config list` prints the configured remotes, one per line: name, type, and
— for a vault remote — the remote it wraps. Two narrow columns plus the base,
because a listing is what a script greps; the settings behind a name are
`show`'s job, where the redaction rules apply. A remote that stores bytes itself
prints `-` in the base column. Nothing at all is printed when nothing is
configured (an empty table with a header reads as a malfunction); the count goes
to stderr at `-v`, where it cannot pollute a pipeline. Remotes are listed sorted
by name — the same order the file itself is written in, so the listing and the
file read alike and a one-setting change stays a one-line diff.

### show

`dctl config show NAME` prints one remote's settings as `key value` pairs,
sorted by key, `type` included. Optional settings that are unset do not appear
at all rather than printing a placeholder that would imply a decision nobody
made.

**This command never prints a secret.** Every value is routed through the
redaction policy, and a withheld value is *replaced*, never dropped — hiding the
row would hide the mistake from the person who has to fix it. Four rules can
fire, and `--json` reports which one did: the key names a credential
(`sensitive_key`), the value carries key material such as PEM armour or a bearer
token (`credential_marker`), the value is a URL with a password in its authority
(`credential_url`), or the value is a long, mixed-case, high-entropy token
(`opaque_token`). A pre-signed URL keeps its shape but loses its signature
parameters. When anything is withheld, a warning on stderr names the keys and
the rules — never the values — and tells you to treat them as exposed and rotate
them.

### create

`dctl config create NAME TYPE [key=value …]` adds a remote in one
non-interactive command. The settings are turned into a real, typed remote
before anything is written, so a missing `bucket`, a setting the provider does
not define, or a `vault` remote naming a base that does not exist fails here
rather than at 3am in a backup job. An existing name is **not** silently
replaced without `--force` — rewriting `vault` because a script re-ran would
repoint every path in every other script that mentions it — and `--force`
replaces the whole section rather than merging into it.

`vault` is accepted here even though [`providers`](#providers) does not list it:
it is a legal section type but a wrapper rather than a destination, so it is not
offered as somewhere to put data.

### update

`dctl config update NAME [key=value …]` **merges into** an existing section.
Keys you do not mention keep their values, which is what makes it safe to run
from configuration management that only knows about the two settings it owns.
An empty value removes a key (`dctl config update s3west region=`) — the only
way to unset a setting without opening an editor.

It never *creates* a remote: a typo in the name would otherwise leave behind a
plausible-looking remote that points nowhere and is used by nothing. And it
never writes a merge result that would not load again — the merged settings are
turned back into a typed remote first, so removing a required setting fails with
the file byte-identical.

Values are coerced to the type the file expects, so `chunk_size=8388608` is
written as a number rather than a quoted string the loader would reject.
Integers and booleans are recognised; a number is only taken as a number when it
round-trips exactly, so `007` and `+5` stay strings — silently rewriting `007`
into `7` would report a value back differently from how it was set.

### delete

`dctl config delete NAME` removes a remote from the configuration. **No stored
data is touched** — the objects stay exactly where they are — but it removes the
only record of how to reach them, and a vault whose endpoint, bucket and region
have been forgotten is gone for practical purposes until someone reconstructs
them. So it goes through the destructive-confirmation gate like any other
destructive action (`--interactive` asks, `--dry-run` declines, `--force`
approves silently) and says on stderr, at `-v`, that the objects survive.

Deleting a remote that a vault remote still wraps is refused, naming every
dependant, because a vault remote whose base is gone makes the whole file
unloadable. Delete or repoint the wrapper first.

### import

`dctl config import LOCATION [--name NAME]` writes the two remotes that address
a vault which **already exists**. It inspects the location, confirms a `DKE1`
envelope is really there, and writes the same pair `dctl init` writes:

```
[remotes.archive-store]  type = local  path = /srv/vault  require_vault = true
[remotes.archive]        type = vault  base = archive-store
```

This is the recovery path for a configuration that was lost, and it is worth
saying plainly what was and was not at risk: **the data was never at risk.** A
vault's envelope lives on its own store, and every object is self-describing
(`PLAN.md` §13.1), so losing `config.toml` loses only the names you type. Nothing
here reads a secret, unwraps a key or moves a byte; it needs no vault password
at all, only the provider credentials required to read one small object.

**It is a command, not a detection.** DCTL could notice an envelope during a
`copy` and quietly start encrypting. It must not: what a command does to the
bytes passing through it is a function of the **remote name typed**, fixed when
the remote was defined, and never of what the destination happens to contain
today. A tool that switched to encrypting because it found a file would have
encryption semantics that changed under a running backup job, and no operator
could state from a script what that script does. So the inspection is explicit
and deliberate, and what it produces is *configuration* — after which every
later command behaves exactly as if `dctl init` had written it.

`--name` is optional here and required by `dctl init`, and the asymmetry is
deliberate. `init` creates something that did not exist, and its name is a
permanent choice nobody else can make. `import` is re-addressing a store that is
already there, and the container's own name — the bucket, the directory — is a
name you did choose, in the provider's console. It is used as the default, and
the moment it is not a legal remote name the command asks rather than mangling
it into something typeable. The store remote is `<NAME>-store` unless
`--store-name` says otherwise.

A location that holds **no** envelope is refused with exit 7 rather than
addressed, because writing configuration for an empty bucket would produce a
file that looks exactly like a working one and fails at the first unlock — in
the command people reach for precisely when something has already gone wrong.
An envelope of a format version this build cannot read is imported anyway, with
a warning: the addressing is correct whatever the version says, and refusing to
write two harmless lines would not fix an upgrade problem.

### verify

`dctl config verify` proves — from the configuration **alone**, with no data
access, no key and no network — that every remote resolves, that no vault chain
loops or dangles, and whether each remote is plain or sealed. It is the
compliance pre-flight: the check to run before an audit, in CI, or on a machine
you have just provisioned and have not yet trusted with data.

```console
$ dctl config verify
Name           Type   Mode    Store          Status
archive        vault  sealed  archive-store  ok
archive-store  local  plain   archive-store  ok
✓ 2 remote(s) in /home/ops/.config/dctl/config.toml verified
```

The `Mode` column is only possible because a remote's encryption behaviour
follows the **name**, fixed when the remote was defined, and never the
destination's current contents. A tool that decided by inspection could tell you
what a command *would have done* a moment ago; this one tells you what your next
command *will* do, and is right.

It is the one subcommand that deliberately opens a configuration the loader
refuses. Every other command reads through the strict door and stops at the
first fault, which is correct for them and useless here — an operator with a
dangling base would get the same one-line refusal from `verify` as from
`dctl ls` and still not know what else is wrong. So `verify` reads leniently,
applies the same rule functions the loader applies, and reports **every**
finding. Leniency covers the remote graph only: a malformed file, or a
credential-shaped key pasted in from an rclone tutorial, is still refused
outright.

Findings carry stable slugs, so a CI job can branch on the kind of fault rather
than on the wording of a message: `unknown-base`, `chain-cycle`,
`chain-too-deep`, `illegal-name`, `case-collision`, `incomplete-settings`,
`plain-at-vault-location`. Any finding at all is exit **7**; a sound file — and
an empty one — is exit 0.

### file

`dctl config file` prints the path of the configuration file and nothing else —
one line, no label — because it exists to be substituted:
`$EDITOR "$(dctl config file)"`. Whether the file exists, and whether its
permissions are looser than owner-only, are notes on stderr where they cannot
end up inside the command substitution.

### touch

`dctl config touch` creates the file if it is missing, with the right
permissions and the no-secrets header from the first byte — which
`mkdir -p ~/.config/dctl && $EDITOR config.toml` does not give you, since that
takes whatever your umask says. Idempotent: an existing file is never rewritten,
because comments and formatting are things a human put there deliberately. The
`created` field describes *this run*, so a provisioning script can tell a fresh
install from a re-run.

### edit

`dctl config edit` opens the file in `$VISUAL`, then `$EDITOR`, then `vi`
(`notepad` on Windows); an empty variable is skipped rather than obeyed. The
file is created first if it is missing, so the editor opens a correctly
permissioned document with the header rather than an empty buffer.

The reason this is a command and not a shell alias is what happens *after* the
editor exits: the file is re-loaded, and a syntax error, a dangling vault base
or a credential pasted in from an rclone tutorial is reported now, while you
still remember what you changed. A configuration that no longer loads is a
failed `config edit`, not a successful one. With no terminal to inherit it fails
immediately rather than blocking a cron job on `vi` forever.

### providers

`dctl config providers` prints the remote types this build can store bytes in,
with a one-line description of each. Printing the list beats documenting it: a
build compiled without a provider must not advertise it. `vault` is deliberately
absent from the table and mentioned on stderr instead — it stores nothing itself
and cannot be the answer to "where should this go".

### redact

`dctl config redact` prints the whole configuration — remote, key, value —
with the same redaction rules `show` applies to one remote. This is the command
to run before pasting a configuration into a bug report or a chat message. It is
deliberately **not** a TOML dump: reproducing the file's syntax would invite
pasting the output back over a working config, and a configuration in which four
values have become `<redacted>` is worse than none. When nothing is withheld it
says so explicitly, because the reassurance is the point.

### The settings vocabulary

`key=value` arguments split on the **first** `=` only, so a value may contain
one — an endpoint with a query string, a base64 blob — with no quoting. The keys
each provider accepts are exactly the keys the file accepts:

| Type | Settings |
|------|----------|
| `local` | `path` (required), `verify`, `require_vault` |
| `b2` | `bucket` (required), `endpoint`, `chunk_size`, `verify`, `require_vault` |
| `s3` | `bucket` (required), `endpoint`, `region`, `chunk_size`, `verify`, `require_vault` |
| `r2` | `bucket` (required), `account`, `endpoint`, `chunk_size`, `verify`, `require_vault` |
| `vault` | `base` (required), `base_path`, `chunk_size`, `verify` |

`verify` is the per-remote verification strength — `checksum`, `sample` or
`strict` — spelled exactly as the `--verify` flag spells it, because the
cost/assurance trade-off belongs to the destination. `base` is a bare remote
**name**, never a `name:path` spec; the subdirectory inside it is `base_path`.
Anything else is refused with the offending key named.

`require_vault = true` marks a location as a **vault's object store**, and
`dctl init` sets it on the store remote it creates. It says one thing: no
*plain* remote may address this place. Point a second, ordinary remote at the
same bucket or directory and the file is refused — on save and on load, naming
both remotes and the location they share — because two readings of one directory
is how plaintext ends up sitting beside the ciphertext it was supposed to
become. The comparison is between *locations*, not names: a bucket and its
endpoint decide the place, while a region, a chunk size or a verification policy
do not.

It is a declaration rather than a lock. Nothing stops you clearing it with
`dctl config update`, and nothing should — it protects against the accident of
pointing a plain remote at a store, not against an administrator who has decided
otherwise. The invariant with no override is the one on the write path: a vault
remote always seals, and no flag turns that off.

Coming from rclone: a `vault` remote is DCTL's equivalent of rclone's `crypt`
remote, differing in that it is an object with identity rather than a stateless
transformation over a base — it carries a `vault_id`, key slots that can be added
and revoked, a root key that never changes, an encrypted index, and a
hash-chained audit log, so two vaults sharing a password are not interchangeable
the way two rclone `crypt` remotes are.

### Remote names

A name is 2–64 characters of ASCII letters, digits, `-`, `_` and `.`, starting
with a letter or a digit. Two characters minimum so a name can never be mistaken
for a Windows drive letter: `c:\data` must always be a path. A name that is
already a provider type (`b2`, `s3`, `r2`, `local`) is refused, because
`b2:bucket` would then mean two different things. `vault` is deliberately **not**
on that list: a vault is not a place bytes can land, so there is no `vault:`
shorthand for a remote of that name to collide with, and `dctl config create
vault vault base=b2prod` is the ordinary case rather than an error. Two remotes
differing only in case make the file refuse to load.

```
dctl config <subcommand> [args] [flags]
```

## Examples

Build the `PLAN.md` §14 worked example one command at a time: a B2 bucket, and a
vault remote that encrypts on the way through to it. Neither command asks a
question, so both work in a provisioning script:

```console
$ dctl config touch
✓ created /home/mx/.config/dctl/config.toml
/home/mx/.config/dctl/config.toml  true
$ dctl config create b2prod b2 bucket=media-archive chunk_size=8388608
✓ created remote 'b2prod'
b2prod  b2
$ dctl config create vault vault base=b2prod base_path=photos
✓ created remote 'vault'
vault  vault
$ dctl config list
b2prod  b2     -
vault   vault  b2prod
```

The base column is what makes the listing answer the question it is usually
being asked: which of these actually encrypts, and over what.

Change one setting without disturbing the others, then unset one. `update`
merges, so `region` and `endpoint` survive the first command untouched:

```console
$ dctl config show s3west
bucket    archive
endpoint  https://s3.eu-central-1.amazonaws.com
region    eu-central-1
type      s3
$ dctl config update s3west bucket=cold-archive
✓ updated remote 's3west'
s3west  bucket
$ dctl config update s3west region=
✓ updated remote 's3west'
s3west  region
$ dctl config show s3west
bucket    cold-archive
endpoint  https://s3.eu-central-1.amazonaws.com
type      s3
```

Removing a *required* setting is refused and the file is left byte-identical:

```console
$ dctl config update s3west bucket=
error: not a usable remote: missing field `bucket`
warning: Only the settings a provider defines are accepted, and 'type' is
required. See `dctl config show` on a working remote for the vocabulary.
$ echo $?
1
```

A local remote on Windows. The drive-letter path is just a value here — it is
the `path` setting of a `local` remote, stored and printed exactly as typed, and
the two-character minimum on remote names is what guarantees `C:\vaults\main`
can never be read as a remote called `C`:

```console
C:\> dctl config create winvault local path=C:\vaults\main
✓ created remote 'winvault'
winvault  local
C:\> dctl config show winvault
path  C:\vaults\main
type  local
C:\> dctl config file
C:\Users\mx\AppData\Roaming\dctl\config\config.toml
```

Prepare a configuration for a bug report. `redact` applies the rules to every
remote at once and tells you exactly what it withheld and why — keys and
reasons, never values:

```console
$ dctl config redact
warning: 1 value(s) were withheld from this report: s3west.endpoint (the URL
carries a password). They do not belong in /home/mx/.config/dctl/config.toml —
treat them as exposed
s3west  bucket    archive
s3west  endpoint  <redacted>
s3west  region    eu-central-1
s3west  type      s3
```

Machine-readable, one document per line, with the rule that fired:

```console
$ dctl config redact --format json-lines
{"remote":"s3west","key":"bucket","value":"archive","redacted":false}
{"remote":"s3west","key":"endpoint","value":"<redacted>","redacted":true,"reason":"credential_url"}
{"remote":"s3west","key":"region","value":"eu-central-1","redacted":false}
{"remote":"s3west","key":"type","value":"s3","redacted":false}
```

A credential offered as a setting is refused by name, and the value is not
echoed back into the error:

```console
$ dctl config create b2prod b2 bucket=media-archive app_key=K001secretvalue
error: not a usable remote: unknown field `app_key`, expected one of `bucket`,
`endpoint`, `chunk_size`, `verify`
warning: Only the settings a provider defines are accepted, and 'type' is
required. See `dctl config show` on a working remote for the vocabulary.
$ echo $?
1
```

A credential written into the file by hand stops every command that reads it,
rather than being quietly ignored:

```console
$ printf 'app_key = "K001x"\n' >> ~/.config/dctl/config.toml
$ dctl config list
error: configuration key 'remotes.b2prod.app_key' looks like a credential, and
credentials are never stored in the configuration file
warning: Delete that line. Provider credentials are read from the environment,
and the vault password is prompted for or produced by --password-command — DCTL
never stores either in the configuration file (PLAN.md §14). Treat the
credential as exposed and rotate it.
$ echo $?
7
```

Removing a remote something else depends on is refused before anything changes:

```console
$ dctl config delete b2prod
error: 'b2prod' is wrapped by vault
warning: Remove or repoint vault first — a vault remote whose base is gone
cannot be loaded at all.
$ echo $?
1
$ dctl config delete vault --force -v
objects stored under 'vault' are untouched; only the settings are gone
✓ removed remote 'vault'
vault  true
```

See what a change would do without making it. Every mutating subcommand
supports `--dry-run`, and the file comes out byte-identical:

```console
$ dctl config update b2prod bucket=films --dry-run
warning: [dry-run] would update remote: b2prod
b2prod  bucket
```

## Options

`dctl config` takes a subcommand; there is no default, because rclone's default
is an interactive menu and `PLAN.md` §14 rules those out. Subcommand names may
be abbreviated to any unambiguous prefix (`dctl config prov`).

```
  -h, --help   help for config
```

Subcommands:

```
  list       List the configured remotes
  show       Show one remote's settings. Never prints a secret
  create     Add a remote
  update     Change settings on an existing remote
  delete     Remove a remote from the configuration. Stored objects are untouched
  import     Write the remotes that address a vault which already exists
  verify     Prove every remote resolves, from the configuration alone
  file       Print the path of the configuration file
  touch      Create the configuration file if it does not exist
  edit       Open the configuration file in an editor, then check that it parses
  providers  List the remote types this build supports
  redact     Print the whole configuration, safe to paste into a bug report
  help       Print this message or the help of the given subcommand(s)
```

Arguments, by subcommand. None of them has a flag of its own — every option
they consult (`--config`, `--force`, `--dry-run`, `--format`, `--json`) is
global:

```
  dctl config show   <NAME>                      Remote to show
  dctl config create <NAME> <TYPE> [KEY=VALUE]...  Name, provider type, settings
  dctl config update <NAME> [KEY=VALUE]...       Remote to change, settings
  dctl config delete <NAME>                      Remote to remove
  dctl config import <LOCATION>                  Location holding the vault
```

`import` is the one subcommand with flags of its own: `--name NAME` for the
sealed view (default: the container's own name) and `--store-name NAME` for the
object view (default: `<NAME>-store`).

`list`, `verify`, `file`, `touch`, `edit`, `providers` and `redact` take no
arguments.
For `update`, an empty value (`region=`) removes the key; giving no settings at
all is a usage error rather than a silent success.

## Options inherited from parent commands

Every global flag is accepted; see [../GLOBAL_FLAGS.md](../GLOBAL_FLAGS.md). The
ones that matter here:

| Flag | Effect here |
|------|-------------|
| `--config <PATH>` (`DCTL_CONFIG`) | The file to read and write. Defaults to the platform location — `~/.config/dctl/config.toml` on Linux, `~/Library/Application Support/dctl/config.toml` on macOS, `%APPDATA%\dctl\config\config.toml` on Windows. A path that does not exist reads as an empty configuration. |
| `-n`, `--dry-run` | `create`, `update`, `delete`, `import`, `touch` and `edit` report what they would do and change nothing. `import` additionally contacts no store. The read-only subcommands are unaffected. |
| `--force` | `create` and `import`: replace an existing section instead of refusing. `delete`: skip the confirmation prompt. |
| `-i`, `--interactive` | `delete` prompts before removing; requires typing `yes`. Conflicts with `--force`. |
| `--format`, `--json` | Results go to stdout as an aligned table (default), one JSON document, or one JSON Lines record per row. Text output is borderless and header-free on purpose, so `dctl config show b2prod \| awk '{print $2}'` keeps working. |
| `-v` | Adds the stderr notes: the remote count, "no remotes configured", the `vault` note on `providers`, the "objects are untouched" note on `delete`, and the "nothing secret-shaped" reassurance on `redact`. |
| `--quiet` | Suppresses the success lines and warnings. Results still go to stdout; errors are still printed. |
| `--color`, `--ascii` | Affect only the stderr decoration; results are always plain. |

The password, transfer, filter and durability flags are accepted because they
are global, and do nothing here: no `config` subcommand unlocks a vault or moves
any data.

## Exit codes

See [../EXIT_CODES.md](../EXIT_CODES.md) for the full contract.

| Code | Name | When |
|------|------|------|
| 0 | `success` | The subcommand did what it said, including a `--dry-run` that changed nothing and a listing of an absent configuration. |
| 1 | `usage` | A malformed `key=value`; `update` with no settings; a name that is not a legal remote name (too short, too long, illegal character, does not start with a letter or digit, or collides with a provider type); an unknown provider type; settings that would not be a usable remote (missing required key, unknown key, credential offered as a setting); `create` or `import` on a name that already exists without `--force`; a base location that names no place, or one naming a subdirectory of its container; `delete` on a remote that a vault remote still wraps; `edit` with no terminal for an editor; `--interactive` with no terminal to prompt on. In every case the file is left byte-identical. |
| 7 | `fatal_error` | **No remote of that name is configured** (`show`, `update`, `delete`) — classified by the configuration layer so every command reports it identically; the file is not valid TOML or does not match the expected shape; the file contains a credential-shaped key; a vault remote names a base that does not exist, forms a cycle, or wraps too deep; two remotes differ only in case; a plain remote addresses a location another remote declares is a vault's object store; the file exists but cannot be read or written; the editor could not be started or exited non-zero; `import` was pointed at a location holding no vault envelope; `verify` found at least one problem. |
| 25 | `cancelled` | A `delete` confirmation was declined, or the run was interrupted with Ctrl-C. |

Exit code 20 (`checksum_mismatch`) and the other durability codes are not
reachable from `dctl config`: it writes one small local file and moves no data.

## See also

* [dctl init](dctl_init.md) — create a vault and register both of its remotes in one command.
* [dctl about](dctl_about.md) — check usage, quota and capabilities of a configured remote.
* [dctl ls](dctl_ls.md) — list what a remote holds once it is configured and initialised.
* [dctl version](dctl_version.md) — the other command that needs no vault and no password.
