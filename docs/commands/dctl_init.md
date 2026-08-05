# dctl init

Create a vault and register both of its remotes.

## Synopsis

`dctl init` does two things in one command, because neither is useful alone.

**It creates a vault.** A 256-bit root key from the system CSPRNG, wrapped under
your password with Argon2id, written to the store as a single *envelope* object
(`system/envelope.bin`). It then creates the local encrypted index database that
every later command reads and writes.

**It registers the two remotes that address that vault.**

```console
$ dctl init --name archive --base local:/srv/vault
created:
  [remotes.archive-store]  type = local  path = /srv/vault  require_vault = true
  [remotes.archive]        type = vault  base = archive-store
```

* `archive:` is the **sealed view**. Everything written through it is encrypted.
  No flag turns that off.
* `archive-store:` is the **object view** — the opaque ciphertext objects as they
  sit on the provider.

**Why the base gets a name.** Because it has one, an offsite replication job can
be addressed at `archive-store:` and run with **no vault password at all**. A
backup operator can replicate ciphertext to a second provider and satisfy 3-2-1
without ever holding decryption capability: separation of duties becomes a
structural property of the configuration rather than a rule somebody is trusted
to follow. `PLAN.md` §13.3 requires replicating a vault's object tree
provider-to-provider with no re-encryption, and that is unimplementable if the
base has no name to type.

**Why `--name` is required.** DCTL will not invent one. A generated name is a
name nobody chose appearing in every future command, in every script written
against the vault, and in every runbook — and unlike a bucket it cannot be
changed later without editing all of them. So the command asks, and the object
store is named after your choice (`<NAME>-store`) unless `--store-name` says
otherwise.

**Everything else hangs off the envelope.** The root key derives the index key,
the name-hash and name-value keys, and the per-object keying material, so losing
the envelope — or replacing it with a new one — makes every object already
stored permanently unreadable. The bytes remain in the bucket and the provider
will keep billing for them, but nothing can decrypt them again.

## It prints a recovery phrase. Write it down.

The envelope gets **two** key slots, not one (`docs/FORMAT.md` §2.1): your
password, and a freshly generated 24-word BIP-39 **recovery phrase**. Both wrap
the same root key, independently, so either one opens the vault on its own. A
forgotten password is therefore survivable — which `PLAN.md` §13.2 calls the #1
risk of a twenty-year tool.

The phrase is printed **once**, on stderr, immediately after the vault is
created:

```
========================================================================
  RECOVERY PHRASE - WRITE THESE WORDS DOWN ON PAPER, NOW
  Vault: archive    Words: 24
========================================================================

    1 shiver     2 quantum    3 raw        4 toss
    5 copy       6 secret     7 theme      8 alone
    ...
   21 bulk      22 original  23 response  24 word

  Shown once, here. DCTL stores it nowhere it can read, so nothing can
  print it again - not this machine, not the provider, not a support
  request.
  ...
========================================================================
```

Four things about that output are deliberate:

* **It is on stderr, never stdout.** stdout is the result stream, so
  `dctl init --json | tee provisioning.log` is an ordinary thing to run — and a
  phrase in a log file is a vault that is permanently compromised, because
  unlike a password it cannot be rotated away. `--json` reports only
  `"recovery_phrase_issued": true`; the words are not in the document.
* **`--quiet` does not suppress it.** `--quiet` asks for less noise, not for
  something irreversible to happen silently. A vault whose second key was
  generated and never shown has no second key at all.
* **It cannot be shown again.** Not by re-running anything. The phrase is
  generated, wrapped into the mnemonic slot, and dropped: DCTL keeps no copy,
  which is the property that makes it worth having — a phrase the tool could
  reprint is a phrase an attacker holding the envelope could reprint.
* **Paper, not the machine the vault is on.** Anyone holding the words can read
  every file in the vault.

Once it is on paper, prove it works:

```
dctl vault recover archive: --keep-password
```

That checks the phrase opens the vault and changes nothing (`PLAN.md` §13.6 — a
backup you have never restored is not a backup). To *use* it later, see
[dctl vault](dctl_vault.md), or pass `--recovery-phrase` to any command.

**Changing your password never invalidates the phrase.** Only the password slot
is rewritten; the paper stays current forever.

You cannot choose the phrase. `dctl init --recovery-phrase …` is refused rather
than ignored: the words are 256 bits of CSPRNG output, and a phrase a person
picked would be the weakest way into the vault.

That asymmetry (seconds to run, impossible to undo) shapes the whole command:

* **The password is typed twice** when it comes from a terminal. A mistyped
  password wraps the root key under a secret nobody knows, so the two readings
  must match or the run fails with nothing created. A password that arrives from
  `--password`, `--password-command` or `--password-file` is *not* confirmed:
  reading the same source twice is not a check, so the confirmation is skipped
  rather than faked.
* **A password shorter than 8 characters is refused**, at creation only.
  Unlocking never re-applies today's policy to an older vault.
* **An existing local index is a hard refusal** without `--force`.
* **A store that already holds a vault is a hard refusal** without `--force`.
* **The run goes through the destructive-confirmation gate**, so `--interactive`
  asks before anything happens and `--dry-run` declines and reports.

**The store is probed before anything is written.** Earlier builds could only
*warn* that they had not checked whether a vault was already there. They can now
check: `init` fetches the first 23 bytes of `system/envelope.bin` — the frozen
`DKE1` magic, version and slot count from `docs/FORMAT.md` §2 — and refuses if an
envelope is there:

```
error: refusing to initialise: 'b2:media-archive' already holds a vault with 1 key slot(s)
warning: Re-initialising generates a new root key and makes everything already
stored there permanently unreadable. To address the vault that is already there,
run `dctl config import b2:media-archive --name archive`. Pass --force only if
you are certain the stored objects are worthless.
```

The read is a ranged GET, so it costs one small request rather than a download,
and it needs no password: nothing in the header can decrypt anything. An
envelope written by a *newer* DCTL — one whose format version this build cannot
read — counts as a vault too, because "there is a vault here I am too old to
address" and "there is nothing here" lead to opposite actions. A store that
cannot be read at all (bad credentials, wrong endpoint, a timeout) is an error,
never a quiet "no vault here": a probe that reported absence because it could
not look would send `init` straight into overwriting what it failed to see.

**The verified-write contract applies to the envelope.** The envelope is written
through the same path as any other object: DCTL computes the BLAKE3 hash of the
bytes it intends to store, hands both to the backend, and the backend refuses to
publish anything whose stored bytes do not hash to that value. On a local remote
that is temp file → `fsync` → read the bytes back → compare → atomic rename, and
the directory is `fsync`ed after the rename; on B2 and S3 the provider's own
checksum is compared against ours before the write counts. A mismatch aborts
with exit **20** (`checksum_mismatch`), leaves no partial object, and never
creates the index.

**What is committed, and in what order.** Everything that can fail locally fails
before anything is created, and the two irreversible steps are as late as
possible:

1. reject `--key-file`; resolve the names, the base location and the index path;
2. load the configuration and **rehearse the whole result against a copy**, so a
   name already taken — or a plain remote already pointing at the store's
   location — is reported now, while nothing exists;
3. refuse an existing index;
4. stop here for `--dry-run`, which therefore contacts no store and asks for no
   password;
5. build the backend and probe for an existing envelope;
6. run the destructive gate;
7. read the password;
8. create the index's parent directory and **write the envelope** —
   irreversible;
9. **save the configuration naming both remotes**, in one atomic write.

Step 9 can fail after step 8 has succeeded. That leaves a real vault on a real
store with no addressing — recoverable, and reported as exactly that:

```
error: the vault was created on 'b2:media-archive', but the configuration naming
it could not be written: …
warning: Your data is not at risk: the vault's envelope is on the store, and only
the addressing is missing. Do NOT re-run `dctl init` — with --force it would
replace the vault you just created. Fix the configuration file, then run:

    dctl config import b2:media-archive --name archive
```

The result carries **two** booleans rather than one, for exactly this reason:
`created` is true only after the envelope write returns, and `registered` only
after the configuration is saved. A script that needs "is this vault usable?"
must read both.

**Both configuration entries are written by one save, or neither is.** A
configuration naming a vault whose base does not exist is worse than no
configuration: it refuses to load at all, so a half-write would take the vault's
addressing with it and leave a file to repair by hand before any command runs
again. The two entries are assembled in memory and committed by a single
staged-and-renamed write.

**The store is marked `require_vault`.** The `<NAME>-store` entry carries
`require_vault = true`, which says: no *plain* remote may address this location.
Point a second, ordinary remote at the same bucket or directory and the
configuration is refused — naming both remotes and the place they share —
because two readings of one directory is how plaintext ends up sitting beside
the ciphertext it was supposed to become. See
[dctl config](dctl_config.md#the-settings-vocabulary).

**Which locations work today.** `--base` names a *place*, parsed by the same
rules every other command uses: a bare path, a Windows drive path
(`C:\vaults\main`) and a UNC path (`\\server\share\vault`) are all local on every
platform, and `local:` is the explicit escape hatch for a directory whose own
name would otherwise parse as a remote. Beyond that, the provider shorthands
`b2:`, `s3:` and `r2:` name a bucket, and `sftp:HOST/PATH` names a directory on
an SSH host (see below). Provider credentials come from the
environment (`DCTL_B2_KEY_ID`, `DCTL_B2_APP_KEY`, and the S3/R2 equivalents),
never from the configuration file.

`--base` deliberately does **not** accept the name of a remote that already
exists. `init` promises to register *both* views of a vault, and a base that
resolved to an existing section would make that promise conditional — sometimes
two remotes appear, sometimes one, depending on what the file happened to
contain, and a reader of the command could not tell which. To wrap a remote that
is already configured, use `dctl config create NAME vault base=EXISTING`.

**An sftp base says where on the server it is.** `--base sftp:HOST/PATH`
splits at the first `/`, and what follows reads exactly as `scp` and rclone
read it: **one** slash is the SSH login directory, **two** is the filesystem
root. So `--base sftp:lsx-001/dctl-store` is `~/dctl-store`,
`--base sftp:lsx-001//srv/dctl-store` is the absolute `/srv/dctl-store` —
exactly as `dctl config create NAME sftp host=lsx-001 base=/srv/dctl-store`
writes it — and `--base sftp:lsx-001/~/dctl-store` spells the login-relative
form explicitly. A single slash used to mean the absolute path, which put
1.6 GiB of a benchmark's ciphertext on a server's OS disk while every
convention said it would land under the home directory. Every
base is stored in one of those two self-describing spellings, so
`dctl config show` always says which one you have.

This used to be two different things depending on which command wrote it:
`base=/srv/dctl-store` was absolute and `--base sftp:h/srv/dctl-store` was
`$HOME/srv/dctl-store`, with `init` reporting the vault on the path you typed
while the envelope went somewhere else. A bare relative base — `base=dctl-store`
— is the spelling that meant both, and is now refused by both commands with the
one-character fix in the message. An existing configuration carrying one fails
loudly rather than being silently reinterpreted.

**A base naming a subdirectory is refused.** `--base s3:archive/vaults/a` fails
with exit 1. The engine writes a vault's envelope to a fixed key at the root of
its store and honours no prefix, so accepting the spec would create the vault at
the bucket root while the configuration said it was in a subdirectory, and every
later command would look where the file pointed and find nothing. Address the
container itself, or give the vault a container of its own.

**`--key-file` is not implemented, and the gap is one crate down.** `PLAN.md`
§8's second factor — "know" plus "have" — has no way into the engine in this
build: `dctl_core::Vault::init` and `::unlock` take a password and no factor
parameter, so no arrangement of CLI code supplies one. Passing `--key-file`
therefore fails immediately with exit **7** rather than quietly creating a
one-factor vault for someone who asked for two, which would be exactly the
"reported as done when it did not happen" failure `PLAN.md` §6 exists to
prevent:

```
error: dctl init: the --key-file second factor (missing in dctl-core:
Vault::init and ::unlock take a password and no factor parameter) is not
implemented in this build
warning: This build derives the key-encryption key from the password alone, so
the file named by --key-file is never read and the second factor cannot be
applied. dctl_core::Vault::init and ::unlock take no factor parameter; PLAN.md
§8 (the auth/key model of phase 0, §11) is where the missing half is specified.
No command was run and nothing was read or written.
```

Note what the message does *not* say. It used to read "dctl init is not
implemented in this build", which is false — `init` creates vaults perfectly
well, and the only thing missing is the factor. Two-factor unlock arrives with
the `PLAN.md` §8 envelope-slot work.

**The index.** Each vault needs its own index database. It defaults to
`vault.redb` inside `~/.dctl/index/`.
Windows) and is chosen with `--index` or `DCTL_INDEX`. Initialising a second
vault without giving it a distinct `--index` hits the refusal below, which is
the point of the refusal:

```
error: refusing to initialise: an index already exists at /srv/dctl/vault.redb
warning: That index belongs to a vault. Re-initialising generates a new root key
and makes everything already stored unreadable. Point --index somewhere else, or
pass --force if you are certain.
```

`--force` overrides that refusal, and it is worth understanding exactly what it
does: the existing index file is **not** deleted. It is opened in place and the
new vault's records are written into it under keys derived from the *new* root.
Rows written under the previous root stay in the file and cannot be read or
listed again. If you want a clean start, delete or move the index file yourself.

**The old positional form is an error, and says what to run instead.**
`dctl init local:/srv/vault` no longer names a vault. It is still accepted by
the parser so the failure can be a message rather than "unexpected argument",
and the message carries the exact replacement command built from what you typed:

```
error: `dctl init local:/srv/vault` no longer names a vault
warning: A vault now has two remotes: the sealed view you write through, and the
object store that holds its ciphertext. Both get names, and the name is yours to
choose. Run:

    dctl init --name NAME --base local:/srv/vault

replacing NAME with what you want to type on every later command; the store is
then called NAME-store.
```

`NAME` stays a placeholder on purpose. A name guessed here would appear in every
script written against the vault, and nobody would have chosen it.

**No password is stored anywhere.** The password reaches the key-derivation
function and nothing else; it is wrapped in a redacting container the moment it
exists, so it cannot reach a log line even through a stray debug format. What
`init` reports is the *mechanism* that supplied it (`--password`,
`--password-command`, `--password-file`, `terminal prompt`), never the value.
`--password-command` runs through a shell, so pipelines such as
`pass show vault/prod | head -1` work; only the first line of its output is
used, and a trailing `\r` or `\n` is stripped before the value reaches Argon2id.

```
dctl init --name NAME --base BASE [--store-name NAME] [flags]
```

## Examples

Create a vault in a directory on this machine, with an explicit index. The
result names the *mechanism* that supplied the password; the value itself is
never printed, logged or stored:

```console
$ dctl init --name photos --base local:/srv/vaults/photos --index /srv/dctl/photos.redb
Vault password:
Confirm vault password:
vault_remote     photos
store_remote     photos-store
base             local:/srv/vaults/photos
index            /srv/dctl/photos.redb
created          true
registered       true
password_source  terminal prompt
✓ created vault 'photos' on 'local:/srv/vaults/photos'; its objects are addressable as 'photos-store'
$ find /srv/vaults/photos
/srv/vaults/photos
/srv/vaults/photos/system
/srv/vaults/photos/system/envelope.bin
$ dctl config list
Name          Type   base
photos        vault  photos-store
photos-store  local  -
```

Create a vault on a Backblaze B2 bucket from a provisioning script. Nothing here
prompts: the credentials come from the environment, the password comes from a
secret manager, and `--no-ask-password` guarantees the job fails instead of
blocking on a prompt nobody will answer:

```console
$ export DCTL_B2_KEY_ID=0012ab... DCTL_B2_APP_KEY=K001...
$ dctl init --name media --base b2:media-archive \
    --index /var/lib/dctl/media.redb \
    --password-command 'pass show dctl/media-archive' \
    --no-ask-password --json
{
  "vault_remote": "media",
  "store_remote": "media-store",
  "base": "b2:media-archive",
  "index": "/var/lib/dctl/media.redb",
  "created": true,
  "registered": true,
  "password_source": "command",
  "dry_run": false
}
```

The record goes to stdout and every note to stderr, so
`dctl init … --json | jq -r .store_remote` is a working pipeline. `created` and
`registered` are the fields to branch on, and a usable vault needs both.

Replicate the ciphertext offsite with no vault password anywhere. This is what
naming the store buys: the operator running it can copy every object and cannot
read any of them.

```console
$ dctl config create media-offsite s3 bucket=media-dr endpoint=https://s3.eu-central-1.wasabisys.com
✓ created remote 'media-offsite'
$ dctl sync media-store: media-offsite:
```

Preview first. A dry run resolves the names, rehearses the configuration change
and prints the plan without asking for a password, contacting the store or
creating anything:

```console
$ dctl init --name archive --base s3:archive --index /var/lib/dctl/archive.redb --dry-run
warning: [dry-run] would create a vault on: s3:archive
warning: [dry-run] would register remotes: archive, archive-store
vault_remote  archive
store_remote  archive-store
base          s3:archive
index         /var/lib/dctl/archive.redb
created       false
registered    false
```

A Windows drive path is a local location on a platform that has drives, which is
where rclone treats it as one. `C:` is a drive letter there and wins over any
remote of the same name — and `dctl config create` refuses to mint such a name on
such a machine — so the whole argument is handed to the filesystem as typed:

```console
C:\> dctl init --name main --base C:\vaults\main --index C:\vaults\main.redb --dry-run
warning: [dry-run] would create a vault on: C:\vaults\main
warning: [dry-run] would register remotes: main, main-store
```

The same applies to a UNC path (`\\fileserver\backups\vault`) and to any bare
path. Use `local:` when a directory name would otherwise be read as a remote —
`dctl init --name archive --base local:D:\archive:2024`.

Be asked before anything happens. `--interactive` requires the word `yes`;
anything else is a decline and exits 25 with nothing created:

```console
$ dctl init --name media --base b2:media-archive --interactive
confirm: create a vault on 'b2:media-archive'? Type 'yes' to confirm: no
error: initialisation of 'b2:media-archive' was declined
warning: Nothing was created.
$ echo $?
25
```

Pointing a second `init` at a store that already holds a vault is refused before
the password is read, and names the command that addresses the existing one:

```console
$ dctl init --name backup --base local:/srv/vaults/photos --index /srv/dctl/backup.redb
error: refusing to initialise: 'local:/srv/vaults/photos' already holds a vault with 1 key slot(s)
warning: Re-initialising generates a new root key and makes everything already
stored there permanently unreadable. To address the vault that is already there,
run `dctl config import local:/srv/vaults/photos --name backup`. Pass --force
only if you are certain the stored objects are worthless.
$ echo $?
7
```

A name already in use is caught by the rehearsal, before anything is created:

```console
$ dctl init --name photos --base b2:other-bucket
error: remote 'photos' already exists
warning: Pick another name, or pass --force to replace 'photos'. `dctl config
list` shows what is configured.
$ echo $?
1
```

## Options

```
      --name <NAME>        Name for the vault: the remote you write through
      --base <BASE>        Location for the ciphertext objects
      --store-name <NAME>  Name for the object store remote [default: <NAME>-store]
  -h, --help               help for init
```

`--name` is required. `--base` falls back to the global `--remote`
(`DCTL_REMOTE`), so a headless deployment that already exports a default
location keeps working with only the name added.

A hidden positional `[REMOTE]` still exists so that the pre-`--name` form can be
answered with a useful message; it is always an error. It no longer shadows the
global `--remote` flag, so `dctl init --name archive --remote b2:media` works.

## Options inherited from parent commands

Every global flag is accepted; see [../GLOBAL_FLAGS.md](../GLOBAL_FLAGS.md). The
ones that matter here:

| Flag | Effect here |
|------|-------------|
| `--config <PATH>` (`DCTL_CONFIG`) | The configuration file both remotes are written to. Defaults to the platform location. |
| `--index <PATH>` (`DCTL_INDEX`) | Where the encrypted index is created. Defaults to `vault.redb` in the platform data directory. One vault per index file. |
| `--remote <SPEC>` (`DCTL_REMOTE`) | The base location when `--base` is absent. |
| `--password <PASSWORD>` (`DCTL_PASSWORD`) | Highest-precedence source. Not confirmed. An argument is visible to every process on the machine; prefer the environment or a command. |
| `--password-command <COMMAND>` (`DCTL_PASSWORD_COMMAND`) | Run through a shell; first line of stdout is the password. Not confirmed. |
| `--password-file <PATH>` | First line of the file is the password. Not confirmed. Trailing `\r`/`\n` stripped. |
| `--no-ask-password` | Never prompt: fail instead. For unattended runs. |
| `--key-file <PATH>` | **Refused.** Fails with exit 7 rather than creating a weaker vault than asked for. |
| `--force` | Skips the confirmation prompt, and overrides three refusals: an existing index, an existing envelope on the store, and a name already taken in the configuration. |
| `-i`, `--interactive` | Prompts before creating; requires typing `yes`. Conflicts with `--force`. |
| `-n`, `--dry-run` | Resolves, rehearses the configuration change and reports; asks for no password, contacts no store, creates nothing. |
| `--format`, `--json` | Render the result as an aligned table, one JSON document, or one JSON Lines record. The result goes to stdout; every note and warning goes to stderr. |
| `-v` | Adds the `password read from …` note and the engine's `vault created` log record. |
| `--quiet` | Suppresses the success line and the warnings. Errors are still printed. |

The transfer, filter and durability flags (`--transfers`, `--include`,
`--verify`, …) are accepted because they are global, and do nothing here: `init`
writes one small object, and the checksum verification of that write is
unconditional rather than something `--verify` selects.

## Exit codes

See [../EXIT_CODES.md](../EXIT_CODES.md) for the full contract.

| Code | Name | When |
|------|------|------|
| 0 | `success` | The envelope was written and verified, the index was created, and both remotes were registered. Also returned by `--dry-run`, which creates nothing. |
| 1 | `usage` | The old positional form; no `--name`; no `--base` and no `--remote`; a name that is not a legal remote name, is a provider type, or is already taken; a base that addresses nothing, names no container, names a configured remote, or names a subdirectory; no password available and `--no-ask-password` set; no terminal to prompt on; the two typed passwords differed; a password shorter than 8 characters; an empty `--password-file`. Nothing was created in any of these cases. |
| 4 | `file_not_found` | `--password-file` names a file that does not exist. |
| 5 | `temporary_error` | The provider or network failed and the retry budget was exhausted. |
| 7 | `fatal_error` | `--key-file` was passed; an index already exists and `--force` was not given; **the store already holds a vault** and `--force` was not given; a plain remote already addresses the store's location; `--password-command` could not be run, exited non-zero, or produced nothing; a required credential environment variable is unset, empty, or not UTF-8; permission denied creating the index directory; the configuration could not be written *after* the vault was created (see the message — the data is safe, and `dctl config import` finishes the job). |
| 20 | `checksum_mismatch` | The envelope did not survive the round trip to the destination. Nothing was published and no index was created. |
| 21 | `integrity_failure` | Key derivation or envelope sealing failed inside the engine. |
| 23 | `index_error` | The encrypted index could not be created or opened at the resolved path. The envelope has already been written at this point. |
| 25 | `cancelled` | An `--interactive` confirmation was declined, or the run was interrupted with Ctrl-C. |
| 2 | `uncategorised` | Any other filesystem failure while preparing the index directory. |

## See also

* [dctl config](dctl_config.md) — inspect and change the two remotes `init` wrote; `config import` re-creates them if the configuration is lost; `config verify` proves they resolve.
* [dctl about](dctl_about.md) — check a remote's usage, quota and capabilities.
* [dctl backup](dctl_backup.md) — put a local tree into the vault once it exists.
* [dctl sync](dctl_sync.md) — replicate the object store offsite, with no vault password.
* [dctl verify](dctl_verify.md) — confirm stored objects still decrypt and match their recorded hashes.
* [dctl scrub](dctl_scrub.md) — re-read and verify the whole dataset.
