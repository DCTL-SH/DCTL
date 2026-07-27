# dctl vault

Operate on a vault's key material: recover one with its recovery phrase.

## Synopsis

Everything here acts on the **envelope** — the small object holding the wrapped
root key that every byte in the vault depends on (`docs/FORMAT.md` §2). That is
why it is its own command group rather than a flag on `init` or a mode of
`config`: losing an object loses a file, and losing the envelope loses the
dataset.

```
dctl vault recover REMOTE: [--keep-password]
```

## Every vault has two keys

`dctl init` writes **two** key slots, not one:

* a **password** slot, and
* a **recovery phrase** slot — 24 BIP-39 words, printed once when the vault is
  created and stored nowhere DCTL can read.

Both wrap the same root key, independently. Either opens the vault on its own.
That is what makes a forgotten password survivable, and it is what `PLAN.md`
§13.2 calls the #1 risk of a twenty-year tool.

The phrase is not only for this command. `--recovery-phrase` is a **global
option**, so any command takes one:

```
dctl --recovery-phrase "$(cat phrase.txt)" ls archive:
dctl --recovery-phrase-file ~/phrase.txt restore archive: ./restored
```

Use `--recovery-phrase-file` or `DCTL_RECOVERY_PHRASE` in preference to typing
the words as an argument: a command line is visible to every other process on
the machine, and unlike a password, a leaked phrase cannot be rotated away by
changing the password.

## dctl vault recover

Open a vault with its recovery phrase, then set a new password.

```
dctl vault recover archive:
```

Two steps, because doing only the first leaves you no better off. "I lost my
password" does not mean "read my files once through an awkward flag"; it means
"give me my vault back". So this unlocks with the phrase and then replaces the
password slot, and the vault is ordinary again afterwards.

Both secrets can come from any of the usual sources. The phrase is read from
`--recovery-phrase`, `--recovery-phrase-file`, `DCTL_RECOVERY_PHRASE`, or an
interactive prompt; the **new** password from `--password`,
`--password-command`, `--password-file`, or a prompt that asks twice.

```
$ dctl vault recover archive:
Recovery phrase (24 words):
OK the recovery phrase opened 'archive:'
Vault password:
Confirm vault password:
OK 'archive:' now has a new password; the recovery phrase is unchanged and still opens this vault; keep the paper
remote            archive:
unlocked          true
password_changed  true
```

The two booleans are the result, on stdout; the `OK` lines are on stderr. They
are separate because they can differ — see [Exit codes](#exit-codes).

### The phrase survives a password change

Deliberately, and it is worth being explicit because the opposite assumption
destroys a backup: **changing the password does not change or invalidate the
recovery phrase.** Only the password slot is rewritten (`FORMAT.md` §2.2); every
other slot is carried through byte-identical. A sheet of paper written the day
the vault was created is still current after any number of password changes.

The reverse also holds: recovering does not re-issue the phrase. Nothing in DCTL
can print those words again — not this command, not a support request — because
nothing anywhere stores them.

### --keep-password: the restore drill

```
dctl vault recover archive: --keep-password
```

Proves the phrase opens the vault and changes nothing. `PLAN.md` §13.6: a backup
you have never restored is not a backup, and the same is true of a recovery
phrase you have never tried. Checking it has to be a read-only act, or it will
not be done yearly.

Run it after transcribing the phrase to paper, before you need it.

### A mistyped phrase says so

BIP-39 carries a checksum, so a wrong or transposed word is caught before any
unlock is attempted:

```
$ dctl vault recover archive:
Recovery phrase (24 words):
error: an interactive prompt is not a valid recovery phrase: kdf: invalid
mnemonic: the mnemonic has an invalid checksum
warning: Check the words against the paper: BIP-39 has a checksum, so this
refusal means a word is misspelled, missing, or in the wrong place — not that
the phrase belongs to another vault. Nothing was read or written.
```

That distinction matters: *"you mistyped a word"* and *"this phrase is for a
different vault"* have opposite remedies, and an unlock attempt cannot tell them
apart — both end as "no slot opened".

Line breaks and extra spaces are ignored, so a phrase transcribed from paper
across four lines into a file works unchanged.

## What this command does not do

* **It does not re-issue the phrase.** A recovery is performed by somebody whose
  access is already precarious; a command that rewrote key material it was not
  asked about could *cost* a way in.
* **It does not touch any other slot.** Only `slot_type = 1` is replaced.
* **It cannot restore a vault you have neither secret for.** If the password and
  the phrase are both gone, the data is gone — the root key exists only inside
  the envelope, wrapped under those two secrets. This is why the phrase is
  printed on paper at creation and why the drill above exists.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | The phrase opened the vault (and the password was replaced, unless `--keep-password`). |
| 1 | A local path or a path inside a vault was named instead of a whole remote; or the run is unattended (`--no-ask-password`) with no password source and no `--keep-password`, which is refused **before** the phrase is asked for. A new password that is rejected once typed — too short, or the two readings disagreeing — also exits 1, after `OK the recovery phrase opened …`: the unlock genuinely happened and only the password write did not. |
| 7 | `--key-file` was given, or the remote could not be resolved. |
| 22 | No phrase was available, the phrase was malformed, or it opened no slot. |

See [docs/EXIT_CODES.md](../EXIT_CODES.md) for the full contract.

## See also

* [dctl init](dctl_init.md) — creates the vault and prints the phrase, once.
* [dctl index rebuild](dctl_index.md) — the other half of recovering a machine:
  the phrase and the object store are enough to make every path listable again.
* `docs/FORMAT.md` §2 — the envelope, its slot list, and the exact bytes a
  clean-room decoder would need to unwrap the root key without DCTL.
