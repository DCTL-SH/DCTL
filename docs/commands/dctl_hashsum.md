# dctl hashsum

Print content hashes for objects.

## Synopsis

`dctl hashsum` prints the content hashes of stored objects in the coreutils
line format. It exists because of `PLAN.md` §13.1: the data has to outlive the
tool. A vault whose checksums can only be read by DCTL is a vault that depends
on DCTL still existing in 2045; a vault whose checksums come out as

```
af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262  photos/2024/a.jpg
```

can be handed to `sha256sum -c`, to a tape catalogue, or to whatever replaces
them, by someone who has never heard of this program. That is the whole design
constraint.

**Text output is therefore not a table.** It is the coreutils format byte for
byte on stdout with nothing else mixed in: `<hash>`, then exactly **two
spaces**, then the path. Not one space, not a tab, not an aligned column — GNU's
parser reads the character immediately after the first space as the mode flag,
so anything else produces a file that looks right and cannot be checked. Every
word of commentary goes to stderr, so `dctl hashsum sha256 vault: > SUMS`
produces a checkable file and not a mixture. `--binary` replaces the second
space with `*`, matching `sha256sum --binary`; text mode is the default because
that is what `sha256sum` writes unless asked otherwise, and matching the common
spelling keeps a diff of two SUMS files readable.

Three algorithms are accepted, and the choice has a price attached:

| `ALGO` | hex width | cost |
|--------|----------:|------|
| `blake3` | 64 | the vault's own plaintext hash, recorded for every object at write time — answered from the index, **no egress** |
| `sha1` | 40 | not recorded; every object must be read back and decrypted |
| `sha256` | 64 | not recorded; every object must be read back and decrypted |

BLAKE3 is what DCTL actually stores (`PLAN.md` §13.3's integrity manifest);
SHA-1 and SHA-256 exist for interoperability with systems that predate it, since
a 20-year tool has to be able to hand its checksums to software that does not
know BLAKE3. When an unrecorded algorithm is requested, `hashsum` warns before
it starts, because the surprise otherwise arrives as an egress bill. An unknown
algorithm is a usage error rather than a fallback to a different one: silently
substituting would produce a checksum file that fails to check for no visible
reason.

**An object that fails authentication while being hashed ends the process with
exit code 21** and a message containing the literal phrase *the data was NOT
served*. Printing a hash of bytes that failed to authenticate would be the worst
possible outcome this command has: it would certify corruption, and the
certificate would outlive the incident.

The target must be a remote. Hashes come from the vault's integrity manifest; a
local path has none, and quietly hashing local files instead would answer a
different question from the one that was asked (use `sha256sum` for that).
Following rclone's rule, `\\server\share` is treated as **local** on every
platform and `C:\data` and `d:/data` are local where drives exist; off Windows
they name the remotes `C` and `d`. Paths inside a vault are
canonicalised (`/`-separated, NFC, no `.` or `..`); a `..` component is rejected.

Paths may contain spaces, and they survive the round trip: only the *first*
double space separates the two fields, exactly as coreutils defines it. Lines
never contain a newline of their own, so a path cannot smuggle an extra record
into the stream.

`--json` and `--format json-lines` exist for consumers that would rather not
parse a checksum file. Both carry the algorithm on **every** record, because a
64-character hex string alone is ambiguous between BLAKE3 and SHA-256, and a
JSON Lines consumer sees one record at a time with no document-level context to
fall back on. `--json` emits an array of `{algorithm, hash, path}`;
`--format json-lines` emits one such object per line.

`hashsum` mutates nothing, so `--dry-run` has nothing to suppress.

### The digest is of the plaintext, always

This is the single most important sentence about the command. A sealed object is
a nonce, a header, a chain of AEAD chunks and a footer; hashing *that* would
produce a well-formed digest which matches nothing you have, and which changes
every time the object is re-sealed even though the file has not moved a byte.

What you are about to do with the answer is compare it against `sha256sum` on
your own disk, so the digest is of the **file** — the same bytes `dctl cat`
would write. That is what makes the round trip below work at all.

### The shortcut, and what it does not prove

`blake3` is the vault's own plaintext hash, recorded for every object at write
time, so it is answered from the index with **no egress**. `sha1` and `sha256`
are not recorded and are produced by reading and decrypting every object; the
command warns before it starts, because the surprise otherwise arrives as a bill.

A `blake3` run answered from the index reports the hash the file had when it was
written and never touches the provider, so it cannot notice that the object has
since rotted. That is what `dctl verify` and `dctl scrub` are for, and this
command does not pretend otherwise.

An object that fails authentication while being hashed ends the run with exit
**21** and **nothing on stdout** — no line for it, and no line after it. A
checksum file is a certificate, and a line computed from bytes that failed to
authenticate would certify the corruption as though it were the file.

```
dctl hashsum ALGO REMOTE:PATH [flags]
```

## Examples

The round trip that is the whole point of the command: hash a vault, then check
the file against the original tree with coreutils, which has never heard of DCTL.

```console
$ dctl hashsum sha256 archive: > SUMS
warning: sha256 is not recorded in the index, so every object under 'archive:' must be read back and decrypted to compute it
$ cat SUMS
ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  a.jpg
b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9  notes.txt
d98b239423d217ef98c1572e009f04878002197c96cd9e8c4468fe684e7b73c1  photos/2024/c.jpg
0e91f050fec39c6abc0e4e18fe01dc1c6f42ebae81e2b2b551d61371fad2ee1c  photos/b.jpg
5a9cb6b54ea56d52a69891af8c21afb73d3841611bbabb5d7c61312d81e6e041  photos/tmp/scratch.jpg
2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b  private/secret.txt
f8b27fb5d0fb00293486be039ec6021c0361f5ea088d1ae54d6f64697a413174  tmp/scratch.txt
$ cd tree && sha256sum -c ../SUMS
a.jpg: OK
notes.txt: OK
photos/2024/c.jpg: OK
photos/b.jpg: OK
photos/tmp/scratch.jpg: OK
private/secret.txt: OK
tmp/scratch.txt: OK
```

A damaged object is never certified. The run stops, exit **21**, and stdout is
empty:

```console
$ dctl hashsum sha256 archive: > SUMS
warning: corrupt: format: footer mismatch
error: 'photos/b.jpg' failed integrity verification — the data was NOT served
$ echo $?; wc -c < SUMS
21
       0
```

Export a checksum file for an entire vault. BLAKE3 is recorded in the index, so
this is a metadata sweep with no object bytes read and no egress charge:

```
dctl hashsum blake3 vault: > vault-BLAKE3SUMS
```

Produce a SHA-256 manifest to hand to an archivist, a tape catalogue, or a
system that has never heard of BLAKE3. SHA-256 is not recorded, so this reads
and decrypts every object under the prefix — `hashsum` warns before it starts:

```
dctl hashsum sha256 vault:photos/2024 --binary > photos-2024-SHA256SUMS
warning: sha256 is not recorded in the index, so every object under
         'vault:photos/2024' must be read back and decrypted to compute it
```

The resulting file is byte-compatible with GNU coreutils, `*` marking binary
mode:

```
9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 *photos/2024/IMG_4417.CR3
```

Hash one object and read the result as structured data. The `algorithm` field
travels with the digest, so a consumer never has to guess which 64-character hex
string it is looking at:

```
dctl hashsum blake3 vault:photos/2024/IMG_4417.CR3 --json
```

Compare a vault against a second provider by way of two checksum files, using
tools that are not DCTL — which is the point of the command:

```
dctl hashsum blake3 vault:media       | sort > vault.sums
dctl hashsum blake3 b2prod:bucket/media | sort > b2prod.sums
diff vault.sums b2prod.sums
```

A Windows path is local, so it is rejected. `C:` is a drive letter, never a
remote named `C`, and DCTL will not quietly hash local files in place of the
vault objects that were asked for — use `sha256sum` if local files are what you
want:

```
dctl hashsum sha256 C:\Users\mx\Pictures
ERROR: dctl hashsum needs a remote path, but 'C:\Users\mx\Pictures' is local
  hint: Write the target as 'REMOTE:PATH', for example 'vault:photos'.
```

## Options

```
      --binary   Mark paths as binary, the way `sha256sum --binary` does
  -h, --help     help for hashsum
```

`ALGO` and `REMOTE:PATH` are both required, in that order. `ALGO` is one of
`blake3`, `sha1`, `sha256`. A bare `vault:` or a trailing separator
(`vault:photos/`) names a tree and hashes everything under it; without the
separator the spec names a single object.

## Options inherited from parent commands

Every global flag is accepted on `dctl hashsum`. The ones that change what this
command does are the `--include`/`--exclude`/`--filter-from`/`--files-from`/
`--min-size`/`--max-size`/`--max-depth` filters, `--format`/`--json`/`--quiet`
(note that text output is a wire format, so `--format` is the only way to change
its shape), and `--transfers`/`--bwlimit`/`--retries` when an unrecorded
algorithm forces a read-back. See [../GLOBAL_FLAGS.md](../GLOBAL_FLAGS.md) for
the full list.

## Exit codes

| Code | Name | When |
|-----:|------|------|
| 0 | `success` | Every requested hash was printed. |
| 1 | `usage` | Unknown flag or algorithm, a missing argument, a local target, a remote name shorter than two characters, or a path containing `..`. |
| 2 | `uncategorised` | The report could not be serialised. Not reachable for these types in practice. |
| 4 | `file_not_found` | An object is recorded in the index but absent at the provider. |
| 5 | `temporary_error` | The provider could not serve an object and the retry budget was exhausted. |
| 7 | `fatal_error` | An unresolvable remote, an unreadable configuration, or a vault that would not unlock. |
| 21 | `integrity_failure` | An object failed authentication while being hashed. No hash is printed for it. **The data was NOT served.** |
| 25 | `cancelled` | Ctrl-C or SIGTERM. A truncated checksum file is never reported as complete. |

See [../EXIT_CODES.md](../EXIT_CODES.md) for the full contract.

## See also

* [dctl verify](dctl_verify.md) — compare the recorded hashes against the stored
  objects instead of printing them.
* [dctl check](dctl_check.md) — compare two trees, optionally by checksum.
* [dctl scrub](dctl_scrub.md) — the scheduled whole-dataset read-back.
* [dctl ls](dctl_ls.md) — list objects with size and path.
* [dctl cat](dctl_cat.md) — write an object's contents to stdout, with the same
  refusal to serve bytes that failed authentication.
