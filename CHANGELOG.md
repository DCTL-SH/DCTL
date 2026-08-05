# Changelog

Notable changes to DCTL. Dates are the date the work landed.

This project is in **alpha**: the on-disk format is frozen and documented in
`docs/FORMAT.md`, but the tool around it is still moving, and there has been no
independent cryptographic audit.

## Unreleased

### Performance

- **Directory listings cost their own directory rather than the whole vault.**
  Index rows now carry the keyed hash of the directory holding them, in an
  indexed column, with reference-counted directory rows so a directory stops
  existing when its last file goes. Because the row key is a keyed hash, a
  listing previously could not seek to a prefix or stop early, and had to decrypt
  every row in the index — a listing matching *no* files cost the same as one
  matching all of them. A mount walk was therefore quadratic: 47 ms over 1,000
  files, 4.0 s over 10,000, and 417 s over 100,000. It is now linear, at 2.9 s
  over 100,000, and a single directory read went from 413 ms to 7 ms.

- **`statfs` reads maintained totals instead of walking.** The mount root
  listing used to carry the recursive byte and object totals, which is why a
  listing had to visit everything beneath it. The totals are now carried forward
  as files arrive and leave, so `df` costs one row read.

- **`--transfers` runs files concurrently**, defaulting to 4 and accepting 1–64.
  Ingesting 10,000 files to a local store went from 103.8 s to 56.2 s. Past four
  the limit is the index write lock rather than the link, which is why the
  default is four and not higher.

- **A local paged listing is one tree walk.** It re-walked and re-sorted the
  whole tree for every page, so `dctl check` took 30.1 s over 100,000 files; it
  now takes 11.9 s and scales linearly. This also made a listing a consistent
  snapshot: re-walking between pages could return a page sequence no single walk
  ever saw, silently skipping or repeating keys.

### Fixed

- **`--max-transfer` could be exceeded once transfers ran concurrently.** The
  budget was checked before a file started and charged after it finished, so
  several files could each read the same total and all proceed — 192 KiB moved
  against a 100 KiB ceiling, exiting 0. The budget is now claimed in the same
  atomic operation that checks it, and reconciled against what actually moved.

- **A run stopped at its ceiling no longer discards finished work.** A fatal
  error dropped the transfers still in flight, so reaching `--max-transfer`
  cancelled files that fitted and had already been paid for. The run now stops
  starting new files and drains those already moving before it reports.
