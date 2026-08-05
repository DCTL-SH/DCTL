# Contributing

This is source-available software, not open source, and that changes what
contributing means here. Read `LICENSE.md` and `NOTICE` first.

## Before you open a pull request

Contributions are welcome but not automatically accepted, and the licence is the
reason to be upfront about it: the tool is under the PolyForm Noncommercial
License 1.0.0 and the copyright is held by a company that licenses it
commercially for any business use. A patch merged here becomes part of a product that is sold. If you
are not comfortable with that, please open an issue instead — a well-described
bug is genuinely more useful than an unmergeable patch.

Contributor licensing is not yet formalised. Until it is, please ask in an issue
before sending anything substantial.

## What the code expects

The house style is unusual and deliberate, so a patch that ignores it will not
merge even if it works.

**Comments explain why, not what.** Nearly every non-obvious decision in this
repository carries a comment saying what went wrong that made the code look like
this — usually with the measurement that proved it. Preserve those. If you change
the behaviour they describe, update the reasoning rather than deleting it.

**No hardcoded values.** Constants live in the constants module of their crate
with a doc comment explaining what the number *is* — ideally a measurement of the
system rather than a preference. A magic number in a function body will be asked
about.

**Nothing may report success it did not achieve.** This is the single rule the
project cares most about. A function that could not do what it was asked must
say so, with an exit code and a message naming what failed. Swallowing an error,
defaulting a missing value to zero, or reporting a file as stored before it is
durably stored are all treated as serious defects, and several of the comments in
this repository exist because exactly that happened.

**A fix needs a test that fails without it.** Write the test, break the fix,
watch the test go red, restore the fix. A test that passes both ways guards
nothing, and this has caught real non-fixes here more than once.

## Gates

Everything must be green before review:

    cargo build --workspace --all-targets
    cargo test --workspace
    cargo clippy --workspace --all-targets -- -D warnings

Clippy warnings are denied, not advisory.

## Layout

[The architecture reference](https://doc.dctl.sh/reference/architecture) and
[the crate reference](https://doc.dctl.sh/reference/crates) describe how the
crates fit together; `crates/dctl-decode/FORMAT.md` is the frozen on-disk format
and is licensed separately, under Apache 2.0, so anyone can implement against
it. Changing `FORMAT.md` is a compatibility decision, not a code change — raise
it as an issue first.
