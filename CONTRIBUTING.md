# Contributing

Cairn is developed on Cairn. Changes are pushed to `refs/for/main`, carry
a claim naming the command that checked them, are re-run by an
independent runner, and land under the repository's policy. The GitHub
repository is a mirror; pull requests there are read, and a maintainer
will carry a good one across.

## Sign your commits

Every commit needs a `Signed-off-by:` line certifying the
[Developer Certificate of Origin](DCO) — `git commit -s` adds it. It says
you wrote the change or have the right to submit it. Unsigned commits are
not landed.

## Licence of contributions

By contributing you agree that:

- your contribution is licensed under the licence of the crate it touches
  — AGPL-3.0 for the forge, Apache-2.0 for `cairn-client` — as recorded
  in that crate's manifest and licence file;
- you grant the project's copyright holder a perpetual, worldwide,
  irrevocable, royalty-free licence to use, modify, sublicense and
  redistribute your contribution, including under other licence terms,
  so that the project can offer the forge under additional licences to
  organisations that need them without asking every contributor again;
- you have the right to grant the above, and your contribution does not
  knowingly include code under a licence incompatible with it.

These terms are deliberately short. Before the first contribution from
outside the project they will be reviewed by a lawyer, and if they change,
the change will be recorded here and in the log like anything else.

## What a change needs

- Tests that exercise the behaviour, not the implementation; the suite
  is the claim, and a runner re-runs it.
- Comments that state constraints the code cannot show, not what the next
  line does.
- Nothing in the log that a person could not later ask to have forgotten:
  credentials, addresses and sessions live beside it, never in it.
- `cargo fmt`, `cargo clippy --workspace --all-targets` clean.
