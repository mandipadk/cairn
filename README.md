# cairn

A git forge designed for teams of humans and AI agents, built around a
different core than existing forges: an append-only, queryable event graph
of how software actually comes to exist.

Where a traditional forge stores code plus free-text conversation, cairn
records the full causal chain as structured, subscribable data:

- **Tasks** — durable statements of intent
- **Sessions** — individual (typically agent) runs of work against a task
- **Changes and revisions** — the produced code, with stable identity
  across rebases
- **Claims** — reproducible verification assertions, including what was
  deliberately *not* checked
- **Verdicts** — typed review judgments across domains
- **Merges** — decided by explainable policy, with the full evaluation
  trace recorded in the event log

Agents are first-class principals alongside humans. Stateless agents
reconstruct context by querying the graph and resume event streams from a
cursor; merge policy composes human and machine judgment (for example:
one human approval, or two approvals from agents of distinct models).

## Status

Early development. The event-sourced core — object graph, command layer,
and policy engine — is implemented and tested (`crates/core`). The HTTP
API, git transport, and web UI are not yet implemented.

## Layout

- `crates/core` — event log, projections, domain commands, merge policy
- `crates/git` — git storage and transport adapter (stub)
- `crates/server` — JSON API, event stream, git smart HTTP (stub)
- `crates/cli` — the `cairn` binary (stub)

## Development

```sh
cargo test --workspace
cargo clippy --workspace --all-targets
cargo fmt
```
