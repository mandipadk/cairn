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

Early development. Implemented and tested: the event-sourced core —
object graph, command layer, policy engine (`crates/core`); the HTTP
surface: a JSON API covering every protocol verb plus a Server-Sent
Events stream with cursor resume (`crates/server`, `cairn serve`); and
an MCP adapter exposing the protocol as tools for AI agents
(`cairn mcp`); and git hosting with change-native transport — pushing
to `refs/for/<branch>` opens a change or adds a revision (matched by
`Change-Id` trailer, as emitted by Gerrit tooling and jj), every
revision stays fetchable at `refs/changes/<number>/<revision>`, and a
policy-approved merge fast-forwards the real branch. Not yet
implemented: capability grants, merge queue, stacked-change
auto-rebase, and the web UI. Identity is currently dev-mode — callers assert a
principal via the `x-cairn-principal` header; credential verification
and capability grants are the next trust layer.

## Running

```sh
cargo run -- serve --db forge.db --listen 127.0.0.1:6160

# register the first principal (bootstrap self-registration)
curl -X POST localhost:6160/api/principals \
  -H 'x-cairn-principal: ada' -H 'content-type: application/json' \
  -d '{"id": "ada", "kind": "human", "display": "Ada"}'

# follow everything that happens, resumable by cursor
curl -N 'localhost:6160/api/events/stream?after=0' -H 'x-cairn-principal: ada'
```

Agents connect natively over MCP — the adapter proxies the same API:

```sh
cairn mcp --server http://127.0.0.1:6160 --principal scout
```

The transport is also the API — plain git speaks to the graph:

```sh
git clone http://127.0.0.1:6160/git/demo
git commit -m $'Do the thing\n\nChange-Id: I8f3a1c2e'
git push http://scout:x@127.0.0.1:6160/git/demo HEAD:refs/for/main
# remote reports the change ref, e.g. refs/changes/1/1;
# amend + push again with the same Change-Id -> revision 2
```

## Layout

- `crates/core` — event log, projections, domain commands, merge policy
- `crates/git` — bare-repo storage, pkt-line codec, commit parsing
- `crates/server` — JSON API, event stream, git smart HTTP
- `crates/cli` — the `cairn` binary: server, MCP adapter, push hook

## Development

```sh
cargo test --workspace
cargo clippy --workspace --all-targets
cargo fmt
```
