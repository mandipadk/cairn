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
`Change-Id` trailer, as emitted by Gerrit tooling and jj), a
multi-commit push becomes a stack of linked changes (one per commit,
requiring a trailer on each), every revision stays fetchable at
`refs/changes/<number>/<revision>`, and a policy-approved merge
fast-forwards the real branch. Direct pushes to branches are refused —
branches advance only by merge. Repos may use SHA-1 or SHA-256 object
databases.

Identity and authority are real: API tokens (secrets shown once at
mint, only hashes stored — recorded via the event log itself), and
capability grants. Humans hold every capability; agents act only under
grants — typed verbs (`task`, `push`, `review`, `merge`, `admin`),
optionally repo-scoped and time-boxed, revocable with immediate
effect. A refusal names the missing capability and the exact grant
that would fix it. Git pushes authenticate with a token as the
Basic-auth password. An asserted-identity dev header exists behind an
explicit `--dev` flag, off by default.

Ready changes land through a merge queue: enqueue a change (policy
must already be satisfied) and the forge lands it — fast-forward when
the target is unmoved, otherwise auto-rebased in memory with the
original author preserved and the landed commit recorded as
`merged_as` on the merge event. Whatever cannot land is dequeued with
a reason event naming exactly why: a policy regression, a revoked
capability, or the conflicting files. Policy is re-checked at landing
time, and stacks enqueue bottom-up.

A web interface ships in the same binary, server-rendered from the same
store the API reads: browse the tree (every file linking to the change
that landed it), read a change with its verification, judgment and
readiness side by side, give a verdict, enqueue, and watch the landing
queue and event log. Sign in with an API token.

Blame answers a different question here. Instead of who typed a line,
each line carries the change that landed it, what was claimed about it,
who judged it — and what those claims explicitly left unverified.
Lines that landed under a declared gap are marked, and the gaps are
listed. The same view is available to agents as an API endpoint and an
MCP tool, so an agent can ask what is known about code before changing
it.

Claims are contracts rather than assertions: a runner holding the
verify capability can re-execute a claim's recorded command and record
what it actually observed. Verification must be independent — a claim's
author cannot verify it — and a claim a runner cannot reproduce blocks
the change from landing until the dispute is resolved. `cairn verify`
is such a runner: it re-runs a change's claims in whatever environment
you point it at and reports honestly.

Deciding what deserves a human's attention gets the same treatment as
deciding what may land: an explainable evaluation over the graph rather
than a feed sorted by recency. Open changes are ranked by what judgment
is worth on them — reviewers disagreeing, a disputed claim, work resting
on argument alone, claims nobody re-ran, declared gaps — and each
ranking carries its signals and their evidence. A sampling policy also
draws a fixed share of changes no human ever looked at, deterministically
by change id, so a share of agent-only work reaches a person whether or
not anything about it looks wrong.

Not yet implemented: speculative queue batching and path leases with
conflict forecasting.

## Running

```sh
# first run: register the first human and mint their token (shown once)
cargo run -- admin bootstrap --db forge.db ada --display "Ada"
cargo run -- serve --db forge.db --listen 127.0.0.1:6160

# everything authenticates with 'Authorization: Bearer <token>'
curl -X POST localhost:6160/api/principals \
  -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"id": "scout", "kind": "agent", "display": "Scout", "model": "claude-fable-5"}'

# delegate: agents act only under capability grants
curl -X POST localhost:6160/api/grants \
  -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"grantee": "scout", "actions": ["task", "push"]}'

# follow everything that happens, resumable by cursor
curl -N 'localhost:6160/api/events/stream?after=0' -H "Authorization: Bearer $TOKEN"
```

Agents connect natively over MCP — the adapter proxies the same API:

```sh
cairn mcp --server http://127.0.0.1:6160 --token $AGENT_TOKEN
```

The web interface is served at the same address — open
`http://127.0.0.1:6160` and sign in with a token. Add `--dev` to accept
asserted identity instead, for local development only.

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
- `crates/server` — JSON API, event stream, git smart HTTP, web interface
- `crates/cli` — the `cairn` binary: server, MCP adapter, push hook

## Development

```sh
cargo test --workspace
cargo clippy --workspace --all-targets
cargo fmt
```
