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

What a repository requires before anything lands on it is its own
choice, recorded as an event like everything else: whether an executed
check is needed, who counts as an independent approver, whether a
runner must have reproduced a claim, and which review domains must sign
off. The defaults are the rules the forge ships with, so a repository
that never sets a policy behaves as it always did. A proposed policy
can be previewed first — it reports which open changes it would stop
from landing, and why, without changing anything.

A repository can mirror its landed branches somewhere else, which is
how a migration happens without a cutover: work moves here while
whatever people already read — GitHub, usually — keeps seeing the
branches it always did. Every attempt is recorded whether it succeeded
or not, because a mirror that has been quietly failing for a week is
exactly what nobody notices. An unreachable mirror never holds up work
on the forge that owns it. The credential that authorises the push
belongs to whoever runs the forge and is never written to the graph:
mirror URLs carrying credentials are refused.

Because projections are derived from the log, a schema change is not a
migration: on opening a database whose projection shape is out of date,
the forge drops the derived tables and replays the log into fresh ones.
The log itself is never touched.

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

A session can declare which paths it expects to touch, and is told who
else is already there — including whether they have pushed code, which
means a rebase is coming rather than merely possible. Nothing is
refused: the forge makes the collision visible while it is still cheap
and the agent decides what to do. Declarations are replaced rather than
accumulated, so narrowing scope releases ground, and a lease lives
exactly as long as the session behind it.

Where reviewers reach opposite conclusions, both positions are put side
by side on the change — that is the one place a human's judgment is
worth more than another review.

Because the protocol refuses to let a session end without recording an
outcome, failed attempts leave knowledge behind by construction. Those
outcomes are searchable, so the question an agent should ask first —
has anyone tried this before? — has an answer.

When a stacked change lands, its open children are carried onto the new
tip automatically: a successful carry adds a revision exactly as a push
would, and one that conflicts is recorded with the files that collided
and left for a person. The author's own revisions are never rewritten.

Each branch is its own landing queue and they run at the same time,
since two lanes never advance the same ref. Within a lane, order stays
strict — that is what keeps every landing a plain consequence of the
one before it.

## Continuous integration

`cairn verify` is the runner. Given a change it re-runs that change's
claims; given none, it works through every change whose claims name a
command nobody has re-run, fetching each revision from the forge rather
than trusting whatever directory it was started in. It exits non-zero
when a claim cannot be reproduced, so a CI job goes red where people
already look, and the dispute blocks the change until someone resolves
it. `.github/workflows/verify.yml.example` is a working configuration;
nothing about the runner is specific to any CI product.

## Exposure

Before putting a forge somewhere strangers can reach it: serve it over
HTTPS and pass `--secure-cookies`, keep `--dev` off, and note what is
and is not defended. Responses carry a strict content policy, frame and
sniffing protections, and HSTS. Sign-in attempts are rate limited per
source address — behind a reverse proxy, pass `--trust-proxy` so callers
are told apart by the forwarded address rather than sharing the proxy's.
`/healthz` answers unauthenticated, for whatever is watching. Every free-text field a caller controls is bounded, so
the log cannot be inflated by a stranger. Git subprocesses have
timeouts, so a hung transfer cannot hold a connection indefinitely.

What one request may cost is bounded too, because the sizes involved are
not the forge's to choose. A single push carries at most 64 commits —
beyond that it is history rather than a stack, and it is refused with
that explanation. Files are rendered up to 2 MB and diffs up to 1 MB;
past that the page says how large the thing is instead of loading it,
since the bytes would otherwise be held once as read, again as a string,
and again escaped into HTML. Binary files are named rather than shown. A
database with no room left fails the write whole: every command is one
transaction, so a full disk costs the write and not the log.

Repositories are private unless someone says otherwise, and that is
enforced at the transport rather than only in the interface: a private
repository cannot be cloned without a token, and it answers a stranger
exactly as a repository that does not exist does, so which private
repositories are here is not public either. Making one public is an
admin decision and is recorded like any other. Reading authenticates on
the token alone — the username in Basic auth is decoration, as it is
everywhere else — while a push still requires the two to agree, because
a mismatch there is usually somebody's mistake worth catching.

What is not here yet: per-user visibility within a forge, so everyone
signed in can see every repository they are told about; request-rate
limiting beyond sign-in and the waitlist; quotas on repository or push
size; and any protection against a principal that holds legitimate
capabilities and abuses them. Grants are the tool for
that, and they are only as narrow as whoever issues them.

## Requirements

**git 2.39 or newer**, on the PATH of whoever runs `serve`. Merging uses
`merge-tree --write-tree`, which arrived in git 2.38, so a stock Ubuntu
22.04 (git 2.34) cannot merge — add `ppa:git-core/ppa`, or run somewhere
newer. `serve` checks this at startup and refuses to boot on a git it
cannot merge with, rather than accepting work it will fail to land.

2.39 rather than 2.38 because 2.39 is the oldest git the test suite runs
against; the floor is a tested fact, not an inference.

**SHA-256 repositories additionally need git 2.43 or newer on the
client.** Cloning an empty repository cannot infer the object format from
any object, so it depends on the transport advertising it, and older git
quietly produces a SHA-1 working copy whose first push will not match the
repository it came from. Verified: 2.40 fails, 2.43 works. This is a
client limitation and applies to whoever clones, not to the server.

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

Mirroring landed branches outward, for a migration that needs no
cutover:

```sh
cairn serve --db forge.db --mirror-token $GITHUB_TOKEN   # or CAIRN_MIRROR_TOKEN
curl -X POST localhost:6160/api/repos/demo/mirror \
  -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"mirror": {"url": "https://github.com/you/demo.git", "enabled": true}}'
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
