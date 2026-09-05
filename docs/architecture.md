# Architecture

Cairn is built around a different core than existing forges: an
append-only, queryable event log of how software actually comes to
exist. Where a traditional forge stores code plus free-text conversation,
Cairn records the causal chain as structured, subscribable data.

## The objects

- **Tasks** — durable statements of intent.
- **Sessions** — individual (typically agent) runs of work against a task.
- **Changes and revisions** — the produced code, with stable identity
  across rebases.
- **Claims** — reproducible verification assertions, including what was
  deliberately *not* checked.
- **Verdicts** — typed review judgments across domains.
- **Threads** — discussion anchored to a line, a claim, a verdict or the
  change. A concern is a commitment the change carries until it is
  resolved, and the resolution says how.
- **Merges** — decided by explainable policy, with the full evaluation
  trace recorded in the event log.

Agents are first-class principals alongside humans. Stateless agents
reconstruct context by querying the graph and resume event streams from a
cursor; merge policy composes human and machine judgment (for example:
one human approval, or two approvals from agents of distinct models).

## The log, applied

Every projection — the tree, the queue, blame, the ranking — is derived
from the log. A schema change is therefore not a migration: on opening a
database whose projection shape is out of date, the forge drops the
derived tables and replays the log into fresh ones. The log itself is
never touched. `cairn admin fsck` replays the log into empty projections
and compares them with the live ones, and with `--repos` also checks that
every branch really contains what the log says landed on it.

Not everything belongs in a log that cannot forget. Credentials, browser
sessions and the waitlist live in operational tables beside the
projections, because a password must be changeable in a way that retires
the old secret and a session must expire.

### Audience

Each event records its scope as it is applied: a repository's, a
principal's own, or the forge's. You see a repository's events if you
could read the repository, your own account's events because they are
about you, and the forge's events because they are how the forge is run.
The resumable stream filters the same way and advances its cursor past
what it withheld, so nobody learns what they missed from a hole in the
numbering.

Authority is scoped but never private: a grant is visible to everyone it
stands alongside, because a forge arguing that authority should be
auditable cannot hide who may act. Passwords and tokens stay with their
subject — those are credentials, not authority.

### Inbox

A notice is an event read from one person's side: your change was
judged, your claim was disputed, your change landed or left the queue,
somebody gave you authority, somebody took on a task you wrote. Notices
are routed as events are applied, so the inbox is a projection like the
tree and the queue — rebuilt from the log, never edited. Nobody is told
about their own action. Whether you have read a notice is operational
state beside the projection, because what you have dealt with is not a
fact about the software.

## Changes over git

Pushing to `refs/for/<branch>` opens a change or adds a revision, matched
by `Change-Id` trailer as emitted by Gerrit tooling and jj. A
multi-commit push becomes a stack of linked changes, one per commit, each
requiring a trailer. Every revision stays fetchable at
`refs/changes/<number>/<revision>`, and a policy-approved merge
fast-forwards the real branch. Direct pushes to branches are refused —
branches advance only by merge. Repositories may use SHA-1 or SHA-256
object databases.

When a stacked change lands, its open children are carried onto the new
tip automatically: a successful carry adds a revision exactly as a push
would, and one that conflicts is recorded with the files that collided
and left for a person. The author's own revisions are never rewritten.

## Policy and readiness

What a repository requires before anything lands is its own choice,
recorded as an event like everything else: whether an executed check is
needed, who counts as an independent approver, whether a runner must have
reproduced a claim, and which review domains must sign off. The defaults
are the rules the forge ships with, so a repository that never sets a
policy behaves as it always did. A proposed policy can be previewed
first — it reports which open changes it would stop from landing, and
why, without changing anything.

## The landing queue

Ready changes land through a merge queue: enqueue a change (policy must
already be satisfied) and the forge lands it — fast-forward when the
target is unmoved, otherwise auto-rebased in memory with the original
author preserved and the landed commit recorded as `merged_as` on the
merge event. Whatever cannot land is dequeued with a reason event naming
exactly why: a policy regression, a revoked capability, or the conflicting
files. Policy is re-checked at landing time, and stacks enqueue
bottom-up.

Each branch is its own lane and lanes run at the same time, since two
lanes never advance the same ref. Within a lane, order stays strict —
that is what keeps every landing a plain consequence of the one before
it.

Recording a merge and moving the branch are two steps in two stores. The
forge treats the log as the outbox: a landing is recorded first, the ref
is advanced second, and anything recorded but not yet advanced is
reconciled on startup and after any failed advance.

## Claims and verification

Claims are contracts rather than assertions: a runner holding the verify
capability can re-execute a claim's recorded command and record what it
actually observed. Verification must be independent — a claim's author
cannot verify it — and a claim a runner cannot reproduce blocks the change
from landing until the dispute is resolved.

A runner's verdict on a claim is its current position, not a permanent
artefact: its own later re-run supersedes its earlier one, with both kept
in the log. Two different runners disagreeing is not superseded by
either, because that disagreement is real information. A runner that
could not run the command at all — a missing toolchain, a full disk —
refuses and records nothing, since "I could not check" is not evidence
that the claim is false.

## Attention as a budget

Human judgment is the scarce input, so the forge spends it deliberately.
Every open change is ranked by explainable signals — reviewers who
disagree, a claim a runner could not reproduce, a block, a case resting
on argument alone, a sampled spot check — and a repository may set an
attention budget: how many changes a day the policy draws for a human
look. Each draw is an event that names the day, the grounds and the
humans asked, and a drawn change waits for a human verdict before it
lands. What is not drawn proceeds on the policy's other rules, which is
the point: review becomes triage of disagreement, not a queue.

## Discussion as evidence

Discussion is part of the graph, not a comment box beside it. A thread is
anchored to a thing — a line of a revision's diff, a claim, a verdict, or
the change — and has a kind that means something: a concern must be
resolved before the change lands, a question should be answered, a note
is for the record. Resolving says how: answered in the thread, fixed by a
named later revision, withdrawn by whoever raised it, or overruled by the
change's owner or a reviewer, on the record. Every step is an event, so
an agent picking up revision three can read what was raised on revision
two and what became of it, and a merge trace shows which concerns stood
and how each was closed. Taking part needs a hand in the repository: its
owner, the change's owner, or a holder of any capability on it.

## Verification debt

Every line of a repository carries one state, from what the log knows
about the change that landed it: reproduced (a runner re-ran the claim),
claimed (its author ran something nobody re-ran), gap (a claim named it
unchecked), argued (only a reasoning claim), or imported (from before the
forge; nothing here ever judged it). `GET /api/repos/{name}/debt` rolls the
states up for the default branch, by file with the most debt first, and
the blame API carries the state per line; agents have both as MCP tools.
"27% coverage" becomes "these lines shipped on a promise".

## Blame

Blame answers a different question here. Instead of who typed a line,
each line carries the change that landed it, what was claimed about it,
who judged it — and what those claims explicitly left unverified. Lines
that landed under a declared gap are marked, and the gaps are listed. The
same view is available as an API endpoint and an MCP tool, so an agent
can ask what is known about code before changing it.

## Attention

Deciding what deserves a human's attention gets the same treatment as
deciding what may land: an explainable evaluation over the graph rather
than a feed sorted by recency. Open changes are ranked by what judgment is
worth on them — reviewers disagreeing, a disputed claim, work resting on
argument alone, claims nobody re-ran, declared gaps — and each ranking
carries its signals and their evidence. A sampling policy also draws a
fixed share of changes no human ever looked at, deterministically by
change id, so a share of agent-only work reaches a person whether or not
anything about it looks wrong.

Where reviewers reach opposite conclusions, both positions are put side
by side on the change — that is the one place a human's judgment is worth
more than another review.

## Sessions, leases and outcomes

A session can declare which paths it expects to touch, and is told who
else is already there — including whether they have pushed code, which
means a rebase is coming rather than merely possible. Nothing is refused:
the forge makes the collision visible while it is still cheap and the
agent decides what to do. Declarations are replaced rather than
accumulated, so narrowing scope releases ground, and a lease lives
exactly as long as the session behind it.

Because the protocol refuses to let a session end without recording an
outcome, failed attempts leave knowledge behind by construction. Those
outcomes are searchable, so the question an agent should ask first — has
anyone tried this before? — has an answer.

## Identity and authority

API tokens are shown once at mint and only their hashes are stored,
recorded via the event log itself. Authority is explicit for everyone.
You hold every capability on repositories you own — creating one is how
you come to own it — and everywhere else you hold precisely what somebody
granted you: typed verbs (`task`, `push`, `review`, `merge`, `verify`,
`admin`), optionally repo-scoped and time-boxed, revocable with immediate
effect. The same rules apply to people and to agents. Running the forge
is itself a grant — an unscoped `admin` — held by whoever
`cairn admin bootstrap` set up, and grantable onward like any other. A
refusal names the missing capability and the exact grant that would fix
it.

An agent need not hold a standing token to work. A session - one run
against a claimed task - can draw a credential of its own: a bearer token
shown once, scoped to the task's repository and the verbs the agent holds
there, alive for an hour unless asked otherwise and never past eight, and
dead the moment the session ends. Scope is checked before any grant, on
every call and every read, over the API and over git alike, so a leaked
session credential buys exactly what it carried for exactly as long as it
lived; the mint and the revocation are events, and every event an action
under the credential appends names the session it ran under. The MCP
server draws one
when it opens a session and works under it. A repository may insist
(`agents_act_in_sessions`): agents' standing tokens are then refused for
push, review and merge on it, while claiming a task and verifying stay
open to them.

A team is a principal that never acts: it holds grants, and its members
act with them. Every authority check reads a principal's own grants and
their teams' as one list, so joining a team is effective at once and
leaving it is too. A team cannot sign in, cannot join a team, and cannot
own a repository; only a person owns one. Ownership is offered rather
than assigned — the owner offers, the person is told, and nothing moves
until they accept, because owning carries every capability on the
repository and whatever is in it.

Repositories are private unless someone says otherwise, and that is
enforced at the transport: a private repository cannot be cloned without
a token, and it answers a stranger exactly as a repository that does not
exist does. Making one public is an admin decision and is recorded like
any other, and it means public: its pages and its read-only API answer
without anyone signing in, with nothing to act on and no sidebar but the
public repositories; every write still needs identity.

## Imports and mirrors

History that predates the forge is recorded as imported, never dressed up
as reviewed. A repository can also mirror its landed branches somewhere
else, which is how a migration happens without a cutover: work moves here
while whatever people already read — GitHub, usually — keeps seeing the
branches it always did. Every attempt is recorded whether it succeeded or
not, an unreachable mirror never holds up work on the forge that owns it,
and the credential that authorises the push belongs to whoever runs the
forge and is never written to the graph.

## Layout

- `crates/core` — event log, projections, domain commands, merge policy
- `crates/git` — bare-repo storage, pkt-line codec, commit parsing
- `crates/server` — JSON API, event stream, git smart HTTP, web interface
- `crates/client` — the MCP adapter and the claim runner (Apache-2.0; everything else is AGPL-3.0)
- `crates/cli` — the `cairn` binary: server, admin commands, push hook, and the client commands
