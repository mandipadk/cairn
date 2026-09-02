# Cairn

A git forge that records how software came to exist.

Not who typed which line — what was claimed about the code, who re-ran
those claims, who judged it, and why anything was allowed to land. When
most of the work arrives from agents, the diff stops being the thing worth
reading and the evidence starts.

Cairn speaks ordinary git. Clone and push with the client you already
have; the forge turns a push into a change, a change into a record, and a
record into a decision it can explain.

## What a merge looks like here

Every merge carries the evaluation that allowed it. This is a real one,
from the forge that hosts this repository:

```json
{
  "kind": "change_merged",
  "change": "c-11jegz16kc10xfvbf6y8tnrzzc",
  "actor": "mandip",
  "trace": {
    "satisfied": true,
    "requirements": [
      { "description": "latest revision carries a passing test claim",
        "evidence": "cl-0ssb0r7z6v4852jp7tste29jhy" },
      { "description": "a runner reproduced a claim on the latest revision",
        "evidence": "runner reproduced cl-0ssb0r7z6v4852jp7tste29jhy" },
      { "description": "no claim on the latest revision is disputed by a runner",
        "evidence": "1 re-run(s), all reproduced" },
      { "description": "no blocking verdict on the latest revision",
        "evidence": "no blocks" }
    ]
  }
}
```

Months later, "why did this land?" has an answer that does not depend on
anyone remembering.

## What is different

**Claims are contracts, not comments.** A claim that the tests pass is
recorded with the command that produced it, so somebody else can run it
and say whether they saw the same thing. Verification has to be
independent — a claim cannot vouch for itself — and a claim nobody could
reproduce blocks the change until it is settled. A claim also says what
it deliberately did *not* check, and that gap follows the code: blame
here tells you which lines landed under a declared gap.

**Merges explain themselves.** What a repository requires before anything
lands is its policy: an executed check, an independent approver, a runner
that reproduced a claim, review domains that must sign off. Policy is
evaluated at landing time and the full trace is written into the merge
event, as above. A proposed policy can be previewed first — it reports
which open changes it would stop, and why, without changing anything.

**Attention is routed, not scrolled.** Open work is ranked by what human
judgment is actually worth on it — reviewers disagreeing, a disputed
claim, code resting on argument alone, claims nobody re-ran — and each
ranking carries its evidence. A fixed share of work no human has looked at
is sampled regardless, so agent output cannot quietly become unread
output.

**Agents are principals, not plugins.** People and agents hold the same
kind of identity and the same kind of authority: typed capabilities
(`task`, `push`, `review`, `merge`, `verify`, `admin`), scoped to a
repository if you like, time-boxed if you like, revocable with immediate
effect. You hold everything on what you own and precisely what someone
granted you everywhere else — and that rule is the same for a person as
for an agent. A team holds grants and its members carry them, so
authority can be given in one place and follows people on and off the
team. Ownership is offered, never assigned: it moves when the other side
accepts. A refusal names the missing capability and the exact grant
that would fix it. Agents connect over MCP; the adapter ships in the same
binary.

**The log is the product, and it has an audience.** Everything above is an
event in an append-only log, and every projection — the tree, the queue,
blame, the ranking — is that log, applied. A schema change is a replay,
not a migration. `fsck` proves the two still agree. And each event knows
who it is for: a repository's events go to the people who can read that
repository, your account's events to you, and nothing leaks through a gap
in the sequence numbers.

**Imported history says so.** History that predates the forge is recorded
as imported, never dressed up as reviewed. The log would rather admit a
gap than invent a decision.

## It speaks git

```sh
git clone https://forge.example/git/demo
git commit -m $'Do the thing\n\nChange-Id: I8f3a1c2e'
git push origin HEAD:refs/for/main
#  * [new reference]   HEAD -> refs/changes/1/1
```

Pushing to `refs/for/<branch>` opens a change. Push again with the same
`Change-Id` and it becomes revision 2 of the same change; every revision
stays fetchable at `refs/changes/<number>/<revision>`. A multi-commit push
becomes a stack, landed bottom-up, with children carried onto each new
tip automatically. Branches move only by merge — a direct push is refused
with the reason.

## Try it

```sh
cargo run -- admin bootstrap --db forge.db you --display "You"
cargo run -- serve --db forge.db --listen 127.0.0.1:6160
```

Open `http://127.0.0.1:6160` and sign in with the token it printed. Push
a change as above, attach a claim, and watch the readiness view fill in.
To let an agent work alongside you:

```sh
cairn mcp --server http://127.0.0.1:6160 --token $AGENT_TOKEN
```

Needs git 2.39 or newer on the server. [Operating](docs/operating.md)
covers exposure, CI, mirroring and the admin commands;
[Architecture](docs/architecture.md) covers the model in depth.

## Status

Early, self-hosted, and hosting itself: since the day it could, every
change to this repository has been pushed to Cairn, independently re-run
by a runner, and landed under its own policy. A hosted instance is on the way
— there is a waitlist at [cairn.mandip.dev](https://cairn.mandip.dev).

What is not here yet, so nobody has to find out the hard way:
organisations as a level above teams, and quotas on repository size. What is here is tested at
the boundaries where a forge is usually wrong — authority, concurrency,
crash recovery, hostile input, resource limits — and `fsck` runs clean on
the instance serving this page.

## License

Apache-2.0. See [LICENSE](LICENSE).
