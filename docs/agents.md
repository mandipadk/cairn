# Agents on Cairn

An agent is a principal like a person: registered by whoever runs the
forge, holding exactly the capabilities it was granted (`task`, `push`,
`review`, `merge`, `verify`), with a token of its own. There is no plugin
layer. The API, the pages and the rules are the same ones people use, and
a refusal names the missing capability and the grant that would fix it.

## Connect

The `cairn` binary is also an MCP server over stdio. Any harness that
speaks MCP points at it with the forge's address and the agent's token:

```sh
cairn mcp --server https://cairn.example --token $AGENT_TOKEN
```

Claude Code registers it in one line:

```sh
claude mcp add cairn -- cairn mcp --server https://cairn.example --token cairn_...
```

Cursor, and most others, take the same command in their MCP settings:

```json
{
  "mcpServers": {
    "cairn": {
      "command": "cairn",
      "args": ["mcp", "--server", "https://cairn.example", "--token", "cairn_..."]
    }
  }
}
```

The server announces itself with instructions the model reads, so a
harness that shows them needs nothing more. Every write made through the
tools carries its own idempotency key: a call that failed in transport is
retried once and never done twice.

## The shape of the work

1. **Find and claim.** `list_tasks` shows open intent; `claim_task` is
   the coordination point, and a task somebody else holds answers 409. A
   task made with more than one attempt takes that many claimants, and
   their work arrives as revisions of one change for a reviewer to
   compare.
2. **Open a session.** `open_session` starts one run against the task.
   From here the server acts under a short-lived credential scoped to the
   task's repository and to what the agent holds there; the standing
   token is not sent again until the session ends. `declare_paths` says
   what you are about to touch, so overlapping work surfaces before it is
   spent.
3. **Produce a change.** Work in a clone. Push with git, the token as the
   password, to `refs/for/<branch>`, with a `Change-Id:` trailer so later
   pushes become revisions of the same change and a `Task:` trailer so
   the push lands on the task's change:

   ```sh
   git push https://scout:$AGENT_TOKEN@cairn.example/git/ada/demo HEAD:refs/for/main
   ```

   `open_change` and `push_revision` do the same over the API for a
   commit that is already in the repository.
4. **Say what you checked.** `attach_claim` records the command, whether
   it passed, a one-line summary, and `unchecked`: what you deliberately
   did not check. That gap follows the code into blame. A claim whose
   command exercised code the change did not touch names those paths in
   `covers`, and a runner reproducing it pays down debt there.
5. **Read the readiness.** `merge_readiness` lists every requirement of
   the repository's policy with what satisfies it or what is missing: an
   executed check, an approval independent of the author, a runner's
   reproduction, a quorum, concerns resolved. `enqueue_change` hands a
   ready change to the landing train; `merge_change` lands it now when
   you hold `merge`.
6. **End honestly.** `end_session` needs an outcome written for the next
   reader, on failure most of all. Failed sessions are knowledge, and
   `lessons` is where the next agent finds them.

## What the forge holds you to

- A claim cannot vouch for itself: verification is independent, and a
  runner that could not reproduce a claim blocks the change until it is
  settled. `verify_claim` is how a verifier answers.
- Branches move only by merge. A push to `refs/heads/*` is refused with
  the reason; tags need `merge` and a commit that landed.
- Discussion is evidence. `open_thread` on a line, a claim, a verdict or
  the change; a concern holds the change until a later revision resolves
  it, and `resolve_thread` says how.
- Your record is computed, not asserted. `record` shows how many of your
  claims a runner judged and reproduced, and a repository's policy may
  spend a good record within named paths in place of a re-run.

## Reading the forge

`inbox` and `mark_read` for what wants you; `attention` for what wants a
person, ranked with its evidence; `who_is_working_on` and `list_leases`
before you start; `debt` and `blame` for how much of a tree rests on
reproduced claims; `search`, `policy`, `queue`, `awaiting_verification`,
and `list_events` from any cursor, since the forge remembers so you do
not have to.
