# Running Cairn

A runbook: what to do, in the order you meet it, and what to do when
something is wrong. The reference at the end lists every command, flag
and variable the sections use.

## Before you start

**git 2.39 or newer**, on the PATH of whoever runs `serve`. Merging uses
`merge-tree --write-tree`, which arrived in git 2.38, so a stock Ubuntu
22.04 (git 2.34) cannot merge — add `ppa:git-core/ppa`, or run somewhere
newer. `serve` checks this at startup and refuses to boot on a git it
cannot merge with, rather than accepting work it will fail to land. The
floor is 2.39 rather than 2.38 because 2.39 is the oldest git the test
suite runs against; it is a tested fact, not an inference.

**SHA-256 repositories additionally need git 2.43 or newer on the
client.** Cloning an empty repository cannot infer the object format from
any object, so it depends on the transport advertising it, and older git
quietly produces a SHA-1 working copy whose first push will not match the
repository it came from. Verified: 2.40 fails, 2.43 works.

## Install

From a release, for x86_64 Linux: each tagged version is built on the
reference instance and published at
`https://dl.cairn.mandip.dev/releases/<version>/`, as one archive holding
the binary, the licence and the README, beside a `SHA256SUMS` that covers
it. Check the sum before you unpack:

```sh
V=0.1.0-alpha.1
curl -sSfLO "https://dl.cairn.mandip.dev/releases/$V/cairn-$V-x86_64-linux.tar.gz"
curl -sSfL "https://dl.cairn.mandip.dev/releases/$V/SHA256SUMS" | sha256sum -c --ignore-missing
```

From source, anywhere with a Rust toolchain:

```sh
cargo install --git https://cairn.mandip.dev/git/cairn cairn
```

The mirror at `github.com/mandipadk/cairn` is the same code. `cairn
--version` names the version and the commit it was built from, and
`/healthz` on a running forge carries the same string. `scripts/release.sh`
is what produces a release archive; run it anywhere to package a build
for that machine.

## First run

```sh
# register the first human and mint their token (shown once)
cairn admin bootstrap --db forge.db ada --display "Ada"
cairn serve --db forge.db --listen 127.0.0.1:6160 --repos repos
```

The web interface is served at the same address; sign in with the token
or, once one is set, a password. Everything on the API authenticates with
`Authorization: Bearer <token>`:

```sh
curl -X POST localhost:6160/api/principals \
  -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"id": "scout", "kind": "agent", "display": "Scout", "model": "claude-fable-5"}'

# delegate: agents act only under capability grants
curl -X POST localhost:6160/api/grants \
  -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"grantee": "scout", "actions": ["task", "push"]}'

# the agent's own token, shown once in the response
curl -X POST localhost:6160/api/principals/scout/tokens \
  -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"label": "laptop"}'

# a repository, private until its settings say otherwise
curl -X POST localhost:6160/api/repos \
  -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"name": "demo"}'

# follow everything you may see, resumable by cursor
curl -N 'localhost:6160/api/events/stream?after=0' -H "Authorization: Bearer $TOKEN"
```

The pages offer the same: **New** creates a repository, and **Agents**
registers, grants and mints. Agents connect natively over MCP — the
adapter proxies the same API, and [Agents on Cairn](agents.md) says what
they do from there:

```sh
cairn mcp --server http://127.0.0.1:6160 --token $AGENT_TOKEN
```

Git authenticates with a token as the Basic-auth password, on clone as
well as on push: a private repository — the default — is not readable
without one, so an anonymous clone is asked for credentials rather than
told the repository exists. Give git a username and let it ask, or keep
the token in a credential helper:

```sh
git clone http://scout@127.0.0.1:6160/git/demo
git commit -m $'Do the thing\n\nChange-Id: I8f3a1c2e'
git push http://scout@127.0.0.1:6160/git/demo HEAD:refs/for/main
```

Add `--dev` to accept asserted identity via the `x-cairn-principal`
header, for local development only.

## Put it where others can reach it

Before putting a forge somewhere strangers can reach it: serve it over
HTTPS, pass `--secure-cookies`, set `--public-url` (or `CAIRN_PUBLIC_URL`)
to the address people use, keep `--dev` off, and note what is and is not
defended. The public URL is the only authority on where the forge lives:
every link it mails — invitations, confirmations, resets, sign-in links —
is built from it and never from a request's `Host` header, and passkeys
bind to it. Without it, links are built from the request, which is fine
on a laptop and unsafe anywhere else. Do not change it once passkeys
exist; every credential is bound to that host.

Some actions spend the operator's resources and are therefore the
operator's to authorise, not a repository owner's: setting a mirror (the
push carries the forge's mirror credential), importing history (the forge
connects out on the caller's behalf; only `https://` sources are
accepted), and registering agents. Minting a token for somebody else,
and revoking another person's token or grant, are likewise the unscoped
admin's.

Responses carry a strict content policy, frame and sniffing protections,
and HSTS. Sign-in attempts are rate limited per source address — behind a
reverse proxy, pass `--trust-proxy` so callers are told apart by the
forwarded address rather than sharing the proxy's. API writes are allowed
per principal, 600 a minute unless `--api-writes-per-minute` says
otherwise (0 turns the allowance off); past that a caller gets `429` with
`Retry-After`, which is how a loop stuck on a refusal is stopped without
stopping anyone else. `/healthz` answers unauthenticated, for whatever is
watching. Every free-text field a caller controls is bounded, so the log
cannot be inflated by a stranger. Git subprocesses have timeouts, so a
hung transfer cannot hold a connection indefinitely.

What one request may cost is bounded too. A single push carries at most
64 commits — beyond that it is history rather than a stack, and it is
refused with that explanation. Files are rendered up to 2 MB and diffs up
to 1 MB; past that the page says how large the thing is instead of
loading it. Binary files are named rather than shown. A database with no
room left fails the write whole: every command is one transaction, so a
full disk costs the write and not the log.

Repositories are private by default and that is enforced at the
transport: a private repository cannot be cloned without a token, and it
answers a stranger exactly as a repository that does not exist does.
Reading authenticates on the token alone — the username in Basic auth is
decoration — while a push still requires the two to agree, because a
mismatch there is usually somebody's mistake worth catching.

Not defended yet: rate limiting on reads; quotas on repository or push
size; and a principal that holds legitimate capabilities and abuses them.
Grants are the tool for that, and they are only as narrow as whoever
issues them.

## Send mail

Point the forge at an SMTP relay — your own, or a provider's — as one URL
with the credentials in it, plus the address to send from:

```sh
CAIRN_SMTP_URL='smtps://user:pass@smtp.example.com:465' \
CAIRN_MAIL_FROM='forge@example.org' cairn serve ...
# smtp://user:pass@host:587?tls=required for STARTTLS; unencrypted is refused
```

Put them in the service's environment file rather than on the command
line, so the password is not in the process list. `cairn admin
mail-check` proves the configuration — reaches the relay, negotiates TLS,
authenticates, hangs up — without sending anyone anything. On a machine
that already has a mail system, `--mail-command "sendmail -t"` hands each
message to that instead; the command gets the whole message on stdin.

With mail configured, an invitation from the People page goes to the
address given, and following it proves that address. An address given
later on the settings page is pending until a link mailed to it is
followed, and changing an address goes the same way; a reset only ever
goes to a confirmed address. From the sign-in page, a forgotten password
gets a link that works once, for thirty minutes; and anyone with a
confirmed address can ask for a sign-in link instead of typing a
password — it works once, for fifteen minutes. Both forms answer everyone
the same way whether or not they know them. Reports filed at `/report`
go to every confirmed address of whoever runs the forge.

Without mail, or for a person with no address on record, a reset request
is not a dead end: the people who run the forge are told in their inbox
and can send a new sign-in link from the People page in one click.

## Ways to sign in

**Passkeys** bind to the forge's origin, so they exist only once the
public URL is set. With it, a signed-in person adds a passkey from their
settings page and the sign-in page offers "Sign in with a passkey". This
is the one place the pages run script: a small first-party file, served
under a content hash and permitted by the content policy for this origin
alone. The in-flight ceremony state lives in the database for five
minutes and is spent exactly once, so any forge process can finish what
another started.

**An OpenID Connect provider**:

```sh
cairn serve ... --oidc-issuer https://accounts.google.com \
  --oidc-client-id <id> --oidc-client-secret-file /data/cairn/oidc.secret \
  --oidc-label Google
```

The login page then offers "Continue with Google". A provider identity
signs somebody in only once it is linked: the person signs in another way
and links it in Settings, or — with `--oidc-link-by-email` — the
identity's verified email matches exactly one person here. Nothing links
itself, and every link and unlink is an event. The public URL must be
set: the provider sends people back to `<public URL>/login/oidc/callback`.

**Workload identity, for agents.** Agents need not hold a standing token.
Trust an issuer with `--workload-issuer
https://token.actions.githubusercontent.com` (repeatable), bind its
subjects to agents (`POST /api/principals/{agent}/workload {"issuer": ..,
"subject": ..}`, whoever runs the forge), and a workload exchanges its
token at `POST /api/identity/exchange {"token": ..}` for a fifteen-minute
credential that can only claim a task and open a session; the session
then draws its own scoped credential. The token must name the forge's
public URL as its audience unless `--workload-audience` says otherwise.

## Day to day

### Repositories

An owner, or whoever runs the forge, can rename, archive and delete a
repository from its settings page or over the API
(`POST /api/repos/{name}/rename {"to": ..}`, `/archive`, `/unarchive`,
`/delete {"confirm": "<name>"}`). A rename moves everything, including the
git directory; the old name answers not found. An archived repository is
read-only: clones and reads go on, pushes, new changes and new tasks are
refused with a message that says so. Deleting needs the name typed out
and nothing waiting in the landing queue; the repository's changes,
claims, verdicts and discussion go with it, tasks and lessons keep their
text and lose their home, and the log keeps what happened.

### Tags

A tag names a landed commit. Push one the ordinary way — `git push origin
v0.1.0` — and the forge takes it from whoever holds `merge` on the
repository, for a commit that is on one of its branches, under a name it
has not used before. Tags are never moved or deleted: a later tag is a
new statement, not a correction. Each is recorded as a `tag_pushed` event
with who set it, listed at `GET /api/repos/{name}/tags` and on the
repository's page, and copied to the mirror along with the branches.

### Mirroring

```sh
cairn serve --db forge.db --mirror-token $GITHUB_TOKEN   # or CAIRN_MIRROR_TOKEN
curl -X POST localhost:6160/api/repos/demo/mirror \
  -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"mirror": {"url": "https://github.com/you/demo.git", "enabled": true}}'
```

Mirror URLs carrying credentials are refused; the credential belongs to
whoever runs the forge. Every landing, and every tag, is pushed outward
and the attempt recorded either way as a `mirror_pushed` event.

### Runners and CI

`cairn verify` is the runner. Given a change it re-runs that change's
claims; given none, it works through every change whose claims name a
command nobody has re-run, fetching each revision from the forge rather
than trusting whatever directory it was started in. It exits non-zero
when a claim cannot be reproduced, so a CI job goes red where people
already look, and the dispute blocks the change until someone resolves
it. It refuses to start — recording nothing — when it cannot write to its
working or temporary directory, and refuses a command it cannot run at
all, because a runner must be able to say "I could not check" rather than
"the claim is false". `.github/workflows/verify.yml.example` is a working
configuration; nothing about the runner is specific to any CI product.

A second runner is a second principal. Register it as an agent with a
`harness` naming where it runs (`POST /api/principals` with
`"harness": "github-actions"`, or the name of a box), or bind it to a
workload identity issuer so the forge has the issuer's word for it, and
give it the `verify` capability and nothing else: a runner that could
also push or review is not a third party to the change, and its word does
not count toward a quorum. Then set `runner_quorum` on the repositories
that want two machines to agree. Each runner asks `awaiting-verification`
under its own token and is handed only what it still owes.

### Merge receipts

Every landing is signed. The key lives in `signing.key` beside the
database (owner-only, generated on first start) or wherever
`--signing-key-file` points; back it up with the database, and know that
losing it means a new fingerprint while receipts already issued still
verify against the key they carry. The public key is at `/api/forge/key`.
Each receipt is also a git note on the landed commit under
`refs/notes/cairn`, pushed to the mirror with the branch.

```sh
curl -s https://forge.example/api/changes/c-…/receipt > receipt.json
cairn receipt verify receipt.json --key 3f9a1c…        # the fingerprint /api/forge/key shows
git -C clone log --show-notes=cairn -1                  # the same document, on the commit
```

### Agents' credentials

An agent's session can draw a short-lived credential:
`POST /api/sessions/{id}/credential` with an optional body
`{"minutes": 60, "actions": ["push","task"]}` returns a bearer token shown
once, scoped to the task's repository and no more than the agent holds
there, good for an hour by default and never more than eight, and refused
from the moment the session ends. `cairn mcp` does this on `open_session`
and works under the credential until `end_session`. A repository whose
policy carries `"agents_act_in_sessions": true` refuses agents' standing
tokens for push, review and merge; `task` and `verify` remain open, so an
agent can still claim a task and open a session, and a runner is
unaffected.

### Attention budget

A repository's policy may carry `"attention_budget": 2`: the forge then
draws up to that many open changes a day for a human look, highest-ranked
first — disagreement, disputed claims, blocks, argument-only cases, spot
checks — and tells the repository's owner and every human holding review
on it. A drawn change needs a human verdict on its latest revision before
it can land. Draws happen on the landing train's tick, or on request with
`POST /api/repos/{name}/attention/draw` (merge capability); without a
budget nothing is drawn and attention stays a ranked list.

### Discussion

Review talks in threads, and a thread is anchored to something: a line of
a revision's diff, a claim, a verdict, or the change itself. On the page,
a line number opens a composer beneath the line; the Discussion column
lists every thread on the change and can start one on the change as a
whole. Over the API the same goes through `POST /api/changes/{id}/threads`
with an `anchor` (`{"on":"line","path":..,"side":"new","line":12}`,
`{"on":"claim","claim":..}`, `{"on":"verdict","verdict":..}` or
`{"on":"change"}`); a thread then lives at `/api/threads/{id}`, and replies
and resolutions are `POST`ed to `/api/threads/{id}/reply` and
`/api/threads/{id}/resolve`. Agents have the same as MCP tools:
`open_thread`, `list_threads`, `reply_thread` and `resolve_thread`.

The kind is a commitment. A `concern` holds the change: the merge policy
requires every concern to be resolved (`require_concerns_resolved`, on by
default), and names the standing ones by id in the readiness trace. A
`question` should be answered; a `note` is for the record. Resolving says
how — `answered`, `fixed` by a named later revision, `withdrawn` by whoever
raised it, or `overruled` by the change's owner or a reviewer — and is an
event like everything else, so nothing is closed quietly. Taking part
needs a hand in the repository: its owner, the change's owner, or a holder
of any capability on it; reading alone does not let you impose a concern.

### People and agents who should stop

Whoever runs the forge can deactivate a person or an agent from the
People page or with `POST /api/principals/{id}/state {"active": false}`.
From that moment they cannot sign in, their browser sessions are over,
their tokens and session credentials stop answering, and nothing can be
done in their name; what they did stays on the record, and repositories
they own stay theirs until offered to someone else. Reactivation is the
same call with `true`. Nobody can deactivate themselves, so the forge
always keeps someone who can undo it.

## Keep it running

### Back up

Three things hold a forge: the database, which is the log and everything
derived from it; the repositories under `--repos`; and `signing.key`,
without which the next landing's receipt is signed by a new key. Copy the
database through sqlite's backup API rather than `cp` — a live database
keeps recent writes in its WAL file, and a plain copy can miss them.
`scripts/backup.sh` does all three into one bundle, integrity-checks the
copy before keeping it, and prunes old bundles:

```sh
CAIRN_DB=/srv/cairn/cairn.db CAIRN_REPOS=/srv/cairn/repos scripts/backup.sh
```

Run it from a timer, and keep a copy of the bundle somewhere the machine's
disk is not: `scripts/upload-s3.py` puts a file into any S3-compatible
bucket (Cloudflare R2 included) with only python and curl, and the
bucket's lifecycle rule is the retention. To restore, extract the bundle
and point `serve` at the copies; `cairn admin fsck --db <copy> --repos
<copy>/repos` proves the bundle before you need it, and the first-run walk
does exactly that on every change to these documents.

### Upgrade

Stop the service, take a backup, install the new binary, start it. The
first open after an upgrade that changed the schema rebuilds every
projection from the log — the tree, the queue, blame, the rankings — and
the forge serves only once that is done; the log itself, tokens, sessions
and the idempotency ledger are not touched. On the reference instance the
rebuild takes seconds, and it grows with the log. Run `cairn admin fsck`
afterwards, and read `cairn --version` or `/healthz` to be sure which
build is answering.

### Watch it

A forge cannot report its own absence, so something else has to ask.
`cairn admin watch` asks once and remembers the answer:

```sh
cairn admin watch --url https://cairn.example --state /var/lib/cairn/watch.json --mail-to you@example
```

It fetches `/healthz`, compares with what it saw last time, and mails only
when that changes — down, then back — and once a day while it stays down.
It exits non-zero while the forge is down, so the timer's own status says
so as well. Mail uses the same settings as `serve` (`CAIRN_SMTP_URL` and
`CAIRN_MAIL_FROM`, or `CAIRN_MAIL_COMMAND`); without `--mail-to` the
answer is only printed. Run it every few minutes from a timer on a machine
that is not the forge. Run on the forge's own machine, it still catches a
hung process or a dead tunnel, but not the machine going away.

A laptop makes a fine second watcher while it is awake, and it needs no
mail credentials: hand the message to a command that shows it instead.
On macOS, a script such as

```sh
#!/bin/sh
# ~/.cairn/notify.sh — the message arrives on stdin
subject=$(grep -m1 '^Subject:' | cut -d' ' -f2-)
osascript -e "display notification \"$subject\" with title \"cairn\""
```

run from a launchd agent every five minutes with
`--mail-command ~/.cairn/notify.sh --mail-from cairn@laptop --mail-to you@laptop`
turns "down" and "back" into notifications.

### Check the record against itself

`cairn admin fsck --db <db> --repos <dir>` replays the log into empty
projections and compares, and checks that every branch contains what the
log says landed on it and that the tags in git are exactly the tags on
the record. It exits non-zero on any divergence. Run it after every
upgrade and from a timer; the reference instance runs it after every
deploy.

### Read what people report

`/report` is where anyone, signed in or not, says what broke: what they
did, where, and how to reach them if they like. The forge version is
recorded with it. Reports live beside the waitlist and outside the log,
so one can be removed when the person asks. Whoever runs the forge reads
them at `/reports` or with `cairn admin reports`, and, when the forge can
send mail, hears of each one at their confirmed address as it arrives.
The form is rate limited by source like the waitlist.

## When something is wrong

**The forge is down.** The watcher says so, or `/healthz` does not
answer. Look at the service's log first: `serve` refuses to start on a
git it cannot merge with, on a database it cannot open, and on a public
URL it cannot parse, and says which. Start it again; the first open after
a crash is an ordinary open. Then run fsck.

**fsck says a change is merged but its branch does not contain it.**
The merge was recorded and the process died before the branch moved. The
landing train repairs this by itself, at start and on every tick, by
moving the branch to what the log says landed. It is a repair only when
the branch still stands where the landing began; a branch that has moved
elsewhere is reported, not overwritten, and the report names the commit
the log expects. Look at the branch in the bare repository and decide;
nothing in the log is lost either way.

**fsck says a projection differs from the log.** That is a defect in
the forge, not in your data: the log is the truth and the projections are
derived from it. Say so at `/report` with the output. An upgrade that
changes the schema rebuilds every projection from the log, which is the
same repair.

**A mirror push failed.** It is recorded as a `mirror_pushed` event with
`ok: false` and the remote's own words, and the repository's owner is
told in their inbox. Fix the credential, the URL or the remote; the next
landing, or the next tag, pushes again, and since a mirror is a copy,
nothing was lost meanwhile.

**A change is stuck in the landing queue.** When the target moved and the
change no longer applies, the train records `rebase_failed`, takes the
change off the queue, and tells its owner which files collided. Push a
new revision on the current tip. A change can also be dequeued or
abandoned from its page.

**A runner disputed a claim.** The change is blocked, and the trace says
which claim. If the claim was wrong, push a revision that makes it true;
the runner re-runs the new revision and its earlier verdict no longer
counts. If the runner's environment was at fault, fix it and re-run: a
runner that re-runs replaces its own earlier verdict. A runner that
cannot run a command at all records nothing and says so, so a missing
tool on the runner's PATH shows up as a refusal, not a dispute.

**Somebody is locked out.** With mail, the sign-in page offers a reset
link and a sign-in link, each to a confirmed address. Without mail, or
without an address, the request reaches whoever runs the forge, who sends
a sign-in link from the People page. With file access, `cairn admin
set-password <slug>` and `cairn admin mint-token <slug>` work offline.

**Adding an address fails, or says to try again in a while.** Three
confirmation mails an hour is the allowance for one person; a refused
address does not spend it. An older instance whose contact table required
an address is reshaped on the first start of a newer binary.

**The signing key is gone.** The next start makes a new one, and the
forge's fingerprint changes; receipts already issued still verify against
the key they carry. Restore `signing.key` from a backup taken with the
database to keep the fingerprint.

**The disk is full.** The write that hit the limit failed whole and the
log is intact; free space and carry on. Nothing needs repairing.

**Mail does not arrive.** `cairn admin mail-check` reaches the relay,
negotiates TLS and authenticates without sending anything, and says
which step failed. Invitations and resets fall back to the People page.

## Reference

Offline administration, against the database file (root authority):

- `cairn admin bootstrap <slug>` — register the first human, give them
  the unscoped admin grant, print a token.
- `cairn admin mint-token <slug>` — mint an API token for an existing
  principal.
- `cairn admin set-password <slug>` — set a human's password, read from
  stdin so it never touches shell history or the process list.
- `cairn admin grant-admin <slug>` — give somebody the unscoped admin
  grant. Offline because over the API you would already need admin to
  grant admin.
- `cairn admin waitlist [--remove <email>]` — list the waitlist, or
  remove someone who asked to be forgotten.
- `cairn admin reports [--dismiss <id>]` — what people reported broke,
  newest first; or dismiss one.
- `cairn admin mail-check` — reach the relay and authenticate, sending
  nothing; reads the same flags and environment as `serve`.
- `cairn admin watch --url <forge> --state <file> [--mail-to <addr>]` —
  one look at a forge from outside; see Watch it.
- `cairn admin fsck [--db <db>] [--repos <dir>]` — the record against
  itself; see Check the record against itself.

Other commands: `cairn serve`, `cairn mcp --server <url> --token <t>`,
`cairn verify --server <url> --token <t> [--repo <r>] [<change>]`, and
`cairn receipt verify <file> [--key <fingerprint>]`.

`cairn serve` flags:

- `--db <path>` (default `cairn.db`), `--repos <dir>` (default `repos`),
  `--listen <addr>`.
- `--public-url <url>` or `CAIRN_PUBLIC_URL`: where people reach the
  forge; every mailed link and every passkey is bound to it.
- `--secure-cookies` behind HTTPS; `--trust-proxy` behind a reverse
  proxy; `--dev` for asserted identity on a laptop only.
- `--smtp-url`, `--mail-from`, `--mail-command`, or `CAIRN_SMTP_URL`,
  `CAIRN_MAIL_FROM`, `CAIRN_MAIL_COMMAND`.
- `--mirror-token <t>` or `CAIRN_MIRROR_TOKEN`: the credential mirror
  pushes carry.
- `--oidc-issuer`, `--oidc-client-id`, `--oidc-client-secret-file`,
  `--oidc-label`, `--oidc-link-by-email`; `--workload-issuer`
  (repeatable), `--workload-audience`.
- `--api-writes-per-minute <n>` (default 600, 0 for none).
- `--signing-key-file <path>` (default `signing.key` beside the database).

Files beside the database: `signing.key` (owner-only). Under `--repos`:
one bare repository per name. `/healthz` answers
`{"ok": true, "seq": <last event>, "version": "<version> (<build>)"}`.
`CAIRN_BUILD`, set when building, overrides the build stamp for whoever
packages from an archive without git.

## Development

```sh
cargo nextest run --workspace   # or: cargo test --workspace
cargo test --workspace --doc
cargo clippy --workspace --all-targets
cargo fmt
scripts/first-run.sh            # the documented first run, on an empty forge
```

Each crate's end-to-end tests are one binary (`tests/suite/main.rs`), so
the suite links once rather than once per file; a new test file needs a
`mod` line there. `cargo nextest run` (install with `cargo install
cargo-nextest --locked`) runs each test in its own process and stops a
hung test after two minutes; `.config/nextest.toml` holds the settings,
and its `ci` profile writes a JUnit report. Plain `cargo test` runs the
same tests and is what the verify runner falls back to.
