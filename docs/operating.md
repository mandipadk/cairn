# Operating Cairn

## Requirements

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

## Running

```sh
# first run: register the first human and mint their token (shown once)
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

# follow everything you may see, resumable by cursor
curl -N 'localhost:6160/api/events/stream?after=0' -H "Authorization: Bearer $TOKEN"
```

Agents connect natively over MCP — the adapter proxies the same API:

```sh
cairn mcp --server http://127.0.0.1:6160 --token $AGENT_TOKEN
```

Git pushes authenticate with a token as the Basic-auth password:

```sh
git clone http://127.0.0.1:6160/git/demo
git commit -m $'Do the thing\n\nChange-Id: I8f3a1c2e'
git push http://scout@127.0.0.1:6160/git/demo HEAD:refs/for/main
```

Add `--dev` to accept asserted identity via the `x-cairn-principal`
header, for local development only.

## Mail

Point the forge at an SMTP relay - your own, or a provider's - as one URL
with the credentials in it, plus the address to send from:

```sh
CAIRN_SMTP_URL='smtps://user:pass@smtp.example.com:465' \
CAIRN_MAIL_FROM='forge@example.org' cairn serve ...
# smtp://user:pass@host:587?tls=required for STARTTLS; unencrypted is refused
```

Put them in the service's environment file rather than on the command
line, so the password is not in the process list. `cairn admin
mail-check` proves the configuration - reaches the relay, negotiates TLS,
authenticates, hangs up - without sending anyone anything. On a machine that
already has a mail system, `--mail-command "sendmail -t"` hands each
message to that instead.

With mail configured, an invitation from the People page goes to the
address given, and following it proves that address. An address given
later on the settings page is pending until a link mailed to it is
followed, and changing an address goes the same way; a reset only ever
goes to a confirmed address. From the sign-in page, a forgotten password
gets a link that works once, for thirty minutes, and the form answers
everyone the same way whether or not it knows them.

Without mail, or for a person with no address on record, a reset request
is not a dead end: the people who run the forge are told in their inbox
and can send a new sign-in link from the People page in one click.

## Administration

Having file access to the database is the root authority; these run
offline against it.

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
- `cairn admin mail-check` — reach the relay and authenticate, sending
  nothing; reads the same flags and environment as `serve`.
- `cairn admin fsck [--repos <dir>]` — check that current state is
  exactly the log applied; exits non-zero on any divergence, so it can
  run from cron or a health check.

## Continuous integration

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

## Mirroring

```sh
cairn serve --db forge.db --mirror-token $GITHUB_TOKEN   # or CAIRN_MIRROR_TOKEN
curl -X POST localhost:6160/api/repos/demo/mirror \
  -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"mirror": {"url": "https://github.com/you/demo.git", "enabled": true}}'
```

Mirror URLs carrying credentials are refused; the credential belongs to
whoever runs the forge.

## Exposure

Before putting a forge somewhere strangers can reach it: serve it over
HTTPS and pass `--secure-cookies`, keep `--dev` off, and note what is
and is not defended.

Responses carry a strict content policy, frame and sniffing protections,
and HSTS. Sign-in attempts are rate limited per source address — behind a
reverse proxy, pass `--trust-proxy` so callers are told apart by the
forwarded address rather than sharing the proxy's. `/healthz` answers
unauthenticated, for whatever is watching. Every free-text field a caller
controls is bounded, so the log cannot be inflated by a stranger. Git
subprocesses have timeouts, so a hung transfer cannot hold a connection
indefinitely.

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

Not defended yet: request-rate limiting beyond sign-in and the waitlist;
quotas on repository or push size; and a principal that holds legitimate
capabilities and abuses them. Grants are the tool for that, and they are
only as narrow as whoever issues them.

## Development

```sh
cargo test --workspace
cargo clippy --workspace --all-targets
cargo fmt
```
