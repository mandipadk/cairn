#!/usr/bin/env bash
# Walk the first-run path that README.md and docs/operating.md describe, on
# an empty forge, with the binary this tree builds. Every step is what a
# newcomer would type; the script stops at the first one that does not do
# what the documents say. It is the command behind the claim that the
# documents are true, so a runner can re-run it.
set -euo pipefail
cd "$(dirname "$0")/.."

BIN=$(cargo build --quiet --bin cairn --message-format=json | python3 -c '
import json, sys
for line in sys.stdin:
    d = json.loads(line)
    if d.get("reason") == "compiler-artifact" and d.get("executable") and d["target"]["name"] == "cairn":
        print(d["executable"])' | tail -1)
[ -x "$BIN" ] || { echo "!! no cairn binary was built"; exit 1; }

W=$(mktemp -d)
SERVE=
trap '[ -n "$SERVE" ] && kill "$SERVE" 2>/dev/null; rm -rf "$W"' EXIT
cd "$W"
PORT=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
URL=http://127.0.0.1:$PORT

json() { python3 -c "import json, sys; d = json.load(sys.stdin); print($1)"; }
expect() { [ "$1" = "$2" ] || { echo "!! $3: expected $2, got $1"; exit 1; }; }
status() { curl -s -o /dev/null -w '%{http_code}' "$URL$1"; }
api() { curl -sS -X POST "$URL/api/$1" -H "Authorization: Bearer $2" -H 'content-type: application/json' -d "$3"; }
get() { curl -sS "$URL/api/$1" -H "Authorization: Bearer $2"; }
as_scout() { GIT_TERMINAL_PROMPT=0 git -c credential.helper= -c credential.helper="!f() { echo username=scout; echo password=$AGENT; }; f" "$@"; }
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1

echo "README: bootstrap, then serve"
TOKEN=$("$BIN" admin bootstrap --db forge.db you --display "You" | grep -oE 'cairn_[A-Za-z0-9_-]+' | head -1)
[ -n "$TOKEN" ] || { echo "!! bootstrap printed no token"; exit 1; }
"$BIN" serve --db forge.db --listen "127.0.0.1:$PORT" >serve.log 2>&1 &
SERVE=$!
for _ in $(seq 1 60); do curl -sf -m 1 "$URL/healthz" >/dev/null 2>&1 && break; sleep 0.5; done
curl -sf "$URL/healthz" >/dev/null || { echo "!! serve did not come up"; cat serve.log; exit 1; }
expect "$(status /)" 200 "the home page answers a stranger"
expect "$(status /login)" 200 "the sign-in page answers a stranger"

echo "operating.md: a repository, an agent, a grant, the agent's token"
expect "$(api repos "$TOKEN" '{"name": "demo"}' | json "d['event']['kind']")" repo_created "create a repository"
expect "$(api principals "$TOKEN" '{"id": "scout", "kind": "agent", "display": "Scout", "model": "claude-fable-5"}' | json "d['event']['kind']")" principal_registered "register an agent"
expect "$(api grants "$TOKEN" '{"grantee": "scout", "actions": ["task", "push"]}' | json "d['event']['kind']")" grant_issued "grant task and push"
AGENT=$(api principals/scout/tokens "$TOKEN" '{"label": "first-run"}' | json "d['token']")
[ -n "$AGENT" ] || { echo "!! no agent token was minted"; exit 1; }

echo "git: a private repository asks an anonymous clone for credentials; scout clones with the token"
if GIT_TERMINAL_PROMPT=0 git -c credential.helper= clone -q "$URL/git/demo" anon 2>/dev/null; then
  echo "!! a private repository was cloned without a token"; exit 1
fi
as_scout clone -q "$URL/git/demo" wc 2>/dev/null
cd wc
echo hello >hello.txt
git add hello.txt
git -c user.name=Scout -c user.email=scout@example.test commit -q -m $'Do the thing\n\nChange-Id: I8f3a1c2e'
as_scout push -q origin HEAD:refs/for/main 2>/dev/null
cd ..
CH=$(get repos/demo/changes "$TOKEN" | json "d[0]['id']")
expect "$(get repos/demo/changes "$TOKEN" | json "(d[0]['number'], d[0]['title'], d[0]['owner'])")" "(1, 'Do the thing', 'scout')" "the push opened change 1 owned by scout"

echo "README: attach a claim, read the readiness, approve, merge"
expect "$(api "changes/$CH/claims" "$AGENT" '{"kind": "test", "passed": true, "summary": "it says hello", "command": "test -f hello.txt"}' | json "d['id'][:3]")" "cl-" "scout attaches a claim"
expect "$(get "changes/$CH/readiness" "$TOKEN" | json "d['satisfied']")" False "readiness waits for an independent approval"
expect "$(api "changes/$CH/verdicts" "$TOKEN" '{"domain": "correctness", "disposition": "approve", "rationale": "It does the thing."}' | json "d['id'][:2]")" "v-" "you approve"
expect "$(api "changes/$CH/merge" "$TOKEN" '{}' | json "d['event']['kind']")" change_merged "the change lands"

echo "operating.md: the receipt verifies offline against the forge's key; the debt page counts the claim"
get "changes/$CH/receipt" "$TOKEN" >receipt.json
KEY=$(curl -sS "$URL/api/forge/key" | json "d['key']")
"$BIN" receipt verify receipt.json --key "$KEY" >/dev/null || { echo "!! the receipt did not verify"; exit 1; }
expect "$(get repos/demo/debt "$TOKEN" | json "d['counts']['claimed']")" 1 "the debt map counts one claimed line"
for p in /demo /demo/changes/1 /demo/debt /tasks /agents /people; do
  expect "$(status "$p")" 303 "a private page sends a stranger to sign in ($p)"
done

echo "README: an agent connects over MCP"
TOOLS=$(printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"first-run","version":"0"}}}' '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  | "$BIN" mcp --server "$URL" --token "$AGENT" 2>/dev/null | python3 -c '
import json, sys
n = 0
for line in sys.stdin:
    d = json.loads(line)
    if d["id"] == 2: n = len(d["result"]["tools"])
print(n)')
[ "$TOOLS" -gt 0 ] || { echo "!! MCP listed no tools"; exit 1; }

echo "operating.md: fsck"
kill "$SERVE"; wait "$SERVE" 2>/dev/null || true; SERVE=
"$BIN" admin fsck --db forge.db --repos repos | tail -1 | grep -q '^clean' || { echo "!! fsck is not clean"; exit 1; }
echo "first run: every documented step did what the documents say"
