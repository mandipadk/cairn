//! MCP adapter: the forge protocol as tools for AI agents.
//!
//! `cairn mcp` speaks the Model Context Protocol over stdio (one
//! JSON-RPC 2.0 message per line) and proxies every tool call to a
//! running forge's HTTP API — the same API every other consumer uses,
//! carrying the same asserted principal. The adapter is deliberately
//! thin: tool schemas mirror the API request shapes, and API error
//! bodies (typed kinds, policy traces) pass through verbatim so the
//! agent can act on *why*, not just "no".
//!
//! Protocol scope: `initialize` (echoing the client's requested
//! version), `ping`, `tools/list`, `tools/call`. Notifications are
//! accepted and ignored. Stdout carries protocol only; logs go to
//! stderr.

use anyhow::Context;
use serde_json::{Value, json};
use std::io::{self, BufRead, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub fn run(server: &str, token: Option<&str>, principal: Option<&str>) -> anyhow::Result<()> {
    let client = ApiClient::new(server, token, principal);
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line.context("reading stdin")?;
        if line.trim().is_empty() {
            continue;
        }
        let Ok(message) = serde_json::from_str::<Value>(&line) else {
            write_message(
                &mut stdout,
                &error_response(Value::Null, -32700, "parse error"),
            )?;
            continue;
        };
        // Notifications (no id) require no reply.
        let Some(id) = message.get("id").cloned() else {
            continue;
        };
        let method = message
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let reply = match method {
            "initialize" => response(id, initialize_result(&message)),
            "ping" => response(id, json!({})),
            "tools/list" => response(id, json!({ "tools": tool_definitions() })),
            "tools/call" => match handle_call(&client, message.get("params")) {
                Ok(result) => response(id, result),
                Err(message) => error_response(id, -32602, &message),
            },
            "" => error_response(id, -32600, "invalid request: missing method"),
            other => error_response(id, -32601, &format!("method {other} not supported")),
        };
        write_message(&mut stdout, &reply)?;
    }
    Ok(())
}

fn write_message(out: &mut impl Write, message: &Value) -> anyhow::Result<()> {
    serde_json::to_writer(&mut *out, message)?;
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}

fn response(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn error_response(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn initialize_result(message: &Value) -> Value {
    let requested = message
        .pointer("/params/protocolVersion")
        .and_then(Value::as_str)
        .unwrap_or("2025-06-18");
    json!({
        "protocolVersion": requested,
        "capabilities": { "tools": {} },
        "serverInfo": { "name": "cairn", "version": env!("CARGO_PKG_VERSION") },
        "instructions": "You are a principal on a cairn forge: an event log of tasks \
            (intent), sessions (attempts), changes and revisions (output), claims \
            (verification), and verdicts (judgment), where merges are decided by policy. \
            Typical flow: list_tasks, claim_task, open_session, open_change, \
            push_revision, attach_claim, then check merge_readiness. Attach honest \
            claims including what you did NOT check. Always end your session with an \
            outcome written for the next reader, especially on failure. If a merge is \
            refused, the response names the exact unmet requirements. Every write \
            made through these tools carries its own idempotency key, so a call that \
            failed in transport is retried once without being done twice."
    })
}

/// A required string argument, with a machine-actionable absence message.
fn need<'a>(args: &'a Value, key: &str) -> Result<&'a str, String> {
    args.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing required argument: {key}"))
}

fn arg_str(args: &Value, key: &str) -> Option<String> {
    args.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn arg_num(args: &Value, key: &str) -> Option<String> {
    args.get(key).and_then(Value::as_i64).map(|n| n.to_string())
}

fn arg_flag(args: &Value, key: &str) -> Option<String> {
    (args.get(key).and_then(Value::as_bool) == Some(true)).then(|| "true".to_owned())
}

/// A path plus whichever query parameters were given, percent-encoded.
fn with_query(path: &str, params: &[(&str, Option<String>)]) -> String {
    let mut out = path.to_owned();
    let mut separator = '?';
    for (name, value) in params {
        if let Some(value) = value {
            out.push(separator);
            out.push_str(name);
            out.push('=');
            out.push_str(&encode(value));
            separator = '&';
        }
    }
    out
}

fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            other => format!("%{other:02X}"),
        })
        .collect()
}

fn handle_call(client: &ApiClient, params: Option<&Value>) -> Result<Value, String> {
    let params = params.ok_or("missing params")?;
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or("missing tool name")?;
    let default_args = json!({});
    let args = params.get("arguments").unwrap_or(&default_args);

    let (status, body) = dispatch(client, name, args)?;
    let text = serde_json::to_string_pretty(&body).unwrap_or_else(|_| body.to_string());
    Ok(json!({
        "content": [{ "type": "text", "text": text }],
        "isError": !(200..300).contains(&status),
    }))
}

/// Route one tool call to the HTTP API. Path parameters are pulled from
/// the arguments; the arguments object itself is forwarded as the body,
/// since tool schemas mirror API request shapes.
fn dispatch(client: &ApiClient, name: &str, args: &Value) -> Result<(u16, Value), String> {
    let call = match name {
        "list_tasks" => client.get(&with_query(
            "/api/tasks",
            &[
                ("state", arg_str(args, "state")),
                ("repo", arg_str(args, "repo")),
                ("before", arg_num(args, "before")),
                ("limit", arg_num(args, "limit")),
            ],
        )),
        "create_task" => client.post("/api/tasks", args),
        "get_task" => client.get(&format!("/api/tasks/{}", need(args, "task")?)),
        "claim_task" => client.post(&format!("/api/tasks/{}/claim", need(args, "task")?), args),
        // Opening a session draws its credential and acts under it from
        // here on; the agent never handles the secret. Ending the session
        // goes back to the standing credential.
        "open_session" => {
            let task = need(args, "task")?;
            (|| -> anyhow::Result<(u16, Value)> {
                let (status, mut opened) =
                    client.post(&format!("/api/tasks/{task}/sessions"), args)?;
                if status == 200
                    && let Some(id) = opened.get("id").and_then(Value::as_str).map(str::to_owned)
                {
                    let (drawn, credential) =
                        client.post(&format!("/api/sessions/{id}/credential"), &json!({}))?;
                    if drawn == 200
                        && let Some(token) = credential.get("token").and_then(Value::as_str)
                    {
                        client.adopt(token);
                        opened["credential"] = json!({
                            "until": credential["until"],
                            "scope": credential["scope"],
                            "note": "this server now acts under the session's credential; it dies when the session ends",
                        });
                    }
                }
                Ok((status, opened))
            })()
        }
        "end_session" => {
            let out = client.post(
                &format!("/api/sessions/{}/end", need(args, "session")?),
                args,
            );
            client.restore();
            out
        }
        "list_changes" => client.get(&with_query(
            &format!("/api/repos/{}/changes", need(args, "repo")?),
            &[
                ("state", arg_str(args, "state")),
                ("before", arg_num(args, "before")),
                ("limit", arg_num(args, "limit")),
            ],
        )),
        "get_change" => client.get(&format!("/api/changes/{}", need(args, "change")?)),
        "get_repo" => client.get(&format!("/api/repos/{}", need(args, "repo")?)),
        "get_session" => client.get(&format!("/api/sessions/{}", need(args, "session")?)),
        "list_revisions" => {
            client.get(&format!("/api/changes/{}/revisions", need(args, "change")?))
        }
        "list_claims" | "list_verdicts" | "list_verifications" => client.get(&with_query(
            &format!(
                "/api/changes/{}/{}",
                need(args, "change")?,
                name.trim_start_matches("list_")
            ),
            &[("revision", arg_num(args, "revision"))],
        )),
        "abandon_change" => client.post(
            &format!("/api/changes/{}/abandon", need(args, "change")?),
            args,
        ),
        "queue" => client.get(&with_query(
            &format!("/api/repos/{}/queue", need(args, "repo")?),
            &[("target", arg_str(args, "target"))],
        )),
        "awaiting_verification" => client.get(&format!(
            "/api/repos/{}/awaiting-verification",
            need(args, "repo")?
        )),
        "list_leases" => client.get(&format!("/api/repos/{}/leases", need(args, "repo")?)),
        "search" => client.get(&with_query(
            "/api/search",
            &[
                ("q", Some(need(args, "q")?.to_owned())),
                ("limit", arg_num(args, "limit")),
            ],
        )),
        "inbox" => client.get(&with_query(
            "/api/inbox",
            &[
                ("unread", arg_flag(args, "unread")),
                ("before", arg_num(args, "before")),
                ("limit", arg_num(args, "limit")),
            ],
        )),
        "mark_read" => client.post("/api/inbox/read", args),
        "get_thread" => client.get(&format!("/api/threads/{}", need(args, "thread")?)),
        "open_change" => client.post("/api/changes", args),
        "push_revision" => client.post(
            &format!("/api/changes/{}/revisions", need(args, "change")?),
            args,
        ),
        "attach_claim" => client.post(
            &format!("/api/changes/{}/claims", need(args, "change")?),
            args,
        ),
        "give_verdict" => client.post(
            &format!("/api/changes/{}/verdicts", need(args, "change")?),
            args,
        ),
        "open_thread" => client.post(
            &format!("/api/changes/{}/threads", need(args, "change")?),
            args,
        ),
        "list_threads" => {
            let change = need(args, "change")?;
            match args.get("state").and_then(Value::as_str) {
                Some(state) => client.get(&format!("/api/changes/{change}/threads?state={state}")),
                None => client.get(&format!("/api/changes/{change}/threads")),
            }
        }
        "reply_thread" => client.post(
            &format!("/api/threads/{}/reply", need(args, "thread")?),
            args,
        ),
        "resolve_thread" => client.post(
            &format!("/api/threads/{}/resolve", need(args, "thread")?),
            args,
        ),
        "merge_readiness" => {
            client.get(&format!("/api/changes/{}/readiness", need(args, "change")?))
        }
        "enqueue_change" => client.post(
            &format!("/api/changes/{}/enqueue", need(args, "change")?),
            args,
        ),
        "dequeue_change" => client.post(
            &format!("/api/changes/{}/dequeue", need(args, "change")?),
            args,
        ),
        "merge_change" => client.post(
            &format!("/api/changes/{}/merge", need(args, "change")?),
            args,
        ),
        "attention" => client.get(&format!("/api/repos/{}/attention", need(args, "repo")?)),
        "policy" => client.get(&format!("/api/repos/{}/policy", need(args, "repo")?)),
        "lessons" => client.get(&with_query(
            "/api/lessons",
            &[
                (
                    "limit",
                    Some(arg_num(args, "limit").unwrap_or_else(|| "20".to_owned())),
                ),
                ("repo", arg_str(args, "repo")),
                ("q", arg_str(args, "query")),
                ("failures_only", arg_flag(args, "failures_only")),
            ],
        )),
        "declare_paths" => client.post(
            &format!("/api/sessions/{}/paths", need(args, "session")?),
            args,
        ),
        "who_is_working_on" => client.get(&format!(
            "/api/repos/{}/conflicts?paths={}",
            need(args, "repo")?,
            need(args, "paths")?
        )),
        "verify_claim" => client.post(
            &format!("/api/claims/{}/verify", need(args, "claim")?),
            args,
        ),
        "debt" => client.get(&format!("/api/repos/{}/debt", need(args, "repo")?)),
        "blame" => client.get(&format!(
            "/api/repos/{}/blame?path={}",
            need(args, "repo")?,
            need(args, "path")?
        )),
        "list_events" => {
            let after = args.get("after").and_then(Value::as_i64).unwrap_or(0);
            let limit = args.get("limit").and_then(Value::as_i64).unwrap_or(100);
            client.get(&format!("/api/events?after={after}&limit={limit}"))
        }
        other => return Err(format!("unknown tool: {other}")),
    };
    call.map_err(|err| format!("forge unreachable: {err}"))
}

fn tool_definitions() -> Vec<Value> {
    fn tool(name: &str, description: &str, required: &[&str], properties: Value) -> Value {
        json!({
            "name": name,
            "description": description,
            "inputSchema": {
                "type": "object",
                "properties": properties,
                "required": required,
            }
        })
    }
    let s = |desc: &str| json!({ "type": "string", "description": desc });
    vec![
        tool(
            "list_tasks",
            "List tasks, optionally filtered by state and repo. Tasks are durable statements \
             of intent. Without `limit` or `before` the whole list comes back oldest first; \
             with either, one page newest first as {tasks, next_before}, where next_before \
             is the cursor for the next page or null at the end.",
            &[],
            json!({
                "state": { "type": "string", "enum": ["open", "claimed", "landed", "abandoned"] },
                "repo": s("Only tasks of this repo (optional)"),
                "before": { "type": "integer", "description": "Cursor from a previous page's next_before" },
                "limit": { "type": "integer", "description": "Page size, up to 200" },
            }),
        ),
        tool(
            "create_task",
            "Create a task: a durable statement of what should be done and why. The spec is \
             the intent future sessions will work from — write it complete.",
            &["title", "spec"],
            json!({
                "title": s("Short imperative title"),
                "spec": s("The full intent: what, why, constraints, acceptance criteria"),
                "repo": s("Repo this task concerns (optional)"),
                "parent": s("Parent task id, for decomposed work (optional)"),
            }),
        ),
        tool(
            "get_task",
            "Fetch one task by id.",
            &["task"],
            json!({ "task": s("Task id") }),
        ),
        tool(
            "claim_task",
            "Claim an open task before working on it. Claiming is the coordination point \
             that stops two agents burning effort on the same work; a claimed task \
             conflicts (409) for everyone else.",
            &["task"],
            json!({ "task": s("Task id") }),
        ),
        tool(
            "open_session",
            "Open a session: one run of work against a task you have claimed. From here on \
             this server acts under a credential drawn from the session - scoped to the \
             task's repository and your capabilities there, dead when the session ends - \
             and your standing token is not sent again until then.",
            &["task"],
            json!({ "task": s("Task id you claimed") }),
        ),
        tool(
            "end_session",
            "End your session honestly. The outcome is mandatory and is read by whoever \
             comes next: say what happened, what failed, and what you learned — failed \
             sessions are knowledge, not embarrassments.",
            &["session", "state", "outcome"],
            json!({
                "session": s("Session id"),
                "state": { "type": "string", "enum": ["completed", "failed"] },
                "outcome": s("What happened, written for the next reader"),
            }),
        ),
        tool(
            "list_changes",
            "List changes in a repo, with states and latest revisions. Without `limit` or \
             `before` the whole list comes back oldest first; with either, one page newest \
             first as {changes, next_before}, next_before being the cursor for the next \
             page or null at the end.",
            &["repo"],
            json!({
                "repo": s("Repo name"),
                "state": { "type": "string", "enum": ["open", "merged", "abandoned"] },
                "before": { "type": "integer", "description": "Cursor: a change number from a previous page's next_before" },
                "limit": { "type": "integer", "description": "Page size, up to 200" },
            }),
        ),
        tool(
            "get_change",
            "Fetch one change by id.",
            &["change"],
            json!({ "change": s("Change id") }),
        ),
        tool(
            "get_repo",
            "A repository's record: default branch, visibility, owner, policy, description.",
            &["repo"],
            json!({ "repo": s("Repo name") }),
        ),
        tool(
            "get_session",
            "One session: whose, on which task, active or ended, and its outcome.",
            &["session"],
            json!({ "session": s("Session id") }),
        ),
        tool(
            "list_revisions",
            "Every revision of a change, oldest first, each with its commit and the session \
             that pushed it.",
            &["change"],
            json!({ "change": s("Change id") }),
        ),
        tool(
            "list_claims",
            "The verification claims on a revision (latest by default): what was checked, \
             how, whether it passed, and what was declared unchecked. Read these before \
             judging a change, and before trusting one.",
            &["change"],
            json!({
                "change": s("Change id"),
                "revision": { "type": "integer", "description": "Revision number (defaults to latest)" },
            }),
        ),
        tool(
            "list_verdicts",
            "The review verdicts on a revision (latest by default), by domain and \
             disposition, with each reviewer's rationale.",
            &["change"],
            json!({
                "change": s("Change id"),
                "revision": { "type": "integer", "description": "Revision number (defaults to latest)" },
            }),
        ),
        tool(
            "list_verifications",
            "What runners saw when they re-ran the claims on a revision: reproduced or \
             disputed, with the command and what was observed.",
            &["change"],
            json!({
                "change": s("Change id"),
                "revision": { "type": "integer", "description": "Revision number (defaults to latest)" },
            }),
        ),
        tool(
            "abandon_change",
            "Abandon a change with a reason, on the record. The reason is read by whoever \
             picks the work up next, so say what was learned.",
            &["change", "reason"],
            json!({ "change": s("Change id"), "reason": s("Why it is being abandoned") }),
        ),
        tool(
            "queue",
            "The landing queue for a branch: what is waiting to land, in order.",
            &["repo"],
            json!({ "repo": s("Repo name"), "target": s("Branch (defaults to the repo's default)") }),
        ),
        tool(
            "awaiting_verification",
            "Open changes whose claims name a command nobody has re-run: the work queue \
             for a runner, and where an independent re-run is worth most.",
            &["repo"],
            json!({ "repo": s("Repo name") }),
        ),
        tool(
            "list_leases",
            "Every path currently declared by an active session in this repo, and by whom.",
            &["repo"],
            json!({ "repo": s("Repo name") }),
        ),
        tool(
            "search",
            "Ranked search over everything you may see: repositories, changes, tasks, \
             people. Plain words, plus `kind:`, `repo:`, `state:` and `by:` filters, or a \
             bare `#12` for a change by number. Ask before starting work whether it \
             already exists.",
            &["q"],
            json!({
                "q": s("The query"),
                "limit": { "type": "integer", "description": "Max hits (default 50, cap 200)" },
            }),
        ),
        tool(
            "inbox",
            "What has been addressed to you: verdicts on your changes, disputes on your \
             claims, authority given to you. Newest first, paged by `before`; each notice \
             says whether you have dealt with it.",
            &[],
            json!({
                "unread": { "type": "boolean", "description": "Only what you have not dealt with" },
                "before": { "type": "integer", "description": "Cursor from a previous page's next_before" },
                "limit": { "type": "integer", "description": "Page size, up to 500" },
            }),
        ),
        tool(
            "mark_read",
            "Mark one notice, or everything so far, dealt with.",
            &[],
            json!({
                "seq": { "type": "integer", "description": "The notice's seq" },
                "all": { "type": "boolean", "description": "Everything up to now" },
            }),
        ),
        tool(
            "get_thread",
            "One discussion thread with its anchor, replies and resolution.",
            &["thread"],
            json!({ "thread": s("Thread id") }),
        ),
        tool(
            "open_change",
            "Open a change: a unit of code with stable identity across revisions. Link it \
             to the task it serves; use parent_change to stack on an open change.",
            &["repo", "target", "title"],
            json!({
                "repo": s("Repo name"),
                "target": s("Target branch, e.g. main"),
                "title": s("What this change does"),
                "task": s("Task id this change serves (optional)"),
                "parent_change": s("Change id this stacks on (optional)"),
                "external_key": s("Stable client-chosen key, e.g. a Change-Id trailer (optional)"),
            }),
        ),
        tool(
            "push_revision",
            "Record a new revision of a change from a commit already in the repo.",
            &["change", "commit_oid"],
            json!({
                "change": s("Change id"),
                "commit_oid": s("Full commit oid (40 or 64 hex chars)"),
                "session": s("Your session id, for provenance (recommended)"),
                "message": s("Commit message"),
            }),
        ),
        tool(
            "attach_claim",
            "Attach a verification claim to a revision: what you checked, how, whether it \
             passed — and, in `unchecked`, what you deliberately did NOT verify. Honest \
             coverage statements are what make your work reviewable at speed.",
            &["change", "kind", "passed", "summary"],
            json!({
                "change": s("Change id"),
                "revision": { "type": "integer", "description": "Revision number (defaults to latest)" },
                "kind": { "type": "string", "enum": ["test", "lint", "typecheck", "build", "manual", "reasoning"] },
                "command": s("Exact reproducible command (strongly recommended)"),
                "passed": { "type": "boolean" },
                "summary": s("What the check showed"),
                "unchecked": { "type": "array", "items": { "type": "string" },
                               "description": "What this claim does not cover" },
            }),
        ),
        tool(
            "give_verdict",
            "Give a typed review verdict on a revision. Blocks veto merging; concerns are \
             recorded but do not veto. Rationale is mandatory — judgment without reasons \
             doesn't compose.",
            &["change", "domain", "disposition", "rationale"],
            json!({
                "change": s("Change id"),
                "revision": { "type": "integer", "description": "Revision number (defaults to latest)" },
                "domain": { "type": "string", "enum": ["correctness", "security", "design", "style"] },
                "disposition": { "type": "string", "enum": ["approve", "concern", "block"] },
                "rationale": s("Why"),
            }),
        ),
        tool(
            "open_thread",
            "Start a discussion on a change, anchored to a diff line, a claim, a verdict, or \
             the change itself. Kinds mean things: a `concern` must be resolved before the \
             change can land; a `question` should be answered; a `note` is for the record.",
            &["change", "anchor", "kind", "body"],
            json!({
                "change": s("Change id"),
                "revision": { "type": "integer", "description": "Revision the thread is on (defaults to latest; a claim or verdict anchor pins its own)" },
                "anchor": {
                    "type": "object",
                    "description": "What the thread is about",
                    "required": ["on"],
                    "properties": {
                        "on": { "type": "string", "enum": ["line", "claim", "verdict", "change"] },
                        "path": s("File path, for a line anchor"),
                        "side": { "type": "string", "enum": ["old", "new"], "description": "Which side of the diff the line number counts on (line anchors)" },
                        "line": { "type": "integer", "description": "Line number, counted from 1 (line anchors)" },
                        "claim": s("Claim id (claim anchors)"),
                        "verdict": s("Verdict id (verdict anchors)"),
                    }
                },
                "kind": { "type": "string", "enum": ["question", "concern", "note"] },
                "body": s("What you want to say"),
            }),
        ),
        tool(
            "list_threads",
            "List the discussion on a change: every thread with its anchor, replies and \
             resolution, oldest first. `state=open` shows what still stands.",
            &["change"],
            json!({
                "change": s("Change id"),
                "state": { "type": "string", "enum": ["open", "resolved"] },
            }),
        ),
        tool(
            "reply_thread",
            "Reply in a thread.",
            &["thread", "body"],
            json!({ "thread": s("Thread id"), "body": s("Your reply") }),
        ),
        tool(
            "resolve_thread",
            "Close a thread and say how: `answered` in the thread; `fixed` by a later \
             revision you name; `withdrawn` (only by whoever opened it); or `overruled` \
             (the change's owner or a reviewer, on the record). Resolving is an event; it \
             cannot be undone quietly.",
            &["thread", "how"],
            json!({
                "thread": s("Thread id"),
                "how": { "type": "string", "enum": ["answered", "fixed", "withdrawn", "overruled"] },
                "revision": { "type": "integer", "description": "The revision that fixed it (required for `fixed`)" },
                "note": s("A word on why (optional)"),
            }),
        ),
        tool(
            "merge_readiness",
            "Dry-run the merge policy: every requirement, satisfied or not, with evidence. \
             Use this to learn what to do next instead of attempting blind merges.",
            &["change"],
            json!({ "change": s("Change id") }),
        ),
        tool(
            "enqueue_change",
            "Enter the landing queue: once enqueued, the forge lands the change for you \
             — rebasing onto the moved target if needed — or dequeues it with a reason \
             event saying exactly why it could not land. Requires policy to already be \
             satisfied. Prefer this over merge_change when the target branch is busy.",
            &["change"],
            json!({ "change": s("Change id") }),
        ),
        tool(
            "dequeue_change",
            "Withdraw a change from the landing queue.",
            &["change", "reason"],
            json!({ "change": s("Change id"), "reason": s("Why it is being withdrawn") }),
        ),
        tool(
            "merge_change",
            "Merge a change if policy allows. A refusal returns the full policy trace \
             naming the unmet requirements.",
            &["change"],
            json!({ "change": s("Change id") }),
        ),
        tool(
            "policy",
            "The rules this repository requires before anything lands on it: whether an \
             executed check is needed, who counts as an independent approver, whether a \
             runner must have reproduced a claim, and which review domains must sign off. \
             Read it before you plan your verification, so you produce what will actually \
             be required rather than what usually is.",
            &["repo"],
            json!({ "repo": s("Repo name") }),
        ),
        tool(
            "lessons",
            "Has anyone tried this before? Search what earlier sessions recorded on their \
             way out — especially the ones that failed, where the outcome says what did \
             not work and why. Ask before starting work that resembles something already \
             attempted; the corpus exists because every session must record an outcome.",
            &[],
            json!({
                "query": s("Words to look for in outcomes and task titles"),
                "repo": s("Limit to one repo (optional)"),
                "failures_only": { "type": "boolean", "description": "Only failed attempts" },
                "limit": { "type": "integer", "description": "Max results (default 20)" },
            }),
        ),
        tool(
            "declare_paths",
            "Say which paths your session expects to change, before you start changing \
             them. The forge answers with anyone else already working there — including \
             whether they have already pushed code, which means a rebase is coming rather \
             than merely possible. Nothing is refused; you decide whether to narrow your \
             scope, wait, or continue knowing. Re-declaring replaces your previous \
             declaration, so narrowing releases ground you no longer need.",
            &["session", "repo", "paths"],
            json!({
                "session": s("Your active session id"),
                "repo": s("Repo name"),
                "paths": { "type": "array", "items": { "type": "string" },
                           "description": "Paths or prefixes, e.g. crates/core/ or src/main.rs" },
            }),
        ),
        tool(
            "who_is_working_on",
            "Who has declared intent over these paths right now. Ask before claiming work \
             so two agents do not spend a session each on the same files.",
            &["repo", "paths"],
            json!({
                "repo": s("Repo name"),
                "paths": s("Comma-separated paths or prefixes"),
            }),
        ),
        tool(
            "attention",
            "What in this repo is worth a human's judgment right now, ranked, with the \
             signals behind each ranking: reviewers disagreeing, a disputed claim, work \
             resting on argument alone, claims nobody re-ran, declared gaps, and changes \
             the sampling policy drew for a look. Use it to decide what to escalate to a \
             person rather than guessing, and to see where your own work sits.",
            &["repo"],
            json!({ "repo": s("Repo name") }),
        ),
        tool(
            "verify_claim",
            "Re-run someone else's claim and report what you actually saw. Requires the \
             verify capability, and you may not verify your own claim. A claim you cannot \
             reproduce blocks the change from landing until it is resolved — which is the \
             point: claims are contracts, not assertions.",
            &["claim", "agrees", "command", "observed"],
            json!({
                "claim": s("Claim id to re-run"),
                "agrees": { "type": "boolean", "description": "Did your run reproduce the claim's result?" },
                "command": s("The command you actually executed"),
                "observed": s("What you saw"),
            }),
        ),
        tool(
            "debt",
            "What backs every line of a repository, by file, most debt first. Each line is \
             one of: reproduced (a runner re-ran the claim that landed it), claimed (its \
             author ran something nobody re-ran), gap (a claim named it unchecked), argued \
             (only a reasoning claim), imported (from before the forge; never judged here). \
             Use it to see where your own verification is worth most before you touch a file.",
            &["repo"],
            json!({ "repo": s("Repo name") }),
        ),
        tool(
            "blame",
            "Before changing code you did not write: what is known about each line of a \
             file — the change that landed it, its state (reproduced, claimed, gap, argued, \
             imported), whether an executed check ever covered it, and what its claims \
             explicitly left unverified. Anything but reproduced is where your own \
             verification matters most.",
            &["repo", "path"],
            json!({ "repo": s("Repo name"), "path": s("File path within the repo") }),
        ),
        tool(
            "list_events",
            "Read the event log after a cursor — the full causal history of the forge. \
             Remember the last seq you saw and resume from it.",
            &[],
            json!({
                "after": { "type": "integer", "description": "Cursor: last seq already seen (default 0)" },
                "limit": { "type": "integer", "description": "Max events (default 100, cap 1000)" },
            }),
        ),
    ]
}

struct ApiClient {
    agent: ureq::Agent,
    base: String,
    /// The credential this process was started with.
    standing: (&'static str, String),
    /// Header name and value in use: the standing credential, or a
    /// session's while one is open. A Bearer token normally, the
    /// asserted dev header against dev-mode servers.
    auth: std::sync::Mutex<(&'static str, String)>,
    /// Makes each write's idempotency key its own.
    writes: AtomicU64,
}

impl ApiClient {
    fn new(server: &str, token: Option<&str>, principal: Option<&str>) -> Self {
        let config = ureq::Agent::config_builder()
            // 4xx/5xx are protocol answers here (typed kinds, policy
            // traces), not transport failures — pass bodies through.
            .http_status_as_error(false)
            .build();
        let auth = match (token, principal) {
            (Some(token), _) => ("Authorization", format!("Bearer {token}")),
            (None, Some(principal)) => ("x-cairn-principal", principal.to_owned()),
            (None, None) => unreachable!("main validates token or principal"),
        };
        ApiClient {
            agent: config.into(),
            base: server.trim_end_matches('/').to_owned(),
            standing: auth.clone(),
            auth: std::sync::Mutex::new(auth),
            writes: AtomicU64::new(0),
        }
    }

    /// A key no other write from this process has used. Keys are scoped
    /// to the principal on the forge, so they need only be unique here.
    fn fresh_key(&self) -> String {
        let n = self.writes.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        format!("mcp-{}-{nanos:x}-{n}", std::process::id())
    }

    fn header(&self) -> (&'static str, String) {
        self.auth
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Act with a session's credential from here on.
    fn adopt(&self, token: &str) {
        *self
            .auth
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            ("Authorization", format!("Bearer {token}"));
    }

    /// Back to the standing credential, once the session is over.
    fn restore(&self) {
        *self
            .auth
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = self.standing.clone();
    }

    fn get(&self, path: &str) -> anyhow::Result<(u16, Value)> {
        let mut response = self
            .agent
            .get(format!("{}{path}", self.base))
            .header(self.header().0, &self.header().1)
            .call()?;
        Ok((response.status().as_u16(), response.body_mut().read_json()?))
    }

    /// Every write carries its own idempotency key, so a transport
    /// failure - which says nothing about whether the forge received
    /// the write - can be followed by one more attempt under the same
    /// key: answered if it did arrive, done if it did not, never twice.
    fn post(&self, path: &str, body: &Value) -> anyhow::Result<(u16, Value)> {
        let key = self.fresh_key();
        let mut attempts = 0;
        loop {
            attempts += 1;
            let (name, value) = self.header();
            let sent = self
                .agent
                .post(format!("{}{path}", self.base))
                .header(name, &value)
                .header("Idempotency-Key", &key)
                .send_json(body);
            match sent {
                Ok(mut response) => {
                    return Ok((response.status().as_u16(), response.body_mut().read_json()?));
                }
                Err(_) if attempts < 2 => std::thread::sleep(Duration::from_millis(250)),
                Err(err) => return Err(err.into()),
            }
        }
    }
}
