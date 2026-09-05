//! MCP end-to-end: the real `cairn mcp` binary as a subprocess, speaking
//! newline-delimited JSON-RPC over stdio to a live forge server.

use cairn_core::{PrincipalId, PrincipalKind, Store};
use cairn_server::{AppState, router};
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

struct McpChild {
    child: Child,
    stdin: std::process::ChildStdin,
    lines: tokio::sync::mpsc::UnboundedReceiver<String>,
}

impl McpChild {
    fn spawn(server_url: &str, principal: &str) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_cairn"))
            .args(["mcp", "--server", server_url, "--principal", principal])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn cairn mcp");
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, lines) = tokio::sync::mpsc::unbounded_channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if !line.trim().is_empty() && tx.send(line).is_err() {
                    break;
                }
            }
        });
        McpChild {
            child,
            stdin,
            lines,
        }
    }

    fn send(&mut self, message: Value) {
        let mut line = message.to_string();
        line.push('\n');
        self.stdin
            .write_all(line.as_bytes())
            .expect("write to mcp stdin");
        self.stdin.flush().unwrap();
    }

    async fn recv(&mut self) -> Value {
        let line = tokio::time::timeout(Duration::from_secs(10), self.lines.recv())
            .await
            .expect("timed out waiting for mcp reply")
            .expect("mcp closed stdout");
        serde_json::from_str(&line).expect("mcp emitted invalid json")
    }

    /// Call a tool and return (parsed content json, isError).
    async fn call_tool(&mut self, id: i64, name: &str, arguments: Value) -> (Value, bool) {
        self.send(json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": { "name": name, "arguments": arguments }
        }));
        let reply = self.recv().await;
        assert_eq!(reply["id"], id, "reply id mismatch: {reply}");
        let result = &reply["result"];
        let text = result["content"][0]["text"].as_str().expect("text content");
        (
            serde_json::from_str(text).expect("tool content is json"),
            result["isError"].as_bool().unwrap_or(false),
        )
    }
}

impl Drop for McpChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn full_agent_workflow_over_mcp() {
    // A live forge with a human, an agent, a repo, and one open task.
    let mut store = Store::open_in_memory().unwrap();
    let ada = PrincipalId::new("ada").unwrap();
    let scout = PrincipalId::new("scout").unwrap();
    store
        .register_principal(&ada, &ada, PrincipalKind::Human, "Ada", None, None)
        .unwrap();
    store.grant_bootstrap_admin(&ada).unwrap();
    store
        .register_principal(
            &ada,
            &scout,
            PrincipalKind::Agent,
            "Scout",
            Some("claude-fable-5"),
            None,
        )
        .unwrap();
    store
        .create_repo(&ada, "demo", "main", cairn_core::ObjectFormat::Sha1)
        .unwrap();
    store
        .issue_grant(
            &ada,
            &scout,
            None,
            vec![cairn_core::Capability::Task, cairn_core::Capability::Push],
            None,
        )
        .unwrap();
    let (task, _) = store
        .create_task(
            &ada,
            Some("demo"),
            "Try the adapter",
            "Walk the protocol over MCP.",
            None,
        )
        .unwrap();

    let app = router(AppState::new(store).with_dev_identity());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(axum::serve(listener, app).into_future());

    let mut mcp = McpChild::spawn(&url, "scout");

    // Handshake: initialize echoes the requested protocol version.
    mcp.send(json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": { "protocolVersion": "2025-06-18",
                    "clientInfo": { "name": "test", "version": "0" } }
    }));
    let reply = mcp.recv().await;
    assert_eq!(reply["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(reply["result"]["serverInfo"]["name"], "cairn");
    mcp.send(json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));

    // Discovery: the protocol verbs are all present as tools.
    mcp.send(json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }));
    let reply = mcp.recv().await;
    let tools: Vec<&str> = reply["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    for expected in [
        "list_tasks",
        "claim_task",
        "open_session",
        "end_session",
        "open_change",
        "push_revision",
        "attach_claim",
        "give_verdict",
        "open_thread",
        "debt",
        "resolve_thread",
        "merge_readiness",
        "merge_change",
        "list_events",
    ] {
        assert!(
            tools.contains(&expected),
            "missing tool {expected}; got {tools:?}"
        );
    }

    // Workflow: find the open task, claim it, open a session.
    let (found, is_error) = mcp
        .call_tool(3, "list_tasks", json!({ "state": "open" }))
        .await;
    assert!(!is_error);
    assert_eq!(found[0]["id"], task.as_str());

    let (_, is_error) = mcp
        .call_tool(4, "claim_task", json!({ "task": task.as_str() }))
        .await;
    assert!(!is_error);

    let (session, is_error) = mcp
        .call_tool(5, "open_session", json!({ "task": task.as_str() }))
        .await;
    assert!(!is_error);
    let session_id = session["id"].as_str().unwrap().to_owned();
    // The server drew a credential and says so; the secret stays with it.
    assert!(session["credential"]["until"].is_string(), "{session}");
    assert!(session["credential"].get("token").is_none(), "{session}");

    // A typed API refusal surfaces as a tool error with the kind intact.
    let (conflict, is_error) = mcp
        .call_tool(6, "claim_task", json!({ "task": task.as_str() }))
        .await;
    assert!(is_error, "double-claim must be a tool error");
    assert_eq!(conflict["kind"], "conflict");

    // The session ends with knowledge, and the log saw everything.
    let (_, is_error) = mcp
        .call_tool(
            7,
            "end_session",
            json!({
                "session": session_id, "state": "completed",
                "outcome": "Exercised the MCP adapter end to end."
            }),
        )
        .await;
    assert!(!is_error);

    let (events, is_error) = mcp.call_tool(8, "list_events", json!({ "after": 0 })).await;
    assert!(!is_error);
    let kinds: Vec<&str> = events
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["kind"].as_str().unwrap())
        .collect();
    assert!(kinds.contains(&"task_claimed"));
    // The session ended, and the credential the server drew died with it.
    let n = kinds.len();
    assert_eq!(
        &kinds[n - 2..],
        ["session_ended", "session_credentials_revoked"],
        "{kinds:?}"
    );

    // Protocol edges: unknown method and unknown tool are typed errors.
    mcp.send(json!({ "jsonrpc": "2.0", "id": 9, "method": "resources/list" }));
    let reply = mcp.recv().await;
    assert_eq!(reply["error"]["code"], -32601);
    mcp.send(json!({
        "jsonrpc": "2.0", "id": 10, "method": "tools/call",
        "params": { "name": "no_such_tool", "arguments": {} }
    }));
    let reply = mcp.recv().await;
    assert_eq!(reply["error"]["code"], -32602);
}
