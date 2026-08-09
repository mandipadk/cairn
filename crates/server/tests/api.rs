//! The protocol over real HTTP: full lifecycle, error surfaces, and the
//! SSE stream's exactly-once-in-order contract over a live socket.

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use cairn_server::{AppState, router};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tower::ServiceExt;

fn test_router() -> Router {
    // Dev identity is explicit here: these tests exercise the protocol,
    // not credentials. Token enforcement has its own test below.
    router(AppState::new(cairn_core::Store::open_in_memory().unwrap()).with_dev_identity())
}

async fn call(
    app: &Router,
    method: &str,
    path: &str,
    actor: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut request = Request::builder().method(method).uri(path);
    if let Some(actor) = actor {
        request = request.header("x-cairn-principal", actor);
    }
    let request = match body {
        Some(json) => request
            .header("content-type", "application/json")
            .body(Body::from(json.to_string())),
        None => request.body(Body::empty()),
    }
    .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, value)
}

/// Register the standard cast: human `ada`, agents `scout` and `arbiter`.
async fn seed(app: &Router) {
    let (status, _) = call(
        app,
        "POST",
        "/api/principals",
        Some("ada"),
        Some(json!({
            "id": "ada", "kind": "human", "display": "Ada"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    for (id, model) in [("scout", "claude-fable-5"), ("arbiter", "gpt-6")] {
        let (status, _) = call(
            app,
            "POST",
            "/api/principals",
            Some("ada"),
            Some(json!({
                "id": id, "kind": "agent", "display": id, "model": model
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }
    let (status, _) = call(
        app,
        "POST",
        "/api/repos",
        Some("ada"),
        Some(json!({
            "name": "demo"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // Agents act only under grants; ada delegates.
    for (grantee, actions) in [
        ("scout", json!(["task", "push", "review"])),
        ("arbiter", json!(["task", "review"])),
    ] {
        let (status, _) = call(
            app,
            "POST",
            "/api/grants",
            Some("ada"),
            Some(json!({ "grantee": grantee, "actions": actions })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }
}

const OID: &str = "0123456789abcdef0123456789abcdef01234567";

#[tokio::test]
async fn full_protocol_over_http() {
    let app = test_router();

    // No identity, no entry.
    let (status, body) = call(&app, "GET", "/api/tasks", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["kind"], "unauthenticated");

    seed(&app).await;

    // Intent.
    let (status, body) = call(
        &app,
        "POST",
        "/api/tasks",
        Some("ada"),
        Some(json!({
            "repo": "demo",
            "title": "Ship the demo",
            "spec": "Walk the whole protocol over HTTP."
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let task = body["id"].as_str().unwrap().to_owned();
    assert_eq!(body["event"]["kind"], "task_created");

    // Attempt: claim, then session.
    let (status, _) = call(
        &app,
        "POST",
        &format!("/api/tasks/{task}/claim"),
        Some("scout"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // Claiming twice conflicts, and the error is typed.
    let (status, body) = call(
        &app,
        "POST",
        &format!("/api/tasks/{task}/claim"),
        Some("arbiter"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["kind"], "conflict");
    let (status, body) = call(
        &app,
        "POST",
        &format!("/api/tasks/{task}/sessions"),
        Some("scout"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let session = body["id"].as_str().unwrap().to_owned();

    // Output.
    let (status, body) = call(
        &app,
        "POST",
        "/api/changes",
        Some("scout"),
        Some(json!({
            "repo": "demo", "target": "main", "title": "Demo change", "task": task
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let change = body["id"].as_str().unwrap().to_owned();
    assert_eq!(body["number"], 1);
    let (status, body) = call(
        &app,
        "POST",
        &format!("/api/changes/{change}/revisions"),
        Some("scout"),
        Some(json!({ "commit_oid": OID, "session": session, "message": "demo: first cut" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["revision"], 1);

    // Verification, with the honesty field intact on the way back out.
    let (status, _) = call(
        &app,
        "POST",
        &format!("/api/changes/{change}/claims"),
        Some("scout"),
        Some(json!({
            "kind": "test", "passed": true, "summary": "12 tests green",
            "command": "cargo test --workspace",
            "unchecked": ["load beyond 1k concurrent agents"]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = call(
        &app,
        "GET",
        &format!("/api/changes/{change}/claims"),
        Some("ada"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body[0]["unchecked"][0], "load beyond 1k concurrent agents");

    // Capability precedes policy: scout holds no merge capability.
    let (status, body) = call(
        &app,
        "POST",
        &format!("/api/changes/{change}/merge"),
        Some("scout"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["kind"], "forbidden");
    // A refused merge teaches: 409 plus the exact unmet requirements.
    let (status, body) = call(
        &app,
        "POST",
        &format!("/api/changes/{change}/merge"),
        Some("ada"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["kind"], "policy_unsatisfied");
    let unmet: Vec<&str> = body["detail"]["trace"]["requirements"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| !r["satisfied"].as_bool().unwrap())
        .map(|r| r["description"].as_str().unwrap())
        .collect();
    assert_eq!(unmet.len(), 1);
    assert!(unmet[0].contains("approved independently"));

    // Judgment (human), then the merge lands with its trace.
    let (status, _) = call(
        &app,
        "POST",
        &format!("/api/changes/{change}/verdicts"),
        Some("ada"),
        Some(json!({
            "domain": "correctness", "disposition": "approve",
            "rationale": "Exercised the flow end to end."
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = call(
        &app,
        "GET",
        &format!("/api/changes/{change}/readiness"),
        Some("scout"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["satisfied"], true);
    let (status, body) = call(
        &app,
        "POST",
        &format!("/api/changes/{change}/merge"),
        Some("ada"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["event"]["kind"], "change_merged");
    assert_eq!(body["event"]["trace"]["satisfied"], true);

    // Attempt closes with knowledge; the graph remembers everything.
    let (status, _) = call(
        &app,
        "POST",
        &format!("/api/sessions/{session}/end"),
        Some("scout"),
        Some(json!({ "state": "completed", "outcome": "Landed change 1 cleanly." })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = call(
        &app,
        "GET",
        "/api/events?after=0&limit=100",
        Some("ada"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let kinds: Vec<&str> = body
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds.first(), Some(&"principal_registered"));
    assert!(kinds.contains(&"change_merged"));
    assert_eq!(kinds.last(), Some(&"session_ended"));

    // Unknowns 404 with the typed kind.
    let (status, body) = call(&app, "GET", "/api/changes/c-nope", Some("ada"), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["kind"], "not_found");
}

/// Parse SSE fields out of a raw buffer (tolerating HTTP chunked framing):
/// returns (ids, event names) in arrival order.
fn parse_sse(buffer: &str) -> (Vec<i64>, Vec<String>) {
    let mut ids = Vec::new();
    let mut names = Vec::new();
    for line in buffer.lines() {
        if let Some(id) = line.strip_prefix("id: ") {
            if let Ok(id) = id.trim().parse() {
                ids.push(id);
            }
        } else if let Some(name) = line.strip_prefix("event: ") {
            names.push(name.trim().to_owned());
        }
    }
    (ids, names)
}

async fn read_until(stream: &mut TcpStream, buffer: &mut String, predicate: impl Fn(&str) -> bool) {
    read_until_within(stream, buffer, Duration::from_secs(5), predicate).await;
}

async fn read_until_within(
    stream: &mut TcpStream,
    buffer: &mut String,
    limit: Duration,
    predicate: impl Fn(&str) -> bool,
) {
    tokio::time::timeout(limit, async {
        let mut chunk = [0u8; 4096];
        while !predicate(buffer) {
            let n = stream.read(&mut chunk).await.expect("stream read");
            assert!(n > 0, "stream closed before condition met; got:\n{buffer}");
            buffer.push_str(&String::from_utf8_lossy(&chunk[..n]));
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for SSE condition; got:\n{buffer}"));
}

#[tokio::test]
async fn sse_stream_catches_up_heals_and_follows_live() {
    let app = test_router();
    seed(&app).await;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(axum::serve(listener, app.clone()).into_future());

    // Resume from cursor 2: catch-up must start at exactly seq 3.
    // (Seed events run past this cursor either way.)
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(
            b"GET /api/events/stream?after=2 HTTP/1.1\r\n\
              Host: cairn\r\n\
              x-cairn-principal: ada\r\n\
              Accept: text/event-stream\r\n\r\n",
        )
        .await
        .unwrap();

    let mut buffer = String::new();
    read_until(&mut stream, &mut buffer, |b| b.contains("repo_created")).await;
    assert!(buffer.contains("200 OK"));
    assert!(buffer.contains("text/event-stream"));

    // Live follow: a mutation made after connecting arrives on the wire.
    let (status, body) = call(
        &app,
        "POST",
        "/api/tasks",
        Some("ada"),
        Some(json!({
            "title": "Live event", "spec": "Prove the stream follows commits."
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let live_seq = body["seq"].as_i64().unwrap();
    read_until(&mut stream, &mut buffer, |b| b.contains("task_created")).await;

    let (ids, names) = parse_sse(&buffer);
    // Strictly ascending, gapless, starting exactly after the cursor.
    assert_eq!(ids.first(), Some(&3));
    assert!(
        ids.windows(2).all(|w| w[1] == w[0] + 1),
        "ids not gapless: {ids:?}"
    );
    assert_eq!(ids.last(), Some(&live_seq));
    assert_eq!(names.last().map(String::as_str), Some("task_created"));
    // The events carry their full envelopes.
    assert!(buffer.contains("\"actor\":\"ada\""));
}

#[tokio::test]
async fn last_event_id_header_overrides_query_cursor() {
    let app = test_router();
    seed(&app).await; // seeds events 1..=6

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(axum::serve(listener, app.clone()).into_future());

    // A reconnecting client sends Last-Event-ID; it must win over ?after=.
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(
            b"GET /api/events/stream?after=0 HTTP/1.1\r\n\
              Host: cairn\r\n\
              x-cairn-principal: ada\r\n\
              Last-Event-ID: 3\r\n\
              Accept: text/event-stream\r\n\r\n",
        )
        .await
        .unwrap();

    let mut buffer = String::new();
    read_until(&mut stream, &mut buffer, |b| !parse_sse(b).0.is_empty()).await;
    let (ids, _) = parse_sse(&buffer);
    assert_eq!(
        ids.first(),
        Some(&4),
        "resume must start after Last-Event-ID, got {ids:?}"
    );
}

#[tokio::test]
async fn concurrent_writers_keep_the_stream_gapless() {
    let app = test_router();
    seed(&app).await; // seeds events 1..=6
    const WRITERS: usize = 20;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(axum::serve(listener, app.clone()).into_future());

    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(
            b"GET /api/events/stream?after=0 HTTP/1.1\r\n\
              Host: cairn\r\n\
              x-cairn-principal: ada\r\n\
              Accept: text/event-stream\r\n\r\n",
        )
        .await
        .unwrap();

    // Hammer the API from many concurrent writers; their commit and
    // publish orders will interleave, which is exactly what the stream's
    // gap-healing must absorb.
    let writers: Vec<_> = (0..WRITERS)
        .map(|i| {
            let app = app.clone();
            tokio::spawn(async move {
                let (status, _) = call(
                    &app,
                    "POST",
                    "/api/tasks",
                    Some("ada"),
                    Some(json!({
                        "title": format!("Task {i}"),
                        "spec": "Concurrency probe."
                    })),
                )
                .await;
                assert_eq!(status, StatusCode::OK);
            })
        })
        .collect();
    for writer in writers {
        writer.await.unwrap();
    }

    let expected = 6 + WRITERS as i64;
    let mut buffer = String::new();
    read_until(&mut stream, &mut buffer, |b| {
        parse_sse(b).0.len() >= expected as usize
    })
    .await;
    let (ids, _) = parse_sse(&buffer);
    let want: Vec<i64> = (1..=expected).collect();
    assert_eq!(
        ids, want,
        "stream must be gapless and in order despite concurrent writers"
    );
}

/// Contention correctness: many agents race to claim one task; the
/// transactional core must crown exactly one winner, and everyone
/// else must get a typed conflict.
#[tokio::test(flavor = "multi_thread")]
async fn claim_storm_has_exactly_one_winner() {
    const AGENTS: usize = 30;
    let app = test_router();
    seed(&app).await;
    for i in 0..AGENTS {
        let (status, _) = call(
            &app,
            "POST",
            "/api/principals",
            Some("ada"),
            Some(json!({
                "id": format!("racer-{i}"), "kind": "agent", "display": format!("Racer {i}")
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(
            &app,
            "POST",
            "/api/grants",
            Some("ada"),
            Some(json!({ "grantee": format!("racer-{i}"), "actions": ["task"] })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }
    let (_, body) = call(
        &app,
        "POST",
        "/api/tasks",
        Some("ada"),
        Some(json!({
            "title": "Contended", "spec": "Exactly one of you may take this."
        })),
    )
    .await;
    let task = body["id"].as_str().unwrap().to_owned();

    let racers: Vec<_> = (0..AGENTS)
        .map(|i| {
            let app = app.clone();
            let task = task.clone();
            tokio::spawn(async move {
                let (status, _) = call(
                    &app,
                    "POST",
                    &format!("/api/tasks/{task}/claim"),
                    Some(&format!("racer-{i}")),
                    None,
                )
                .await;
                status
            })
        })
        .collect();
    let mut wins = 0;
    let mut conflicts = 0;
    for racer in racers {
        match racer.await.unwrap() {
            StatusCode::OK => wins += 1,
            StatusCode::CONFLICT => conflicts += 1,
            other => panic!("unexpected status {other}"),
        }
    }
    assert_eq!((wins, conflicts), (1, AGENTS - 1));

    // The projection agrees: claimed exactly once, by a racer.
    let (_, task_body) = call(
        &app,
        "GET",
        &format!("/api/tasks/{task}"),
        Some("ada"),
        None,
    )
    .await;
    assert_eq!(task_body["state"], "claimed");
    assert!(
        task_body["claimed_by"]
            .as_str()
            .unwrap()
            .starts_with("racer-")
    );
}

/// Sustained concurrent writes: the stream contract (every event,
/// exactly once, in order) and cursor pagination must both hold at a
/// scale well beyond the other tests. Correctness under concurrency,
/// not a benchmark.
#[tokio::test(flavor = "multi_thread")]
async fn sustained_concurrent_writes_keep_stream_and_pages_consistent() {
    const WRITERS: usize = 50;
    const PER_WRITER: usize = 30;
    let app = test_router();
    seed(&app).await; // events 1..=4

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(axum::serve(listener, app.clone()).into_future());
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(
            b"GET /api/events/stream?after=0 HTTP/1.1\r\n\
              Host: cairn\r\n\
              x-cairn-principal: ada\r\n\
              Accept: text/event-stream\r\n\r\n",
        )
        .await
        .unwrap();

    let writers: Vec<_> = (0..WRITERS)
        .map(|w| {
            let app = app.clone();
            tokio::spawn(async move {
                for i in 0..PER_WRITER {
                    let (status, _) = call(
                        &app,
                        "POST",
                        "/api/tasks",
                        Some("ada"),
                        Some(json!({
                            "title": format!("w{w} task {i}"),
                            "spec": "Sustained load probe."
                        })),
                    )
                    .await;
                    assert_eq!(status, StatusCode::OK);
                }
            })
        })
        .collect();
    for writer in writers {
        writer.await.unwrap();
    }

    let expected = (6 + WRITERS * PER_WRITER) as i64;
    let mut buffer = String::new();
    read_until_within(&mut stream, &mut buffer, Duration::from_secs(60), |b| {
        parse_sse(b).0.len() >= expected as usize
    })
    .await;
    let (ids, _) = parse_sse(&buffer);
    let want: Vec<i64> = (1..=expected).collect();
    assert_eq!(
        ids, want,
        "stream lost ordering or events under sustained load"
    );

    // Cursor pagination walks the same log without gaps or overlap.
    let mut cursor = 0i64;
    let mut total = 0usize;
    loop {
        let (status, page) = call(
            &app,
            "GET",
            &format!("/api/events?after={cursor}&limit=100"),
            Some("ada"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let page = page.as_array().unwrap().clone();
        if page.is_empty() {
            break;
        }
        for event in &page {
            let seq = event["seq"].as_i64().unwrap();
            assert_eq!(seq, cursor + 1, "pagination must be gapless");
            cursor = seq;
        }
        total += page.len();
    }
    assert_eq!(total as i64, expected);
}

/// The real credential path, dev identity OFF: tokens authenticate,
/// grants authorize, revocations bite immediately, and asserted
/// headers are worthless.
#[tokio::test]
async fn tokens_and_grants_enforce_without_dev_identity() {
    // Bootstrap happens out-of-band (cairn admin): first human + token.
    let mut store = cairn_core::Store::open_in_memory().unwrap();
    let ada = cairn_core::PrincipalId::new("ada").unwrap();
    store
        .register_principal(
            &ada,
            &ada,
            cairn_core::PrincipalKind::Human,
            "Ada",
            None,
            None,
        )
        .unwrap();
    let (_, ada_token, _) = store.mint_token(&ada, &ada, Some("bootstrap")).unwrap();
    let app = router(AppState::new(store));

    async fn call_auth(
        app: &Router,
        method: &str,
        path: &str,
        auth: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut request = Request::builder().method(method).uri(path);
        if let Some(auth) = auth {
            request = request.header("authorization", auth);
        }
        let request = match body {
            Some(json) => request
                .header("content-type", "application/json")
                .body(Body::from(json.to_string())),
            None => request.body(Body::empty()),
        }
        .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };
        (status, value)
    }

    // Asserted identity is refused when dev mode is off.
    let (status, _) = call(&app, "GET", "/api/tasks", Some("ada"), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // Garbage tokens are refused.
    let (status, _) = call_auth(&app, "GET", "/api/tasks", Some("Bearer cairn_nope"), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // The bootstrap token works; ada builds the world over HTTP.
    let ada_auth = format!("Bearer {ada_token}");
    let (status, _) = call_auth(
        &app,
        "POST",
        "/api/repos",
        Some(&ada_auth),
        Some(json!({
            "name": "demo"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = call_auth(
        &app,
        "POST",
        "/api/principals",
        Some(&ada_auth),
        Some(json!({
            "id": "drone", "kind": "agent", "display": "Drone", "model": "m"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, minted) = call_auth(
        &app,
        "POST",
        "/api/principals/drone/tokens",
        Some(&ada_auth),
        Some(json!({ "label": "ci" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let drone_token = minted["token"].as_str().unwrap().to_owned();
    let drone_auth = format!("Bearer {drone_token}");

    // Authenticated but ungranted: 403 with the fix spelled out.
    let (status, body) = call_auth(
        &app,
        "POST",
        "/api/tasks",
        Some(&drone_auth),
        Some(json!({
            "repo": "demo", "title": "T", "spec": "S"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body["error"].as_str().unwrap().contains("task"));

    // Granted: allowed. Revoked: refused again, immediately.
    let (status, granted) = call_auth(
        &app,
        "POST",
        "/api/grants",
        Some(&ada_auth),
        Some(json!({
            "grantee": "drone", "actions": ["task"], "repo": "demo"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = call_auth(
        &app,
        "POST",
        "/api/tasks",
        Some(&drone_auth),
        Some(json!({
            "repo": "demo", "title": "T", "spec": "S"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let grant = granted["id"].as_str().unwrap();
    let (status, _) = call_auth(
        &app,
        "POST",
        &format!("/api/grants/{grant}/revoke"),
        Some(&ada_auth),
        Some(json!({ "reason": "done" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = call_auth(
        &app,
        "POST",
        "/api/tasks",
        Some(&drone_auth),
        Some(json!({
            "repo": "demo", "title": "T2", "spec": "S"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Token metadata never leaks secrets; token revocation kills auth.
    let (_, tokens) = call_auth(
        &app,
        "GET",
        "/api/principals/drone/tokens",
        Some(&ada_auth),
        None,
    )
    .await;
    assert!(!tokens.to_string().contains(&drone_token));
    let token_id = minted["id"].as_str().unwrap();
    let (status, _) = call_auth(
        &app,
        "POST",
        &format!("/api/tokens/{token_id}/revoke"),
        Some(&ada_auth),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = call_auth(&app, "GET", "/api/tasks", Some(&drone_auth), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
