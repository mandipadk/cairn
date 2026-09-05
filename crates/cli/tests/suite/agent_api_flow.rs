//! The agent API's conventions: a write asked twice is done once, a
//! list that grows without bound comes in pages, and a caller who will
//! not wait is told how long to.

use crate::common::*;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

/// A request with the dev header, an optional idempotency key, and the
/// answer's headers kept - the conventions under test live in them.
async fn call(
    app: &Router,
    method: &str,
    path: &str,
    actor: &str,
    key: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, HeaderMap, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("x-cairn-principal", actor);
    if let Some(key) = key {
        request = request.header("idempotency-key", key);
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
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            panic!(
                "{method} {path} returned {status} with a body that is not JSON ({e}): {}",
                String::from_utf8_lossy(&bytes)
            )
        })
    };
    (status, headers, value)
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_write_asked_twice_is_done_once() {
    let forge = boot().await;
    let app = &forge.app;
    let task = json!({
        "repo": "demo", "title": "Only once",
        "spec": "A retry must not make a second task."
    });

    let (status, headers, first) = call(
        app,
        "POST",
        "/api/tasks",
        "ada",
        Some("k-1"),
        Some(task.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{first}");
    assert!(header(&headers, "idempotent-replayed").is_none());

    // The same request under the same key: the same answer, nothing new.
    let (status, headers, again) = call(
        app,
        "POST",
        "/api/tasks",
        "ada",
        Some("k-1"),
        Some(task.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(header(&headers, "idempotent-replayed"), Some("true"));
    assert_eq!(first, again, "the replay is the first answer, unchanged");
    let (_, _, tasks) = call(app, "GET", "/api/tasks", "ada", None, None).await;
    assert_eq!(
        tasks
            .as_array()
            .unwrap()
            .iter()
            .filter(|t| t["title"] == "Only once")
            .count(),
        1,
        "one task, not two: {tasks}"
    );

    // A different request under a used key is a mistake, and refused.
    let other = json!({ "repo": "demo", "title": "Something else", "spec": "Not the same." });
    let (status, _, refused) = call(
        app,
        "POST",
        "/api/tasks",
        "ada",
        Some("k-1"),
        Some(other.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{refused}");
    assert_eq!(refused["kind"], "idempotency_mismatch");

    // Keys are the caller's own: scout's k-1 has nothing to do with ada's.
    let (status, headers, _) = call(
        app,
        "POST",
        "/api/tasks",
        "scout",
        Some("k-1"),
        Some(task.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(header(&headers, "idempotent-replayed").is_none());

    // A refusal is an answer too, and is replayed as one.
    let (status, _, refused) = call(
        app,
        "POST",
        "/api/tasks/no-such-task/claim",
        "scout",
        Some("k-2"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{refused}");
    let (status, headers, replayed) = call(
        app,
        "POST",
        "/api/tasks/no-such-task/claim",
        "scout",
        Some("k-2"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(header(&headers, "idempotent-replayed"), Some("true"));
    assert_eq!(refused, replayed);

    // The key has to be a key.
    let (status, _, body) = call(
        app,
        "POST",
        "/api/tasks",
        "ada",
        Some(&"x".repeat(201)),
        Some(task.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["kind"], "invalid");

    // Reads have nothing to replay; the header is simply ignored.
    let (status, headers, _) = call(app, "GET", "/api/tasks", "ada", Some("k-1"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(header(&headers, "idempotent-replayed").is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn tasks_come_in_pages_newest_first() {
    let forge = boot().await;
    let app = &forge.app;
    for i in 1..=5 {
        let (status, _) = api(
            app,
            "POST",
            "/api/tasks",
            "ada",
            Some(json!({ "repo": "demo", "title": format!("Task {i}"), "spec": "paged" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }
    api(
        app,
        "POST",
        "/api/tasks",
        "ada",
        Some(json!({ "title": "Forge-wide", "spec": "belongs to no repo" })),
    )
    .await;

    let titles = |page: &Value| -> Vec<String> {
        page["tasks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["title"].as_str().unwrap().to_owned())
            .collect()
    };
    let (status, page) = api(app, "GET", "/api/tasks?limit=2&repo=demo", "ada", None).await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(titles(&page), ["Task 5", "Task 4"]);
    let cursor = page["next_before"].as_i64().expect("more to come");

    let (_, page) = api(
        app,
        "GET",
        &format!("/api/tasks?limit=2&repo=demo&before={cursor}"),
        "ada",
        None,
    )
    .await;
    assert_eq!(titles(&page), ["Task 3", "Task 2"]);
    let cursor = page["next_before"].as_i64().expect("one more page");

    let (_, page) = api(
        app,
        "GET",
        &format!("/api/tasks?limit=2&repo=demo&before={cursor}"),
        "ada",
        None,
    )
    .await;
    assert_eq!(titles(&page), ["Task 1"]);
    assert!(page["next_before"].is_null(), "the end says so: {page}");

    // Without a page asked for, the answer is what it always was: the
    // whole list, oldest first, now saying which event created each.
    let (_, all) = api(app, "GET", "/api/tasks?repo=demo", "ada", None).await;
    let all = all.as_array().unwrap();
    assert_eq!(all.len(), 5);
    assert_eq!(all[0]["title"], "Task 1");
    assert!(all[0]["seq"].as_i64().unwrap() < all[4]["seq"].as_i64().unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn the_inbox_pages_by_seq() {
    let forge = boot().await;
    let app = &forge.app;
    // Two things addressed to scout: a verdict on their change, and
    // authority given to them.
    let (status, opened) = api(
        app,
        "POST",
        "/api/changes",
        "scout",
        Some(json!({ "repo": "demo", "target": "main", "title": "Paged inbox" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{opened}");
    let change = opened["id"].as_str().unwrap();
    let (status, _) = api(
        app,
        "POST",
        &format!("/api/changes/{change}/revisions"),
        "scout",
        Some(json!({ "commit_oid": "a".repeat(40) })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, verdict) = api(
        app,
        "POST",
        &format!("/api/changes/{change}/verdicts"),
        "ada",
        Some(json!({
            "domain": "correctness", "disposition": "concern",
            "rationale": "Worth a second look."
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{verdict}");
    let (status, granted) = api(
        app,
        "POST",
        "/api/grants",
        "ada",
        Some(json!({ "grantee": "scout", "repo": "demo", "actions": ["review"] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{granted}");

    let (_, whole) = api(app, "GET", "/api/inbox", "scout", None).await;
    let all_seqs: Vec<i64> = whole["notices"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n["seq"].as_i64().unwrap())
        .collect();
    assert!(all_seqs.len() >= 2, "{whole}");
    assert!(whole["next_before"].is_null(), "everything fit: {whole}");

    // One at a time, following the cursor, arrives at the same list.
    let mut paged = Vec::new();
    let mut before: Option<i64> = None;
    loop {
        let path = match before {
            Some(seq) => format!("/api/inbox?limit=1&before={seq}"),
            None => "/api/inbox?limit=1".to_owned(),
        };
        let (status, page) = api(app, "GET", &path, "scout", None).await;
        assert_eq!(status, StatusCode::OK, "{page}");
        let notices = page["notices"].as_array().unwrap();
        assert!(notices.len() <= 1);
        paged.extend(notices.iter().map(|n| n["seq"].as_i64().unwrap()));
        match page["next_before"].as_i64() {
            Some(next) => before = Some(next),
            None => break,
        }
        assert!(paged.len() <= all_seqs.len() + 1, "the cursor must end");
    }
    assert_eq!(paged, all_seqs);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_caller_who_will_not_wait_is_told_how_long() {
    let forge = boot().await;
    let app = cairn_server::router(forge.state.clone().with_write_allowance(2));
    let task = |i: i32| json!({ "title": format!("Write {i}"), "spec": "counted" });

    for i in 0..2 {
        let (status, _, body) = call(&app, "POST", "/api/tasks", "ada", None, Some(task(i))).await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    let (status, headers, body) =
        call(&app, "POST", "/api/tasks", "ada", None, Some(task(2))).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["kind"], "rate_limited");
    let wait: u64 = header(&headers, "retry-after")
        .expect("Retry-After names the wait")
        .parse()
        .unwrap();
    assert!((1..=60).contains(&wait), "{wait}");
    assert_eq!(body["detail"]["retry_after"], wait);

    // Reading is not writing, and somebody else's allowance is their own.
    let (status, _, _) = call(&app, "GET", "/api/tasks", "ada", None, None).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, body) = call(&app, "POST", "/api/tasks", "scout", None, Some(task(3))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}
