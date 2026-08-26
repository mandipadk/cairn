//! The claim underneath every other claim: current state is nothing
//! more than the log applied in order.
//!
//! If that is false, everything downstream is worthless — a policy trace
//! explains a merge only if the state it was evaluated against really
//! came from the events it cites. So this exercises a full working
//! forge, then replays the whole log into empty projections and demands
//! the same answer.
//!
//! The companion test that gives this one its meaning — that fsck
//! actually notices divergence, rather than always reporting "clean" —
//! lives in cairn-core, where a projection can be corrupted directly.

mod common;
use common::*;

use axum::http::StatusCode;
use serde_json::json;

#[tokio::test(flavor = "multi_thread")]
async fn a_full_flow_leaves_state_the_log_can_reproduce() {
    let forge = boot().await;
    let (app, addr) = (&forge.app, forge.addr);

    // Exercise as much of the vocabulary as one flow can: policy, tasks,
    // sessions, a real push, claims, verification, verdicts, a merge,
    // and an import. Events nobody replays are events nobody has tested.
    let (status, _) = api(
        app,
        "POST",
        "/api/repos/demo/policy",
        "ada",
        Some(json!({
            "require_executed_check": false,
            "require_runner_verification": false,
            "independence": "none",
            "required_domains": []
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (_, task) = api(
        app,
        "POST",
        "/api/tasks",
        "ada",
        Some(json!({ "title": "Land something real", "spec": "exercise the whole vocabulary" })),
    )
    .await;
    let task_id = task["id"].as_str().unwrap().to_owned();
    api(
        app,
        "POST",
        &format!("/api/tasks/{task_id}/claim"),
        "scout",
        Some(json!({})),
    )
    .await;
    let (_, session) = api(
        app,
        "POST",
        &format!("/api/tasks/{task_id}/sessions"),
        "scout",
        Some(json!({})),
    )
    .await;
    let session_id = session["id"].as_str().unwrap().to_owned();
    api(
        app,
        "POST",
        &format!("/api/sessions/{session_id}/paths"),
        "scout",
        Some(json!({ "repo": "demo", "paths": ["src/**"] })),
    )
    .await;

    git(
        &forge.work,
        &[
            "clone",
            "-q",
            &format!("http://scout:x@{addr}/git/demo"),
            "wc",
        ],
    );
    let wc = forge.work.join("wc");
    commit_file(&wc, "src/a.txt", "one\n", "First\n\nChange-Id: Ifsck1");
    git(&wc, &["push", "-q", "origin", "HEAD:refs/for/main"]);

    let (_, changes) = api(app, "GET", "/api/repos/demo/changes", "ada", None).await;
    let change = changes[0]["id"].as_str().unwrap().to_owned();
    let (_, claim) = api(
        app,
        "POST",
        &format!("/api/changes/{change}/claims"),
        "scout",
        Some(json!({
            "kind": "test",
            "command": "true",
            "passed": true,
            "summary": "it works",
            "unchecked": ["everything else"]
        })),
    )
    .await;
    let claim_id = claim["id"].as_str().unwrap().to_owned();
    api(
        app,
        "POST",
        &format!("/api/claims/{claim_id}/verify"),
        "ada",
        Some(json!({ "agrees": true, "command": "true", "observed": "exit 0" })),
    )
    .await;
    api(
        app,
        "POST",
        &format!("/api/changes/{change}/verdicts"),
        "ada",
        Some(json!({ "disposition": "approve", "domain": "correctness", "rationale": "read it" })),
    )
    .await;
    api(
        app,
        "POST",
        &format!("/api/changes/{change}/enqueue"),
        "ada",
        Some(json!({})),
    )
    .await;
    wait_for(app, "the change to land", async |app: &axum::Router| {
        let (_, c) = api(app, "GET", &format!("/api/changes/{change}"), "ada", None).await;
        c["state"] == "merged"
    })
    .await;

    // An import too, so a history_imported event is in the log.
    let elsewhere = forge.work.join("elsewhere.git");
    let seed = forge.work.join("seed");
    std::fs::create_dir_all(&seed).unwrap();
    std::process::Command::new("git")
        .args(["init", "--bare", "-b", "main", elsewhere.to_str().unwrap()])
        .output()
        .unwrap();
    git(&seed, &["init", "-q", "-b", "main"]);
    git(&seed, &["config", "user.email", "prior@example.test"]);
    git(&seed, &["config", "user.name", "Prior"]);
    commit_file(&seed, "old.txt", "old\n", "Older work");
    git(
        &seed,
        &["push", "-q", elsewhere.to_str().unwrap(), "main:main"],
    );
    api(
        app,
        "POST",
        "/api/repos",
        "ada",
        Some(json!({ "name": "brought-in", "default_branch": "main" })),
    )
    .await;
    let (status, _) = api(
        app,
        "POST",
        "/api/repos/brought-in/import",
        "ada",
        Some(json!({ "source": format!("file://{}", elsewhere.display()) })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // The whole point.
    let divergences = forge.state.fsck().expect("fsck should run");
    assert!(
        divergences.is_empty(),
        "state does not match the log: {divergences:#?}"
    );

    // And it is not vacuous: the log actually produced something.
    let (_, events) = api(app, "GET", "/api/events?after=0&limit=500", "ada", None).await;
    let kinds: Vec<&str> = events
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["kind"].as_str())
        .collect();
    for expected in [
        "repo_created",
        "policy_set",
        "task_created",
        "session_opened",
        "change_opened",
        "claim_attached",
        "claim_verified",
        "verdict_given",
        "change_merged",
        "history_imported",
    ] {
        assert!(
            kinds.contains(&expected),
            "the flow should have produced a {expected} event; got {kinds:?}"
        );
    }
}
