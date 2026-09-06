//! Earned trust: a principal's record is the log counted, and a policy
//! can let it stand in for a requirement - within a path, never over an
//! objection, and only while the record holds.

use crate::common::*;

use axum::Router;
use axum::http::StatusCode;
use serde_json::{Value, json};

async fn ok(app: &Router, method: &str, path: &str, actor: &str, body: Option<Value>) -> Value {
    let (status, value) = api(app, method, path, actor, body).await;
    assert_eq!(status, StatusCode::OK, "{method} {path}: {value}");
    value
}

/// A change by scout with a claim naming a command and the given paths
/// on its revision, entered over the API.
async fn claimed_change(app: &Router, title: &str, paths: &[&str]) -> (String, String) {
    let opened = ok(
        app,
        "POST",
        "/api/changes",
        "scout",
        Some(json!({ "repo": "demo", "target": "main", "title": title })),
    )
    .await;
    let change = opened["id"].as_str().unwrap().to_owned();
    ok(
        app,
        "POST",
        &format!("/api/changes/{change}/revisions"),
        "scout",
        Some(json!({ "commit_oid": "c".repeat(40), "paths": paths })),
    )
    .await;
    let claimed = ok(
        app,
        "POST",
        &format!("/api/changes/{change}/claims"),
        "scout",
        Some(json!({
            "kind": "test", "passed": true, "summary": "green", "command": "exit 0"
        })),
    )
    .await;
    (change, claimed["id"].as_str().unwrap().to_owned())
}

async fn requirement(app: &Router, change: &str, needle: &str) -> Value {
    let trace = ok(
        app,
        "GET",
        &format!("/api/changes/{change}/readiness"),
        "ada",
        None,
    )
    .await;
    trace["requirements"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["description"].as_str().unwrap().contains(needle))
        .cloned()
        .unwrap_or_else(|| panic!("no requirement containing {needle:?} in {trace}"))
}

async fn set_trust_policy(app: &Router) {
    ok(
        app,
        "POST",
        "/api/repos/demo/policy",
        "ada",
        Some(json!({
            "require_executed_check": true,
            "independence": "none",
            "require_runner_verification": true,
            "runner_quorum": 1,
            "required_domains": [],
            "require_concerns_resolved": true,
            "attention_budget": null,
            "agents_act_in_sessions": false,
            "trust": {
                "min_reproduced_percent": 100,
                "min_claims": 2,
                "window_days": 90,
                "paths": ["docs/", "*.md"],
                "waives": ["runner_verification"]
            }
        })),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_record_is_earned_and_a_policy_can_spend_it_within_a_path() {
    let forge = boot().await;
    let app = &forge.app;
    ok(
        app,
        "POST",
        "/api/principals",
        "ada",
        Some(json!({ "id": "runner-a", "kind": "agent", "display": "Runner", "model": "sandbox", "harness": "aquaman" })),
    )
    .await;
    ok(
        app,
        "POST",
        "/api/grants",
        "ada",
        Some(json!({ "grantee": "runner-a", "actions": ["verify"] })),
    )
    .await;
    set_trust_policy(app).await;

    // Nothing on the record yet.
    let record = ok(app, "GET", "/api/principals/scout/record", "scout", None).await;
    assert_eq!(record["claims"], 0);
    assert!(record["reproduced_percent"].is_null(), "{record}");
    assert_eq!(record["window_days"], 90);

    // One judged claim: the bar wants two, and the trace says so.
    let (first, claim) = claimed_change(app, "First", &["src/lib.rs"]).await;
    ok(
        app,
        "POST",
        &format!("/api/claims/{claim}/verify"),
        "runner-a",
        Some(json!({ "agrees": true, "command": "exit 0", "observed": "ok" })),
    )
    .await;
    let (docs, _) = claimed_change(app, "Docs only", &["docs/guide.md", "README.md"]).await;
    let trust = requirement(app, &docs, "earned trust").await;
    assert_eq!(
        trust["satisfied"], true,
        "the line is informational: {trust}"
    );
    let evidence = trust["evidence"].as_str().unwrap();
    assert!(
        evidence.contains("not applied") && evidence.contains("1 judged claims, 2 needed"),
        "{evidence}"
    );
    assert_eq!(
        requirement(app, &docs, "runner reproduced").await["satisfied"],
        false
    );

    // A second judged claim clears the bar; the docs change lands on
    // scout's own claim, and the trace says exactly why.
    let (_, claim) = claimed_change(app, "Second", &["src/lib.rs"]).await;
    ok(
        app,
        "POST",
        &format!("/api/claims/{claim}/verify"),
        "runner-a",
        Some(json!({ "agrees": true, "command": "exit 0", "observed": "ok" })),
    )
    .await;
    let record = ok(app, "GET", "/api/principals/scout/record", "ada", None).await;
    assert_eq!(record["claims"], 3, "{record}");
    assert_eq!(record["judged"], 2);
    assert_eq!(record["reproduced"], 2);
    assert_eq!(record["reproduced_percent"], 100);
    let runner = requirement(app, &docs, "runner reproduced").await;
    assert_eq!(runner["satisfied"], true, "{runner}");
    let evidence = runner["evidence"].as_str().unwrap();
    assert!(
        evidence.starts_with("waived by earned trust: scout: 2 judged claims, 100% reproduced")
            && evidence.contains("all 2 path(s) match docs/, *.md"),
        "{evidence}"
    );
    let trace = ok(
        app,
        "GET",
        &format!("/api/changes/{docs}/readiness"),
        "ada",
        None,
    )
    .await;
    assert_eq!(trace["satisfied"], true, "{trace}");

    // A change reaching outside the trusted paths is not covered.
    assert_eq!(
        requirement(app, &first, "runner reproduced").await["satisfied"],
        true,
        "the first change was reproduced by a runner outright"
    );
    let (code, _) = claimed_change(app, "Code too", &["docs/x.md", "src/main.rs"]).await;
    let trust = requirement(app, &code, "earned trust").await;
    let evidence = trust["evidence"].as_str().unwrap();
    assert!(
        evidence.contains("not applied")
            && evidence.contains("1 path(s) outside docs/, *.md: src/main.rs"),
        "{evidence}"
    );
    assert_eq!(
        requirement(app, &code, "runner reproduced").await["satisfied"],
        false
    );

    // One human block on any of scout's changes suspends the waiver.
    ok(
        app,
        "POST",
        &format!("/api/changes/{code}/verdicts"),
        "ada",
        Some(json!({ "domain": "correctness", "disposition": "block", "rationale": "Not yet." })),
    )
    .await;
    let record = ok(app, "GET", "/api/principals/scout/record", "ada", None).await;
    assert_eq!(record["blocks"], 1, "{record}");
    assert_eq!(record["audits"], 1);
    let trust = requirement(app, &docs, "earned trust").await;
    let evidence = trust["evidence"].as_str().unwrap();
    assert!(
        evidence.contains("not applied") && evidence.contains("1 human block(s) in the window"),
        "{evidence}"
    );
    assert_eq!(
        requirement(app, &docs, "runner reproduced").await["satisfied"],
        false,
        "trust is earned continuously; a block takes it back"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_push_records_the_paths_its_commit_touched() {
    let forge = boot().await;
    let (app, addr) = (&forge.app, forge.addr);
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
    commit_file(
        &wc,
        "docs/guide.md",
        "# Guide\n",
        "Write the guide\n\nChange-Id: Iguide",
    );
    std::fs::write(wc.join("README.md"), "read me\n").unwrap();
    git(&wc, &["add", "."]);
    git(&wc, &["commit", "-q", "--amend", "--no-edit"]);
    git(&wc, &["push", "-q", "origin", "HEAD:refs/for/main"]);

    let changes = ok(app, "GET", "/api/repos/demo/changes", "ada", None).await;
    let change = changes[0]["id"].as_str().unwrap();
    let revisions = ok(
        app,
        "GET",
        &format!("/api/changes/{change}/revisions"),
        "ada",
        None,
    )
    .await;
    let mut paths: Vec<&str> = revisions[0]["paths"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p.as_str().unwrap())
        .collect();
    paths.sort_unstable();
    assert_eq!(paths, ["README.md", "docs/guide.md"], "{revisions}");
}

#[tokio::test(flavor = "multi_thread")]
async fn trust_is_set_and_cleared_from_the_policy_page() {
    let forge = boot().await;
    let app = &forge.app;
    let (_, ada) = sign_in_as(&forge, "ada").await;
    let (status, location) = post_form(
        app,
        "/demo/settings/policy",
        &ada,
        "action=save&require_executed_check=on&require_runner_verification=on&runner_quorum=1&independence=none&attention_budget=\
         &trust_waives=runner_verification&trust_waives=independent_approval&trust_percent=98&trust_claims=20&trust_days=90&trust_paths=docs%2F%2C+*.md",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{location}");
    let policy = ok(app, "GET", "/api/repos/demo/policy", "ada", None).await;
    assert_eq!(
        policy["trust"],
        json!({
            "min_reproduced_percent": 98, "min_claims": 20, "window_days": 90,
            "paths": ["docs/", "*.md"],
            "waives": ["runner_verification", "independent_approval"]
        }),
        "{policy}"
    );
    let (status, page) = page_with_cookie(app, "/demo/settings", &ada).await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains(r#"value="docs/, *.md""#), "{page}");

    // Nothing waived means no trust is spent, whatever the numbers say.
    let (status, _) = post_form(
        app,
        "/demo/settings/policy",
        &ada,
        "action=save&require_executed_check=on&independence=none&attention_budget=&trust_percent=98&trust_claims=20&trust_days=90",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let policy = ok(app, "GET", "/api/repos/demo/policy", "ada", None).await;
    assert!(policy["trust"].is_null(), "{policy}");
}
