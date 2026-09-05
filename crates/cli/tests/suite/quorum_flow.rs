//! Runner quorum: a policy can ask that more than one machine's word
//! back a claim, and says what a machine's word is worth here.

use crate::common::*;

use axum::Router;
use axum::http::StatusCode;
use serde_json::{Value, json};

async fn register_runner(app: &Router, id: &str, harness: &str) {
    let (status, body) = api(
        app,
        "POST",
        "/api/principals",
        "ada",
        Some(json!({ "id": id, "kind": "agent", "display": id, "model": "sandbox", "harness": harness })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = api(
        app,
        "POST",
        "/api/grants",
        "ada",
        Some(json!({ "grantee": id, "actions": ["verify"] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// A change by scout with one claim naming a command; returns (change id, claim id).
async fn change_with_claim(app: &Router, title: &str) -> (String, String) {
    let (status, opened) = api(
        app,
        "POST",
        "/api/changes",
        "scout",
        Some(json!({ "repo": "demo", "target": "main", "title": title })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{opened}");
    let change = opened["id"].as_str().unwrap().to_owned();
    let (status, _) = api(
        app,
        "POST",
        &format!("/api/changes/{change}/revisions"),
        "scout",
        Some(json!({ "commit_oid": "b".repeat(40) })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, claimed) = api(
        app,
        "POST",
        &format!("/api/changes/{change}/claims"),
        "scout",
        Some(json!({
            "kind": "test", "passed": true, "summary": "the suite is green",
            "command": "exit 0"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{claimed}");
    (change, claimed["id"].as_str().unwrap().to_owned())
}

async fn verify(app: &Router, runner: &str, claim: &str, agrees: bool) -> Value {
    let (status, body) = api(
        app,
        "POST",
        &format!("/api/claims/{claim}/verify"),
        runner,
        Some(json!({
            "agrees": agrees, "command": "exit 0",
            "observed": if agrees { "exit 0, as claimed" } else { "exit 1" }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

/// The requirement the quorum adds to the trace, by its description.
async fn quorum_requirement(app: &Router, change: &str) -> Value {
    let (status, trace) = api(
        app,
        "GET",
        &format!("/api/changes/{change}/readiness"),
        "ada",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{trace}");
    trace["requirements"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| {
            r["description"]
                .as_str()
                .is_some_and(|d| d.contains("runners of distinct provenance"))
        })
        .cloned()
        .unwrap_or_else(|| panic!("no quorum requirement in {trace}"))
}

async fn awaiting(app: &Router, runner: &str) -> Vec<String> {
    let (status, waiting) = api(
        app,
        "GET",
        "/api/repos/demo/awaiting-verification",
        runner,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{waiting}");
    waiting
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap().to_owned())
        .collect()
}

async fn set_quorum(app: &Router, quorum: u32) {
    let (status, body) = api(
        app,
        "POST",
        "/api/repos/demo/policy",
        "ada",
        Some(json!({
            "require_executed_check": true,
            "independence": "none",
            "require_runner_verification": true,
            "runner_quorum": quorum,
            "required_domains": [],
            "require_concerns_resolved": true,
            "attention_budget": null,
            "agents_act_in_sessions": false
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn two_provenances_make_quorum_and_the_same_one_twice_does_not() {
    let forge = boot().await;
    let app = &forge.app;
    register_runner(app, "runner-a", "aquaman").await;
    register_runner(app, "runner-b", "aquaman").await;
    register_runner(app, "runner-c", "github-actions").await;
    register_runner(app, "runner-d", "somewhere-else").await;
    // An agent that can also push here: its word is evidence, not quorum.
    let (status, _) = api(
        app,
        "POST",
        "/api/grants",
        "ada",
        Some(json!({ "grantee": "arbiter", "repo": "demo", "actions": ["verify", "push"] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    set_quorum(app, 2).await;

    let (change, claim) = change_with_claim(app, "Needs two machines").await;
    let requirement = quorum_requirement(app, &change).await;
    assert_eq!(
        requirement["description"],
        "2 runners of distinct provenance reproduced the same claim on the latest revision"
    );
    assert_eq!(requirement["satisfied"], false);
    // Every runner is owed a run while nothing has been re-run.
    assert_eq!(awaiting(app, "runner-a").await, [change.as_str()]);
    assert_eq!(awaiting(app, "runner-c").await, [change.as_str()]);

    verify(app, "runner-a", &claim, true).await;
    let requirement = quorum_requirement(app, &change).await;
    assert_eq!(requirement["satisfied"], false);
    let evidence = requirement["evidence"].as_str().unwrap();
    assert!(
        evidence.contains("runner-a (aquaman) reproduced"),
        "{evidence}"
    );
    assert!(evidence.contains("1 of 2 provenances"), "{evidence}");
    // The runner that ran it is owed nothing more; the others still are.
    assert!(awaiting(app, "runner-a").await.is_empty());
    assert_eq!(awaiting(app, "runner-c").await, [change.as_str()]);

    // The same provenance again is the same machine's word twice.
    verify(app, "runner-b", &claim, true).await;
    let requirement = quorum_requirement(app, &change).await;
    assert_eq!(requirement["satisfied"], false);
    let evidence = requirement["evidence"].as_str().unwrap();
    assert!(evidence.contains("1 of 2 provenances"), "{evidence}");
    assert!(
        evidence.contains("runner-b reproduced")
            && evidence.contains("is also aquaman like runner-a"),
        "{evidence}"
    );

    // A principal holding more than verify is not a third party here.
    verify(app, "arbiter", &claim, true).await;
    let requirement = quorum_requirement(app, &change).await;
    assert_eq!(requirement["satisfied"], false);
    let evidence = requirement["evidence"].as_str().unwrap();
    assert!(
        evidence.contains("arbiter reproduced") && evidence.contains("holds more than verify here"),
        "{evidence}"
    );

    // A second provenance makes quorum, and nobody else is owed a run.
    verify(app, "runner-c", &claim, true).await;
    let requirement = quorum_requirement(app, &change).await;
    assert_eq!(requirement["satisfied"], true, "{requirement}");
    let evidence = requirement["evidence"].as_str().unwrap();
    assert!(evidence.contains("2 of 2 provenances"), "{evidence}");
    assert!(
        evidence.contains("runner-c (github-actions) reproduced"),
        "{evidence}"
    );
    assert!(
        awaiting(app, "runner-d").await.is_empty(),
        "quorum is met; no run is owed"
    );

    // Every third-party word is on the page as a run of the claim.
    let (status, page) =
        page_with_cookie(app, &format!("/demo/changes/{}", 1), "cairn_dev=ada").await;
    assert_eq!(status, StatusCode::OK);
    for who in ["runner-a", "runner-b", "runner-c", "arbiter"] {
        assert!(
            page.contains(&format!("{who} reproduced this")),
            "{who} missing from the page"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn runners_disagreeing_is_a_signal_and_a_block() {
    let forge = boot().await;
    let app = &forge.app;
    register_runner(app, "runner-a", "aquaman").await;
    register_runner(app, "runner-c", "github-actions").await;
    set_quorum(app, 2).await;

    let (change, claim) = change_with_claim(app, "Flaky somewhere").await;
    verify(app, "runner-a", &claim, true).await;
    verify(app, "runner-c", &claim, false).await;

    // Neither machine's word erases the other's: the change is blocked
    // by the dispute and a person is asked to look at the disagreement.
    let (_, trace) = api(
        app,
        "GET",
        &format!("/api/changes/{change}/readiness"),
        "ada",
        None,
    )
    .await;
    assert_eq!(trace["satisfied"], false);
    let disputed = trace["requirements"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["description"].as_str().unwrap().contains("disputed"))
        .unwrap();
    assert_eq!(disputed["satisfied"], false, "{disputed}");

    let (status, attention) = api(app, "GET", "/api/repos/demo/attention", "ada", None).await;
    assert_eq!(status, StatusCode::OK, "{attention}");
    let item = attention
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["change"]["id"] == change)
        .unwrap_or_else(|| panic!("the change is not in attention: {attention}"));
    let signal = item["signals"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["kind"] == "runners_disagree")
        .unwrap_or_else(|| panic!("no runners_disagree signal: {item}"));
    let evidence = signal["evidence"].as_str().unwrap();
    assert!(
        evidence.contains("runner-a reproduced")
            && evidence.contains("runner-c could not reproduce"),
        "{evidence}"
    );
    // It ranks above a plain dispute and below reviewers disagreeing.
    assert_eq!(signal["weight"], 92);

    // The disputing runner re-running and agreeing supersedes only its
    // own position, and the disagreement is gone.
    verify(app, "runner-c", &claim, true).await;
    let (_, trace) = api(
        app,
        "GET",
        &format!("/api/changes/{change}/readiness"),
        "ada",
        None,
    )
    .await;
    assert_eq!(trace["satisfied"], true, "{trace}");
    let (_, attention) = api(app, "GET", "/api/repos/demo/attention", "ada", None).await;
    let still = attention
        .as_array()
        .unwrap()
        .iter()
        .filter(|i| i["change"]["id"] == change)
        .flat_map(|i| i["signals"].as_array().unwrap().clone())
        .any(|s| s["kind"] == "runners_disagree");
    assert!(!still, "the disagreement was resolved by the runner itself");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_quorum_is_set_from_the_policy_page() {
    let forge = boot().await;
    let app = &forge.app;
    let (_, ada) = sign_in_as(&forge, "ada").await;
    let (status, location) = post_form(
        app,
        "/demo/settings/policy",
        &ada,
        "action=save&require_executed_check=on&require_runner_verification=on&runner_quorum=3&independence=none&attention_budget=",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{location}");
    let (_, policy) = api(app, "GET", "/api/repos/demo/policy", "ada", None).await;
    assert_eq!(policy["runner_quorum"], 3, "{policy}");
    assert_eq!(policy["require_runner_verification"], true);

    // The page shows the number it holds.
    let (status, page) = page_with_cookie(app, "/demo/settings", &ada).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        page.contains(r#"name="runner_quorum""#) && page.contains(r#"value="3""#),
        "{page}"
    );

    // Out of range is refused with a word, not saved.
    let (status, page) = post_form_page(
        app,
        "/demo/settings/policy",
        &ada,
        "action=save&require_runner_verification=on&runner_quorum=42&independence=none&attention_budget=",
    )
    .await;
    assert!(status.is_success() || status.is_redirection(), "{status}");
    let (_, policy) = api(app, "GET", "/api/repos/demo/policy", "ada", None).await;
    assert_eq!(
        policy["runner_quorum"], 3,
        "an out-of-range quorum must not be saved: {page}"
    );
}
