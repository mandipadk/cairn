//! Human attention as a budget: the policy draws the changes most worth
//! a look, up to a daily allowance, on the record; a drawn change waits
//! for a human before it lands, and nothing else is asked of anyone.

use crate::common::*;
use axum::http::StatusCode;
use serde_json::{Value, json};

async fn set_budget(forge: &Forge, budget: Value) {
    let (status, body) = api(
        &forge.app,
        "POST",
        "/api/repos/demo/policy",
        "ada",
        Some(json!({
            "require_executed_check": false,
            "independence": "human_or_two_models",
            "require_runner_verification": false,
            "required_domains": [],
            "attention_budget": budget
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// A change by scout that rests on argument alone, so attention ranks it.
async fn argued_change(forge: &Forge, title: &str) -> String {
    let (status, change) = api_with_token(
        &forge.app,
        "POST",
        "/api/changes",
        &forge.scout_token,
        Some(json!({ "repo": "demo", "target": "main", "title": title })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{change}");
    let id = change["id"].as_str().unwrap().to_owned();
    api_with_token(
        &forge.app,
        "POST",
        &format!("/api/changes/{id}/revisions"),
        &forge.scout_token,
        Some(json!({ "commit_oid": format!("{:0>40}", title.len()), "message": title })),
    )
    .await;
    api_with_token(
        &forge.app,
        "POST",
        &format!("/api/changes/{id}/claims"),
        &forge.scout_token,
        Some(json!({ "kind": "reasoning", "passed": true, "summary": "argued", "unchecked": ["all of it"] })),
    )
    .await;
    id
}

async fn draw(forge: &Forge, day: &str) -> Value {
    let (status, body) = api(
        &forge.app,
        "POST",
        &format!("/api/repos/demo/attention/draw?day={day}"),
        "ada",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

fn requirement<'a>(readiness: &'a Value, needle: &str) -> Option<&'a Value> {
    readiness["requirements"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["description"].as_str().unwrap().contains(needle))
}

#[tokio::test(flavor = "multi_thread")]
async fn the_budget_draws_the_top_change_a_day_and_the_draw_waits_for_a_human() {
    let forge = boot().await;
    let app = &forge.app;
    let first = argued_change(&forge, "First argued").await;
    let second = argued_change(&forge, "Second argued").await;

    // Without a budget nothing is drawn, whatever wants attention.
    let (status, nothing) = api(app, "POST", "/api/repos/demo/attention/draw", "ada", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(nothing["drawn"].as_array().unwrap().len(), 0);

    set_budget(&forge, json!(1)).await;
    let (_, before) = api(app, "GET", "/api/repos/demo/attention", "ada", None).await;
    assert_eq!(
        before.as_array().unwrap().len(),
        2,
        "both argued changes want attention: {before}"
    );
    let (_, policy) = api(app, "GET", "/api/repos/demo/policy", "ada", None).await;
    assert_eq!(policy["attention_budget"], 1, "{policy}");
    let today = draw(&forge, "2031-01-01").await;
    let drawn = today["drawn"].as_array().unwrap();
    assert_eq!(drawn.len(), 1, "{today}");
    assert_eq!(
        drawn[0]["change"], first,
        "the older of two equals goes first"
    );
    assert_eq!(drawn[0]["kind"], "attention_drawn");
    assert_eq!(
        drawn[0]["reviewers"],
        json!(["ada"]),
        "the owner, never the author"
    );
    // The budget is spent for the day.
    assert_eq!(
        draw(&forge, "2031-01-01").await["drawn"]
            .as_array()
            .unwrap()
            .len(),
        0
    );

    // The draw shows where attention is listed, and holds the change.
    let (_, items) = api(app, "GET", "/api/repos/demo/attention", "ada", None).await;
    let item = items
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["change"]["id"] == first)
        .unwrap();
    assert_eq!(item["drawn"]["day"], "2031-01-01");
    assert!(
        item["signals"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["kind"] == "drawn")
    );
    let (_, readiness) = api(
        app,
        "GET",
        &format!("/api/changes/{first}/readiness"),
        "ada",
        None,
    )
    .await;
    let held = requirement(&readiness, "since it was drawn")
        .expect("a drawn change carries the requirement");
    assert_eq!(held["satisfied"], false, "{held}");
    let (_, readiness) = api(
        app,
        "GET",
        &format!("/api/changes/{second}/readiness"),
        "ada",
        None,
    )
    .await;
    assert!(
        requirement(&readiness, "since it was drawn").is_none(),
        "undrawn changes are not held"
    );

    // A human look releases it; an agent's would not.
    api_with_token(
        app,
        "POST",
        &format!("/api/changes/{first}/verdicts"),
        &forge.scout_token,
        Some(json!({ "domain": "correctness", "disposition": "approve", "rationale": "self-approval is not a look" })),
    )
    .await;
    let (_, readiness) = api(
        app,
        "GET",
        &format!("/api/changes/{first}/readiness"),
        "ada",
        None,
    )
    .await;
    assert_eq!(
        requirement(&readiness, "since it was drawn").unwrap()["satisfied"],
        false
    );
    api(
        app,
        "POST",
        &format!("/api/changes/{first}/verdicts"),
        "ada",
        Some(json!({ "domain": "correctness", "disposition": "approve", "rationale": "Looked; fine." })),
    )
    .await;
    let (_, readiness) = api(
        app,
        "GET",
        &format!("/api/changes/{first}/readiness"),
        "ada",
        None,
    )
    .await;
    assert_eq!(
        requirement(&readiness, "since it was drawn").unwrap()["satisfied"],
        true
    );

    // Tomorrow's budget draws the next one, and never the same change twice.
    let tomorrow = draw(&forge, "2031-01-02").await;
    assert_eq!(tomorrow["drawn"][0]["change"], second, "{tomorrow}");
    assert_eq!(
        draw(&forge, "2031-01-03").await["drawn"]
            .as_array()
            .unwrap()
            .len(),
        0
    );

    // The people asked hear about it; the log says it in words; the home page marks it.
    let (_, cookie) = sign_in_as(&forge, "ada").await;
    let (_, inbox) = page_with_cookie(app, "/inbox", &cookie).await;
    assert!(inbox.contains("was drawn for your look"), "{inbox}");
    let (_, log) = page_with_cookie(app, "/demo/log", &cookie).await;
    assert!(log.contains("the policy drew"), "{log}");
    assert!(log.contains("for a human look"), "{log}");
    let (_, home) = page_with_cookie(app, "/", &cookie).await;
    assert!(home.contains("drawn 2031-01-02"), "{home}");
}

#[tokio::test(flavor = "multi_thread")]
async fn drawing_takes_landing_authority() {
    let forge = boot().await;
    set_budget(&forge, json!(1)).await;
    argued_change(&forge, "Argued").await;
    let (status, _) = api_with_token(
        &forge.app,
        "POST",
        "/api/repos/demo/attention/draw",
        &forge.scout_token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_train_spends_the_budget_for_today_on_its_own() {
    let forge = boot_drawing().await;
    let app = &forge.app;
    set_budget(&forge, json!(1)).await;
    let id = argued_change(&forge, "Argued on its own").await;
    // Nobody asks; the tick draws it, and the draw names today.
    wait_for(
        app,
        "the train to draw today's look",
        async |app: &axum::Router| {
            let (_, items) = api(app, "GET", "/api/repos/demo/attention", "ada", None).await;
            items
                .as_array()
                .unwrap()
                .iter()
                .any(|i| i["change"]["id"] == id && i["drawn"].is_object())
        },
    )
    .await;
    let (_, readiness) = api(
        app,
        "GET",
        &format!("/api/changes/{id}/readiness"),
        "ada",
        None,
    )
    .await;
    assert_eq!(
        requirement(&readiness, "since it was drawn").unwrap()["satisfied"],
        false
    );
}
