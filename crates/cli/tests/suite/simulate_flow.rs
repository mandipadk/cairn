//! The policy simulator: a proposed policy judged against what already
//! landed, each landing as of its merge, and policies that travel as packs.

use crate::common::*;

use axum::Router;
use axum::http::StatusCode;
use serde_json::{Value, json};

async fn ok(app: &Router, method: &str, path: &str, actor: &str, body: Option<Value>) -> Value {
    let (status, value) = api(app, method, path, actor, body).await;
    assert_eq!(status, StatusCode::OK, "{method} {path}: {value}");
    value
}

/// Push a commit as scout and return the change id and its claim id.
async fn pushed(forge: &Forge, wc: &std::path::Path, file: &str, key: &str) -> (String, String) {
    commit_file(
        wc,
        file,
        "x\n",
        &format!("Change {file}\n\nChange-Id: {key}"),
    );
    git(wc, &["push", "-q", "origin", "HEAD:refs/for/main"]);
    let changes = ok(
        &forge.app,
        "GET",
        "/api/repos/ada/demo/changes",
        "ada",
        None,
    )
    .await;
    let change = changes.as_array().unwrap().last().unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let claimed = ok(
        &forge.app,
        "POST",
        &format!("/api/changes/{change}/claims"),
        "scout",
        Some(json!({ "kind": "test", "passed": true, "summary": "green", "command": "exit 0" })),
    )
    .await;
    (change, claimed["id"].as_str().unwrap().to_owned())
}

async fn approve_and_land(app: &Router, change: &str) {
    ok(
        app,
        "POST",
        &format!("/api/changes/{change}/verdicts"),
        "ada",
        Some(json!({ "domain": "correctness", "disposition": "approve", "rationale": "fine" })),
    )
    .await;
    ok(
        app,
        "POST",
        &format!("/api/changes/{change}/merge"),
        "ada",
        None,
    )
    .await;
}

fn requiring_a_runner() -> Value {
    json!({
        "require_executed_check": true, "independence": "none",
        "require_runner_verification": true, "runner_quorum": 1,
        "required_domains": [], "require_concerns_resolved": true,
        "attention_budget": null, "agents_act_in_sessions": false, "trust": null
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn a_policy_is_judged_against_landings_as_of_their_merge() {
    let forge = boot().await;
    let (app, addr) = (&forge.app, forge.addr);
    ok(
        app,
        "POST",
        "/api/principals",
        "ada",
        Some(json!({ "id": "runner", "kind": "agent", "display": "Runner", "model": "sandbox", "harness": "aquaman" })),
    )
    .await;
    ok(
        app,
        "POST",
        "/api/grants",
        "ada",
        Some(json!({ "grantee": "runner", "actions": ["verify"] })),
    )
    .await;
    git(
        &forge.work,
        &[
            "clone",
            "-q",
            &format!("http://scout:x@{addr}/git/ada/demo"),
            "wc",
        ],
    );
    let wc = forge.work.join("wc");

    // Three landings under the default policy: only the second was
    // reproduced by a runner before it landed.
    let (first, _) = pushed(&forge, &wc, "a.txt", "Ia").await;
    approve_and_land(app, &first).await;
    let (second, claim) = pushed(&forge, &wc, "b.txt", "Ib").await;
    ok(
        app,
        "POST",
        &format!("/api/claims/{claim}/verify"),
        "runner",
        Some(json!({ "agrees": true, "command": "exit 0", "observed": "ok" })),
    )
    .await;
    approve_and_land(app, &second).await;
    let (third, third_claim) = pushed(&forge, &wc, "c.txt", "Ic").await;
    approve_and_land(app, &third).await;
    // A runner re-runs the third claim *after* it landed. As of its
    // merge, nobody had.
    ok(
        app,
        "POST",
        &format!("/api/claims/{third_claim}/verify"),
        "runner",
        Some(json!({ "agrees": true, "command": "exit 0", "observed": "late" })),
    )
    .await;

    let (status, simulated) = api(
        app,
        "POST",
        "/api/repos/ada/demo/policy/simulate?since=2020-01-01",
        "ada",
        Some(requiring_a_runner()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{simulated}");
    assert_eq!(simulated["landings"], 3, "{simulated}");
    assert_eq!(
        simulated["held"], 2,
        "as of their merges, two had no runner: {simulated}"
    );
    let held: Vec<&str> = simulated["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["held"] == true)
        .map(|e| e["change"].as_str().unwrap())
        .collect();
    assert!(
        held.contains(&first.as_str()) && held.contains(&third.as_str()),
        "{simulated}"
    );
    assert_eq!(
        simulated["by_requirement"][0],
        json!(["a runner reproduced a claim on the latest revision", 2]),
        "{simulated}"
    );
    // Newest first, and each entry says when it landed.
    assert_eq!(simulated["entries"][0]["change"], third);
    assert!(
        simulated["entries"][0]["landed_at"]
            .as_str()
            .unwrap()
            .starts_with("20")
    );

    // The policy they actually landed under holds nothing.
    let current = ok(app, "GET", "/api/repos/ada/demo/policy", "ada", None).await;
    let (_, unchanged) = api(
        app,
        "POST",
        "/api/repos/ada/demo/policy/simulate?since=2020-01-01",
        "ada",
        Some(current),
    )
    .await;
    assert_eq!(unchanged["held"], 0, "{unchanged}");

    // A stranger is not answered, even on a public repository: the
    // simulator does real work per call.
    ok(
        app,
        "POST",
        "/api/repos/ada/demo/visibility",
        "ada",
        Some(json!({ "visibility": "public" })),
    )
    .await;
    let (status, refused) = api_anonymous(
        app,
        "POST",
        "/api/repos/ada/demo/policy/simulate?since=2020-01-01",
        Some(requiring_a_runner()),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{refused}");

    // A window with nothing in it is an honest zero, and a bad date is refused.
    let (_, none) = api(
        app,
        "POST",
        "/api/repos/ada/demo/policy/simulate?since=2999-01-01",
        "ada",
        Some(requiring_a_runner()),
    )
    .await;
    assert_eq!(none["landings"], 0);
    let (status, refused) = api(
        app,
        "POST",
        "/api/repos/ada/demo/policy/simulate?since=yesterday",
        "ada",
        Some(requiring_a_runner()),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");

    // The same question from the settings page, answered in a sentence.
    let (_, ada) = sign_in_as(&forge, "ada").await;
    let (status, page) = post_form_page(
        app,
        "/ada/demo/settings/policy",
        &ada,
        "action=simulate&since=2020-01-01&require_executed_check=on&require_runner_verification=on&runner_quorum=1&independence=none&attention_budget=",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        page.contains("Against 3 landing(s) since") && page.contains("would have held 2."),
        "{page}"
    );
    assert!(
        page.contains("2 held by: a runner reproduced a claim"),
        "{page}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_policy_travels_as_a_pack() {
    let forge = boot().await;
    let app = &forge.app;

    // The forge ships packs to start from; anyone may read them.
    let (status, packs) = api_anonymous(app, "GET", "/api/policy/packs", None).await;
    assert_eq!(status, StatusCode::OK, "{packs}");
    let names: Vec<&str> = packs
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["floor", "reproduced", "agents-supervised"]);
    assert_eq!(packs[1]["policy"]["require_runner_verification"], true);

    // A repository exports its own, with where it came from.
    ok(
        app,
        "POST",
        "/api/repos/ada/demo/description",
        "ada",
        Some(json!({ "description": "the demo" })),
    )
    .await;
    let pack = ok(app, "GET", "/api/repos/ada/demo/policy/pack", "ada", None).await;
    assert_eq!(pack["pack"], 1);
    assert_eq!(pack["name"], "ada/demo");
    assert_eq!(pack["description"], "the demo");
    assert_eq!(pack["from"]["repo"], "ada/demo");
    let policy = ok(app, "GET", "/api/repos/ada/demo/policy", "ada", None).await;
    assert_eq!(pack["policy"], policy);

    // The settings page starts from a shipped pack, or a pasted one.
    let (_, ada) = sign_in_as(&forge, "ada").await;
    let (status, _) = post_form(
        app,
        "/ada/demo/settings/policy",
        &ada,
        "action=save&pack=agents-supervised&independence=none&attention_budget=",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let policy = ok(app, "GET", "/api/repos/ada/demo/policy", "ada", None).await;
    assert_eq!(policy["agents_act_in_sessions"], true, "{policy}");
    assert_eq!(policy["independence"], "human_only");
    assert_eq!(policy["attention_budget"], 2);

    let pasted = json!({
        "pack": 1, "name": "elsewhere", "description": "from another forge",
        "policy": packs[0]["policy"]
    });
    let body = format!(
        "action=save&pack_json={}&independence=none&attention_budget=",
        urlencoded(&pasted.to_string())
    );
    let (status, _) = post_form(app, "/ada/demo/settings/policy", &ada, &body).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let policy = ok(app, "GET", "/api/repos/ada/demo/policy", "ada", None).await;
    assert_eq!(
        policy, packs[0]["policy"],
        "the pasted pack is the policy now"
    );

    // Garbage is refused with a word, and changes nothing.
    let (status, location) = post_form(
        app,
        "/ada/demo/settings/policy",
        &ada,
        "action=save&pack_json=%7Bnot+json&independence=none&attention_budget=",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(location.contains("error="), "{location}");
}

fn urlencoded(value: &str) -> String {
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
