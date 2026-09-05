//! The verification-debt map: every line is backed by something the log
//! knows, and the roll-up says which files shipped on a promise.

use crate::common::*;
use axum::http::StatusCode;
use serde_json::{Value, json};

/// Push a one-file change as scout and land it with the given claim.
async fn land(
    forge: &Forge,
    wc: &std::path::Path,
    file: &str,
    body: &str,
    key: &str,
    claim: Value,
    verify: bool,
) -> String {
    let app = &forge.app;
    commit_file(wc, file, body, &format!("Add {file}\n\nChange-Id: {key}"));
    git(wc, &["push", "-q", "origin", "HEAD:refs/for/main"]);
    let (_, change) = api(
        app,
        "GET",
        &format!("/api/repos/demo/changes/{}", key_number(app, key).await),
        "ada",
        None,
    )
    .await;
    let id = change["id"].as_str().unwrap().to_owned();
    let (status, attached) = api_with_token(
        app,
        "POST",
        &format!("/api/changes/{id}/claims"),
        &forge.scout_token,
        Some(claim),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{attached}");
    if verify {
        let claim_id = attached["id"].as_str().unwrap();
        let (status, seen) = api(
            app,
            "POST",
            &format!("/api/claims/{claim_id}/verify"),
            "arbiter",
            Some(json!({ "agrees": true, "command": "cargo test", "observed": "ok" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{seen}");
    }
    let (status, _) = api(
        app,
        "POST",
        &format!("/api/changes/{id}/verdicts"),
        "ada",
        Some(json!({ "domain": "correctness", "disposition": "approve", "rationale": "fine" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, merged) = api(
        app,
        "POST",
        &format!("/api/changes/{id}/merge"),
        "ada",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{merged}");
    id
}

async fn key_number(app: &axum::Router, key: &str) -> i64 {
    let (_, changes) = api(app, "GET", "/api/repos/demo/changes", "ada", None).await;
    changes
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["external_key"] == key)
        .unwrap()["number"]
        .as_i64()
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn every_line_is_backed_by_what_the_log_knows_and_the_map_rolls_it_up() {
    let forge = boot().await;
    let (app, addr) = (&forge.app, forge.addr);
    // Let argued changes land, and let arbiter verify.
    let (status, _) = api(
        app,
        "POST",
        "/api/repos/demo/policy",
        "ada",
        Some(json!({
            "require_executed_check": false, "independence": "human_or_two_models",
            "require_runner_verification": false, "required_domains": []
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, granted) = api(
        app,
        "POST",
        "/api/grants",
        "ada",
        Some(json!({ "grantee": "arbiter", "actions": ["verify"] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{granted}");

    git(
        &forge.work,
        &[
            "clone",
            "-q",
            &format!("http://scout:{}@{addr}/git/demo", forge.scout_token),
            "wc",
        ],
    );
    let wc = forge.work.join("wc");
    land(
        &forge,
        &wc,
        "reproduced.rs",
        "a\nb\nc\n",
        "Irepro01",
        json!({ "kind": "test", "command": "cargo test", "passed": true, "summary": "ran" }),
        true,
    )
    .await;
    land(&forge, &wc, "claimed.rs", "a\nb\n", "Iclaim01",
        json!({ "kind": "test", "command": "cargo test", "passed": true, "summary": "ran, nobody re-ran" }), false).await;
    land(&forge, &wc, "gap.rs", "a\nb\nc\nd\n", "Igap0001",
        json!({ "kind": "test", "command": "cargo test", "passed": true, "summary": "ran", "unchecked": ["error paths"] }), true).await;
    land(
        &forge,
        &wc,
        "argued.rs",
        "a\n",
        "Iargue01",
        json!({ "kind": "reasoning", "passed": true, "summary": "looks right" }),
        false,
    )
    .await;

    // Per line, over the blame API.
    let (status, blame) = api(app, "GET", "/api/repos/demo/blame?path=gap.rs", "ada", None).await;
    assert_eq!(status, StatusCode::OK, "{blame}");
    assert!(
        blame["lines"]
            .as_array()
            .unwrap()
            .iter()
            .all(|l| l["state"] == "gap"),
        "{blame}"
    );
    assert_eq!(blame["debt_lines"], 4);
    let (_, blame) = api(
        app,
        "GET",
        "/api/repos/demo/blame?path=reproduced.rs",
        "ada",
        None,
    )
    .await;
    assert!(
        blame["lines"]
            .as_array()
            .unwrap()
            .iter()
            .all(|l| l["state"] == "reproduced"),
        "{blame}"
    );
    assert_eq!(blame["debt_lines"], 0);

    // Rolled up, most debt first.
    let (status, map) = api(app, "GET", "/api/repos/demo/debt", "ada", None).await;
    assert_eq!(status, StatusCode::OK, "{map}");
    assert_eq!(map["counts"]["reproduced"], 3, "{map}");
    assert_eq!(map["counts"]["claimed"], 2);
    assert_eq!(map["counts"]["gap"], 4);
    assert_eq!(map["counts"]["argued"], 1);
    assert_eq!(map["counts"]["imported"], 0);
    let files: Vec<&str> = map["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["path"].as_str().unwrap())
        .collect();
    assert_eq!(
        files,
        ["gap.rs", "claimed.rs", "argued.rs", "reproduced.rs"],
        "{map}"
    );
    // The page says the same, files most debt first, and blame marks each line.
    let (_, cookie) = sign_in_as(&forge, "ada").await;
    let (status, page) = page_with_cookie(app, "/demo/debt", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("What backs this code"), "{page}");
    assert!(
        page.contains(r#"class="tab active" href="/demo/debt""#),
        "{page}"
    );
    let gap_at = page.find("gap.rs").unwrap();
    let repro_at = page.find("reproduced.rs").unwrap();
    assert!(gap_at < repro_at, "most debt first: {page}");
    assert!(page.contains("under a declared gap"), "{page}");
    let (status, blame) = page_with_cookie(app, "/demo/blame/gap.rs", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(blame.contains(r#"class="cline gap"#), "{blame}");
    assert!(blame.contains("4 under a declared gap"), "{blame}");
    let (_, blame) = page_with_cookie(app, "/demo/blame/reproduced.rs", &cookie).await;
    assert!(blame.contains(r#"class="cline reproduced"#), "{blame}");
    assert!(blame.contains("3 reproduced"), "{blame}");
    // The same tip answers from the cache; a stranger reads it once the repo is public.
    let (_, again) = api(app, "GET", "/api/repos/demo/debt", "ada", None).await;
    assert_eq!(again["tip"], map["tip"]);
    let (status, _) = api_anonymous(app, "GET", "/api/repos/demo/debt", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread")]
async fn history_from_before_the_forge_is_imported_debt() {
    let forge = boot().await;
    let app = &forge.app;
    // A repository elsewhere, with history nobody here judged.
    let elsewhere = forge.work.join("elsewhere.git");
    std::process::Command::new("git")
        .args([
            "init",
            "-q",
            "--bare",
            "-b",
            "main",
            elsewhere.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    let seed = forge.work.join("seed");
    std::fs::create_dir_all(&seed).unwrap();
    git(&seed, &["init", "-q", "-b", "main"]);
    git(&seed, &["config", "user.email", "prior@example.test"]);
    git(&seed, &["config", "user.name", "Prior Work"]);
    commit_file(&seed, "old.txt", "one\ntwo\nthree\n", "Before the forge");
    git(&seed, &["push", "-q", elsewhere.to_str().unwrap(), "main"]);
    api(
        app,
        "POST",
        "/api/repos",
        "ada",
        Some(json!({ "name": "imported" })),
    )
    .await;
    let (status, done) = api(
        app,
        "POST",
        "/api/repos/imported/import",
        "ada",
        Some(json!({ "source": format!("file://{}", elsewhere.display()) })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{done}");
    let (status, map) = api(app, "GET", "/api/repos/imported/debt", "ada", None).await;
    assert_eq!(status, StatusCode::OK, "{map}");
    assert_eq!(map["counts"]["imported"], 3, "{map}");
    assert_eq!(map["counts"]["reproduced"], 0);
    assert_eq!(map["files"][0]["path"], "old.txt");
}
