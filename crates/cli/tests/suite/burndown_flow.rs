//! Migration as burndown: imported code is paid down by covering claims
//! a runner reproduced, the map keeps its history, and debt becomes tasks.

use crate::common::*;

use axum::Router;
use axum::http::StatusCode;
use serde_json::{Value, json};

async fn ok(app: &Router, method: &str, path: &str, actor: &str, body: Option<Value>) -> Value {
    let (status, value) = api(app, method, path, actor, body).await;
    assert_eq!(status, StatusCode::OK, "{method} {path}: {value}");
    value
}

fn file<'a>(map: &'a Value, path: &str) -> &'a Value {
    map["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["path"] == path)
        .unwrap_or_else(|| panic!("no {path} in {map}"))
}

#[tokio::test(flavor = "multi_thread")]
async fn imported_code_is_paid_down_by_reproduced_covering_claims() {
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

    // History from elsewhere: ten lines of library, five of docs.
    let source = forge.work.join("elsewhere");
    std::fs::create_dir_all(&source).unwrap();
    git(&source, &["init", "-q", "-b", "main"]);
    commit_file(&source, "src/lib.rs", &"fn f() {}\n".repeat(10), "Library");
    commit_file(&source, "docs/a.md", &"docs\n".repeat(5), "Docs");
    ok(
        app,
        "POST",
        "/api/repos/ada/demo/import",
        "ada",
        Some(json!({ "source": format!("file://{}", source.display()), "branch": "main" })),
    )
    .await;
    let map = ok(app, "GET", "/api/repos/ada/demo/debt", "ada", None).await;
    assert_eq!(map["counts"]["imported"], 15, "{map}");
    assert_eq!(map["counts"]["reproduced"], 0);
    assert!(map["paid_down"].as_array().unwrap().is_empty());

    // Scout adds a check for the library and claims it covers src/lib.rs;
    // a runner reproduces; the change lands.
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
    commit_file(
        &wc,
        "tests/lib_test.rs",
        "#[test] fn f() {}\n",
        "Test the library\n\nChange-Id: Icover",
    );
    git(&wc, &["push", "-q", "origin", "HEAD:refs/for/main"]);
    let changes = ok(app, "GET", "/api/repos/ada/demo/changes", "ada", None).await;
    let change = changes[0]["id"].as_str().unwrap().to_owned();
    let claim = ok(
        app,
        "POST",
        &format!("/api/changes/{change}/claims"),
        "scout",
        Some(json!({
            "kind": "test", "passed": true, "summary": "the library is exercised",
            "command": "exit 0", "covers": ["src/lib.rs"]
        })),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    ok(
        app,
        "POST",
        &format!("/api/claims/{claim}/verify"),
        "runner",
        Some(json!({ "agrees": true, "command": "exit 0", "observed": "ok" })),
    )
    .await;
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

    let map = ok(app, "GET", "/api/repos/ada/demo/debt", "ada", None).await;
    let lib = file(&map, "src/lib.rs");
    assert_eq!(lib["counts"]["reproduced"], 10, "{lib}");
    assert_eq!(lib["covered_by"][0]["change"], 1);
    assert_eq!(lib["covered_by"][0]["by"], "scout");
    assert_eq!(lib["covered_by"][0]["reproduced"], true);
    assert_eq!(
        map["counts"]["imported"], 5,
        "only the docs are still imported: {map}"
    );
    assert_eq!(map["paid_down"][0]["by"], "scout");
    assert_eq!(map["paid_down"][0]["lines"], 10);
    assert_eq!(map["paid_down"][0]["files"], 1);

    // The map kept its history: two tips, imported fell.
    let history = ok(app, "GET", "/api/repos/ada/demo/debt/history", "ada", None).await;
    let points = history.as_array().unwrap();
    assert!(points.len() >= 2, "{history}");
    assert_eq!(points[0]["imported"], 15);
    assert_eq!(points[points.len() - 1]["imported"], 5);

    // A cover cannot name the whole tree.
    for bare in ["*", "/", "**/", "."] {
        let (status, refused) = api(
            app,
            "POST",
            &format!("/api/changes/{change}/claims"),
            "scout",
            Some(json!({ "kind": "test", "passed": true, "summary": "all of it", "command": "exit 0", "covers": [bare] })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bare:?}: {refused}");
    }

    // A cover nobody re-ran is shown and moves nothing.
    commit_file(
        &wc,
        "tests/docs_test.rs",
        "#[test] fn d() {}\n",
        "Check the docs\n\nChange-Id: Idocs",
    );
    git(&wc, &["push", "-q", "origin", "HEAD:refs/for/main"]);
    let changes = ok(app, "GET", "/api/repos/ada/demo/changes", "ada", None).await;
    let second = changes.as_array().unwrap().last().unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    ok(
        app,
        "POST",
        &format!("/api/changes/{second}/claims"),
        "scout",
        Some(json!({ "kind": "test", "passed": true, "summary": "docs checked", "command": "exit 0", "covers": ["docs/"] })),
    )
    .await;
    ok(
        app,
        "POST",
        &format!("/api/changes/{second}/verdicts"),
        "ada",
        Some(json!({ "domain": "correctness", "disposition": "approve", "rationale": "fine" })),
    )
    .await;
    ok(
        app,
        "POST",
        &format!("/api/changes/{second}/merge"),
        "ada",
        None,
    )
    .await;
    let map = ok(app, "GET", "/api/repos/ada/demo/debt", "ada", None).await;
    let docs = file(&map, "docs/a.md");
    assert_eq!(docs["counts"]["imported"], 5, "{docs}");
    assert_eq!(docs["covered_by"][0]["reproduced"], false);

    // Debt becomes tasks, one per file without one; owner only.
    let (status, refused) = api(
        app,
        "POST",
        "/api/repos/ada/demo/debt/tasks",
        "scout",
        Some(json!({ "count": 1 })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refused}");
    let created = ok(
        app,
        "POST",
        "/api/repos/ada/demo/debt/tasks",
        "ada",
        Some(json!({ "count": 1 })),
    )
    .await;
    assert_eq!(created["tasks"].as_array().unwrap().len(), 1, "{created}");
    let task = created["tasks"][0].as_str().unwrap();
    let shown = ok(app, "GET", &format!("/api/tasks/{task}"), "ada", None).await;
    assert_eq!(
        shown["title"], "Verify docs/a.md",
        "the most indebted file: {shown}"
    );
    assert!(
        shown["spec"]
            .as_str()
            .unwrap()
            .contains("\"covers\": [\"docs/a.md\"]"),
        "{shown}"
    );
    let again = ok(
        app,
        "POST",
        "/api/repos/ada/demo/debt/tasks",
        "ada",
        Some(json!({ "count": 1 })),
    )
    .await;
    let map = ok(app, "GET", "/api/repos/ada/demo/debt", "ada", None).await;
    assert_eq!(file(&map, "docs/a.md")["task"][0], "docs/a.md", "{map}");
    assert!(
        again["tasks"]
            .as_array()
            .unwrap()
            .iter()
            .all(|t| t != &created["tasks"][0]),
        "a file with a task is not given another: {again}"
    );

    // The tab shows the burndown, who paid, and the button.
    let (_, ada) = sign_in_as(&forge, "ada").await;
    let (status, page) = page_with_cookie(app, "/ada/demo/debt", &ada).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        page.contains("Burndown") && page.contains("class=\"burndown\""),
        "{page}"
    );
    assert!(
        page.contains("Paid down") && page.contains("scout"),
        "{page}"
    );
    assert!(
        page.contains("covered by #1") && page.contains("runner reproduced"),
        "{page}"
    );
    assert!(page.contains("task open"), "{page}");
}
