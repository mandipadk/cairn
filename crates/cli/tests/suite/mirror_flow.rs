//! Mirroring end to end against a real remote. GitHub is only a URL
//! here, so the test uses a bare repository on disk: the code path is
//! identical, and the assertion that matters — the landed branch
//! actually arrives somewhere else — is a real one.

use crate::common::*;

use axum::Router;
use axum::http::StatusCode;
use serde_json::json;

#[tokio::test(flavor = "multi_thread")]
async fn a_landed_branch_is_copied_outward_and_the_attempt_is_recorded() {
    let forge = boot().await;
    let (app, addr) = (&forge.app, forge.addr);

    // Somewhere else that speaks git. In production this is GitHub.
    let elsewhere = forge.work.join("elsewhere.git");
    let init = std::process::Command::new("git")
        .args(["init", "--bare", elsewhere.to_str().unwrap()])
        .output()
        .expect("create the far side");
    assert!(init.status.success());

    // A credential is never required to be present, but the URL is
    // rejected if it tries to carry one.
    let (status, refused) = api(
        app,
        "POST",
        "/api/repos/demo/mirror",
        "ada",
        Some(json!({ "mirror": { "url": "https://token@example.test/x.git", "enabled": true } })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        refused["error"]
            .as_str()
            .unwrap()
            .contains("keep credentials out"),
        "the refusal should say where the secret belongs: {refused}"
    );

    // Point the repo at the far side. A file URL is a real mirror
    // target — another disk — and exercises the same push path a
    // hosted remote does.
    let (status, _) = api(
        app,
        "POST",
        "/api/repos/demo/mirror",
        "ada",
        Some(json!({
            "mirror": { "url": format!("file://{}", elsewhere.display()), "enabled": true }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, configured) = api(app, "GET", "/api/repos/demo/mirror", "ada", None).await;
    assert_eq!(configured["enabled"], true);

    // Land something.
    git(
        &forge.work,
        &["clone", &format!("http://scout:x@{addr}/git/demo"), "wc"],
    );
    let wc = forge.work.join("wc");
    commit_file(
        &wc,
        "mirrored.txt",
        "hello\n",
        "Mirrored\n\nChange-Id: Imirror",
    );
    git(&wc, &["push", "origin", "HEAD:refs/for/main"]);
    let (_, changes) = api(app, "GET", "/api/repos/demo/changes", "ada", None).await;
    let change = changes[0]["id"].as_str().unwrap().to_owned();
    let landed = git(&wc, &["rev-parse", "HEAD"]).trim().to_owned();
    approve_and_enqueue(app, &change).await;

    // The attempt is recorded whether or not it worked, so wait on the
    // record rather than on the far side.
    wait_for(
        app,
        "the mirror push to be recorded",
        async |app: &Router| {
            let (_, events) = api(app, "GET", "/api/events?after=0&limit=300", "ada", None).await;
            events
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["kind"] == "mirror_pushed")
        },
    )
    .await;

    let (_, events) = api(app, "GET", "/api/events?after=0&limit=300", "ada", None).await;
    let pushed = events
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["kind"] == "mirror_pushed")
        .expect("a mirror push should be on the record");
    assert_eq!(pushed["ok"], true, "mirror push failed: {pushed}");
    assert_eq!(pushed["branch"], "main");
    assert_eq!(pushed["commit_oid"], landed.as_str());

    // The real assertion: the branch is genuinely over there.
    let over_there = std::process::Command::new("git")
        .args([
            "-C",
            elsewhere.to_str().unwrap(),
            "rev-parse",
            "refs/heads/main",
        ])
        .output()
        .expect("read the far side");
    assert!(
        over_there.status.success(),
        "main should exist on the mirror"
    );
    assert_eq!(
        String::from_utf8_lossy(&over_there.stdout).trim(),
        landed,
        "the mirror should carry exactly what landed"
    );

    // Turning it off stops the copying, and says so.
    let (status, _) = api(
        app,
        "POST",
        "/api/repos/demo/mirror",
        "ada",
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, configured) = api(app, "GET", "/api/repos/demo/mirror", "ada", None).await;
    assert!(configured.is_null());

    // A failing mirror is recorded rather than swallowed.
    let (status, _) = api(
        app,
        "POST",
        "/api/repos/demo/mirror",
        "ada",
        Some(json!({
            "mirror": { "url": "file:///nowhere/that/exists.git", "enabled": true }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    git(&wc, &["fetch", "-q", "origin", "main"]);
    git(&wc, &["reset", "-q", "--hard", "FETCH_HEAD"]);
    commit_file(&wc, "second.txt", "again\n", "Second\n\nChange-Id: Isecond");
    git(&wc, &["push", "origin", "HEAD:refs/for/main"]);
    let (_, changes) = api(app, "GET", "/api/repos/demo/changes", "ada", None).await;
    let second = changes
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["external_key"] == "Isecond")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    approve_and_enqueue(app, &second).await;

    wait_for(
        app,
        "the failed attempt to be recorded",
        async |app: &Router| {
            let (_, events) = api(app, "GET", "/api/events?after=0&limit=300", "ada", None).await;
            events
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["kind"] == "mirror_pushed" && e["ok"] == false)
        },
    )
    .await;

    // The change still landed here: an unreachable mirror must not
    // hold up work on the forge that owns it.
    let (_, change) = api(app, "GET", &format!("/api/changes/{second}"), "ada", None).await;
    assert_eq!(change["state"], "merged");
}
