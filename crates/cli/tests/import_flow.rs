//! Importing history that predates the forge.
//!
//! A branch normally moves only when a policy says it may. Imported
//! history never faced a policy, so the interesting assertions are not
//! that the commits arrive — it is that the log says plainly they were
//! never judged here, and that an import can never land on a branch the
//! log has already vouched for.

mod common;
use common::*;

use axum::http::StatusCode;
use serde_json::json;

#[tokio::test(flavor = "multi_thread")]
async fn history_from_elsewhere_arrives_and_is_recorded_as_unreviewed() {
    let forge = boot().await;
    let app = &forge.app;

    // Somewhere a repository already existed, with history nobody here
    // has ever seen. A bare repo on disk is a real remote.
    let elsewhere = forge.work.join("elsewhere.git");
    let seed = forge.work.join("seed");
    std::fs::create_dir_all(&seed).unwrap();
    assert!(
        std::process::Command::new("git")
            .args(["init", "--bare", "-b", "main", elsewhere.to_str().unwrap()])
            .output()
            .expect("create the far side")
            .status
            .success()
    );
    git(&seed, &["init", "-q", "-b", "main"]);
    git(&seed, &["config", "user.email", "prior@example.test"]);
    git(&seed, &["config", "user.name", "Prior Work"]);
    for n in 1..=3 {
        commit_file(
            &seed,
            &format!("file{n}.txt"),
            &format!("contents {n}\n"),
            &format!("Commit {n}"),
        );
    }
    let far_tip = git(&seed, &["rev-parse", "HEAD"]).trim().to_owned();
    git(
        &seed,
        &["push", "-q", elsewhere.to_str().unwrap(), "main:main"],
    );

    // A fresh repo on the forge, with nothing on main.
    let (status, _) = api(
        app,
        "POST",
        "/api/repos",
        "ada",
        Some(json!({ "name": "imported", "default_branch": "main" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // A source url may not carry a credential, exactly as a mirror may not.
    let (status, refused) = api(
        app,
        "POST",
        "/api/repos/imported/import",
        "ada",
        Some(json!({ "source": "https://token@example.test/x.git" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        refused["error"].as_str().unwrap().contains("credentials"),
        "the refusal should say where the secret belongs: {refused}"
    );

    // The import itself.
    let (status, body) = api(
        app,
        "POST",
        "/api/repos/imported/import",
        "ada",
        Some(json!({ "source": format!("file://{}", elsewhere.display()) })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "import failed: {body}");
    assert_eq!(body["event"]["kind"], "history_imported");
    assert_eq!(body["event"]["commits"], 3);
    assert_eq!(body["event"]["tip_oid"], far_tip.as_str());
    assert_eq!(body["event"]["branch"], "main");

    // The whole point: the log records this as an import, never as a
    // merge, and no policy trace is attached claiming it was judged.
    let (_, events) = api(app, "GET", "/api/events?after=0&limit=200", "ada", None).await;
    let events = events.as_array().unwrap();
    let imported = events
        .iter()
        .find(|e| e["kind"] == "history_imported")
        .expect("the import belongs on the record");
    assert!(
        imported["trace"].is_null(),
        "an import must not carry a policy trace: {imported}"
    );
    assert!(
        !events.iter().any(|e| e["kind"] == "change_merged"),
        "importing must not manufacture merges"
    );

    // And the history is genuinely here: a clone gets all three commits.
    let addr = forge.addr;
    git(
        &forge.work,
        &[
            "clone",
            "-q",
            &format!("http://ada:{}@{addr}/git/imported", forge.scout_token),
            "check",
        ],
    );
    let wc = forge.work.join("check");
    assert_eq!(git(&wc, &["rev-parse", "HEAD"]).trim(), far_tip);
    assert_eq!(git(&wc, &["rev-list", "--count", "HEAD"]).trim(), "3");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_import_cannot_overwrite_a_branch_the_log_already_vouched_for() {
    let forge = boot().await;
    let app = &forge.app;
    let addr = forge.addr;

    // `demo` already has main, landed the ordinary way.
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
        "real.txt",
        "reviewed\n",
        "Real work\n\nChange-Id: Ireal",
    );
    git(&wc, &["push", "-q", "origin", "HEAD:refs/for/main"]);
    let (_, changes) = api(app, "GET", "/api/repos/demo/changes", "ada", None).await;
    let change = changes[0]["id"].as_str().unwrap().to_owned();
    approve_and_enqueue(app, &change).await;
    wait_for(app, "the change to land", async |app: &axum::Router| {
        let (_, c) = api(app, "GET", &format!("/api/changes/{change}"), "ada", None).await;
        c["state"] == "merged"
    })
    .await;
    let reviewed_tip = git(&wc, &["rev-parse", "HEAD"]).trim().to_owned();

    // Somewhere else holds a different main entirely.
    let elsewhere = forge.work.join("other.git");
    let seed = forge.work.join("otherseed");
    std::fs::create_dir_all(&seed).unwrap();
    std::process::Command::new("git")
        .args(["init", "--bare", "-b", "main", elsewhere.to_str().unwrap()])
        .output()
        .unwrap();
    git(&seed, &["init", "-q", "-b", "main"]);
    git(&seed, &["config", "user.email", "other@example.test"]);
    git(&seed, &["config", "user.name", "Other"]);
    commit_file(&seed, "other.txt", "unrelated\n", "Unrelated history");
    git(
        &seed,
        &["push", "-q", elsewhere.to_str().unwrap(), "main:main"],
    );

    // Importing onto a branch that already carries reviewed work must
    // fail: it would erase decisions the log exists to keep.
    let (status, body) = api(
        app,
        "POST",
        "/api/repos/demo/import",
        "ada",
        Some(json!({ "source": format!("file://{}", elsewhere.display()) })),
    )
    .await;
    assert_ne!(
        status,
        StatusCode::OK,
        "importing over reviewed history should be refused: {body}"
    );

    // The reviewed tip is untouched.
    git(&wc, &["fetch", "-q", "origin", "main"]);
    assert_eq!(
        git(&wc, &["rev-parse", "FETCH_HEAD"]).trim(),
        reviewed_tip,
        "main must still carry exactly what was reviewed"
    );
}
