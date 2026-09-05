//! A repository can be renamed, archived and deleted by its owner; each
//! is an event, every projection and the git directory follow, and an
//! archived repository takes nothing new.

use crate::common::*;
use axum::http::StatusCode;
use serde_json::json;

async fn a_change_in(forge: &Forge, repo: &str) -> String {
    let (status, change) = api_with_token(
        &forge.app,
        "POST",
        "/api/changes",
        &forge.scout_token,
        Some(json!({ "repo": repo, "target": "main", "title": "Lives here" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{change}");
    let id = change["id"].as_str().unwrap().to_owned();
    api_with_token(
        &forge.app,
        "POST",
        &format!("/api/changes/{id}/revisions"),
        &forge.scout_token,
        Some(json!({ "commit_oid": "c".repeat(40), "message": "work" })),
    )
    .await;
    id
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rename_moves_everything_and_the_old_name_is_gone() {
    let forge = boot().await;
    let app = &forge.app;
    let id = a_change_in(&forge, "demo").await;
    let repos = forge._tmp.path().join("repos");
    assert!(repos.join("demo.git").is_dir());

    // Not the agent's to do.
    let (status, _) = api_with_token(
        app,
        "POST",
        "/api/repos/demo/rename",
        &forge.scout_token,
        Some(json!({ "to": "stolen" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // Nor to a name that is taken or malformed.
    api(
        app,
        "POST",
        "/api/repos",
        "ada",
        Some(json!({ "name": "taken" })),
    )
    .await;
    let (status, _) = api(
        app,
        "POST",
        "/api/repos/demo/rename",
        "ada",
        Some(json!({ "to": "taken" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = api(
        app,
        "POST",
        "/api/repos/demo/rename",
        "ada",
        Some(json!({ "to": "Bad Name" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, renamed) = api(
        app,
        "POST",
        "/api/repos/demo/rename",
        "ada",
        Some(json!({ "to": "shown" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{renamed}");
    assert!(repos.join("shown.git").is_dir() && !repos.join("demo.git").exists());
    let (status, _) = api(app, "GET", "/api/repos/demo", "ada", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, change) = api(app, "GET", &format!("/api/changes/{id}"), "ada", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(change["repo"], "shown");
    let (_, changes) = api(app, "GET", "/api/repos/shown/changes", "ada", None).await;
    assert_eq!(changes.as_array().unwrap().len(), 1);
    // The log followed the name too, and says what happened.
    let (_, cookie) = sign_in_as(&forge, "ada").await;
    let (status, log) = page_with_cookie(app, "/shown/log", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(log.contains("renamed demo to shown"), "{log}");
    assert!(
        log.contains("created demo"),
        "the old events came along: {log}"
    );
    // And git serves the new name.
    git(
        &forge.work,
        &[
            "clone",
            &format!("http://ada:{}@{}/git/shown", forge.ada_token, forge.addr),
            "wc",
        ],
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_archived_repository_takes_nothing_new_until_it_is_unarchived() {
    let forge = boot().await;
    let app = &forge.app;
    let (status, _) = api(app, "POST", "/api/repos/demo/archive", "ada", None).await;
    assert_eq!(status, StatusCode::OK);
    let (_, repo) = api(app, "GET", "/api/repos/demo", "ada", None).await;
    assert_eq!(repo["archived"], true);
    let (status, refused) = api_with_token(
        app,
        "POST",
        "/api/changes",
        &forge.scout_token,
        Some(json!({ "repo": "demo", "target": "main", "title": "Too late" })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{refused}");
    assert!(
        refused["error"].as_str().unwrap().contains("archived"),
        "{refused}"
    );
    let (status, _) = api(
        app,
        "POST",
        "/api/tasks",
        "ada",
        Some(json!({ "title": "t", "spec": "s", "repo": "demo" })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    // Reading goes on.
    let (status, _) = api(app, "GET", "/api/repos/demo/changes", "ada", None).await;
    assert_eq!(status, StatusCode::OK);
    // Twice is refused; unarchiving reopens it.
    let (status, _) = api(app, "POST", "/api/repos/demo/archive", "ada", None).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _) = api(app, "POST", "/api/repos/demo/unarchive", "ada", None).await;
    assert_eq!(status, StatusCode::OK);
    a_change_in(&forge, "demo").await;
    // From the settings page, the same.
    let (_, cookie) = sign_in_as(&forge, "ada").await;
    let (status, location) =
        post_form(app, "/demo/settings/archive", &cookie, "archived=yes").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location, "/demo/settings?done=1");
    let (_, settings) = page_with_cookie(app, "/demo/settings", &cookie).await;
    assert!(settings.contains("Unarchive"), "{settings}");
}

#[tokio::test(flavor = "multi_thread")]
async fn deleting_needs_the_name_typed_and_takes_the_repository_away() {
    let forge = boot().await;
    let app = &forge.app;
    let id = a_change_in(&forge, "demo").await;
    let repos = forge._tmp.path().join("repos");
    let (status, refused) = api(
        app,
        "POST",
        "/api/repos/demo/delete",
        "ada",
        Some(json!({ "confirm": "dem" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    assert!(repos.join("demo.git").is_dir());
    let (status, _) = api_with_token(
        app,
        "POST",
        "/api/repos/demo/delete",
        &forge.scout_token,
        Some(json!({ "confirm": "demo" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (_, cookie) = sign_in_as(&forge, "ada").await;
    let (status, location) = post_form(app, "/demo/settings/delete", &cookie, "confirm=demo").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location, "/");
    assert!(
        !repos.join("demo.git").exists(),
        "the directory went with it"
    );
    let (status, _) = api(app, "GET", "/api/repos/demo", "ada", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = api(app, "GET", &format!("/api/changes/{id}"), "ada", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = get_redirect(app, "/demo", &cookie).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // The log still knows, and every projection matches it.
    assert!(forge.state.fsck().unwrap().is_empty());
}
