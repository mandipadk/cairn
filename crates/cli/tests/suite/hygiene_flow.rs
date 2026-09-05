//! Change hygiene: when things happened, a list that filters and pages,
//! the commit message and the interdiff on the page, and a way out of
//! the queue or the change itself from the page. And a repository that
//! says what it is for.

use crate::common::*;
use axum::http::StatusCode;
use serde_json::json;

async fn open_changes(forge: &Forge, n: usize) -> Vec<String> {
    let mut ids = Vec::new();
    for i in 0..n {
        let (_, change) = api_with_token(
            &forge.app,
            "POST",
            "/api/changes",
            &forge.scout_token,
            Some(json!({ "repo": "demo", "target": "main", "title": format!("Change {i}") })),
        )
        .await;
        ids.push(change["id"].as_str().unwrap().to_owned());
    }
    ids
}

#[tokio::test(flavor = "multi_thread")]
async fn changes_say_when_and_the_list_filters_and_pages() {
    let forge = boot().await;
    let app = &forge.app;
    let ids = open_changes(&forge, 5).await;
    // Timestamps: opened, and moved when something happens.
    let (_, first) = api(app, "GET", &format!("/api/changes/{}", ids[0]), "ada", None).await;
    assert!(
        first["opened_at"].as_str().unwrap().starts_with("20"),
        "{first}"
    );
    assert_eq!(first["opened_at"], first["updated_at"]);
    api_with_token(app, "POST", &format!("/api/changes/{}/revisions", ids[0]), &forge.scout_token,
        Some(json!({ "commit_oid": "d".repeat(40), "message": "Change 0\n\nWhy this exists, in a paragraph.\nAnd a second line." }))).await;
    let (_, moved) = api(app, "GET", &format!("/api/changes/{}", ids[0]), "ada", None).await;
    assert!(moved["updated_at"].as_str().unwrap() >= moved["opened_at"].as_str().unwrap());
    // Abandon one so the filter has something to filter.
    api(
        app,
        "POST",
        &format!("/api/changes/{}/abandon", ids[4]),
        "ada",
        Some(json!({ "reason": "duplicate" })),
    )
    .await;

    // Whole list, as before; pages, newest first, with a cursor.
    let (_, all) = api(app, "GET", "/api/repos/demo/changes", "ada", None).await;
    assert_eq!(all.as_array().unwrap().len(), 5);
    let (_, page) = api(app, "GET", "/api/repos/demo/changes?limit=2", "ada", None).await;
    let numbers: Vec<i64> = page["changes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["number"].as_i64().unwrap())
        .collect();
    assert_eq!(numbers, [5, 4], "{page}");
    assert_eq!(page["next_before"], 4);
    let (_, next) = api(
        app,
        "GET",
        "/api/repos/demo/changes?limit=2&before=4",
        "ada",
        None,
    )
    .await;
    let numbers: Vec<i64> = next["changes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["number"].as_i64().unwrap())
        .collect();
    assert_eq!(numbers, [3, 2]);
    let (_, last) = api(
        app,
        "GET",
        "/api/repos/demo/changes?limit=2&before=2",
        "ada",
        None,
    )
    .await;
    assert_eq!(last["changes"].as_array().unwrap().len(), 1);
    assert!(last["next_before"].is_null());
    let (_, open_only) = api(
        app,
        "GET",
        "/api/repos/demo/changes?limit=10&state=open",
        "ada",
        None,
    )
    .await;
    assert_eq!(open_only["changes"].as_array().unwrap().len(), 4);

    // The page: filters, when, and the message.
    let (_, cookie) = sign_in_as(&forge, "ada").await;
    let (_, list) = page_with_cookie(app, "/demo/changes", &cookie).await;
    assert!(
        list.contains(r#"href="/demo/changes?state=open""#),
        "{list}"
    );
    assert!(list.contains("opened "), "{list}");
    let (_, abandoned) = page_with_cookie(app, "/demo/changes?state=abandoned", &cookie).await;
    assert!(
        abandoned.contains("Change 4") && !abandoned.contains("Change 3"),
        "{abandoned}"
    );
    let (_, page) = page_with_cookie(app, "/demo/changes/1", &cookie).await;
    assert!(page.contains("Why this exists, in a paragraph."), "{page}");
    assert!(page.contains("moved "), "{page}");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_interdiff_shows_only_what_moved_between_revisions() {
    let forge = boot().await;
    let (app, addr) = (&forge.app, forge.addr);
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
    commit_file(&wc, "a.txt", "alpha\n", "Two files\n\nChange-Id: Iinter001");
    git(&wc, &["push", "-q", "origin", "HEAD:refs/for/main"]);
    std::fs::write(wc.join("b.txt"), "beta\n").unwrap();
    git(&wc, &["add", "."]);
    git(&wc, &["commit", "-q", "--amend", "--no-edit"]);
    git(&wc, &["push", "-q", "origin", "HEAD:refs/for/main"]);
    let (_, cookie) = sign_in_as(&forge, "ada").await;
    let (status, full) = page_with_cookie(app, "/demo/changes/1?r=2", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(full.contains("a.txt") && full.contains("b.txt"), "{full}");
    assert!(
        full.contains("?r=2&amp;vs=1"),
        "the page offers the interdiff: {full}"
    );
    let (_, inter) = page_with_cookie(app, "/demo/changes/1?r=2&vs=1", &cookie).await;
    assert!(
        inter.contains("b.txt") && !inter.contains("alpha"),
        "{inter}"
    );
    assert!(inter.contains("from r1 to r2"), "{inter}");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_page_can_dequeue_and_abandon_and_a_repository_can_say_what_it_is_for() {
    let forge = boot().await;
    let app = &forge.app;
    let ids = open_changes(&forge, 1).await;
    let id = &ids[0];
    api_with_token(
        app,
        "POST",
        &format!("/api/changes/{id}/revisions"),
        &forge.scout_token,
        Some(json!({ "commit_oid": "e".repeat(40), "message": "Change 0" })),
    )
    .await;
    let (_, cookie) = sign_in_as(&forge, "ada").await;
    let (status, location) = post_form(
        app,
        "/demo/changes/1/abandon",
        &cookie,
        "reason=Superseded+by+%232",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{location}");
    assert_eq!(location, "/demo/changes/1");
    let (_, change) = api(app, "GET", &format!("/api/changes/{id}"), "ada", None).await;
    assert_eq!(change["state"], "abandoned");
    let (_, page) = page_with_cookie(app, "/demo/changes/1", &cookie).await;
    assert!(
        !page.contains("Abandon this change"),
        "no way out of a closed change: {page}"
    );

    let (status, location) = post_form(
        app,
        "/demo/settings/description",
        &cookie,
        "description=The+forge+that+hosts+itself.",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{location}");
    let (_, repo) = api(app, "GET", "/api/repos/demo", "ada", None).await;
    assert_eq!(repo["description"], "The forge that hosts itself.");
    let (_, home) = page_with_cookie(app, "/demo", &cookie).await;
    assert!(home.contains("The forge that hosts itself."), "{home}");
    let (status, _) = api_with_token(
        app,
        "POST",
        "/api/repos/demo/description",
        &forge.scout_token,
        Some(json!({ "description": "mine now" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}
