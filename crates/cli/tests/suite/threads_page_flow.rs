//! The change page carries the discussion: threads under the lines they
//! are about, a composer where a line number is clicked, the standing
//! concern named in the title line, and everything listed beside the diff.

use crate::common::*;
use axum::http::StatusCode;
use serde_json::json;

/// A real change with a real diff, pushed through git as scout.
async fn pushed_change(forge: &Forge) -> String {
    let addr = forge.addr;
    git(
        &forge.work,
        &["clone", &format!("http://scout:x@{addr}/git/demo"), "wc"],
    );
    let wc = forge.work.join("wc");
    commit_file(
        &wc,
        "src/lib.rs",
        "one\ntwo\nthree\n",
        "Add three lines\n\nChange-Id: Ithreads01",
    );
    let push_url = format!("http://scout:{}@{addr}/git/demo", forge.scout_token);
    git(&wc, &["remote", "set-url", "origin", &push_url]);
    git(&wc, &["push", "origin", "HEAD:refs/for/main"]);
    let (_, changes) = api(&forge.app, "GET", "/api/repos/demo/changes", "ada", None).await;
    changes[0]["id"].as_str().unwrap().to_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_page_shows_threads_where_they_belong_and_takes_new_ones() {
    let forge = boot().await;
    let app = &forge.app;
    let id = pushed_change(&forge).await;

    // A concern raised through the API, on the second line.
    let (status, opened) = api(
        app,
        "POST",
        &format!("/api/changes/{id}/threads"),
        "ada",
        Some(json!({
            "anchor": { "on": "line", "path": "src/lib.rs", "side": "new", "line": 2 },
            "kind": "concern",
            "body": "Two is one too many."
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{opened}");
    let thread = opened["id"].as_str().unwrap().to_owned();

    let (_, ada) = sign_in_as(&forge, "ada").await;
    let (status, page) = page_with_cookie(app, "/demo/changes/1", &ada).await;
    assert_eq!(status, StatusCode::OK);
    // Under its line, named in the title line, listed beside the diff.
    assert!(page.contains(&format!("id=\"{thread}\"")), "{page}");
    assert!(page.contains("Two is one too many."));
    assert!(page.contains("1 concern stands"), "{page}");
    assert!(page.contains("src/lib.rs:2"), "{page}");
    assert!(page.contains("Discussion"), "{page}");
    assert!(page.contains("raised a concern"), "{page}");
    // Line numbers open a composer beneath themselves.
    assert!(page.contains("at=new:3:src/lib.rs#at"), "{page}");
    let (_, composing) =
        page_with_cookie(app, "/demo/changes/1?r=1&at=new:3:src/lib.rs", &ada).await;
    assert!(
        composing.contains(r#"name="line" value="3""#),
        "{composing}"
    );
    assert!(
        composing.contains(r#"name="path" value="src/lib.rs""#),
        "{composing}"
    );
    assert!(
        composing.contains("New thread at src/lib.rs:3"),
        "{composing}"
    );

    // Opening one from the page is the same thread the API knows.
    let (status, location) = post_form(
        app,
        "/demo/changes/1/threads",
        &ada,
        "revision=1&on=line&path=src%2Flib.rs&side=new&line=3&kind=question&body=Why+three%3F",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{location}");
    assert!(
        location.starts_with("/demo/changes/1?r=1#th-"),
        "{location}"
    );
    let (_, listed) = api(
        app,
        "GET",
        &format!("/api/changes/{id}/threads"),
        "ada",
        None,
    )
    .await;
    assert_eq!(listed.as_array().unwrap().len(), 2);
    assert_eq!(listed[1]["anchor"]["line"], 3);
    assert_eq!(listed[1]["body"], "Why three?");

    // A reply from the page, then a resolution; the resolved thread folds.
    let (status, _) = post_form(
        app,
        &format!("/demo/changes/1/threads/{thread}/reply"),
        &ada,
        "revision=1&body=Thinking+about+it.",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (_, page) = page_with_cookie(app, "/demo/changes/1", &ada).await;
    assert!(page.contains("Thinking about it."), "{page}");
    let (status, _) = post_form(
        app,
        &format!("/demo/changes/1/threads/{thread}/resolve"),
        &ada,
        "revision=1&how=withdrawn&note=Two+is+fine.",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (_, page) = page_with_cookie(app, "/demo/changes/1", &ada).await;
    assert!(
        page.contains(&format!("<details class=\"thread folded\" id=\"{thread}\"")),
        "{page}"
    );
    assert!(page.contains("withdrawn"), "{page}");
    assert!(page.contains("Two is fine."), "{page}");
    assert!(!page.contains("concern stands"), "{page}");

    // A malformed `at` is simply no composer.
    let (status, page) =
        page_with_cookie(app, "/demo/changes/1?at=new:zero:src/lib.rs", &ada).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!page.contains(r#"id="at""#), "{page}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_thread_on_the_change_starts_from_the_discussion_column() {
    let forge = boot().await;
    let app = &forge.app;
    pushed_change(&forge).await;
    let (_, ada) = sign_in_as(&forge, "ada").await;
    let (_, page) = page_with_cookie(app, "/demo/changes/1", &ada).await;
    assert!(page.contains("No discussion on this change"), "{page}");
    assert!(page.contains("at=change#at"), "{page}");
    let (_, composing) = page_with_cookie(app, "/demo/changes/1?r=1&at=change", &ada).await;
    assert!(
        composing.contains("New thread on the change"),
        "{composing}"
    );
    let (status, location) = post_form(
        app,
        "/demo/changes/1/threads",
        &ada,
        "revision=1&on=change&kind=note&body=Landing+this+before+the+release.",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{location}");
    let (_, page) = page_with_cookie(app, "/demo/changes/1", &ada).await;
    assert!(page.contains("the change"), "{page}");
    assert!(page.contains("Landing this before the release."), "{page}");
    // Somebody with no part in the repository is told so, in words.
    api_with_token(
        app,
        "POST",
        "/api/principals",
        &forge.ada_token,
        Some(json!({ "id": "bee", "kind": "human", "display": "Bee" })),
    )
    .await;
    let (_, bee) = sign_in_as(&forge, "bee").await;
    let (status, location) = post_form(
        app,
        "/demo/changes/1/threads",
        &bee,
        "revision=1&on=change&kind=concern&body=No.",
    )
    .await;
    assert!(
        status == StatusCode::SEE_OTHER || status == StatusCode::NOT_FOUND,
        "{status}"
    );
    if status == StatusCode::SEE_OTHER {
        assert!(location.contains("error="), "{location}");
    }
}
