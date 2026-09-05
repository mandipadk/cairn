//! The pages, held to what was drawn: the sidebar knows where you are,
//! rows say things in words, forms refuse what they cannot use, and a
//! clone address is one you can paste.

use crate::common::*;
use axum::http::StatusCode;
use serde_json::json;

#[tokio::test(flavor = "multi_thread")]
async fn the_sidebar_marks_every_page_you_can_be_on() {
    let forge = boot().await;
    let app = &forge.app;
    let (_, cookie) = sign_in_as(&forge, "ada").await;
    for (path, label) in [
        ("/you", "Your changes"),
        ("/you/tokens", "Tokens"),
        ("/you/sessions", "Sessions"),
        ("/you/settings", "Settings"),
        ("/agents", "Agents"),
        ("/inbox", "Inbox"),
    ] {
        let (status, page) = page_with_cookie(app, path, &cookie).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        let on = page
            .find(r#"class="on""#)
            .unwrap_or_else(|| panic!("{path} marks nothing"));
        let after = &page[on..on + 200];
        assert!(
            after.contains(label),
            "{path} marks the wrong entry: {after}"
        );
        assert!(
            !page.contains(r#"class="repohead""#),
            "{path} is not a repository"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn forms_refuse_what_they_cannot_use_before_they_send_it() {
    let forge = boot().await;
    let app = &forge.app;
    let (_, login) = page_with_cookie(app, "/login", "").await;
    assert!(login.contains(r#"name="principal" type="text" autocomplete="username webauthn" autocapitalize="none" autofocus required"#), "{login}");
    let (_, cookie) = sign_in_as(&forge, "ada").await;
    let (_, new_repo) = page_with_cookie(app, "/new", &cookie).await;
    assert!(new_repo.contains("required"), "{new_repo}");
    let (_, people) = page_with_cookie(app, "/people", &cookie).await;
    assert!(people.matches("required").count() >= 1, "{people}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_clone_address_is_one_you_can_paste_and_empty_lists_say_so() {
    let forge = boot_with_passkeys().await;
    let app = &forge.app;
    let (_, cookie) = sign_in_as(&forge, "ada").await;
    let (_, repo) = page_with_cookie(app, "/demo", &cookie).await;
    assert!(repo.contains("https://forge.example/git/demo"), "{repo}");
    let (_, changes) = page_with_cookie(app, "/demo/changes", &cookie).await;
    assert!(changes.contains("No changes yet"), "{changes}");
    let (_, log) = page_with_cookie(app, "/demo/log", &cookie).await;
    // Rows say when and who and what; no sequence numbers or event kinds.
    assert!(!log.contains("repo_created"), "{log}");
    assert!(log.contains("created demo"), "{log}");
    api_with_token(
        app,
        "POST",
        "/api/changes",
        &forge.scout_token,
        Some(json!({ "repo": "demo", "target": "main", "title": "Something" })),
    )
    .await;
    let (_, changes) = page_with_cookie(app, "/demo/changes", &cookie).await;
    assert!(!changes.contains("No changes yet"));
}
