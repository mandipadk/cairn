//! Bringing a person in without handing them a terminal: an admin makes
//! a link, the link signs them in once, and then they set a password.

mod common;

use axum::http::StatusCode;
use common::*;

#[tokio::test(flavor = "multi_thread")]
async fn an_invitation_signs_somebody_in_exactly_once() {
    let forge = boot().await;
    let app = &forge.app;
    let (_, ada) = sign_in_as(&forge, "ada").await;

    let (status, location) =
        post_form(app, "/people", &ada, "action=register&id=bee&display=Bee").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    // The page shows the link once, as a link to this forge, and never
    // puts the secret in a URL of its own.
    let link = shown_once(app, &location, &ada).await;
    assert!(link.contains("/join?token="), "{link}");
    let secret = link.split("token=").nth(1).unwrap().to_owned();
    let (_, page) = page_with_cookie(app, "/people", &ada).await;
    assert!(page.contains("no password yet"));
    assert!(
        !page.contains(r#"class="repohead""#),
        "a section page is not a repository"
    );

    // Following it signs bee in and lands on settings, told to set a password.
    let response = tower::ServiceExt::oneshot(
        app.clone(),
        axum::http::Request::builder()
            .uri(format!("/join?token={secret}"))
            .body(axum::body::Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()["location"], "/you/settings?first=1");
    let cookie = response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let (status, page) = page_with_cookie(app, "/you/settings?first=1", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("Set a password"), "{page}");
    assert!(
        page.contains(">bee<") || page.contains("bee"),
        "signed in as bee"
    );

    // The link is spent.
    let response = tower::ServiceExt::oneshot(
        app.clone(),
        axum::http::Request::builder()
            .uri(format!("/join?token={secret}"))
            .body(axum::body::Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(
        response.headers()["location"]
            .to_str()
            .unwrap()
            .starts_with("/login?error="),
        "a used invitation is refused"
    );

    // Bee sets a password and can now sign in the ordinary way.
    let (status, location) = post_form(
        app,
        "/you/settings",
        &cookie,
        "password=a+perfectly+ordinary+password&confirm=a+perfectly+ordinary+password",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{location}");
    // Changing a password ends every session, this one included.
    assert!(location.contains("Password+changed"), "{location}");
    let redirect = redirect_of(app, "bee", "a perfectly ordinary password").await;
    assert_eq!(redirect, "/", "a password set from an invitation signs in");
    let (_, page) = page_with_cookie(app, "/people", &ada).await;
    assert!(page.contains("can sign in"), "{page}");
}

#[tokio::test(flavor = "multi_thread")]
async fn only_whoever_runs_the_forge_sees_people() {
    let forge = boot().await;
    let app = &forge.app;
    let (_, ada) = sign_in_as(&forge, "ada").await;
    post_form(app, "/people", &ada, "action=register&id=bee&display=Bee").await;
    let (_, bee) = sign_in_as(&forge, "bee").await;
    assert_eq!(
        get_with_cookie(app, "/people", &bee).await,
        StatusCode::NOT_FOUND
    );
    let (status, _) = post_form(app, "/people", &bee, "action=register&id=cat&display=Cat").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // A bare API token is a credential, not an invitation.
    let (_, page) = page_with_cookie(app, "/", &bee).await;
    assert!(
        !page.contains(r#"href="/people""#),
        "no People link for bee"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_invitation_can_be_cancelled_and_only_the_newest_link_works() {
    let forge = boot().await;
    let app = &forge.app;
    let (_, ada) = sign_in_as(&forge, "ada").await;

    let (_, first) = post_form(app, "/people", &ada, "action=register&id=bee&display=Bee").await;
    let first = shown_once(app, &first, &ada)
        .await
        .split("token=")
        .nth(1)
        .unwrap()
        .to_owned();
    let (_, page) = page_with_cookie(app, "/people", &ada).await;
    assert!(page.contains("invited, link good until"), "{page}");

    // A new link retires the old one.
    let (_, second) = post_form(app, "/people", &ada, "action=relink&id=bee").await;
    let second = shown_once(app, &second, &ada)
        .await
        .split("token=")
        .nth(1)
        .unwrap()
        .to_owned();
    let (status, location) = get_redirect(app, &format!("/join?token={first}"), "").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        location.starts_with("/login?error="),
        "the old link is dead: {location}"
    );

    // Cancelling retires the newest too, and the page stops saying invited.
    post_form(app, "/people", &ada, "action=cancel&id=bee").await;
    let (_, location) = get_redirect(app, &format!("/join?token={second}"), "").await;
    assert!(location.starts_with("/login?error="), "{location}");
    let (_, page) = page_with_cookie(app, "/people", &ada).await;
    assert!(!page.contains("invited, link good until"), "{page}");
}
