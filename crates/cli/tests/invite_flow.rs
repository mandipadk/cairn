//! Bringing a person in without handing them a terminal: an admin makes
//! a link, the link signs them in once, and then they set a password.

mod common;

use axum::http::StatusCode;
use common::*;

fn query_value(location: &str, key: &str) -> Option<String> {
    let (_, query) = location.split_once('?')?;
    query
        .split('&')
        .find_map(|pair| pair.strip_prefix(&format!("{key}=")))
        .map(percent_decode)
}

fn percent_decode(s: &str) -> String {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() + 1 => {
                let hex = &s[i + 1..i + 3];
                out.push(u8::from_str_radix(hex, 16).unwrap());
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn an_invitation_signs_somebody_in_exactly_once() {
    let forge = boot().await;
    let app = &forge.app;
    let (_, ada) = sign_in_as(&forge, "ada").await;

    let (status, location) =
        post_form(app, "/people", &ada, "action=register&id=bee&display=Bee").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let secret = query_value(&location, "invite").expect("an invitation to hand over");

    // The page shows the link once, as a link to this forge.
    let (_, page) = page_with_cookie(app, &location, &ada).await;
    assert!(page.contains("/join?token="), "{page}");
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
