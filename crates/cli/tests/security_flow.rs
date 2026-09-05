//! What the security audit found, held shut.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::*;
use serde_json::json;

async fn stranger_token(forge: &Forge, id: &str) -> String {
    api_with_token(
        &forge.app,
        "POST",
        "/api/principals",
        &forge.ada_token,
        Some(json!({ "id": id, "kind": "human", "display": id })),
    )
    .await;
    let (_, minted) = api_with_token(
        &forge.app,
        "POST",
        &format!("/api/principals/{id}/tokens"),
        &forge.ada_token,
        Some(json!({ "label": "test" })),
    )
    .await;
    minted["token"].as_str().unwrap().to_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_person_mints_and_revokes_only_their_own_credentials() {
    let forge = boot_token_only().await;
    let app = &forge.app;
    let bee = stranger_token(&forge, "bee").await;

    // Minting for somebody else is running the forge, which bee is not.
    let (status, body) = api_with_token(
        app,
        "POST",
        "/api/principals/ada/tokens",
        &bee,
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, _) = api_with_token(
        app,
        "POST",
        "/api/principals/bee/tokens",
        &bee,
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "your own is yours");
    let (status, _) = api_with_token(
        app,
        "POST",
        "/api/principals/bee/tokens",
        &forge.ada_token,
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "and the admin's to mint");

    // Revoking somebody else's token, or the admin grant, is not bee's either.
    let (_, adas) = api_with_token(
        app,
        "GET",
        "/api/principals/ada/tokens",
        &forge.ada_token,
        None,
    )
    .await;
    let ada_token_id = adas[0]["id"].as_str().unwrap();
    let (status, _) = api_with_token(
        app,
        "POST",
        &format!("/api/tokens/{ada_token_id}/revoke"),
        &bee,
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (_, grants) = api_with_token(
        app,
        "GET",
        "/api/grants?grantee=ada",
        &forge.ada_token,
        None,
    )
    .await;
    let admin_grant = grants[0]["id"].as_str().unwrap();
    let (status, _) = api_with_token(
        app,
        "POST",
        &format!("/api/grants/{admin_grant}/revoke"),
        &bee,
        Some(json!({ "reason": "lol" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_invitation_is_not_a_bearer_token() {
    let forge = boot().await;
    let app = &forge.app;
    let (_, ada) = sign_in_as(&forge, "ada").await;
    let (_, location) = post_form(app, "/people", &ada, "action=register&id=bee&display=Bee").await;
    let link = shown_once(app, &location, &ada).await;
    let secret = link.split("token=").nth(1).unwrap().to_owned();
    let (status, _) = api_with_token(app, "GET", "/api/principals/bee", &secret, None).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an invitation opens the door once; it is not a credential"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn importing_and_mirroring_are_the_operators_to_authorise() {
    // A deployment, not a development forge: local sources are refused.
    let forge = boot_token_only().await;
    let app = &forge.app;
    let bee = stranger_token(&forge, "bee").await;
    // Bee owns a repository of their own.
    api_with_token(
        app,
        "POST",
        "/api/repos",
        &bee,
        Some(json!({ "name": "bees" })),
    )
    .await;

    // file:// and ssh:// are this machine's, not a caller's.
    let (status, body) = api_with_token(
        app,
        "POST",
        "/api/repos/bees/import",
        &bee,
        Some(json!({ "source": "file:///etc", "branch": "main" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    // Into somebody else's repository: refused before anything is fetched,
    // so the answer is authority, not a network error.
    let (status, body) = api_with_token(
        app,
        "POST",
        "/api/repos/demo/import",
        &bee,
        Some(json!({ "source": "https://127.0.0.1:1/nothing.git", "branch": "main" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // A mirror is pushed with the operator's credential, so an owner
    // cannot point it anywhere.
    let (status, body) = api_with_token(
        app,
        "POST",
        "/api/repos/bees/mirror",
        &bee,
        Some(json!({ "mirror": { "url": "https://attacker.example/x.git", "enabled": true } })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, body) = api_with_token(
        app,
        "POST",
        "/api/repos/bees/mirror",
        &forge.ada_token,
        Some(json!({ "mirror": { "url": "file:///tmp/x.git", "enabled": true } })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn private_repositories_do_not_leak_through_side_doors() {
    let forge = boot().await;
    let app = &forge.app;
    let bee = stranger_token(&forge, "bee").await;

    let (status, _) = api_with_token(
        app,
        "GET",
        "/api/repos/demo/blame?path=README.md",
        &bee,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "blame is a read of the repository"
    );
    let (status, _) = api_with_token(
        app,
        "POST",
        "/api/repos/demo/policy",
        &bee,
        Some(json!({
            "preview": true,
            "require_executed_check": false,
            "require_runner_verification": false,
            "independence": "none",
            "required_domains": []
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a preview lists open changes"
    );
    // Grants on repositories bee cannot read are not bee's to list.
    let (_, grants) = api_with_token(app, "GET", "/api/grants?grantee=scout", &bee, None).await;
    assert!(
        grants
            .as_array()
            .unwrap()
            .iter()
            .all(|g| g["repo"].is_null()),
        "{grants}"
    );
    // The agents page is running the forge.
    let (_, bee_cookie) = sign_in_as(&forge, "bee").await;
    assert_eq!(
        get_with_cookie(app, "/agents", &bee_cookie).await,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn links_are_built_from_configuration_not_from_the_caller() {
    let outbox = tempfile::tempdir().unwrap();
    let mail_file = outbox.path().join("mail.txt");
    let forge = boot_mailing_public(&format!("cat > '{}'", mail_file.display())).await;
    let app = &forge.app;
    let (_, cookie) = sign_in_as(&forge, "ada").await;
    post_form(
        app,
        "/you/settings/email",
        &cookie,
        "email=ada%40example.org",
    )
    .await;
    let confirm = std::fs::read_to_string(&mail_file).unwrap();
    std::fs::remove_file(&mail_file).unwrap();
    assert!(
        confirm.contains("https://forge.example/verify?token="),
        "{confirm}"
    );

    // A forged Host header does not move the reset link anywhere else.
    let request = Request::builder()
        .method("POST")
        .uri("/forgot")
        .header("host", "evil.example")
        .header("x-forwarded-proto", "http")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from("who=ada"))
        .unwrap();
    tower::ServiceExt::oneshot(app.clone(), request)
        .await
        .unwrap();
    // The address is pending, not confirmed, so nothing goes out yet; confirm it first.
    let path = confirm
        .split("https://forge.example")
        .nth(1)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_owned();
    get_redirect(app, &path, &cookie).await;
    let request = Request::builder()
        .method("POST")
        .uri("/forgot")
        .header("host", "evil.example")
        .header("x-forwarded-proto", "http")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from("who=ada"))
        .unwrap();
    tower::ServiceExt::oneshot(app.clone(), request)
        .await
        .unwrap();
    let reset = std::fs::read_to_string(&mail_file).expect("a reset was mailed");
    assert!(
        reset.contains("https://forge.example/reset?token="),
        "{reset}"
    );
    assert!(!reset.contains("evil.example"), "{reset}");
}

#[tokio::test(flavor = "multi_thread")]
async fn small_doors_are_shut_too() {
    let forge = boot().await;
    let app = &forge.app;
    let (_, cookie) = sign_in_as(&forge, "ada").await;
    // No protocol-relative escape through the theme switch.
    let (status, location) =
        post_form(app, "/theme", &cookie, "to=light&back=//evil.example/x").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location, "/", "{location}");
    // Origin: null is nobody's.
    let request = Request::builder()
        .method("POST")
        .uri("/inbox/read")
        .header("host", "forge.example")
        .header("origin", "null")
        .header("cookie", &cookie)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from("all=1"))
        .unwrap();
    let status = tower::ServiceExt::oneshot(app.clone(), request)
        .await
        .unwrap()
        .status();
    assert_eq!(status, StatusCode::FORBIDDEN);
    // A too-short password does not spend a reset link.
    let (_, location) = post_form(
        app,
        "/reset",
        "",
        "token=whatever&password=short&confirm=short",
    )
    .await;
    assert!(location.contains("error="), "{location}");
    assert!(
        location.contains("token=whatever"),
        "the link is still in hand: {location}"
    );
}
