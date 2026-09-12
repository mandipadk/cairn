//! The operator's door: served apart when the forge is told to, and
//! what stands behind it — the waitlist, invitations, reports, and the
//! switch for strangers.

use crate::common::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::json;
use tower::ServiceExt;

async fn post_public_form(app: &axum::Router, path: &str, body: &str) -> (StatusCode, String) {
    let request = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body.to_owned()))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    (status, location)
}

/// With the door elsewhere, the public listener refuses what grants
/// access — to an admin token as to anyone — and the door answers it.
#[tokio::test(flavor = "multi_thread")]
async fn the_operators_door_is_not_on_the_public_listener() {
    let forge = boot().await;
    let (public, door) = split_listeners(&forge);
    let bee = json!({ "id": "bee", "kind": "human", "display": "Bee" });
    let (status, body) = api(&public, "POST", "/api/principals", "ada", Some(bee.clone())).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["kind"], "not_found");
    let (status, body) = api(&door, "POST", "/api/principals", "ada", Some(bee)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // Minting for somebody else is the door's; your own is yours anywhere.
    let (status, body) = api(
        &public,
        "POST",
        "/api/principals/bee/tokens",
        "ada",
        Some(json!({ "label": "for bee" })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    let (status, body) = api(
        &public,
        "POST",
        "/api/principals/ada/tokens",
        "ada",
        Some(json!({ "label": "mine" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = api(
        &door,
        "POST",
        "/api/principals/bee/tokens",
        "ada",
        Some(json!({ "label": "for bee" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // Grants, quotas, state: the door's.
    for (method, path, body) in [
        (
            "POST",
            "/api/grants",
            json!({ "grantee": "scout", "actions": ["review"] }),
        ),
        ("POST", "/api/principals/bee/quota", json!({ "repos": 1 })),
        (
            "POST",
            "/api/principals/bee/state",
            json!({ "active": false }),
        ),
    ] {
        let (status, answer) = api(&public, method, path, "ada", Some(body)).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path}: {answer}");
    }
    // Reading stays public; the People page does not.
    let (status, _) = api(&public, "GET", "/api/principals/bee", "ada", None).await;
    assert_eq!(status, StatusCode::OK);
    let (_, cookie) = sign_in_as(&forge, "ada").await;
    let (status, page) = page_with_cookie(&public, "/people", &cookie).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{page}");
    assert!(page.contains("Nothing lives here"), "{page}");
    let (status, _) = page_with_cookie(&door, "/people", &cookie).await;
    assert_eq!(status, StatusCode::OK);
}

/// The door is not a list of paths but where the admin grant counts:
/// on the public listener, ada's unscoped admin reaches nothing she
/// does not own, on routes that are anybody's the rest of the time.
#[tokio::test(flavor = "multi_thread")]
async fn the_admin_grant_counts_only_at_the_door() {
    let forge = boot().await;
    let (public, door) = split_listeners(&forge);
    let bee = json!({ "id": "bee", "kind": "human", "display": "Bee" });
    let (status, body) = api(&door, "POST", "/api/principals", "ada", Some(bee)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = api(
        &public,
        "POST",
        "/api/repos",
        "bee",
        Some(json!({ "name": "private" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = api(
        &public,
        "POST",
        "/api/principals/bee/tokens",
        "bee",
        Some(json!({ "label": "mine" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = body["id"].as_str().unwrap_or_default().to_owned();
    assert!(!token.is_empty(), "{body}");

    // What the leaked admin token could do to bee through the tunnel.
    let acts = [
        (
            "POST",
            "/api/repos/bee/private/visibility",
            json!({ "visibility": "public" }),
        ),
        (
            "POST",
            "/api/repos/bee/private/transfer",
            json!({ "to": "ada" }),
        ),
        (
            "POST",
            "/api/repos/bee/private/policy",
            json!({
                "require_executed_check": false,
                "independence": "human_or_two_models",
                "require_runner_verification": false,
                "required_domains": [],
                "agents_act_in_sessions": false
            }),
        ),
        (
            "POST",
            "/api/repos/bee/private/rename",
            json!({ "to": "taken" }),
        ),
        ("POST", "/api/repos/bee/private/archive", json!({})),
        ("POST", &format!("/api/tokens/{token}/revoke"), json!({})),
    ];
    for (method, path, body) in &acts {
        let (status, answer) = api(&public, method, path, "ada", Some(body.clone())).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path}: {answer}");
    }
    // The repository is still bee's, private, and hers to read alone.
    let (status, _) = api(&public, "GET", "/api/repos/bee/private", "ada", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = api(&public, "GET", "/api/repos/bee/private", "bee", None).await;
    assert_eq!(status, StatusCode::OK);
    // At the door the same token runs the forge.
    let (status, answer) = api(
        &door,
        "POST",
        "/api/repos/bee/private/visibility",
        "ada",
        Some(json!({ "visibility": "public" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    let (status, answer) = api(&door, "POST", acts[5].1, "ada", Some(json!({}))).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    // And what is ada's own stays hers on either listener.
    let (status, answer) = api(
        &public,
        "POST",
        "/api/repos",
        "ada",
        Some(json!({ "name": "hers" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    let (status, answer) = api(
        &public,
        "POST",
        "/api/repos/ada/hers/visibility",
        "ada",
        Some(json!({ "visibility": "public" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
}

/// An invitation reaches an account nobody has been yet. One that
/// somebody has signed in to is theirs: a new address is refused, the
/// address already on it is not.
#[tokio::test(flavor = "multi_thread")]
async fn an_invitation_never_hands_over_a_claimed_account() {
    let tmp = tempfile::tempdir().unwrap();
    let outbox = tmp.path().join("mail.txt");
    let forge = boot_mailing_public(&format!("cat >> {}", outbox.display())).await;
    let app = &forge.app;
    let invite = |id: &str, email: &str| json!({ "id": id, "email": email });
    let (status, body) = api(
        app,
        "POST",
        "/api/invitations",
        "ada",
        Some(invite("jane", "jane@example.test")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // Not yet come: the operator may still correct the address.
    let (status, body) = api(
        app,
        "POST",
        "/api/invitations",
        "ada",
        Some(invite("jane", "jane@work.test")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let mail = std::fs::read_to_string(&outbox).unwrap_or_default();
    let link = mail
        .lines()
        .filter_map(|l| l.split_whitespace().find(|w| w.contains("/join?token=")))
        .next_back()
        .unwrap()
        .trim_matches(|c| c == '<' || c == '>')
        .to_owned();
    let path = link
        .split("https://forge.example")
        .nth(1)
        .unwrap()
        .to_owned();
    // Jane follows it: the account is hers now.
    let (status, _) = get_redirect(app, &path, "").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (status, body) = api(
        app,
        "POST",
        "/api/invitations",
        "ada",
        Some(invite("jane", "mallory@attacker.test")),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("already somebody's"),
        "{body}"
    );
    // The address that is hers may be sent a fresh link.
    let (status, body) = api(
        app,
        "POST",
        "/api/invitations",
        "ada",
        Some(invite("jane", "jane@work.test")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // And ada, who has a password, cannot be re-addressed either.
    let (status, body) = api(
        app,
        "POST",
        "/api/invitations",
        "ada",
        Some(invite("ada", "mallory@attacker.test")),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
}

/// Who asked for an account is the operator's to read and to answer.
#[tokio::test(flavor = "multi_thread")]
async fn the_waitlist_is_read_and_answered_behind_the_door() {
    let forge = boot().await;
    let app = &forge.app;
    post_public_form(app, "/waitlist", "email=jane%40example.test&note=for+work").await;
    post_public_form(app, "/waitlist", "email=cto%40acme.test&company=Acme").await;
    let (status, body) = api(app, "GET", "/api/waitlist", "scout", None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, body) = api(app, "GET", "/api/waitlist", "ada", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["waitlist"][0]["email"], "jane@example.test");
    assert_eq!(body["waitlist"][0]["note"], "for work");
    assert!(body["waitlist"][0].get("company").is_none(), "{body}");
    assert_eq!(body["waitlist"][1]["company"], "Acme", "{body}");
    // Inviting her makes the account, puts the address on it, and takes
    // her off the list; with no mailer the link comes back to hand over.
    let (status, invited) = api(
        app,
        "POST",
        "/api/invitations",
        "ada",
        Some(json!({ "id": "jane", "display": "Jane", "email": "jane@example.test" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{invited}");
    assert_eq!(invited["mailed"], false);
    let link = invited["link"].as_str().expect("a link to hand over");
    assert!(link.contains("/join?token="), "{link}");
    let (_, list) = api(app, "GET", "/api/waitlist", "ada", None).await;
    assert_eq!(
        list["waitlist"].as_array().map(Vec::len),
        Some(1),
        "only the company is left: {list}"
    );
    assert_eq!(list["waitlist"][0]["email"], "cto@acme.test", "{list}");
    let (_, jane) = api(app, "GET", "/api/principals/jane", "ada", None).await;
    assert_eq!(jane["kind"], "human", "{jane}");
    // The link signs her in once.
    let path = link
        .split_once("/join")
        .map(|(_, rest)| format!("/join{rest}"))
        .unwrap();
    let request = Request::builder().uri(&path).body(Body::empty()).unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let signed = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .any(|v| v.to_str().unwrap_or("").starts_with("cairn_session="));
    assert!(signed, "following the invitation signs jane in");
    let request = Request::builder().uri(&path).body(Body::empty()).unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let again = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .any(|v| v.to_str().unwrap_or("").starts_with("cairn_session="));
    assert!(!again, "and only once");
    // Inviting again replaces the open invitation rather than adding one.
    let (status, twice) = api(
        app,
        "POST",
        "/api/invitations",
        "ada",
        Some(json!({ "id": "jane", "email": "jane@example.test" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{twice}");
    // An agent cannot be invited.
    let (status, refused) = api(
        app,
        "POST",
        "/api/invitations",
        "ada",
        Some(json!({ "id": "scout", "email": "scout@example.test" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    // Leaving the list by hand.
    post_public_form(app, "/waitlist", "email=bob%40example.test").await;
    let (status, removed) = api(
        app,
        "DELETE",
        "/api/waitlist/bob%40example.test",
        "ada",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{removed}");
    assert_eq!(removed["removed"], true);
}

/// When the forge can mail, the invitation goes by mail and the link
/// is in the mail and nowhere else.
#[tokio::test(flavor = "multi_thread")]
async fn an_invitation_is_mailed_when_the_forge_can_mail() {
    let tmp = tempfile::tempdir().unwrap();
    let outbox = tmp.path().join("mail.txt");
    let forge = boot_mailing_public(&format!("cat >> {}", outbox.display())).await;
    let (status, invited) = api(
        &forge.app,
        "POST",
        "/api/invitations",
        "ada",
        Some(json!({ "id": "jane", "email": "jane@example.test" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{invited}");
    assert_eq!(invited["mailed"], true);
    assert!(invited["link"].is_null(), "{invited}");
    let mail = std::fs::read_to_string(&outbox).unwrap_or_default();
    assert!(mail.contains("https://forge.example/join?token="), "{mail}");
    assert!(mail.contains("ada has invited you"), "{mail}");
}

/// What people said broke is read and dismissed behind the door.
#[tokio::test(flavor = "multi_thread")]
async fn reports_are_read_and_dismissed_behind_the_door() {
    let forge = boot().await;
    let app = &forge.app;
    post_public_form(
        app,
        "/report",
        "what=The+log+page+is+blank&place=%2Fada%2Fdemo%2Flog&contact=me%40example.test",
    )
    .await;
    let (status, body) = api(app, "GET", "/api/reports", "scout", None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, body) = api(app, "GET", "/api/reports", "ada", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let report = &body["reports"][0];
    assert_eq!(report["what"], "The log page is blank", "{body}");
    let id = report["id"].as_i64().unwrap();
    let (status, gone) = api(
        app,
        "POST",
        &format!("/api/reports/{id}/dismiss"),
        "ada",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{gone}");
    let (_, body) = api(app, "GET", "/api/reports", "ada", None).await;
    assert_eq!(body["reports"].as_array().map(Vec::len), Some(0), "{body}");
    let (status, _) = api(
        app,
        "POST",
        &format!("/api/reports/{id}/dismiss"),
        "ada",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Closed, the sign-up page says so and takes nothing; open, a stranger
/// makes an account and is signed in.
#[tokio::test(flavor = "multi_thread")]
async fn sign_up_is_a_switch() {
    let closed = boot_token_only().await;
    let request = Request::builder()
        .uri("/signup")
        .body(Body::empty())
        .unwrap();
    let response = closed.app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let page = String::from_utf8_lossy(&response.into_body().collect().await.unwrap().to_bytes())
        .into_owned();
    assert!(page.contains("by invitation"), "{page}");
    assert!(!page.contains("Make the account"), "{page}");
    let (status, _) = post_public_form(
        &closed.app,
        "/signup",
        "name=jane&password=a+perfectly+ordinary+password",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "closed means closed");

    let open = boot_open_signup().await;
    let request = Request::builder()
        .uri("/signup")
        .body(Body::empty())
        .unwrap();
    let response = open.app.clone().oneshot(request).await.unwrap();
    let page = String::from_utf8_lossy(&response.into_body().collect().await.unwrap().to_bytes())
        .into_owned();
    assert!(page.contains("Make the account"), "{page}");
    let request = Request::builder()
        .method("POST")
        .uri("/signup")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from("name=jane&display=Jane&email=jane%40example.test&password=a+perfectly+ordinary+password"))
        .unwrap();
    let response = open.app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let signed = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .any(|v| v.to_str().unwrap_or("").starts_with("cairn_session="));
    assert!(signed, "a new account is signed in");
    let (status, jane) = api_with_token(
        &open.app,
        "GET",
        "/api/principals/jane",
        &open.ada_token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{jane}");
    assert_eq!(jane["kind"], "human");
    // The same name twice is refused; a short password is refused; a
    // reserved name is refused.
    for body in [
        "name=jane&password=a+perfectly+ordinary+password",
        "name=bob&password=short",
        "name=login&password=a+perfectly+ordinary+password",
    ] {
        let (status, location) = post_public_form(&open.app, "/signup", body).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
        assert!(location.contains("error"), "{body}: {location}");
    }
    // The log says jane made jane.
    let (_, events) = api_with_token(
        &open.app,
        "GET",
        "/api/events?after=0&limit=500",
        &open.ada_token,
        None,
    )
    .await;
    let text = events.to_string();
    assert!(text.contains(r#""actor":"jane""#), "{text}");
}

/// A stranger's account is a reachable person's: it creates nothing
/// until an address is confirmed, and the forge takes only so many.
#[tokio::test(flavor = "multi_thread")]
async fn a_self_made_account_confirms_an_address_first_and_the_forge_fills_up() {
    let tmp = tempfile::tempdir().unwrap();
    let outbox = tmp.path().join("mail.txt");
    let forge = boot_open_signup_mailing(&format!("cat >> {}", outbox.display()), 2).await;
    let app = &forge.app;
    let sign_up = |name: &str| {
        format!(
            "name={name}&display={name}&email={name}%40example.test&password=long-enough-passphrase"
        )
    };
    let (status, location) = post_public_form(app, "/signup", &sign_up("bee")).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{location}");
    assert!(!location.contains("error="), "{location}");
    // Bee is somebody, and is not yet allowed to make anything.
    let (status, body) = api(app, "GET", "/api/principals/bee", "ada", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["self_made"], true, "{body}");
    let (status, body) = api(
        app,
        "POST",
        "/api/repos",
        "bee",
        Some(json!({ "name": "mine" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("confirmed an address"),
        "{body}"
    );
    let (status, body) = api(
        app,
        "POST",
        "/api/principals",
        "bee",
        Some(json!({ "id": "bee-bot", "kind": "agent", "display": "Bot" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    // The confirmation link went to the address; following it opens the forge.
    let mail = std::fs::read_to_string(&outbox).unwrap_or_default();
    let link = mail
        .split_whitespace()
        .find(|w| w.contains("/verify?token="))
        .unwrap_or_else(|| panic!("no verification link in {mail}"))
        .trim_matches(|c| c == '<' || c == '>')
        .to_owned();
    let path = link
        .split("https://forge.example")
        .nth(1)
        .unwrap()
        .to_owned();
    let (status, _) = get_redirect(app, &path, "").await;
    assert_ne!(status, StatusCode::NOT_FOUND);
    let (status, body) = api(
        app,
        "POST",
        "/api/repos",
        "bee",
        Some(json!({ "name": "mine" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // Two is what this forge takes; the third finds it full, and the
    // form is not a way around the page.
    let (status, _) = post_public_form(app, "/signup", &sign_up("cat")).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (status, page) = page_with_cookie(app, "/signup", "").await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("This forge is full"), "{page}");
    let (status, location) = post_public_form(app, "/signup", &sign_up("dan")).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location, "/signup", "{location}");
    let (status, _) = api(app, "GET", "/api/principals/dan", "ada", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // The operator's registrations do not count against the cap, and
    // are not self-made.
    let (status, body) = api(
        app,
        "POST",
        "/api/principals",
        "ada",
        Some(json!({ "id": "eve", "kind": "human", "display": "Eve" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, eve) = api(app, "GET", "/api/principals/eve", "ada", None).await;
    assert_eq!(eve["self_made"], false, "{eve}");
}
