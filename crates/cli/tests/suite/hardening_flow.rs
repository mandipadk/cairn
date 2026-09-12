//! The doors the second adversarial pass found open, closed and held
//! closed: what a session credential may not do, what an agent may not
//! hold, what leaves with a person, what a transfer takes with it, and
//! the shape of every refusal a program reads.

use crate::common::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

async fn person(forge: &Forge, id: &str) {
    let (status, body) = api(
        &forge.app,
        "POST",
        "/api/principals",
        "ada",
        Some(json!({ "id": id, "kind": "human", "display": id })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

async fn team(forge: &Forge, id: &str, members: &[&str]) {
    let (status, body) = api(
        &forge.app,
        "POST",
        "/api/principals",
        "ada",
        Some(json!({ "id": id, "kind": "team", "display": id })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    for member in members {
        let (status, body) = api(
            &forge.app,
            "POST",
            &format!("/api/teams/{id}/members"),
            "ada",
            Some(json!({ "member": member })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
}

/// A request as a program makes it, with the answer's type and body.
async fn raw(
    app: &axum::Router,
    method: &str,
    path: &str,
    actor: Option<&str>,
) -> (StatusCode, String, String) {
    let mut request = Request::builder().method(method).uri(path);
    if let Some(actor) = actor {
        request = request.header("x-ambolt-principal", actor);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        content_type,
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

async fn session_credential(forge: &Forge) -> String {
    let app = &forge.app;
    let (status, task) = api_with_token(
        app,
        "POST",
        "/api/tasks",
        &forge.ada_token,
        Some(json!({ "title": "Work", "spec": "Do it in demo.", "repo": "ada/demo" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{task}");
    let task_id = task["id"].as_str().unwrap().to_owned();
    let (status, _) = api_with_token(
        app,
        "POST",
        &format!("/api/tasks/{task_id}/claim"),
        &forge.scout_token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, session) = api_with_token(
        app,
        "POST",
        &format!("/api/tasks/{task_id}/sessions"),
        &forge.scout_token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{session}");
    let session = session["id"].as_str().unwrap();
    let (status, drawn) = api_with_token(
        app,
        "POST",
        &format!("/api/sessions/{session}/credential"),
        &forge.scout_token,
        Some(json!({ "minutes": 30 })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{drawn}");
    drawn["token"].as_str().unwrap().to_owned()
}

/// A credential drawn for one task's work does none of the standing
/// acts, however it would otherwise reach them: by being its holder's
/// own, or by holding the agent.
#[tokio::test(flavor = "multi_thread")]
async fn a_session_credential_does_no_standing_act() {
    let forge = boot().await;
    let app = &forge.app;
    let credential = session_credential(&forge).await;
    // scout's own standing token, which the credential's holder could
    // revoke as itself.
    let (_, tokens) = api(app, "GET", "/api/principals/scout/tokens", "ada", None).await;
    let list = tokens
        .as_array()
        .cloned()
        .or_else(|| tokens["tokens"].as_array().cloned())
        .expect("a list of tokens");
    let token_id = list[0]["id"].as_str().unwrap().to_owned();
    for (path, body) in [
        ("/api/repos".to_owned(), json!({ "name": "under-a-scope" })),
        (
            "/api/repos/ada/demo/transfer".to_owned(),
            json!({ "to": "ada" }),
        ),
        (
            "/api/principals/arbiter/state".to_owned(),
            json!({ "active": false }),
        ),
        (format!("/api/tokens/{token_id}/revoke"), json!({})),
    ] {
        let (status, refused) = api_with_token(app, "POST", &path, &credential, Some(body)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}: {refused}");
        assert!(
            refused["error"]
                .as_str()
                .unwrap_or_default()
                .contains("session credential"),
            "{path}: {refused}"
        );
    }
    // The token it could not revoke still works.
    let (status, _) = api_with_token(app, "GET", "/api/inbox", &forge.scout_token, None).await;
    assert_eq!(status, StatusCode::OK);
}

/// A person who leaves takes the credentials they drew for agents that
/// are not theirs: a team's agent, whose token they kept.
#[tokio::test(flavor = "multi_thread")]
async fn a_deactivated_person_takes_their_drawn_credentials_with_them() {
    let forge = boot().await;
    let app = &forge.app;
    person(&forge, "bee").await;
    team(&forge, "crew", &["bee"]).await;
    let (status, body) = api(
        app,
        "POST",
        "/api/principals",
        "bee",
        Some(json!({ "id": "hand", "kind": "agent", "display": "Hand", "owner": "crew" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, minted) = api(
        app,
        "POST",
        "/api/principals/hand/tokens",
        "bee",
        Some(json!({ "label": "kept by bee" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{minted}");
    let hand = minted["token"].as_str().unwrap().to_owned();
    let (status, _) = api_with_token(app, "GET", "/api/inbox", &hand, None).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "hand's token works while bee is here"
    );

    let (status, body) = api(
        app,
        "POST",
        "/api/principals/bee/state",
        "ada",
        Some(json!({ "active": false })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _) = api_with_token(app, "GET", "/api/inbox", &hand, None).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the token bee drew for the team's agent left with bee"
    );
    // The agent itself is the team's and goes on.
    let (_, record) = api(app, "GET", "/api/principals/hand", "ada", None).await;
    assert_eq!(record["active"], true, "{record}");
}

/// A stopped owner takes nothing new, and an agent has no quota to ask
/// about.
#[tokio::test(flavor = "multi_thread")]
async fn a_stopped_owner_takes_nothing_new() {
    let forge = boot().await;
    let app = &forge.app;
    person(&forge, "bee").await;
    team(&forge, "crew", &["bee"]).await;
    let (status, body) = api(
        app,
        "POST",
        "/api/principals/crew/state",
        "ada",
        Some(json!({ "active": false })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, refused) = api(
        app,
        "POST",
        "/api/principals",
        "bee",
        Some(json!({ "id": "hand", "kind": "agent", "display": "Hand", "owner": "crew" })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{refused}");
    assert!(
        refused["error"]
            .as_str()
            .unwrap_or_default()
            .contains("takes nothing new"),
        "{refused}"
    );
    let (status, refused) = api(app, "GET", "/api/principals/scout/quota", "ada", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    assert!(
        refused["error"]
            .as_str()
            .unwrap_or_default()
            .contains("ask about ada"),
        "{refused}"
    );
}

/// A transfer is the owner's or the forge's — a grant of admin on the
/// repository does not move it — and what the old owner handed out on
/// it is revoked on the record, with the reason.
#[tokio::test(flavor = "multi_thread")]
async fn a_transfer_is_the_owners_and_takes_its_grants_with_it_on_the_record() {
    let forge = boot().await;
    let app = &forge.app;
    person(&forge, "bee").await;
    person(&forge, "cat").await;
    let (status, granted) = api(
        app,
        "POST",
        "/api/grants",
        "ada",
        Some(json!({ "grantee": "cat", "repo": "ada/demo", "actions": ["admin"] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{granted}");
    // Admin on the repository runs it; it does not carry it off.
    let (status, refused) = api(
        app,
        "POST",
        "/api/repos/ada/demo/transfer",
        "cat",
        Some(json!({ "to": "cat" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refused}");

    let (status, body) = api(
        app,
        "POST",
        "/api/repos/ada/demo/transfer",
        "ada",
        Some(json!({ "to": "bee" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, accepted) = api(
        app,
        "POST",
        "/api/repos/ada/demo/transfer/accept",
        "bee",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{accepted}");
    let (_, events) = api(app, "GET", "/api/events?after=0&limit=500", "ada", None).await;
    let events = events
        .as_array()
        .cloned()
        .or_else(|| events["events"].as_array().cloned())
        .expect("events");
    let revocation = events
        .iter()
        .find(|e| e["event"]["kind"] == "grant_revoked" || e["kind"] == "grant_revoked");
    let revocation = revocation.expect("the grant was revoked by an event of its own");
    let text = revocation.to_string();
    assert!(
        text.contains("transferred to bee"),
        "the reason names the transfer: {text}"
    );
    let (_, grants) = api(app, "GET", "/api/grants?grantee=cat", "ada", None).await;
    assert!(
        !grants.to_string().contains("\"revoked\":false"),
        "nothing cat held on it is live: {grants}"
    );
}

/// A member may not take an organisation's repository for themselves;
/// they may offer it to somebody else.
#[tokio::test(flavor = "multi_thread")]
async fn a_member_may_not_take_the_organisations_repository() {
    let forge = boot().await;
    let app = &forge.app;
    person(&forge, "bee").await;
    person(&forge, "cat").await;
    team(&forge, "crew", &["bee"]).await;
    let (status, body) = api(
        app,
        "POST",
        "/api/repos",
        "bee",
        Some(json!({ "name": "tool", "owner": "crew" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, refused) = api(
        app,
        "POST",
        "/api/repos/crew/tool/transfer",
        "bee",
        Some(json!({ "to": "bee" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    let (status, body) = api(
        app,
        "POST",
        "/api/repos/crew/tool/transfer",
        "bee",
        Some(json!({ "to": "cat" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// The labels that make a token an invitation are the forge's to write.
#[tokio::test(flavor = "multi_thread")]
async fn an_invitation_label_is_the_forges_own() {
    let forge = boot().await;
    let app = &forge.app;
    for label in ["invitation", "invitation:mailed", "invitation-ish"] {
        let (status, refused) = api(
            app,
            "POST",
            "/api/principals/ada/tokens",
            "ada",
            Some(json!({ "label": label })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{label}: {refused}");
    }
    let (status, refused) = api(
        app,
        "POST",
        "/api/principals/ada/tokens",
        "ada",
        Some(json!({ "label": "x".repeat(100_000) })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
}

/// A retired agent gets no token, is marked on the page, and a live
/// one can be retired from there.
#[tokio::test(flavor = "multi_thread")]
async fn a_retired_agent_is_marked_and_takes_no_token() {
    let forge = boot().await;
    let app = &forge.app;
    let (status, body) = api(
        app,
        "POST",
        "/api/principals/scout/state",
        "ada",
        Some(json!({ "active": false })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, refused) = api(
        app,
        "POST",
        "/api/principals/scout/tokens",
        "ada",
        Some(json!({ "label": "for a stopped agent" })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{refused}");

    let (_, cookie) = sign_in_as(&forge, "ada").await;
    let (status, page) = page_with_cookie(app, "/agents", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("retired"), "the page says so: {page}");
    assert_eq!(
        page.matches("New token").count(),
        1,
        "only the live agent (arbiter) offers a token"
    );
    // Retire the other from the page.
    let (status, location) =
        post_form(app, "/agents", &cookie, "action=retire&grantee=arbiter").await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{location}");
    let (_, record) = api(app, "GET", "/api/principals/arbiter", "ada", None).await;
    assert_eq!(record["active"], false, "{record}");
}

/// Off the map, the API still answers in its own shape.
#[tokio::test(flavor = "multi_thread")]
async fn the_api_answers_in_its_own_shape_off_the_map() {
    let forge = boot().await;
    let app = &forge.app;
    let (status, kind, body) = raw(app, "GET", "/api/nope", Some("ada")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(kind.contains("json"), "{kind}: {body}");
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap()["kind"],
        "not_found"
    );
    let (status, kind, body) = raw(app, "PUT", "/api/principals/ada/quota", Some("ada")).await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED, "{body}");
    assert!(kind.contains("json"), "{kind}: {body}");
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap()["kind"],
        "method_not_allowed"
    );
    let (status, kind, body) = raw(app, "GET", "/api/events?after=abc", Some("ada")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(kind.contains("json"), "{kind}: {body}");
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap()["kind"],
        "invalid"
    );
    // A path no page answers to is a page that says so, to a stranger
    // and to somebody signed in alike. (A short unknown path is a
    // possible private name, and those send a stranger to sign in
    // instead; that is the owner page's business, not the router's.)
    let (status, kind, page) = raw(app, "GET", "/no/where/at/all/and/then/some/more", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{page}");
    assert!(kind.contains("html"), "{kind}");
    assert!(page.contains("Nothing lives here"), "{page}");
    let (_, cookie) = sign_in_as(&forge, "ada").await;
    let request = Request::builder()
        .uri("/no/where/at/all/and/then/some/more")
        .header("cookie", &cookie)
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let page = String::from_utf8_lossy(&bytes).into_owned();
    assert_eq!(status, StatusCode::NOT_FOUND, "sent to {location}: {page}");
    assert!(page.contains("Nothing lives here"), "{page}");
}

/// Too many sign-ins get a page, in a browser.
#[tokio::test(flavor = "multi_thread")]
async fn too_many_sign_ins_get_a_page() {
    let forge = boot().await;
    let app = &forge.app;
    let mut last = (StatusCode::OK, String::new(), String::new());
    for _ in 0..12 {
        let request = Request::builder()
            .method("POST")
            .uri("/login")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from("principal=ada&password=wrong"))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let kind = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        last = (status, kind, String::from_utf8_lossy(&bytes).into_owned());
        if status == StatusCode::TOO_MANY_REQUESTS {
            break;
        }
    }
    assert_eq!(last.0, StatusCode::TOO_MANY_REQUESTS, "{}", last.2);
    assert!(last.1.contains("html"), "a page, not a line: {}", last.1);
    assert!(last.2.contains("Too many"), "{}", last.2);
}

/// An organisation's members are not a stranger's to read.
#[tokio::test(flavor = "multi_thread")]
async fn an_organisations_members_are_not_a_strangers_to_read() {
    let forge = boot().await;
    let app = &forge.app;
    person(&forge, "bee").await;
    team(&forge, "crew", &["bee"]).await;
    let (status, body) = api(
        app,
        "POST",
        "/api/repos",
        "ada",
        Some(json!({ "name": "tool", "owner": "crew" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = api(
        app,
        "POST",
        "/api/repos/crew/tool/visibility",
        "ada",
        Some(json!({ "visibility": "public" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _, page) = raw(app, "GET", "/crew", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        page.contains("tool"),
        "the public repository is there: {page}"
    );
    assert!(!page.contains("bee"), "the members are not: {page}");
    let (_, cookie) = sign_in_as(&forge, "ada").await;
    let (status, page) = page_with_cookie(app, "/crew", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("bee"), "signed in, they are: {page}");
}

/// Whoever holds a repository decides who acts on it, whoever issued
/// the grant.
#[tokio::test(flavor = "multi_thread")]
async fn an_owner_revokes_a_grant_on_their_repository_whoever_issued_it() {
    let forge = boot().await;
    let app = &forge.app;
    person(&forge, "bee").await;
    let (status, body) = api(
        app,
        "POST",
        "/api/repos",
        "bee",
        Some(json!({ "name": "mine" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, granted) = api(
        app,
        "POST",
        "/api/grants",
        "ada",
        Some(json!({ "grantee": "scout", "repo": "bee/mine", "actions": ["review"] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{granted}");
    let grant = granted["id"].as_str().unwrap();
    let (status, body) = api(
        app,
        "POST",
        &format!("/api/grants/{grant}/revoke"),
        "bee",
        Some(json!({ "reason": "not on my repository" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}
