//! Identity from outside: a provider signs a person in only once they
//! linked it; a workload's token becomes a credential that can only
//! claim a task and open a session.

use crate::common::*;
use axum::http::StatusCode;
use axum::response::Redirect;
use axum::{Json, Router, extract::Query, extract::State, routing::get, routing::post};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// A tiny OpenID provider: discovery, keys, an authorize step that sends
/// the browser straight back with a code, and a token step that turns
/// the code into an EdDSA-signed id token.
#[derive(Clone)]
struct Provider {
    issuer: String,
    jwk_x: String,
    key: Arc<EncodingKey>,
    codes: Arc<Mutex<HashMap<String, (String, String)>>>,
    subject: Arc<Mutex<(String, String)>>,
}

impl Provider {
    fn id_token(&self, sub: &str, email: &str, aud: &str) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let claims = json!({
            "iss": self.issuer, "sub": sub, "aud": aud, "iat": now, "exp": now + 300,
            "email": email, "email_verified": true,
        });
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some("k1".into());
        encode(&header, &claims, &self.key).unwrap()
    }
}

async fn start_provider() -> Provider {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let public = URL_SAFE_NO_PAD.encode(ring::signature::KeyPair::public_key(&pair).as_ref());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}", listener.local_addr().unwrap());
    let provider = Provider {
        issuer: issuer.clone(),
        jwk_x: public,
        key: Arc::new(EncodingKey::from_ed_der(pkcs8.as_ref())),
        codes: Arc::new(Mutex::new(HashMap::new())),
        subject: Arc::new(Mutex::new(("sub-ada".into(), "ada@example.test".into()))),
    };
    let app = Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(|State(s): State<Provider>| async move {
                Json(json!({
                    "issuer": s.issuer,
                    "authorization_endpoint": format!("{}/authorize", s.issuer),
                    "token_endpoint": format!("{}/token", s.issuer),
                    "jwks_uri": format!("{}/jwks", s.issuer),
                }))
            }),
        )
        .route(
            "/jwks",
            get(|State(s): State<Provider>| async move {
                Json(json!({ "keys": [{ "kty": "OKP", "crv": "Ed25519", "kid": "k1", "alg": "EdDSA", "use": "sig", "x": s.jwk_x }] }))
            }),
        )
        .route(
            "/authorize",
            get(|State(s): State<Provider>, Query(q): Query<HashMap<String, String>>| async move {
                let code = format!("code-{}", s.codes.lock().unwrap().len());
                let nonce = q.get("nonce").cloned().unwrap_or_default();
                let (sub, _) = s.subject.lock().unwrap().clone();
                s.codes.lock().unwrap().insert(code.clone(), (nonce, sub));
                Redirect::to(&format!("{}?code={code}&state={}", q["redirect_uri"], q["state"]))
            }),
        )
        .route(
            "/token",
            post(|State(s): State<Provider>, axum::Form(form): axum::Form<HashMap<String, String>>| async move {
                let Some((nonce, sub)) = s.codes.lock().unwrap().remove(&form["code"]) else {
                    return Json(json!({ "error": "invalid_grant" }));
                };
                let (_, email) = s.subject.lock().unwrap().clone();
                let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
                let claims = json!({
                    "iss": s.issuer, "sub": sub, "aud": form["client_id"], "iat": now, "exp": now + 300,
                    "email": email, "email_verified": true, "nonce": nonce,
                });
                let mut header = Header::new(Algorithm::EdDSA);
                header.kid = Some("k1".into());
                Json(json!({ "id_token": encode(&header, &claims, &s.key).unwrap(), "token_type": "Bearer", "access_token": "x" }))
            }),
        )
        .with_state(provider.clone());
    tokio::spawn(axum::serve(listener, app).into_future());
    provider
}

fn forge_provider(issuer: &str) -> cairn_server::oidc::Provider {
    cairn_server::oidc::Provider {
        issuer: issuer.to_owned(),
        client_id: "cairn".into(),
        client_secret: "shh".into(),
        label: "Example".into(),
        link_by_email: false,
    }
}

/// Walk the browser's part of the dance: the forge's redirect to the
/// provider, the provider's redirect back, the forge's callback.
async fn round_trip(
    forge: &Forge,
    provider: &Provider,
    start: &str,
    cookie: &str,
) -> (StatusCode, String, String) {
    let (status, to_provider) = if start.starts_with("/you/") {
        post_form(&forge.app, start, cookie, "").await
    } else {
        get_redirect(&forge.app, start, cookie).await
    };
    assert_eq!(status, StatusCode::SEE_OTHER, "{to_provider}");
    assert!(
        to_provider.starts_with(&format!("{}/authorize?", provider.issuer)),
        "{to_provider}"
    );
    let back = tokio::task::spawn_blocking(move || {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .max_redirects(0)
            .http_status_as_error(false)
            .build()
            .into();
        let response = agent.get(&to_provider).call().unwrap();
        response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned()
    })
    .await
    .unwrap();
    let path = back.trim_start_matches("https://forge.example").to_owned();
    get_redirect_with_cookie(&forge.app, &path, cookie).await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_provider_identity_signs_in_only_once_it_is_linked() {
    let provider = start_provider().await;
    let forge = boot_with_oidc(forge_provider(&provider.issuer)).await;
    let app = &forge.app;

    // The login page offers it, since the forge knows its public address.
    let (_, login) = page_with_cookie(app, "/login", "").await;
    assert!(login.contains("Continue with Example"), "{login}");

    // Unlinked: told so, not signed in.
    let (status, next, _) = round_trip(&forge, &provider, "/login/oidc", "").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(next.contains("not+linked"), "{next}");

    // ada links it from Settings, signed in with her password.
    let (_, ada) = sign_in_as(&forge, "ada").await;
    let (status, next, _) = round_trip(&forge, &provider, "/you/settings/oidc/link", &ada).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{next}");
    assert_eq!(next, "/you/settings?done=1");
    let (_, settings) = page_with_cookie(app, "/you/settings", &ada).await;
    assert!(settings.contains("ada@example.test"), "{settings}");
    assert!(settings.contains("Unlink"), "{settings}");

    // Now the provider signs her in.
    let (status, next, set_cookie) = round_trip(&forge, &provider, "/login/oidc", "").await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{next}");
    assert_eq!(next, "/");
    let fresh = set_cookie.split(';').next().unwrap().to_owned();
    let (status, you) = page_with_cookie(app, "/you/settings", &fresh).await;
    assert_eq!(status, StatusCode::OK);
    assert!(you.contains(r#"title="ada""#), "signed in as ada: {you}");

    // The same identity cannot be linked to somebody else.
    api_with_token(
        app,
        "POST",
        "/api/principals",
        &forge.ada_token,
        Some(json!({ "id": "bee", "kind": "human", "display": "Bee" })),
    )
    .await;
    let (_, bee) = sign_in_as(&forge, "bee").await;
    let (status, next, _) = round_trip(&forge, &provider, "/you/settings/oidc/link", &bee).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(next.contains("already+linked"), "{next}");

    // Unlinking closes the door again.
    let (status, _) = post_form(app, "/you/settings/oidc/unlink", &ada, "subject=sub-ada").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (_, next, _) = round_trip(&forge, &provider, "/login/oidc", "").await;
    assert!(next.contains("not+linked"), "{next}");
    let (_, log) = page_with_cookie(app, "/inbox", &ada).await;
    let _ = log;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_workload_token_becomes_a_credential_that_can_only_begin_work() {
    let provider = start_provider().await;
    let forge = boot_with_oidc(forge_provider(&provider.issuer)).await;
    let app = &forge.app;
    let token = provider.id_token("ci-job-7", "ci@example.test", "https://forge.example");

    // Unbound: refused, with the way to fix it.
    let (status, refused) = api_anonymous(
        app,
        "POST",
        "/api/identity/exchange",
        Some(json!({ "token": token })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refused}");
    assert!(
        refused["error"].as_str().unwrap().contains("bound"),
        "{refused}"
    );

    // Whoever runs the forge binds the workload to scout; people cannot be bound.
    let (status, _) = api(
        app,
        "POST",
        "/api/principals/ada/workload",
        "ada",
        Some(json!({ "issuer": provider.issuer, "subject": "ci-job-7" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = api_with_token(
        app,
        "POST",
        "/api/principals/scout/workload",
        &forge.scout_token,
        Some(json!({ "issuer": provider.issuer, "subject": "ci-job-7" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, bound) = api(
        app,
        "POST",
        "/api/principals/scout/workload",
        "ada",
        Some(json!({ "issuer": provider.issuer, "subject": "ci-job-7" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{bound}");

    let (status, drawn) = api_anonymous(
        app,
        "POST",
        "/api/identity/exchange",
        Some(json!({ "token": token })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{drawn}");
    assert_eq!(drawn["principal"], "scout");
    let credential = drawn["token"].as_str().unwrap().to_owned();
    // It can begin work and nothing else.
    let (status, task) = api(
        app,
        "POST",
        "/api/tasks",
        "ada",
        Some(json!({ "title": "For the workload", "spec": "Do it.", "repo": "demo" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let task_id = task["id"].as_str().unwrap();
    let (status, _) = api_with_token(
        app,
        "POST",
        &format!("/api/tasks/{task_id}/claim"),
        &credential,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, session) = api_with_token(
        app,
        "POST",
        &format!("/api/tasks/{task_id}/sessions"),
        &credential,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{session}");
    let (status, refused) = api_with_token(
        app,
        "POST",
        "/api/changes",
        &credential,
        Some(json!({ "repo": "demo", "target": "main", "title": "Not with this" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refused}");
    // From the session it draws a real one.
    let (status, scoped) = api_with_token(
        app,
        "POST",
        &format!(
            "/api/sessions/{}/credential",
            session["id"].as_str().unwrap()
        ),
        &credential,
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{scoped}");
    let (status, _) = api_with_token(
        app,
        "POST",
        "/api/changes",
        scoped["token"].as_str().unwrap(),
        Some(json!({ "repo": "demo", "target": "main", "title": "With this" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Wrong audience or not a token: refused.
    let elsewhere = provider.id_token("ci-job-7", "ci@example.test", "https://someone.else");
    let (status, _) = api_anonymous(
        app,
        "POST",
        "/api/identity/exchange",
        Some(json!({ "token": elsewhere })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = api_anonymous(
        app,
        "POST",
        "/api/identity/exchange",
        Some(json!({ "token": "not.a.token" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
