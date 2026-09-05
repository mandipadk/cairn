//! Identity from outside: sign-in with an OpenID Connect provider for
//! people, and workload identity for agents.
//!
//! Nothing links itself. A provider identity signs a person in only once
//! that person, signed in some other way, linked it in Settings - or,
//! when the operator said so, once its verified email matches exactly
//! one person here. A workload (a CI job, an agent runtime) presents a
//! token from its issuer; if whoever runs the forge bound that issuer
//! and subject to an agent, the forge answers with a credential that can
//! do one thing: claim a task and open a session. From there the session
//! draws its own credential, and no standing agent token need exist.

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// The provider people sign in with.
#[derive(Clone, Debug)]
pub struct Provider {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    /// What the button says: "Google", "Okta", "Company SSO".
    pub label: String,
    /// Link an unknown identity to the one person whose verified email
    /// matches. Off unless the operator says so.
    pub link_by_email: bool,
}

/// Everything the forge believes about identity from outside.
pub struct Trust {
    pub provider: Option<Provider>,
    /// Issuers whose tokens a workload may exchange.
    pub workload_issuers: Vec<String>,
    /// The audience a workload token must name: the forge's public URL
    /// unless the operator chose another.
    pub audience: Option<String>,
    discovery: Mutex<HashMap<String, (Instant, Discovery)>>,
    keys: Mutex<HashMap<String, (Instant, JwkSet)>>,
    http: ureq::Agent,
}

#[derive(Clone, Debug, Deserialize)]
struct Discovery {
    authorization_endpoint: Option<String>,
    token_endpoint: Option<String>,
    jwks_uri: String,
}

/// What a verified token says about who presented it.
#[derive(Debug, Deserialize)]
pub struct Claims {
    pub sub: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: Option<bool>,
    #[serde(default)]
    pub nonce: Option<String>,
}

const CACHE_FOR: Duration = Duration::from_secs(600);

fn same_issuer(a: &str, b: &str) -> bool {
    a.trim_end_matches('/') == b.trim_end_matches('/')
}

impl Trust {
    pub fn new(
        provider: Option<Provider>,
        workload_issuers: Vec<String>,
        audience: Option<String>,
    ) -> Self {
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(10)))
            .build();
        Trust {
            provider,
            workload_issuers,
            audience,
            discovery: Mutex::new(HashMap::new()),
            keys: Mutex::new(HashMap::new()),
            http: config.into(),
        }
    }

    fn discover(&self, issuer: &str) -> Result<Discovery, String> {
        if let Some((at, found)) = self
            .discovery
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(issuer)
            && at.elapsed() < CACHE_FOR
        {
            return Ok(found.clone());
        }
        let url = format!(
            "{}/.well-known/openid-configuration",
            issuer.trim_end_matches('/')
        );
        let found: Discovery = self
            .http
            .get(&url)
            .call()
            .map_err(|e| format!("could not reach {issuer}: {e}"))?
            .body_mut()
            .read_json()
            .map_err(|e| {
                format!("{issuer} answered something other than a discovery document: {e}")
            })?;
        self.discovery
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(issuer.to_owned(), (Instant::now(), found.clone()));
        Ok(found)
    }

    fn keys(&self, issuer: &str, refresh: bool) -> Result<JwkSet, String> {
        if !refresh
            && let Some((at, set)) = self
                .keys
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get(issuer)
            && at.elapsed() < CACHE_FOR
        {
            return Ok(set.clone());
        }
        let jwks_uri = self.discover(issuer)?.jwks_uri;
        let set: JwkSet = self
            .http
            .get(&jwks_uri)
            .call()
            .map_err(|e| format!("could not fetch {issuer}'s keys: {e}"))?
            .body_mut()
            .read_json()
            .map_err(|e| format!("{issuer}'s keys were unreadable: {e}"))?;
        self.keys
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(issuer.to_owned(), (Instant::now(), set.clone()));
        Ok(set)
    }

    /// Verify a token from `issuer` meant for `audience`: signature by a
    /// published key, issuer, audience and expiry.
    pub fn verify(&self, issuer: &str, token: &str, audience: &str) -> Result<Claims, String> {
        let header = decode_header(token).map_err(|e| format!("not a signed token: {e}"))?;
        let alg = match header.alg {
            Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::ES256
            | Algorithm::ES384
            | Algorithm::EdDSA => header.alg,
            other => return Err(format!("token algorithm {other:?} is not accepted")),
        };
        let pick = |set: &JwkSet| match &header.kid {
            Some(kid) => set.find(kid).cloned(),
            None => set.keys.first().cloned(),
        };
        let jwk = match pick(&self.keys(issuer, false)?) {
            Some(jwk) => jwk,
            None => pick(&self.keys(issuer, true)?)
                .ok_or_else(|| "the token's key is not one the issuer publishes".to_owned())?,
        };
        let key = DecodingKey::from_jwk(&jwk).map_err(|e| format!("unusable issuer key: {e}"))?;
        let mut validation = Validation::new(alg);
        validation.set_issuer(&[issuer, issuer.trim_end_matches('/')]);
        validation.set_audience(&[audience]);
        validation.validate_exp = true;
        let data = decode::<Claims>(token, &key, &validation)
            .map_err(|e| format!("token refused: {e}"))?;
        Ok(data.claims)
    }
}

fn random_urlsafe() -> String {
    URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
}

fn provider_of(app: &AppState) -> Option<(std::sync::Arc<Trust>, Provider)> {
    let trust = app.oidc()?;
    let provider = trust.provider.clone()?;
    Some((trust, provider))
}

fn callback_url(app: &AppState) -> Option<String> {
    app.public_url()
        .map(|base| format!("{}/login/oidc/callback", base.trim_end_matches('/')))
}

/// Whether the login page can offer the provider at all.
pub fn label(app: &AppState) -> Option<String> {
    let (_, provider) = provider_of(app)?;
    callback_url(app)?;
    Some(provider.label)
}

#[derive(serde::Serialize, Deserialize)]
struct Pending {
    nonce: String,
    verifier: String,
}

fn to_provider(
    app: &AppState,
    kind: &str,
    principal: Option<&cairn_core::PrincipalId>,
) -> Response {
    let Some((trust, provider)) = provider_of(app) else {
        return login_error("Sign-in with a provider is not set up here");
    };
    let Some(redirect_uri) = callback_url(app) else {
        return login_error("This forge does not know its public address yet");
    };
    let discovery = match trust.discover(&provider.issuer) {
        Ok(d) => d,
        Err(why) => return login_error(&why),
    };
    let Some(authorize) = discovery.authorization_endpoint else {
        return login_error("The provider offers no way to sign in interactively");
    };
    let pending = Pending {
        nonce: random_urlsafe(),
        verifier: random_urlsafe(),
    };
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(pending.verifier.as_bytes()));
    let payload = serde_json::to_string(&pending).expect("pending serializes");
    let state = match app.with_store(|s| s.put_webauthn_state(principal, kind, &payload)) {
        Ok(id) => id,
        Err(err) => return crate::web::oops(err),
    };
    let url = format!(
        "{authorize}?response_type=code&client_id={}&redirect_uri={}&scope=openid%20email%20profile&state={}&nonce={}&code_challenge={}&code_challenge_method=S256",
        crate::web::urlencode(&provider.client_id),
        crate::web::urlencode(&redirect_uri),
        crate::web::urlencode(&state),
        crate::web::urlencode(&pending.nonce),
        challenge
    );
    Redirect::to(&url).into_response()
}

fn login_error(message: &str) -> Response {
    Redirect::to(&format!("/login?error={}", crate::web::urlencode(message))).into_response()
}

fn settings_error(message: &str) -> Response {
    Redirect::to(&format!(
        "/you/settings?error={}",
        crate::web::urlencode(message)
    ))
    .into_response()
}

/// `GET /login/oidc`: off to the provider.
pub async fn login_begin(State(app): State<AppState>) -> Response {
    to_provider(&app, "oidc-login", None)
}

/// `GET /you/settings/oidc/link`: off to the provider, to come back
/// linked to whoever is signed in now.
pub async fn link_begin(State(app): State<AppState>, viewer: crate::web::Viewer) -> Response {
    to_provider(&app, "oidc-link", Some(&viewer.0))
}

#[derive(Deserialize)]
pub struct Callback {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

#[derive(Deserialize)]
struct TokenAnswer {
    id_token: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

fn not_linked(label: &str, no_email: bool) -> Response {
    let why = if no_email {
        format!(
            "Your {label} account is not linked to anyone here and carries no verified email. Sign in another way, then link it in Settings."
        )
    } else {
        format!(
            "Your {label} account is not linked to anyone here. Sign in another way, then link it in Settings."
        )
    };
    login_error(&why)
}

/// `GET /login/oidc/callback`: the provider sent them back.
pub async fn callback(
    State(app): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(query): Query<Callback>,
) -> Response {
    if let Some(error) = query.error {
        let why = query.error_description.unwrap_or(error);
        return login_error(&format!("The provider said no: {why}"));
    }
    let (Some(code), Some(state)) = (query.code, query.state) else {
        return login_error("The provider sent nothing usable back");
    };
    let Some((trust, provider)) = provider_of(&app) else {
        return login_error("Sign-in with a provider is not set up here");
    };
    let Some(redirect_uri) = callback_url(&app) else {
        return login_error("This forge does not know its public address yet");
    };
    let stale = || login_error("That sign-in took too long or was already used; start again");
    let (principal, kind, pending) = match app.with_store(|s| s.take_webauthn_state(&state)) {
        Ok(Some(taken)) => taken,
        Ok(None) => return stale(),
        Err(err) => return crate::web::oops(err),
    };
    let Ok(pending) = serde_json::from_str::<Pending>(&pending) else {
        return stale();
    };
    // The code becomes an id token at the provider, over the back channel.
    let answer = {
        let trust = trust.clone();
        let provider = provider.clone();
        let redirect_uri = redirect_uri.clone();
        let verifier = pending.verifier.clone();
        tokio::task::spawn_blocking(move || -> Result<TokenAnswer, String> {
            let endpoint = trust
                .discover(&provider.issuer)?
                .token_endpoint
                .ok_or_else(|| "the provider offers no token endpoint".to_owned())?;
            let form = [
                ("grant_type", "authorization_code"),
                ("code", code.as_str()),
                ("redirect_uri", redirect_uri.as_str()),
                ("client_id", provider.client_id.as_str()),
                ("client_secret", provider.client_secret.as_str()),
                ("code_verifier", verifier.as_str()),
            ];
            trust
                .http
                .post(&endpoint)
                .send_form(form)
                .map_err(|e| format!("could not reach the provider: {e}"))?
                .body_mut()
                .read_json::<TokenAnswer>()
                .map_err(|e| format!("the provider answered something unexpected: {e}"))
        })
        .await
    };
    let answer = match answer {
        Ok(Ok(answer)) => answer,
        Ok(Err(why)) => return login_error(&why),
        Err(_) => return login_error("The sign-in could not be completed"),
    };
    let Some(id_token) = answer.id_token else {
        let why = answer
            .error_description
            .or(answer.error)
            .unwrap_or_else(|| "no id token".into());
        return login_error(&format!("The provider said no: {why}"));
    };
    let claims = {
        let trust = trust.clone();
        let provider = provider.clone();
        let verified = tokio::task::spawn_blocking(move || {
            trust.verify(&provider.issuer, &id_token, &provider.client_id)
        })
        .await;
        match verified {
            Ok(Ok(claims)) => claims,
            Ok(Err(why)) => return login_error(&why),
            Err(_) => return login_error("The sign-in could not be completed"),
        }
    };
    if claims.nonce.as_deref() != Some(pending.nonce.as_str()) {
        return login_error("The provider's answer did not match this sign-in; start again");
    }
    let verified_email = claims
        .email
        .as_deref()
        .filter(|_| claims.email_verified.unwrap_or(false))
        .map(|e| e.trim().to_ascii_lowercase());

    match (kind.as_str(), principal) {
        ("oidc-link", Some(who)) => {
            let linked = app.with_store(|s| {
                s.link_identity(
                    &who,
                    &provider.issuer,
                    &claims.sub,
                    verified_email.as_deref(),
                )
            });
            match linked {
                Ok(env) => {
                    app.publish(&env);
                    Redirect::to("/you/settings?done=1").into_response()
                }
                Err(err) => settings_error(&crate::web::humane(&err)),
            }
        }
        ("oidc-login", _) => {
            let linked = match app.with_store(|s| s.identity_of(&provider.issuer, &claims.sub)) {
                Ok(linked) => linked,
                Err(err) => return crate::web::oops(err),
            };
            let who = match linked {
                Some(who) => who,
                None if provider.link_by_email => {
                    let Some(email) = verified_email.as_deref() else {
                        return not_linked(&provider.label, true);
                    };
                    let by_email = app.with_store(|s| {
                        s.link_identity_by_email(&provider.issuer, &claims.sub, email)
                    });
                    match by_email {
                        Ok(Some((who, env))) => {
                            app.publish(&env);
                            who
                        }
                        Ok(None) => return not_linked(&provider.label, false),
                        Err(err) => return login_error(&crate::web::humane(&err)),
                    }
                }
                None => return not_linked(&provider.label, false),
            };
            match app.start_session(&who, crate::web::user_agent(&headers)) {
                Ok(session) => crate::web::signed_in(&app, crate::web::SESSION_COOKIE, &session),
                Err(err) => login_error(&crate::web::humane(&err)),
            }
        }
        _ => stale(),
    }
}

#[derive(Deserialize)]
pub struct UnlinkForm {
    pub subject: String,
}

/// `POST /you/settings/oidc/unlink`
pub async fn unlink(
    State(app): State<AppState>,
    viewer: crate::web::Viewer,
    axum::Form(form): axum::Form<UnlinkForm>,
) -> Response {
    let Some((_, provider)) = provider_of(&app) else {
        return Redirect::to("/you/settings").into_response();
    };
    match app.with_store(|s| s.unlink_identity(&viewer.0, &provider.issuer, &form.subject)) {
        Ok(env) => {
            app.publish(&env);
            Redirect::to("/you/settings?done=1").into_response()
        }
        Err(err) => settings_error(&crate::web::humane(&err)),
    }
}

#[derive(Deserialize)]
pub struct Exchange {
    /// A token the workload's issuer signed, naming this forge as its
    /// audience.
    pub token: String,
}

fn unauthenticated(message: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::UNAUTHORIZED, "unauthenticated", message)
}

/// `POST /api/identity/exchange`: a workload proves who it is and gets a
/// credential that can claim a task and open a session, nothing more.
pub async fn exchange(
    State(app): State<AppState>,
    Json(body): Json<Exchange>,
) -> ApiResult<Json<Value>> {
    let Some(trust) = app.oidc() else {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "not_found",
            "no workload issuer is trusted here",
        ));
    };
    // The issuer is read before verification, only to know whose keys to
    // check the signature against; nothing else is believed until then.
    let issuer = body
        .token
        .split('.')
        .nth(1)
        .and_then(|part| URL_SAFE_NO_PAD.decode(part).ok())
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .and_then(|claims| claims.get("iss").and_then(Value::as_str).map(str::to_owned))
        .ok_or_else(|| unauthenticated("not a token that names its issuer"))?;
    if !trust
        .workload_issuers
        .iter()
        .any(|t| same_issuer(t, &issuer))
    {
        return Err(unauthenticated(format!(
            "{issuer} is not an issuer this forge trusts for workloads"
        )));
    }
    let audience = trust
        .audience
        .clone()
        .or_else(|| app.public_url().map(str::to_owned))
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "not_found",
                "this forge has no public address to be an audience",
            )
        })?;
    let claims = {
        let trust = trust.clone();
        let token = body.token.clone();
        let issuer = issuer.clone();
        tokio::task::spawn_blocking(move || trust.verify(&issuer, &token, &audience))
            .await
            .map_err(|_| {
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal",
                    "verification did not complete",
                )
            })?
            .map_err(unauthenticated)?
    };
    let (principal, token, secret, until, env) =
        app.with_store(|s| s.mint_workload_credential(&issuer, &claims.sub))?;
    app.publish(&env);
    Ok(Json(json!({
        "principal": principal,
        "id": token.0,
        "token": secret,
        "until": until,
        "scope": { "session": null, "repo": null, "actions": ["task"] },
        "seq": env.seq.0,
    })))
}

/// Routes for the pages side; the API side registers `exchange` itself.
pub fn web_routes() -> axum::Router<AppState> {
    axum::Router::new()
        .route("/login/oidc", axum::routing::get(login_begin))
        .route("/login/oidc/callback", axum::routing::get(callback))
        // A link, not a form: `form-action 'self'` in the CSP also covers
        // the redirect a form's answer makes, and this one leaves for the
        // provider. Nothing changes here until the provider sends them back.
        .route("/you/settings/oidc/link", axum::routing::get(link_begin))
        .route("/you/settings/oidc/unlink", axum::routing::post(unlink))
}
