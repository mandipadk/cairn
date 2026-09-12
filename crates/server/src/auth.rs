//! Request identity: who is acting.
//!
//! Two ways in for ordinary requests, tried in order:
//!
//! 1. `Authorization: Bearer ambolt_…` — a minted API token, resolved
//!    through its stored hash. The normal path.
//! 2. The `x-ambolt-principal` dev header — an asserted identity,
//!    honored only when the server explicitly opted in (`--dev`).
//!
//! There is a third credential, deliberately kept out of that list: the
//! ephemeral secret this server hands its own proc-receive hook for the
//! length of one receive-pack. It is accepted by [`Pusher`] alone, on
//! the single endpoint the hook calls. Honouring it everywhere would
//! make a secret that exists to say "this one push is authenticated"
//! into a full-privilege credential for the whole API and the web UI
//! until it expired.
//!
//! Authentication answers "who"; the capability law in the core
//! answers "may they" — this module never authorizes anything.

use crate::error::ApiError;
use crate::state::AppState;
use ambolt_core::PrincipalId;
use axum::extract::FromRequestParts;
use axum::http::StatusCode;
use axum::http::request::Parts;

pub const PRINCIPAL_HEADER: &str = "x-ambolt-principal";

/// The authenticated principal performing the request.
pub struct Actor(pub PrincipalId, pub Option<ambolt_core::Scope>);

fn unauthenticated(message: &str) -> ApiError {
    ApiError::new(StatusCode::UNAUTHORIZED, "unauthenticated", message)
}

pub(crate) fn resolve_bearer(
    app: &AppState,
    token: &str,
) -> Result<(PrincipalId, Option<ambolt_core::Scope>), ApiError> {
    app.with_store(|s| s.identity_for_token(token))?
        .ok_or_else(|| unauthenticated("unknown or revoked token"))
}

fn bearer(parts: &Parts) -> Option<&str> {
    parts
        .headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
}

/// Whoever is calling, if anyone: a bad credential is still refused, but
/// no credential at all is a stranger, who may read what is public.
pub struct MaybeActor(pub Option<Actor>);

impl MaybeActor {
    pub fn scope(&self) -> Option<&ambolt_core::Scope> {
        self.0.as_ref().and_then(|actor| actor.1.as_ref())
    }
}

impl FromRequestParts<AppState> for MaybeActor {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let has_identity = bearer(parts).is_some()
            || (state.dev_identity() && parts.headers.contains_key(PRINCIPAL_HEADER));
        if !has_identity {
            return Ok(MaybeActor(None));
        }
        Actor::from_request_parts(parts, state)
            .await
            .map(|actor| MaybeActor(Some(actor)))
    }
}

/// Identity for the endpoints the receive-pack hooks call.
///
/// Only the ephemeral push secret is accepted, and only while its
/// receive-pack runs: the token names the repository the push is
/// into, so a leaked hook credential buys nothing outside the one
/// push it was issued for, and nothing after it. A standing token is
/// refused here; what these endpoints do is done through the API
/// proper, where the checks that live in the hooks are asked again.
pub struct Pusher {
    pub principal: PrincipalId,
    pub scope: Option<ambolt_core::Scope>,
    /// The repository the push is into.
    pub repo: String,
    /// The secret itself, which is what the push is known by.
    pub secret: String,
}

impl FromRequestParts<AppState> for Pusher {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let Some(token) = bearer(parts) else {
            return Err(unauthenticated("the push hook must present its token"));
        };
        match state.resolve_push_token(token) {
            Some(identity) => Ok(Pusher {
                principal: identity.principal,
                scope: identity.scope,
                repo: identity.repo,
                secret: token.to_owned(),
            }),
            None => Err(unauthenticated(
                "this is the push hook's door, and the push it was given a token for has ended",
            )),
        }
    }
}

impl FromRequestParts<AppState> for Actor {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        if let Some(token) = bearer(parts) {
            return resolve_bearer(state, token).map(|(principal, scope)| Actor(principal, scope));
        }

        if state.dev_identity()
            && let Some(value) = parts
                .headers
                .get(PRINCIPAL_HEADER)
                .and_then(|v| v.to_str().ok())
        {
            let principal = PrincipalId::new(value).ok_or_else(|| {
                unauthenticated(&format!("{value:?} is not a valid principal id"))
            })?;
            return Ok(Actor(principal, None));
        }

        Err(unauthenticated(
            "authenticate with 'Authorization: Bearer <token>' (mint one via ambolt admin or /api/principals/{id}/tokens)",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::router;
    use ambolt_core::{PrincipalKind, Store};
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn forge() -> (AppState, String) {
        let mut store = Store::open_in_memory().unwrap();
        let ada = PrincipalId::new("ada").unwrap();
        store
            .register_principal(&ada, &ada, PrincipalKind::Human, "Ada", None, None)
            .unwrap();
        let (_, secret, _) = store.mint_token(&ada, &ada, Some("test"), None).unwrap();
        (AppState::new(store), secret)
    }

    async fn status_with_bearer(state: &AppState, path: &str, token: &str) -> StatusCode {
        let request = Request::builder()
            .uri(path)
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        router(state.clone())
            .oneshot(request)
            .await
            .unwrap()
            .status()
    }

    /// The hook's door takes the push token and nothing else: a standing
    /// token is not a push, and a push token speaks only of the
    /// repository its push is into.
    #[tokio::test]
    async fn the_hook_door_takes_only_the_push_it_was_issued_for() {
        let (state, real) = forge();
        let ada = PrincipalId::new("ada").unwrap();
        let push_token = state.issue_push_token(&ada, None, "ada/demo", &ada);
        for (token, repo, expected) in [
            (real.as_str(), "ada/demo", StatusCode::UNAUTHORIZED),
            (push_token.as_str(), "ada/other", StatusCode::FORBIDDEN),
        ] {
            let request = Request::builder()
                .method("POST")
                .uri("/api/git/room")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(format!(r#"{{"repo":"{repo}"}}"#)))
                .unwrap();
            let response = router(state.clone()).oneshot(request).await.unwrap();
            assert_eq!(response.status(), expected, "{repo} with {token}");
        }
        state.end_push(&push_token);
        let request = Request::builder()
            .method("POST")
            .uri("/api/git/room")
            .header("authorization", format!("Bearer {push_token}"))
            .header("content-type", "application/json")
            .body(Body::from(r#"{"repo":"ada/demo"}"#))
            .unwrap();
        let response = router(state.clone()).oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "a push that ended took its token with it"
        );
    }

    /// The hook credential exists to authenticate one receive-pack. It
    /// must not open the rest of the API, or the web UI, for the ten
    /// minutes it stays alive.
    #[tokio::test]
    async fn a_push_token_is_not_a_general_credential() {
        let (state, real) = forge();
        let ada = PrincipalId::new("ada").unwrap();
        let push_token = state.issue_push_token(&ada, None, "demo", &ada);

        assert_eq!(
            status_with_bearer(&state, "/api/principals/ada", &real).await,
            StatusCode::OK,
            "a real token still works"
        );
        assert_eq!(
            status_with_bearer(&state, "/api/principals/ada", &push_token).await,
            StatusCode::UNAUTHORIZED,
            "a push token must not authenticate ordinary API requests"
        );

        // The browser half reads the same credential out of a cookie.
        // `/` is public now, so this asks a page that still requires
        // somebody to be signed in.
        let request = Request::builder()
            .uri("/you")
            .header("cookie", format!("ambolt_token={push_token}"))
            .body(Body::empty())
            .unwrap();
        let response = router(state.clone()).oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::SEE_OTHER,
            "a push token in a session cookie must not sign anyone in"
        );

        // But it is still accepted where the hook actually needs it.
        let request = Request::builder()
            .method("POST")
            .uri("/api/git/pushes")
            .header("authorization", format!("Bearer {push_token}"))
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"repo":"demo","target":"main","commits":[]}"#,
            ))
            .unwrap();
        let response = router(state.clone()).oneshot(request).await.unwrap();
        assert_ne!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "the hook endpoint must still accept the credential it is given: {}",
            String::from_utf8_lossy(&response.into_body().collect().await.unwrap().to_bytes())
        );
    }
}
