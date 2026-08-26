//! Request identity: who is acting.
//!
//! Two ways in for ordinary requests, tried in order:
//!
//! 1. `Authorization: Bearer cairn_…` — a minted API token, resolved
//!    through its stored hash. The normal path.
//! 2. The `x-cairn-principal` dev header — an asserted identity,
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
use axum::extract::FromRequestParts;
use axum::http::StatusCode;
use axum::http::request::Parts;
use cairn_core::PrincipalId;

pub const PRINCIPAL_HEADER: &str = "x-cairn-principal";

/// The authenticated principal performing the request.
pub struct Actor(pub PrincipalId);

fn unauthenticated(message: &str) -> ApiError {
    ApiError::new(StatusCode::UNAUTHORIZED, "unauthenticated", message)
}

pub(crate) fn resolve_bearer(app: &AppState, token: &str) -> Result<PrincipalId, ApiError> {
    app.with_store(|s| s.principal_for_token(token))?
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

/// Identity for the one endpoint a proc-receive hook calls.
///
/// Accepts the ephemeral push secret as well as a real token, and is
/// used nowhere else — so a leaked hook credential buys a push it was
/// already authorised to make, and nothing further.
pub struct Pusher(pub PrincipalId);

impl FromRequestParts<AppState> for Pusher {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let Some(token) = bearer(parts) else {
            return Err(unauthenticated("the push hook must present its token"));
        };
        if let Some(principal) = state.resolve_push_token(token) {
            return Ok(Pusher(principal));
        }
        resolve_bearer(state, token).map(Pusher)
    }
}

impl FromRequestParts<AppState> for Actor {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        if let Some(token) = bearer(parts) {
            return resolve_bearer(state, token).map(Actor);
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
            return Ok(Actor(principal));
        }

        Err(unauthenticated(
            "authenticate with 'Authorization: Bearer <token>' (mint one via cairn admin or /api/principals/{id}/tokens)",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::router;
    use axum::body::Body;
    use axum::http::Request;
    use cairn_core::{PrincipalKind, Store};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn forge() -> (AppState, String) {
        let mut store = Store::open_in_memory().unwrap();
        let ada = PrincipalId::new("ada").unwrap();
        store
            .register_principal(&ada, &ada, PrincipalKind::Human, "Ada", None, None)
            .unwrap();
        let (_, secret, _) = store.mint_token(&ada, &ada, Some("test")).unwrap();
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

    /// The hook credential exists to authenticate one receive-pack. It
    /// must not open the rest of the API, or the web UI, for the ten
    /// minutes it stays alive.
    #[tokio::test]
    async fn a_push_token_is_not_a_general_credential() {
        let (state, real) = forge();
        let ada = PrincipalId::new("ada").unwrap();
        let push_token = state.issue_push_token(&ada);

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
        let request = Request::builder()
            .uri("/")
            .header("cookie", format!("cairn_token={push_token}"))
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
