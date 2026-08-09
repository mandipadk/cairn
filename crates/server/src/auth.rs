//! Request identity: who is acting.
//!
//! Three ways in, tried in order:
//!
//! 1. `Authorization: Bearer cairn_…` — a minted API token, resolved
//!    through its stored hash. The normal path.
//! 2. `Authorization: Bearer` with an ephemeral push token — issued by
//!    this server to its own proc-receive hook for the duration of one
//!    receive-pack, never stored.
//! 3. The `x-cairn-principal` dev header — an asserted identity,
//!    honored only when the server explicitly opted in (`--dev`).
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
    if let Some(principal) = app.resolve_push_token(token) {
        return Ok(principal);
    }
    app.with_store(|s| s.principal_for_token(token))?
        .ok_or_else(|| unauthenticated("unknown or revoked token"))
}

impl FromRequestParts<AppState> for Actor {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let bearer = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        if let Some(token) = bearer {
            return resolve_bearer(state, token.trim()).map(Actor);
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
