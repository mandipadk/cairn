//! Dev-mode identity: the caller asserts a principal via header.
//!
//! This module is the seam where real authentication lands (capability
//! grants, credential verification). Handlers only ever see [`Actor`],
//! so replacing assertion with proof is a change confined to this file.

use crate::error::ApiError;
use crate::state::AppState;
use axum::extract::FromRequestParts;
use axum::http::StatusCode;
use axum::http::request::Parts;
use cairn_core::PrincipalId;

pub const PRINCIPAL_HEADER: &str = "x-cairn-principal";

/// The authenticated principal performing the request.
pub struct Actor(pub PrincipalId);

impl FromRequestParts<AppState> for Actor {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let value = parts
            .headers
            .get(PRINCIPAL_HEADER)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                ApiError::new(
                    StatusCode::UNAUTHORIZED,
                    "unauthenticated",
                    format!("missing {PRINCIPAL_HEADER} header"),
                )
            })?;
        let principal = PrincipalId::new(value).ok_or_else(|| {
            ApiError::new(
                StatusCode::UNAUTHORIZED,
                "unauthenticated",
                format!("{value:?} is not a valid principal id"),
            )
        })?;
        Ok(Actor(principal))
    }
}
