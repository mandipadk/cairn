//! What every API write passes through before its handler: the
//! caller's allowance, and idempotency keys.
//!
//! Agents retry. A harness times out, a connection drops after the
//! request was received, a process restarts mid-loop, and the write is
//! sent again. Without a key the forge would do it twice: two tasks,
//! two changes, a claim attached twice. With `Idempotency-Key`, the
//! second request is answered from the first's answer and does nothing.
//!
//! The allowance is the other half of the same story. A loop that
//! retries without waiting is told to wait, with `Retry-After` saying
//! how long, instead of being served until something else gives.

use crate::auth::Actor;
use crate::error::ApiError;
use crate::guard::rate_limited;
use crate::state::AppState;
use axum::Json;
use axum::body::{Body, Bytes};
use axum::extract::{FromRequestParts, Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use cairn_core::{PrincipalId, Replay};
use serde_json::json;
use sha2::{Digest, Sha256};

pub const IDEMPOTENCY_KEY: &str = "idempotency-key";
/// Set on an answer that was remembered rather than made.
pub const REPLAYED: &str = "idempotent-replayed";

/// A body past this is not an API write; the JSON extractor refuses it too.
const BODY_LIMIT: usize = 2 * 1024 * 1024;
const KEY_LIMIT: usize = 200;

pub async fn api_writes(State(app): State<AppState>, request: Request, next: Next) -> Response {
    let reads = matches!(
        *request.method(),
        Method::GET | Method::HEAD | Method::OPTIONS
    );
    if reads || !request.uri().path().starts_with("/api/") {
        return next.run(request).await;
    }
    let key = match request.headers().get(IDEMPOTENCY_KEY).map(valid_key) {
        None => None,
        Some(Some(key)) => Some(key),
        Some(None) => return invalid_key(),
    };
    // Who is writing decides whose allowance is spent and whose keys
    // are consulted. A request that cannot say is left to the handler,
    // which refuses it as unauthenticated.
    let (mut parts, body) = request.into_parts();
    let Ok(Actor(principal, _)) = Actor::from_request_parts(&mut parts, &app).await else {
        return next.run(Request::from_parts(parts, body)).await;
    };
    if let Err(wait) = app.write_limiter.check(principal.clone()) {
        return rate_limited(wait);
    }
    let Some(key) = key else {
        return next.run(Request::from_parts(parts, body)).await;
    };
    let Ok(bytes) = axum::body::to_bytes(body, BODY_LIMIT).await else {
        return ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "invalid",
            "the request body is too large",
        )
        .into_response();
    };
    let fingerprint = fingerprint(&parts, &bytes);
    match app.with_store(|s| s.replay_for(&principal, &key)) {
        Ok(Some(replay)) if replay.fingerprint == fingerprint => return replayed(replay),
        Ok(Some(_)) => return mismatch(),
        Ok(None) => {}
        Err(err) => return ApiError::from(err).into_response(),
    }
    if !app.begin_write(&principal, &key) {
        return in_flight();
    }
    let response = next
        .run(Request::from_parts(parts, Body::from(bytes)))
        .await;
    let response = remembered(&app, &principal, &key, fingerprint, response).await;
    app.finish_write(&principal, &key);
    response
}

/// Keep what the handler answered, unless the forge itself failed, in
/// which case the caller is owed another attempt rather than a copy.
async fn remembered(
    app: &AppState,
    principal: &PrincipalId,
    key: &str,
    fingerprint: String,
    response: Response,
) -> Response {
    let (parts, body) = response.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, BODY_LIMIT).await else {
        return ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "the answer could not be read back",
        )
        .into_response();
    };
    if parts.status.is_success() || parts.status.is_client_error() {
        let replay = Replay {
            fingerprint,
            status: parts.status.as_u16(),
            content_type: parts
                .headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned),
            body: String::from_utf8_lossy(&bytes).into_owned(),
        };
        if let Err(err) = app.with_store(|s| s.remember_replay(principal, key, &replay)) {
            tracing::error!(error = %err, "could not remember a write's answer");
        }
    }
    Response::from_parts(parts, Body::from(bytes))
}

fn replayed(replay: Replay) -> Response {
    let mut response = Response::new(Body::from(replay.body));
    *response.status_mut() =
        StatusCode::from_u16(replay.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let content_type = replay
        .content_type
        .as_deref()
        .and_then(|v| HeaderValue::from_str(v).ok())
        .unwrap_or_else(|| HeaderValue::from_static("application/json"));
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, content_type);
    response
        .headers_mut()
        .insert(REPLAYED, HeaderValue::from_static("true"));
    response
}

/// The request, reduced to what makes it the same request: method,
/// path and query, body. Headers are left out on purpose - a retry
/// carries a new date, a new trace id, and is still the same write.
fn fingerprint(parts: &axum::http::request::Parts, body: &Bytes) -> String {
    let mut hasher = Sha256::new();
    hasher.update(parts.method.as_str().as_bytes());
    hasher.update(b"\n");
    hasher.update(
        parts
            .uri
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or_default()
            .as_bytes(),
    );
    hasher.update(b"\n");
    hasher.update(body);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// A key is the caller's to choose, within reason: printable, and not
/// long enough to be a message in itself.
fn valid_key(value: &HeaderValue) -> Option<String> {
    let key = value.to_str().ok()?.trim();
    let printable = key.chars().all(|c| c.is_ascii_graphic() || c == ' ');
    ((1..=KEY_LIMIT).contains(&key.len()) && printable).then(|| key.to_owned())
}

fn invalid_key() -> Response {
    ApiError::new(
        StatusCode::BAD_REQUEST,
        "invalid",
        format!("Idempotency-Key must be 1 to {KEY_LIMIT} printable characters"),
    )
    .into_response()
}

/// The same key, a different request. Answering from the remembered
/// one would hand back an answer to a question that was not asked.
fn mismatch() -> Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({
            "kind": "idempotency_mismatch",
            "error": "this Idempotency-Key was already used for a different request; choose a new key",
        })),
    )
        .into_response()
}

/// The first request under this key has not answered yet. Waiting for
/// it here would hold two requests on one write; saying so lets the
/// caller wait and ask again.
fn in_flight() -> Response {
    (
        StatusCode::CONFLICT,
        [(header::RETRY_AFTER, "1")],
        Json(json!({
            "kind": "idempotency_in_flight",
            "error": "a request with this Idempotency-Key is still being answered; retry shortly",
        })),
    )
        .into_response()
}
