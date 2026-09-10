use axum::Json as AxumJson;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use cairn_core::CoreError;
use serde_json::json;

pub type ApiResult<T> = Result<T, ApiError>;

/// A typed API failure. The `kind` field is stable vocabulary for
/// machine callers; the message is for the human reading the log.
pub struct ApiError {
    pub status: StatusCode,
    pub kind: &'static str,
    pub message: String,
    /// Extra structured context, e.g. the policy trace on a refused merge.
    pub detail: Option<serde_json::Value>,
}

impl ApiError {
    pub fn new(status: StatusCode, kind: &'static str, message: impl Into<String>) -> Self {
        ApiError {
            status,
            kind,
            message: message.into(),
            detail: None,
        }
    }
}

impl From<CoreError> for ApiError {
    fn from(err: CoreError) -> Self {
        let (status, kind) = match &err {
            CoreError::NotFound(_) => (StatusCode::NOT_FOUND, "not_found"),
            CoreError::Conflict(_) => (StatusCode::CONFLICT, "conflict"),
            CoreError::Invalid(_) => (StatusCode::BAD_REQUEST, "invalid"),
            CoreError::PolicyUnsatisfied(_) => (StatusCode::CONFLICT, "policy_unsatisfied"),
            CoreError::Forbidden(_) => (StatusCode::FORBIDDEN, "forbidden"),
            // Not 403: nothing about authority would change the answer,
            // and a caller that reads this as "sign in differently"
            // would retry forever.
            CoreError::OverQuota(_) => (StatusCode::CONFLICT, "over_quota"),
            CoreError::Db(_) | CoreError::Corrupt { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal")
            }
        };
        if status == StatusCode::INTERNAL_SERVER_ERROR {
            tracing::error!(error = %err, "internal store failure");
        }
        ApiError::new(status, kind, err.to_string())
    }
}

impl From<cairn_git::GitError> for ApiError {
    fn from(err: cairn_git::GitError) -> Self {
        use cairn_git::GitError as G;
        let (status, kind) = match &err {
            G::InvalidRepoName(_) => (StatusCode::BAD_REQUEST, "invalid"),
            G::RepoMissing(_) => (StatusCode::NOT_FOUND, "not_found"),
            G::CommandFailed { .. } | G::Io(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
            // A hung git process is the server's problem, but the
            // caller is owed a status they can retry on.
            G::TimedOut { .. } => (StatusCode::GATEWAY_TIMEOUT, "timeout"),
        };
        if status == StatusCode::INTERNAL_SERVER_ERROR {
            // The detail names paths and quotes git's stderr; that is for
            // the operator's log, not for whoever made the request.
            tracing::error!(error = %err, "git operation failed");
            return ApiError::new(
                status,
                kind,
                "git operation failed; the log has the details",
            );
        }
        ApiError::new(status, kind, err.to_string())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut body = json!({ "kind": self.kind, "error": self.message });
        if let Some(detail) = self.detail {
            body["detail"] = detail;
        }
        (self.status, AxumJson(body)).into_response()
    }
}

/// JSON in and out, with a refusal that looks like every other refusal.
///
/// axum's own extractor answers a malformed or mistyped body with a
/// line of plain text, which is the one place the API's promise of
/// `{"kind": ..., "error": ...}` was not kept — and it is the place a
/// caller who typed a limit wrong meets first.
pub struct Json<T>(pub T);

impl<S, T> axum::extract::FromRequest<S> for Json<T>
where
    axum::Json<T>:
        axum::extract::FromRequest<S, Rejection = axum::extract::rejection::JsonRejection>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(
        request: axum::extract::Request,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        match axum::Json::<T>::from_request(request, state).await {
            Ok(axum::Json(value)) => Ok(Json(value)),
            Err(rejection) => Err(refused_body(&rejection)),
        }
    }
}

/// A body that could not be taken, refused in the API's own words. A
/// body that does not fit is invalid the way a value out of range is
/// invalid, and answers 400 with it; too large, or not JSON at all,
/// keep the statuses that say exactly that.
fn refused_body(rejection: &axum::extract::rejection::JsonRejection) -> ApiError {
    let status = match rejection.status() {
        StatusCode::PAYLOAD_TOO_LARGE | StatusCode::UNSUPPORTED_MEDIA_TYPE => rejection.status(),
        _ => StatusCode::BAD_REQUEST,
    };
    ApiError::new(status, "invalid", rejection.body_text())
}

/// Query strings, refused the same way when they do not fit.
pub struct Query<T>(pub T);

impl<S, T> axum::extract::FromRequestParts<S> for Query<T>
where
    T: serde::de::DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        match <axum::extract::Query<T> as axum::extract::FromRequestParts<S>>::from_request_parts(
            parts, state,
        )
        .await
        {
            Ok(axum::extract::Query(value)) => Ok(Query(value)),
            Err(rejection) => Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "invalid",
                rejection.body_text(),
            )),
        }
    }
}

/// Path segments, likewise.
pub struct Path<T>(pub T);

impl<S, T> axum::extract::FromRequestParts<S> for Path<T>
where
    T: serde::de::DeserializeOwned + Send,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        match <axum::extract::Path<T> as axum::extract::FromRequestParts<S>>::from_request_parts(
            parts, state,
        )
        .await
        {
            Ok(axum::extract::Path(value)) => Ok(Path(value)),
            Err(rejection) => Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "invalid",
                rejection.body_text(),
            )),
        }
    }
}

/// The same, for a handler that takes a body or none: absent stays
/// absent, and a body that is there but wrong is refused the same way.
impl<S, T> axum::extract::OptionalFromRequest<S> for Json<T>
where
    axum::Json<T>:
        axum::extract::OptionalFromRequest<S, Rejection = axum::extract::rejection::JsonRejection>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(
        request: axum::extract::Request,
        state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        match <axum::Json<T> as axum::extract::OptionalFromRequest<S>>::from_request(request, state)
            .await
        {
            Ok(Some(axum::Json(value))) => Ok(Some(Json(value))),
            Ok(None) => Ok(None),
            Err(rejection) => Err(refused_body(&rejection)),
        }
    }
}

impl<T: serde::Serialize> IntoResponse for Json<T> {
    fn into_response(self) -> Response {
        axum::Json(self.0).into_response()
    }
}
