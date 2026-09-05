use axum::Json;
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
        (self.status, Json(body)).into_response()
    }
}
