//! The two path segments that name a repository, joined back into the one
//! name the graph uses. A repository lives at `/{owner}/{repo}` on the
//! pages, under `/api/repos/{owner}/{name}` on the API and under
//! `/git/{owner}/{repo}` for git; a pair that is not two slugs is not a
//! repository and answers not found before any handler runs.

use axum::extract::{FromRequestParts, Path};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};

pub struct RepoName(pub String);

impl<S: Send + Sync> FromRequestParts<S> for RepoName {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let machine =
            parts.uri.path().starts_with("/api/") || parts.uri.path().starts_with("/git/");
        let refuse = || {
            if machine {
                crate::error::ApiError::new(StatusCode::NOT_FOUND, "not_found", "repo not found")
                    .into_response()
            } else {
                crate::web::not_found()
            }
        };
        let Path(params): Path<Vec<(String, String)>> = Path::from_request_parts(parts, state)
            .await
            .map_err(|_| refuse())?;
        let get = |key: &str| {
            params
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value.as_str())
        };
        let (Some(owner), Some(repo)) = (get("owner"), get("repo").or_else(|| get("name"))) else {
            return Err(refuse());
        };
        // Clone URLs may spell the repository with a `.git` suffix.
        let repo = repo.strip_suffix(".git").unwrap_or(repo);
        let full = format!("{owner}/{repo}");
        if !ambolt_core::validate_repo_name(&full) {
            return Err(refuse());
        }
        Ok(RepoName(full))
    }
}
