//! HTTP surface for the cairn graph.
//!
//! One API for every consumer: agents, the CLI, the web UI, and the MCP
//! adapter all speak exactly these routes — no privileged surface. The
//! shape mirrors the core protocol verbs one-to-one, and every mutation
//! response carries the event envelope it produced, so a caller always
//! leaves with the cursor it needs to resume the world.
//!
//! Identity is currently dev-mode (see [`auth`]): a principal header,
//! asserted rather than proven. Capability grants and real credentials
//! are the trust layer scheduled to replace it; nothing else in the API
//! will change shape when they do.

mod auth;
mod error;
mod git_http;
mod guard;
pub mod mail;
pub mod passkeys;
mod queue;
mod routes;
mod sse;
mod state;
mod web;

pub use mail::Mailer;
pub use queue::{reconcile_branches, spawn_queue_processor};
pub use state::AppState;

use axum::Router;
use axum::routing::{get, post};

/// Pack payloads dwarf JSON bodies; axum's 2 MB default would reject
/// any real push.
const GIT_BODY_LIMIT: usize = 256 * 1024 * 1024;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/principals", post(routes::register_principal))
        .route("/api/principals/{id}", get(routes::get_principal))
        .route("/api/principals/{id}/password", post(routes::set_password))
        .route("/api/repos", post(routes::create_repo))
        .route("/api/repos/{name}", get(routes::get_repo))
        .route("/api/repos/{name}/import", post(routes::import_history))
        .route("/api/repos/{name}/visibility", post(routes::set_visibility))
        .route("/api/repos/{name}/transfer", post(routes::offer_transfer))
        .route(
            "/api/repos/{name}/transfer/accept",
            post(routes::accept_transfer),
        )
        .route(
            "/api/repos/{name}/transfer/decline",
            post(routes::decline_transfer),
        )
        .route("/api/repos/{name}/changes", get(routes::list_changes))
        .route(
            "/api/repos/{name}/changes/{number}",
            get(routes::get_change_by_number),
        )
        .route(
            "/api/tasks",
            post(routes::create_task).get(routes::list_tasks),
        )
        .route("/api/tasks/{id}", get(routes::get_task))
        .route("/api/tasks/{id}/claim", post(routes::claim_task))
        .route("/api/tasks/{id}/state", post(routes::set_task_state))
        .route("/api/tasks/{id}/sessions", post(routes::open_session))
        .route("/api/sessions/{id}", get(routes::get_session))
        .route("/api/sessions/{id}/end", post(routes::end_session))
        .route("/api/changes", post(routes::open_change))
        .route("/api/changes/{id}", get(routes::get_change))
        .route(
            "/api/changes/{id}/revisions",
            post(routes::push_revision).get(routes::list_revisions),
        )
        .route(
            "/api/changes/{id}/claims",
            post(routes::attach_claim).get(routes::list_claims),
        )
        .route(
            "/api/changes/{id}/verdicts",
            post(routes::give_verdict).get(routes::list_verdicts),
        )
        .route(
            "/api/changes/{id}/threads",
            post(routes::open_thread).get(routes::list_threads),
        )
        .route("/api/threads/{id}", get(routes::get_thread))
        .route("/api/threads/{id}/reply", post(routes::reply_thread))
        .route("/api/threads/{id}/resolve", post(routes::resolve_thread))
        .route("/api/claims/{id}/verify", post(routes::verify_claim))
        .route(
            "/api/changes/{id}/verifications",
            get(routes::list_verifications),
        )
        .route("/api/changes/{id}/readiness", get(routes::merge_readiness))
        .route("/api/changes/{id}/merge", post(routes::merge_change))
        .route("/api/changes/{id}/enqueue", post(routes::enqueue_change))
        .route("/api/changes/{id}/dequeue", post(routes::dequeue_change))
        .route("/api/repos/{name}/queue", get(routes::list_queue))
        .route("/api/repos/{name}/attention", get(routes::attention))
        .route(
            "/api/repos/{name}/awaiting-verification",
            get(routes::awaiting_verification),
        )
        .route(
            "/api/repos/{name}/policy",
            get(routes::get_policy).post(routes::set_policy),
        )
        .route(
            "/api/repos/{name}/mirror",
            get(routes::get_mirror).post(routes::set_mirror),
        )
        .route("/api/repos/{name}/leases", get(routes::list_leases))
        .route("/api/repos/{name}/conflicts", get(routes::path_conflicts))
        .route("/api/sessions/{id}/paths", post(routes::declare_paths))
        .route("/api/changes/{id}/abandon", post(routes::abandon_change))
        .route(
            "/api/principals/{id}/tokens",
            post(routes::mint_token).get(routes::list_tokens),
        )
        .route("/api/tokens/{id}/revoke", post(routes::revoke_token))
        .route(
            "/api/grants",
            post(routes::issue_grant).get(routes::list_grants),
        )
        .route("/api/grants/{id}/revoke", post(routes::revoke_grant))
        .route("/api/lessons", get(routes::lessons))
        .route("/healthz", get(routes::health))
        .route("/api/events", get(routes::list_events))
        .route("/api/search", get(routes::search))
        .route(
            "/api/teams/{id}/members",
            get(routes::list_members).post(routes::add_member),
        )
        .route(
            "/api/teams/{id}/members/remove",
            post(routes::remove_member),
        )
        .route("/api/inbox", get(routes::inbox))
        .route("/api/inbox/read", post(routes::mark_read))
        .route("/api/events/stream", get(sse::stream))
        .route("/api/git/pushes", post(git_http::record_push))
        .route("/api/repos/{name}/blame", get(git_http::blame))
        .route("/git/{repo}/info/refs", get(git_http::info_refs))
        .route(
            "/git/{repo}/git-upload-pack",
            post(git_http::upload_pack).layer(axum::extract::DefaultBodyLimit::max(GIT_BODY_LIMIT)),
        )
        .route(
            "/git/{repo}/git-receive-pack",
            post(git_http::receive_pack)
                .layer(axum::extract::DefaultBodyLimit::max(GIT_BODY_LIMIT)),
        )
        .merge(web::routes())
        .layer(axum::middleware::from_fn(guard::security_headers))
        .layer(axum::middleware::from_fn(guard::same_origin_writes))
        .layer(axum::middleware::from_fn(web::themed_fallbacks))
        .with_state(state)
}
