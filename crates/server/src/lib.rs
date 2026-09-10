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

mod api_guard;
mod auth;
mod debt;
mod error;
mod git_http;
mod guard;
pub mod mail;
pub mod oidc;
pub mod passkeys;
mod queue;
pub mod receipts;
pub mod repo_path;
mod routes;
mod sse;
mod state;
mod web;

pub use mail::Mailer;
pub use queue::{reconcile_branches, spawn_queue_processor};
pub use state::{
    AppState, DEFAULT_ANONYMOUS_READS_PER_MINUTE, DEFAULT_READS_PER_MINUTE,
    DEFAULT_WRITES_PER_MINUTE,
};

use axum::Router;
use axum::routing::{get, post};

/// A size a person reads at a glance: three significant figures and a
/// binary unit, since that is what disk is sold and measured in.
pub fn in_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut size = bytes as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit + 1 < UNITS.len() {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else if size < 10.0 {
        format!("{size:.1} {}", UNITS[unit])
    } else {
        format!("{size:.0} {}", UNITS[unit])
    }
}

/// Pack payloads dwarf JSON bodies; axum's 2 MB default would reject
/// any real push.
const GIT_BODY_LIMIT: usize = 256 * 1024 * 1024;

/// Today's date in UTC, the unit the attention budget is spent in.
pub fn today() -> String {
    jiff::Timestamp::now().strftime("%Y-%m-%d").to_string()
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/principals", post(routes::register_principal))
        .route("/api/principals/{id}", get(routes::get_principal))
        .route("/api/principals/{id}/record", get(routes::principal_record))
        .route(
            "/api/principals/{id}/quota",
            get(routes::get_quota)
                .post(routes::set_quota)
                .delete(routes::unset_quota),
        )
        .route("/api/principals/{id}/password", post(routes::set_password))
        .route(
            "/api/principals/{id}/state",
            post(routes::set_principal_state),
        )
        .route(
            "/api/principals/{id}/workload",
            post(routes::bind_workload).get(routes::list_workload),
        )
        .route("/api/identity/exchange", post(oidc::exchange))
        .route("/api/repos", post(routes::create_repo))
        .route("/api/repos/{owner}/{name}", get(routes::get_repo))
        .route(
            "/api/repos/{owner}/{name}/import",
            post(routes::import_history),
        )
        .route(
            "/api/repos/{owner}/{name}/visibility",
            post(routes::set_visibility),
        )
        .route(
            "/api/repos/{owner}/{name}/rename",
            post(routes::rename_repo),
        )
        .route(
            "/api/repos/{owner}/{name}/description",
            post(routes::describe_repo),
        )
        .route(
            "/api/repos/{owner}/{name}/archive",
            post(routes::archive_repo),
        )
        .route(
            "/api/repos/{owner}/{name}/unarchive",
            post(routes::unarchive_repo),
        )
        .route(
            "/api/repos/{owner}/{name}/delete",
            post(routes::delete_repo),
        )
        .route(
            "/api/repos/{owner}/{name}/transfer",
            post(routes::offer_transfer),
        )
        .route(
            "/api/repos/{owner}/{name}/transfer/accept",
            post(routes::accept_transfer),
        )
        .route(
            "/api/repos/{owner}/{name}/transfer/decline",
            post(routes::decline_transfer),
        )
        .route(
            "/api/repos/{owner}/{name}/changes",
            get(routes::list_changes),
        )
        .route(
            "/api/repos/{owner}/{name}/changes/{number}",
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
        .route(
            "/api/sessions/{id}/credential",
            post(routes::mint_session_credential),
        )
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
        .route("/api/changes/{id}/prefer", post(routes::prefer_revision))
        .route("/api/changes/{id}/receipt", get(receipts::change_receipt))
        .route(
            "/api/repos/{owner}/{name}/receipts",
            get(receipts::repo_receipts),
        )
        .route("/api/forge/key", get(receipts::forge_key))
        .route("/api/changes/{id}/merge", post(routes::merge_change))
        .route("/api/changes/{id}/enqueue", post(routes::enqueue_change))
        .route("/api/changes/{id}/dequeue", post(routes::dequeue_change))
        .route("/api/repos/{owner}/{name}/queue", get(routes::list_queue))
        .route(
            "/api/repos/{owner}/{name}/attention",
            get(routes::attention),
        )
        .route(
            "/api/repos/{owner}/{name}/attention/draw",
            post(routes::draw_attention),
        )
        .route(
            "/api/repos/{owner}/{name}/awaiting-verification",
            get(routes::awaiting_verification),
        )
        .route(
            "/api/repos/{owner}/{name}/policy",
            get(routes::get_policy).post(routes::set_policy),
        )
        .route(
            "/api/repos/{owner}/{name}/policy/simulate",
            post(routes::simulate_policy),
        )
        .route(
            "/api/repos/{owner}/{name}/policy/pack",
            get(routes::policy_pack),
        )
        .route("/api/policy/packs", get(routes::policy_packs))
        .route(
            "/api/repos/{owner}/{name}/mirror",
            get(routes::get_mirror).post(routes::set_mirror),
        )
        .route("/api/repos/{owner}/{name}/leases", get(routes::list_leases))
        .route(
            "/api/repos/{owner}/{name}/conflicts",
            get(routes::path_conflicts),
        )
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
        .route("/api/git/room", post(git_http::room))
        .route("/api/git/pushes", post(git_http::record_push))
        .route("/api/git/tags", post(git_http::record_tag))
        .route("/api/repos/{owner}/{name}/tags", get(routes::tags))
        .route("/api/repos/{owner}/{name}/blame", get(git_http::blame))
        .route("/api/repos/{owner}/{name}/debt", get(debt::debt))
        .route("/api/repos/{owner}/{name}/debt/history", get(debt::history))
        .route("/api/repos/{owner}/{name}/debt/tasks", post(debt::pay_down))
        .route("/git/{owner}/{repo}/info/refs", get(git_http::info_refs))
        .route(
            "/git/{owner}/{repo}/git-upload-pack",
            post(git_http::upload_pack).layer(axum::extract::DefaultBodyLimit::max(GIT_BODY_LIMIT)),
        )
        .route(
            "/git/{owner}/{repo}/git-receive-pack",
            post(git_http::receive_pack)
                .layer(axum::extract::DefaultBodyLimit::max(GIT_BODY_LIMIT)),
        )
        // Under /api and /git, an address nothing answers to is the
        // API's to refuse: without these the page routes' `/{owner}`
        // and `/{owner}/{repo}` would take `/api/nope` as a repository
        // named nope and send the caller to sign in.
        .route("/api/{*rest}", axum::routing::any(unmatched))
        .route("/git/{owner}", axum::routing::any(unmatched))
        .route("/git/{owner}/{repo}", axum::routing::any(unmatched))
        .route("/git/{owner}/{repo}/{*rest}", axum::routing::any(unmatched))
        .merge(web::routes())
        // An address nothing answers to, or a method nothing answers
        // with, is answered in the shape the caller reads: the API's
        // refusal on the API, a page everywhere else. Left to itself
        // the router says nothing, and a client reading JSON chokes on
        // nothing.
        .fallback(unmatched)
        .method_not_allowed_fallback(wrong_method)
        // Innermost, so every API write passes it after the origin
        // check and every answer it gives still gets the headers.
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            api_guard::api_writes,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            guard::read_allowance,
        ))
        .layer(axum::middleware::from_fn(guard::security_headers))
        .layer(axum::middleware::from_fn(guard::same_origin_writes))
        .layer(axum::middleware::from_fn(web::themed_fallbacks))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            web::old_names,
        ))
        .with_state(state)
}

/// Whether a path is read by a program rather than a person.
fn machine_read(path: &str) -> bool {
    path.starts_with("/api/") || path.starts_with("/git/")
}

async fn unmatched(request: axum::extract::Request) -> axum::response::Response {
    use axum::response::IntoResponse;
    if machine_read(request.uri().path()) {
        return error::ApiError::new(
            axum::http::StatusCode::NOT_FOUND,
            "not_found",
            "no such route; the routes are listed in docs/api.md",
        )
        .into_response();
    }
    web::not_found()
}

async fn wrong_method(request: axum::extract::Request) -> axum::response::Response {
    use axum::response::IntoResponse;
    if machine_read(request.uri().path()) {
        return error::ApiError::new(
            axum::http::StatusCode::METHOD_NOT_ALLOWED,
            "method_not_allowed",
            format!("{} is not how this route is called", request.method()),
        )
        .into_response();
    }
    (
        axum::http::StatusCode::METHOD_NOT_ALLOWED,
        [(
            axum::http::HeaderName::from_static(web::FALLBACK),
            "not-found",
        )],
        "",
    )
        .into_response()
}
