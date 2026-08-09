//! The human surface: server-rendered pages inside the same binary.
//!
//! Every page is a projection of the same store the API serves — the
//! UI holds no capability the protocol lacks, it only arranges what
//! the graph already knows. No client framework; HTML and one
//! stylesheet, rendered per request.
//!
//! Browser identity is the API token in an HttpOnly cookie (SameSite
//! Lax, which also covers the simple POST forms here). Dev-mode
//! servers additionally accept a bare principal name at login, same
//! as the rest of the dev seam.

mod diff;
mod views;

use crate::auth::resolve_bearer;
use crate::state::AppState;
use axum::Router;
use axum::extract::{Form, FromRequestParts, Path, Query, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use cairn_core::{Disposition, PrincipalId, ReviewDomain};
use serde::Deserialize;
use std::collections::HashMap;

const STYLE: &str = include_str!("style.css");
const TOKEN_COOKIE: &str = "cairn_token";
const DEV_COOKIE: &str = "cairn_dev";

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(home))
        .route("/assets/app.css", get(stylesheet))
        .route("/login", get(login_page).post(login_submit))
        .route("/logout", post(logout))
        .route("/{repo}", get(repo_page))
        .route("/{repo}/tree/{*path}", get(tree_page))
        .route("/{repo}/changes", get(changes_page))
        .route("/{repo}/changes/{number}", get(change_page))
        .route("/{repo}/changes/{number}/verdict", post(submit_verdict))
        .route("/{repo}/changes/{number}/enqueue", post(submit_enqueue))
        .route("/{repo}/landing", get(landing_page))
        .route("/{repo}/log", get(log_page))
}

async fn stylesheet() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], STYLE)
}

fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split("; ")
        .find_map(|pair| pair.strip_prefix(&format!("{name}=")))
        .map(str::to_owned)
}

/// The signed-in viewer. Pages redirect to /login instead of failing
/// with a machine-shaped 401.
pub struct Viewer(pub PrincipalId);

impl FromRequestParts<AppState> for Viewer {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        if let Some(token) = cookie(&parts.headers, TOKEN_COOKIE)
            && let Ok(principal) = resolve_bearer(state, &token)
        {
            return Ok(Viewer(principal));
        }
        if state.dev_identity()
            && let Some(name) = cookie(&parts.headers, DEV_COOKIE)
            && let Some(principal) = PrincipalId::new(&name)
        {
            return Ok(Viewer(principal));
        }
        Err(Redirect::to("/login").into_response())
    }
}

#[derive(Deserialize)]
struct FlashQuery {
    error: Option<String>,
}

async fn home(State(app): State<AppState>, viewer: Viewer) -> Response {
    let repos = match app.with_store(|s| s.repos()) {
        Ok(repos) => repos,
        Err(err) => return oops(err),
    };
    match repos.as_slice() {
        [only] => Redirect::to(&format!("/{}", only.name)).into_response(),
        _ => views::home(&viewer, &repos).into_response(),
    }
}

async fn login_page(State(app): State<AppState>, Query(flash): Query<FlashQuery>) -> Response {
    views::login(app.dev_identity(), flash.error.as_deref()).into_response()
}

#[derive(Deserialize)]
struct LoginForm {
    #[serde(default)]
    token: String,
    #[serde(default)]
    principal: String,
}

async fn login_submit(State(app): State<AppState>, Form(form): Form<LoginForm>) -> Response {
    let token = form.token.trim();
    if !token.is_empty() {
        return match app.with_store(|s| s.principal_for_token(token)) {
            Ok(Some(_)) => signed_in(TOKEN_COOKIE, token),
            Ok(None) => {
                Redirect::to("/login?error=That+token+is+unknown+or+revoked").into_response()
            }
            Err(err) => oops(err),
        };
    }
    let name = form.principal.trim();
    if app.dev_identity() && PrincipalId::new(name).is_some() {
        return signed_in(DEV_COOKIE, name);
    }
    Redirect::to("/login?error=Paste+an+API+token+to+sign+in").into_response()
}

fn signed_in(name: &str, value: &str) -> Response {
    let cookie = format!("{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000");
    ([(header::SET_COOKIE, cookie)], Redirect::to("/")).into_response()
}

async fn logout() -> Response {
    let clear = [
        format!("{TOKEN_COOKIE}=; Path=/; HttpOnly; Max-Age=0"),
        format!("{DEV_COOKIE}=; Path=/; HttpOnly; Max-Age=0"),
    ];
    (
        [
            (header::SET_COOKIE, clear[0].clone()),
            (header::SET_COOKIE, clear[1].clone()),
        ],
        Redirect::to("/login"),
    )
        .into_response()
}

fn oops(err: impl std::fmt::Display) -> Response {
    tracing::error!(error = %err, "web: page render failed");
    (StatusCode::INTERNAL_SERVER_ERROR, views::error_page()).into_response()
}

fn not_found() -> Response {
    (StatusCode::NOT_FOUND, views::not_found_page()).into_response()
}

async fn repo_page(
    State(app): State<AppState>,
    viewer: Viewer,
    Path(repo): Path<String>,
) -> Response {
    render_tree(app, viewer, repo, String::new()).await
}

async fn tree_page(
    State(app): State<AppState>,
    viewer: Viewer,
    Path((repo, path)): Path<(String, String)>,
) -> Response {
    render_tree(app, viewer, repo, path).await
}

async fn render_tree(app: AppState, viewer: Viewer, repo: String, path: String) -> Response {
    let Some(git) = app.git() else {
        return not_found();
    };
    let record = match app.with_store(|s| s.repo(&repo)) {
        Ok(Some(record)) => record,
        Ok(None) => return not_found(),
        Err(err) => return oops(err),
    };
    let branch = record.default_branch.clone();
    let rev = format!("refs/heads/{branch}");
    let tip = match git.store.tip(&repo, &branch).await {
        Ok(tip) => tip,
        Err(err) => return oops(err),
    };

    // A blob path renders as a file; a tree path (or the root) lists.
    if !path.is_empty() {
        match git.store.show_file(&repo, &rev, &path).await {
            Ok(Some(bytes)) => {
                let is_dir = git
                    .store
                    .ls_tree(&repo, &rev, &path)
                    .await
                    .map(|entries| !entries.is_empty())
                    .unwrap_or(false);
                if !is_dir {
                    let text = String::from_utf8_lossy(&bytes).into_owned();
                    return views::file(&viewer, &repo, &path, &text).into_response();
                }
            }
            Ok(None) => return not_found(),
            Err(err) => return oops(err),
        }
    }

    let listing = if tip.is_some() {
        match git.store.ls_tree(&repo, &rev, &path).await {
            Ok(entries) => entries,
            Err(err) => return oops(err),
        }
    } else {
        Vec::new()
    };
    // Each entry carries the change that last touched it: the file
    // tree is a way into the graph, not just a directory listing.
    let mut entries = Vec::with_capacity(listing.len());
    for (kind, name) in listing {
        let full = if path.is_empty() {
            name.clone()
        } else {
            format!("{path}/{name}")
        };
        let last = git
            .store
            .last_commit_for(&repo, &rev, &full)
            .await
            .ok()
            .flatten();
        let change = last.as_ref().and_then(|(oid, _)| {
            app.with_store(|s| s.change_by_landed_oid(&repo, oid))
                .ok()
                .flatten()
        });
        entries.push(views::Entry {
            is_dir: kind == "tree",
            name,
            subject: last.map(|(_, subject)| subject),
            change,
        });
    }
    let readme = if path.is_empty() && tip.is_some() {
        git.store
            .show_file(&repo, &rev, "README.md")
            .await
            .ok()
            .flatten()
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
    } else {
        None
    };
    let sidebar = match sidebar_data(&app, &repo, &record.default_branch) {
        Ok(sidebar) => sidebar,
        Err(err) => return oops(err),
    };
    views::repository(
        &viewer,
        &repo,
        &branch,
        tip.as_deref(),
        &path,
        &entries,
        readme.as_deref(),
        &sidebar,
    )
    .into_response()
}

pub(crate) struct Sidebar {
    pub open_changes: Vec<cairn_core::Change>,
    pub queue: Vec<cairn_core::QueueEntry>,
    pub sessions: Vec<cairn_core::Session>,
}

fn sidebar_data(
    app: &AppState,
    repo: &str,
    target: &str,
) -> Result<Sidebar, cairn_core::CoreError> {
    let mut open_changes = app.with_store(|s| s.changes_in_repo(repo))?;
    open_changes.retain(|c| c.state == cairn_core::ChangeState::Open);
    open_changes.reverse();
    open_changes.truncate(5);
    Ok(Sidebar {
        open_changes,
        queue: app.with_store(|s| s.queue_for(repo, target))?,
        sessions: app.with_store(|s| s.active_sessions())?,
    })
}

async fn changes_page(
    State(app): State<AppState>,
    viewer: Viewer,
    Path(repo): Path<String>,
) -> Response {
    if let Ok(None) | Err(_) = app.with_store(|s| s.repo(&repo)) {
        return not_found();
    }
    match app.with_store(|s| s.changes_in_repo(&repo)) {
        Ok(mut changes) => {
            changes.reverse();
            views::changes(&viewer, &repo, &changes).into_response()
        }
        Err(err) => oops(err),
    }
}

#[derive(Deserialize)]
struct ChangeQuery {
    r: Option<i64>,
    error: Option<String>,
}

async fn change_page(
    State(app): State<AppState>,
    viewer: Viewer,
    Path((repo, number)): Path<(String, i64)>,
    Query(query): Query<ChangeQuery>,
) -> Response {
    let change = match app.with_store(|s| s.change_by_number(&repo, number)) {
        Ok(Some(change)) => change,
        Ok(None) => return not_found(),
        Err(err) => return oops(err),
    };
    let revisions = match app.with_store(|s| s.revisions(&change.id)) {
        Ok(revisions) => revisions,
        Err(err) => return oops(err),
    };
    let shown = query
        .r
        .filter(|r| (1..=change.latest_revision).contains(r))
        .unwrap_or(change.latest_revision);
    let (claims, verdicts, trace) = match app.with_store(|s| {
        Ok::<_, cairn_core::CoreError>((
            s.claims_on(&change.id, shown)?,
            s.verdicts_on(&change.id, shown)?,
            s.merge_readiness(&change.id)?,
        ))
    }) {
        Ok(data) => data,
        Err(err) => return oops(err),
    };
    let queued = app.with_store(|s| s.queue_entry(&change.id)).ok().flatten();
    let task = change
        .task
        .as_ref()
        .and_then(|id| app.with_store(|s| s.task(id)).ok().flatten());

    let patch = match (app.git(), revisions.iter().find(|r| r.number == shown)) {
        (Some(git), Some(revision)) => git
            .store
            .show_patch(&repo, &revision.commit_oid)
            .await
            .unwrap_or_default(),
        _ => String::new(),
    };
    let files = diff::parse(&patch);

    views::change(views::ChangePage {
        viewer: &viewer,
        repo: &repo,
        change: &change,
        task: task.as_ref(),
        revisions: &revisions,
        shown,
        files: &files,
        claims: &claims,
        verdicts: &verdicts,
        trace: &trace,
        queued: queued.is_some(),
        error: query.error.as_deref(),
    })
    .into_response()
}

#[derive(Deserialize)]
struct VerdictForm {
    revision: i64,
    domain: String,
    disposition: String,
    rationale: String,
}

async fn submit_verdict(
    State(app): State<AppState>,
    viewer: Viewer,
    Path((repo, number)): Path<(String, i64)>,
    Form(form): Form<VerdictForm>,
) -> Response {
    let back = format!("/{repo}/changes/{number}");
    let Some(domain) = ReviewDomain::parse(&form.domain) else {
        return flash(&back, "Pick a domain");
    };
    let Some(disposition) = Disposition::parse(&form.disposition) else {
        return flash(&back, "Pick a disposition");
    };
    let change = match app.with_store(|s| s.change_by_number(&repo, number)) {
        Ok(Some(change)) => change.id,
        Ok(None) => return not_found(),
        Err(err) => return oops(err),
    };
    match app.with_store(|s| {
        s.give_verdict(
            &viewer.0,
            &change,
            form.revision,
            domain,
            disposition,
            form.rationale.trim(),
        )
    }) {
        Ok((_, env)) => {
            app.publish(&env);
            Redirect::to(&back).into_response()
        }
        Err(err) => flash(&back, &err.to_string()),
    }
}

async fn submit_enqueue(
    State(app): State<AppState>,
    viewer: Viewer,
    Path((repo, number)): Path<(String, i64)>,
) -> Response {
    let back = format!("/{repo}/changes/{number}");
    let change = match app.with_store(|s| s.change_by_number(&repo, number)) {
        Ok(Some(change)) => change.id,
        Ok(None) => return not_found(),
        Err(err) => return oops(err),
    };
    match app.with_store(|s| s.enqueue_change(&viewer.0, &change)) {
        Ok(env) => {
            app.publish(&env);
            Redirect::to(&back).into_response()
        }
        Err(err) => flash(&back, &err.to_string()),
    }
}

fn flash(back: &str, message: &str) -> Response {
    let encoded: String = message
        .bytes()
        .map(|b| match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'.' | b'_' => (b as char).to_string(),
            b' ' => "+".to_owned(),
            other => format!("%{other:02X}"),
        })
        .collect();
    Redirect::to(&format!("{back}?error={encoded}")).into_response()
}

async fn landing_page(
    State(app): State<AppState>,
    viewer: Viewer,
    Path(repo): Path<String>,
) -> Response {
    let record = match app.with_store(|s| s.repo(&repo)) {
        Ok(Some(record)) => record,
        Ok(None) => return not_found(),
        Err(err) => return oops(err),
    };
    let data = match landing_data(&app, &repo, &record.default_branch) {
        Ok(data) => data,
        Err(err) => return oops(err),
    };
    views::landing(&viewer, &repo, &record.default_branch, &data).into_response()
}

pub(crate) struct LandingData {
    /// (change, reason) — open changes that need a human, with why.
    pub needs_you: Vec<(cairn_core::Change, String)>,
    pub queue: Vec<cairn_core::QueueEntry>,
    /// Recent merged/dequeued outcomes, newest first.
    pub outcomes: Vec<cairn_core::Envelope>,
    pub live: Vec<cairn_core::Envelope>,
    pub sessions: Vec<cairn_core::Session>,
    /// Change id → (number, title), for readable references.
    pub numbers: HashMap<String, (i64, String)>,
}

fn landing_data(
    app: &AppState,
    repo: &str,
    target: &str,
) -> Result<LandingData, cairn_core::CoreError> {
    let changes = app.with_store(|s| s.changes_in_repo(repo))?;
    let numbers: HashMap<String, (i64, String)> = changes
        .iter()
        .map(|c| (c.id.as_str().to_owned(), (c.number, c.title.clone())))
        .collect();
    let mut needs_you = Vec::new();
    for change in changes.iter().rev() {
        if change.state != cairn_core::ChangeState::Open || change.latest_revision == 0 {
            continue;
        }
        let verdicts = app.with_store(|s| s.verdicts_on(&change.id, change.latest_revision))?;
        let claims = app.with_store(|s| s.claims_on(&change.id, change.latest_revision))?;
        let blocks: Vec<_> = verdicts
            .iter()
            .filter(|v| v.disposition == cairn_core::Disposition::Block)
            .collect();
        let approves = verdicts
            .iter()
            .filter(|v| v.disposition == cairn_core::Disposition::Approve)
            .count();
        let executed = claims
            .iter()
            .any(|c| c.kind != cairn_core::ClaimKind::Reasoning && c.passed);
        let reason = if !blocks.is_empty() && approves > 0 {
            format!(
                "{} approve, {} block — reviewers disagree",
                approves,
                blocks.len()
            )
        } else if !blocks.is_empty() {
            format!("blocked by {}", blocks[0].by)
        } else if !claims.is_empty() && !executed {
            "no executed check — reasoning only".to_owned()
        } else {
            continue;
        };
        needs_you.push((change.clone(), reason));
        if needs_you.len() == 8 {
            break;
        }
    }

    let latest = app.with_store(|s| s.latest_seq())?.0;
    let events =
        app.with_store(|s| s.events_after(cairn_core::EventSeq((latest - 200).max(0)), 220))?;
    let outcomes: Vec<_> = events
        .iter()
        .rev()
        .filter(|e| {
            matches!(
                e.event,
                cairn_core::Event::ChangeMerged { .. } | cairn_core::Event::ChangeDequeued { .. }
            )
        })
        .take(6)
        .cloned()
        .collect();
    let live: Vec<_> = events.iter().rev().take(9).cloned().collect();

    Ok(LandingData {
        needs_you,
        queue: app.with_store(|s| s.queue_for(repo, target))?,
        outcomes,
        live,
        sessions: app.with_store(|s| s.active_sessions())?,
        numbers,
    })
}

#[derive(Deserialize)]
struct LogQuery {
    after: Option<i64>,
}

async fn log_page(
    State(app): State<AppState>,
    viewer: Viewer,
    Path(repo): Path<String>,
    Query(query): Query<LogQuery>,
) -> Response {
    if let Ok(None) | Err(_) = app.with_store(|s| s.repo(&repo)) {
        return not_found();
    }
    let after = query.after.unwrap_or(0);
    let numbers: HashMap<String, (i64, String)> = match app.with_store(|s| s.changes_in_repo(&repo))
    {
        Ok(changes) => changes
            .iter()
            .map(|c| (c.id.as_str().to_owned(), (c.number, c.title.clone())))
            .collect(),
        Err(err) => return oops(err),
    };
    match app.with_store(|s| s.events_after(cairn_core::EventSeq(after), 100)) {
        Ok(events) => views::log(&viewer, &repo, &numbers, after, &events).into_response(),
        Err(err) => oops(err),
    }
}
