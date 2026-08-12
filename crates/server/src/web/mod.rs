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
const THEME_COOKIE: &str = "cairn_theme";

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(home))
        .route("/assets/app.css", get(stylesheet))
        .route("/login", get(login_page).post(login_submit))
        .route("/logout", post(logout))
        .route("/theme", post(set_theme))
        .route("/{repo}", get(repo_page))
        .route("/{repo}/tree/{*path}", get(tree_page))
        .route("/{repo}/blame/{*path}", get(blame_page))
        .route("/{repo}/changes", get(changes_page))
        .route("/{repo}/changes/{number}", get(change_page))
        .route("/{repo}/changes/{number}/verdict", post(submit_verdict))
        .route("/{repo}/changes/{number}/enqueue", post(submit_enqueue))
        .route("/{repo}/landing", get(landing_page))
        .route("/{repo}/log", get(log_page))
        .route("/{repo}/lessons", get(lessons_page))
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

/// The viewer's palette. Dark unless they have chosen otherwise.
pub struct Palette(pub views::Theme);

impl<S: Send + Sync> FromRequestParts<S> for Palette {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let theme = match cookie(&parts.headers, THEME_COOKIE).as_deref() {
            Some("light") => views::Theme::Light,
            _ => views::Theme::Dark,
        };
        Ok(Palette(theme))
    }
}

#[derive(Deserialize)]
struct ThemeForm {
    to: String,
    #[serde(default)]
    back: String,
}

async fn set_theme(headers: HeaderMap, Form(form): Form<ThemeForm>) -> Response {
    let value = if form.to == "light" { "light" } else { "dark" };
    let cookie = format!("{THEME_COOKIE}={value}; Path=/; SameSite=Lax; Max-Age=31536000");
    // Return where they were: the referer, or the repo root.
    let back = if form.back.starts_with('/') {
        form.back
    } else {
        headers
            .get(header::REFERER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split_once("://").map(|(_, rest)| rest))
            .and_then(|rest| rest.split_once('/').map(|(_, path)| format!("/{path}")))
            .unwrap_or_else(|| "/".to_owned())
    };
    ([(header::SET_COOKIE, cookie)], Redirect::to(&back)).into_response()
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

async fn home(State(app): State<AppState>, Palette(theme): Palette, viewer: Viewer) -> Response {
    let repos = match app.with_store(|s| s.repos()) {
        Ok(repos) => repos,
        Err(err) => return oops(err),
    };
    match repos.as_slice() {
        [only] => Redirect::to(&format!("/{}", only.name)).into_response(),
        _ => views::home(theme, &viewer, &repos).into_response(),
    }
}

async fn login_page(
    State(app): State<AppState>,
    Palette(theme): Palette,
    Query(flash): Query<FlashQuery>,
) -> Response {
    views::login(theme, app.dev_identity(), flash.error.as_deref()).into_response()
}

#[derive(Deserialize)]
struct LoginForm {
    #[serde(default)]
    token: String,
    #[serde(default)]
    principal: String,
}

async fn login_submit(
    State(app): State<AppState>,
    crate::guard::ClientIp(client): crate::guard::ClientIp,
    Form(form): Form<LoginForm>,
) -> Response {
    // Guessing a token should not be worth trying.
    if let Some(peer) = client
        && !app.login_limiter.accept(peer)
    {
        return crate::guard::too_many_attempts();
    }
    let token = form.token.trim();
    if !token.is_empty() {
        return match app.with_store(|s| s.principal_for_token(token)) {
            Ok(Some(_)) => signed_in(&app, TOKEN_COOKIE, token),
            Ok(None) => {
                Redirect::to("/login?error=That+token+is+unknown+or+revoked").into_response()
            }
            Err(err) => oops(err),
        };
    }
    let name = form.principal.trim();
    if app.dev_identity() && PrincipalId::new(name).is_some() {
        return signed_in(&app, DEV_COOKIE, name);
    }
    Redirect::to("/login?error=Paste+an+API+token+to+sign+in").into_response()
}

fn signed_in(app: &AppState, name: &str, value: &str) -> Response {
    let secure = if app.secure_cookies() { "; Secure" } else { "" };
    let cookie = format!("{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000{secure}");
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
    Palette(theme): Palette,
    viewer: Viewer,
    Path(repo): Path<String>,
) -> Response {
    render_tree(app, theme, viewer, repo, String::new()).await
}

async fn tree_page(
    State(app): State<AppState>,
    Palette(theme): Palette,
    viewer: Viewer,
    Path((repo, path)): Path<(String, String)>,
) -> Response {
    render_tree(app, theme, viewer, repo, path).await
}

async fn render_tree(
    app: AppState,
    theme: views::Theme,
    viewer: Viewer,
    repo: String,
    path: String,
) -> Response {
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
                    let landed_by = git
                        .store
                        .last_commit_for(&repo, &rev, &path)
                        .await
                        .ok()
                        .flatten()
                        .and_then(|(oid, _)| {
                            app.with_store(|s| s.change_by_landed_oid(&repo, &oid))
                                .ok()
                                .flatten()
                        });
                    return views::file(theme, &viewer, &repo, &path, &text, landed_by.as_ref())
                        .into_response();
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
        theme,
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
    /// What each live session declared it is working on.
    pub leases: Vec<cairn_core::Lease>,
    /// Change id → (number, title), so queued entries read as changes.
    pub numbers: HashMap<String, (i64, String)>,
}

fn sidebar_data(
    app: &AppState,
    repo: &str,
    target: &str,
) -> Result<Sidebar, cairn_core::CoreError> {
    let all = app.with_store(|s| s.changes_in_repo(repo))?;
    let numbers = all
        .iter()
        .map(|c| (c.id.as_str().to_owned(), (c.number, c.title.clone())))
        .collect();
    let mut open_changes: Vec<_> = all
        .into_iter()
        .filter(|c| c.state == cairn_core::ChangeState::Open)
        .collect();
    open_changes.reverse();
    open_changes.truncate(5);
    Ok(Sidebar {
        open_changes,
        queue: app.with_store(|s| s.queue_for(repo, target))?,
        sessions: app.with_store(|s| s.active_sessions())?,
        leases: app.with_store(|s| s.live_leases(repo))?,
        numbers,
    })
}

/// Attribution that answers "what do we know about this line": which
/// change landed it, what was claimed, who judged it — and what the
/// claims explicitly left unverified.
async fn blame_page(
    State(app): State<AppState>,
    Palette(theme): Palette,
    viewer: Viewer,
    Path((repo, path)): Path<(String, String)>,
) -> Response {
    let Some(git) = app.git() else {
        return not_found();
    };
    let record = match app.with_store(|s| s.repo(&repo)) {
        Ok(Some(record)) => record,
        Ok(None) => return not_found(),
        Err(err) => return oops(err),
    };
    let rev = format!("refs/heads/{}", record.default_branch);
    let text = match git.store.show_file(&repo, &rev, &path).await {
        Ok(Some(bytes)) => String::from_utf8_lossy(&bytes).into_owned(),
        Ok(None) => return not_found(),
        Err(err) => return oops(err),
    };
    let oids = git
        .store
        .blame_lines(&repo, &rev, &path)
        .await
        .unwrap_or_default();

    // One lookup per distinct commit, not per line.
    let mut known: HashMap<String, Option<std::sync::Arc<cairn_core::Provenance>>> = HashMap::new();
    let mut rows = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let oid = oids.get(index).cloned().unwrap_or_default();
        let provenance = match known.get(&oid) {
            Some(hit) => hit.clone(),
            None => {
                let found = app
                    .with_store(|s| s.provenance_of(&repo, &oid))
                    .ok()
                    .flatten()
                    .map(std::sync::Arc::new);
                known.insert(oid.clone(), found.clone());
                found
            }
        };
        rows.push(views::BlameRow {
            number: index + 1,
            text: line.to_owned(),
            provenance,
        });
    }
    views::blame(theme, &viewer, &repo, &path, &rows).into_response()
}

async fn changes_page(
    State(app): State<AppState>,
    Palette(theme): Palette,
    viewer: Viewer,
    Path(repo): Path<String>,
) -> Response {
    if let Ok(None) | Err(_) = app.with_store(|s| s.repo(&repo)) {
        return not_found();
    }
    match app.with_store(|s| s.changes_in_repo(&repo)) {
        Ok(mut changes) => {
            changes.reverse();
            views::changes(theme, &viewer, &repo, &changes).into_response()
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
    Palette(theme): Palette,
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
    let (claims, verifications, verdicts, trace) = match app.with_store(|s| {
        Ok::<_, cairn_core::CoreError>((
            s.claims_on(&change.id, shown)?,
            s.verifications_on(&change.id, shown)?,
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
        theme,
        viewer: &viewer,
        repo: &repo,
        change: &change,
        task: task.as_ref(),
        revisions: &revisions,
        shown,
        files: &files,
        claims: &claims,
        verifications: &verifications,
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
    Palette(theme): Palette,
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
    views::landing(theme, &viewer, &repo, &record.default_branch, &data).into_response()
}

pub(crate) struct LandingData {
    /// What a human should look at, ranked and explained.
    pub needs_you: Vec<cairn_core::AttentionItem>,
    pub queue: Vec<cairn_core::QueueEntry>,
    /// Recent merged/dequeued outcomes, newest first.
    pub outcomes: Vec<cairn_core::Envelope>,
    pub live: Vec<cairn_core::Envelope>,
    pub sessions: Vec<cairn_core::Session>,
    /// Change id → (number, title), for readable references.
    pub numbers: HashMap<String, (i64, String)>,
    /// The cursor a consumer would resume from right now.
    pub latest_seq: i64,
    /// A grounded summary of the window the page is showing.
    pub brief: Brief,
}

/// What happened lately, counted from the log rather than narrated.
/// Every number here is the size of a set the reader can go and look
/// at, which is what keeps it honest.
pub(crate) struct Brief {
    pub since: i64,
    pub landed: usize,
    pub dequeued: Vec<(String, String)>,
    pub failed_sessions: Vec<cairn_core::Lesson>,
    pub disputed: usize,
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
    let mut needs_you = app.with_store(|s| s.attention_for(repo))?;
    needs_you.truncate(8);

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

    // Everything the brief says is a count of events in this window,
    // so a reader can always go and check it.
    let window_start = (latest - 200).max(0);
    let mut landed = 0;
    let mut dequeued = Vec::new();
    let mut disputed = 0;
    for envelope in &events {
        match &envelope.event {
            cairn_core::Event::ChangeMerged { change, .. } => {
                if numbers.contains_key(change.as_str()) {
                    landed += 1;
                }
            }
            cairn_core::Event::ChangeDequeued { change, reason } => {
                if let Some((number, title)) = numbers.get(change.as_str()) {
                    dequeued.push((format!("#{number} {title}"), reason.clone()));
                }
            }
            cairn_core::Event::ClaimVerified { agrees: false, .. } => disputed += 1,
            _ => {}
        }
    }
    let failed_sessions = app
        .with_store(|s| s.lessons(Some(repo), None, true, 3))
        .unwrap_or_default();

    Ok(LandingData {
        brief: Brief {
            since: window_start,
            landed,
            dequeued,
            failed_sessions,
            disputed,
        },
        needs_you,
        queue: app.with_store(|s| s.queue_for(repo, target))?,
        outcomes,
        live,
        sessions: app.with_store(|s| s.active_sessions())?,
        numbers,
        latest_seq: latest,
    })
}

#[derive(Deserialize)]
struct LessonQuery {
    q: Option<String>,
}

async fn lessons_page(
    State(app): State<AppState>,
    Palette(theme): Palette,
    viewer: Viewer,
    Path(repo): Path<String>,
    Query(query): Query<LessonQuery>,
) -> Response {
    if let Ok(None) | Err(_) = app.with_store(|s| s.repo(&repo)) {
        return not_found();
    }
    let search = query.q.as_deref().filter(|q| !q.trim().is_empty());
    match app.with_store(|s| s.lessons(Some(&repo), search, false, 100)) {
        Ok(lessons) => views::lessons(theme, &viewer, &repo, search, &lessons).into_response(),
        Err(err) => oops(err),
    }
}

#[derive(Deserialize)]
struct LogQuery {
    after: Option<i64>,
}

async fn log_page(
    State(app): State<AppState>,
    Palette(theme): Palette,
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
        Ok(events) => views::log(theme, &viewer, &repo, &numbers, after, &events).into_response(),
        Err(err) => oops(err),
    }
}
