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
use cairn_core::{Disposition, PrincipalId, Repo, ReviewDomain};
use serde::Deserialize;
use std::collections::HashMap;

const STYLE: &str = include_str!("style.css");
/// The largest file rendered in a browser. Comfortably larger than any
/// source file, far smaller than what would hurt the process: the bytes
/// are held once as read, again as a string, and again escaped into
/// HTML, so the real cost is several times this.
const MAX_RENDERED_BLOB: u64 = 2 * 1024 * 1024;

/// The largest diff rendered on a change page. Same reasoning, plus the
/// diff is parsed into per-file structures before it is displayed.
const MAX_RENDERED_DIFF: usize = 1024 * 1024;

const SESSION_COOKIE: &str = "cairn_session";
const TOKEN_COOKIE: &str = "cairn_token";
const DEV_COOKIE: &str = "cairn_dev";
const THEME_COOKIE: &str = "cairn_theme";

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(root))
        .route("/waitlist", post(join_waitlist))
        .route("/assets/{file}", get(asset))
        .route("/login", get(login_page).post(login_submit))
        .route("/logout", post(logout))
        .route("/theme", post(set_theme))
        .route("/search", get(search_page))
        .route("/new", get(new_page).post(create_from_form))
        .route("/inbox", get(inbox_page))
        .route("/inbox/read", post(inbox_read))
        .route("/you", get(you_page))
        .route("/you/settings", get(settings_page).post(change_password))
        .route("/you/tokens", get(tokens_page).post(token_action))
        .route("/agents", get(agents_page).post(agent_action))
        .route("/people", get(people_page).post(people_action))
        .route("/join", get(join))
        .route("/{repo}", get(repo_page))
        .route("/{repo}/tree/{*path}", get(tree_page))
        .route("/{repo}/blame/{*path}", get(blame_page))
        .route("/{repo}/changes", get(changes_page))
        .route("/{repo}/changes/{number}", get(change_page))
        .route("/{repo}/changes/{number}/verdict", post(submit_verdict))
        .route("/{repo}/changes/{number}/claim", post(submit_claim))
        .route("/{repo}/changes/{number}/enqueue", post(submit_enqueue))
        .route("/{repo}/landing", get(landing_page))
        .route("/{repo}/log", get(log_page))
        .route("/{repo}/lessons", get(lessons_page))
}

/// The stylesheet's content hash, fixed for the life of the binary.
///
/// The page links to `/assets/app.<hash>.css`, so a deploy that changes
/// the CSS changes the URL, and the old one can be cached forever by
/// browsers and by whatever sits in front of the forge. Without this a
/// returning visitor gets last week's layout until some cache expires,
/// and nobody can tell from the outside why the page looks wrong.
static STYLE_HASH: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(STYLE.as_bytes());
    digest.iter().take(6).map(|b| format!("{b:02x}")).collect()
});

pub(crate) fn stylesheet_href() -> String {
    format!("/assets/app.{}.css", *STYLE_HASH)
}

/// Serve the stylesheet under its hashed name, immutable, or under its
/// bare name for anything that still asks that way, uncached.
async fn asset(Path(file): Path<String>) -> Response {
    let hashed = format!("app.{}.css", *STYLE_HASH);
    let cache = if file == hashed {
        "public, max-age=31536000, immutable"
    } else if file == "app.css" {
        "no-cache"
    } else {
        return not_found();
    };
    (
        [
            (header::CONTENT_TYPE, "text/css; charset=utf-8"),
            (header::CACHE_CONTROL, cache),
        ],
        STYLE,
    )
        .into_response()
}

/// Sizes for people, not for machines.
fn human_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;
    match bytes {
        b if b >= GIB => format!("{:.1} GB", b as f64 / GIB as f64),
        b if b >= MIB => format!("{:.1} MB", b as f64 / MIB as f64),
        b if b >= KIB => format!("{:.1} kB", b as f64 / KIB as f64),
        b => format!("{b} bytes"),
    }
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

#[derive(Deserialize)]
struct SearchQuery {
    #[serde(default)]
    q: String,
}

/// One search hit as the page shows it: what it is, where it goes.
pub struct Hit {
    pub kind: &'static str,
    pub label: String,
    pub detail: String,
    pub href: String,
}

/// Where a hit leads. A person leads to their work, because a page
/// about a person is a list of what they did.
fn hit_href(hit: &cairn_core::SearchHit) -> String {
    use cairn_core::HitKind::*;
    match (hit.kind, &hit.repo, hit.number, &hit.principal) {
        (Change, Some(repo), Some(number), _) => format!("/{repo}/changes/{number}"),
        (Repository, Some(repo), _, _) => format!("/{repo}"),
        (Task, Some(repo), _, _) => format!("/{repo}/changes"),
        (Lesson, Some(repo), _, _) => format!("/{repo}/lessons"),
        (Person, _, _, Some(who)) => format!("/search?q=by:{}", urlencode(who.as_str())),
        _ => "/".to_owned(),
    }
}

/// Search across what a person looks for by name, ranked, filtered by
/// the `key:value` words everybody already types into a forge.
async fn search_page(
    State(app): State<AppState>,
    Palette(theme): Palette,
    viewer: Viewer,
    Query(query): Query<SearchQuery>,
) -> Response {
    let parsed = cairn_core::SearchQuery::parse(&query.q);
    let hits = app.with_store(|store| store.search(&viewer.0, &parsed, 100));
    match hits {
        Ok(hits) => {
            let hits: Vec<Hit> = hits
                .iter()
                .map(|hit| Hit {
                    kind: hit.kind.as_str(),
                    label: hit.title.clone(),
                    detail: hit.detail.clone(),
                    href: hit_href(hit),
                })
                .collect();
            views::search(theme, &viewer, &query.q, parsed.kind, &hits).into_response()
        }
        Err(err) => oops(err),
    }
}

async fn new_page(Palette(theme): Palette, viewer: Viewer) -> Response {
    views::new_repo(theme, &viewer, None).into_response()
}

#[derive(Deserialize)]
struct NewRepoForm {
    #[serde(default)]
    name: String,
    #[serde(default)]
    default_branch: String,
    #[serde(default)]
    source: String,
}

/// Create a repository, and import into it when a source is given —
/// one form, because "start a repository" is one intention whether the
/// history already exists somewhere or not.
async fn create_from_form(
    State(app): State<AppState>,
    Palette(theme): Palette,
    viewer: Viewer,
    Form(form): Form<NewRepoForm>,
) -> Response {
    let name = form.name.trim().to_owned();
    let branch = match form.default_branch.trim() {
        "" => "main".to_owned(),
        given => given.to_owned(),
    };
    let source = form.source.trim().to_owned();

    let created = app.with_store(|store| {
        store.check_new_repo(&viewer.0, &name, &branch)?;
        Ok::<_, cairn_core::CoreError>(())
    });
    if let Err(err) = created {
        return views::new_repo(theme, &viewer, Some(&err.to_string())).into_response();
    }
    if let Some(git) = app.git()
        && let Err(err) = git.store.create_repo(&name, &branch, "sha1").await
    {
        return views::new_repo(theme, &viewer, Some(&err.to_string())).into_response();
    }
    let env = app.with_store(|store| {
        store.create_repo(&viewer.0, &name, &branch, cairn_core::ObjectFormat::Sha1)
    });
    match env {
        Ok(env) => app.publish(&env),
        Err(err) => return views::new_repo(theme, &viewer, Some(&err.to_string())).into_response(),
    }

    if !source.is_empty() {
        let outcome = import_into(&app, &viewer.0, &name, &branch, &source).await;
        if let Err(message) = outcome {
            return views::new_repo(theme, &viewer, Some(&message)).into_response();
        }
    }
    Redirect::to(&format!("/{name}")).into_response()
}

/// Bring existing history in. Same path the API takes, so the import is
/// recorded as an import rather than dressed up as review.
async fn import_into(
    app: &AppState,
    who: &PrincipalId,
    repo: &str,
    branch: &str,
    source: &str,
) -> Result<(), String> {
    cairn_core::Store::validate_import_source(source).map_err(|e| e.to_string())?;
    let git = app.git().ok_or("this forge has no git storage")?;
    let (tip, commits) = git
        .store
        .fetch_history(repo, source, branch)
        .await
        .map_err(|e| e.to_string())?;
    let env = app
        .with_store(|store| store.import_history(who, repo, branch, source, &tip, commits))
        .map_err(|e| e.to_string())?;
    git.store
        .advance_ref(repo, branch, &tip, None)
        .await
        .map_err(|e| e.to_string())?;
    let _ = git.store.clear_import_ref(repo, branch).await;
    app.publish(&env);
    Ok(())
}

/// Your open work, across every repository.
async fn inbox_page(
    State(app): State<AppState>,
    Palette(theme): Palette,
    viewer: Viewer,
) -> Response {
    let notices = app.with_store(|s| s.inbox(&viewer.0, 200));
    match notices {
        Ok(notices) => {
            let unread = notices.iter().filter(|n| !n.read).count();
            views::inbox(theme, &viewer, &notices, unread).into_response()
        }
        Err(err) => oops(err),
    }
}

#[derive(Deserialize)]
struct InboxReadForm {
    seq: Option<i64>,
    #[serde(default)]
    all: Option<String>,
}

async fn inbox_read(
    State(app): State<AppState>,
    viewer: Viewer,
    Form(form): Form<InboxReadForm>,
) -> Response {
    let result = match (form.all.is_some(), form.seq) {
        (true, _) => app.with_store(|s| s.mark_all_read(&viewer.0)),
        (false, Some(seq)) => app.with_store(|s| s.mark_read(&viewer.0, seq)),
        (false, None) => Ok(()),
    };
    match result {
        Ok(()) => Redirect::to("/inbox").into_response(),
        Err(err) => oops(err),
    }
}

async fn you_page(
    State(app): State<AppState>,
    Palette(theme): Palette,
    viewer: Viewer,
) -> Response {
    let mine = app.with_store(
        |store| -> Result<Vec<(String, cairn_core::Change)>, cairn_core::CoreError> {
            let mut mine = Vec::new();
            for repo in store.repos()? {
                for change in store.changes_in_repo(&repo.name)? {
                    if change.owner == viewer.0 && change.state == cairn_core::ChangeState::Open {
                        mine.push((repo.name.clone(), change));
                    }
                }
            }
            Ok(mine)
        },
    );
    match mine {
        Ok(mine) => views::you(theme, &viewer, &mine).into_response(),
        Err(err) => oops(err),
    }
}

#[derive(Deserialize)]
struct Flash {
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    done: Option<String>,
    /// A freshly minted token, shown once and never stored anywhere we
    /// could show it again.
    #[serde(default)]
    secret: Option<String>,
    /// A freshly minted invitation, likewise shown once.
    #[serde(default)]
    invite: Option<String>,
    /// First sign-in, straight from an invitation.
    #[serde(default)]
    first: Option<String>,
}

async fn settings_page(
    Palette(theme): Palette,
    viewer: Viewer,
    Query(flash): Query<Flash>,
) -> Response {
    views::settings(
        theme,
        &viewer,
        flash.error.as_deref(),
        flash.done.is_some(),
        flash.first.is_some(),
    )
    .into_response()
}

#[derive(Deserialize)]
struct PasswordForm {
    #[serde(default)]
    password: String,
    #[serde(default)]
    confirm: String,
}

async fn change_password(
    State(app): State<AppState>,
    viewer: Viewer,
    Form(form): Form<PasswordForm>,
) -> Response {
    if form.password != form.confirm {
        return Redirect::to("/you/settings?error=Those+two+did+not+match").into_response();
    }
    match app.with_store(|s| s.set_password(&viewer.0, &viewer.0, &form.password)) {
        Ok(env) => {
            // Changing a password ends every session it protected —
            // including this one, which is the correct and slightly
            // surprising consequence, so say so on the way out.
            app.end_sessions_of(&viewer.0);
            app.publish(&env);
            Redirect::to("/login?error=Password+changed.+Sign+in+again.").into_response()
        }
        Err(err) => Redirect::to(&format!(
            "/you/settings?error={}",
            urlencode(&err.to_string())
        ))
        .into_response(),
    }
}

/// Your tokens: what exists, and the two things you can do to them.
async fn tokens_page(
    State(app): State<AppState>,
    Palette(theme): Palette,
    viewer: Viewer,
    Query(flash): Query<Flash>,
) -> Response {
    match app.with_store(|s| s.tokens_of(&viewer.0)) {
        Ok(tokens) => views::tokens(
            theme,
            &viewer,
            &tokens,
            flash.secret.as_deref(),
            flash.error.as_deref(),
        )
        .into_response(),
        Err(err) => oops(err),
    }
}

#[derive(Deserialize)]
struct TokenForm {
    #[serde(default)]
    action: String,
    #[serde(default)]
    label: String,
    #[serde(default)]
    token: String,
}

async fn token_action(
    State(app): State<AppState>,
    viewer: Viewer,
    Form(form): Form<TokenForm>,
) -> Response {
    let outcome = match form.action.as_str() {
        "revoke" => app
            .with_store(|s| s.revoke_token(&viewer.0, &cairn_core::TokenId(form.token.clone())))
            .map(|env| {
                app.publish(&env);
                None
            }),
        _ => {
            let label = form.label.trim();
            let label = (!label.is_empty()).then_some(label);
            app.with_store(|s| s.mint_token(&viewer.0, &viewer.0, label))
                .map(|(_, secret, env)| {
                    app.publish(&env);
                    Some(secret)
                })
        }
    };
    match outcome {
        // The secret exists exactly once. It rides back in the redirect
        // because there is nowhere else it could come from later.
        Ok(Some(secret)) => {
            Redirect::to(&format!("/you/tokens?secret={}", urlencode(&secret))).into_response()
        }
        Ok(None) => Redirect::to("/you/tokens").into_response(),
        Err(err) => Redirect::to(&format!(
            "/you/tokens?error={}",
            urlencode(&err.to_string())
        ))
        .into_response(),
    }
}

/// An agent and everything it is allowed to do.
/// A person as the people page shows them: who they are, and whether
/// they can sign in yet.
pub struct PersonRow {
    pub principal: cairn_core::Principal,
    pub has_password: bool,
    pub admin: bool,
}

/// Who is here, and a way to bring somebody in. Running the forge is
/// what this page is for, so to anybody else it does not exist.
async fn people_page(
    State(app): State<AppState>,
    Palette(theme): Palette,
    viewer: Viewer,
    headers: HeaderMap,
    Query(flash): Query<Flash>,
) -> Response {
    if !viewer.1.admin {
        return not_found();
    }
    let people = app.with_store(|store| {
        let mut rows = Vec::new();
        for principal in store.principals()? {
            if principal.kind != cairn_core::PrincipalKind::Human {
                continue;
            }
            rows.push(PersonRow {
                has_password: store.has_password(&principal.id),
                admin: store.is_admin(&principal.id),
                principal,
            });
        }
        Ok::<_, cairn_core::CoreError>(rows)
    });
    // The invitation is a link to this forge, so it needs to know its
    // own address; a proxy in front says so, and otherwise the cookie
    // policy already tells us whether this is https.
    let join_link = flash.invite.as_deref().map(|secret| {
        let host = headers
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("localhost");
        let scheme = headers
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .unwrap_or(if app.secure_cookies() {
                "https"
            } else {
                "http"
            });
        format!("{scheme}://{host}/join?token={}", urlencode(secret))
    });
    match people {
        Ok(people) => views::people(
            theme,
            &viewer,
            &people,
            join_link.as_deref(),
            flash.error.as_deref(),
        )
        .into_response(),
        Err(err) => oops(err),
    }
}

#[derive(Deserialize)]
struct PersonForm {
    #[serde(default)]
    id: String,
    #[serde(default)]
    display: String,
}

/// Register a person and hand back the one thing they need: a link
/// that signs them in once. It is a token under the hood, labelled so
/// that /join knows to spend it, and shown exactly once like any other.
async fn people_action(
    State(app): State<AppState>,
    viewer: Viewer,
    Form(form): Form<PersonForm>,
) -> Response {
    if !viewer.1.admin {
        return not_found();
    }
    let back =
        |error: &str| Redirect::to(&format!("/people?error={}", urlencode(error))).into_response();
    let Some(id) = PrincipalId::new(form.id.trim()) else {
        return back(&format!("{:?} is not a valid name", form.id));
    };
    let display = form.display.trim();
    let display = if display.is_empty() {
        id.as_str()
    } else {
        display
    };
    let registered = app.with_store(|s| {
        s.register_principal(
            &viewer.0,
            &id,
            cairn_core::PrincipalKind::Human,
            display,
            None,
            None,
        )
    });
    match registered {
        Ok(env) => {
            app.publish(&env);
            match app.with_store(|s| s.mint_token(&viewer.0, &id, Some(INVITE_LABEL))) {
                Ok((_, secret, env)) => {
                    app.publish(&env);
                    Redirect::to(&format!("/people?invite={}", urlencode(&secret))).into_response()
                }
                Err(err) => back(&err.to_string()),
            }
        }
        Err(err) => back(&err.to_string()),
    }
}

/// The label that marks a token as an invitation rather than a credential.
const INVITE_LABEL: &str = "invitation";

#[derive(Deserialize)]
struct JoinQuery {
    #[serde(default)]
    token: String,
}

/// Arrive from an invitation: the token becomes a browser session and is
/// spent in the same breath, so the link works once. Then straight to
/// setting a password, because a session expires and the link is gone.
async fn join(State(app): State<AppState>, Query(query): Query<JoinQuery>) -> Response {
    let expired =
        || Redirect::to("/login?error=That+invitation+has+been+used+or+revoked").into_response();
    let token = match app.with_store(|s| s.token_for_secret(query.token.trim())) {
        Ok(Some(token)) if token.label.as_deref() == Some(INVITE_LABEL) => token,
        Ok(_) => return expired(),
        Err(err) => return oops(err),
    };
    // Spend it first: a session that could be minted twice from one
    // link is a link that can be forwarded.
    match app.with_store(|s| s.revoke_token(&token.principal, &token.id)) {
        Ok(env) => app.publish(&env),
        Err(err) => return oops(err),
    }
    match app.start_session(&token.principal) {
        Ok(session) => signed_in_to(&app, SESSION_COOKIE, &session, "/you/settings?first=1"),
        Err(err) => oops(err),
    }
}

pub struct AgentRow {
    pub principal: cairn_core::Principal,
    pub grants: Vec<cairn_core::Grant>,
}

async fn agents_page(
    State(app): State<AppState>,
    Palette(theme): Palette,
    viewer: Viewer,
    Query(flash): Query<Flash>,
) -> Response {
    let data = app.with_store(|store| {
        let mut agents = Vec::new();
        for principal in store.principals()? {
            if principal.kind != cairn_core::PrincipalKind::Agent {
                continue;
            }
            let grants = store.grants_of(&principal.id)?;
            agents.push(AgentRow { principal, grants });
        }
        let repos: Vec<String> = store.repos()?.into_iter().map(|r| r.name).collect();
        Ok::<_, cairn_core::CoreError>((agents, repos))
    });
    match data {
        Ok((agents, repos)) => views::agents(
            theme,
            &viewer,
            &agents,
            &repos,
            flash.secret.as_deref(),
            flash.error.as_deref(),
        )
        .into_response(),
        Err(err) => oops(err),
    }
}

#[derive(Deserialize)]
struct AgentForm {
    #[serde(default)]
    action: String,
    #[serde(default)]
    id: String,
    #[serde(default)]
    display: String,
    #[serde(default)]
    model: String,
    #[serde(default)]
    grantee: String,
    #[serde(default)]
    repo: String,
    // One field per capability rather than a repeated `actions` key:
    // the form encoding axum uses cannot deserialise a sequence, and a
    // checkbox group that silently arrives empty is the worst kind of
    // bug — the grant looks issued and grants nothing.
    #[serde(default)]
    task: Option<String>,
    #[serde(default)]
    push: Option<String>,
    #[serde(default)]
    review: Option<String>,
    #[serde(default)]
    merge: Option<String>,
    #[serde(default)]
    verify: Option<String>,
    #[serde(default)]
    grant: String,
    #[serde(default)]
    reason: String,
}

async fn agent_action(
    State(app): State<AppState>,
    viewer: Viewer,
    Form(form): Form<AgentForm>,
) -> Response {
    let back = |error: Option<String>, secret: Option<String>| match (error, secret) {
        (Some(error), _) => {
            Redirect::to(&format!("/agents?error={}", urlencode(&error))).into_response()
        }
        (None, Some(secret)) => {
            Redirect::to(&format!("/agents?secret={}", urlencode(&secret))).into_response()
        }
        _ => Redirect::to("/agents").into_response(),
    };

    match form.action.as_str() {
        "register" => {
            let Some(id) = PrincipalId::new(form.id.trim()) else {
                return back(Some(format!("{:?} is not a valid name", form.id)), None);
            };
            let model = form.model.trim();
            let registered = app.with_store(|s| {
                s.register_principal(
                    &viewer.0,
                    &id,
                    cairn_core::PrincipalKind::Agent,
                    form.display.trim(),
                    (!model.is_empty()).then_some(model),
                    None,
                )
            });
            match registered {
                Ok(env) => {
                    app.publish(&env);
                    // A registered agent with no token cannot do
                    // anything, so mint one here rather than making
                    // somebody find the second form.
                    match app.with_store(|s| s.mint_token(&viewer.0, &id, Some("created here"))) {
                        Ok((_, secret, env)) => {
                            app.publish(&env);
                            back(None, Some(secret))
                        }
                        Err(err) => back(Some(err.to_string()), None),
                    }
                }
                Err(err) => back(Some(err.to_string()), None),
            }
        }
        "grant" => {
            let actions: Vec<cairn_core::Capability> = [
                (form.task.is_some(), cairn_core::Capability::Task),
                (form.push.is_some(), cairn_core::Capability::Push),
                (form.review.is_some(), cairn_core::Capability::Review),
                (form.merge.is_some(), cairn_core::Capability::Merge),
                (form.verify.is_some(), cairn_core::Capability::Verify),
            ]
            .into_iter()
            .filter_map(|(ticked, capability)| ticked.then_some(capability))
            .collect();
            if actions.is_empty() {
                return back(Some("pick at least one capability".to_owned()), None);
            }
            let repo = form.repo.trim();
            let issued = app.with_store(|s| {
                s.issue_grant(
                    &viewer.0,
                    &PrincipalId(form.grantee.clone()),
                    (!repo.is_empty()).then_some(repo),
                    actions,
                    None,
                )
            });
            match issued {
                Ok((_, env)) => {
                    app.publish(&env);
                    back(None, None)
                }
                Err(err) => back(Some(err.to_string()), None),
            }
        }
        "revoke" => {
            let reason = match form.reason.trim() {
                "" => "revoked from the agents page".to_owned(),
                given => given.to_owned(),
            };
            match app.with_store(|s| {
                s.revoke_grant(&viewer.0, &cairn_core::GrantId(form.grant.clone()), &reason)
            }) {
                Ok(env) => {
                    app.publish(&env);
                    back(None, None)
                }
                Err(err) => back(Some(err.to_string()), None),
            }
        }
        other => back(Some(format!("unknown action {other:?}")), None),
    }
}

/// Everything the chrome needs, in one pass over the store./// Everything the chrome needs, in one pass over the store.
fn chrome_for(app: &AppState, who: &PrincipalId) -> Result<Chrome, cairn_core::CoreError> {
    app.with_store(|store| {
        let mut repos = Vec::new();
        let mut yours = 0;
        let mut leases = Vec::new();
        for repo in store.readable_repos(who)? {
            leases.extend(store.live_leases(&repo.name)?);
            let changes = store.changes_in_repo(&repo.name)?;
            let open: Vec<_> = changes
                .iter()
                .filter(|c| c.state == cairn_core::ChangeState::Open)
                .collect();
            yours += open.iter().filter(|c| c.owner == *who).count();
            repos.push(ChromeRepo {
                name: repo.name,
                open: open.len(),
            });
        }

        // Who is mid-session, and what they said they would touch. This
        // is cairn's version of a live activity view: not what people
        // published, but what is being worked on at this moment.
        let working = store
            .active_sessions()?
            .into_iter()
            .map(|session| {
                let lease = leases.iter().find(|l| l.session == session.id);
                Working {
                    who: session.agent.as_str().to_owned(),
                    repo: lease.map(|l| l.repo.clone()),
                    paths: lease.map(|l| l.paths.clone()).unwrap_or_default(),
                }
            })
            .collect();

        Ok(Chrome {
            repos,
            working,
            yours,
            unread: store.unread_count(who)?,
            admin: store.is_admin(who),
        })
    })
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
/// One repository, as the sidebar lists it.
pub struct ChromeRepo {
    pub name: String,
    pub open: usize,
}

/// Somebody working right now: an agent or a person mid-session.
pub struct Working {
    pub who: String,
    pub repo: Option<String>,
    pub paths: Vec<String>,
}

/// What every signed-in page renders around its content.
///
/// Gathered by the [`Viewer`] extractor rather than by each handler:
/// the question "who is looking" and the question "what can they see"
/// have the same answer, and threading it through thirteen page
/// functions would only invite them to drift apart.
pub struct Chrome {
    pub repos: Vec<ChromeRepo>,
    pub working: Vec<Working>,
    pub yours: usize,
    /// Notices the viewer has not dealt with, for the sidebar count.
    pub unread: usize,
    /// Whether the viewer runs the forge, which decides what the sidebar
    /// offers rather than what any page allows.
    pub admin: bool,
}

pub struct Viewer(pub PrincipalId, pub Chrome);

/// Who is looking, if anyone.
///
/// Shared by the extractor and by the routes that serve both a
/// signed-out and a signed-in page, so the two can never disagree about
/// what counts as being signed in.
fn viewer_from(headers: &HeaderMap, state: &AppState) -> Option<Viewer> {
    // A signed-in browser, the ordinary case.
    let who = if let Some(id) = cookie(headers, SESSION_COOKIE)
        && let Some(principal) = state.resolve_session(&id)
    {
        principal
    }
    // A pasted API token still works, for anyone driving the UI the way
    // a script would.
    else if let Some(token) = cookie(headers, TOKEN_COOKIE)
        && let Ok(principal) = resolve_bearer(state, &token)
    {
        principal
    } else if state.dev_identity()
        && let Some(name) = cookie(headers, DEV_COOKIE)
        && let Some(principal) = PrincipalId::new(&name)
    {
        principal
    } else {
        return None;
    };
    chrome_for(state, &who)
        .ok()
        .map(|chrome| Viewer(who, chrome))
}

impl FromRequestParts<AppState> for Viewer {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        viewer_from(&parts.headers, state).ok_or_else(|| Redirect::to("/login").into_response())
    }
}

/// A change wanting judgment, and which repository it lives in.
pub struct HomeAttention {
    pub repo: String,
    pub item: cairn_core::AttentionItem,
}

/// One line of "what happened lately", already resolved to words.
pub struct Recent {
    pub where_: String,
    pub what: String,
    pub kind: &'static str,
}

/// A branch's landing queue, for the rail.
pub struct Lane {
    pub repo: String,
    pub branch: String,
    pub queued: usize,
}

pub struct HomeData {
    pub needs_you: Vec<HomeAttention>,
    pub mine: Vec<(String, cairn_core::Change)>,
    pub recent: Vec<Recent>,
    pub lanes: Vec<Lane>,
    pub lessons: Vec<cairn_core::Lesson>,
}

#[derive(Deserialize)]
struct LandingQuery {
    #[serde(default)]
    joined: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

/// `/` is two pages. Signed in, it is the home; signed out, it is what
/// this thing is and a way to be told when it is ready. Redirecting a
/// visitor to a sign-in form tells them nothing and asks for something
/// they do not have.
async fn root(
    State(app): State<AppState>,
    Palette(theme): Palette,
    headers: HeaderMap,
    Query(flash): Query<LandingQuery>,
) -> Response {
    let Some(viewer) = viewer_from(&headers, &app) else {
        return views::welcome(theme, flash.joined.is_some(), flash.error.as_deref())
            .into_response();
    };
    if viewer.1.repos.is_empty() {
        return views::first_run(theme, &viewer).into_response();
    }
    match gather_home(&app, &viewer.0) {
        Ok(data) => views::home(theme, &viewer, &data).into_response(),
        Err(err) => oops(err),
    }
}

#[derive(Deserialize)]
struct WaitlistForm {
    #[serde(default)]
    email: String,
    #[serde(default)]
    note: String,
}

/// Take an address from a stranger, which means assuming the worst about
/// who is calling: rate limited by source, validated, and answered the
/// same way whether or not the address was already on the list.
async fn join_waitlist(
    State(app): State<AppState>,
    crate::guard::ClientIp(client): crate::guard::ClientIp,
    Form(form): Form<WaitlistForm>,
) -> Response {
    if let Some(peer) = client
        && !app.waitlist_limiter.accept(peer)
    {
        return crate::guard::too_many_attempts();
    }
    let note = form.note.trim().to_owned();
    match app.with_store(|store| store.join_waitlist(&form.email, Some(&note))) {
        // Whether they were already on it is not the visitor's business
        // to learn, and not worth a different answer.
        Ok(_) => Redirect::to("/?joined=1").into_response(),
        Err(cairn_core::CoreError::Invalid(message)) => {
            Redirect::to(&format!("/?error={}", urlencode(&message))).into_response()
        }
        Err(err) => oops(err),
    }
}

/// Percent-encode for a query string. Small enough to own.
fn urlencode(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            b' ' => "+".to_owned(),
            other => format!("%{other:02X}"),
        })
        .collect()
}

fn gather_home(app: &AppState, who: &PrincipalId) -> Result<HomeData, cairn_core::CoreError> {
    app.with_store(|store| {
        let mut needs_you = Vec::new();
        let mut mine = Vec::new();
        let mut lanes = Vec::new();
        for repo in store.readable_repos(who)? {
            for item in store.attention_for(&repo.name)? {
                needs_you.push(HomeAttention {
                    repo: repo.name.clone(),
                    item,
                });
            }
            for change in store.changes_in_repo(&repo.name)? {
                if change.owner == *who && change.state == cairn_core::ChangeState::Open {
                    mine.push((repo.name.clone(), change));
                }
            }
            let queued = store.queue_for(&repo.name, &repo.default_branch)?.len();
            if queued > 0 {
                lanes.push(Lane {
                    repo: repo.name.clone(),
                    branch: repo.default_branch.clone(),
                    queued,
                });
            }
        }
        // Rank the whole set together: the work does not care which
        // repository it happens to live in.
        needs_you.sort_by_key(|entry| std::cmp::Reverse(entry.item.score));
        needs_you.truncate(10);
        mine.truncate(6);

        let latest = store.latest_seq()?.0;
        let recent = store
            .events_visible_to(who, cairn_core::EventSeq((latest - 300).max(0)), 320)?
            .into_iter()
            .rev()
            .filter_map(describe)
            .take(8)
            .collect();

        // Failures only: a lesson is what an attempt that did not work left behind.
        let lessons = store.lessons(None, None, true, 3)?;
        Ok(HomeData {
            needs_you,
            mine,
            recent,
            lanes,
            lessons,
        })
    })
}

/// Turn an event into a line worth reading. Anything not worth a
/// person's attention on a home page is left out rather than padded in.
fn describe(envelope: cairn_core::Envelope) -> Option<Recent> {
    use cairn_core::Event;
    let actor = envelope.actor.as_str().to_owned();
    match envelope.event {
        Event::ChangeMerged { change, .. } => Some(Recent {
            where_: change.as_str().to_owned(),
            what: format!("{actor} landed a change"),
            kind: "landed",
        }),
        Event::ChangeDequeued { reason, .. } => Some(Recent {
            where_: String::new(),
            what: reason,
            kind: "dequeued",
        }),
        Event::ClaimVerified { agrees, .. } if !agrees => Some(Recent {
            where_: String::new(),
            what: format!("{actor} could not reproduce a claim"),
            kind: "disputed",
        }),
        Event::HistoryImported { repo, commits, .. } => Some(Recent {
            where_: repo,
            what: format!("{actor} imported {commits} commits"),
            kind: "imported",
        }),
        Event::RepoCreated { repo, .. } => Some(Recent {
            where_: repo.clone(),
            what: format!("{actor} created {repo}"),
            kind: "created",
        }),
        _ => None,
    }
}

#[derive(Deserialize)]
struct FlashQuery {
    error: Option<String>,
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
    #[serde(default)]
    password: Option<String>,
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
    // A name and password: the ordinary way a person signs in.
    let name = form.principal.trim();
    let password = form.password.unwrap_or_default();
    if !name.is_empty() && !password.is_empty() {
        let Some(principal) = PrincipalId::new(name) else {
            // Same answer as a wrong password: which names exist is not
            // something a sign-in form should be willing to confirm.
            return Redirect::to("/login?error=That+name+and+password+do+not+match")
                .into_response();
        };
        return if app.with_store(|s| s.password_matches(&principal, &password)) {
            match app.start_session(&principal) {
                Ok(session) => signed_in(&app, SESSION_COOKIE, &session),
                Err(err) => oops(err),
            }
        } else {
            Redirect::to("/login?error=That+name+and+password+do+not+match").into_response()
        };
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
    if app.dev_identity() && PrincipalId::new(name).is_some() {
        return signed_in(&app, DEV_COOKIE, name);
    }
    Redirect::to("/login?error=Enter+your+name+and+password%2C+or+paste+an+API+token")
        .into_response()
}

fn signed_in(app: &AppState, name: &str, value: &str) -> Response {
    signed_in_to(app, name, value, "/")
}

fn signed_in_to(app: &AppState, name: &str, value: &str, to: &str) -> Response {
    let secure = if app.secure_cookies() { "; Secure" } else { "" };
    let cookie = format!("{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000{secure}");
    ([(header::SET_COOKIE, cookie)], Redirect::to(to)).into_response()
}

async fn logout(State(app): State<AppState>, headers: HeaderMap) -> Response {
    // Forget the session server-side too. Clearing the cookie alone
    // would leave a credential that still works if it was ever copied.
    if let Some(id) = cookie(&headers, SESSION_COOKIE) {
        app.end_session(&id);
    }
    let clear = [
        format!("{SESSION_COOKIE}=; Path=/; HttpOnly; Max-Age=0"),
        format!("{TOKEN_COOKIE}=; Path=/; HttpOnly; Max-Age=0"),
        format!("{DEV_COOKIE}=; Path=/; HttpOnly; Max-Age=0"),
    ];
    (
        [
            (header::SET_COOKIE, clear[0].clone()),
            (header::SET_COOKIE, clear[1].clone()),
            (header::SET_COOKIE, clear[2].clone()),
        ],
        Redirect::to("/login"),
    )
        .into_response()
}

fn oops(err: impl std::fmt::Display) -> Response {
    tracing::error!(error = %err, "web: page render failed");
    (StatusCode::INTERNAL_SERVER_ERROR, views::error_page()).into_response()
}

/// The repository if the viewer may read it. A page for a private
/// repository answers a stranger exactly as a missing one does, which is
/// the same rule the API and the git transport apply.
fn readable(app: &AppState, viewer: &Viewer, repo: &str) -> Result<Repo, Box<Response>> {
    match app.with_store(|s| s.readable(&viewer.0, repo)) {
        Ok(Some(record)) => Ok(record),
        Ok(None) => Err(Box::new(not_found())),
        Err(err) => Err(Box::new(oops(err))),
    }
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
    let record = match readable(&app, &viewer, &repo) {
        Ok(record) => record,
        Err(response) => return *response,
    };
    let branch = record.default_branch.clone();
    let rev = format!("refs/heads/{branch}");
    let tip = match git.store.tip(&repo, &branch).await {
        Ok(tip) => tip,
        Err(err) => return oops(err),
    };

    // A blob path renders as a file; a tree path (or the root) lists.
    if !path.is_empty() {
        match git
            .store
            .read_blob(&repo, &rev, &path, MAX_RENDERED_BLOB)
            .await
        {
            Ok(Some(blob)) => {
                let is_dir = git
                    .store
                    .ls_tree(&repo, &rev, &path)
                    .await
                    .map(|entries| !entries.is_empty())
                    .unwrap_or(false);
                if !is_dir {
                    let text = match blob {
                        cairn_git::Blob::Text(text) => text,
                        cairn_git::Blob::Binary { bytes } => {
                            format!("Binary file, {}.", human_bytes(bytes))
                        }
                        cairn_git::Blob::TooLarge { bytes } => format!(
                            "File is {}, larger than the {} this forge renders. \
                             Clone the repository to read it.",
                            human_bytes(bytes),
                            human_bytes(MAX_RENDERED_BLOB)
                        ),
                    };
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
        // This one renders without anyone asking for it, so the bound
        // matters more here than on a file someone chose to open.
        match git
            .store
            .read_blob(&repo, &rev, "README.md", MAX_RENDERED_BLOB)
            .await
        {
            Ok(Some(cairn_git::Blob::Text(text))) => Some(text),
            _ => None,
        }
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
    let record = match readable(&app, &viewer, &repo) {
        Ok(record) => record,
        Err(response) => return *response,
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
    if let Err(response) = readable(&app, &viewer, &repo) {
        return *response;
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
    if let Err(response) = readable(&app, &viewer, &repo) {
        return *response;
    }
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
        (Some(git), Some(revision)) => {
            let full = git
                .store
                .show_patch(&repo, &revision.commit_oid)
                .await
                .unwrap_or_default();
            // A change that adds a large file produces a diff nobody
            // reads and every viewer pays for. Cut it at a boundary the
            // parser understands, on a line, and say so.
            if full.len() > MAX_RENDERED_DIFF {
                let cut = full[..MAX_RENDERED_DIFF]
                    .rfind('\n')
                    .unwrap_or(MAX_RENDERED_DIFF);
                format!(
                    "{}\n--- diff truncated at {} of {}; fetch the revision to see the rest ---\n",
                    &full[..cut],
                    human_bytes(MAX_RENDERED_DIFF as u64),
                    human_bytes(full.len() as u64)
                )
            } else {
                full
            }
        }
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
struct ClaimForm {
    revision: i64,
    kind: String,
    #[serde(default)]
    command: String,
    passed: String,
    summary: String,
    #[serde(default)]
    unchecked: String,
}

/// Attach a claim from the page. A person recording what they ran, or an
/// agent driving the UI, gets the same contract the API offers: kind,
/// the command that produced it, what was seen, and what was left
/// unchecked - which is a comma-separated field here because a form
/// cannot carry a list.
async fn submit_claim(
    State(app): State<AppState>,
    viewer: Viewer,
    Path((repo, number)): Path<(String, i64)>,
    Form(form): Form<ClaimForm>,
) -> Response {
    let back = format!("/{repo}/changes/{number}");
    let Some(kind) = cairn_core::ClaimKind::parse(&form.kind) else {
        return flash(&back, "Pick a kind");
    };
    let passed = match form.passed.as_str() {
        "yes" => true,
        "no" => false,
        _ => return flash(&back, "Say whether it passed"),
    };
    if let Err(response) = readable(&app, &viewer, &repo) {
        return *response;
    }
    let change = match app.with_store(|s| s.change_by_number(&repo, number)) {
        Ok(Some(change)) => change.id,
        Ok(None) => return not_found(),
        Err(err) => return oops(err),
    };
    let command = form.command.trim();
    let spec = cairn_core::ClaimSpec {
        kind,
        command: (!command.is_empty()).then(|| command.to_owned()),
        passed,
        summary: form.summary.trim().to_owned(),
        unchecked: form
            .unchecked
            .split(',')
            .map(str::trim)
            .filter(|gap| !gap.is_empty())
            .map(str::to_owned)
            .collect(),
    };
    match app.with_store(|s| s.attach_claim(&viewer.0, &change, form.revision, spec)) {
        Ok((_, env)) => {
            app.publish(&env);
            Redirect::to(&back).into_response()
        }
        Err(err) => flash(&back, &err.to_string()),
    }
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
    if let Err(response) = readable(&app, &viewer, &repo) {
        return *response;
    }
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
    if let Err(response) = readable(&app, &viewer, &repo) {
        return *response;
    }
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
    let record = match readable(&app, &viewer, &repo) {
        Ok(record) => record,
        Err(response) => return *response,
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
    if let Err(response) = readable(&app, &viewer, &repo) {
        return *response;
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
    if let Err(response) = readable(&app, &viewer, &repo) {
        return *response;
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
    // This repository's own log, not the forge's. The scope is on the
    // event, so the page does not have to guess which rows belong here.
    match app.with_store(|s| s.events_for_repo(&repo, cairn_core::EventSeq(after), 100)) {
        Ok(events) => views::log(theme, &viewer, &repo, &numbers, after, &events).into_response(),
        Err(err) => oops(err),
    }
}
