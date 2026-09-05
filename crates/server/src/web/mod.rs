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

pub(crate) const SESSION_COOKIE: &str = "cairn_session";
const TOKEN_COOKIE: &str = "cairn_token";
const DEV_COOKIE: &str = "cairn_dev";
const THEME_COOKIE: &str = "cairn_theme";

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(root))
        .route("/waitlist", post(join_waitlist))
        .route("/assets/{file}", get(asset))
        .route("/login", get(login_page).post(login_submit))
        .route("/login/link", post(login_link))
        .route("/signin", get(signin_with_link))
        .route("/forgot", get(forgot_page).post(forgot_submit))
        .route("/reset", get(reset_page).post(reset_submit))
        .route("/verify", get(verify_email))
        .route("/logout", post(logout))
        .route("/theme", post(set_theme))
        .route("/search", get(search_page))
        .route("/new", get(new_page).post(create_from_form))
        .route("/inbox", get(inbox_page))
        .route("/inbox/read", post(inbox_read))
        .route("/you", get(you_page))
        .route("/you/settings", get(settings_page).post(change_password))
        .route("/you/settings/email", post(change_email))
        .route("/you/sessions", get(sessions_page).post(sessions_action))
        .route(
            "/passkeys/register/begin",
            post(crate::passkeys::register_begin),
        )
        .route(
            "/passkeys/register/finish",
            post(crate::passkeys::register_finish),
        )
        .route("/passkeys/login/begin", post(crate::passkeys::login_begin))
        .route(
            "/passkeys/login/finish",
            post(crate::passkeys::login_finish),
        )
        .route("/you/passkeys/remove", post(crate::passkeys::remove))
        .route("/you/tokens", get(tokens_page).post(token_action))
        .route("/agents", get(agents_page).post(agent_action))
        .route("/people", get(people_page).post(people_action))
        .route("/teams", get(teams_page).post(teams_action))
        .route("/join", get(join))
        .route("/{repo}", get(repo_page))
        .route("/{repo}/tree/{*path}", get(tree_page))
        .route("/{repo}/blame/{*path}", get(blame_page))
        .route("/{repo}/changes", get(changes_page))
        .route("/{repo}/changes/{number}", get(change_page))
        .route("/{repo}/changes/{number}/verdict", post(submit_verdict))
        .route("/{repo}/changes/{number}/threads", post(submit_thread))
        .route(
            "/{repo}/changes/{number}/threads/{thread}/reply",
            post(submit_reply),
        )
        .route(
            "/{repo}/changes/{number}/threads/{thread}/resolve",
            post(submit_resolve),
        )
        .route("/{repo}/changes/{number}/claim", post(submit_claim))
        .route("/{repo}/changes/{number}/enqueue", post(submit_enqueue))
        .route("/{repo}/landing", get(landing_page))
        .route("/{repo}/log", get(log_page))
        .route("/{repo}/settings", get(repo_settings_page))
        .route("/{repo}/settings/visibility", post(repo_visibility))
        .route("/{repo}/settings/rename", post(repo_rename))
        .route("/{repo}/settings/archive", post(repo_archive))
        .route("/{repo}/settings/delete", post(repo_delete))
        .route("/{repo}/settings/transfer", post(repo_transfer))
        .route("/{repo}/transfer", get(transfer_page).post(transfer_answer))
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

static SCRIPT_HASH: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(crate::passkeys::SCRIPT.as_bytes());
    digest.iter().take(6).map(|b| format!("{b:02x}")).collect()
});

pub(crate) fn script_href() -> String {
    format!("/assets/passkeys.{}.js", *SCRIPT_HASH)
}

pub(crate) fn stylesheet_href() -> String {
    format!("/assets/app.{}.css", *STYLE_HASH)
}

/// Serve the stylesheet under its hashed name, immutable, or under its
/// bare name for anything that still asks that way, uncached.
async fn asset(Path(file): Path<String>) -> Response {
    let (body, kind, cache) = if file == format!("app.{}.css", *STYLE_HASH) {
        (
            STYLE,
            "text/css; charset=utf-8",
            "public, max-age=31536000, immutable",
        )
    } else if file == "app.css" {
        (STYLE, "text/css; charset=utf-8", "no-cache")
    } else if file == format!("passkeys.{}.js", *SCRIPT_HASH) {
        (
            crate::passkeys::SCRIPT,
            "text/javascript; charset=utf-8",
            "public, max-age=31536000, immutable",
        )
    } else {
        return not_found();
    };
    (
        [(header::CONTENT_TYPE, kind), (header::CACHE_CONTROL, cache)],
        body,
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
        return views::new_repo(theme, &viewer, Some(&humane(&err))).into_response();
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
        Err(err) => return views::new_repo(theme, &viewer, Some(&humane(&err))).into_response(),
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
    // Who, then where, then fetch: the forge connects out only for
    // somebody allowed to import here, and only to https.
    app.with_store(|s| s.check_import(who, repo))
        .map_err(|e| humane(&e))?;
    cairn_core::Store::validate_import_source(source, app.dev_identity())
        .map_err(|e| humane(&e))?;
    let git = app.git().ok_or("this forge has no git storage")?;
    let (tip, commits) = git
        .store
        .fetch_history(repo, source, branch)
        .await
        .map_err(|_| "could not fetch from that source".to_owned())?;
    let recorded = app.with_store(|store| {
        store.import_history(who, repo, branch, source, &tip, commits, app.dev_identity())
    });
    let env = match recorded {
        Ok(env) => env,
        Err(err) => {
            let _ = git.store.clear_import_ref(repo, branch).await;
            return Err(humane(&err));
        }
    };
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
    /// First sign-in, straight from an invitation.
    #[serde(default)]
    first: Option<String>,
    /// A verification mail just went out.
    #[serde(default)]
    sent: Option<String>,
    /// The id of something parked to be shown exactly once.
    #[serde(default)]
    once: Option<String>,
}

async fn settings_page(
    State(app): State<AppState>,
    Palette(theme): Palette,
    viewer: Viewer,
    Query(flash): Query<Flash>,
) -> Response {
    let contact = app
        .with_store(|s| s.contact_of(&viewer.0))
        .unwrap_or_default();
    let passkeys = app
        .with_store(|s| s.passkeys_of(&viewer.0))
        .unwrap_or_default();
    views::settings(
        theme,
        &viewer,
        &contact,
        app.mailer().is_some(),
        crate::passkeys::enabled(&app).then_some(passkeys.as_slice()),
        views::SettingsNote {
            error: flash.error.as_deref(),
            done: flash.done.is_some(),
            sent: flash.sent.is_some(),
            first: flash.first.is_some(),
        },
    )
    .into_response()
}

fn user_agent(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
}

/// Every session you hold, the one you are on marked, each one endable.
async fn sessions_page(
    State(app): State<AppState>,
    Palette(theme): Palette,
    viewer: Viewer,
    headers: HeaderMap,
    Query(flash): Query<Flash>,
) -> Response {
    let current = cookie(&headers, SESSION_COOKIE);
    match app.with_store(|s| s.sessions_of(&viewer.0, current.as_deref())) {
        Ok(sessions) => {
            views::sessions(theme, &viewer, &sessions, flash.done.is_some()).into_response()
        }
        Err(err) => oops(err),
    }
}

#[derive(Deserialize)]
struct SessionsForm {
    #[serde(default)]
    id: String,
    #[serde(default)]
    others: Option<String>,
}

async fn sessions_action(
    State(app): State<AppState>,
    viewer: Viewer,
    headers: HeaderMap,
    Form(form): Form<SessionsForm>,
) -> Response {
    let current = cookie(&headers, SESSION_COOKIE);
    let result = match (form.others.is_some(), current) {
        (true, Some(current)) => app
            .with_store(|s| s.end_other_sessions(&viewer.0, &current))
            .map(|_| ()),
        (true, None) => Ok(()),
        (false, _) => app
            .with_store(|s| s.end_browser_session_by_id(&viewer.0, form.id.trim()))
            .map(|_| ()),
    };
    match result {
        Ok(()) => Redirect::to("/you/sessions?done=1").into_response(),
        Err(err) => flash("/you/sessions", &humane(&err)),
    }
}

#[derive(Deserialize)]
struct EmailForm {
    #[serde(default)]
    email: String,
}

/// Put an address on record. It is pending until the link mailed to it
/// is followed, so the form only exists where the forge can send.
async fn change_email(
    State(app): State<AppState>,
    viewer: Viewer,
    headers: HeaderMap,
    Form(form): Form<EmailForm>,
) -> Response {
    let Some(mailer) = app.mailer() else {
        return Redirect::to(
            "/you/settings?error=This+forge+does+not+send+mail%2C+so+it+cannot+verify+an+address",
        )
        .into_response();
    };
    let email = form.email.trim().to_owned();
    // Mail with the forge's name on it, to an address of the caller's
    // choosing: three an hour is plenty for a person and useless for spam.
    let slot = jiff::Timestamp::now().as_second() / 1200;
    let allowed = app
        .with_store(|s| s.throttle(&format!("email-confirm:{}:{slot}", viewer.0), 1200))
        .unwrap_or(true);
    if !allowed {
        return Redirect::to("/you/settings?error=Try+again+in+a+little+while").into_response();
    }
    let secret = match app.with_store(|s| s.request_email(&viewer.0, &email)) {
        Ok(secret) => secret,
        Err(err) => {
            return Redirect::to(&format!("/you/settings?error={}", urlencode(&humane(&err))))
                .into_response();
        }
    };
    let link = absolute(
        &app,
        &headers,
        &format!("/verify?token={}", urlencode(&secret)),
    );
    let body = format!(
        "This address was given for {} on cairn.\n\nOpen this link within a day to confirm it; \
         it works once:\n\n  {link}\n\nIf that was not you, ignore this and nothing changes.\n",
        viewer.0.as_str()
    );
    let to = email.clone();
    let sent = tokio::task::spawn_blocking(move || {
        mailer.send(&to, "Confirm your address on cairn", &body)
    })
    .await
    .unwrap_or_else(|e| Err(e.to_string()));
    match sent {
        Ok(()) => Redirect::to("/you/settings?sent=1").into_response(),
        Err(err) => {
            tracing::error!(%err, "verification mail failed");
            Redirect::to("/you/settings?error=The+mail+could+not+be+sent%3B+try+again+in+a+moment")
                .into_response()
        }
    }
}

#[derive(Deserialize)]
struct VerifyQuery {
    #[serde(default)]
    token: String,
}

/// Follow a verification link. Whether or not anyone is signed in, the
/// address is proved by the link having been followed; the page then
/// sends them to sign in, or to settings if they already are.
async fn verify_email(
    State(app): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<VerifyQuery>,
) -> Response {
    match app.with_store(|s| s.confirm_email(query.token.trim())) {
        Ok(Some(_)) => {
            if viewer_from(&headers, &app).is_some() {
                Redirect::to("/you/settings?done=1").into_response()
            } else {
                Redirect::to("/login?done=Address+confirmed.+Sign+in.").into_response()
            }
        }
        Ok(None) => Redirect::to("/login?error=That+link+has+expired+or+been+used").into_response(),
        Err(err) => oops(err),
    }
}

/// A link back to this forge, from the request that asked for it.
fn absolute(app: &AppState, headers: &HeaderMap, path: &str) -> String {
    // The configured public URL is the only authority on where this forge
    // lives. A Host header is a caller's, and a caller who can choose the
    // host in a reset link can collect the reset. Headers serve only a
    // forge with no public URL, which is a laptop.
    if let Some(base) = app.public_url() {
        return format!("{base}{path}");
    }
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
    format!("{scheme}://{host}{path}")
}

async fn forgot_page(
    State(app): State<AppState>,
    Palette(theme): Palette,
    Query(flash): Query<Flash>,
) -> Response {
    views::forgot(
        theme,
        app.mailer().is_some(),
        flash.done.is_some(),
        flash.error.as_deref(),
    )
    .into_response()
}

#[derive(Deserialize)]
struct ForgotForm {
    #[serde(default)]
    who: String,
}

/// Ask for a way back in. With mail and an address on record, a link
/// goes out. Otherwise - no mail on this forge, or no address for this
/// person - the people who run the forge are told, in their inbox, and
/// can send a new sign-in link from the People page. Either way the
/// answer on the page is the same, so the form confirms nothing about
/// who exists.
async fn forgot_submit(
    State(app): State<AppState>,
    crate::guard::ClientIp(client): crate::guard::ClientIp,
    headers: HeaderMap,
    Form(form): Form<ForgotForm>,
) -> Response {
    if let Some(peer) = client
        && !app.reset_limiter.accept(peer)
    {
        return crate::guard::too_many_attempts();
    }
    let who = form.who.trim();
    let found = if who.contains('@') {
        app.with_store(|s| s.principal_by_email(who))
            .unwrap_or(None)
    } else {
        PrincipalId::new(who).filter(|id| {
            matches!(
                app.with_store(|s| s.principal(id)),
                Ok(Some(p)) if p.kind == cairn_core::PrincipalKind::Human
            )
        })
    };
    let Some(who) = found else {
        return Redirect::to("/forgot?done=1").into_response();
    };
    let contact = app.with_store(|s| s.contact_of(&who)).unwrap_or_default();
    let address = contact.email.filter(|_| contact.verified);
    match (app.mailer(), address) {
        (Some(mailer), Some(email)) => {
            if let Ok(secret) = app.with_store(|s| s.begin_password_reset(&who)) {
                let link = absolute(
                    &app,
                    &headers,
                    &format!("/reset?token={}", urlencode(&secret)),
                );
                let host = link
                    .split("://")
                    .nth(1)
                    .and_then(|rest| rest.split('/').next())
                    .unwrap_or("this forge")
                    .to_owned();
                let body = format!(
                    "Somebody asked to reset the password for {} on {host}.\n\n\
                     If that was you, open this link within thirty minutes; it works once:\n\n  {link}\n\n\
                     If it was not you, nothing has changed and you can ignore this.\n",
                    who.as_str()
                );
                let sent = tokio::task::spawn_blocking(move || {
                    mailer.send(&email, "Reset your cairn password", &body)
                })
                .await
                .unwrap_or_else(|e| Err(e.to_string()));
                if let Err(err) = sent {
                    tracing::error!(%err, "password reset mail failed");
                }
            }
        }
        _ => {
            // Once an hour per person: the form is anonymous, and this
            // writes to the log and pages every admin.
            let allowed = app
                .with_store(|s| s.throttle(&format!("reset-request:{who}"), 3600))
                .unwrap_or(false);
            if allowed {
                match app.with_store(|s| s.request_password_reset(&who)) {
                    Ok(env) => app.publish(&env),
                    Err(err) => tracing::warn!(%err, "could not record a reset request"),
                }
            }
        }
    }
    Redirect::to("/forgot?done=1").into_response()
}

#[derive(Deserialize)]
struct ResetQuery {
    #[serde(default)]
    token: String,
}

async fn reset_page(
    Palette(theme): Palette,
    Query(query): Query<ResetQuery>,
    Query(flash): Query<Flash>,
) -> Response {
    if query.token.trim().is_empty() {
        return Redirect::to("/forgot").into_response();
    }
    views::reset(theme, &query.token, flash.error.as_deref()).into_response()
}

#[derive(Deserialize)]
struct ResetForm {
    #[serde(default)]
    token: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    confirm: String,
}

async fn reset_submit(State(app): State<AppState>, Form(form): Form<ResetForm>) -> Response {
    let back = |error: &str| {
        Redirect::to(&format!(
            "/reset?token={}&error={}",
            urlencode(&form.token),
            urlencode(error)
        ))
        .into_response()
    };
    if form.password != form.confirm {
        return back("Those two did not match");
    }
    if let Err(err) = cairn_core::password_acceptable(&form.password) {
        return back(&humane(&err));
    }
    let who = match app.with_store(|s| s.redeem_password_reset(form.token.trim())) {
        Ok(Some(who)) => who,
        Ok(None) => {
            return Redirect::to("/forgot?error=That+link+has+expired+or+been+used")
                .into_response();
        }
        Err(err) => return oops(err),
    };
    match app.with_store(|s| s.set_password(&who, &who, &form.password)) {
        Ok(env) => {
            app.end_sessions_of(&who);
            app.publish(&env);
            Redirect::to("/login?done=Password+changed.+Sign+in.").into_response()
        }
        Err(err) => {
            // The link was spent on a password the forge refused; give
            // them a fresh one rather than a dead end.
            let _ = app.with_store(|s| s.begin_password_reset(&who));
            back(&humane(&err))
        }
    }
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
            Redirect::to("/login?done=Password+changed.+Sign+in+again.").into_response()
        }
        Err(err) => Redirect::to(&format!("/you/settings?error={}", urlencode(&humane(&err))))
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
    let once = take(&app, &viewer.0, flash.once.as_deref());
    match app.with_store(|s| s.tokens_of(&viewer.0)) {
        Ok(tokens) => views::tokens(
            theme,
            &viewer,
            &tokens,
            once.secret.as_deref(),
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
    #[serde(default)]
    days: Option<String>,
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
            // Ninety days unless asked otherwise: long enough for a
            // script to matter, short enough that a forgotten one dies.
            let until = match form.days.as_deref().unwrap_or("90") {
                "0" | "never" => None,
                d => Some(cairn_core::until_in_days(
                    d.parse::<i64>().unwrap_or(90).clamp(1, 3650),
                )),
            };
            app.with_store(|s| s.mint_token(&viewer.0, &viewer.0, label, until.as_deref()))
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
            let once = Once {
                secret: Some(secret),
                mailed: None,
            };
            match park(&app, &viewer.0, &once) {
                Some(id) => Redirect::to(&format!("/you/tokens?once={id}")).into_response(),
                None => Redirect::to("/you/tokens?error=Could+not+show+the+token").into_response(),
            }
        }
        Ok(None) => Redirect::to("/you/tokens").into_response(),
        Err(err) => {
            Redirect::to(&format!("/you/tokens?error={}", urlencode(&humane(&err)))).into_response()
        }
    }
}

/// An agent and everything it is allowed to do.
/// A team as the teams page shows it: its members and what it holds.
pub struct TeamRow {
    pub principal: cairn_core::Principal,
    pub members: Vec<PrincipalId>,
    pub grants: Vec<cairn_core::Grant>,
}

/// Teams: authority held in one place and carried by whoever is on the
/// team today. Running the forge is what this page is for.
async fn teams_page(
    State(app): State<AppState>,
    Palette(theme): Palette,
    viewer: Viewer,
    Query(flash): Query<Flash>,
) -> Response {
    if !viewer.1.admin {
        return not_found();
    }
    let data = app.with_store(|store| {
        let mut teams = Vec::new();
        for principal in store.principals()? {
            if principal.kind != cairn_core::PrincipalKind::Team {
                continue;
            }
            teams.push(TeamRow {
                members: store.members_of(&principal.id)?,
                grants: store.grants_of(&principal.id)?,
                principal,
            });
        }
        let repos: Vec<String> = store.repos()?.into_iter().map(|r| r.name).collect();
        Ok::<_, cairn_core::CoreError>((teams, repos))
    });
    match data {
        Ok((teams, repos)) => {
            views::teams(theme, &viewer, &teams, &repos, flash.error.as_deref()).into_response()
        }
        Err(err) => oops(err),
    }
}

#[derive(Deserialize)]
struct TeamForm {
    #[serde(default)]
    action: String,
    #[serde(default)]
    id: String,
    #[serde(default)]
    display: String,
    #[serde(default)]
    team: String,
    #[serde(default)]
    member: String,
    #[serde(default)]
    repo: String,
    task: Option<String>,
    push: Option<String>,
    review: Option<String>,
    merge: Option<String>,
    verify: Option<String>,
    admin: Option<String>,
}

async fn teams_action(
    State(app): State<AppState>,
    viewer: Viewer,
    Form(form): Form<TeamForm>,
) -> Response {
    if !viewer.1.admin {
        return not_found();
    }
    let back = |error: Option<String>| match error {
        Some(error) => Redirect::to(&format!("/teams?error={}", urlencode(&error))).into_response(),
        None => Redirect::to("/teams").into_response(),
    };
    let result = match form.action.as_str() {
        "create" => {
            let Some(id) = PrincipalId::new(form.id.trim()) else {
                return back(Some(format!(
                    "{} is not a valid name: lowercase letters, digits and hyphens",
                    form.id.trim()
                )));
            };
            let display = form.display.trim();
            let display = if display.is_empty() {
                id.as_str()
            } else {
                display
            };
            app.with_store(|s| {
                s.register_principal(
                    &viewer.0,
                    &id,
                    cairn_core::PrincipalKind::Team,
                    display,
                    None,
                    None,
                )
            })
        }
        "add" | "remove" => {
            let (Some(team), Some(member)) = (
                PrincipalId::new(form.team.trim()),
                PrincipalId::new(form.member.trim()),
            ) else {
                return back(Some("Say which team and who".to_owned()));
            };
            if form.action == "add" {
                app.with_store(|s| s.add_team_member(&viewer.0, &team, &member))
            } else {
                app.with_store(|s| s.remove_team_member(&viewer.0, &team, &member))
            }
        }
        "grant" => {
            let Some(team) = PrincipalId::new(form.team.trim()) else {
                return back(Some("Say which team".to_owned()));
            };
            let actions: Vec<cairn_core::Capability> = [
                (form.task.is_some(), cairn_core::Capability::Task),
                (form.push.is_some(), cairn_core::Capability::Push),
                (form.review.is_some(), cairn_core::Capability::Review),
                (form.merge.is_some(), cairn_core::Capability::Merge),
                (form.verify.is_some(), cairn_core::Capability::Verify),
                (form.admin.is_some(), cairn_core::Capability::Admin),
            ]
            .into_iter()
            .filter_map(|(ticked, capability)| ticked.then_some(capability))
            .collect();
            if actions.is_empty() {
                return back(Some("pick at least one capability".to_owned()));
            }
            let repo = form.repo.trim();
            app.with_store(|s| {
                s.issue_grant(
                    &viewer.0,
                    &team,
                    (!repo.is_empty()).then_some(repo),
                    actions,
                    None,
                )
            })
            .map(|(_, env)| env)
        }
        _ => return back(Some("Unknown action".to_owned())),
    };
    match result {
        Ok(env) => {
            app.publish(&env);
            back(None)
        }
        Err(err) => back(Some(humane(&err))),
    }
}

/// A person as the people page shows them: who they are, and whether
/// they can sign in yet.
pub struct PersonRow {
    pub principal: cairn_core::Principal,
    pub has_password: bool,
    pub contact: cairn_core::Contact,
    pub admin: bool,
    /// The open invitation, if one is out.
    pub invitation: Option<cairn_core::TokenInfo>,
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
                contact: store.contact_of(&principal.id)?,
                admin: store.is_admin(&principal.id),
                invitation: {
                    let now = jiff::Timestamp::now().to_string();
                    store.tokens_of(&principal.id)?.into_iter().rfind(|t| {
                        !t.revoked
                            && is_invitation(t)
                            && t.until.as_deref().is_none_or(|u| u > now.as_str())
                    })
                },
                principal,
            });
        }
        Ok::<_, cairn_core::CoreError>(rows)
    });
    let once = take(&app, &viewer.0, flash.once.as_deref());
    let join_link = once
        .secret
        .as_deref()
        .map(|secret| join_link(&app, &headers, secret));
    match people {
        Ok(people) => views::people(
            theme,
            &viewer,
            &people,
            app.mailer().is_some(),
            join_link.as_deref(),
            once.mailed.as_deref(),
            flash.error.as_deref(),
        )
        .into_response(),
        Err(err) => oops(err),
    }
}

#[derive(Deserialize)]
struct PersonForm {
    #[serde(default)]
    action: String,
    #[serde(default)]
    id: String,
    #[serde(default)]
    display: String,
    #[serde(default)]
    email: String,
}

/// Register a person, or make an existing one a fresh way in. Either
/// way the result is a link that signs them in once; if the forge can
/// send mail and knows where, the link goes there too, and the page
/// still shows it in case it does not arrive.
async fn people_action(
    State(app): State<AppState>,
    viewer: Viewer,
    headers: HeaderMap,
    Form(form): Form<PersonForm>,
) -> Response {
    if !viewer.1.admin {
        return not_found();
    }
    let back =
        |error: &str| Redirect::to(&format!("/people?error={}", urlencode(error))).into_response();
    let Some(id) = PrincipalId::new(form.id.trim()) else {
        return back(&format!(
            "{} is not a valid name: lowercase letters, digits and hyphens",
            form.id.trim()
        ));
    };
    let email = form.email.trim();
    match form.action.as_str() {
        "register" => {
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
                Ok(env) => app.publish(&env),
                Err(err) => return back(&humane(&err)),
            }
            if !email.is_empty()
                && let Err(err) = app.with_store(|s| s.request_email(&id, email))
            {
                return back(&humane(&err));
            }
        }
        "deactivate" | "reactivate" => {
            match app.with_store(|s| s.set_active(&viewer.0, &id, form.action == "reactivate")) {
                Ok(env) => {
                    app.publish(&env);
                    return Redirect::to("/people").into_response();
                }
                Err(err) => return back(&humane(&err)),
            }
        }
        "relink" | "cancel" => {
            match app.with_store(|s| s.principal(&id)) {
                Ok(Some(p)) if p.kind == cairn_core::PrincipalKind::Human => {}
                Ok(_) => return back(&format!("{id} is not a person here")),
                Err(err) => return oops(err),
            }
            // Only one invitation is ever live: a new link kills the old,
            // and cancelling kills it without a new one.
            let open: Vec<cairn_core::TokenInfo> = app
                .with_store(|s| s.tokens_of(&id))
                .unwrap_or_default()
                .into_iter()
                .filter(|t| !t.revoked && is_invitation(t))
                .collect();
            for token in open {
                match app.with_store(|s| s.revoke_token(&viewer.0, &token.id)) {
                    Ok(env) => app.publish(&env),
                    Err(err) => return back(&humane(&err)),
                }
            }
            if form.action == "cancel" {
                return Redirect::to("/people").into_response();
            }
        }
        _ => return back("Unknown action"),
    }
    // Mail it if we can and know where: the verified address, or the
    // pending one - an invitation followed from that inbox proves it.
    let contact = app.with_store(|s| s.contact_of(&id)).unwrap_or_default();
    let destination = contact.email.clone().or(contact.pending.clone());
    let will_mail = app.mailer().is_some() && destination.is_some();
    let label = if will_mail {
        MAILED_INVITE_LABEL
    } else {
        INVITE_LABEL
    };
    let secret = match app.with_store(|s| {
        s.mint_token(
            &viewer.0,
            &id,
            Some(label),
            Some(&cairn_core::until_in_days(INVITATION_DAYS)),
        )
    }) {
        Ok((_, secret, env)) => {
            app.publish(&env);
            secret
        }
        Err(err) => return back(&humane(&err)),
    };
    let mut mailed = None;
    if let Some(mailer) = app.mailer()
        && let Some(to) = destination
    {
        let link = join_link(&app, &headers, &secret);
        let body = format!(
            "{} has invited you to cairn.\n\nOpen this link to sign in; it works once, and \
             you will be asked to set a password:\n\n  {link}\n",
            viewer.0.as_str()
        );
        let dest = to.clone();
        let sent = tokio::task::spawn_blocking(move || {
            mailer.send(&dest, "You are invited to cairn", &body)
        })
        .await
        .unwrap_or_else(|e| Err(e.to_string()));
        match sent {
            Ok(()) => mailed = Some(to),
            Err(err) => tracing::error!(%err, "invitation mail failed"),
        }
    }
    let once = Once {
        secret: Some(secret),
        mailed,
    };
    match park(&app, &viewer.0, &once) {
        Some(id) => Redirect::to(&format!("/people?once={id}")).into_response(),
        None => Redirect::to("/people?error=Could+not+show+the+link").into_response(),
    }
}

/// The invitation is a link to this forge, so it needs to know its own
/// address; a proxy in front says so, and otherwise the cookie policy
/// already tells us whether this is https.
fn join_link(app: &AppState, headers: &HeaderMap, secret: &str) -> String {
    if let Some(base) = app.public_url() {
        return format!("{base}/join?token={}", urlencode(secret));
    }
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
}

/// The label that marks a token as an invitation rather than a credential.
const INVITE_LABEL: &str = "invitation";
/// An invitation that went out by mail: following it proves the address.
const MAILED_INVITE_LABEL: &str = "invitation:mailed";
/// How long an invitation stays open. A week is what everyone expects.
const INVITATION_DAYS: i64 = 7;

fn is_invitation(token: &cairn_core::TokenInfo) -> bool {
    token
        .label
        .as_deref()
        .is_some_and(|l| l.starts_with(INVITE_LABEL))
}

#[derive(Deserialize)]
struct JoinQuery {
    #[serde(default)]
    token: String,
}

/// Arrive from an invitation: the token becomes a browser session and is
/// spent in the same breath, so the link works once. Then straight to
/// setting a password, because a session expires and the link is gone.
async fn join(
    State(app): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<JoinQuery>,
) -> Response {
    let expired =
        || Redirect::to("/login?error=That+invitation+has+been+used+or+revoked").into_response();
    let token = match app.with_store(|s| s.token_for_secret(query.token.trim())) {
        Ok(Some(token))
            if matches!(
                token.label.as_deref(),
                Some(INVITE_LABEL | MAILED_INVITE_LABEL)
            ) =>
        {
            token
        }
        Ok(_) => return expired(),
        Err(err) => return oops(err),
    };
    // A mailed invitation, followed, proves the address it went to.
    if token.label.as_deref() == Some(MAILED_INVITE_LABEL)
        && let Ok(contact) = app.with_store(|s| s.contact_of(&token.principal))
        && let Some(pending) = contact.pending
    {
        let _ = app.with_store(|s| s.mark_email_verified(&token.principal, &pending));
    }
    // Spend it first: a session that could be minted twice from one
    // link is a link that can be forwarded.
    match app.with_store(|s| s.revoke_token(&token.principal, &token.id)) {
        Ok(env) => app.publish(&env),
        Err(err) => return oops(err),
    }
    match app.start_session(&token.principal, user_agent(&headers)) {
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
    if !viewer.1.admin {
        return not_found();
    }
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
    let once = take(&app, &viewer.0, flash.once.as_deref());
    match data {
        Ok((agents, repos)) => views::agents(
            theme,
            &viewer,
            &agents,
            &repos,
            once.secret.as_deref(),
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
    if !viewer.1.admin {
        return not_found();
    }
    let back = |error: Option<String>, secret: Option<String>| match (error, secret) {
        (Some(error), _) => {
            Redirect::to(&format!("/agents?error={}", urlencode(&error))).into_response()
        }
        (None, Some(secret)) => {
            let once = Once {
                secret: Some(secret),
                mailed: None,
            };
            match park(&app, &viewer.0, &once) {
                Some(id) => Redirect::to(&format!("/agents?once={id}")).into_response(),
                None => Redirect::to("/agents?error=Could+not+show+the+token").into_response(),
            }
        }
        _ => Redirect::to("/agents").into_response(),
    };

    match form.action.as_str() {
        "register" => {
            let Some(id) = PrincipalId::new(form.id.trim()) else {
                return back(
                    Some(format!(
                        "{} is not a valid name: lowercase letters, digits and hyphens",
                        form.id.trim()
                    )),
                    None,
                );
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
                    match app
                        .with_store(|s| s.mint_token(&viewer.0, &id, Some("created here"), None))
                    {
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
        let mut owned = Vec::new();
        let mut yours = 0;
        let mut leases = Vec::new();
        for repo in store.readable_repos(who)? {
            if repo.owner == *who {
                owned.push(repo.name.clone());
            }
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
            // Leases were gathered from readable repositories only, so a
            // session with no lease here is working somewhere the viewer
            // may not see, and is not shown.
            .filter(|session| leases.iter().any(|l| l.session == session.id))
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
            owned,
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
    let back = if form.back.starts_with('/')
        && !form.back.starts_with("//")
        && !form.back.starts_with("/\\")
    {
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
    /// Repositories the viewer owns, for the tabs that only an owner gets.
    pub owned: Vec<String>,
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
        // Only a standing token signs a browser in: a session credential
        // is scoped to one repository's work and the pages are not.
        && let Ok((principal, None)) = resolve_bearer(state, &token)
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

/// Whoever is looking, signed in or not. Never refuses: the page
/// decides what nobody may see.
pub struct Reader(pub Option<Viewer>);

impl FromRequestParts<AppState> for Reader {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        Ok(Reader(viewer_from(&parts.headers, state)))
    }
}

/// The chrome a stranger sees: the public repositories, nothing personal.
fn chrome_public(app: &AppState) -> Result<Chrome, cairn_core::CoreError> {
    app.with_store(|store| {
        let mut repos = Vec::new();
        for repo in store.repos()? {
            if repo.visibility != cairn_core::Visibility::Public {
                continue;
            }
            let open = store
                .changes_in_repo(&repo.name)?
                .iter()
                .filter(|c| c.state == cairn_core::ChangeState::Open)
                .count();
            repos.push(ChromeRepo {
                name: repo.name.clone(),
                open,
            });
        }
        Ok(Chrome {
            repos,
            working: Vec::new(),
            yours: 0,
            unread: 0,
            admin: false,
            owned: Vec::new(),
        })
    })
}

/// Who a repository page renders for, once the boundary has been checked.
pub enum Who {
    Signed(Viewer),
    Anonymous(Chrome),
}

impl Who {
    fn reading(&self) -> views::Reading<'_> {
        match self {
            Who::Signed(viewer) => views::Reading::Signed(viewer),
            Who::Anonymous(chrome) => views::Reading::Anonymous(chrome),
        }
    }
}

/// The read boundary for pages. A public repository is readable by
/// anyone; a private one by those it is theirs to see, and a stranger is
/// sent to sign in rather than told anything.
fn read_repo(app: &AppState, reader: Reader, repo: &str) -> Result<(Repo, Who), Box<Response>> {
    let record = match app.with_store(|s| s.repo(repo)) {
        Ok(record) => record,
        Err(err) => return Err(Box::new(oops(err))),
    };
    match (record, reader.0) {
        (Some(record), None) if record.visibility == cairn_core::Visibility::Public => {
            match chrome_public(app) {
                Ok(chrome) => Ok((record, Who::Anonymous(chrome))),
                Err(err) => Err(Box::new(oops(err))),
            }
        }
        (_, None) => Err(Box::new(Redirect::to("/login").into_response())),
        (_, Some(viewer)) => {
            let record = readable(app, &viewer, repo)?;
            Ok((record, Who::Signed(viewer)))
        }
    }
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
pub(crate) fn urlencode(value: &str) -> String {
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
    #[serde(default)]
    sent: Option<String>,
    #[serde(default)]
    done: Option<String>,
}

async fn login_page(
    State(app): State<AppState>,
    Palette(theme): Palette,
    Query(flash): Query<FlashQuery>,
) -> Response {
    views::login(
        theme,
        app.dev_identity(),
        app.mailer().is_some(),
        crate::passkeys::enabled(&app),
        flash.sent.is_some(),
        flash.done.as_deref(),
        flash.error.as_deref(),
    )
    .into_response()
}

#[derive(Deserialize)]
struct LinkForm {
    #[serde(default)]
    who: String,
}

/// Ask for a sign-in link. It goes only to a confirmed address, works
/// once, and the page answers the same whether or not it knows you.
async fn login_link(
    State(app): State<AppState>,
    crate::guard::ClientIp(client): crate::guard::ClientIp,
    headers: HeaderMap,
    Form(form): Form<LinkForm>,
) -> Response {
    let Some(mailer) = app.mailer() else {
        return Redirect::to("/login").into_response();
    };
    if let Some(peer) = client
        && !app.reset_limiter.accept(peer)
    {
        return crate::guard::too_many_attempts();
    }
    let who = form.who.trim();
    let found = if who.contains('@') {
        app.with_store(|s| s.principal_by_email(who))
            .unwrap_or(None)
    } else {
        PrincipalId::new(who).filter(|id| {
            matches!(
                app.with_store(|s| s.principal(id)),
                Ok(Some(p)) if p.kind == cairn_core::PrincipalKind::Human
            )
        })
    };
    if let Some(who) = found {
        let contact = app.with_store(|s| s.contact_of(&who)).unwrap_or_default();
        if let Some(email) = contact.email.filter(|_| contact.verified)
            && let Ok(secret) = app.with_store(|s| s.begin_signin_link(&who))
        {
            let link = absolute(
                &app,
                &headers,
                &format!("/signin?token={}", urlencode(&secret)),
            );
            let body = format!(
                "Here is your sign-in link for {} on cairn. It works once, for fifteen \
                 minutes:\n\n  {link}\n\nIf you did not ask for it, ignore this; nothing changes.\n",
                who.as_str()
            );
            let sent = tokio::task::spawn_blocking(move || {
                mailer.send(&email, "Your cairn sign-in link", &body)
            })
            .await
            .unwrap_or_else(|e| Err(e.to_string()));
            if let Err(err) = sent {
                tracing::error!(%err, "sign-in link mail failed");
            }
        }
    }
    Redirect::to("/login?sent=1").into_response()
}

#[derive(Deserialize)]
struct SigninQuery {
    #[serde(default)]
    token: String,
}

async fn signin_with_link(
    State(app): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SigninQuery>,
) -> Response {
    match app.with_store(|s| s.redeem_signin_link(query.token.trim())) {
        Ok(Some(who)) => match app.start_session(&who, user_agent(&headers)) {
            Ok(session) => signed_in(&app, SESSION_COOKIE, &session),
            Err(err) => oops(err),
        },
        Ok(None) => Redirect::to("/login?error=That+link+has+expired+or+been+used").into_response(),
        Err(err) => oops(err),
    }
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
    headers: HeaderMap,
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
        let (hash, real) = app.with_store(|s| s.password_hash_for_check(&principal));
        let matches = tokio::task::spawn_blocking(move || {
            cairn_core::verify_password(&password, &hash) && real
        })
        .await
        .unwrap_or(false);
        return if matches {
            match app.start_session(&principal, user_agent(&headers)) {
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

pub(crate) fn oops(err: impl std::fmt::Display) -> Response {
    tracing::error!(error = %err, "web: page render failed");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        [(FALLBACK, "error")],
        views::error_page(views::Theme::Dark),
    )
        .into_response()
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

/// What a page shows exactly once, carried across the redirect by id.
#[derive(serde::Serialize, serde::Deserialize, Default)]
struct Once {
    secret: Option<String>,
    mailed: Option<String>,
}

fn park(app: &AppState, who: &PrincipalId, once: &Once) -> Option<String> {
    let payload = serde_json::to_string(once).ok()?;
    app.with_store(|s| s.put_flash(who, &payload)).ok()
}

fn take(app: &AppState, who: &PrincipalId, id: Option<&str>) -> Once {
    let Some(id) = id else { return Once::default() };
    app.with_store(|s| s.take_flash(who, id))
        .ok()
        .flatten()
        .and_then(|p| serde_json::from_str(&p).ok())
        .unwrap_or_default()
}

/// An error as a page should say it: the message, without the kind the
/// API prefixes it with. "invalid: that does not look like an email
/// address" is for a machine; a person gets the second half.
pub(crate) fn humane(err: &cairn_core::CoreError) -> String {
    let text = err.to_string();
    match text.split_once(": ") {
        Some((kind, rest)) if !kind.contains(' ') => rest.to_owned(),
        _ => text,
    }
}

/// Rendered before the theme is known; `themed_fallbacks` re-renders it
/// with the viewer's theme on the way out.
fn not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        [(FALLBACK, "not-found")],
        views::not_found_page(views::Theme::Dark),
    )
        .into_response()
}

const FALLBACK: &str = "x-cairn-fallback";

/// 404 and 500 pages are produced deep inside handlers that never saw
/// the theme cookie. This runs after them: a marked fallback is rendered
/// again in the theme the request asked for, and the marker is removed.
pub(crate) async fn themed_fallbacks(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let theme = match cookie(request.headers(), THEME_COOKIE).as_deref() {
        Some("light") => views::Theme::Light,
        _ => views::Theme::Dark,
    };
    let mut response = next.run(request).await;
    let Some(kind) = response
        .headers()
        .get(FALLBACK)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
    else {
        return response;
    };
    response.headers_mut().remove(FALLBACK);
    let status = response.status();
    let page = match kind.as_str() {
        "not-found" => views::not_found_page(theme),
        _ => views::error_page(theme),
    };
    let mut fresh = (status, page).into_response();
    for (name, value) in response.headers() {
        fresh.headers_mut().insert(name, value.clone());
    }
    fresh
}

async fn repo_page(
    State(app): State<AppState>,
    Palette(theme): Palette,
    reader: Reader,
    Path(repo): Path<String>,
) -> Response {
    render_tree(app, theme, reader, repo, String::new()).await
}

async fn tree_page(
    State(app): State<AppState>,
    Palette(theme): Palette,
    reader: Reader,
    Path((repo, path)): Path<(String, String)>,
) -> Response {
    render_tree(app, theme, reader, repo, path).await
}

async fn render_tree(
    app: AppState,
    theme: views::Theme,
    reader: Reader,
    repo: String,
    path: String,
) -> Response {
    // The clone URL is a real address only when the forge knows its own.
    let clone_url = app
        .public_url()
        .map(|base| format!("{base}/git/{repo}"))
        .unwrap_or_else(|| format!("/git/{repo}"));
    let Some(git) = app.git() else {
        return not_found();
    };
    let (record, who) = match read_repo(&app, reader, &repo) {
        Ok(found) => found,
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
                    return views::file(
                        theme,
                        who.reading(),
                        &repo,
                        &path,
                        &text,
                        landed_by.as_ref(),
                    )
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
        who.reading(),
        &repo,
        &branch,
        tip.as_deref(),
        &path,
        &entries,
        readme.as_deref(),
        &sidebar,
        &clone_url,
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
        sessions: app.with_store(|s| s.active_sessions_in(repo))?,
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
    reader: Reader,
    Path((repo, path)): Path<(String, String)>,
) -> Response {
    let Some(git) = app.git() else {
        return not_found();
    };
    let (record, who) = match read_repo(&app, reader, &repo) {
        Ok(found) => found,
        Err(response) => return *response,
    };
    let rev = format!("refs/heads/{}", record.default_branch);
    let text = match git.store.show_file(&repo, &rev, &path).await {
        // Blame walks history for every line; a file this size would
        // hold the process for longer than anyone is waiting.
        Ok(Some(bytes)) if bytes.len() as u64 > MAX_RENDERED_BLOB => {
            return (
                StatusCode::OK,
                views::plain_note(
                    theme,
                    &format!(
                        "{} is {} - too large to blame here.",
                        path,
                        human_bytes(bytes.len() as u64)
                    ),
                ),
            )
                .into_response();
        }
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
    views::blame(theme, who.reading(), &repo, &path, &rows).into_response()
}

async fn changes_page(
    State(app): State<AppState>,
    Palette(theme): Palette,
    reader: Reader,
    Path(repo): Path<String>,
) -> Response {
    let who = match read_repo(&app, reader, &repo) {
        Ok((_, who)) => who,
        Err(response) => return *response,
    };
    match app.with_store(|s| s.changes_in_repo(&repo)) {
        Ok(mut changes) => {
            changes.reverse();
            views::changes(theme, who.reading(), &repo, &changes).into_response()
        }
        Err(err) => oops(err),
    }
}

#[derive(Deserialize)]
struct ChangeQuery {
    r: Option<i64>,
    error: Option<String>,
    /// Where a new thread is being composed: `new:12:src/x.rs`,
    /// `claim:<id>`, `verdict:<id>`, or `change`.
    at: Option<String>,
}

async fn change_page(
    State(app): State<AppState>,
    Palette(theme): Palette,
    reader: Reader,
    Path((repo, number)): Path<(String, i64)>,
    Query(query): Query<ChangeQuery>,
) -> Response {
    let who = match read_repo(&app, reader, &repo) {
        Ok((_, who)) => who,
        Err(response) => return *response,
    };
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
    let threads = match app.with_store(|s| s.threads_on(&change.id)) {
        Ok(threads) => threads,
        Err(err) => return oops(err),
    };
    let composer = query.at.as_deref().and_then(views::ThreadAt::parse);

    views::change(views::ChangePage {
        theme,
        who: who.reading(),
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
        threads: &threads,
        composer,
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
        Err(err) => flash(&back, &humane(&err)),
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
        Err(err) => flash(&back, &humane(&err)),
    }
}

#[derive(Deserialize)]
struct ThreadForm {
    revision: i64,
    kind: String,
    body: String,
    /// `change`, `line`, `claim` or `verdict`; the matching fields follow.
    on: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    side: String,
    #[serde(default)]
    line: Option<i64>,
    #[serde(default)]
    claim: String,
    #[serde(default)]
    verdict: String,
}

async fn submit_thread(
    State(app): State<AppState>,
    viewer: Viewer,
    Path((repo, number)): Path<(String, i64)>,
    Form(form): Form<ThreadForm>,
) -> Response {
    let back = format!("/{repo}/changes/{number}");
    let Some(kind) = cairn_core::ThreadKind::parse(&form.kind) else {
        return flash(&back, "Pick a kind");
    };
    let anchor = match form.on.as_str() {
        "change" => cairn_core::Anchor::Change,
        "line" => {
            let Some(side) = cairn_core::Side::parse(&form.side) else {
                return flash(&back, "Pick a side of the diff");
            };
            let Some(line) = form.line else {
                return flash(&back, "Pick a line");
            };
            cairn_core::Anchor::Line {
                path: form.path.trim().to_owned(),
                side,
                line,
            }
        }
        "claim" => cairn_core::Anchor::Claim {
            claim: cairn_core::ClaimId(form.claim.trim().to_owned()),
        },
        "verdict" => cairn_core::Anchor::Verdict {
            verdict: cairn_core::VerdictId(form.verdict.trim().to_owned()),
        },
        _ => return flash(&back, "Say what the thread is about"),
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
        s.open_thread(
            &viewer.0,
            &change,
            Some(form.revision),
            anchor,
            kind,
            form.body.trim(),
        )
    }) {
        Ok((thread, env)) => {
            app.publish(&env);
            let revision = match &env.event {
                cairn_core::Event::ThreadOpened { revision, .. } => *revision,
                _ => form.revision,
            };
            Redirect::to(&format!("{back}?r={revision}#{}", thread.as_str())).into_response()
        }
        Err(err) => flash(&back, &humane(&err)),
    }
}

#[derive(Deserialize)]
struct ReplyForm {
    revision: i64,
    body: String,
}

async fn submit_reply(
    State(app): State<AppState>,
    viewer: Viewer,
    Path((repo, number, thread)): Path<(String, i64, String)>,
    Form(form): Form<ReplyForm>,
) -> Response {
    let back = format!("/{repo}/changes/{number}");
    if let Err(response) = readable(&app, &viewer, &repo) {
        return *response;
    }
    let id = cairn_core::ThreadId(thread);
    match app.with_store(|s| s.reply_thread(&viewer.0, &id, form.body.trim())) {
        Ok(env) => {
            app.publish(&env);
            Redirect::to(&format!("{back}?r={}#{}", form.revision, id.as_str())).into_response()
        }
        Err(err) => flash(&back, &humane(&err)),
    }
}

#[derive(Deserialize)]
struct ResolveForm {
    revision: i64,
    /// `answered`, `fixed:<revision>`, `withdrawn` or `overruled`.
    how: String,
    #[serde(default)]
    note: String,
}

async fn submit_resolve(
    State(app): State<AppState>,
    viewer: Viewer,
    Path((repo, number, thread)): Path<(String, i64, String)>,
    Form(form): Form<ResolveForm>,
) -> Response {
    let back = format!("/{repo}/changes/{number}");
    if let Err(response) = readable(&app, &viewer, &repo) {
        return *response;
    }
    let (how, fixed) = match form.how.split_once(':') {
        Some(("fixed", revision)) => (
            cairn_core::Resolution::Fixed,
            revision.trim().parse::<i64>().ok(),
        ),
        _ => match cairn_core::Resolution::parse(&form.how) {
            Some(how) => (how, None),
            None => return flash(&back, "Say how it was resolved"),
        },
    };
    let id = cairn_core::ThreadId(thread);
    match app.with_store(|s| s.resolve_thread(&viewer.0, &id, how, fixed, form.note.trim())) {
        Ok(env) => {
            app.publish(&env);
            Redirect::to(&format!("{back}?r={}#{}", form.revision, id.as_str())).into_response()
        }
        Err(err) => flash(&back, &humane(&err)),
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
        Err(err) => flash(&back, &humane(&err)),
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
    reader: Reader,
    Path(repo): Path<String>,
) -> Response {
    let (record, who) = match read_repo(&app, reader, &repo) {
        Ok(found) => found,
        Err(response) => return *response,
    };
    let data = match landing_data(&app, &repo, &record.default_branch) {
        Ok(data) => data,
        Err(err) => return oops(err),
    };
    views::landing(theme, who.reading(), &repo, &record.default_branch, &data).into_response()
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
    let events = app.with_store(|s| {
        s.events_for_repo(repo, cairn_core::EventSeq((latest - 200).max(0)), 220)
    })?;
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
        sessions: app.with_store(|s| s.active_sessions_in(repo))?,
        numbers,
    })
}

#[derive(Deserialize)]
struct LessonQuery {
    q: Option<String>,
}

async fn lessons_page(
    State(app): State<AppState>,
    Palette(theme): Palette,
    reader: Reader,
    Path(repo): Path<String>,
    Query(query): Query<LessonQuery>,
) -> Response {
    let who = match read_repo(&app, reader, &repo) {
        Ok((_, who)) => who,
        Err(response) => return *response,
    };
    let search = query.q.as_deref().filter(|q| !q.trim().is_empty());
    match app.with_store(|s| s.lessons(Some(&repo), search, false, 100)) {
        Ok(lessons) => {
            views::lessons(theme, who.reading(), &repo, search, &lessons).into_response()
        }
        Err(err) => oops(err),
    }
}

#[derive(Deserialize)]
struct LogQuery {
    after: Option<i64>,
}

/// A repository's settings: who may see it, and who owns it. For
/// anybody who is neither its owner nor running the forge, the page
/// does not exist - the same answer a private repository gives.
async fn repo_settings_page(
    State(app): State<AppState>,
    Palette(theme): Palette,
    viewer: Viewer,
    Path(repo): Path<String>,
    Query(flash): Query<Flash>,
) -> Response {
    let record = match readable(&app, &viewer, &repo) {
        Ok(record) => record,
        Err(response) => return *response,
    };
    if record.owner != viewer.0 && !viewer.1.admin {
        return not_found();
    }
    views::repo_settings(
        theme,
        &viewer,
        &record,
        flash.error.as_deref(),
        flash.done.is_some(),
    )
    .into_response()
}

#[derive(Deserialize)]
struct VisibilityForm {
    #[serde(default)]
    visibility: String,
}

async fn repo_visibility(
    State(app): State<AppState>,
    viewer: Viewer,
    Path(repo): Path<String>,
    Form(form): Form<VisibilityForm>,
) -> Response {
    let back = format!("/{repo}/settings");
    let Some(visibility) = cairn_core::Visibility::parse(&form.visibility) else {
        return flash(&back, "Pick a visibility");
    };
    match app.with_store(|s| s.set_visibility(&viewer.0, &repo, visibility)) {
        Ok(env) => {
            app.publish(&env);
            Redirect::to(&format!("{back}?done=1")).into_response()
        }
        Err(cairn_core::CoreError::NotFound(_)) => not_found(),
        Err(err) => flash(&back, &humane(&err)),
    }
}

#[derive(Deserialize)]
struct TransferForm {
    #[serde(default)]
    action: String,
    #[serde(default)]
    to: String,
}

#[derive(Deserialize)]
struct RenameForm {
    to: String,
}

async fn repo_rename(
    State(app): State<AppState>,
    viewer: Viewer,
    Path(repo): Path<String>,
    Form(form): Form<RenameForm>,
) -> Response {
    let back = format!("/{repo}/settings");
    let to = form.to.trim().to_owned();
    if let Err(err) = app.with_store(|s| s.check_rename(&viewer.0, &repo, &to)) {
        return flash(&back, &humane(&err));
    }
    if let Some(git) = app.git()
        && let Err(err) = git.store.rename_repo(&repo, &to).await
    {
        return flash(&back, &err.to_string());
    }
    match app.with_store(|s| s.rename_repo(&viewer.0, &repo, &to)) {
        Ok(env) => {
            app.publish(&env);
            Redirect::to(&format!("/{to}/settings?done=1")).into_response()
        }
        Err(err) => {
            if let Some(git) = app.git() {
                let _ = git.store.rename_repo(&to, &repo).await;
            }
            flash(&back, &humane(&err))
        }
    }
}

#[derive(Deserialize)]
struct ArchiveForm {
    archived: String,
}

async fn repo_archive(
    State(app): State<AppState>,
    viewer: Viewer,
    Path(repo): Path<String>,
    Form(form): Form<ArchiveForm>,
) -> Response {
    let back = format!("/{repo}/settings");
    match app.with_store(|s| s.set_archived(&viewer.0, &repo, form.archived == "yes")) {
        Ok(env) => {
            app.publish(&env);
            Redirect::to(&format!("{back}?done=1")).into_response()
        }
        Err(err) => flash(&back, &humane(&err)),
    }
}

#[derive(Deserialize)]
struct DeleteForm {
    confirm: String,
}

async fn repo_delete(
    State(app): State<AppState>,
    viewer: Viewer,
    Path(repo): Path<String>,
    Form(form): Form<DeleteForm>,
) -> Response {
    let back = format!("/{repo}/settings");
    match app.with_store(|s| s.delete_repo(&viewer.0, &repo, &form.confirm)) {
        Ok(env) => {
            if let Some(git) = app.git() {
                let _ = git.store.remove_repo(&repo).await;
            }
            app.publish(&env);
            Redirect::to("/").into_response()
        }
        Err(err) => flash(&back, &humane(&err)),
    }
}

async fn repo_transfer(
    State(app): State<AppState>,
    viewer: Viewer,
    Path(repo): Path<String>,
    Form(form): Form<TransferForm>,
) -> Response {
    let back = format!("/{repo}/settings");
    let result = match form.action.as_str() {
        "offer" => match PrincipalId::new(form.to.trim()) {
            Some(to) => app.with_store(|s| s.offer_transfer(&viewer.0, &repo, &to)),
            None => return flash(&back, "Say who, by their name"),
        },
        "withdraw" => app.with_store(|s| s.decline_transfer(&viewer.0, &repo)),
        _ => return flash(&back, "Unknown action"),
    };
    match result {
        Ok(env) => {
            app.publish(&env);
            Redirect::to(&format!("{back}?done=1")).into_response()
        }
        Err(cairn_core::CoreError::NotFound(_)) => not_found(),
        Err(err) => flash(&back, &humane(&err)),
    }
}

/// The offer as the person it was made to sees it. They may not be able
/// to read the repository yet - that is rather the point - so this page
/// is gated on the offer itself, not on readability.
async fn transfer_page(
    State(app): State<AppState>,
    Palette(theme): Palette,
    viewer: Viewer,
    Path(repo): Path<String>,
    Query(flash): Query<Flash>,
) -> Response {
    let record = match app.with_store(|s| s.repo(&repo)) {
        Ok(Some(record)) if record.pending_owner.as_ref() == Some(&viewer.0) => record,
        Ok(_) => return not_found(),
        Err(err) => return oops(err),
    };
    views::transfer_offer(theme, &viewer, &record, flash.error.as_deref()).into_response()
}

#[derive(Deserialize)]
struct AnswerForm {
    #[serde(default)]
    action: String,
}

async fn transfer_answer(
    State(app): State<AppState>,
    viewer: Viewer,
    Path(repo): Path<String>,
    Form(form): Form<AnswerForm>,
) -> Response {
    let result = match form.action.as_str() {
        "accept" => app.with_store(|s| s.accept_transfer(&viewer.0, &repo)),
        "decline" => app.with_store(|s| s.decline_transfer(&viewer.0, &repo)),
        _ => return flash(&format!("/{repo}/transfer"), "Unknown action"),
    };
    match result {
        Ok(env) => {
            app.publish(&env);
            let to = if form.action == "accept" {
                format!("/{repo}")
            } else {
                "/inbox".to_owned()
            };
            Redirect::to(&to).into_response()
        }
        Err(cairn_core::CoreError::NotFound(_)) => not_found(),
        Err(err) => flash(&format!("/{repo}/transfer"), &humane(&err)),
    }
}

async fn log_page(
    State(app): State<AppState>,
    Palette(theme): Palette,
    reader: Reader,
    Path(repo): Path<String>,
    Query(query): Query<LogQuery>,
) -> Response {
    let who = match read_repo(&app, reader, &repo) {
        Ok((_, who)) => who,
        Err(response) => return *response,
    };
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
        Ok(events) => {
            views::log(theme, who.reading(), &repo, &numbers, after, &events).into_response()
        }
        Err(err) => oops(err),
    }
}
