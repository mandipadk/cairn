//! Route handlers: a one-to-one mapping onto the core protocol verbs.
//!
//! Every mutation responds with the event envelope it committed (plus
//! the id of anything created), so callers always hold a valid cursor.
//! Reads return projections. Nothing here contains domain logic — that
//! all lives in the core, where it is tested.

use crate::auth::Actor;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use cairn_core::{
    Capability, Change, ChangeId, ChangeSpec, ChangeState, ClaimId, ClaimSpec, CoreError,
    Disposition, Envelope, EventSeq, GrantId, ObjectFormat, PrincipalId, PrincipalKind, Repo,
    ReviewDomain, SessionId, SessionState, Task, TaskId, TaskState, TokenId,
};
use serde::Deserialize;
use serde_json::{Value, json};

pub(crate) fn committed(id: Option<String>, envelope: &Envelope) -> Json<Value> {
    let mut body = json!({ "seq": envelope.seq.0, "event": envelope });
    if let Some(id) = id {
        body["id"] = json!(id);
    }
    Json(body)
}

fn found<T>(item: Option<T>, what: &str) -> ApiResult<T> {
    item.ok_or_else(|| {
        ApiError::new(
            StatusCode::NOT_FOUND,
            "not_found",
            format!("{what} not found"),
        )
    })
}

/// A repository the caller may read, or "not found". Reads on the API
/// are gated exactly as the git transport is: a private repository
/// answers a stranger the way a missing one does, so the API gives away
/// neither its contents nor its existence. Everything scoped to a
/// repository - a change, a task, a session, a queue - goes through here.
fn readable_repo(app: &AppState, actor: &Actor, name: &str) -> ApiResult<Repo> {
    found(app.with_store(|s| s.readable(&actor.0, name))?, "repo")
}

fn readable_change(app: &AppState, actor: &Actor, id: &ChangeId) -> ApiResult<Change> {
    let change = found(app.with_store(|s| s.change(id))?, "change")?;
    readable_repo(app, actor, &change.repo)?;
    Ok(change)
}

fn readable_task(app: &AppState, actor: &Actor, id: &TaskId) -> ApiResult<Task> {
    let task = found(app.with_store(|s| s.task(id))?, "task")?;
    if let Some(repo) = &task.repo {
        readable_repo(app, actor, repo)?;
    }
    Ok(task)
}

// ---- principals ----

#[derive(Deserialize)]
pub struct RegisterPrincipal {
    pub id: String,
    pub kind: PrincipalKind,
    pub display: String,
    pub model: Option<String>,
    pub harness: Option<String>,
}

pub async fn register_principal(
    State(app): State<AppState>,
    actor: Actor,
    Json(body): Json<RegisterPrincipal>,
) -> ApiResult<Json<Value>> {
    let id = PrincipalId::new(&body.id).ok_or_else(|| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid",
            format!("{:?} is not a valid slug", body.id),
        )
    })?;
    let env = app.with_store(|s| {
        s.register_principal(
            &actor.0,
            &id,
            body.kind,
            &body.display,
            body.model.as_deref(),
            body.harness.as_deref(),
        )
    })?;
    app.publish(&env);
    Ok(committed(Some(id.0), &env))
}

#[derive(Deserialize)]
pub struct SetPassword {
    pub password: String,
}

/// Set a password: your own, or anyone's if you are an admin.
///
/// Every existing session of that principal ends, because a password
/// change that leaves old sessions alive has not locked anybody out —
/// which is usually the entire reason for changing it.
pub async fn set_password(
    State(app): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
    Json(body): Json<SetPassword>,
) -> ApiResult<Json<Value>> {
    let principal = PrincipalId(id);
    let env = app.with_store(|s| s.set_password(&actor.0, &principal, &body.password))?;
    app.end_sessions_of(&principal);
    app.publish(&env);
    Ok(committed(Some(principal.0), &env))
}

pub async fn get_principal(
    State(app): State<AppState>,
    _actor: Actor,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let principal = app.with_store(|s| s.principal(&PrincipalId(id)))?;
    Ok(Json(json!(found(principal, "principal")?)))
}

// ---- repos ----

#[derive(Deserialize)]
pub struct CreateRepo {
    pub name: String,
    #[serde(default = "default_branch")]
    pub default_branch: String,
    #[serde(default)]
    pub object_format: ObjectFormat,
}

fn default_branch() -> String {
    "main".to_owned()
}

pub async fn create_repo(
    State(app): State<AppState>,
    actor: Actor,
    Json(body): Json<CreateRepo>,
) -> ApiResult<Json<Value>> {
    // Ask before doing anything outside the store. Creating the bare
    // repo first used to mean a caller who turned out to hold no admin
    // capability, or who named a repository something disallowed, still
    // left a directory behind — a side effect ahead of the check that
    // should have prevented it. create_repo applies these same rules
    // again when it appends the event.
    app.with_store(|s| s.check_new_repo(&actor.0, &body.name, &body.default_branch))?;
    // Then the bare repo lands on disk before the graph event. An orphan
    // directory from a lost race is harmless — nothing serves a
    // repository the graph does not know about — whereas the reverse
    // would leave a repository that exists but cannot be cloned.
    if let Some(git) = app.git() {
        git.store
            .create_repo(
                &body.name,
                &body.default_branch,
                body.object_format.as_str(),
            )
            .await?;
    }
    let env = app.with_store(|s| {
        s.create_repo(
            &actor.0,
            &body.name,
            &body.default_branch,
            body.object_format,
        )
    })?;
    app.publish(&env);
    Ok(committed(Some(body.name), &env))
}

#[derive(Deserialize)]
pub struct ImportHistory {
    /// Where to fetch from. Credentials belong in --mirror-token, not here.
    pub source: String,
    #[serde(default = "default_branch")]
    pub branch: String,
}

/// Seed a branch with history that already existed somewhere else.
///
/// Every other route that moves a branch does so because a policy said
/// yes. This one cannot: the commits predate the forge. So it refuses to
/// pretend — the import is recorded as its own kind of event, and the
/// compare-and-swap against the zero-oid means it can only ever create a
/// branch, never overwrite one the log has already vouched for.
pub async fn import_history(
    State(app): State<AppState>,
    actor: Actor,
    Path(name): Path<String>,
    Json(body): Json<ImportHistory>,
) -> ApiResult<Json<Value>> {
    let git = app.git().ok_or_else(|| {
        ApiError::new(
            StatusCode::CONFLICT,
            "unavailable",
            "this forge is running without git storage",
        )
    })?;
    // Before dialling out: the url is a caller's, and this forge does
    // not connect anywhere on nothing but a caller's say-so.
    cairn_core::Store::validate_import_source(&body.source)?;
    let (tip, commits) = git
        .store
        .fetch_history(&name, &body.source, &body.branch)
        .await?;
    // Record before publishing the ref: if this fails, the branch stays
    // absent and the import can be retried, which is the harmless order.
    let env = app.with_store(|s| {
        s.import_history(&actor.0, &name, &body.branch, &body.source, &tip, commits)
    })?;
    git.store
        .advance_ref(&name, &body.branch, &tip, None)
        .await?;
    let _ = git.store.clear_import_ref(&name, &body.branch).await;
    app.publish(&env);
    Ok(committed(Some(name), &env))
}

#[derive(Deserialize)]
pub struct SetVisibility {
    pub visibility: cairn_core::Visibility,
}

pub async fn set_visibility(
    State(app): State<AppState>,
    actor: Actor,
    Path(name): Path<String>,
    Json(body): Json<SetVisibility>,
) -> ApiResult<Json<Value>> {
    let env = app.with_store(|s| s.set_visibility(&actor.0, &name, body.visibility))?;
    app.publish(&env);
    Ok(committed(Some(name), &env))
}

pub async fn get_repo(
    State(app): State<AppState>,
    actor: Actor,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    Ok(Json(json!(readable_repo(&app, &actor, &name)?)))
}

// ---- tasks ----

#[derive(Deserialize)]
pub struct CreateTask {
    pub repo: Option<String>,
    pub title: String,
    pub spec: String,
    pub parent: Option<TaskId>,
}

pub async fn create_task(
    State(app): State<AppState>,
    actor: Actor,
    Json(body): Json<CreateTask>,
) -> ApiResult<Json<Value>> {
    let (task, env) = app.with_store(|s| {
        s.create_task(
            &actor.0,
            body.repo.as_deref(),
            &body.title,
            &body.spec,
            body.parent.as_ref(),
        )
    })?;
    app.publish(&env);
    Ok(committed(Some(task.0), &env))
}

#[derive(Deserialize)]
pub struct TaskFilter {
    pub state: Option<TaskState>,
}

pub async fn list_tasks(
    State(app): State<AppState>,
    actor: Actor,
    Query(filter): Query<TaskFilter>,
) -> ApiResult<Json<Value>> {
    let mut tasks = app.with_store(|s| s.tasks(filter.state))?;
    // A task with no repository is forge-wide work and everybody's.
    tasks.retain(|task| {
        task.repo
            .as_deref()
            .is_none_or(|repo| app.with_store(|s| s.may_read(&actor.0, repo)))
    });
    Ok(Json(json!(tasks)))
}

pub async fn get_task(
    State(app): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    Ok(Json(json!(readable_task(&app, &actor, &TaskId(id))?)))
}

pub async fn claim_task(
    State(app): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let env = app.with_store(|s| s.claim_task(&actor.0, &TaskId(id)))?;
    app.publish(&env);
    Ok(committed(None, &env))
}

#[derive(Deserialize)]
pub struct SetTaskState {
    pub state: TaskState,
}

pub async fn set_task_state(
    State(app): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
    Json(body): Json<SetTaskState>,
) -> ApiResult<Json<Value>> {
    let env = app.with_store(|s| s.set_task_state(&actor.0, &TaskId(id), body.state))?;
    app.publish(&env);
    Ok(committed(None, &env))
}

// ---- sessions ----

pub async fn open_session(
    State(app): State<AppState>,
    actor: Actor,
    Path(task): Path<String>,
) -> ApiResult<Json<Value>> {
    let (session, env) = app.with_store(|s| s.open_session(&actor.0, &TaskId(task)))?;
    app.publish(&env);
    Ok(committed(Some(session.0), &env))
}

pub async fn get_session(
    State(app): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let session = found(app.with_store(|s| s.session(&SessionId(id)))?, "session")?;
    readable_task(&app, &actor, &session.task)?;
    Ok(Json(json!(session)))
}

#[derive(Deserialize)]
pub struct EndSession {
    pub state: SessionState,
    pub outcome: String,
}

pub async fn end_session(
    State(app): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
    Json(body): Json<EndSession>,
) -> ApiResult<Json<Value>> {
    let env =
        app.with_store(|s| s.end_session(&actor.0, &SessionId(id), body.state, &body.outcome))?;
    app.publish(&env);
    Ok(committed(None, &env))
}

// ---- changes ----

pub async fn open_change(
    State(app): State<AppState>,
    actor: Actor,
    Json(body): Json<ChangeSpec>,
) -> ApiResult<Json<Value>> {
    let (change, number, env) = app.with_store(|s| s.open_change(&actor.0, body))?;
    app.publish(&env);
    let mut response = committed(Some(change.0), &env);
    response.0["number"] = json!(number);
    Ok(response)
}

pub async fn get_change(
    State(app): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    Ok(Json(json!(readable_change(&app, &actor, &ChangeId(id))?)))
}

pub async fn get_change_by_number(
    State(app): State<AppState>,
    actor: Actor,
    Path((repo, number)): Path<(String, i64)>,
) -> ApiResult<Json<Value>> {
    readable_repo(&app, &actor, &repo)?;
    let change = app.with_store(|s| s.change_by_number(&repo, number))?;
    Ok(Json(json!(found(change, "change")?)))
}

#[derive(Deserialize)]
pub struct ChangesQuery {
    pub state: Option<ChangeState>,
}

pub async fn list_changes(
    State(app): State<AppState>,
    actor: Actor,
    Path(repo): Path<String>,
    Query(query): Query<ChangesQuery>,
) -> ApiResult<Json<Value>> {
    readable_repo(&app, &actor, &repo)?;
    let mut changes = app.with_store(|s| s.changes_in_repo(&repo))?;
    if let Some(state) = query.state {
        changes.retain(|change| change.state == state);
    }
    Ok(Json(json!(changes)))
}

#[derive(Deserialize)]
pub struct PushRevision {
    pub commit_oid: String,
    pub session: Option<SessionId>,
    #[serde(default)]
    pub message: String,
}

pub async fn push_revision(
    State(app): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
    Json(body): Json<PushRevision>,
) -> ApiResult<Json<Value>> {
    let change = ChangeId(id);
    let (revision, env) = app.with_store(|s| {
        s.push_revision(
            &actor.0,
            &change,
            &body.commit_oid,
            body.session.as_ref(),
            &body.message,
        )
    })?;
    app.publish(&env);
    let mut response = committed(None, &env);
    response.0["revision"] = json!(revision);
    Ok(response)
}

pub async fn list_revisions(
    State(app): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    readable_change(&app, &actor, &ChangeId(id.clone()))?;
    let revisions = app.with_store(|s| s.revisions(&ChangeId(id)))?;
    Ok(Json(json!(revisions)))
}

#[derive(Deserialize)]
pub struct RevisionQuery {
    pub revision: Option<i64>,
}

/// Resolve an optional `?revision=` to a concrete revision number,
/// defaulting to the change's latest.
fn resolve_revision(app: &AppState, change: &ChangeId, query: Option<i64>) -> ApiResult<i64> {
    match query {
        Some(revision) => Ok(revision),
        None => {
            let current = app.with_store(|s| s.change(change))?;
            Ok(found(current, "change")?.latest_revision)
        }
    }
}

#[derive(Deserialize)]
pub struct AttachClaim {
    pub revision: Option<i64>,
    #[serde(flatten)]
    pub spec: ClaimSpec,
}

pub async fn attach_claim(
    State(app): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
    Json(body): Json<AttachClaim>,
) -> ApiResult<Json<Value>> {
    let change = ChangeId(id);
    let revision = resolve_revision(&app, &change, body.revision)?;
    let (claim, env) =
        app.with_store(|s| s.attach_claim(&actor.0, &change, revision, body.spec))?;
    app.publish(&env);
    Ok(committed(Some(claim.0), &env))
}

pub async fn list_claims(
    State(app): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
    Query(query): Query<RevisionQuery>,
) -> ApiResult<Json<Value>> {
    let change = ChangeId(id);
    readable_change(&app, &actor, &change)?;
    let revision = resolve_revision(&app, &change, query.revision)?;
    let claims = app.with_store(|s| s.claims_on(&change, revision))?;
    Ok(Json(json!(claims)))
}

#[derive(Deserialize)]
pub struct GiveVerdict {
    pub revision: Option<i64>,
    pub domain: ReviewDomain,
    pub disposition: Disposition,
    pub rationale: String,
}

pub async fn give_verdict(
    State(app): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
    Json(body): Json<GiveVerdict>,
) -> ApiResult<Json<Value>> {
    let change = ChangeId(id);
    let revision = resolve_revision(&app, &change, body.revision)?;
    let (verdict, env) = app.with_store(|s| {
        s.give_verdict(
            &actor.0,
            &change,
            revision,
            body.domain,
            body.disposition,
            &body.rationale,
        )
    })?;
    app.publish(&env);
    Ok(committed(Some(verdict.0), &env))
}

pub async fn list_verdicts(
    State(app): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
    Query(query): Query<RevisionQuery>,
) -> ApiResult<Json<Value>> {
    let change = ChangeId(id);
    readable_change(&app, &actor, &change)?;
    let revision = resolve_revision(&app, &change, query.revision)?;
    let verdicts = app.with_store(|s| s.verdicts_on(&change, revision))?;
    Ok(Json(json!(verdicts)))
}

pub async fn merge_readiness(
    State(app): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let change = readable_change(&app, &actor, &ChangeId(id))?;
    let trace = app.with_store(|s| s.merge_readiness(&change.id))?;
    Ok(Json(json!(trace)))
}

/// Record a merge in the graph, translating a policy refusal into a
/// 409 carrying the full trace. Publishing is the caller's job.
pub(crate) fn merge_core(app: &AppState, actor: &Actor, change: &ChangeId) -> ApiResult<Envelope> {
    match app.with_store(|s| s.merge_change(&actor.0, change)) {
        Ok(env) => Ok(env),
        // A refused merge answers with the full trace: the caller learns
        // exactly which requirement to go satisfy, not just "no".
        Err(CoreError::PolicyUnsatisfied(message)) => {
            let trace = app.with_store(|s| s.merge_readiness(change))?;
            let mut error = ApiError::from(CoreError::PolicyUnsatisfied(message));
            error.detail = Some(json!({ "trace": trace }));
            Err(error)
        }
        Err(err) => Err(err.into()),
    }
}

pub async fn merge_change(
    State(app): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let change = ChangeId(id);
    if app.git().is_some() {
        return crate::git_http::merge_with_git(&app, &actor, &change).await;
    }
    let env = merge_core(&app, &actor, &change)?;
    app.publish(&env);
    Ok(committed(None, &env))
}

#[derive(Deserialize)]
pub struct AbandonChange {
    pub reason: String,
}

pub async fn abandon_change(
    State(app): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
    Json(body): Json<AbandonChange>,
) -> ApiResult<Json<Value>> {
    let env = app.with_store(|s| s.abandon_change(&actor.0, &ChangeId(id), &body.reason))?;
    app.publish(&env);
    Ok(committed(None, &env))
}

// ---- events ----

#[derive(Deserialize)]
pub struct EventsQuery {
    #[serde(default)]
    pub after: i64,
    pub limit: Option<usize>,
}

pub async fn list_events(
    State(app): State<AppState>,
    actor: Actor,
    Query(query): Query<EventsQuery>,
) -> ApiResult<Json<Value>> {
    let limit = query.limit.unwrap_or(100).min(1000);
    // Who is asking decides what comes back. It used to only decide
    // whether anything came back at all.
    let events = app.with_store(|s| s.events_visible_to(&actor.0, EventSeq(query.after), limit))?;
    Ok(Json(json!(events)))
}

// ---- tokens ----

#[derive(Deserialize)]
pub struct MintToken {
    pub label: Option<String>,
}

/// Mint a token. The response is the only place the secret ever exists;
/// the log and every later read carry nothing but its hash.
pub async fn mint_token(
    State(app): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
    Json(body): Json<MintToken>,
) -> ApiResult<Json<Value>> {
    let principal = PrincipalId(id);
    let (token, secret, env) =
        app.with_store(|s| s.mint_token(&actor.0, &principal, body.label.as_deref()))?;
    app.publish(&env);
    Ok(Json(
        json!({ "id": token, "token": secret, "seq": env.seq.0 }),
    ))
}

pub async fn list_tokens(
    State(app): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    // Credentials stay with their subject. Only the hashes are stored,
    // but which tokens somebody holds, and what they called them, is
    // still theirs - and the forge's operator's, since revoking is.
    if actor.0.as_str() != id && !app.with_store(|s| s.is_admin(&actor.0)) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "forbidden",
            "only the principal or an admin may list their tokens".to_owned(),
        ));
    }
    let tokens = app.with_store(|s| s.tokens_of(&PrincipalId(id)))?;
    Ok(Json(json!(tokens)))
}

pub async fn revoke_token(
    State(app): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let env = app.with_store(|s| s.revoke_token(&actor.0, &TokenId(id)))?;
    app.publish(&env);
    Ok(committed(None, &env))
}

// ---- grants ----

#[derive(Deserialize)]
pub struct IssueGrant {
    pub grantee: PrincipalId,
    pub repo: Option<String>,
    pub actions: Vec<Capability>,
    pub until: Option<String>,
}

pub async fn issue_grant(
    State(app): State<AppState>,
    actor: Actor,
    Json(body): Json<IssueGrant>,
) -> ApiResult<Json<Value>> {
    let (grant, env) = app.with_store(|s| {
        s.issue_grant(
            &actor.0,
            &body.grantee,
            body.repo.as_deref(),
            body.actions,
            body.until.as_deref(),
        )
    })?;
    app.publish(&env);
    Ok(committed(Some(grant.0), &env))
}

#[derive(Deserialize)]
pub struct GrantFilter {
    pub grantee: String,
}

pub async fn list_grants(
    State(app): State<AppState>,
    _actor: Actor,
    Query(filter): Query<GrantFilter>,
) -> ApiResult<Json<Value>> {
    let grants = app.with_store(|s| s.grants_of(&PrincipalId(filter.grantee)))?;
    Ok(Json(json!(grants)))
}

#[derive(Deserialize)]
pub struct RevokeGrant {
    pub reason: String,
}

pub async fn revoke_grant(
    State(app): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
    Json(body): Json<RevokeGrant>,
) -> ApiResult<Json<Value>> {
    let env = app.with_store(|s| s.revoke_grant(&actor.0, &GrantId(id), &body.reason))?;
    app.publish(&env);
    Ok(committed(None, &env))
}

// ---- merge queue ----

pub async fn enqueue_change(
    State(app): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let change = ChangeId(id);
    match app.with_store(|s| s.enqueue_change(&actor.0, &change)) {
        Ok(env) => {
            app.publish(&env);
            Ok(committed(None, &env))
        }
        // Same teaching refusal as a direct merge: the full trace.
        Err(CoreError::PolicyUnsatisfied(message)) => {
            let trace = app.with_store(|s| s.merge_readiness(&change))?;
            let mut error = ApiError::from(CoreError::PolicyUnsatisfied(message));
            error.detail = Some(json!({ "trace": trace }));
            Err(error)
        }
        Err(err) => Err(err.into()),
    }
}

#[derive(Deserialize)]
pub struct DequeueChange {
    pub reason: String,
}

pub async fn dequeue_change(
    State(app): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
    Json(body): Json<DequeueChange>,
) -> ApiResult<Json<Value>> {
    let env = app.with_store(|s| s.dequeue_change(&actor.0, &ChangeId(id), &body.reason))?;
    app.publish(&env);
    Ok(committed(None, &env))
}

#[derive(Deserialize)]
pub struct QueueQuery {
    pub target: Option<String>,
}

pub async fn list_queue(
    State(app): State<AppState>,
    actor: Actor,
    Path(repo): Path<String>,
    Query(query): Query<QueueQuery>,
) -> ApiResult<Json<Value>> {
    let record = readable_repo(&app, &actor, &repo)?;
    let target = query.target.unwrap_or(record.default_branch);
    let entries = app.with_store(|s| s.queue_for(&repo, &target))?;
    Ok(Json(json!(entries)))
}

// ---- verification ----

#[derive(Deserialize)]
pub struct VerifyClaim {
    pub agrees: bool,
    pub command: String,
    pub observed: String,
}

/// Record an independent re-execution of a claim. Runners call this;
/// a disputed claim blocks the landing until it is resolved.
pub async fn verify_claim(
    State(app): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
    Json(body): Json<VerifyClaim>,
) -> ApiResult<Json<Value>> {
    let claim = ClaimId(id);
    let (verification, env) = app.with_store(|s| {
        s.verify_claim(&actor.0, &claim, body.agrees, &body.command, &body.observed)
    })?;
    app.publish(&env);
    Ok(committed(Some(verification.0), &env))
}

pub async fn list_verifications(
    State(app): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
    Query(query): Query<RevisionQuery>,
) -> ApiResult<Json<Value>> {
    let change = ChangeId(id);
    readable_change(&app, &actor, &change)?;
    let revision = resolve_revision(&app, &change, query.revision)?;
    let verifications = app.with_store(|s| s.verifications_on(&change, revision))?;
    Ok(Json(json!(verifications)))
}

/// What a human should look at in this repo, ranked, with the signals
/// and the evidence behind each ranking.
pub async fn attention(
    State(app): State<AppState>,
    actor: Actor,
    Path(repo): Path<String>,
) -> ApiResult<Json<Value>> {
    readable_repo(&app, &actor, &repo)?;
    let items = app.with_store(|s| s.attention_for(&repo))?;
    Ok(Json(json!(items)))
}

// ---- path leases ----

#[derive(Deserialize)]
pub struct DeclarePaths {
    pub repo: String,
    pub paths: Vec<String>,
}

/// Declare the paths a session expects to touch, and learn who else is
/// already there. Overlaps are reported, never refused.
pub async fn declare_paths(
    State(app): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
    Json(body): Json<DeclarePaths>,
) -> ApiResult<Json<Value>> {
    let session = SessionId(id);
    let (overlaps, env) =
        app.with_store(|s| s.declare_paths(&actor.0, &session, &body.repo, body.paths))?;
    app.publish(&env);
    let mut response = committed(None, &env);
    response.0["overlaps"] = json!(overlaps);
    Ok(response)
}

#[derive(Deserialize)]
pub struct PathsQuery {
    /// Comma-separated paths or prefixes.
    pub paths: String,
}

/// Who is already working where, before you start.
pub async fn path_conflicts(
    State(app): State<AppState>,
    actor: Actor,
    Path(repo): Path<String>,
    Query(query): Query<PathsQuery>,
) -> ApiResult<Json<Value>> {
    readable_repo(&app, &actor, &repo)?;
    let paths: Vec<String> = query
        .paths
        .split(',')
        .map(|p| p.trim().to_owned())
        .filter(|p| !p.is_empty())
        .collect();
    let overlaps = app.with_store(|s| s.path_conflicts(&repo, &paths))?;
    Ok(Json(json!({ "paths": paths, "overlaps": overlaps })))
}

pub async fn list_leases(
    State(app): State<AppState>,
    actor: Actor,
    Path(repo): Path<String>,
) -> ApiResult<Json<Value>> {
    readable_repo(&app, &actor, &repo)?;
    let leases = app.with_store(|s| s.live_leases(&repo))?;
    Ok(Json(json!(leases)))
}

#[derive(Deserialize)]
pub struct LessonQuery {
    pub repo: Option<String>,
    pub q: Option<String>,
    #[serde(default)]
    pub failures_only: bool,
    pub limit: Option<usize>,
}

/// What earlier attempts learned, searchable. Every ending session is
/// required to record an outcome, so this corpus is a by-product of
/// the protocol rather than something anyone has to maintain.
pub async fn lessons(
    State(app): State<AppState>,
    actor: Actor,
    Query(query): Query<LessonQuery>,
) -> ApiResult<Json<Value>> {
    if let Some(repo) = &query.repo {
        readable_repo(&app, &actor, repo)?;
    }
    let mut lessons = app.with_store(|s| {
        s.lessons(
            query.repo.as_deref(),
            query.q.as_deref().filter(|q| !q.trim().is_empty()),
            query.failures_only,
            query.limit.unwrap_or(50),
        )
    })?;
    // Searching across everything is searching across what you may see.
    lessons.retain(|lesson| {
        lesson
            .repo
            .as_deref()
            .is_none_or(|repo| app.with_store(|s| s.may_read(&actor.0, repo)))
    });
    Ok(Json(json!(lessons)))
}

// ---- inbox ----

#[derive(Deserialize)]
pub struct InboxQuery {
    #[serde(default)]
    pub unread: bool,
    pub limit: Option<usize>,
}

/// What has been addressed to the caller: judgments on their changes,
/// disputes on their claims, authority given to them. Newest first.
pub async fn inbox(
    State(app): State<AppState>,
    actor: Actor,
    Query(query): Query<InboxQuery>,
) -> ApiResult<Json<Value>> {
    let mut notices = app.with_store(|s| s.inbox(&actor.0, query.limit.unwrap_or(100)))?;
    if query.unread {
        notices.retain(|notice| !notice.read);
    }
    let unread = app.with_store(|s| s.unread_count(&actor.0))?;
    Ok(Json(json!({ "unread": unread, "notices": notices })))
}

#[derive(Deserialize)]
pub struct MarkRead {
    pub seq: Option<i64>,
    #[serde(default)]
    pub all: bool,
}

/// Mark one notice, or everything so far, dealt with. Not an event:
/// what somebody has read is not a fact about the software.
pub async fn mark_read(
    State(app): State<AppState>,
    actor: Actor,
    Json(body): Json<MarkRead>,
) -> ApiResult<Json<Value>> {
    match (body.all, body.seq) {
        (true, _) => app.with_store(|s| s.mark_all_read(&actor.0))?,
        (false, Some(seq)) => app.with_store(|s| s.mark_read(&actor.0, seq))?,
        (false, None) => {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "invalid",
                "say which notice, or all".to_owned(),
            ));
        }
    }
    let unread = app.with_store(|s| s.unread_count(&actor.0))?;
    Ok(Json(json!({ "unread": unread })))
}

// ---- policy ----

#[derive(Deserialize)]
pub struct PolicyBody {
    #[serde(flatten)]
    pub policy: cairn_core::Policy,
    /// Report what this policy would do to the open changes, and
    /// change nothing.
    #[serde(default)]
    pub preview: bool,
}

/// Read or set the rules a repository requires. Setting is admin
/// authority; previewing asks what a proposed policy would cost
/// without committing to it.
pub async fn get_policy(
    State(app): State<AppState>,
    actor: Actor,
    Path(repo): Path<String>,
) -> ApiResult<Json<Value>> {
    let record = readable_repo(&app, &actor, &repo)?;
    Ok(Json(json!(record.policy)))
}

pub async fn set_policy(
    State(app): State<AppState>,
    actor: Actor,
    Path(repo): Path<String>,
    Json(body): Json<PolicyBody>,
) -> ApiResult<Json<Value>> {
    if body.preview {
        let previewed = app.with_store(|s| s.policy_preview(&repo, &body.policy))?;
        let would_block: Vec<Value> = previewed
            .iter()
            .filter(|(_, trace)| !trace.satisfied)
            .map(|(change, trace)| {
                json!({
                    "change": change.number,
                    "title": change.title,
                    "unmet": trace
                        .requirements
                        .iter()
                        .filter(|r| !r.satisfied)
                        .map(|r| r.description.clone())
                        .collect::<Vec<_>>(),
                })
            })
            .collect();
        return Ok(Json(json!({
            "preview": true,
            "open_changes": previewed.len(),
            "would_block": would_block,
        })));
    }
    let env = app.with_store(|s| s.set_policy(&actor.0, &repo, body.policy))?;
    app.publish(&env);
    Ok(committed(Some(repo), &env))
}

// ---- mirror ----

#[derive(Deserialize)]
pub struct MirrorBody {
    /// Absent stops mirroring.
    pub mirror: Option<cairn_core::Mirror>,
}

/// Where a repository copies its landed branches. The credential that
/// authorises the push is the operator's and lives with the server, so
/// nothing secret passes through here or comes back.
pub async fn set_mirror(
    State(app): State<AppState>,
    actor: Actor,
    Path(repo): Path<String>,
    Json(body): Json<MirrorBody>,
) -> ApiResult<Json<Value>> {
    let env = app.with_store(|s| s.set_mirror(&actor.0, &repo, body.mirror))?;
    app.publish(&env);
    Ok(committed(Some(repo), &env))
}

pub async fn get_mirror(
    State(app): State<AppState>,
    actor: Actor,
    Path(repo): Path<String>,
) -> ApiResult<Json<Value>> {
    let record = readable_repo(&app, &actor, &repo)?;
    Ok(Json(json!(record.mirror)))
}

/// Liveness and readiness in one: the store answers, so the forge can
/// serve. Deliberately unauthenticated and deliberately dull — a probe
/// that needs a credential is a probe nobody configures.
pub async fn health(State(app): State<AppState>) -> Response {
    match app.with_store(|s| s.latest_seq()) {
        Ok(seq) => (StatusCode::OK, Json(json!({ "ok": true, "seq": seq.0 }))).into_response(),
        Err(err) => {
            tracing::error!(error = %err, "health: the store did not answer");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "ok": false })),
            )
                .into_response()
        }
    }
}

/// The changes a runner should pick up: open work whose claims name a
/// command nobody has re-run.
pub async fn awaiting_verification(
    State(app): State<AppState>,
    actor: Actor,
    Path(repo): Path<String>,
) -> ApiResult<Json<Value>> {
    readable_repo(&app, &actor, &repo)?;
    let waiting = app.with_store(|s| s.awaiting_verification(&repo))?;
    Ok(Json(json!(waiting)))
}
