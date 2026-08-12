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
use cairn_core::{
    Capability, ChangeId, ChangeSpec, ClaimId, ClaimSpec, CoreError, Disposition, Envelope,
    EventSeq, GrantId, ObjectFormat, PrincipalId, PrincipalKind, ReviewDomain, SessionId,
    SessionState, TaskId, TaskState, TokenId,
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
    if app.with_store(|s| s.repo(&body.name))?.is_some() {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "conflict",
            format!("repo {} already exists", body.name),
        ));
    }
    // The bare repo lands on disk first; the graph event follows. An
    // orphan directory from a lost race is harmless, the reverse is not.
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

pub async fn get_repo(
    State(app): State<AppState>,
    _actor: Actor,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    let repo = app.with_store(|s| s.repo(&name))?;
    Ok(Json(json!(found(repo, "repo")?)))
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
    _actor: Actor,
    Query(filter): Query<TaskFilter>,
) -> ApiResult<Json<Value>> {
    let tasks = app.with_store(|s| s.tasks(filter.state))?;
    Ok(Json(json!(tasks)))
}

pub async fn get_task(
    State(app): State<AppState>,
    _actor: Actor,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let task = app.with_store(|s| s.task(&TaskId(id)))?;
    Ok(Json(json!(found(task, "task")?)))
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
    _actor: Actor,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let session = app.with_store(|s| s.session(&SessionId(id)))?;
    Ok(Json(json!(found(session, "session")?)))
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
    _actor: Actor,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let change = app.with_store(|s| s.change(&ChangeId(id)))?;
    Ok(Json(json!(found(change, "change")?)))
}

pub async fn get_change_by_number(
    State(app): State<AppState>,
    _actor: Actor,
    Path((repo, number)): Path<(String, i64)>,
) -> ApiResult<Json<Value>> {
    let change = app.with_store(|s| s.change_by_number(&repo, number))?;
    Ok(Json(json!(found(change, "change")?)))
}

pub async fn list_changes(
    State(app): State<AppState>,
    _actor: Actor,
    Path(repo): Path<String>,
) -> ApiResult<Json<Value>> {
    let changes = app.with_store(|s| s.changes_in_repo(&repo))?;
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
    _actor: Actor,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
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
    _actor: Actor,
    Path(id): Path<String>,
    Query(query): Query<RevisionQuery>,
) -> ApiResult<Json<Value>> {
    let change = ChangeId(id);
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
    _actor: Actor,
    Path(id): Path<String>,
    Query(query): Query<RevisionQuery>,
) -> ApiResult<Json<Value>> {
    let change = ChangeId(id);
    let revision = resolve_revision(&app, &change, query.revision)?;
    let verdicts = app.with_store(|s| s.verdicts_on(&change, revision))?;
    Ok(Json(json!(verdicts)))
}

pub async fn merge_readiness(
    State(app): State<AppState>,
    _actor: Actor,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let trace = app.with_store(|s| s.merge_readiness(&ChangeId(id)))?;
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
    _actor: Actor,
    Query(query): Query<EventsQuery>,
) -> ApiResult<Json<Value>> {
    let limit = query.limit.unwrap_or(100).min(1000);
    let events = app.with_store(|s| s.events_after(EventSeq(query.after), limit))?;
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
    _actor: Actor,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
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
    _actor: Actor,
    Path(repo): Path<String>,
    Query(query): Query<QueueQuery>,
) -> ApiResult<Json<Value>> {
    let target = match query.target {
        Some(target) => target,
        None => found(app.with_store(|s| s.repo(&repo))?, "repo")?.default_branch,
    };
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
    _actor: Actor,
    Path(id): Path<String>,
    Query(query): Query<RevisionQuery>,
) -> ApiResult<Json<Value>> {
    let change = ChangeId(id);
    let revision = resolve_revision(&app, &change, query.revision)?;
    let verifications = app.with_store(|s| s.verifications_on(&change, revision))?;
    Ok(Json(json!(verifications)))
}

/// What a human should look at in this repo, ranked, with the signals
/// and the evidence behind each ranking.
pub async fn attention(
    State(app): State<AppState>,
    _actor: Actor,
    Path(repo): Path<String>,
) -> ApiResult<Json<Value>> {
    let items = app.with_store(|s| s.attention_for(&repo))?;
    Ok(Json(json!(items)))
}
