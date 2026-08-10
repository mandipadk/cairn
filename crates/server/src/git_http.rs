//! Git over HTTP, feeding the graph.
//!
//! Smart-HTTP requests are relayed to real git via `GitStore`; pushes
//! to `refs/for/<branch>` reach the proc-receive hook, which calls
//! [`record_push`] here to enter the revision into the graph before
//! receive-pack creates the `refs/changes/<number>/<revision>` ref it
//! reports back to the pusher.
//!
//! Reads (clone/fetch) are anonymous in dev-mode; pushes identify the
//! principal from HTTP Basic auth's username (any password) or the
//! dev header — the same seam as the rest of the API.

use crate::auth::{Actor, PRINCIPAL_HEADER};
use crate::error::{ApiError, ApiResult};
use crate::routes::committed;
use crate::state::AppState;
use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::prelude::*;
use cairn_core::{ChangeState, PrincipalId};
use cairn_git::Service;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::io::Read;

/// Clone URLs may spell the repo with or without a `.git` suffix.
fn repo_name(raw: &str) -> String {
    raw.strip_suffix(".git").unwrap_or(raw).to_owned()
}

fn git_enabled(app: &AppState) -> ApiResult<&crate::state::GitContext> {
    app.git().ok_or_else(|| {
        ApiError::new(
            StatusCode::NOT_FOUND,
            "not_found",
            "git hosting is not enabled",
        )
    })
}

fn ensure_repo(app: &AppState, name: &str) -> ApiResult<()> {
    app.with_store(|s| s.repo(name))?
        .map(|_| ())
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "not_found",
                format!("repo {name} not found"),
            )
        })
}

fn git_protocol(headers: &HeaderMap) -> Option<String> {
    headers
        .get("git-protocol")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

/// Request bodies from git clients may arrive gzip-compressed.
fn request_body(headers: &HeaderMap, body: Bytes) -> ApiResult<Vec<u8>> {
    let gzipped = headers
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("gzip"));
    if !gzipped {
        return Ok(body.to_vec());
    }
    let mut decoded = Vec::new();
    flate2::read::GzDecoder::new(body.as_ref())
        .read_to_end(&mut decoded)
        .map_err(|e| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "invalid",
                format!("bad gzip body: {e}"),
            )
        })?;
    Ok(decoded)
}

/// The pushing principal. Normal path: HTTP Basic with the principal
/// as username and a live API token as password. Dev mode additionally
/// accepts a bare username or the dev header — asserted, not proven.
fn push_principal(app: &AppState, headers: &HeaderMap) -> ApiResult<PrincipalId> {
    let unauthorized = || {
        ApiError::new(
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "push requires identity: http://<principal>:<api-token>@host/...",
        )
    };
    let basic = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic "))
        .and_then(|b64| BASE64_STANDARD.decode(b64).ok())
        .and_then(|raw| String::from_utf8(raw).ok())
        .and_then(|creds| {
            creds
                .split_once(':')
                .map(|(user, pass)| (user.to_owned(), pass.to_owned()))
        });
    if let Some((user, password)) = &basic {
        let claimed = PrincipalId::new(user).ok_or_else(unauthorized)?;
        let owner = app.with_store(|s| s.principal_for_token(password))?;
        match owner {
            Some(owner) if owner == claimed => return Ok(claimed),
            Some(_) => return Err(unauthorized()),
            None if !app.dev_identity() => return Err(unauthorized()),
            None => {}
        }
    }
    if app.dev_identity() {
        let asserted = basic
            .map(|(user, _)| user)
            .or_else(|| {
                headers
                    .get(PRINCIPAL_HEADER)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned)
            })
            .ok_or_else(unauthorized)?;
        let principal = PrincipalId::new(&asserted).ok_or_else(unauthorized)?;
        if app.with_store(|s| s.principal(&principal))?.is_none() {
            return Err(unauthorized());
        }
        return Ok(principal);
    }
    Err(unauthorized())
}

fn challenge_basic(err: ApiError) -> Response {
    let mut response = err.into_response();
    if response.status() == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            "Basic realm=\"cairn\"".parse().unwrap(),
        );
    }
    response
}

#[derive(Deserialize)]
pub struct InfoRefsQuery {
    service: String,
}

pub async fn info_refs(
    State(app): State<AppState>,
    Path(repo): Path<String>,
    Query(query): Query<InfoRefsQuery>,
    headers: HeaderMap,
) -> Response {
    let result: ApiResult<Response> = async {
        let git = git_enabled(&app)?;
        let name = repo_name(&repo);
        ensure_repo(&app, &name)?;
        let service = Service::parse(&query.service)
            .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "invalid", "unknown service"))?;
        let body = git
            .store
            .advertise_refs(service, &name, git_protocol(&headers).as_deref())
            .await?;
        Ok((
            [
                (header::CONTENT_TYPE, service.advertisement_content_type()),
                (header::CACHE_CONTROL, "no-cache".to_owned()),
            ],
            body,
        )
            .into_response())
    }
    .await;
    result.unwrap_or_else(IntoResponse::into_response)
}

pub async fn upload_pack(
    State(app): State<AppState>,
    Path(repo): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let result: ApiResult<Response> = async {
        let git = git_enabled(&app)?;
        let name = repo_name(&repo);
        ensure_repo(&app, &name)?;
        let input = request_body(&headers, body)?;
        let output = git
            .store
            .serve_rpc(
                Service::UploadPack,
                &name,
                input,
                Vec::new(),
                git_protocol(&headers).as_deref(),
            )
            .await?;
        Ok((
            [(
                header::CONTENT_TYPE,
                Service::UploadPack.result_content_type(),
            )],
            output,
        )
            .into_response())
    }
    .await;
    result.unwrap_or_else(IntoResponse::into_response)
}

pub async fn receive_pack(
    State(app): State<AppState>,
    Path(repo): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let result: ApiResult<Response> = async {
        let git = git_enabled(&app)?;
        let name = repo_name(&repo);
        ensure_repo(&app, &name)?;
        let principal = push_principal(&app, &headers)?;
        let input = request_body(&headers, body)?;
        // The hook inherits this env and records pushes back through
        // the API as the authenticated pusher, via an ephemeral token
        // that outlives nothing but this receive-pack.
        let env = vec![
            ("CAIRN_SERVER".to_owned(), git.base_url.clone()),
            ("CAIRN_TOKEN".to_owned(), app.issue_push_token(&principal)),
            ("CAIRN_REPO".to_owned(), name.clone()),
        ];
        let output = git
            .store
            .serve_rpc(
                Service::ReceivePack,
                &name,
                input,
                env,
                git_protocol(&headers).as_deref(),
            )
            .await?;
        // Objects have left quarantine now; project the graph's revisions
        // onto refs/changes/<number>/<revision>.
        reconcile_change_refs(&app, &name).await;
        Ok((
            [(
                header::CONTENT_TYPE,
                Service::ReceivePack.result_content_type(),
            )],
            output,
        )
            .into_response())
    }
    .await;
    result.unwrap_or_else(challenge_basic)
}

/// `refs/changes/<n>/<rev>` is a projection of the graph onto git,
/// maintained by reconciliation: create whatever refs the graph says
/// should exist and git doesn't have yet. Idempotent, so a ref missed
/// by a failed push heals on the next one. proc-receive cannot create
/// these refs itself — ref updates are forbidden while pushed objects
/// sit in quarantine.
async fn reconcile_change_refs(app: &AppState, repo: &str) {
    let Some(git) = app.git() else { return };
    let wanted = match app.with_store(|s| s.revision_refs(repo)) {
        Ok(wanted) => wanted,
        Err(err) => {
            tracing::warn!(%err, repo, "listing revisions for ref reconciliation failed");
            return;
        }
    };
    let existing: HashSet<String> = match git.store.list_refs(repo, "refs/changes/").await {
        Ok(refs) => refs.into_iter().map(|(name, _)| name).collect(),
        Err(err) => {
            tracing::warn!(%err, repo, "listing change refs failed");
            return;
        }
    };
    for (change_number, revision, oid) in wanted {
        let refname = format!("refs/changes/{change_number}/{revision}");
        if existing.contains(&refname) {
            continue;
        }
        if let Err(err) = git.store.set_ref(repo, &refname, &oid).await {
            // Likely a revision whose objects never landed; it will heal
            // or keep failing quietly, and the graph stays authoritative.
            tracing::debug!(%err, %refname, repo, "revision ref not creatable yet");
        }
    }
}

/// One pushed commit, bottom-up in stack order.
#[derive(Deserialize)]
pub struct PushedCommit {
    pub commit_oid: String,
    pub title: String,
    #[serde(default)]
    pub message: String,
    /// Change-Id trailer, when the commit carries one.
    pub change_id: Option<String>,
}

/// What the proc-receive hook reports about one push: every new commit
/// between the target branch and the pushed tip.
#[derive(Deserialize)]
pub struct RecordPush {
    pub repo: String,
    pub target: String,
    pub commits: Vec<PushedCommit>,
}

/// Stacks larger than this are almost certainly a mistaken push of
/// history; refuse with advice rather than mint hundreds of changes.
const MAX_STACK: usize = 64;

/// Enter a pushed stack into the graph, bottom-up. Each commit becomes
/// a revision of the change addressed by its Change-Id trailer — or a
/// new change stacked on the previous commit's change. Unchanged
/// commits (same oid as the change's latest revision) record nothing,
/// so re-pushing a stack after amending one commit touches one change.
pub async fn record_push(
    State(app): State<AppState>,
    actor: Actor,
    Json(body): Json<RecordPush>,
) -> ApiResult<Json<Value>> {
    if body.commits.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid",
            "push contains no new commits",
        ));
    }
    if body.commits.len() > MAX_STACK {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid",
            format!(
                "push contains {} new commits (limit {MAX_STACK}); this looks like history, not a stack",
                body.commits.len()
            ),
        ));
    }
    // Stack identity across amends and rebases requires per-commit keys.
    if body.commits.len() > 1 && body.commits.iter().any(|c| c.change_id.is_none()) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid",
            "multi-commit pushes require a Change-Id trailer on every commit, so each \
             change keeps its identity across amends",
        ));
    }

    let mut results = Vec::new();
    let mut parent: Option<cairn_core::ChangeId> = None;
    let mut last_seq = 0i64;
    for commit in &body.commits {
        let existing = match &commit.change_id {
            Some(key) => app.with_store(|s| s.change_by_key(&body.repo, key))?,
            None => None,
        };
        let (change, number, created) = match existing {
            Some(change) if change.state == ChangeState::Open && change.target == body.target => {
                let unchanged = app
                    .with_store(|s| s.revisions(&change.id))?
                    .last()
                    .is_some_and(|r| r.commit_oid == commit.commit_oid);
                if unchanged {
                    results.push(json!({
                        "change": change.id,
                        "number": change.number,
                        "revision": change.latest_revision,
                        "created": false,
                        "unchanged": true,
                    }));
                    parent = Some(change.id);
                    continue;
                }
                (change.id, change.number, false)
            }
            Some(change) => {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    "conflict",
                    format!(
                        "change {} (key {}) is {} on target {}; start a new Change-Id",
                        change.number,
                        commit.change_id.as_deref().unwrap_or(""),
                        change.state.as_str(),
                        change.target
                    ),
                ));
            }
            None => {
                let spec = cairn_core::ChangeSpec {
                    external_key: commit.change_id.clone(),
                    parent_change: parent.clone(),
                    ..cairn_core::ChangeSpec::new(&body.repo, &body.target, &commit.title)
                };
                let (id, number, env) = app.with_store(|s| s.open_change(&actor.0, spec))?;
                app.publish(&env);
                (id, number, true)
            }
        };
        let (revision, pushed) = app.with_store(|s| {
            s.push_revision(&actor.0, &change, &commit.commit_oid, None, &commit.message)
        })?;
        app.publish(&pushed);
        last_seq = pushed.seq.0;
        results.push(json!({
            "change": change,
            "number": number,
            "revision": revision,
            "created": created,
            "unchanged": false,
        }));
        parent = Some(change);
    }
    let tip = results.last().cloned().expect("commits is non-empty");
    Ok(Json(json!({
        "results": results,
        "tip": { "number": tip["number"], "revision": tip["revision"] },
        "seq": last_seq,
    })))
}

/// Merge with the git executor: refuse non-fast-forward, record the
/// merge in the graph, then advance the target ref (compare-and-swap
/// against the tip we checked).
pub async fn merge_with_git(
    app: &AppState,
    actor: &Actor,
    change_id: &cairn_core::ChangeId,
) -> ApiResult<Json<Value>> {
    let git = git_enabled(app)?;
    let change = app
        .with_store(|s| s.change(change_id))?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "not_found", "change not found"))?;
    let revisions = app.with_store(|s| s.revisions(change_id))?;
    let Some(revision) = revisions.last() else {
        // No revisions: let core merge produce its policy refusal.
        let env = crate::routes::merge_core(app, actor, change_id)?;
        app.publish(&env);
        return Ok(committed(None, &env));
    };

    let old_tip = git.store.tip(&change.repo, &change.target).await?;
    if let Some(tip) = &old_tip
        && !git
            .store
            .is_ancestor(&change.repo, tip, &revision.commit_oid)
            .await?
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "not_fast_forward",
            format!(
                "target {} has advanced past revision {}; rebase and push a new revision",
                change.target, revision.number
            ),
        ));
    }

    let env = crate::routes::merge_core(app, actor, change_id)?;
    app.publish(&env);

    if let Err(err) = git
        .store
        .advance_ref(
            &change.repo,
            &change.target,
            &revision.commit_oid,
            old_tip.as_deref(),
        )
        .await
    {
        // The graph recorded the merge but the ref did not move — say
        // exactly that, loudly; a retry of update-ref is safe.
        tracing::error!(error = %err, change = %change.id, "merge recorded but ref advance failed");
        return Err(ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "ref_advance_failed",
            format!(
                "merge recorded in the graph, but advancing refs/heads/{} failed: {err}",
                change.target
            ),
        ));
    }
    Ok(committed(None, &env))
}

#[derive(Deserialize)]
pub struct BlameQuery {
    pub path: String,
}

/// What is known about each line of a file: the change that landed it,
/// what was claimed, who judged it, and what the claims left
/// unverified. The pre-flight question an agent should ask before
/// touching code it did not write.
pub async fn blame(
    State(app): State<AppState>,
    _actor: Actor,
    Path(repo): Path<String>,
    axum::extract::Query(query): axum::extract::Query<BlameQuery>,
) -> ApiResult<Json<Value>> {
    let git = git_enabled(&app)?;
    let record = app
        .with_store(|s| s.repo(&repo))?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "not_found", "repo not found"))?;
    let rev = format!("refs/heads/{}", record.default_branch);
    let oids = git.store.blame_lines(&repo, &rev, &query.path).await?;

    let mut known: HashMap<String, Option<cairn_core::Provenance>> = HashMap::new();
    let mut lines = Vec::with_capacity(oids.len());
    for (index, oid) in oids.iter().enumerate() {
        if !known.contains_key(oid) {
            known.insert(
                oid.clone(),
                app.with_store(|s| s.provenance_of(&repo, oid))?,
            );
        }
        let provenance = known.get(oid).and_then(Option::as_ref);
        lines.push(json!({
            "line": index + 1,
            "commit": oid,
            "change": provenance.map(|p| p.change.number),
            "executed_check": provenance.map(|p| p.executed_check()),
            "unchecked": provenance.map(|p| p.unchecked()).unwrap_or_default(),
        }));
    }
    let unverified = lines
        .iter()
        .filter(|l| l["executed_check"] == Value::Bool(false))
        .count();
    Ok(Json(json!({
        "path": query.path,
        "lines": lines,
        "unverified_lines": unverified,
    })))
}
