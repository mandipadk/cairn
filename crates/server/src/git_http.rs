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
use crate::error::Json;
use crate::error::Query;
use crate::error::{ApiError, ApiResult};
use crate::repo_path::RepoName;
use crate::routes::committed;
use crate::state::AppState;
use ambolt_core::{ChangeState, PrincipalId};
use ambolt_git::Service;
use ambolt_git::{RpcInput, RpcStream};
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::prelude::*;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr};
use std::pin::Pin;

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

fn git_protocol(headers: &HeaderMap) -> Option<String> {
    headers
        .get("git-protocol")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

/// Whether a request body says it is gzip-compressed. Git compresses
/// the fetch negotiation it sends, never a pack it pushes.
fn gzipped(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("gzip"))
}

/// The most a compressed request body may unpack to. What git
/// compresses is the fetch negotiation — wants and haves, a line per
/// ref — and a negotiation past this is not one.
const GZIPPED_BODY_LIMIT: u64 = 64 * 1024 * 1024;

/// The fetch negotiation, whole. Small, and decoded before git sees
/// it when it came compressed.
async fn negotiation(headers: &HeaderMap, body: Body) -> ApiResult<RpcInput> {
    let raw = axum::body::to_bytes(body, GZIPPED_BODY_LIMIT as usize)
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "invalid",
                format!(
                    "the request body is larger than {}",
                    crate::in_bytes(GZIPPED_BODY_LIMIT)
                ),
            )
        })?;
    Ok(RpcInput::Whole(unpacked(headers, raw, GZIPPED_BODY_LIMIT)?))
}

/// A push, as it arrives: streamed into receive-pack rather than held,
/// so a push of a large pack costs the forge no memory. Git refuses a
/// pack past `receive.maxInputSize` while reading it; the count here
/// is the backstop for a body that is not a pack at all. A push that
/// came compressed (git never does) is decoded whole, under the same
/// ceiling as anything else.
async fn push_body(headers: &HeaderMap, body: Body) -> ApiResult<RpcInput> {
    if gzipped(headers) {
        let raw = axum::body::to_bytes(body, crate::GIT_BODY_LIMIT)
            .await
            .map_err(|_| {
                ApiError::new(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "invalid",
                    format!(
                        "the request body is larger than {}",
                        crate::in_bytes(crate::GIT_BODY_LIMIT as u64)
                    ),
                )
            })?;
        return Ok(RpcInput::Whole(unpacked(
            headers,
            raw,
            crate::GIT_BODY_LIMIT as u64,
        )?));
    }
    Ok(RpcInput::Streamed(Box::pin(Bounded {
        inner: Box::pin(body.into_data_stream()),
        seen: 0,
        limit: crate::GIT_BODY_LIMIT as u64,
    })))
}

/// A request body with a ceiling: past it, the stream ends in an error
/// and git sees a truncated request, which it refuses.
struct Bounded {
    inner: Pin<Box<axum::body::BodyDataStream>>,
    seen: u64,
    limit: u64,
}

impl tokio_stream::Stream for Bounded {
    type Item = std::io::Result<Bytes>;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        use std::task::Poll;
        let this = self.get_mut();
        match this.inner.as_mut().poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(std::io::Error::other(err)))),
            Poll::Ready(Some(Ok(chunk))) => {
                this.seen = this.seen.saturating_add(chunk.len() as u64);
                if this.seen > this.limit {
                    return Poll::Ready(Some(Err(std::io::Error::other(format!(
                        "the request body is larger than {}",
                        crate::in_bytes(this.limit)
                    )))));
                }
                Poll::Ready(Some(Ok(chunk)))
            }
        }
    }
}

/// A transfer's output with the place it holds among the transfers
/// being served, given back when the last byte has gone.
struct Served {
    stream: RpcStream,
    _slot: crate::state::GitSlot,
}

impl tokio_stream::Stream for Served {
    type Item = std::io::Result<Bytes>;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        Pin::new(&mut self.get_mut().stream).poll_next(cx)
    }
}

/// Too many transfers at once, from everyone or from this caller.
fn transfers_full() -> ApiError {
    ApiError::new(
        StatusCode::TOO_MANY_REQUESTS,
        "rate_limited",
        "too many git transfers are being served at once; try again in a few seconds",
    )
}

/// Who a transfer is charged to: the principal, when the request named
/// one; the address otherwise.
fn transfer_caller(headers: &HeaderMap, client: Option<IpAddr>) -> String {
    basic_user(headers).unwrap_or_else(|| {
        format!(
            "address:{}",
            client.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        )
    })
}

/// The username of an HTTP Basic header, if there is one.
fn basic_user(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic "))
        .and_then(|b64| BASE64_STANDARD.decode(b64).ok())
        .and_then(|raw| String::from_utf8(raw).ok())
        .and_then(|creds| creds.split_once(':').map(|(user, _)| user.to_owned()))
}

fn unpacked(headers: &HeaderMap, body: Bytes, ceiling: u64) -> ApiResult<Vec<u8>> {
    if !gzipped(headers) {
        return Ok(body.to_vec());
    }
    // A compressed body says how big it is only by being decompressed,
    // and gzip will happily turn a few megabytes into hundreds of
    // gigabytes of this process's memory. Read one byte past what a push
    // may carry and refuse there, so the ceiling is the same whether a
    // client compressed its request or not.
    let mut decoded = Vec::new();
    flate2::read::GzDecoder::new(body.as_ref())
        .take(ceiling + 1)
        .read_to_end(&mut decoded)
        .map_err(|e| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "invalid",
                format!("bad gzip body: {e}"),
            )
        })?;
    if decoded.len() as u64 > ceiling {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "invalid",
            format!(
                "the request body unpacks to more than {}",
                crate::in_bytes(ceiling)
            ),
        ));
    }
    Ok(decoded)
}

/// The pushing principal. Normal path: HTTP Basic with the principal
/// as username and a live API token as password. Dev mode additionally
/// accepts a bare username or the dev header — asserted, not proven.
fn push_principal(
    app: &AppState,
    headers: &HeaderMap,
) -> ApiResult<(PrincipalId, Option<ambolt_core::Scope>)> {
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
        let identity = app.with_store(|s| s.identity_for_token(password))?;
        match identity {
            Some((owner, scope)) if owner == claimed => return Ok((claimed, scope)),
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
        return Ok((principal, None));
    }
    Err(unauthorized())
}

/// Who is reading, if they can prove it.
///
/// Unlike a push, the username in Basic auth carries no weight here: the
/// token is the identity, and every client that stores credentials puts
/// something arbitrary in that field. A push checks the two agree
/// because a mismatch there is usually somebody's mistake worth
/// catching; refusing a *read* over it would only mean a valid
/// credential is rejected for being labelled oddly.
pub(crate) fn reader(
    app: &AppState,
    headers: &HeaderMap,
) -> ApiResult<(PrincipalId, Option<ambolt_core::Scope>)> {
    let unauthorized = || {
        ApiError::new(
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "this repository is private: read it with an API token",
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
    if let Some((_, password)) = &basic
        && let Some(identity) = app.with_store(|s| s.identity_for_token(password))?
    {
        return Ok(identity);
    }
    if app.dev_identity() {
        return push_principal(app, headers);
    }
    Err(unauthorized())
}

/// Reading a repository over git requires identity unless the
/// repository is public.
///
/// This is the door everything else was guarding a window next to: the
/// web pages ask who you are, but `git clone` speaks to the transport
/// directly and never did, so every repository was readable by anyone
/// no matter what the interface implied.
///
/// Two details decide the shape of this. A client only sends
/// credentials after being challenged, so an unauthenticated reader has
/// to get 401 with a `WWW-Authenticate` header — answer 404 and git
/// gives up without ever trying to authenticate. And which private
/// repositories exist is itself worth not telling strangers, so a
/// missing repository and a private one answer identically: challenge
/// first, and only once someone has proved who they are does the
/// difference between "no such repository" and "here it is" appear.
fn may_read(app: &AppState, name: &str, headers: &HeaderMap) -> ApiResult<()> {
    let repo = app.with_store(|s| s.repo(name))?;
    if let Some(repo) = &repo
        && repo.visibility == ambolt_core::Visibility::Public
    {
        return Ok(());
    }
    // Private, or not there at all — the caller learns which only by
    // authenticating first, and then only if it is theirs to see.
    let (who, scope) = reader(app, headers)?;
    if repo.is_some() && app.with_store(|s| s.acting_as(scope.as_ref()).may_read(&who, name)) {
        Ok(())
    } else {
        Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "not_found",
            format!("repo {name} not found"),
        ))
    }
}

fn challenge_basic(err: ApiError) -> Response {
    let mut response = err.into_response();
    if response.status() == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            "Basic realm=\"ambolt\"".parse().unwrap(),
        );
    }
    response
}

#[derive(Deserialize)]
pub struct Room {
    pub repo: String,
    /// What the push holds in quarantine, in bytes, if the hook could
    /// measure it. Zero when it could not: the check then only asks
    /// whether the owner is already over.
    #[serde(default)]
    pub arriving: u64,
}

/// Whether this repository's owner has room for what is arriving.
///
/// Asked by the pre-receive hook, which is the last moment a refusal
/// still costs the forge nothing: git holds a pushed pack in quarantine
/// until pre-receive returns, and discards it if pre-receive refuses.
/// By proc-receive time the objects have been migrated into the
/// repository for good, so a refusal there rejects the ref and keeps
/// the bytes — which is a disk quota that cannot refuse anything.
pub async fn room(
    State(app): State<AppState>,
    pusher: crate::auth::Pusher,
    Json(body): Json<Room>,
) -> ApiResult<Json<Value>> {
    this_push(&pusher, &body.repo)?;
    // Only somebody who may push there may ask, because the answer
    // names the owner's usage — and a repository that is not theirs to
    // push to is a repository they learn nothing about.
    let may = app.with_store(|s| {
        s.acting_as(pusher.scope.as_ref())
            .may_push(&pusher.principal, &body.repo)
    });
    if !may {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "not_found",
            "repo not found",
        ));
    }
    let owner = app
        .with_store(|s| s.repo(&body.repo))?
        .map(|record| record.owner)
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "not_found", "repo not found"))?;
    // Other pushes into this owner's repositories are counted as
    // already there, and this one is counted from now on: what the
    // measurement after each push will find, before it is found.
    let elsewhere = app.arriving_elsewhere(&owner, &pusher.secret);
    room_on_disk(&app, &body.repo, body.arriving, elsewhere)?;
    app.reserve_for_push(&pusher.secret, body.arriving);
    Ok(Json(json!({ "ok": true })))
}

/// The hook's token was issued for one push into one repository, and
/// it may speak only of that one.
fn this_push(pusher: &crate::auth::Pusher, repo: &str) -> ApiResult<()> {
    if pusher.repo == repo {
        return Ok(());
    }
    Err(ApiError::new(
        StatusCode::FORBIDDEN,
        "forbidden",
        format!("this push is into {}, not {repo}", pusher.repo),
    ))
}

#[derive(Deserialize)]
pub struct InfoRefsQuery {
    service: String,
}

pub async fn info_refs(
    State(app): State<AppState>,
    RepoName(repo): RepoName,
    Query(query): Query<InfoRefsQuery>,
    headers: HeaderMap,
) -> Response {
    let result: ApiResult<Response> = async {
        let git = git_enabled(&app)?;
        let name = repo_name(&repo);
        may_read(&app, &name, &headers)?;
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
    // Carry the challenge: a client only sends credentials once it
    // has been asked for them.
    result.unwrap_or_else(challenge_basic)
}

pub async fn upload_pack(
    State(app): State<AppState>,
    RepoName(repo): RepoName,
    crate::guard::ClientIp(client): crate::guard::ClientIp,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let result: ApiResult<Response> = async {
        let git = git_enabled(&app)?;
        let name = repo_name(&repo);
        // Advertising refs and serving the pack are two requests; both
        // have to ask, or the second is an open door.
        may_read(&app, &name, &headers)?;
        let input = negotiation(&headers, body).await?;
        let slot = app
            .git_slot(&transfer_caller(&headers, client))
            .ok_or_else(transfers_full)?;
        // The pack goes out as git produces it: a clone of a large
        // repository is a large response, and holding it whole would
        // make the forge's memory the repository's size times the
        // number of people cloning.
        let stream = git
            .store
            .stream_rpc(
                Service::UploadPack,
                &name,
                input,
                git_protocol(&headers).as_deref(),
            )
            .await?;
        Ok((
            [(
                header::CONTENT_TYPE,
                Service::UploadPack.result_content_type(),
            )],
            Body::from_stream(Served {
                stream,
                _slot: slot,
            }),
        )
            .into_response())
    }
    .await;
    // Carry the challenge: a client only sends credentials once it
    // has been asked for them.
    result.unwrap_or_else(challenge_basic)
}

pub async fn receive_pack(
    State(app): State<AppState>,
    RepoName(repo): RepoName,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let result: ApiResult<Response> = async {
        let git = git_enabled(&app)?;
        let name = repo_name(&repo);
        // Who first, then what: an anonymous caller learns nothing about
        // which repositories exist from the shape of the refusal.
        let (principal, scope) = push_principal(&app, &headers)?;
        let owner = app
            .with_store(|s| s.repo(&name))?
            .map(|record| record.owner)
            .ok_or_else(|| {
                ApiError::new(
                    StatusCode::NOT_FOUND,
                    "not_found",
                    format!("repo {name} not found"),
                )
            })?;
        let input = push_body(&headers, body).await?;
        let _slot = app
            .git_slot(principal.as_str())
            .ok_or_else(transfers_full)?;
        // Measured whatever happens next — a push the pusher abandons
        // or the timeout kills has still written into the repository,
        // and the number has to follow what is there. Held from before
        // git is spawned, because a guard made after a failed await is
        // a guard that is never made.
        let _measure = MeasureOnDrop::new(&app, &name);
        // The hooks inherit this env and record the push back through
        // the API as the authenticated pusher, via a token that names
        // this push and dies with it.
        let secret = app.issue_push_token(&principal, scope.as_ref(), &name, &owner);
        let _push = PushInFlight {
            app: app.clone(),
            secret: secret.clone(),
        };
        let env = vec![
            ("AMBOLT_SERVER".to_owned(), git.base_url.clone()),
            ("AMBOLT_TOKEN".to_owned(), secret),
            ("AMBOLT_REPO".to_owned(), name.clone()),
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
        // onto refs/changes/<number>/<revision>, and its tags onto
        // refs/tags/<name>.
        reconcile_change_refs(&app, &name).await;
        if reconcile_tag_refs(&app, &name).await {
            mirror_default_branch(&app, &name).await;
        }
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

/// The push token's life: issued before receive-pack, ended when the
/// handler is done with it — by answering, by failing, or by being
/// dropped when the pusher hung up.
struct PushInFlight {
    app: AppState,
    secret: String,
}

impl Drop for PushInFlight {
    fn drop(&mut self) {
        self.app.end_push(&self.secret);
    }
}

/// `refs/changes/<n>/<rev>` is a projection of the graph onto git,
/// maintained by reconciliation: create whatever refs the graph says
/// should exist and git doesn't have yet. Idempotent, so a ref missed
/// by a failed push heals on the next one. proc-receive cannot create
/// these refs itself — ref updates are forbidden while pushed objects
/// sit in quarantine.
pub(crate) async fn reconcile_change_refs(app: &AppState, repo: &str) {
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
    /// Task trailer, when the commit carries one: the attempt this is.
    #[serde(default)]
    pub task: Option<String>,
}

/// What the proc-receive hook reports about one push: every new commit
/// between the target branch and the pushed tip.
#[derive(Deserialize)]
pub struct RecordPush {
    pub repo: String,
    pub target: String,
    pub commits: Vec<PushedCommit>,
}

/// What the proc-receive hook reports about one pushed tag: the name
/// and the commit it resolves to, on a branch of the repository.
#[derive(Deserialize)]
pub struct RecordTag {
    pub repo: String,
    pub name: String,
    pub commit_oid: String,
    /// The annotated tag object, when there is one.
    #[serde(default)]
    pub object_oid: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
}

/// Enter a pushed tag into the graph. The hook has checked that the
/// commit is on a branch; the store checks who may give names here and
/// that the name is new. The ref itself is written once receive-pack
/// has finished, by [`reconcile_tag_refs`].
pub async fn record_tag(
    State(app): State<AppState>,
    pusher: crate::auth::Pusher,
    Json(body): Json<RecordTag>,
) -> ApiResult<Json<Value>> {
    this_push(&pusher, &body.repo)?;
    // A tag names landed history. The hook checks this in the
    // repository it is running in; asked again here, so that the rule
    // does not live only in the hook.
    let git = git_enabled(&app)?;
    if !git.store.on_a_branch(&body.repo, &body.commit_oid).await? {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid",
            format!(
                "tag {}: {} is on no branch, and a tag names landed history",
                body.name, body.commit_oid
            ),
        ));
    }
    let env = app.with_store(|s| {
        s.acting_as(pusher.scope.as_ref()).push_tag(
            &pusher.principal,
            &body.repo,
            &body.name,
            &body.commit_oid,
            body.object_oid.as_deref(),
            body.message.as_deref(),
        )
    })?;
    app.publish(&env);
    Ok(committed(None, &env))
}

/// `refs/tags/<name>` is a projection of the graph onto git, like the
/// change refs: create whatever the graph says exists and git lacks.
/// Returns whether anything was created, so the caller can send the new
/// names outward without waiting for the next landing.
pub(crate) async fn reconcile_tag_refs(app: &AppState, repo: &str) -> bool {
    let Some(git) = app.git() else { return false };
    let wanted = match app.with_store(|s| s.tags(repo)) {
        Ok(wanted) => wanted,
        Err(err) => {
            tracing::warn!(%err, repo, "listing tags for ref reconciliation failed");
            return false;
        }
    };
    let existing: HashSet<String> = match git.store.list_refs(repo, "refs/tags/").await {
        Ok(refs) => refs.into_iter().map(|(name, _)| name).collect(),
        Err(err) => {
            tracing::warn!(%err, repo, "listing tag refs failed");
            return false;
        }
    };
    let mut created = false;
    for tag in wanted {
        let refname = format!("refs/tags/{}", tag.name);
        if existing.contains(&refname) {
            continue;
        }
        let oid = tag.object_oid.as_deref().unwrap_or(&tag.commit_oid);
        match git.store.set_ref(repo, &refname, oid).await {
            Ok(()) => created = true,
            Err(err) => tracing::warn!(%err, %refname, repo, "tag ref not creatable yet"),
        }
    }
    created
}

/// Send the repository's default branch, and with it its tags, to the
/// mirror now rather than at the next landing.
async fn mirror_default_branch(app: &AppState, repo: &str) {
    let Some(git) = app.git() else { return };
    let Ok(Some(record)) = app.with_store(|s| s.repo(repo)) else {
        return;
    };
    let Ok(Some(tip)) = git.store.tip(repo, &record.default_branch).await else {
        return;
    };
    crate::queue::mirror_branch(app, repo, &record.default_branch, &tip).await;
}

/// Whether this owner has room for `arriving` more bytes.
///
/// Checked against the last measurement plus what is on the wire, which
/// is what can be known before anything is stored. A pack expands when
/// it lands, so this is a floor rather than the true cost — but git is
/// told to keep a pushed pack packed, so the two are close, and the
/// alternative is finding out after the bytes are permanent.
pub(crate) fn room_on_disk(
    app: &AppState,
    repo: &str,
    arriving: u64,
    elsewhere: u64,
) -> ApiResult<()> {
    app.with_store(|s| {
        let Some(record) = s.repo(repo)? else {
            return Ok(());
        };
        let Some(limit) = s.quota(&record.owner)?.disk else {
            return Ok(());
        };
        let used = s.usage(&record.owner)?.disk;
        if used.saturating_add(elsewhere).saturating_add(arriving) <= limit {
            return Ok(());
        }
        let others = if elsewhere > 0 {
            format!(
                ", {} more is arriving in other pushes",
                crate::in_bytes(elsewhere)
            )
        } else {
            String::new()
        };
        Err(ApiError::new(
            StatusCode::CONFLICT,
            "over_quota",
            format!(
                "{} is using {} of git storage{others} and this push carries {}, and this forge allows {}",
                record.owner,
                crate::in_bytes(used),
                crate::in_bytes(arriving),
                crate::in_bytes(limit)
            ),
        ))
    })
}

/// Measure a repository when this goes out of scope, however it goes.
///
/// A fetch that failed or timed out has still written objects, and the
/// number has to follow what is there rather than what was intended.
pub(crate) struct MeasureOnDrop {
    app: AppState,
    repo: String,
}

impl MeasureOnDrop {
    pub(crate) fn new(app: &AppState, repo: &str) -> Self {
        MeasureOnDrop {
            app: app.clone(),
            repo: repo.to_owned(),
        }
    }
}

impl Drop for MeasureOnDrop {
    fn drop(&mut self) {
        let app = self.app.clone();
        let repo = std::mem::take(&mut self.repo);
        tokio::spawn(async move { remember_size(&app, &repo).await });
    }
}

/// How long one measurement may take before the last number stands.
const MEASURE_WITHIN: std::time::Duration = std::time::Duration::from_secs(60);

/// Measure what a repository takes on disk and remember it, so an
/// owner's page and their disk quota have a number to work from.
///
/// After the objects arrive rather than before: what a push will cost
/// is not knowable until it is unpacked, so the forge charges for what
/// is there and refuses the *next* push from an owner already over.
pub(crate) async fn remember_size(app: &AppState, repo: &str) {
    let Some(git) = app.git() else { return };
    // What a dead push left in quarantine is nobody's: swept before the
    // count, so that it is neither charged to the owner nor kept.
    match git.store.sweep_quarantines(repo).await {
        Ok(0) | Err(_) => {}
        Ok(swept) => tracing::info!(repo, swept, "removed quarantines no push was using"),
    }
    // Bounded, because a walk with no bound pins a thread on a stalled
    // disk forever, and the landing train waits behind it.
    let measured = match tokio::time::timeout(MEASURE_WITHIN, git.store.size(repo)).await {
        Ok(measured) => measured,
        Err(_) => {
            tracing::warn!(repo, "measuring took too long; keeping the last number");
            return;
        }
    };
    match measured {
        Ok(bytes) => {
            if let Err(err) = app.with_store(|s| s.record_repo_size(repo, bytes)) {
                tracing::warn!(error = %err, repo, "could not remember a repository's size");
            }
        }
        Err(err) => tracing::warn!(error = %err, repo, "could not measure a repository"),
    }
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
    actor: crate::auth::Pusher,
    Json(body): Json<RecordPush>,
) -> ApiResult<Json<Value>> {
    this_push(&actor, &body.repo)?;
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
    let mut parent: Option<ambolt_core::ChangeId> = None;
    let mut last_seq = 0i64;
    for commit in &body.commits {
        let existing = match &commit.change_id {
            Some(key) => app.with_store(|s| {
                s.acting_as(actor.scope.as_ref())
                    .change_by_key(&body.repo, key)
            })?,
            None => None,
        };
        // An attempt at a task that already has an open change is a
        // revision of that change, whoever pushed it.
        let task = commit
            .task
            .as_deref()
            .map(|t| ambolt_core::TaskId(t.to_owned()));
        let existing = match (existing, &task) {
            (Some(change), _) => Some(change),
            (None, Some(task)) => app
                .with_store(|s| s.acting_as(actor.scope.as_ref()).open_change_for_task(task))?
                .filter(|c| c.repo == body.repo && c.target == body.target),
            (None, None) => None,
        };
        // The pusher's live session on that task, so the revision says
        // which attempt it came from.
        let session = match &task {
            Some(task) => app
                .with_store(|s| s.acting_as(actor.scope.as_ref()).sessions_for_task(task))?
                .into_iter()
                .find(|s| {
                    s.agent == actor.principal && s.state == ambolt_core::SessionState::Active
                })
                .map(|s| s.id),
            None => None,
        };
        let (change, number, created) = match existing {
            Some(change) if change.state == ChangeState::Open && change.target == body.target => {
                let unchanged = app
                    .with_store(|s| s.acting_as(actor.scope.as_ref()).revisions(&change.id))?
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
                let spec = ambolt_core::ChangeSpec {
                    external_key: commit.change_id.clone(),
                    parent_change: parent.clone(),
                    task: task.clone(),
                    ..ambolt_core::ChangeSpec::new(&body.repo, &body.target, &commit.title)
                };
                let (id, number, env) = app.with_store(|s| {
                    s.acting_as(actor.scope.as_ref())
                        .open_change(&actor.principal, spec)
                })?;
                app.publish(&env);
                (id, number, true)
            }
        };
        // What the commit touched is a fact about the revision worth
        // keeping; failing to list it costs the revision its paths, not
        // the push.
        let paths = match app.git() {
            Some(git) => git
                .store
                .changed_paths(&body.repo, &commit.commit_oid)
                .await
                .unwrap_or_else(|err| {
                    tracing::warn!(error = %err, "could not list the paths a commit touched");
                    Vec::new()
                }),
            None => Vec::new(),
        };
        let (revision, pushed) = app.with_store(|s| {
            s.acting_as(actor.scope.as_ref());
            s.push_revision_with_paths(
                &actor.principal,
                &change,
                &commit.commit_oid,
                session.as_ref(),
                &commit.message,
                paths,
            )
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
    change_id: &ambolt_core::ChangeId,
) -> ApiResult<Json<Value>> {
    let git = git_enabled(app)?;
    let change = app
        .with_store(|s| s.change(change_id))?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "not_found", "change not found"))?;
    let revisions = app.with_store(|s| s.revisions(change_id))?;
    let judged = change.judged_revision();
    let Some(revision) = revisions.iter().find(|r| r.number == judged) else {
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
    crate::receipts::attach(app, &change.repo, &change.id, &revision.commit_oid).await;
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
    actor: Actor,
    RepoName(repo): RepoName,
    axum::extract::Query(query): axum::extract::Query<BlameQuery>,
) -> ApiResult<Json<Value>> {
    let git = git_enabled(&app)?;
    let record = app
        .with_store(|s| s.readable(&actor.0, &repo))?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "not_found", "repo not found"))?;
    let rev = format!("refs/heads/{}", record.default_branch);
    let oids = git.store.blame_lines(&repo, &rev, &query.path).await?;

    let mut known: HashMap<String, Option<ambolt_core::Provenance>> = HashMap::new();
    let mut states: std::collections::BTreeMap<&'static str, usize> = Default::default();
    let mut lines = Vec::with_capacity(oids.len());
    for (index, oid) in oids.iter().enumerate() {
        if !known.contains_key(oid) {
            known.insert(
                oid.clone(),
                app.with_store(|s| s.provenance_of(&repo, oid))?,
            );
        }
        let provenance = known.get(oid).and_then(Option::as_ref);
        let state = ambolt_core::line_state(provenance);
        *states.entry(state.as_str()).or_insert(0usize) += 1;
        lines.push(json!({
            "line": index + 1,
            "commit": oid,
            "change": provenance.map(|p| p.change.number),
            "state": state.as_str(),
            "executed_check": provenance.map(|p| p.executed_check()),
            "unchecked": provenance.map(|p| p.unchecked()).unwrap_or_default(),
        }));
    }
    let unverified = lines
        .iter()
        .filter(|l| l["executed_check"] == Value::Bool(false))
        .count();
    let debt = lines.iter().filter(|l| l["state"] != "reproduced").count();
    Ok(Json(json!({
        "path": query.path,
        "lines": lines,
        "unverified_lines": unverified,
        "states": states,
        "debt_lines": debt,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn gzipped(bytes: &[u8]) -> Bytes {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        encoder.write_all(bytes).unwrap();
        Bytes::from(encoder.finish().unwrap())
    }

    fn gzip_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_ENCODING, "gzip".parse().unwrap());
        headers
    }

    /// A small gzip body can name a very large one. Reading it to the
    /// end would be this process's memory, so the ceiling is the same
    /// whether a client compressed its request or not.
    #[test]
    fn a_compressed_body_cannot_expand_past_the_ceiling() {
        let enormous = vec![0u8; 64 * 1024];
        let body = gzipped(&enormous);
        assert!(
            body.len() < 1024,
            "the point of the test is that the body is small: {}",
            body.len()
        );
        let refused = match unpacked(&gzip_headers(), body.clone(), 1024) {
            Err(refused) => refused,
            Ok(_) => panic!("a body that expands past the ceiling must be refused"),
        };
        assert_eq!(refused.status, StatusCode::PAYLOAD_TOO_LARGE);
        // And a body that fits still arrives whole.
        let ordinary = unpacked(&gzip_headers(), gzipped(b"hello"), 1024)
            .unwrap_or_else(|_| panic!("a small body is allowed"));
        assert_eq!(ordinary, b"hello");
        // Exactly at the ceiling is not past it.
        let exact = vec![7u8; 1024];
        let allowed = unpacked(&gzip_headers(), gzipped(&exact), 1024)
            .unwrap_or_else(|_| panic!("exactly at the ceiling is allowed"));
        assert_eq!(allowed.len(), 1024);
    }
}
