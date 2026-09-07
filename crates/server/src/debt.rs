//! The verification-debt map: what backs every line of a repository,
//! rolled up by file and for the whole.
//!
//! Coverage tools count lines a test touched. This counts lines by what
//! the log knows about the change that landed them: a runner reproduced
//! the claim, the author ran something, a claim named a gap, only an
//! argument was made, or the line predates the forge. "27% coverage"
//! becomes "these lines shipped on a promise", by file.

use crate::auth::MaybeActor;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use cairn_core::{
    Cover, DebtSnapshot, LineState, PrincipalId, Provenance, line_state, path_matches,
};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Files above this are not blamed; a map is for code people read.
const MAX_BLAMED_FILE: u64 = 1_000_000;
/// A map is recomputed when the branch tip moves, and at least this often.
const FRESH_FOR: Duration = Duration::from_secs(600);

#[derive(Clone, Debug, Serialize, Default)]
pub struct Counts {
    pub reproduced: usize,
    pub claimed: usize,
    pub gap: usize,
    pub argued: usize,
    pub imported: usize,
}

impl Counts {
    fn add(&mut self, state: LineState) {
        match state {
            LineState::Reproduced => self.reproduced += 1,
            LineState::Claimed => self.claimed += 1,
            LineState::Gap => self.gap += 1,
            LineState::Argued => self.argued += 1,
            LineState::Imported => self.imported += 1,
        }
    }

    fn merge(&mut self, other: &Counts) {
        self.reproduced += other.reproduced;
        self.claimed += other.claimed;
        self.gap += other.gap;
        self.argued += other.argued;
        self.imported += other.imported;
    }

    pub fn total(&self) -> usize {
        self.reproduced + self.claimed + self.gap + self.argued + self.imported
    }

    /// Lines short of a reproduced claim.
    pub fn debt(&self) -> usize {
        self.total() - self.reproduced
    }
}

/// A covering claim as it bears on one file.
#[derive(Clone, Debug, Serialize)]
pub struct CoverRef {
    pub change: i64,
    pub claim: String,
    pub by: String,
    /// A third-party runner reproduced it; only then does it move lines.
    pub reproduced: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct FileDebt {
    pub path: String,
    pub counts: Counts,
    /// Covering claims on landed changes that name this file.
    #[serde(default)]
    pub covered_by: Vec<CoverRef>,
    /// An open task to pay this file down, and who holds it.
    #[serde(default)]
    pub task: Option<(String, Vec<String>)>,
}

/// Lines a principal's reproduced covering claims moved out of debt.
#[derive(Clone, Debug, Serialize, Default)]
pub struct PaidDown {
    pub by: String,
    pub lines: usize,
    pub files: usize,
    pub claims: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct DebtMap {
    pub repo: String,
    pub branch: String,
    /// The commit the map describes; a moved tip means a new map.
    pub tip: String,
    pub counts: Counts,
    /// Every text file, most debt first.
    pub files: Vec<FileDebt>,
    /// Files skipped as binary or too large.
    pub skipped: usize,
    /// Who paid down what, most lines first.
    #[serde(default)]
    pub paid_down: Vec<PaidDown>,
}

/// One map per repository, kept while the branch tip stands still.
#[derive(Default)]
pub struct Cache {
    maps: std::sync::Mutex<HashMap<String, (Instant, Arc<DebtMap>)>>,
}

impl Cache {
    fn get(&self, repo: &str, tip: &str) -> Option<Arc<DebtMap>> {
        let maps = self.maps.lock().unwrap_or_else(|p| p.into_inner());
        maps.get(repo)
            .filter(|(at, map)| map.tip == tip && at.elapsed() < FRESH_FOR)
            .map(|(_, map)| map.clone())
    }

    fn put(&self, repo: &str, map: Arc<DebtMap>) {
        self.maps
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(repo.to_owned(), (Instant::now(), map));
    }

    /// Drop a repository's map so the next look recomputes it.
    pub(crate) fn forget(&self, repo: &str) {
        self.maps
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(repo);
    }
}

/// The state of every line of one file, from its blame.
pub async fn file_states(
    app: &AppState,
    repo: &str,
    rev: &str,
    path: &str,
    known: &mut HashMap<String, Option<Arc<Provenance>>>,
) -> Result<Vec<LineState>, cairn_git::GitError> {
    let git = app.git().expect("a git store when mapping debt");
    let oids = git.store.blame_lines(repo, rev, path).await?;
    let mut states = Vec::with_capacity(oids.len());
    for oid in &oids {
        if !known.contains_key(oid) {
            let found = app
                .with_store(|s| s.provenance_of(repo, oid))
                .ok()
                .flatten()
                .map(Arc::new);
            known.insert(oid.clone(), found);
        }
        states.push(line_state(known[oid].as_deref()));
    }
    Ok(states)
}

/// Map a repository's default branch, or hand back the map already made
/// for the same tip.
pub async fn map(app: &AppState, repo: &str, branch: &str) -> Result<Arc<DebtMap>, ApiError> {
    let git = app
        .git()
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "not_found", "git hosting is off"))?;
    let rev = format!("refs/heads/{branch}");
    let tip = git.store.tip(repo, branch).await?.unwrap_or_default();
    if let Some(map) = app.debt_cache().get(repo, &tip) {
        return Ok(map);
    }
    let covers = app.with_store(|s| s.covers(repo))?;
    // Open pay-down tasks, by the file they name.
    let open_tasks: Vec<(String, Vec<String>)> = app
        .with_store(|s| s.tasks(None))?
        .into_iter()
        .filter(|t| t.repo.as_deref() == Some(repo))
        .filter(|t| {
            matches!(
                t.state,
                cairn_core::TaskState::Open | cairn_core::TaskState::Claimed
            )
        })
        .filter_map(|t| {
            t.title.strip_prefix("Verify ").map(|path| {
                (
                    path.to_owned(),
                    t.claimants.iter().map(|c| c.as_str().to_owned()).collect(),
                )
            })
        })
        .collect();
    let mut counts = Counts::default();
    let mut files = Vec::new();
    let mut skipped = 0;
    let mut known = HashMap::new();
    let mut paid: Vec<(String, PaidDown, Vec<String>)> = Vec::new();
    if !tip.is_empty() {
        for path in git.store.list_files(repo, &rev).await? {
            let text = match git.store.show_file(repo, &rev, &path).await? {
                Some(bytes) if bytes.len() as u64 <= MAX_BLAMED_FILE && !bytes.contains(&0) => {
                    bytes
                }
                _ => {
                    skipped += 1;
                    continue;
                }
            };
            if text.is_empty() {
                continue;
            }
            let mut states = file_states(app, repo, &rev, &path, &mut known).await?;
            // A reproduced covering claim backs every line of the file,
            // whatever landed it; the lines it moved are credited to its
            // author. A cover nobody re-ran is shown and moves nothing.
            let applicable: Vec<&Cover> = covers
                .iter()
                .filter(|c| path_matches(&c.pattern, &path))
                .collect();
            if let Some(cover) = applicable.iter().find(|c| c.reproduced) {
                let moved = states
                    .iter()
                    .filter(|s| **s != LineState::Reproduced)
                    .count();
                if moved > 0 {
                    let by = cover.by.as_str().to_owned();
                    let entry = match paid.iter_mut().find(|(who, _, _)| *who == by) {
                        Some(entry) => entry,
                        None => {
                            paid.push((
                                by.clone(),
                                PaidDown {
                                    by,
                                    ..PaidDown::default()
                                },
                                Vec::new(),
                            ));
                            paid.last_mut().expect("just pushed")
                        }
                    };
                    entry.1.lines += moved;
                    entry.1.files += 1;
                    if !entry.2.contains(&cover.claim.0) {
                        entry.2.push(cover.claim.0.clone());
                        entry.1.claims += 1;
                    }
                }
                states.fill(LineState::Reproduced);
            }
            let mut file = Counts::default();
            for state in states {
                file.add(state);
            }
            counts.merge(&file);
            let mut covered_by: Vec<CoverRef> = Vec::new();
            for cover in &applicable {
                if !covered_by.iter().any(|c| c.claim == cover.claim.0) {
                    covered_by.push(CoverRef {
                        change: cover.number,
                        claim: cover.claim.0.clone(),
                        by: cover.by.as_str().to_owned(),
                        reproduced: cover.reproduced,
                    });
                }
            }
            let task = open_tasks
                .iter()
                .find(|(named, _)| *named == path)
                .map(|(named, holders)| (named.clone(), holders.clone()));
            files.push(FileDebt {
                path,
                counts: file,
                covered_by,
                task,
            });
        }
    }
    // Most debt first; among equals, the bigger file, then the name.
    files.sort_by(|a, b| {
        b.counts
            .debt()
            .cmp(&a.counts.debt())
            .then_with(|| b.counts.total().cmp(&a.counts.total()))
            .then_with(|| a.path.cmp(&b.path))
    });
    let mut paid_down: Vec<PaidDown> = paid.into_iter().map(|(_, p, _)| p).collect();
    paid_down.sort_by(|a, b| b.lines.cmp(&a.lines).then_with(|| a.by.cmp(&b.by)));
    let map = Arc::new(DebtMap {
        repo: repo.to_owned(),
        branch: branch.to_owned(),
        tip: tip.clone(),
        counts,
        files,
        skipped,
        paid_down,
    });
    app.debt_cache().put(repo, map.clone());
    // Every tip the map was drawn at is a point on the burndown.
    if !tip.is_empty() {
        let seq = app
            .with_store(|s| s.latest_seq())
            .map(|s| s.0)
            .unwrap_or_default();
        let snapshot = DebtSnapshot {
            tip,
            seq,
            at: jiff::Timestamp::now().to_string(),
            reproduced: map.counts.reproduced as i64,
            claimed: map.counts.claimed as i64,
            gap: map.counts.gap as i64,
            argued: map.counts.argued as i64,
            imported: map.counts.imported as i64,
        };
        if let Err(err) = app.with_store(|s| s.record_debt_snapshot(repo, &snapshot)) {
            tracing::warn!(error = %err, repo, "debt: could not record the snapshot");
        }
    }
    Ok(map)
}

#[derive(serde::Deserialize)]
pub struct HistoryQuery {
    pub limit: Option<i64>,
}

/// `GET /api/repos/{name}/debt/history`: the burndown, oldest first.
pub async fn history(
    State(app): State<AppState>,
    who: MaybeActor,
    Path(repo): Path<String>,
    axum::extract::Query(query): axum::extract::Query<HistoryQuery>,
) -> ApiResult<Json<Value>> {
    crate::routes::readable_repo_by(&app, &who, &repo)?;
    let points =
        app.with_store(|s| s.debt_history(&repo, query.limit.unwrap_or(120).clamp(1, 1000)))?;
    Ok(Json(json!(points)))
}

#[derive(serde::Deserialize)]
pub struct PayDownBody {
    /// How many of the most indebted files to make tasks for; 5 when absent.
    pub count: Option<usize>,
}

/// What a pay-down task asks for, in words an agent can act on.
fn pay_down_spec(file: &FileDebt) -> String {
    let c = &file.counts;
    format!(
        "Pay down the verification debt on {path}: {debt} of {total} lines are short of a \
         runner-reproduced claim ({imported} imported and never judged here, {gap} under a \
         declared gap, {claimed} claimed but never re-run, {argued} argued only).\n\n\
         Write or extend a check that exercises {path}, push it as a change, and attach a \
         claim whose command a runner can re-run, with \"covers\": [\"{path}\"]. When a \
         third-party runner reproduces it and the change lands, every line of {path} is \
         backed by your claim and this task is done.",
        path = file.path,
        debt = c.debt(),
        total = c.total(),
        imported = c.imported,
        gap = c.gap,
        claimed = c.claimed,
        argued = c.argued
    )
}

/// Make a task per most indebted file without one. Owner or admin.
pub async fn create_pay_down_tasks(
    app: &AppState,
    actor: &PrincipalId,
    repo: &str,
    count: usize,
) -> ApiResult<Vec<cairn_core::TaskId>> {
    let record = app
        .with_store(|s| s.repo(repo))?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "not_found", "repo not found"))?;
    if record.owner != *actor && !app.with_store(|s| s.is_admin(actor)) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "forbidden",
            "only the repository's owner or an admin turns debt into tasks",
        ));
    }
    let map = map(app, repo, &record.default_branch).await?;
    let mut created = Vec::new();
    for file in map
        .files
        .iter()
        .filter(|f| f.counts.debt() > 0 && f.task.is_none())
        .take(count.clamp(1, 50))
    {
        let (task, env) = app.with_store(|s| {
            s.create_task_with_attempts(
                actor,
                Some(repo),
                &format!("Verify {}", file.path),
                &pay_down_spec(file),
                None,
                1,
            )
        })?;
        app.publish(&env);
        created.push(task);
    }
    // The map named files without tasks; now they have them.
    app.debt_cache().forget(repo);
    Ok(created)
}

/// `POST /api/repos/{name}/debt/tasks`
pub async fn pay_down(
    State(app): State<AppState>,
    actor: crate::auth::Actor,
    Path(repo): Path<String>,
    Json(body): Json<PayDownBody>,
) -> ApiResult<Json<Value>> {
    let created = create_pay_down_tasks(&app, &actor.0, &repo, body.count.unwrap_or(5)).await?;
    Ok(Json(json!({ "tasks": created })))
}

/// `GET /api/repos/{name}/debt`
pub async fn debt(
    State(app): State<AppState>,
    who: MaybeActor,
    Path(repo): Path<String>,
) -> ApiResult<Json<Value>> {
    let record = crate::routes::readable_repo_by(&app, &who, &repo)?;
    let map = map(&app, &repo, &record.default_branch).await?;
    Ok(Json(json!(*map)))
}
