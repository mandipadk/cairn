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
use cairn_core::{LineState, Provenance, line_state};
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

#[derive(Clone, Debug, Serialize)]
pub struct FileDebt {
    pub path: String,
    pub counts: Counts,
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
    let mut counts = Counts::default();
    let mut files = Vec::new();
    let mut skipped = 0;
    let mut known = HashMap::new();
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
            let states = file_states(app, repo, &rev, &path, &mut known).await?;
            let mut file = Counts::default();
            for state in states {
                file.add(state);
            }
            counts.merge(&file);
            files.push(FileDebt { path, counts: file });
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
    let map = Arc::new(DebtMap {
        repo: repo.to_owned(),
        branch: branch.to_owned(),
        tip,
        counts,
        files,
        skipped,
    });
    app.debt_cache().put(repo, map.clone());
    Ok(map)
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
