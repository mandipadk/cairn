//! Search across what people look for by name, ranked so the best answer
//! is first and every ranking can say why.
//!
//! The query is plain words plus the `key:value` filters everybody
//! already types into a forge: `kind:change`, `repo:demo`, `state:open`,
//! `by:scout`. A bare `#12` finds a change by number. Lessons are
//! searched too, because "has anyone tried this before?" is the question
//! an agent should ask first and it deserves the same box.

use crate::error::CoreResult;
use crate::id::PrincipalId;
use crate::store::Store;
use crate::types::ChangeState;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HitKind {
    Repository,
    Change,
    Task,
    Lesson,
    Person,
}

impl HitKind {
    pub fn as_str(self) -> &'static str {
        match self {
            HitKind::Repository => "repository",
            HitKind::Change => "change",
            HitKind::Task => "task",
            HitKind::Lesson => "lesson",
            HitKind::Person => "person",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "repo" | "repository" | "repositories" => HitKind::Repository,
            "change" | "changes" => HitKind::Change,
            "task" | "tasks" => HitKind::Task,
            "lesson" | "lessons" => HitKind::Lesson,
            "person" | "people" | "principal" => HitKind::Person,
            _ => return None,
        })
    }
}

/// A parsed query: the words, and the filters pulled out of them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SearchQuery {
    pub words: Vec<String>,
    pub kind: Option<HitKind>,
    pub repo: Option<String>,
    pub state: Option<ChangeState>,
    pub by: Option<String>,
    /// A bare `#12`, which means one change and nothing else.
    pub number: Option<i64>,
}

impl SearchQuery {
    pub fn parse(raw: &str) -> Self {
        let mut query = SearchQuery::default();
        for token in raw.split_whitespace() {
            let lower = token.to_lowercase();
            if let Some((key, value)) = lower.split_once(':')
                && !value.is_empty()
            {
                match key {
                    "kind" | "is" | "type" => {
                        if let Some(kind) = HitKind::parse(value) {
                            query.kind = Some(kind);
                            continue;
                        }
                    }
                    "repo" | "in" => {
                        query.repo = Some(value.to_owned());
                        continue;
                    }
                    "state" => {
                        if let Some(state) = ChangeState::parse(value) {
                            query.state = Some(state);
                            continue;
                        }
                    }
                    "by" | "author" | "owner" => {
                        query.by = Some(value.to_owned());
                        continue;
                    }
                    _ => {}
                }
            }
            if let Some(number) = lower.strip_prefix('#').and_then(|n| n.parse().ok()) {
                query.number = Some(number);
                continue;
            }
            query.words.push(lower);
        }
        query
    }

    /// Whether there is anything to look for at all.
    pub fn is_empty(&self) -> bool {
        self.words.is_empty()
            && self.number.is_none()
            && self.kind.is_none()
            && self.repo.is_none()
            && self.state.is_none()
            && self.by.is_none()
    }

    fn wants(&self, kind: HitKind) -> bool {
        self.kind.is_none_or(|k| k == kind)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchHit {
    pub kind: HitKind,
    pub title: String,
    pub detail: String,
    pub repo: Option<String>,
    pub number: Option<i64>,
    pub principal: Option<PrincipalId>,
    pub score: i64,
    /// Why it ranked where it did, in a few words.
    pub why: &'static str,
}

/// How well a haystack answers the words, and in what way. Exact beats
/// prefix beats a whole word beats a fragment; all words must appear.
fn matched(words: &[String], haystack: &str) -> Option<(i64, &'static str)> {
    if words.is_empty() {
        return Some((0, "filter"));
    }
    let hay = haystack.to_lowercase();
    let joined = words.join(" ");
    if hay == joined {
        return Some((100, "exact"));
    }
    if hay.starts_with(&joined) {
        return Some((60, "starts with it"));
    }
    let mut score = 0;
    for word in words {
        if hay.split(|c: char| !c.is_alphanumeric()).any(|w| w == word) {
            score += 40;
        } else if hay.contains(word.as_str()) {
            score += 20;
        } else {
            return None;
        }
    }
    Some((
        score / words.len() as i64,
        if score >= 40 { "word" } else { "fragment" },
    ))
}

impl Store {
    /// Everything this principal may see that answers the query, best
    /// first. Bounded, because a search is a question and not an export.
    pub fn search(
        &self,
        who: &PrincipalId,
        query: &SearchQuery,
        limit: usize,
    ) -> CoreResult<Vec<SearchHit>> {
        let mut hits = Vec::new();
        if query.is_empty() {
            return Ok(hits);
        }
        let repos = self.readable_repos(who)?;
        let in_scope = |name: &str| query.repo.as_deref().is_none_or(|r| r == name);

        for repo in repos.iter().filter(|r| in_scope(&r.name)) {
            if query.wants(HitKind::Repository)
                && query.number.is_none()
                && query.by.is_none()
                && query.state.is_none()
                && let Some((score, why)) = matched(&query.words, &repo.name)
            {
                hits.push(SearchHit {
                    kind: HitKind::Repository,
                    title: repo.name.clone(),
                    detail: repo.default_branch.clone(),
                    repo: Some(repo.name.clone()),
                    number: None,
                    principal: None,
                    score: score + 5,
                    why,
                });
            }

            if query.wants(HitKind::Change) {
                for change in self.changes_in_repo(&repo.name)? {
                    if query.state.is_some_and(|s| s != change.state) {
                        continue;
                    }
                    if query
                        .by
                        .as_deref()
                        .is_some_and(|by| by != change.owner.as_str())
                    {
                        continue;
                    }
                    let (score, why) = match query.number {
                        Some(n) if n == change.number => (100, "that number"),
                        Some(_) => continue,
                        None => match matched(&query.words, &change.title) {
                            Some(m) => m,
                            None => continue,
                        },
                    };
                    // Open work is what somebody is more likely after;
                    // among equals, newer first.
                    let standing = match change.state {
                        ChangeState::Open => 10,
                        ChangeState::Merged => 5,
                        ChangeState::Abandoned => 0,
                    };
                    hits.push(SearchHit {
                        kind: HitKind::Change,
                        title: change.title.clone(),
                        detail: format!(
                            "{} #{} · {} · {}",
                            repo.name,
                            change.number,
                            change.state.as_str(),
                            change.owner.as_str()
                        ),
                        repo: Some(repo.name.clone()),
                        number: Some(change.number),
                        principal: Some(change.owner.clone()),
                        score: score + standing,
                        why,
                    });
                }
            }
        }

        if query.wants(HitKind::Task) && query.number.is_none() && query.state.is_none() {
            for task in self.tasks(None)? {
                let readable = match &task.repo {
                    Some(repo) => in_scope(repo) && repos.iter().any(|r| &r.name == repo),
                    None => query.repo.is_none(),
                };
                if !readable {
                    continue;
                }
                if query
                    .by
                    .as_deref()
                    .is_some_and(|by| by != task.created_by.as_str())
                {
                    continue;
                }
                let Some((score, why)) = matched(&query.words, &task.title)
                    .or_else(|| matched(&query.words, &task.spec).map(|(s, w)| (s / 2, w)))
                else {
                    continue;
                };
                hits.push(SearchHit {
                    kind: HitKind::Task,
                    title: task.title.clone(),
                    detail: format!(
                        "{} · {}",
                        task.repo.as_deref().unwrap_or("forge-wide"),
                        task.state.as_str()
                    ),
                    repo: task.repo.clone(),
                    number: None,
                    principal: Some(task.created_by.clone()),
                    score,
                    why,
                });
            }
        }

        if query.wants(HitKind::Lesson)
            && !query.words.is_empty()
            && query.number.is_none()
            && query.state.is_none()
        {
            let needle = query.words.join(" ");
            for lesson in self.lessons(query.repo.as_deref(), Some(&needle), false, 50)? {
                let visible = match &lesson.repo {
                    Some(repo) => repos.iter().any(|r| &r.name == repo),
                    None => true,
                };
                if !visible {
                    continue;
                }
                if query
                    .by
                    .as_deref()
                    .is_some_and(|by| by != lesson.agent.as_str())
                {
                    continue;
                }
                let (score, why) = matched(&query.words, &lesson.outcome)
                    .or_else(|| matched(&query.words, &lesson.task_title))
                    .unwrap_or((10, "fragment"));
                hits.push(SearchHit {
                    kind: HitKind::Lesson,
                    title: lesson.outcome.clone(),
                    detail: format!("{} · {}", lesson.task_title, lesson.agent.as_str()),
                    repo: lesson.repo.clone(),
                    number: None,
                    principal: Some(lesson.agent.clone()),
                    score,
                    why,
                });
            }
        }

        if query.wants(HitKind::Person)
            && query.number.is_none()
            && query.repo.is_none()
            && query.state.is_none()
        {
            for principal in self.principals()? {
                if query
                    .by
                    .as_deref()
                    .is_some_and(|by| by != principal.id.as_str())
                {
                    continue;
                }
                let Some((score, why)) = matched(&query.words, principal.id.as_str())
                    .or_else(|| matched(&query.words, &principal.display))
                else {
                    continue;
                };
                hits.push(SearchHit {
                    kind: HitKind::Person,
                    title: principal.display.clone(),
                    detail: format!("{} · {}", principal.id.as_str(), principal.kind.as_str()),
                    repo: None,
                    number: None,
                    principal: Some(principal.id.clone()),
                    score,
                    why,
                });
            }
        }

        hits.sort_by(|a, b| {
            b.score
                .cmp(&a.score)
                .then_with(|| b.number.cmp(&a.number))
                .then_with(|| a.title.cmp(&b.title))
        });
        hits.truncate(limit.min(200));
        Ok(hits)
    }
}
