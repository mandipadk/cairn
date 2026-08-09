//! Read side of the graph. All row-mapping lives here.
//!
//! The `raw` functions take `&Connection` so they work both on the store
//! itself and inside a command's transaction (`Transaction` derefs to
//! `Connection`), keeping validation and public reads on one code path.

use crate::error::{CoreError, CoreResult};
use crate::id::{ChangeId, PrincipalId, SessionId, TaskId};
use crate::store::Store;
use crate::types::{
    Change, ChangeState, Claim, ClaimKind, Disposition, Principal, PrincipalKind, Repo,
    ReviewDomain, Revision, Session, SessionState, Task, TaskState, Verdict,
};
use rusqlite::{Connection, OptionalExtension, Row, params};

fn corrupt(at: &str, reason: impl std::fmt::Display) -> CoreError {
    CoreError::Corrupt {
        at: at.to_owned(),
        reason: reason.to_string(),
    }
}

fn parsed<T>(at: &str, value: &str, parse: impl Fn(&str) -> Option<T>) -> CoreResult<T> {
    parse(value).ok_or_else(|| corrupt(at, format!("unrecognized value {value:?}")))
}

pub(crate) mod raw {
    use super::*;

    pub fn principal(conn: &Connection, id: &str) -> CoreResult<Option<Principal>> {
        conn.prepare_cached(
            "SELECT id, kind, display, model, harness FROM principals WHERE id = ?",
        )?
        .query_row(params![id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
            ))
        })
        .optional()?
        .map(|(id, kind, display, model, harness)| {
            Ok(Principal {
                kind: parsed(&format!("principal {id}"), &kind, PrincipalKind::parse)?,
                id: PrincipalId(id),
                display,
                model,
                harness,
            })
        })
        .transpose()
    }

    pub fn repo(conn: &Connection, name: &str) -> CoreResult<Option<Repo>> {
        Ok(conn
            .prepare_cached("SELECT name, default_branch FROM repos WHERE name = ?")?
            .query_row(params![name], |row| {
                Ok(Repo {
                    name: row.get(0)?,
                    default_branch: row.get(1)?,
                })
            })
            .optional()?)
    }

    fn task_from_row(row: &Row) -> rusqlite::Result<(Task, String)> {
        let state: String = row.get(4)?;
        Ok((
            Task {
                id: TaskId(row.get(0)?),
                repo: row.get(1)?,
                title: row.get(2)?,
                spec: row.get(3)?,
                state: TaskState::Open, // corrected by caller from `state`
                parent: row.get::<_, Option<String>>(5)?.map(TaskId),
                claimed_by: row.get::<_, Option<String>>(6)?.map(PrincipalId),
                created_by: PrincipalId(row.get(7)?),
            },
            state,
        ))
    }

    const TASK_COLS: &str = "id, repo, title, spec, state, parent, claimed_by, created_by";

    pub fn task(conn: &Connection, id: &str) -> CoreResult<Option<Task>> {
        conn.prepare_cached(&format!("SELECT {TASK_COLS} FROM tasks WHERE id = ?"))?
            .query_row(params![id], task_from_row)
            .optional()?
            .map(|(mut task, state)| {
                task.state = parsed(&format!("task {id}"), &state, TaskState::parse)?;
                Ok(task)
            })
            .transpose()
    }

    pub fn tasks(conn: &Connection, state: Option<TaskState>) -> CoreResult<Vec<Task>> {
        let (sql, filter) = match state {
            Some(s) => (
                format!("SELECT {TASK_COLS} FROM tasks WHERE state = ? ORDER BY rowid"),
                Some(s.as_str()),
            ),
            None => (
                format!("SELECT {TASK_COLS} FROM tasks ORDER BY rowid"),
                None,
            ),
        };
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = match filter {
            Some(f) => stmt.query_map(params![f], task_from_row)?,
            None => stmt.query_map([], task_from_row)?,
        }
        .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|(mut task, state)| {
                task.state = parsed(&format!("task {}", task.id), &state, TaskState::parse)?;
                Ok(task)
            })
            .collect()
    }

    pub fn session(conn: &Connection, id: &str) -> CoreResult<Option<Session>> {
        conn.prepare_cached("SELECT id, task, agent, state, outcome FROM sessions WHERE id = ?")?
            .query_row(params![id], |row| {
                Ok((
                    Session {
                        id: SessionId(row.get(0)?),
                        task: TaskId(row.get(1)?),
                        agent: PrincipalId(row.get(2)?),
                        state: SessionState::Active,
                        outcome: row.get(4)?,
                    },
                    row.get::<_, String>(3)?,
                ))
            })
            .optional()?
            .map(|(mut session, state)| {
                session.state = parsed(&format!("session {id}"), &state, SessionState::parse)?;
                Ok(session)
            })
            .transpose()
    }

    const CHANGE_COLS: &str =
        "id, repo, number, target, title, task, parent_change, state, owner, latest_revision";

    fn change_from_row(row: &Row) -> rusqlite::Result<(Change, String)> {
        Ok((
            Change {
                id: ChangeId(row.get(0)?),
                repo: row.get(1)?,
                number: row.get(2)?,
                target: row.get(3)?,
                title: row.get(4)?,
                task: row.get::<_, Option<String>>(5)?.map(TaskId),
                parent_change: row.get::<_, Option<String>>(6)?.map(ChangeId),
                state: ChangeState::Open,
                owner: PrincipalId(row.get(8)?),
                latest_revision: row.get(9)?,
            },
            row.get::<_, String>(7)?,
        ))
    }

    fn finish_change((mut change, state): (Change, String)) -> CoreResult<Change> {
        change.state = parsed(&format!("change {}", change.id), &state, ChangeState::parse)?;
        Ok(change)
    }

    pub fn change(conn: &Connection, id: &str) -> CoreResult<Option<Change>> {
        conn.prepare_cached(&format!("SELECT {CHANGE_COLS} FROM changes WHERE id = ?"))?
            .query_row(params![id], change_from_row)
            .optional()?
            .map(finish_change)
            .transpose()
    }

    pub fn change_by_number(
        conn: &Connection,
        repo: &str,
        number: i64,
    ) -> CoreResult<Option<Change>> {
        conn.prepare_cached(&format!(
            "SELECT {CHANGE_COLS} FROM changes WHERE repo = ? AND number = ?"
        ))?
        .query_row(params![repo, number], change_from_row)
        .optional()?
        .map(finish_change)
        .transpose()
    }

    pub fn changes_in_repo(conn: &Connection, repo: &str) -> CoreResult<Vec<Change>> {
        conn.prepare_cached(&format!(
            "SELECT {CHANGE_COLS} FROM changes WHERE repo = ? ORDER BY number"
        ))?
        .query_map(params![repo], change_from_row)?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(finish_change)
        .collect()
    }

    pub fn revisions(conn: &Connection, change: &str) -> CoreResult<Vec<Revision>> {
        Ok(conn
            .prepare_cached(
                "SELECT change_id, number, commit_oid, session, message
                 FROM revisions WHERE change_id = ? ORDER BY number",
            )?
            .query_map(params![change], |row| {
                Ok(Revision {
                    change: ChangeId(row.get(0)?),
                    number: row.get(1)?,
                    commit_oid: row.get(2)?,
                    session: row.get::<_, Option<String>>(3)?.map(SessionId),
                    message: row.get(4)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?)
    }

    pub fn claims_on(conn: &Connection, change: &str, revision: i64) -> CoreResult<Vec<Claim>> {
        let rows = conn
            .prepare_cached(
                "SELECT id, change_id, revision, kind, command, passed, summary, unchecked, by
                 FROM claims WHERE change_id = ? AND revision = ? ORDER BY rowid",
            )?
            .query_map(params![change, revision], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(
                |(id, change_id, revision, kind, command, passed, summary, unchecked, by)| {
                    let at = format!("claim {id}");
                    Ok(Claim {
                        kind: parsed(&at, &kind, ClaimKind::parse)?,
                        unchecked: serde_json::from_str(&unchecked).map_err(|e| corrupt(&at, e))?,
                        id: crate::id::ClaimId(id),
                        change: ChangeId(change_id),
                        revision,
                        command,
                        passed: passed != 0,
                        summary,
                        by: PrincipalId(by),
                    })
                },
            )
            .collect()
    }

    pub fn verdicts_on(conn: &Connection, change: &str, revision: i64) -> CoreResult<Vec<Verdict>> {
        let rows = conn
            .prepare_cached(
                "SELECT id, change_id, revision, domain, disposition, rationale, by
                 FROM verdicts WHERE change_id = ? AND revision = ? ORDER BY rowid",
            )?
            .query_map(params![change, revision], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(
                |(id, change_id, revision, domain, disposition, rationale, by)| {
                    let at = format!("verdict {id}");
                    Ok(Verdict {
                        domain: parsed(&at, &domain, ReviewDomain::parse)?,
                        disposition: parsed(&at, &disposition, Disposition::parse)?,
                        id: crate::id::VerdictId(id),
                        change: ChangeId(change_id),
                        revision,
                        rationale,
                        by: PrincipalId(by),
                    })
                },
            )
            .collect()
    }

    pub fn principal_count(conn: &Connection) -> CoreResult<i64> {
        Ok(conn.query_row("SELECT COUNT(*) FROM principals", [], |r| r.get(0))?)
    }

    pub fn next_change_number(conn: &Connection, repo: &str) -> CoreResult<i64> {
        Ok(conn.query_row(
            "SELECT COALESCE(MAX(number), 0) + 1 FROM changes WHERE repo = ?",
            params![repo],
            |r| r.get(0),
        )?)
    }
}

impl Store {
    pub fn principal(&self, id: &PrincipalId) -> CoreResult<Option<Principal>> {
        raw::principal(&self.conn, id.as_str())
    }

    pub fn repo(&self, name: &str) -> CoreResult<Option<Repo>> {
        raw::repo(&self.conn, name)
    }

    pub fn task(&self, id: &TaskId) -> CoreResult<Option<Task>> {
        raw::task(&self.conn, id.as_str())
    }

    pub fn tasks(&self, state: Option<TaskState>) -> CoreResult<Vec<Task>> {
        raw::tasks(&self.conn, state)
    }

    pub fn session(&self, id: &SessionId) -> CoreResult<Option<Session>> {
        raw::session(&self.conn, id.as_str())
    }

    pub fn change(&self, id: &ChangeId) -> CoreResult<Option<Change>> {
        raw::change(&self.conn, id.as_str())
    }

    pub fn change_by_number(&self, repo: &str, number: i64) -> CoreResult<Option<Change>> {
        raw::change_by_number(&self.conn, repo, number)
    }

    pub fn changes_in_repo(&self, repo: &str) -> CoreResult<Vec<Change>> {
        raw::changes_in_repo(&self.conn, repo)
    }

    pub fn revisions(&self, change: &ChangeId) -> CoreResult<Vec<Revision>> {
        raw::revisions(&self.conn, change.as_str())
    }

    pub fn claims_on(&self, change: &ChangeId, revision: i64) -> CoreResult<Vec<Claim>> {
        raw::claims_on(&self.conn, change.as_str(), revision)
    }

    pub fn verdicts_on(&self, change: &ChangeId, revision: i64) -> CoreResult<Vec<Verdict>> {
        raw::verdicts_on(&self.conn, change.as_str(), revision)
    }
}
