//! Read side of the graph. All row-mapping lives here.
//!
//! The `raw` functions take `&Connection` so they work both on the store
//! itself and inside a command's transaction (`Transaction` derefs to
//! `Connection`), keeping validation and public reads on one code path.

use crate::error::{CoreError, CoreResult};
use crate::id::{ChangeId, PrincipalId, SessionId, TaskId};
use crate::store::Store;
use crate::types::{
    Capability, Change, ChangeState, Claim, ClaimKind, Disposition, Grant, ObjectFormat, Principal,
    PrincipalKind, QueueEntry, Repo, ReviewDomain, Revision, Session, SessionState, Task,
    TaskState, TokenInfo, Verdict,
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
        conn.prepare_cached("SELECT name, default_branch, object_format FROM repos WHERE name = ?")?
            .query_row(params![name], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .optional()?
            .map(|(name, default_branch, format)| {
                Ok(Repo {
                    object_format: parsed(&format!("repo {name}"), &format, ObjectFormat::parse)?,
                    name,
                    default_branch,
                })
            })
            .transpose()
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

    const CHANGE_COLS: &str = "id, repo, number, target, title, task, parent_change, state, \
                               owner, latest_revision, external_key";

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
                external_key: row.get(10)?,
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

    pub fn change_by_key(conn: &Connection, repo: &str, key: &str) -> CoreResult<Option<Change>> {
        conn.prepare_cached(&format!(
            "SELECT {CHANGE_COLS} FROM changes WHERE repo = ? AND external_key = ?"
        ))?
        .query_row(params![repo, key], change_from_row)
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

    /// Every (change number, revision number, commit oid) in a repo —
    /// the git-side `refs/changes/<n>/<rev>` projection wants exactly this.
    pub fn revision_refs(conn: &Connection, repo: &str) -> CoreResult<Vec<(i64, i64, String)>> {
        Ok(conn
            .prepare_cached(
                "SELECT c.number, r.number, r.commit_oid
                 FROM revisions r JOIN changes c ON c.id = r.change_id
                 WHERE c.repo = ? ORDER BY c.number, r.number",
            )?
            .query_map(params![repo], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })?
            .collect::<Result<Vec<_>, _>>()?)
    }

    /// Resolve a token secret's hash to its live owner.
    pub fn principal_for_token_hash(
        conn: &Connection,
        hash: &str,
    ) -> CoreResult<Option<PrincipalId>> {
        Ok(conn
            .prepare_cached("SELECT principal FROM tokens WHERE hash = ? AND revoked = 0")?
            .query_row(params![hash], |row| row.get::<_, String>(0))
            .optional()?
            .map(PrincipalId))
    }

    pub fn token(conn: &Connection, id: &str) -> CoreResult<Option<TokenInfo>> {
        Ok(conn
            .prepare_cached("SELECT id, principal, label, revoked FROM tokens WHERE id = ?")?
            .query_row(params![id], |row| {
                Ok(TokenInfo {
                    id: crate::id::TokenId(row.get(0)?),
                    principal: PrincipalId(row.get(1)?),
                    label: row.get(2)?,
                    revoked: row.get::<_, i64>(3)? != 0,
                })
            })
            .optional()?)
    }

    pub fn tokens_of(conn: &Connection, principal: &str) -> CoreResult<Vec<TokenInfo>> {
        Ok(conn
            .prepare_cached(
                "SELECT id, principal, label, revoked FROM tokens
                 WHERE principal = ? ORDER BY rowid",
            )?
            .query_map(params![principal], |row| {
                Ok(TokenInfo {
                    id: crate::id::TokenId(row.get(0)?),
                    principal: PrincipalId(row.get(1)?),
                    label: row.get(2)?,
                    revoked: row.get::<_, i64>(3)? != 0,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?)
    }

    fn grant_from_row(row: &Row) -> rusqlite::Result<(Grant, String)> {
        Ok((
            Grant {
                id: crate::id::GrantId(row.get(0)?),
                grantor: PrincipalId(row.get(1)?),
                grantee: PrincipalId(row.get(2)?),
                repo: row.get(3)?,
                actions: Vec::new(),
                until: row.get(5)?,
                revoked: row.get::<_, i64>(6)? != 0,
            },
            row.get::<_, String>(4)?,
        ))
    }

    fn finish_grant((mut grant, actions): (Grant, String)) -> CoreResult<Grant> {
        grant.actions = serde_json::from_str(&actions)
            .map_err(|e| corrupt(&format!("grant {}", grant.id), e))?;
        Ok(grant)
    }

    const GRANT_COLS: &str = "id, grantor, grantee, repo, actions, until_ts, revoked";

    pub fn grant(conn: &Connection, id: &str) -> CoreResult<Option<Grant>> {
        conn.prepare_cached(&format!("SELECT {GRANT_COLS} FROM grants WHERE id = ?"))?
            .query_row(params![id], grant_from_row)
            .optional()?
            .map(finish_grant)
            .transpose()
    }

    /// Live (unrevoked) grants held by a principal. Expiry is judged at
    /// the point of use, not here.
    pub fn grants_of(conn: &Connection, grantee: &str) -> CoreResult<Vec<Grant>> {
        conn.prepare_cached(&format!(
            "SELECT {GRANT_COLS} FROM grants WHERE grantee = ? AND revoked = 0 ORDER BY rowid"
        ))?
        .query_map(params![grantee], grant_from_row)?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(finish_grant)
        .collect()
    }

    /// Does this grant list cover `action` on `repo` right now?
    pub fn grants_cover(
        grants: &[Grant],
        action: Capability,
        repo: Option<&str>,
        now: &str,
    ) -> bool {
        grants.iter().any(|grant| {
            let action_ok = grant.actions.contains(&action);
            // A repo-scoped grant covers only that repo; repo-less
            // operations need a global grant.
            let scope_ok = match (&grant.repo, repo) {
                (None, _) => true,
                (Some(scope), Some(target)) => scope == target,
                (Some(_), None) => false,
            };
            let time_ok = grant.until.as_deref().is_none_or(|until| until > now);
            action_ok && scope_ok && time_ok
        })
    }

    fn queue_entry_from_row(row: &Row) -> rusqlite::Result<QueueEntry> {
        Ok(QueueEntry {
            change: ChangeId(row.get(0)?),
            repo: row.get(1)?,
            target: row.get(2)?,
            enqueued_by: PrincipalId(row.get(3)?),
            enqueued_seq: row.get(4)?,
        })
    }

    const QUEUE_COLS: &str = "change_id, repo, target, enqueued_by, enqueued_seq";

    pub fn queue_entry(conn: &Connection, change: &str) -> CoreResult<Option<QueueEntry>> {
        Ok(conn
            .prepare_cached(&format!(
                "SELECT {QUEUE_COLS} FROM merge_queue WHERE change_id = ?"
            ))?
            .query_row(params![change], queue_entry_from_row)
            .optional()?)
    }

    /// A branch's landing queue, FIFO.
    pub fn queue_for(conn: &Connection, repo: &str, target: &str) -> CoreResult<Vec<QueueEntry>> {
        Ok(conn
            .prepare_cached(&format!(
                "SELECT {QUEUE_COLS} FROM merge_queue
                 WHERE repo = ? AND target = ? ORDER BY enqueued_seq"
            ))?
            .query_map(params![repo, target], queue_entry_from_row)?
            .collect::<Result<Vec<_>, _>>()?)
    }

    /// The head of every non-empty (repo, target) lane, oldest first —
    /// exactly what the landing processor works through.
    pub fn queue_heads(conn: &Connection) -> CoreResult<Vec<QueueEntry>> {
        Ok(conn
            .prepare_cached(&format!(
                "SELECT {QUEUE_COLS} FROM merge_queue
                 WHERE enqueued_seq IN
                   (SELECT MIN(enqueued_seq) FROM merge_queue GROUP BY repo, target)
                 ORDER BY enqueued_seq"
            ))?
            .query_map([], queue_entry_from_row)?
            .collect::<Result<Vec<_>, _>>()?)
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

    pub fn change_by_key(&self, repo: &str, key: &str) -> CoreResult<Option<Change>> {
        raw::change_by_key(&self.conn, repo, key)
    }

    pub fn revision_refs(&self, repo: &str) -> CoreResult<Vec<(i64, i64, String)>> {
        raw::revision_refs(&self.conn, repo)
    }

    /// Resolve a presented token secret to its live owner.
    pub fn principal_for_token(&self, secret: &str) -> CoreResult<Option<PrincipalId>> {
        raw::principal_for_token_hash(&self.conn, &crate::commands::token_hash(secret))
    }

    pub fn tokens_of(&self, principal: &PrincipalId) -> CoreResult<Vec<TokenInfo>> {
        raw::tokens_of(&self.conn, principal.as_str())
    }

    pub fn grants_of(&self, grantee: &PrincipalId) -> CoreResult<Vec<Grant>> {
        raw::grants_of(&self.conn, grantee.as_str())
    }

    pub fn queue_entry(&self, change: &ChangeId) -> CoreResult<Option<QueueEntry>> {
        raw::queue_entry(&self.conn, change.as_str())
    }

    pub fn queue_for(&self, repo: &str, target: &str) -> CoreResult<Vec<QueueEntry>> {
        raw::queue_for(&self.conn, repo, target)
    }

    pub fn queue_heads(&self) -> CoreResult<Vec<QueueEntry>> {
        raw::queue_heads(&self.conn)
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
