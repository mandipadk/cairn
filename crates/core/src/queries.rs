//! Read side of the graph. All row-mapping lives here.
//!
//! The `raw` functions take `&Connection` so they work both on the store
//! itself and inside a command's transaction (`Transaction` derefs to
//! `Connection`), keeping validation and public reads on one code path.

use crate::error::{CoreError, CoreResult};
use crate::id::{ChangeId, PrincipalId, SessionId, TaskId};
use crate::store::Store;
use crate::types::{
    Capability, Change, ChangeState, Claim, ClaimKind, Disposition, Grant, Lease, Lesson, Mirror,
    ObjectFormat, Policy, Principal, PrincipalKind, Provenance, QueueEntry, Repo, ReviewDomain,
    Revision, Session, SessionState, Task, TaskState, TokenInfo, Verdict, Verification,
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

    pub fn repos(conn: &Connection) -> CoreResult<Vec<Repo>> {
        let rows = conn
            .prepare_cached(
                "SELECT name, default_branch, object_format, policy, mirror
                 FROM repos ORDER BY name",
            )?
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|(name, default_branch, format, policy, mirror)| {
                Ok(Repo {
                    object_format: parsed(&format!("repo {name}"), &format, ObjectFormat::parse)?,
                    policy: read_policy(&name, &policy)?,
                    mirror: read_mirror(&name, mirror.as_deref())?,
                    name,
                    default_branch,
                })
            })
            .collect()
    }

    fn read_mirror(name: &str, stored: Option<&str>) -> CoreResult<Option<Mirror>> {
        stored
            .map(|raw| {
                serde_json::from_str(raw).map_err(|e| corrupt(&format!("repo {name} mirror"), e))
            })
            .transpose()
    }

    /// A repo written before policies existed, or one that never set
    /// one, gets the defaults — the rules the forge shipped with.
    fn read_policy(name: &str, stored: &str) -> CoreResult<Policy> {
        if stored.trim().is_empty() || stored.trim() == "{}" {
            return Ok(Policy::default());
        }
        serde_json::from_str(stored).map_err(|e| corrupt(&format!("repo {name} policy"), e))
    }

    pub fn repo(conn: &Connection, name: &str) -> CoreResult<Option<Repo>> {
        conn.prepare_cached(
            "SELECT name, default_branch, object_format, policy, mirror
             FROM repos WHERE name = ?",
        )?
        .query_row(params![name], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
            ))
        })
        .optional()?
        .map(|(name, default_branch, format, policy, mirror)| {
            Ok(Repo {
                object_format: parsed(&format!("repo {name}"), &format, ObjectFormat::parse)?,
                policy: read_policy(&name, &policy)?,
                mirror: read_mirror(&name, mirror.as_deref())?,
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
                               owner, latest_revision, external_key, landed_oid";

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
                landed_oid: row.get(11)?,
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

    /// The change that landed a given commit on a branch — how a file
    /// in the tree finds the judgment that put it there.
    pub fn change_by_landed_oid(
        conn: &Connection,
        repo: &str,
        oid: &str,
    ) -> CoreResult<Option<Change>> {
        conn.prepare_cached(&format!(
            "SELECT {CHANGE_COLS} FROM changes WHERE repo = ? AND landed_oid = ?"
        ))?
        .query_row(params![repo, oid], change_from_row)
        .optional()?
        .map(finish_change)
        .transpose()
    }

    /// Open changes stacked directly on this one.
    pub fn open_children(conn: &Connection, parent: &str) -> CoreResult<Vec<Change>> {
        conn.prepare_cached(&format!(
            "SELECT {CHANGE_COLS} FROM changes
             WHERE parent_change = ? AND state = 'open' ORDER BY number"
        ))?
        .query_map(params![parent], change_from_row)?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(finish_change)
        .collect()
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

    pub fn claim(conn: &Connection, id: &str) -> CoreResult<Option<Claim>> {
        let row = conn
            .prepare_cached(
                "SELECT id, change_id, revision, kind, command, passed, summary, unchecked, by
                 FROM claims WHERE id = ?",
            )?
            .query_row(params![id], |row| {
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
            })
            .optional()?;
        row.map(
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
        .transpose()
    }

    pub fn verifications_on(
        conn: &Connection,
        change: &str,
        revision: i64,
    ) -> CoreResult<Vec<Verification>> {
        Ok(conn
            .prepare_cached(
                "SELECT id, claim_id, change_id, revision, agrees, command, observed, by
                 FROM verifications WHERE change_id = ? AND revision = ? ORDER BY rowid",
            )?
            .query_map(params![change, revision], |row| {
                Ok(Verification {
                    id: crate::id::VerificationId(row.get(0)?),
                    claim: crate::id::ClaimId(row.get(1)?),
                    change: ChangeId(row.get(2)?),
                    revision: row.get(3)?,
                    agrees: row.get::<_, i64>(4)? != 0,
                    command: row.get(5)?,
                    observed: row.get(6)?,
                    by: PrincipalId(row.get(7)?),
                })
            })?
            .collect::<Result<Vec<_>, _>>()?)
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

    /// Sessions currently running, oldest first — the fleet view.
    pub fn active_sessions(conn: &Connection) -> CoreResult<Vec<Session>> {
        conn.prepare_cached(
            "SELECT id, task, agent, state, outcome FROM sessions
             WHERE state = 'active' ORDER BY rowid",
        )?
        .query_map([], |row| {
            Ok(Session {
                id: SessionId(row.get(0)?),
                task: TaskId(row.get(1)?),
                agent: PrincipalId(row.get(2)?),
                state: SessionState::Active,
                outcome: row.get(4)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
    }

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

    /// Leases held by sessions that are still running.
    pub fn live_leases(conn: &Connection, repo: &str) -> CoreResult<Vec<Lease>> {
        let rows = conn
            .prepare_cached(
                "SELECT l.session, l.repo, l.holder, l.paths FROM leases l
                 JOIN sessions s ON s.id = l.session
                 WHERE l.repo = ? AND s.state = 'active' ORDER BY l.rowid",
            )?
            .query_map(params![repo], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|(session, repo, holder, paths)| {
                Ok(Lease {
                    paths: serde_json::from_str(&paths)
                        .map_err(|e| corrupt(&format!("lease {session}"), e))?,
                    session: SessionId(session),
                    repo,
                    holder: PrincipalId(holder),
                })
            })
            .collect()
    }

    /// Has this session already produced a revision? Work in flight
    /// weighs more than declared intent.
    pub fn session_has_revision(conn: &Connection, session: &str) -> CoreResult<bool> {
        Ok(conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM revisions WHERE session = ?)",
            params![session],
            |row| row.get::<_, i64>(0),
        )? != 0)
    }

    /// Finished sessions and what they recorded, newest first. The
    /// protocol already forces an outcome on every ending session, so
    /// this corpus costs nothing to keep and answers the question an
    /// agent should ask first: has anyone tried this before?
    pub fn lessons(
        conn: &Connection,
        repo: Option<&str>,
        query: Option<&str>,
        failures_only: bool,
        limit: usize,
    ) -> CoreResult<Vec<Lesson>> {
        // LIKE with an escaped pattern: callers search prose, not SQL.
        let needle = query.map(|q| {
            format!(
                "%{}%",
                q.replace('\\', "\\\\")
                    .replace('%', "\\%")
                    .replace('_', "\\_")
            )
        });
        let rows = conn
            .prepare_cached(
                "SELECT s.id, s.agent, s.state, s.task, t.title, s.outcome
                 FROM sessions s JOIN tasks t ON t.id = s.task
                 WHERE s.state != 'active' AND s.outcome IS NOT NULL
                   AND (?1 IS NULL OR t.repo = ?1)
                   AND (?2 = 0 OR s.state = 'failed')
                   AND (?3 IS NULL OR s.outcome LIKE ?3 ESCAPE '\\'
                        OR t.title LIKE ?3 ESCAPE '\\')
                 ORDER BY s.rowid DESC LIMIT ?4",
            )?
            .query_map(
                params![repo, failures_only as i64, needle, limit as i64],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|(session, agent, state, task, task_title, outcome)| {
                Ok(Lesson {
                    state: parsed(&format!("session {session}"), &state, SessionState::parse)?,
                    session: SessionId(session),
                    agent: PrincipalId(agent),
                    task: TaskId(task),
                    task_title,
                    outcome,
                })
            })
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

    pub fn open_children(&self, parent: &ChangeId) -> CoreResult<Vec<Change>> {
        raw::open_children(&self.conn, parent.as_str())
    }

    pub fn change_by_landed_oid(&self, repo: &str, oid: &str) -> CoreResult<Option<Change>> {
        raw::change_by_landed_oid(&self.conn, repo, oid)
    }

    /// The judgment behind a landed commit: the change, what was
    /// claimed about it, and who judged it. The join that turns
    /// attribution from "who wrote this" into "what do we know".
    /// Who else has declared intent over these paths right now.
    pub fn path_conflicts(&self, repo: &str, paths: &[String]) -> CoreResult<Vec<crate::Overlap>> {
        crate::leases::conflicts(&self.conn, repo, paths, None)
    }

    pub fn live_leases(&self, repo: &str) -> CoreResult<Vec<Lease>> {
        raw::live_leases(&self.conn, repo)
    }

    /// What earlier attempts learned. `query` searches the outcome text
    /// and the task title.
    pub fn lessons(
        &self,
        repo: Option<&str>,
        query: Option<&str>,
        failures_only: bool,
        limit: usize,
    ) -> CoreResult<Vec<Lesson>> {
        raw::lessons(&self.conn, repo, query, failures_only, limit.min(200))
    }

    /// What a proposed policy would mean for the changes already
    /// open: the answer to "if we tighten this, what stops landing?"
    pub fn policy_preview(
        &self,
        repo: &str,
        policy: &Policy,
    ) -> CoreResult<Vec<(Change, crate::PolicyTrace)>> {
        let mut previewed = Vec::new();
        for change in raw::changes_in_repo(&self.conn, repo)? {
            if change.state != ChangeState::Open || change.latest_revision == 0 {
                continue;
            }
            let trace = crate::policy::evaluate_against(&self.conn, &change, policy)?;
            previewed.push((change, trace));
        }
        Ok(previewed)
    }

    /// What a human should look at in this repo, and why. Ranked by
    /// an explainable evaluation, not by recency.
    pub fn attention_for(&self, repo: &str) -> CoreResult<Vec<crate::AttentionItem>> {
        crate::attention::evaluate(&self.conn, repo)
    }

    pub fn provenance_of(&self, repo: &str, oid: &str) -> CoreResult<Option<Provenance>> {
        let Some(change) = raw::change_by_landed_oid(&self.conn, repo, oid)? else {
            return Ok(None);
        };
        let revision = change.latest_revision;
        Ok(Some(Provenance {
            claims: raw::claims_on(&self.conn, change.id.as_str(), revision)?,
            verdicts: raw::verdicts_on(&self.conn, change.id.as_str(), revision)?,
            change,
        }))
    }

    pub fn active_sessions(&self) -> CoreResult<Vec<Session>> {
        raw::active_sessions(&self.conn)
    }

    pub fn repos(&self) -> CoreResult<Vec<Repo>> {
        raw::repos(&self.conn)
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

    pub fn verifications_on(
        &self,
        change: &ChangeId,
        revision: i64,
    ) -> CoreResult<Vec<Verification>> {
        raw::verifications_on(&self.conn, change.as_str(), revision)
    }
}
