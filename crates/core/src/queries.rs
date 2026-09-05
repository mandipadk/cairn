//! Read side of the graph. All row-mapping lives here.
//!
//! The `raw` functions take `&Connection` so they work both on the store
//! itself and inside a command's transaction (`Transaction` derefs to
//! `Connection`), keeping validation and public reads on one code path.

use crate::error::{CoreError, CoreResult};
use crate::id::{ChangeId, PrincipalId, SessionId, TaskId, ThreadId};
use crate::store::Store;
use crate::types::{
    Capability, Change, ChangeState, Claim, ClaimKind, Disposition, Grant, Lease, Lesson, Mirror,
    Notice, ObjectFormat, Policy, Principal, PrincipalKind, Provenance, QueueEntry, Repo,
    ReviewDomain, Revision, Session, SessionState, Task, TaskState, TokenInfo, Verdict,
    Verification, Visibility,
};
use crate::types::{Reply, Resolution, Resolved, Thread, ThreadKind};
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

    /// A principal's stored password hash.
    ///
    /// Deliberately not a field on [`Principal`]: that struct is
    /// serialised straight into API responses, and a hash that is never
    /// in the type cannot leak through one.
    pub fn credential(conn: &Connection, id: &str) -> CoreResult<Option<String>> {
        Ok(conn
            .prepare_cached("SELECT hash FROM credentials WHERE principal = ?")?
            .query_row(params![id], |row| row.get::<_, String>(0))
            .optional()?)
    }

    pub fn principal(conn: &Connection, id: &str) -> CoreResult<Option<Principal>> {
        conn.prepare_cached(
            "SELECT id, kind, display, model, harness, active FROM principals WHERE id = ?",
        )?
        .query_row(params![id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, i64>(5)?,
            ))
        })
        .optional()?
        .map(|(id, kind, display, model, harness, active)| {
            Ok(Principal {
                active: active != 0,
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
                "SELECT name, default_branch, object_format, policy, mirror, visibility, owner,
                        pending_owner, archived
                 FROM repos ORDER BY name",
            )?
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, i64>(8)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(
                |(
                    name,
                    default_branch,
                    format,
                    policy,
                    mirror,
                    visibility,
                    owner,
                    pending,
                    archived,
                )| {
                    Ok(Repo {
                        owner: PrincipalId(owner),
                        pending_owner: pending.map(PrincipalId),
                        object_format: parsed(
                            &format!("repo {name}"),
                            &format,
                            ObjectFormat::parse,
                        )?,
                        policy: read_policy(&name, &policy)?,
                        mirror: read_mirror(&name, mirror.as_deref())?,
                        visibility: parsed(
                            &format!("repo {name}"),
                            &visibility,
                            Visibility::parse,
                        )?,
                        archived: archived != 0,
                        name,
                        default_branch,
                    })
                },
            )
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
            "SELECT name, default_branch, object_format, policy, mirror, visibility, owner,
                    pending_owner, archived
             FROM repos WHERE name = ?",
        )?
        .query_row(params![name], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, i64>(8)?,
            ))
        })
        .optional()?
        .map(
            |(
                name,
                default_branch,
                format,
                policy,
                mirror,
                visibility,
                owner,
                pending,
                archived,
            )| {
                Ok(Repo {
                    owner: PrincipalId(owner),
                    pending_owner: pending.map(PrincipalId),
                    object_format: parsed(&format!("repo {name}"), &format, ObjectFormat::parse)?,
                    policy: read_policy(&name, &policy)?,
                    mirror: read_mirror(&name, mirror.as_deref())?,
                    visibility: parsed(&format!("repo {name}"), &visibility, Visibility::parse)?,
                    archived: archived != 0,
                    name,
                    default_branch,
                })
            },
        )
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

    pub fn draw_of(conn: &Connection, change: &str) -> CoreResult<Option<crate::attention::Draw>> {
        let row: Option<(String, String, String)> = conn
            .prepare_cached(
                "SELECT day, signals, reviewers FROM attention_draws WHERE change_id = ?",
            )?
            .query_row(params![change], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .optional()?;
        row.map(|(day, signals, reviewers)| {
            let at = format!("draw of {change}");
            Ok(crate::attention::Draw {
                day,
                signals: serde_json::from_str(&signals).map_err(|e| corrupt(&at, e))?,
                reviewers: serde_json::from_str(&reviewers).map_err(|e| corrupt(&at, e))?,
            })
        })
        .transpose()
    }

    pub fn draws_on(conn: &Connection, repo: &str, day: &str) -> CoreResult<i64> {
        Ok(conn
            .prepare_cached("SELECT COUNT(*) FROM attention_draws WHERE repo = ? AND day = ?")?
            .query_row(params![repo, day], |row| row.get(0))?)
    }

    /// The humans a draw can be addressed to: the repository's owner and
    /// every human holding review on it, or running the forge.
    pub fn humans_who_may_review(conn: &Connection, repo: &str) -> CoreResult<Vec<PrincipalId>> {
        let owner = repo_owner(conn, repo)?;
        let now = jiff::Timestamp::now().to_string();
        let mut humans = Vec::new();
        for principal in principals(conn)? {
            if principal.kind != PrincipalKind::Human {
                continue;
            }
            let id = principal.id.as_str();
            let grants = effective_grants(conn, id)?;
            if owner.as_deref() == Some(id)
                || grants_cover(&grants, Capability::Review, Some(repo), &now)
                || grants_cover(&grants, Capability::Admin, None, &now)
            {
                humans.push(principal.id.clone());
            }
        }
        Ok(humans)
    }

    fn repo_owner(conn: &Connection, repo: &str) -> CoreResult<Option<String>> {
        Ok(conn
            .prepare_cached("SELECT owner FROM repos WHERE name = ?")?
            .query_row(params![repo], |row| row.get(0))
            .optional()?)
    }

    pub fn identity_of(
        conn: &Connection,
        issuer: &str,
        subject: &str,
    ) -> CoreResult<Option<PrincipalId>> {
        Ok(conn
            .prepare_cached(
                "SELECT principal FROM identity_links WHERE issuer = ? AND subject = ?",
            )?
            .query_row(params![issuer, subject], |row| row.get::<_, String>(0))
            .optional()?
            .map(PrincipalId))
    }

    pub fn identities_of(
        conn: &Connection,
        principal: &str,
    ) -> CoreResult<Vec<crate::types::IdentityLink>> {
        Ok(conn
            .prepare_cached(
                "SELECT issuer, subject, email, linked_at FROM identity_links
                  WHERE principal = ? ORDER BY linked_at",
            )?
            .query_map(params![principal], |row| {
                Ok(crate::types::IdentityLink {
                    issuer: row.get(0)?,
                    subject: row.get(1)?,
                    email: row.get(2)?,
                    linked_at: row.get(3)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?)
    }

    pub fn workload_binding(
        conn: &Connection,
        issuer: &str,
        subject: &str,
    ) -> CoreResult<Option<PrincipalId>> {
        Ok(conn
            .prepare_cached(
                "SELECT principal FROM workload_bindings WHERE issuer = ? AND subject = ?",
            )?
            .query_row(params![issuer, subject], |row| row.get::<_, String>(0))
            .optional()?
            .map(PrincipalId))
    }

    pub fn workload_bindings_of(
        conn: &Connection,
        principal: &str,
    ) -> CoreResult<Vec<crate::types::WorkloadBinding>> {
        Ok(conn
            .prepare_cached("SELECT issuer, subject FROM workload_bindings WHERE principal = ? ORDER BY issuer, subject")?
            .query_map(params![principal], |row| {
                Ok(crate::types::WorkloadBinding {
                    issuer: row.get(0)?,
                    subject: row.get(1)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?)
    }

    pub fn verdict_ref(conn: &Connection, id: &str) -> CoreResult<Option<(String, i64)>> {
        Ok(conn
            .prepare_cached("SELECT change_id, revision FROM verdicts WHERE id = ?")?
            .query_row(params![id], |row| Ok((row.get(0)?, row.get(1)?)))
            .optional()?)
    }

    const THREAD_COLUMNS: &str = "id, change_id, revision, anchor, kind, body, by, at, \
         resolved_how, resolved_revision, resolved_note, resolved_by, resolved_at";

    type ThreadRow = (
        String,
        String,
        i64,
        String,
        String,
        String,
        String,
        String,
        Option<String>,
        Option<i64>,
        Option<String>,
        Option<String>,
        Option<String>,
    );

    fn threads_where(
        conn: &Connection,
        clause: &str,
        params: &[&dyn rusqlite::ToSql],
    ) -> CoreResult<Vec<Thread>> {
        let sql = format!("SELECT {THREAD_COLUMNS} FROM threads WHERE {clause} ORDER BY rowid");
        let heads = conn
            .prepare_cached(&sql)?
            .query_map(params, |row| {
                Ok::<ThreadRow, _>((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                    row.get(12)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        heads
            .into_iter()
            .map(
                |(id, change, revision, anchor, kind, body, by, at, how, rrev, note, rby, rat)| {
                    let where_ = format!("thread {id}");
                    let replies = conn
                    .prepare_cached(
                        "SELECT by, body, at FROM thread_replies WHERE thread_id = ? ORDER BY seq",
                    )?
                    .query_map(params![id], |row| {
                        Ok(Reply {
                            by: PrincipalId(row.get(0)?),
                            body: row.get(1)?,
                            at: row.get(2)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                    let resolved = match how {
                        Some(how) => Some(Resolved {
                            how: parsed(&where_, &how, Resolution::parse)?,
                            revision: rrev,
                            note: note.unwrap_or_default(),
                            by: PrincipalId(rby.unwrap_or_default()),
                            at: rat.unwrap_or_default(),
                        }),
                        None => None,
                    };
                    Ok(Thread {
                        anchor: serde_json::from_str(&anchor).map_err(|e| corrupt(&where_, e))?,
                        kind: parsed(&where_, &kind, ThreadKind::parse)?,
                        id: ThreadId(id),
                        change: ChangeId(change),
                        revision,
                        body,
                        by: PrincipalId(by),
                        at,
                        replies,
                        resolved,
                    })
                },
            )
            .collect()
    }

    /// Every thread on a change, whatever revision it was opened on,
    /// oldest first.
    pub fn threads_on(conn: &Connection, change: &str) -> CoreResult<Vec<Thread>> {
        threads_where(conn, "change_id = ?", &[&change])
    }

    pub fn thread(conn: &Connection, id: &str) -> CoreResult<Option<Thread>> {
        Ok(threads_where(conn, "id = ?", &[&id])?.pop())
    }

    /// Concerns nobody has resolved yet, on any revision of the change.
    pub fn open_concerns(conn: &Connection, change: &str) -> CoreResult<Vec<Thread>> {
        threads_where(
            conn,
            "change_id = ? AND kind = 'concern' AND resolved_how IS NULL",
            &[&change],
        )
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
    /// Who a token belongs to and, for a session credential, what it may
    /// do. Expired, revoked and invitation tokens resolve to nobody.
    pub fn identity_for_token_hash(
        conn: &Connection,
        hash: &str,
    ) -> CoreResult<Option<(PrincipalId, Option<crate::types::Scope>)>> {
        let row: Option<(String, Option<String>)> = conn
            .prepare_cached(
                "SELECT t.principal, t.scope FROM tokens t
                  JOIN principals p ON p.id = t.principal AND p.active = 1
                  WHERE t.hash = ? AND t.revoked = 0 AND (t.until_ts IS NULL OR t.until_ts > ?)
                    AND (t.label IS NULL OR t.label NOT LIKE 'invitation%')",
            )?
            .query_row(params![hash, jiff::Timestamp::now().to_string()], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .optional()?;
        row.map(|(principal, scope)| {
            let scope = scope
                .map(|s| {
                    serde_json::from_str(&s)
                        .map_err(|e| corrupt(&format!("token of {principal}"), e))
                })
                .transpose()?;
            Ok((PrincipalId(principal), scope))
        })
        .transpose()
    }

    pub fn principal_for_token_hash(
        conn: &Connection,
        hash: &str,
    ) -> CoreResult<Option<PrincipalId>> {
        Ok(conn
            .prepare_cached(
                "SELECT principal FROM tokens
                  WHERE hash = ? AND revoked = 0 AND (until_ts IS NULL OR until_ts > ?)
                    AND (label IS NULL OR label NOT LIKE 'invitation%')",
            )?
            .query_row(params![hash, jiff::Timestamp::now().to_string()], |row| {
                row.get::<_, String>(0)
            })
            .optional()?
            .map(PrincipalId))
    }

    pub fn token(conn: &Connection, id: &str) -> CoreResult<Option<TokenInfo>> {
        Ok(conn
            .prepare_cached(
                "SELECT id, principal, label, revoked, until_ts FROM tokens WHERE id = ?",
            )?
            .query_row(params![id], |row| {
                Ok(TokenInfo {
                    id: crate::id::TokenId(row.get(0)?),
                    principal: PrincipalId(row.get(1)?),
                    label: row.get(2)?,
                    revoked: row.get::<_, i64>(3)? != 0,
                    until: row.get(4)?,
                })
            })
            .optional()?)
    }

    pub fn tokens_of(conn: &Connection, principal: &str) -> CoreResult<Vec<TokenInfo>> {
        Ok(conn
            .prepare_cached(
                "SELECT id, principal, label, revoked, until_ts FROM tokens
                 WHERE principal = ? ORDER BY rowid",
            )?
            .query_map(params![principal], |row| {
                Ok(TokenInfo {
                    id: crate::id::TokenId(row.get(0)?),
                    principal: PrincipalId(row.get(1)?),
                    label: row.get(2)?,
                    revoked: row.get::<_, i64>(3)? != 0,
                    until: row.get(4)?,
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

    pub fn teams_of(conn: &Connection, member: &str) -> CoreResult<Vec<String>> {
        Ok(conn
            .prepare_cached("SELECT team FROM team_members WHERE member = ? ORDER BY team")?
            .query_map(params![member], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?)
    }

    pub fn members_of(conn: &Connection, team: &str) -> CoreResult<Vec<PrincipalId>> {
        Ok(conn
            .prepare_cached("SELECT member FROM team_members WHERE team = ? ORDER BY member")?
            .query_map(params![team], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(PrincipalId)
            .collect())
    }

    /// What a principal may do: their own grants and their teams', as
    /// one list. Every authority check reads this, so joining a team is
    /// effective at once and leaving it is too.
    pub fn effective_grants(conn: &Connection, principal: &str) -> CoreResult<Vec<Grant>> {
        let mut grants = grants_of(conn, principal)?;
        for team in teams_of(conn, principal)? {
            grants.extend(grants_of(conn, &team)?);
        }
        Ok(grants)
    }

    /// Everyone holding the unscoped admin grant that running the forge
    /// consists of.
    pub fn admins(conn: &Connection) -> CoreResult<Vec<String>> {
        Ok(conn
            .prepare_cached(
                "SELECT DISTINCT grantee FROM grants
                  WHERE revoked = 0 AND repo IS NULL AND actions LIKE '%\"admin\"%'
                  ORDER BY grantee",
            )?
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?)
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
    /// Sessions at work in one repository: on a task of its, or holding
    /// a lease on it. What is happening elsewhere is elsewhere's.
    pub fn active_sessions_in(conn: &Connection, repo: &str) -> CoreResult<Vec<Session>> {
        conn.prepare_cached(
            "SELECT s.id, s.task, s.agent, s.state, s.outcome FROM sessions s
              LEFT JOIN tasks t ON t.id = s.task
             WHERE s.state = 'active'
               AND (t.repo = ?1 OR s.id IN (SELECT session FROM leases WHERE repo = ?1))
             ORDER BY s.rowid",
        )?
        .query_map(params![repo], |row| {
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
                "SELECT s.id, s.agent, s.state, s.task, t.title, s.outcome, t.repo
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
                        row.get::<_, Option<String>>(6)?,
                    ))
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|(session, agent, state, task, task_title, outcome, repo)| {
                Ok(Lesson {
                    state: parsed(&format!("session {session}"), &state, SessionState::parse)?,
                    session: SessionId(session),
                    agent: PrincipalId(agent),
                    task: TaskId(task),
                    task_title,
                    repo,
                    outcome,
                })
            })
            .collect()
    }

    /// Everyone the forge knows about, humans and agents alike.
    pub fn principals(conn: &Connection) -> CoreResult<Vec<Principal>> {
        let rows = conn
            .prepare_cached("SELECT id FROM principals ORDER BY id")?
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .filter_map(|id| principal(conn, &id).transpose())
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
    pub fn identity_for_token(
        &self,
        secret: &str,
    ) -> CoreResult<Option<(PrincipalId, Option<crate::types::Scope>)>> {
        raw::identity_for_token_hash(&self.conn, &crate::commands::token_hash(secret))
    }

    pub fn principal_for_token(&self, secret: &str) -> CoreResult<Option<PrincipalId>> {
        raw::principal_for_token_hash(&self.conn, &crate::commands::token_hash(secret))
    }

    /// The live token a secret belongs to, with its label - for the one
    /// place a token is more than a credential: an invitation, which is
    /// spent on use.
    pub fn token_for_secret(&self, secret: &str) -> CoreResult<Option<TokenInfo>> {
        Ok(self
            .conn
            .prepare_cached(
                "SELECT id, principal, label, revoked, until_ts FROM tokens
                  WHERE hash = ? AND revoked = 0 AND (until_ts IS NULL OR until_ts > ?)",
            )?
            .query_row(
                params![
                    crate::commands::token_hash(secret),
                    jiff::Timestamp::now().to_string()
                ],
                |row| {
                    Ok(TokenInfo {
                        id: crate::id::TokenId(row.get(0)?),
                        principal: PrincipalId(row.get(1)?),
                        label: row.get(2)?,
                        revoked: row.get::<_, i64>(3)? != 0,
                        until: row.get(4)?,
                    })
                },
            )
            .optional()?)
    }

    pub fn teams_of(&self, member: &PrincipalId) -> CoreResult<Vec<String>> {
        raw::teams_of(&self.conn, member.as_str())
    }

    pub fn members_of(&self, team: &PrincipalId) -> CoreResult<Vec<PrincipalId>> {
        raw::members_of(&self.conn, team.as_str())
    }

    /// Own grants plus every team's, which is what authority checks use.
    pub fn effective_grants(&self, principal: &PrincipalId) -> CoreResult<Vec<Grant>> {
        raw::effective_grants(&self.conn, principal.as_str())
    }

    pub fn principals(&self) -> CoreResult<Vec<Principal>> {
        raw::principals(&self.conn)
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

    /// What has been addressed to this principal, newest first, each
    /// marked read or not. Read state lives beside the projection rather
    /// than in it: the log says what happened, the reader says what they
    /// have dealt with.
    pub fn inbox(&self, who: &PrincipalId, limit: usize) -> CoreResult<Vec<Notice>> {
        let rows = self
            .conn
            .prepare_cached(
                "SELECT n.seq, e.ts, n.kind, e.actor, n.repo, n.change_id, n.number, n.what,
                        (n.seq <= COALESCE((SELECT seq FROM inbox_cursor WHERE principal = ?1), 0)
                         OR EXISTS (SELECT 1 FROM inbox_read r
                                     WHERE r.principal = ?1 AND r.seq = n.seq)) AS read
                   FROM notices n JOIN events e ON e.seq = n.seq
                  WHERE n.recipient = ?1
                  ORDER BY n.seq DESC LIMIT ?2",
            )?
            .query_map(params![who.as_str(), limit.min(500) as i64], |row| {
                Ok(Notice {
                    seq: row.get(0)?,
                    ts: row.get(1)?,
                    kind: row.get(2)?,
                    actor: PrincipalId(row.get(3)?),
                    repo: row.get(4)?,
                    change: row.get::<_, Option<String>>(5)?.map(ChangeId),
                    number: row.get(6)?,
                    what: row.get(7)?,
                    read: row.get::<_, i64>(8)? != 0,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// How many notices this principal has not dealt with.
    pub fn unread_count(&self, who: &PrincipalId) -> CoreResult<usize> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM notices n
              WHERE n.recipient = ?1
                AND n.seq > COALESCE((SELECT seq FROM inbox_cursor WHERE principal = ?1), 0)
                AND NOT EXISTS (SELECT 1 FROM inbox_read r
                                 WHERE r.principal = ?1 AND r.seq = n.seq)",
            params![who.as_str()],
            |row| row.get(0),
        )?;
        Ok(n as usize)
    }

    /// Open changes whose latest revision carries a claim that names
    /// a command nobody has re-run. This is the work queue for a
    /// runner: everything currently taken on trust.
    pub fn awaiting_verification(&self, repo: &str) -> CoreResult<Vec<Change>> {
        let mut waiting = Vec::new();
        for change in raw::changes_in_repo(&self.conn, repo)? {
            if change.state != ChangeState::Open || change.latest_revision == 0 {
                continue;
            }
            let revision = change.latest_revision;
            let claims = raw::claims_on(&self.conn, change.id.as_str(), revision)?;
            let verifications = raw::verifications_on(&self.conn, change.id.as_str(), revision)?;
            let unrun = claims.iter().any(|claim| {
                claim.command.is_some() && !verifications.iter().any(|v| v.claim == claim.id)
            });
            if unrun {
                waiting.push(change);
            }
        }
        Ok(waiting)
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
            verifications: raw::verifications_on(&self.conn, change.id.as_str(), revision)?,
            change,
        }))
    }

    pub fn active_sessions(&self) -> CoreResult<Vec<Session>> {
        raw::active_sessions(&self.conn)
    }

    pub fn active_sessions_in(&self, repo: &str) -> CoreResult<Vec<Session>> {
        raw::active_sessions_in(&self.conn, repo)
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

    pub fn identity_of(&self, issuer: &str, subject: &str) -> CoreResult<Option<PrincipalId>> {
        raw::identity_of(&self.conn, issuer, subject)
    }

    pub fn identities_of(
        &self,
        principal: &PrincipalId,
    ) -> CoreResult<Vec<crate::types::IdentityLink>> {
        raw::identities_of(&self.conn, principal.as_str())
    }

    pub fn workload_bindings_of(
        &self,
        principal: &PrincipalId,
    ) -> CoreResult<Vec<crate::types::WorkloadBinding>> {
        raw::workload_bindings_of(&self.conn, principal.as_str())
    }

    pub fn draw_of(&self, change: &ChangeId) -> CoreResult<Option<crate::attention::Draw>> {
        raw::draw_of(&self.conn, change.as_str())
    }

    pub fn threads_on(&self, change: &ChangeId) -> CoreResult<Vec<Thread>> {
        raw::threads_on(&self.conn, change.as_str())
    }

    pub fn thread(&self, id: &ThreadId) -> CoreResult<Option<Thread>> {
        raw::thread(&self.conn, id.as_str())
    }

    pub fn verifications_on(
        &self,
        change: &ChangeId,
        revision: i64,
    ) -> CoreResult<Vec<Verification>> {
        raw::verifications_on(&self.conn, change.as_str(), revision)
    }
}
