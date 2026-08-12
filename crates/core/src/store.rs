//! The append-only log and its projections.
//!
//! Writes follow one discipline: a command (in `commands.rs`) validates
//! against current projections, constructs events, and appends them; the
//! [`apply`] function here is the only code that mutates projection
//! tables, and it runs in the same transaction as the append. State is
//! therefore always exactly "the log, applied" — replay reproduces it.

use crate::error::{CoreError, CoreResult};
use crate::event::{Envelope, Event, EventSeq};
use crate::id::PrincipalId;
use rusqlite::{Connection, Transaction, params};
use std::path::Path;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS events (
  seq     INTEGER PRIMARY KEY AUTOINCREMENT,
  ts      TEXT NOT NULL,
  actor   TEXT NOT NULL,
  kind    TEXT NOT NULL,
  payload TEXT NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS idx_events_kind ON events (kind, seq);

CREATE TABLE IF NOT EXISTS principals (
  id      TEXT PRIMARY KEY,
  kind    TEXT NOT NULL,
  display TEXT NOT NULL,
  model   TEXT,
  harness TEXT
) STRICT;

CREATE TABLE IF NOT EXISTS tokens (
  id        TEXT PRIMARY KEY,
  principal TEXT NOT NULL,
  label     TEXT,
  hash      TEXT NOT NULL,
  revoked   INTEGER NOT NULL DEFAULT 0
) STRICT;
CREATE INDEX IF NOT EXISTS idx_tokens_hash ON tokens (hash);

CREATE TABLE IF NOT EXISTS grants (
  id      TEXT PRIMARY KEY,
  grantor TEXT NOT NULL,
  grantee TEXT NOT NULL,
  repo    TEXT,
  actions TEXT NOT NULL,
  until_ts TEXT,
  revoked INTEGER NOT NULL DEFAULT 0
) STRICT;
CREATE INDEX IF NOT EXISTS idx_grants_grantee ON grants (grantee, revoked);

CREATE TABLE IF NOT EXISTS repos (
  name           TEXT PRIMARY KEY,
  default_branch TEXT NOT NULL,
  object_format  TEXT NOT NULL DEFAULT 'sha1'
) STRICT;

CREATE TABLE IF NOT EXISTS tasks (
  id         TEXT PRIMARY KEY,
  repo       TEXT,
  title      TEXT NOT NULL,
  spec       TEXT NOT NULL,
  parent     TEXT,
  state      TEXT NOT NULL,
  claimed_by TEXT,
  created_by TEXT NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS idx_tasks_state ON tasks (state);

CREATE TABLE IF NOT EXISTS sessions (
  id      TEXT PRIMARY KEY,
  task    TEXT NOT NULL,
  agent   TEXT NOT NULL,
  state   TEXT NOT NULL,
  outcome TEXT
) STRICT;
CREATE INDEX IF NOT EXISTS idx_sessions_task ON sessions (task);

CREATE TABLE IF NOT EXISTS leases (
  session TEXT PRIMARY KEY,
  repo    TEXT NOT NULL,
  holder  TEXT NOT NULL,
  paths   TEXT NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS idx_leases_repo ON leases (repo);

CREATE TABLE IF NOT EXISTS changes (
  id              TEXT PRIMARY KEY,
  repo            TEXT NOT NULL,
  number          INTEGER NOT NULL,
  target          TEXT NOT NULL,
  title           TEXT NOT NULL,
  task            TEXT,
  parent_change   TEXT,
  state           TEXT NOT NULL,
  owner           TEXT NOT NULL,
  latest_revision INTEGER NOT NULL DEFAULT 0,
  external_key    TEXT,
  landed_oid      TEXT,
  UNIQUE (repo, number)
) STRICT;
CREATE INDEX IF NOT EXISTS idx_changes_repo_state ON changes (repo, state);
CREATE INDEX IF NOT EXISTS idx_changes_landed ON changes (repo, landed_oid);
CREATE UNIQUE INDEX IF NOT EXISTS idx_changes_key
  ON changes (repo, external_key) WHERE external_key IS NOT NULL;

CREATE TABLE IF NOT EXISTS revisions (
  change_id  TEXT NOT NULL,
  number     INTEGER NOT NULL,
  commit_oid TEXT NOT NULL,
  session    TEXT,
  message    TEXT NOT NULL,
  PRIMARY KEY (change_id, number)
) STRICT;

CREATE TABLE IF NOT EXISTS claims (
  id        TEXT PRIMARY KEY,
  change_id TEXT NOT NULL,
  revision  INTEGER NOT NULL,
  kind      TEXT NOT NULL,
  command   TEXT,
  passed    INTEGER NOT NULL,
  summary   TEXT NOT NULL,
  unchecked TEXT NOT NULL,
  by        TEXT NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS idx_claims_change ON claims (change_id, revision);

CREATE TABLE IF NOT EXISTS merge_queue (
  change_id    TEXT PRIMARY KEY,
  repo         TEXT NOT NULL,
  target       TEXT NOT NULL,
  enqueued_by  TEXT NOT NULL,
  enqueued_seq INTEGER NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS idx_queue_lane ON merge_queue (repo, target, enqueued_seq);

CREATE TABLE IF NOT EXISTS verifications (
  id        TEXT PRIMARY KEY,
  claim_id  TEXT NOT NULL,
  change_id TEXT NOT NULL,
  revision  INTEGER NOT NULL,
  agrees    INTEGER NOT NULL,
  command   TEXT NOT NULL,
  observed  TEXT NOT NULL,
  by        TEXT NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS idx_verifications_claim ON verifications (claim_id);
CREATE INDEX IF NOT EXISTS idx_verifications_change ON verifications (change_id, revision);

CREATE TABLE IF NOT EXISTS verdicts (
  id        TEXT PRIMARY KEY,
  change_id TEXT NOT NULL,
  revision  INTEGER NOT NULL,
  domain    TEXT NOT NULL,
  disposition TEXT NOT NULL,
  rationale TEXT NOT NULL,
  by        TEXT NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS idx_verdicts_change ON verdicts (change_id, revision);
";

pub struct Store {
    pub(crate) conn: Connection,
}

impl Store {
    pub fn open(path: &Path) -> CoreResult<Self> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        Self::init(conn)
    }

    /// Ephemeral store for tests and in-process experiments — the whole
    /// forge core can be stood up inside a unit test.
    pub fn open_in_memory() -> CoreResult<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> CoreResult<Self> {
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch(SCHEMA)?;
        Ok(Store { conn })
    }

    /// Events strictly after `cursor`, oldest first. The resume primitive:
    /// a consumer that remembers one integer can always catch up.
    pub fn events_after(&self, cursor: EventSeq, limit: usize) -> CoreResult<Vec<Envelope>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT seq, ts, actor, payload FROM events WHERE seq > ? ORDER BY seq LIMIT ?",
        )?;
        let rows = stmt.query_map(params![cursor.0, limit as i64], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (seq, ts, actor, payload) = row?;
            let event: Event = serde_json::from_str(&payload).map_err(|e| CoreError::Corrupt {
                at: format!("event seq {seq}"),
                reason: e.to_string(),
            })?;
            out.push(Envelope {
                seq: EventSeq(seq),
                ts,
                actor: PrincipalId(actor),
                event,
            });
        }
        Ok(out)
    }

    pub fn latest_seq(&self) -> CoreResult<EventSeq> {
        let seq: i64 =
            self.conn
                .query_row("SELECT COALESCE(MAX(seq), 0) FROM events", [], |r| r.get(0))?;
        Ok(EventSeq(seq))
    }
}

/// Append one event and apply it to projections, inside the caller's
/// transaction. Commands never touch projection tables directly.
pub(crate) fn append(tx: &Transaction, actor: &PrincipalId, event: Event) -> CoreResult<Envelope> {
    let ts = jiff::Timestamp::now().to_string();
    let payload = serde_json::to_string(&event).expect("events are always serializable");
    tx.execute(
        "INSERT INTO events (ts, actor, kind, payload) VALUES (?, ?, ?, ?)",
        params![ts, actor.as_str(), event.kind(), payload],
    )?;
    let envelope = Envelope {
        seq: EventSeq(tx.last_insert_rowid()),
        ts,
        actor: actor.clone(),
        event,
    };
    apply(tx, &envelope)?;
    Ok(envelope)
}

/// The single projector: the only code that writes projection tables.
fn apply(tx: &Transaction, env: &Envelope) -> CoreResult<()> {
    let actor = env.actor.as_str();
    match &env.event {
        Event::PrincipalRegistered {
            principal,
            principal_kind,
            display,
            model,
            harness,
        } => {
            tx.execute(
                "INSERT INTO principals (id, kind, display, model, harness) VALUES (?, ?, ?, ?, ?)",
                params![
                    principal.as_str(),
                    principal_kind.as_str(),
                    display,
                    model,
                    harness
                ],
            )?;
        }
        Event::TokenMinted {
            token,
            principal,
            label,
            hash,
        } => {
            tx.execute(
                "INSERT INTO tokens (id, principal, label, hash) VALUES (?, ?, ?, ?)",
                params![token.as_str(), principal.as_str(), label, hash],
            )?;
        }
        Event::TokenRevoked { token } => {
            tx.execute(
                "UPDATE tokens SET revoked = 1 WHERE id = ?",
                params![token.as_str()],
            )?;
        }
        Event::GrantIssued {
            grant,
            grantee,
            repo,
            actions,
            until,
        } => {
            tx.execute(
                "INSERT INTO grants (id, grantor, grantee, repo, actions, until_ts)
                 VALUES (?, ?, ?, ?, ?, ?)",
                params![
                    grant.as_str(),
                    actor,
                    grantee.as_str(),
                    repo,
                    serde_json::to_string(actions).expect("capability vec serializes"),
                    until
                ],
            )?;
        }
        Event::GrantRevoked { grant, .. } => {
            tx.execute(
                "UPDATE grants SET revoked = 1 WHERE id = ?",
                params![grant.as_str()],
            )?;
        }
        Event::RepoCreated {
            repo,
            default_branch,
            object_format,
        } => {
            tx.execute(
                "INSERT INTO repos (name, default_branch, object_format) VALUES (?, ?, ?)",
                params![repo, default_branch, object_format.as_str()],
            )?;
        }
        Event::TaskCreated {
            task,
            repo,
            title,
            spec,
            parent,
        } => {
            tx.execute(
                "INSERT INTO tasks (id, repo, title, spec, parent, state, created_by)
                 VALUES (?, ?, ?, ?, ?, 'open', ?)",
                params![
                    task.as_str(),
                    repo,
                    title,
                    spec,
                    parent.as_ref().map(|p| p.as_str()),
                    actor
                ],
            )?;
        }
        Event::TaskClaimed { task } => {
            tx.execute(
                "UPDATE tasks SET state = 'claimed', claimed_by = ? WHERE id = ?",
                params![actor, task.as_str()],
            )?;
        }
        Event::TaskStateChanged { task, state } => {
            tx.execute(
                "UPDATE tasks SET state = ? WHERE id = ?",
                params![state.as_str(), task.as_str()],
            )?;
        }
        Event::SessionOpened { session, task } => {
            tx.execute(
                "INSERT INTO sessions (id, task, agent, state) VALUES (?, ?, ?, 'active')",
                params![session.as_str(), task.as_str(), actor],
            )?;
        }
        Event::PathsDeclared {
            session,
            repo,
            paths,
        } => {
            // Re-declaring replaces: an agent that narrows its scope
            // should release the ground it no longer needs.
            tx.execute(
                "INSERT INTO leases (session, repo, holder, paths) VALUES (?, ?, ?, ?)
                 ON CONFLICT(session) DO UPDATE SET repo = excluded.repo, paths = excluded.paths",
                params![
                    session.as_str(),
                    repo,
                    actor,
                    serde_json::to_string(paths).expect("string vec serializes")
                ],
            )?;
        }
        Event::SessionEnded {
            session,
            state,
            outcome,
        } => {
            tx.execute(
                "UPDATE sessions SET state = ?, outcome = ? WHERE id = ?",
                params![state.as_str(), outcome, session.as_str()],
            )?;
            // A lease lives exactly as long as the work behind it.
            tx.execute(
                "DELETE FROM leases WHERE session = ?",
                params![session.as_str()],
            )?;
        }
        Event::ChangeOpened {
            change,
            repo,
            number,
            target,
            title,
            task,
            parent_change,
            external_key,
        } => {
            tx.execute(
                "INSERT INTO changes (id, repo, number, target, title, task, parent_change, state, owner, external_key)
                 VALUES (?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)",
                params![
                    change.as_str(),
                    repo,
                    number,
                    target,
                    title,
                    task.as_ref().map(|t| t.as_str()),
                    parent_change.as_ref().map(|c| c.as_str()),
                    actor,
                    external_key
                ],
            )?;
        }
        Event::RevisionPushed {
            change,
            revision,
            commit_oid,
            session,
            message,
        } => {
            tx.execute(
                "INSERT INTO revisions (change_id, number, commit_oid, session, message)
                 VALUES (?, ?, ?, ?, ?)",
                params![
                    change.as_str(),
                    revision,
                    commit_oid,
                    session.as_ref().map(|s| s.as_str()),
                    message
                ],
            )?;
            tx.execute(
                "UPDATE changes SET latest_revision = ? WHERE id = ?",
                params![revision, change.as_str()],
            )?;
        }
        Event::ClaimAttached {
            claim,
            change,
            revision,
            claim_kind,
            command,
            passed,
            summary,
            unchecked,
        } => {
            tx.execute(
                "INSERT INTO claims (id, change_id, revision, kind, command, passed, summary, unchecked, by)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                params![
                    claim.as_str(),
                    change.as_str(),
                    revision,
                    claim_kind.as_str(),
                    command,
                    *passed as i64,
                    summary,
                    serde_json::to_string(unchecked).expect("string vec serializes"),
                    actor
                ],
            )?;
        }
        Event::ClaimVerified {
            verification,
            claim,
            change,
            revision,
            agrees,
            command,
            observed,
        } => {
            tx.execute(
                "INSERT INTO verifications
                 (id, claim_id, change_id, revision, agrees, command, observed, by)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                params![
                    verification.as_str(),
                    claim.as_str(),
                    change.as_str(),
                    revision,
                    *agrees as i64,
                    command,
                    observed,
                    actor
                ],
            )?;
        }
        Event::VerdictGiven {
            verdict,
            change,
            revision,
            domain,
            disposition,
            rationale,
        } => {
            tx.execute(
                "INSERT INTO verdicts (id, change_id, revision, domain, disposition, rationale, by)
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
                params![
                    verdict.as_str(),
                    change.as_str(),
                    revision,
                    domain.as_str(),
                    disposition.as_str(),
                    rationale,
                    actor
                ],
            )?;
        }
        Event::ChangeEnqueued { change } => {
            tx.execute(
                "INSERT INTO merge_queue (change_id, repo, target, enqueued_by, enqueued_seq)
                 SELECT id, repo, target, ?, ? FROM changes WHERE id = ?",
                params![actor, env.seq.0, change.as_str()],
            )?;
        }
        Event::ChangeDequeued { change, .. } => {
            tx.execute(
                "DELETE FROM merge_queue WHERE change_id = ?",
                params![change.as_str()],
            )?;
        }
        Event::ChangeMerged {
            change,
            revision,
            merged_as,
            ..
        } => {
            // The landed commit is what the branch now carries: the
            // rebased oid when the queue rewrote it, else the revision's.
            tx.execute(
                "UPDATE changes SET state = 'merged', landed_oid = COALESCE(
                     ?,
                     (SELECT commit_oid FROM revisions WHERE change_id = ? AND number = ?)
                 ) WHERE id = ?",
                params![merged_as, change.as_str(), revision, change.as_str()],
            )?;
            // A merged change leaves the queue however it landed.
            tx.execute(
                "DELETE FROM merge_queue WHERE change_id = ?",
                params![change.as_str()],
            )?;
        }
        Event::ChangeAbandoned { change, .. } => {
            tx.execute(
                "UPDATE changes SET state = 'abandoned' WHERE id = ?",
                params![change.as_str()],
            )?;
        }
    }
    Ok(())
}
