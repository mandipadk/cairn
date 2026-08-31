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
use crate::types::Policy;
use rusqlite::{Connection, Transaction, params};
use std::path::Path;

/// Bump whenever a projection table changes shape. The log is never
/// touched; projections are rebuilt from it.
const SCHEMA_VERSION: i64 = 6;

/// The log itself, which outlives every schema.
const EVENT_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS events (
  seq     INTEGER PRIMARY KEY AUTOINCREMENT,
  ts      TEXT NOT NULL,
  actor   TEXT NOT NULL,
  kind    TEXT NOT NULL,
  payload TEXT NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS idx_events_kind ON events (kind, seq);
";

/// State that is deliberately *not* derived from the log.
///
/// The log records decisions about software, and it is append-only, so
/// anything written there can never be rotated out or erased. Neither
/// property suits authentication material: a password must be
/// changeable in a way that retires the old secret, and a session must
/// be revocable and must expire. Keeping them here — same database,
/// outside the projections — is what lets them be updated and deleted
/// like the operational records they are.
///
/// Consequently a replay does not reconstruct these, which is correct:
/// they are not consequences of the log. Rebuilding projections leaves
/// them untouched, and `fsck` does not compare them, because there is
/// nothing to compare them against.
const OPERATIONAL_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS credentials (
  principal TEXT PRIMARY KEY,
  hash      TEXT NOT NULL,
  set_at    TEXT NOT NULL
) STRICT;

-- Not `sessions`: that already means an agent's run of work against a
-- task, and this is somebody's browser being signed in. Two different
-- things with one name is how a silent CREATE TABLE IF NOT EXISTS ends
-- up writing to the wrong table.
CREATE TABLE IF NOT EXISTS browser_sessions (
  id_hash   TEXT PRIMARY KEY,
  principal TEXT NOT NULL,
  created   TEXT NOT NULL,
  expires   TEXT NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS idx_browser_sessions_principal ON browser_sessions (principal);
CREATE INDEX IF NOT EXISTS idx_browser_sessions_expires ON browser_sessions (expires);

-- People who asked to be told when this is ready. Not a decision about
-- software and not derived from anything, so it is not in the log —
-- which also means someone can be removed when they ask to be, which an
-- append-only log could never honour.
CREATE TABLE IF NOT EXISTS waitlist (
  email  TEXT PRIMARY KEY,
  joined TEXT NOT NULL,
  note   TEXT
) STRICT;
";

/// Everything derived. Dropping and replaying these is always safe:
/// the log is the truth and this is only its current shape.
const PROJECTION_SCHEMA: &str = "

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
  object_format  TEXT NOT NULL DEFAULT 'sha1',
  policy         TEXT NOT NULL DEFAULT '{}',
  mirror         TEXT,
  visibility     TEXT NOT NULL DEFAULT 'private'
) STRICT;

CREATE TABLE IF NOT EXISTS imports (
  repo    TEXT NOT NULL,
  branch  TEXT NOT NULL,
  source  TEXT NOT NULL,
  tip_oid TEXT NOT NULL,
  commits INTEGER NOT NULL,
  PRIMARY KEY (repo, branch)
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

/// Every table derived from the log.
///
/// One list, used both to drop projections for a rebuild and to compare
/// them in [`Store::fsck`], so the two can never disagree about what the
/// log is supposed to produce. A new projection table belongs here the
/// moment it exists; forgetting means a rebuild leaves it stale and fsck
/// never looks at it.
const PROJECTION_TABLES: &[&str] = &[
    "principals",
    "tokens",
    "grants",
    "repos",
    "imports",
    "tasks",
    "sessions",
    "leases",
    "changes",
    "revisions",
    "claims",
    "merge_queue",
    "verifications",
    "verdicts",
];

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

    /// Check that current state is nothing more than the log applied.
    ///
    /// That claim is the foundation everything else rests on, and it is
    /// checkable rather than merely asserted: replay the log into empty
    /// projections and see whether the answer matches what is live. A
    /// divergence means either a projection was written by something
    /// other than an event, or replaying the same log twice does not
    /// produce the same state — and both make every downstream promise,
    /// including the policy trace on a merge, worth nothing.
    ///
    /// Returns one line per divergence; empty means clean. Descriptions
    /// name tables and row positions rather than contents, so this is
    /// safe to print and paste.
    pub fn fsck(&self) -> CoreResult<Vec<String>> {
        let mut shadow = Connection::open_in_memory()?;
        shadow.execute_batch(PROJECTION_SCHEMA)?;
        {
            let tx = shadow.transaction()?;
            replay_into(&tx, &self.conn)?;
            tx.commit()?;
        }

        let mut divergences = Vec::new();
        for table in PROJECTION_TABLES {
            let live = dump_table(&self.conn, table)?;
            let replayed = dump_table(&shadow, table)?;
            if live == replayed {
                continue;
            }
            if live.len() != replayed.len() {
                divergences.push(format!(
                    "{table}: {} row(s) live, {} produced by the log",
                    live.len(),
                    replayed.len()
                ));
                continue;
            }
            let differing = live
                .iter()
                .zip(&replayed)
                .enumerate()
                .filter(|(_, (a, b))| a != b)
                .map(|(index, _)| index)
                .collect::<Vec<_>>();
            divergences.push(format!(
                "{table}: {} of {} row(s) differ from the log (first at row {})",
                differing.len(),
                live.len(),
                differing.first().copied().unwrap_or(0)
            ));
        }
        Ok(divergences)
    }

    fn init(mut conn: Connection) -> CoreResult<Self> {
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch(EVENT_SCHEMA)?;
        conn.execute_batch(OPERATIONAL_SCHEMA)?;

        // Projections are derived, so a schema change is not a
        // migration problem: drop them and replay the log. This is the
        // event-sourced design paying for itself — there is no
        // hand-written ALTER to get wrong, and the rebuilt state is
        // exactly "the log, applied", the same invariant that holds
        // at runtime.
        let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version != SCHEMA_VERSION {
            rebuild_projections(&mut conn)?;
            conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        }
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

/// One projection table, rendered as ordered rows of text so two
/// databases can be compared without knowing anything about the schema.
fn dump_table(conn: &Connection, table: &str) -> CoreResult<Vec<String>> {
    // Row order is not guaranteed by SQLite, so sort by every column:
    // the comparison is about contents, not storage order.
    let width = conn
        .prepare(&format!("SELECT * FROM {table} LIMIT 0"))?
        .column_count();
    let order = (1..=width)
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let mut stmt = conn.prepare(&format!("SELECT * FROM {table} ORDER BY {order}"))?;
    let rows = stmt.query_map([], |row| {
        let mut cells = Vec::with_capacity(width);
        for index in 0..width {
            cells.push(match row.get_ref(index)? {
                rusqlite::types::ValueRef::Null => "NULL".to_owned(),
                rusqlite::types::ValueRef::Integer(value) => value.to_string(),
                rusqlite::types::ValueRef::Real(value) => value.to_string(),
                rusqlite::types::ValueRef::Text(value) => {
                    String::from_utf8_lossy(value).into_owned()
                }
                rusqlite::types::ValueRef::Blob(value) => format!("blob:{}", value.len()),
            });
        }
        Ok(cells.join("\u{1f}"))
    })?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

/// Replay every event into empty projections and apply them to `tx`.
fn replay_into(tx: &Transaction, source: &Connection) -> CoreResult<u64> {
    let mut stmt = source.prepare("SELECT seq, ts, actor, payload FROM events ORDER BY seq")?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?;
    let mut replayed = 0;
    for row in rows {
        let (seq, ts, actor, payload) = row?;
        let event: Event = serde_json::from_str(&payload).map_err(|e| CoreError::Corrupt {
            at: format!("event seq {seq}"),
            reason: e.to_string(),
        })?;
        apply(
            tx,
            &Envelope {
                seq: EventSeq(seq),
                ts,
                actor: PrincipalId(actor),
                event,
            },
        )?;
        replayed += 1;
    }
    Ok(replayed)
}

/// Rebuild every projection by replaying the log into it.
fn rebuild_projections(conn: &mut Connection) -> CoreResult<()> {
    let tx = conn.transaction()?;
    for table in PROJECTION_TABLES {
        tx.execute_batch(&format!("DROP TABLE IF EXISTS {table};"))?;
    }
    tx.execute_batch(PROJECTION_SCHEMA)?;

    let mut replayed = 0u64;
    let mut cursor = 0i64;
    loop {
        let batch = {
            let mut stmt = tx.prepare(
                "SELECT seq, ts, actor, payload FROM events
                 WHERE seq > ? ORDER BY seq LIMIT 1000",
            )?;
            let rows = stmt.query_map(params![cursor], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        if batch.is_empty() {
            break;
        }
        for (seq, ts, actor, payload) in batch {
            let event: Event = serde_json::from_str(&payload).map_err(|e| CoreError::Corrupt {
                at: format!("event seq {seq}"),
                reason: e.to_string(),
            })?;
            apply(
                &tx,
                &Envelope {
                    seq: EventSeq(seq),
                    ts,
                    actor: PrincipalId(actor),
                    event,
                },
            )?;
            cursor = seq;
            replayed += 1;
        }
    }
    tx.commit()?;
    if replayed > 0 {
        tracing_replay(replayed);
    }
    Ok(())
}

/// Rebuilding is rare and worth a line in the log of whoever is
/// watching, but the core does not depend on a logging framework.
fn tracing_replay(events: u64) {
    eprintln!("cairn: projections rebuilt by replaying {events} events");
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
        // The credential itself is not in the event and not a
        // projection; this records only that it happened, and when.
        Event::PasswordSet { .. } => {}
        Event::RepoCreated {
            repo,
            default_branch,
            object_format,
        } => {
            tx.execute(
                "INSERT INTO repos (name, default_branch, object_format, policy)
                 VALUES (?, ?, ?, ?)",
                params![
                    repo,
                    default_branch,
                    object_format.as_str(),
                    serde_json::to_string(&Policy::default()).expect("policy serializes")
                ],
            )?;
        }
        Event::HistoryImported {
            repo,
            branch,
            source,
            tip_oid,
            commits,
        } => {
            tx.execute(
                "INSERT OR REPLACE INTO imports (repo, branch, source, tip_oid, commits)
                 VALUES (?, ?, ?, ?, ?)",
                params![repo, branch, source, tip_oid, commits],
            )?;
        }
        Event::VisibilitySet { repo, visibility } => {
            tx.execute(
                "UPDATE repos SET visibility = ? WHERE name = ?",
                params![visibility.as_str(), repo],
            )?;
        }
        Event::MirrorSet { repo, mirror } => {
            tx.execute(
                "UPDATE repos SET mirror = ? WHERE name = ?",
                params![
                    mirror
                        .as_ref()
                        .map(|m| serde_json::to_string(m).expect("mirror serializes")),
                    repo
                ],
            )?;
        }
        // An attempt is a fact about the outside world, not a change
        // to the graph's own state.
        Event::MirrorPushed { .. } => {}
        Event::PolicySet { repo, policy } => {
            tx.execute(
                "UPDATE repos SET policy = ? WHERE name = ?",
                params![
                    serde_json::to_string(policy).expect("policy serializes"),
                    repo
                ],
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
        // A failed rebase changes nothing about the graph's state; it
        // is a fact about an attempt, and lives only in the log.
        Event::RebaseFailed { .. } => {}
        Event::ChangeAbandoned { change, .. } => {
            tx.execute(
                "UPDATE changes SET state = 'abandoned' WHERE id = ?",
                params![change.as_str()],
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::PrincipalKind;

    /// fsck is only worth running if it can fail. A check that always
    /// reports "clean" passes every positive test ever written for it,
    /// so the important assertion is that deliberately unexplained state
    /// gets caught.
    #[test]
    fn fsck_notices_state_the_log_does_not_explain() {
        let mut store = Store::open_in_memory().unwrap();
        let ada = PrincipalId::new("ada").unwrap();
        store
            .register_principal(&ada, &ada, PrincipalKind::Human, "Ada", None, None)
            .unwrap();
        store
            .create_repo(&ada, "demo", "main", Default::default())
            .unwrap();
        assert!(
            store.fsck().unwrap().is_empty(),
            "a store built only from events should be clean"
        );

        // A row nothing in the log ever asked for: the shape of the bug
        // this exists to find — a projection written by something other
        // than an event.
        store
            .conn
            .execute(
                "INSERT INTO repos (name, default_branch, object_format, policy)
                 VALUES ('ghost', 'main', 'sha1', '{}')",
                [],
            )
            .unwrap();
        let divergences = store.fsck().unwrap();
        assert!(
            divergences.iter().any(|d| d.starts_with("repos:")),
            "an unexplained repo row must be reported; got {divergences:#?}"
        );

        // And an edited row, which is subtler than an extra one: same
        // count, different contents.
        let mut store = Store::open_in_memory().unwrap();
        store
            .register_principal(&ada, &ada, PrincipalKind::Human, "Ada", None, None)
            .unwrap();
        store
            .create_repo(&ada, "demo", "main", Default::default())
            .unwrap();
        store
            .conn
            .execute(
                "UPDATE repos SET default_branch = 'trunk' WHERE name = 'demo'",
                [],
            )
            .unwrap();
        let divergences = store.fsck().unwrap();
        assert!(
            divergences.iter().any(|d| d.starts_with("repos:")),
            "an edited repo row must be reported; got {divergences:#?}"
        );
    }

    /// Replaying the same log twice must produce the same state, or the
    /// rebuild that runs on every schema change is not deterministic.
    #[test]
    fn replay_is_deterministic() {
        let mut store = Store::open_in_memory().unwrap();
        let ada = PrincipalId::new("ada").unwrap();
        store
            .register_principal(&ada, &ada, PrincipalKind::Human, "Ada", None, None)
            .unwrap();
        for name in ["one", "two", "three"] {
            store
                .create_repo(&ada, name, "main", Default::default())
                .unwrap();
        }
        let before: Vec<Vec<String>> = PROJECTION_TABLES
            .iter()
            .map(|table| dump_table(&store.conn, table).unwrap())
            .collect();
        rebuild_projections(&mut store.conn).unwrap();
        let after: Vec<Vec<String>> = PROJECTION_TABLES
            .iter()
            .map(|table| dump_table(&store.conn, table).unwrap())
            .collect();
        assert_eq!(before, after, "a rebuild must not change what state says");
    }
}

#[cfg(test)]
mod concurrency_tests {
    use super::*;
    use crate::id::ChangeId;
    use crate::types::{
        Capability, ChangeSpec, ClaimKind, ClaimSpec, Independence, Policy, PrincipalKind,
    };

    /// Build a store on disk holding one change that is ready to land.
    fn ready_change(path: &std::path::Path) -> (PrincipalId, ChangeId) {
        let mut store = Store::open(path).unwrap();
        let ada = PrincipalId::new("ada").unwrap();
        store
            .register_principal(&ada, &ada, PrincipalKind::Human, "Ada", None, None)
            .unwrap();
        store
            .create_repo(&ada, "demo", "main", Default::default())
            .unwrap();
        // Isolate the question: policy is satisfied, so the only thing
        // that can stop a second merge is the concurrency guard.
        store
            .set_policy(
                &ada,
                "demo",
                Policy {
                    require_executed_check: false,
                    require_runner_verification: false,
                    independence: Independence::None,
                    required_domains: Vec::new(),
                },
            )
            .unwrap();
        let (change, _, _) = store
            .open_change(
                &ada,
                ChangeSpec {
                    repo: "demo".into(),
                    target: "main".into(),
                    title: "Racy".into(),
                    task: None,
                    parent_change: None,
                    external_key: None,
                },
            )
            .unwrap();
        store
            .push_revision(&ada, &change, &"a".repeat(40), None, "m")
            .unwrap();
        store
            .attach_claim(
                &ada,
                &change,
                1,
                ClaimSpec {
                    kind: ClaimKind::Test,
                    command: Some("true".into()),
                    passed: true,
                    summary: "ok".into(),
                    unchecked: Vec::new(),
                },
            )
            .unwrap();
        let _ = Capability::Merge;
        (ada, change)
    }

    /// Two forge processes can share one database — an overlapping
    /// restart is enough to arrange it. Neither may land the same change,
    /// because a second merge event would mean the log records a decision
    /// that was never made and the branch moved twice for one change.
    #[test]
    fn a_change_cannot_be_merged_twice_from_two_connections() {
        // A barrier only guarantees the two threads *start* together, so
        // one attempt would prove little. Repeat the race: over this many
        // rounds the interleavings vary, and every round must still leave
        // exactly one merge.
        for round in 0..12 {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("forge.db");
            let (ada, change) = ready_change(&path);

            // Two independent connections, as two processes would have.
            let mut one = Store::open(&path).unwrap();
            let mut two = Store::open(&path).unwrap();

            let barrier = std::sync::Barrier::new(2);
            let (first, second) = std::thread::scope(|scope| {
                let a = scope.spawn(|| {
                    barrier.wait();
                    one.merge_change_as(&ada, &change, None)
                });
                let b = scope.spawn(|| {
                    barrier.wait();
                    two.merge_change_as(&ada, &change, None)
                });
                (a.join().unwrap(), b.join().unwrap())
            });

            let winners = [&first, &second].iter().filter(|r| r.is_ok()).count();
            assert_eq!(
                winners, 1,
                "round {round}: exactly one merge may succeed, and one must — \
                 got first={first:?} second={second:?}"
            );

            // The log is the real check, whatever the calls returned.
            let store = Store::open(&path).unwrap();
            let merged: i64 = store
                .conn
                .query_row(
                    "SELECT count(*) FROM events WHERE kind = 'change_merged'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(merged, 1, "round {round}: the log must record one merge");
            assert!(
                store.fsck().unwrap().is_empty(),
                "round {round}: state must still be explained by the log"
            );
        }
    }
}

#[cfg(test)]
mod exhaustion_tests {
    use super::*;
    use crate::types::PrincipalKind;

    /// A full disk must fail a write, not damage the log.
    ///
    /// Every command is one transaction, so a write that cannot complete
    /// should roll back whole: no half-applied projection, no event
    /// without its effect. `max_page_count` reproduces the condition
    /// exactly — SQLite reports the same SQLITE_FULL it reports when the
    /// filesystem has nothing left — without needing a real disk to be
    /// filled underneath the test.
    #[test]
    fn a_database_with_no_room_left_fails_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("forge.db");
        let mut store = Store::open(&path).unwrap();
        let ada = PrincipalId::new("ada").unwrap();
        store
            .register_principal(&ada, &ada, PrincipalKind::Human, "Ada", None, None)
            .unwrap();
        store
            .create_repo(&ada, "demo", "main", Default::default())
            .unwrap();

        let used: i64 = store
            .conn
            .query_row("PRAGMA page_count", [], |row| row.get(0))
            .unwrap();
        // Just enough headroom to start a transaction and not finish many.
        store
            .conn
            .pragma_update(None, "max_page_count", used + 2)
            .unwrap();

        let mut refused = None;
        for n in 0..2_000 {
            // Bounded but not tiny, so the file has to grow.
            let title = format!("task {n} {}", "x".repeat(200));
            match store.create_task(&ada, Some("demo"), &title, "spec", None) {
                Ok(_) => continue,
                Err(err) => {
                    refused = Some(err);
                    break;
                }
            }
        }
        let refused = refused.expect("a database with no room must eventually refuse a write");
        assert!(
            format!("{refused}").to_lowercase().contains("full")
                || format!("{refused}").to_lowercase().contains("database"),
            "the refusal should say what happened: {refused}"
        );

        // The point: whatever failed, failed entirely. Give the database
        // room again and the log must still explain every projection.
        store
            .conn
            .pragma_update(None, "max_page_count", 1_073_741_823i64)
            .unwrap();
        assert!(
            store.fsck().unwrap().is_empty(),
            "a refused write must leave no half-applied state behind"
        );

        // And the forge keeps working once there is room.
        store
            .create_task(&ada, Some("demo"), "after", "spec", None)
            .expect("writes resume once the database has room");
        assert!(store.fsck().unwrap().is_empty());
    }
}

#[cfg(test)]
mod credential_tests {
    use super::*;
    use crate::types::PrincipalKind;

    fn human(path: &std::path::Path) -> (Store, PrincipalId) {
        let mut store = Store::open(path).unwrap();
        let ada = PrincipalId::new("ada").unwrap();
        store
            .register_principal(&ada, &ada, PrincipalKind::Human, "Ada", None, None)
            .unwrap();
        (store, ada)
    }

    /// The whole reason sessions are stored rather than held in memory:
    /// deploying must not sign everybody out.
    #[test]
    fn a_session_outlives_the_process_that_issued_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("forge.db");
        let (mut store, ada) = human(&path);
        store
            .set_password(&ada, &ada, "correct horse battery staple")
            .unwrap();
        let secret = store.start_session(&ada, 14).unwrap();
        drop(store);

        // A new process, the same database.
        let mut restarted = Store::open(&path).unwrap();
        assert_eq!(
            restarted.session_holder(&secret),
            Some(ada.clone()),
            "a restart must not sign anyone out"
        );

        restarted.end_browser_session(&secret).unwrap();
        assert_eq!(
            restarted.session_holder(&secret),
            None,
            "signing out must end it everywhere, not just clear a cookie"
        );
    }

    /// Only a hash is kept, so reading the database yields nothing that
    /// can be replayed as a credential.
    #[test]
    fn the_database_holds_no_usable_session_secret() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("forge.db");
        let (mut store, ada) = human(&path);
        let secret = store.start_session(&ada, 14).unwrap();

        let stored: String = store
            .conn
            .query_row("SELECT id_hash FROM browser_sessions", [], |row| row.get(0))
            .unwrap();
        assert_ne!(stored, secret, "the secret itself must not be stored");
        assert!(
            !stored.contains(&secret) && !secret.contains(&stored),
            "and neither must anything it can be recovered from"
        );
    }

    /// An expiry that has passed is not a session.
    #[test]
    fn an_expired_session_stops_working() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("forge.db");
        let (mut store, ada) = human(&path);
        let secret = store.start_session(&ada, 14).unwrap();
        store
            .conn
            .execute(
                "UPDATE browser_sessions SET expires = '2020-01-01T00:00:00Z'",
                [],
            )
            .unwrap();
        assert_eq!(store.session_holder(&secret), None);
    }

    /// A password is a credential, so it lives where credentials can be
    /// rotated and erased — never in an append-only log.
    #[test]
    fn a_password_hash_never_reaches_the_log() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("forge.db");
        let (mut store, ada) = human(&path);
        store
            .set_password(&ada, &ada, "correct horse battery staple")
            .unwrap();
        store
            .set_password(&ada, &ada, "an entirely different secret")
            .unwrap();

        let payloads: Vec<String> = store
            .conn
            .prepare("SELECT payload FROM events WHERE kind = 'password_set'")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(payloads.len(), 2, "both changes are on the record");
        for payload in &payloads {
            assert!(
                !payload.contains("argon2") && !payload.contains("hash"),
                "the log records that it happened, never the credential: {payload}"
            );
        }

        // Rotation actually retires the old secret.
        assert!(!store.password_matches(&ada, "correct horse battery staple"));
        assert!(store.password_matches(&ada, "an entirely different secret"));

        // Exactly one credential is kept, not a history of them.
        let rows: i64 = store
            .conn
            .query_row("SELECT count(*) FROM credentials", [], |row| row.get(0))
            .unwrap();
        assert_eq!(rows, 1, "a rotated password leaves nothing behind");
    }

    /// Rebuilding projections must not touch operational state: a schema
    /// change to the graph is not a reason to sign everyone out or wipe
    /// everybody's password.
    #[test]
    fn a_projection_rebuild_leaves_credentials_and_sessions_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("forge.db");
        let (mut store, ada) = human(&path);
        store
            .set_password(&ada, &ada, "correct horse battery staple")
            .unwrap();
        let secret = store.start_session(&ada, 14).unwrap();

        rebuild_projections(&mut store.conn).unwrap();

        assert!(
            store.password_matches(&ada, "correct horse battery staple"),
            "a rebuild must not erase credentials"
        );
        assert_eq!(
            store.session_holder(&secret),
            Some(ada),
            "a rebuild must not sign anyone out"
        );
        assert!(store.fsck().unwrap().is_empty());
    }
}

#[cfg(test)]
mod legacy_payload_tests {
    use super::*;

    /// Events written by the earlier design carry a password hash. They
    /// cannot be unwritten — the log is append-only, which is the whole
    /// point — but they must never be handed back out: the event feed
    /// answers any authenticated caller, including one holding nothing
    /// but the verify capability.
    #[test]
    fn a_legacy_password_hash_is_read_but_never_served() {
        let stored = r#"{"kind":"password_set","principal":"ada","hash":"$argon2id$v=19$m=19456,t=2,p=1$abc$def"}"#;
        let event: Event = serde_json::from_str(stored).expect("old events must still replay");
        // Reading works, so the log still applies.
        assert!(
            matches!(&event, Event::PasswordSet { principal, .. } if principal.as_str() == "ada")
        );
        // Writing it back out drops the credential.
        let served = serde_json::to_string(&event).unwrap();
        assert!(
            !served.contains("argon2") && !served.contains("hash"),
            "a credential must not be republished: {served}"
        );
    }
}
