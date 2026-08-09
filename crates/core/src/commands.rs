//! Write side of the graph: the protocol verbs.
//!
//! Each command runs validate → append → apply in one transaction, so a
//! command either fully happens (event logged, projections consistent)
//! or leaves no trace. The verbs deliberately mirror how work actually
//! flows: claim a task, open a session, push revisions, attach claims,
//! collect verdicts, merge under policy.

use crate::error::{CoreError, CoreResult};
use crate::event::{Envelope, Event};
use crate::id::{ChangeId, ClaimId, PrincipalId, SessionId, TaskId, VerdictId, validate_slug};
use crate::policy::{self, PolicyTrace};
use crate::queries::raw;
use crate::store::{Store, append};
use crate::types::{
    ChangeSpec, ChangeState, ClaimSpec, Disposition, Principal, PrincipalKind, ReviewDomain,
    SessionState, TaskState,
};
use rusqlite::Transaction;

fn ensure_actor(tx: &Transaction, actor: &PrincipalId) -> CoreResult<Principal> {
    raw::principal(tx, actor.as_str())?
        .ok_or_else(|| CoreError::NotFound(format!("principal {actor}")))
}

fn require(condition: bool, invalid: impl FnOnce() -> String) -> CoreResult<()> {
    if condition {
        Ok(())
    } else {
        Err(CoreError::Invalid(invalid()))
    }
}

fn valid_branch(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with(['-', '/'])
        && !name.ends_with('/')
        && !name.contains("..")
        && !name.contains(|c: char| c.is_whitespace() || c == '\\' || c == ':' || c == '~')
}

fn valid_commit_oid(oid: &str) -> bool {
    matches!(oid.len(), 40 | 64) && oid.chars().all(|c| c.is_ascii_hexdigit())
}

impl Store {
    /// Register a principal. Bootstrap exception: the very first principal
    /// may register itself, since no authority exists yet to vouch for it.
    pub fn register_principal(
        &mut self,
        actor: &PrincipalId,
        id: &PrincipalId,
        kind: PrincipalKind,
        display: &str,
        model: Option<&str>,
        harness: Option<&str>,
    ) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        require(validate_slug(id.as_str()), || {
            format!("principal id {id:?} is not a valid slug")
        })?;
        require(!display.trim().is_empty(), || {
            "display name must not be empty".into()
        })?;
        if raw::principal(&tx, id.as_str())?.is_some() {
            return Err(CoreError::Conflict(format!(
                "principal {id} already exists"
            )));
        }
        let bootstrap = raw::principal_count(&tx)? == 0 && actor == id;
        if !bootstrap {
            ensure_actor(&tx, actor)?;
        }
        let env = append(
            &tx,
            actor,
            Event::PrincipalRegistered {
                principal: id.clone(),
                principal_kind: kind,
                display: display.to_owned(),
                model: model.map(str::to_owned),
                harness: harness.map(str::to_owned),
            },
        )?;
        tx.commit()?;
        Ok(env)
    }

    pub fn create_repo(
        &mut self,
        actor: &PrincipalId,
        name: &str,
        default_branch: &str,
    ) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        ensure_actor(&tx, actor)?;
        require(validate_slug(name), || {
            format!("repo name {name:?} is not a valid slug")
        })?;
        require(valid_branch(default_branch), || {
            format!("{default_branch:?} is not a valid branch name")
        })?;
        if raw::repo(&tx, name)?.is_some() {
            return Err(CoreError::Conflict(format!("repo {name} already exists")));
        }
        let env = append(
            &tx,
            actor,
            Event::RepoCreated {
                repo: name.to_owned(),
                default_branch: default_branch.to_owned(),
            },
        )?;
        tx.commit()?;
        Ok(env)
    }

    pub fn create_task(
        &mut self,
        actor: &PrincipalId,
        repo: Option<&str>,
        title: &str,
        spec: &str,
        parent: Option<&TaskId>,
    ) -> CoreResult<(TaskId, Envelope)> {
        let tx = self.conn.transaction()?;
        ensure_actor(&tx, actor)?;
        require(!title.trim().is_empty(), || {
            "task title must not be empty".into()
        })?;
        require(!spec.trim().is_empty(), || {
            "task spec must not be empty: the spec is the durable intent".into()
        })?;
        if let Some(repo) = repo {
            raw::repo(&tx, repo)?.ok_or_else(|| CoreError::NotFound(format!("repo {repo}")))?;
        }
        if let Some(parent) = parent {
            raw::task(&tx, parent.as_str())?
                .ok_or_else(|| CoreError::NotFound(format!("task {parent}")))?;
        }
        let task = TaskId::generate();
        let env = append(
            &tx,
            actor,
            Event::TaskCreated {
                task: task.clone(),
                repo: repo.map(str::to_owned),
                title: title.to_owned(),
                spec: spec.to_owned(),
                parent: parent.cloned(),
            },
        )?;
        tx.commit()?;
        Ok((task, env))
    }

    pub fn claim_task(&mut self, actor: &PrincipalId, task: &TaskId) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        ensure_actor(&tx, actor)?;
        let current = raw::task(&tx, task.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("task {task}")))?;
        if current.state != TaskState::Open {
            return Err(CoreError::Conflict(format!(
                "task {task} is {}, not open",
                current.state.as_str()
            )));
        }
        let env = append(&tx, actor, Event::TaskClaimed { task: task.clone() })?;
        tx.commit()?;
        Ok(env)
    }

    pub fn set_task_state(
        &mut self,
        actor: &PrincipalId,
        task: &TaskId,
        state: TaskState,
    ) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        ensure_actor(&tx, actor)?;
        raw::task(&tx, task.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("task {task}")))?;
        require(state != TaskState::Claimed, || {
            "use claim_task to claim; claiming records who claimed".into()
        })?;
        let env = append(
            &tx,
            actor,
            Event::TaskStateChanged {
                task: task.clone(),
                state,
            },
        )?;
        tx.commit()?;
        Ok(env)
    }

    /// Open a session: one run of work against a task the actor has
    /// claimed. Claiming first is deliberate — it is the coordination
    /// point that stops two agents burning tokens on the same task.
    pub fn open_session(
        &mut self,
        actor: &PrincipalId,
        task: &TaskId,
    ) -> CoreResult<(SessionId, Envelope)> {
        let tx = self.conn.transaction()?;
        ensure_actor(&tx, actor)?;
        let current = raw::task(&tx, task.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("task {task}")))?;
        if current.state != TaskState::Claimed || current.claimed_by.as_ref() != Some(actor) {
            return Err(CoreError::Conflict(format!(
                "task {task} must be claimed by {actor} before opening a session"
            )));
        }
        let session = SessionId::generate();
        let env = append(
            &tx,
            actor,
            Event::SessionOpened {
                session: session.clone(),
                task: task.clone(),
            },
        )?;
        tx.commit()?;
        Ok((session, env))
    }

    /// End a session. The outcome text is mandatory, for failures most of
    /// all: what was tried and why it didn't work is the knowledge the
    /// next session (or the next agent) starts from.
    pub fn end_session(
        &mut self,
        actor: &PrincipalId,
        session: &SessionId,
        state: SessionState,
        outcome: &str,
    ) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        ensure_actor(&tx, actor)?;
        require(state != SessionState::Active, || {
            "a session cannot end as active".into()
        })?;
        require(!outcome.trim().is_empty(), || {
            "session outcome must not be empty: record what happened for the next reader".into()
        })?;
        let current = raw::session(&tx, session.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("session {session}")))?;
        if current.agent != *actor {
            return Err(CoreError::Conflict(format!(
                "session {session} belongs to {}",
                current.agent
            )));
        }
        if current.state != SessionState::Active {
            return Err(CoreError::Conflict(format!(
                "session {session} already ended"
            )));
        }
        let env = append(
            &tx,
            actor,
            Event::SessionEnded {
                session: session.clone(),
                state,
                outcome: outcome.to_owned(),
            },
        )?;
        tx.commit()?;
        Ok(env)
    }

    pub fn open_change(
        &mut self,
        actor: &PrincipalId,
        spec: ChangeSpec,
    ) -> CoreResult<(ChangeId, i64, Envelope)> {
        let tx = self.conn.transaction()?;
        ensure_actor(&tx, actor)?;
        raw::repo(&tx, &spec.repo)?
            .ok_or_else(|| CoreError::NotFound(format!("repo {}", spec.repo)))?;
        require(valid_branch(&spec.target), || {
            format!("{:?} is not a valid branch name", spec.target)
        })?;
        require(!spec.title.trim().is_empty(), || {
            "change title must not be empty".into()
        })?;
        if let Some(task) = &spec.task {
            raw::task(&tx, task.as_str())?
                .ok_or_else(|| CoreError::NotFound(format!("task {task}")))?;
        }
        if let Some(key) = &spec.external_key {
            require(
                (1..=100).contains(&key.len()) && !key.contains(char::is_whitespace),
                || format!("{key:?} is not a valid external key"),
            )?;
            if raw::change_by_key(&tx, &spec.repo, key)?.is_some() {
                return Err(CoreError::Conflict(format!(
                    "a change with key {key} already exists in {}",
                    spec.repo
                )));
            }
        }
        if let Some(parent) = &spec.parent_change {
            let parent_change = raw::change(&tx, parent.as_str())?
                .ok_or_else(|| CoreError::NotFound(format!("change {parent}")))?;
            require(parent_change.repo == spec.repo, || {
                format!("stack parent {parent} lives in repo {}", parent_change.repo)
            })?;
            if parent_change.state != ChangeState::Open {
                return Err(CoreError::Conflict(format!(
                    "stack parent {parent} is {}, not open",
                    parent_change.state.as_str()
                )));
            }
        }
        let change = ChangeId::generate();
        let number = raw::next_change_number(&tx, &spec.repo)?;
        let env = append(
            &tx,
            actor,
            Event::ChangeOpened {
                change: change.clone(),
                repo: spec.repo,
                number,
                target: spec.target,
                title: spec.title,
                task: spec.task,
                parent_change: spec.parent_change,
                external_key: spec.external_key,
            },
        )?;
        tx.commit()?;
        Ok((change, number, env))
    }

    pub fn push_revision(
        &mut self,
        actor: &PrincipalId,
        change: &ChangeId,
        commit_oid: &str,
        session: Option<&SessionId>,
        message: &str,
    ) -> CoreResult<(i64, Envelope)> {
        let tx = self.conn.transaction()?;
        ensure_actor(&tx, actor)?;
        require(valid_commit_oid(commit_oid), || {
            format!("{commit_oid:?} is not a valid commit oid")
        })?;
        let current = raw::change(&tx, change.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("change {change}")))?;
        if current.state != ChangeState::Open {
            return Err(CoreError::Conflict(format!(
                "change {change} is {}, not open",
                current.state.as_str()
            )));
        }
        if let Some(session) = session {
            let s = raw::session(&tx, session.as_str())?
                .ok_or_else(|| CoreError::NotFound(format!("session {session}")))?;
            if s.agent != *actor || s.state != SessionState::Active {
                return Err(CoreError::Conflict(format!(
                    "session {session} is not an active session of {actor}"
                )));
            }
        }
        let revision = current.latest_revision + 1;
        let env = append(
            &tx,
            actor,
            Event::RevisionPushed {
                change: change.clone(),
                revision,
                commit_oid: commit_oid.to_owned(),
                session: session.cloned(),
                message: message.to_owned(),
            },
        )?;
        tx.commit()?;
        Ok((revision, env))
    }

    pub fn attach_claim(
        &mut self,
        actor: &PrincipalId,
        change: &ChangeId,
        revision: i64,
        spec: ClaimSpec,
    ) -> CoreResult<(ClaimId, Envelope)> {
        let tx = self.conn.transaction()?;
        ensure_actor(&tx, actor)?;
        require(!spec.summary.trim().is_empty(), || {
            "claim summary must not be empty".into()
        })?;
        let current = raw::change(&tx, change.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("change {change}")))?;
        require((1..=current.latest_revision).contains(&revision), || {
            format!("change {change} has no revision {revision}")
        })?;
        let claim = ClaimId::generate();
        let env = append(
            &tx,
            actor,
            Event::ClaimAttached {
                claim: claim.clone(),
                change: change.clone(),
                revision,
                claim_kind: spec.kind,
                command: spec.command,
                passed: spec.passed,
                summary: spec.summary,
                unchecked: spec.unchecked,
            },
        )?;
        tx.commit()?;
        Ok((claim, env))
    }

    pub fn give_verdict(
        &mut self,
        actor: &PrincipalId,
        change: &ChangeId,
        revision: i64,
        domain: ReviewDomain,
        disposition: Disposition,
        rationale: &str,
    ) -> CoreResult<(VerdictId, Envelope)> {
        let tx = self.conn.transaction()?;
        ensure_actor(&tx, actor)?;
        require(!rationale.trim().is_empty(), || {
            "verdict rationale must not be empty: judgment without reasons doesn't compose".into()
        })?;
        let current = raw::change(&tx, change.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("change {change}")))?;
        if current.state != ChangeState::Open {
            return Err(CoreError::Conflict(format!(
                "change {change} is {}, not open",
                current.state.as_str()
            )));
        }
        require((1..=current.latest_revision).contains(&revision), || {
            format!("change {change} has no revision {revision}")
        })?;
        let verdict = VerdictId::generate();
        let env = append(
            &tx,
            actor,
            Event::VerdictGiven {
                verdict: verdict.clone(),
                change: change.clone(),
                revision,
                domain,
                disposition,
                rationale: rationale.to_owned(),
            },
        )?;
        tx.commit()?;
        Ok((verdict, env))
    }

    /// Dry-run the merge policy: what would block a merge right now?
    /// Agents subscribe to events and consult this to decide their next
    /// move — fix a failing requirement, or stop, satisfied.
    pub fn merge_readiness(&self, change: &ChangeId) -> CoreResult<PolicyTrace> {
        let current = raw::change(&self.conn, change.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("change {change}")))?;
        policy::evaluate(&self.conn, &current)
    }

    /// Merge a change if policy allows. Records the decision and its full
    /// justification; advancing the git ref is the transport layer's job,
    /// driven by this event.
    pub fn merge_change(&mut self, actor: &PrincipalId, change: &ChangeId) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        ensure_actor(&tx, actor)?;
        let current = raw::change(&tx, change.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("change {change}")))?;
        if current.state != ChangeState::Open {
            return Err(CoreError::Conflict(format!(
                "change {change} is {}, not open",
                current.state.as_str()
            )));
        }
        let trace = policy::evaluate(&tx, &current)?;
        if !trace.satisfied {
            return Err(CoreError::PolicyUnsatisfied(trace.unmet_summary()));
        }
        let env = append(
            &tx,
            actor,
            Event::ChangeMerged {
                change: change.clone(),
                revision: current.latest_revision,
                trace,
            },
        )?;
        tx.commit()?;
        Ok(env)
    }

    pub fn abandon_change(
        &mut self,
        actor: &PrincipalId,
        change: &ChangeId,
        reason: &str,
    ) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        ensure_actor(&tx, actor)?;
        require(!reason.trim().is_empty(), || {
            "abandon reason must not be empty".into()
        })?;
        let current = raw::change(&tx, change.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("change {change}")))?;
        if current.state != ChangeState::Open {
            return Err(CoreError::Conflict(format!(
                "change {change} is {}, not open",
                current.state.as_str()
            )));
        }
        let env = append(
            &tx,
            actor,
            Event::ChangeAbandoned {
                change: change.clone(),
                reason: reason.to_owned(),
            },
        )?;
        tx.commit()?;
        Ok(env)
    }
}
