//! Write side of the graph: the protocol verbs.
//!
//! Each command runs validate → append → apply in one transaction, so a
//! command either fully happens (event logged, projections consistent)
//! or leaves no trace. The verbs deliberately mirror how work actually
//! flows: claim a task, open a session, push revisions, attach claims,
//! collect verdicts, merge under policy.

use crate::error::{CoreError, CoreResult};
use crate::event::{Envelope, Event};
use crate::id::{
    ChangeId, ClaimId, GrantId, PrincipalId, SessionId, TaskId, TokenId, VerdictId, VerificationId,
    random_token_secret, validate_slug,
};
use crate::policy::{self, PolicyTrace};
use crate::queries::raw;
use crate::store::{Store, append};
use crate::types::{
    Capability, ChangeSpec, ChangeState, ClaimSpec, Disposition, ObjectFormat, Principal,
    PrincipalKind, ReviewDomain, SessionState, TaskState,
};
use rusqlite::Transaction;
use sha2::{Digest, Sha256};

/// The stored fingerprint of a token secret.
pub(crate) fn token_hash(secret: &str) -> String {
    Sha256::digest(secret.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn ensure_actor(tx: &Transaction, actor: &PrincipalId) -> CoreResult<Principal> {
    raw::principal(tx, actor.as_str())?
        .ok_or_else(|| CoreError::NotFound(format!("principal {actor}")))
}

/// The law: humans are sovereign; agents act only under a live grant
/// covering the capability and scope. Refusals name the missing
/// capability and how to obtain it, so an agent can act on them.
fn authorize(
    tx: &Transaction,
    actor: &PrincipalId,
    action: Capability,
    repo: Option<&str>,
) -> CoreResult<Principal> {
    let principal = ensure_actor(tx, actor)?;
    if principal.kind == PrincipalKind::Human {
        return Ok(principal);
    }
    let grants = raw::grants_of(tx, actor.as_str())?;
    let now = jiff::Timestamp::now().to_string();
    if raw::grants_cover(&grants, action, repo, &now) {
        return Ok(principal);
    }
    let scope = repo.map_or_else(|| "all repos".to_owned(), |r| format!("repo {r}"));
    Err(CoreError::Forbidden(format!(
        "{actor} holds no '{}' capability for {scope}; a human can issue one: \
         POST /api/grants {{\"grantee\": \"{actor}\", \"actions\": [\"{}\"]}}",
        action.as_str(),
        action.as_str()
    )))
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
            authorize(&tx, actor, Capability::Admin, None)?;
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
        object_format: ObjectFormat,
    ) -> CoreResult<Envelope> {
        const RESERVED: &[&str] = &["api", "git", "login", "logout", "assets", "ui"];
        let tx = self.conn.transaction()?;
        authorize(&tx, actor, Capability::Admin, None)?;
        require(validate_slug(name), || {
            format!("repo name {name:?} is not a valid slug")
        })?;
        require(!RESERVED.contains(&name), || {
            format!("repo name {name:?} is reserved")
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
                object_format,
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
        authorize(&tx, actor, Capability::Task, repo)?;
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
        let current = raw::task(&tx, task.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("task {task}")))?;
        authorize(&tx, actor, Capability::Task, current.repo.as_deref())?;
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
        let current = raw::task(&tx, task.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("task {task}")))?;
        authorize(&tx, actor, Capability::Task, current.repo.as_deref())?;
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
        let current = raw::task(&tx, task.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("task {task}")))?;
        authorize(&tx, actor, Capability::Task, current.repo.as_deref())?;
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
        require(state != SessionState::Active, || {
            "a session cannot end as active".into()
        })?;
        require(!outcome.trim().is_empty(), || {
            "session outcome must not be empty: record what happened for the next reader".into()
        })?;
        let current = raw::session(&tx, session.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("session {session}")))?;
        let task = raw::task(&tx, current.task.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("task {}", current.task)))?;
        authorize(&tx, actor, Capability::Task, task.repo.as_deref())?;
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
        authorize(&tx, actor, Capability::Push, Some(&spec.repo))?;
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
        require(valid_commit_oid(commit_oid), || {
            format!("{commit_oid:?} is not a valid commit oid")
        })?;
        let current = raw::change(&tx, change.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("change {change}")))?;
        authorize(&tx, actor, Capability::Push, Some(&current.repo))?;
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
        require(!spec.summary.trim().is_empty(), || {
            "claim summary must not be empty".into()
        })?;
        let current = raw::change(&tx, change.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("change {change}")))?;
        authorize(&tx, actor, Capability::Push, Some(&current.repo))?;
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
        require(!rationale.trim().is_empty(), || {
            "verdict rationale must not be empty: judgment without reasons doesn't compose".into()
        })?;
        let current = raw::change(&tx, change.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("change {change}")))?;
        authorize(&tx, actor, Capability::Review, Some(&current.repo))?;
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

    /// Record an independent re-execution of a claim. The runner must
    /// hold the verify capability and must not be the claimant: a
    /// claim re-checked by its own author proves nothing.
    pub fn verify_claim(
        &mut self,
        actor: &PrincipalId,
        claim: &ClaimId,
        agrees: bool,
        command: &str,
        observed: &str,
    ) -> CoreResult<(VerificationId, Envelope)> {
        let tx = self.conn.transaction()?;
        require(!command.trim().is_empty(), || {
            "a verification must say what it ran".into()
        })?;
        require(!observed.trim().is_empty(), || {
            "a verification must say what it saw".into()
        })?;
        let current = raw::claim(&tx, claim.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("claim {claim}")))?;
        let change = raw::change(&tx, current.change.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("change {}", current.change)))?;
        authorize(&tx, actor, Capability::Verify, Some(&change.repo))?;
        if current.by == *actor {
            return Err(CoreError::Conflict(format!(
                "{actor} made claim {claim}; verification must be independent"
            )));
        }
        let verification = VerificationId::generate();
        let env = append(
            &tx,
            actor,
            Event::ClaimVerified {
                verification: verification.clone(),
                claim: claim.clone(),
                change: current.change.clone(),
                revision: current.revision,
                agrees,
                command: command.to_owned(),
                observed: observed.to_owned(),
            },
        )?;
        tx.commit()?;
        Ok((verification, env))
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
        self.merge_change_as(actor, change, None)
    }

    /// Merge with an explicit landed commit — the queue's path when it
    /// rebased the reviewed revision onto a moved target.
    pub fn merge_change_as(
        &mut self,
        actor: &PrincipalId,
        change: &ChangeId,
        merged_as: Option<&str>,
    ) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        let current = raw::change(&tx, change.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("change {change}")))?;
        authorize(&tx, actor, Capability::Merge, Some(&current.repo))?;
        if current.state != ChangeState::Open {
            return Err(CoreError::Conflict(format!(
                "change {change} is {}, not open",
                current.state.as_str()
            )));
        }
        if let Some(oid) = merged_as {
            require(valid_commit_oid(oid), || {
                format!("{oid:?} is not a valid commit oid")
            })?;
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
                merged_as: merged_as.map(str::to_owned),
                trace,
            },
        )?;
        tx.commit()?;
        Ok(env)
    }

    /// Enter the landing queue. Policy must already be satisfied — the
    /// queue lands ready work, it does not wait for reviews — and a
    /// stacked change may only follow its merged parent.
    pub fn enqueue_change(
        &mut self,
        actor: &PrincipalId,
        change: &ChangeId,
    ) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        let current = raw::change(&tx, change.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("change {change}")))?;
        authorize(&tx, actor, Capability::Merge, Some(&current.repo))?;
        if current.state != ChangeState::Open {
            return Err(CoreError::Conflict(format!(
                "change {change} is {}, not open",
                current.state.as_str()
            )));
        }
        if raw::queue_entry(&tx, change.as_str())?.is_some() {
            return Err(CoreError::Conflict(format!(
                "change {change} is already queued"
            )));
        }
        if let Some(parent) = &current.parent_change {
            let parent_change = raw::change(&tx, parent.as_str())?
                .ok_or_else(|| CoreError::NotFound(format!("change {parent}")))?;
            if parent_change.state != ChangeState::Merged {
                return Err(CoreError::Conflict(format!(
                    "stack parent (change {}) is {}, not merged; enqueue the stack bottom-up",
                    parent_change.number,
                    parent_change.state.as_str()
                )));
            }
        }
        let trace = policy::evaluate(&tx, &current)?;
        if !trace.satisfied {
            return Err(CoreError::PolicyUnsatisfied(trace.unmet_summary()));
        }
        let env = append(
            &tx,
            actor,
            Event::ChangeEnqueued {
                change: change.clone(),
            },
        )?;
        tx.commit()?;
        Ok(env)
    }

    /// Leave the queue without merging. The enqueuer, the change's
    /// owner, or anyone holding merge authority (the processor uses
    /// this to record why a landing was abandoned).
    pub fn dequeue_change(
        &mut self,
        actor: &PrincipalId,
        change: &ChangeId,
        reason: &str,
    ) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        require(!reason.trim().is_empty(), || {
            "dequeue reason must not be empty".into()
        })?;
        let entry = raw::queue_entry(&tx, change.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("change {change} is not queued")))?;
        let current = raw::change(&tx, change.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("change {change}")))?;
        if entry.enqueued_by != *actor && current.owner != *actor {
            authorize(&tx, actor, Capability::Merge, Some(&current.repo))?;
        } else {
            ensure_actor(&tx, actor)?;
        }
        let env = append(
            &tx,
            actor,
            Event::ChangeDequeued {
                change: change.clone(),
                reason: reason.to_owned(),
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
        require(!reason.trim().is_empty(), || {
            "abandon reason must not be empty".into()
        })?;
        let current = raw::change(&tx, change.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("change {change}")))?;
        authorize(&tx, actor, Capability::Push, Some(&current.repo))?;
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
    /// Mint an API token. The secret is returned exactly once; only its
    /// hash enters the log. A principal may mint for itself; humans may
    /// mint for anyone.
    pub fn mint_token(
        &mut self,
        actor: &PrincipalId,
        principal: &PrincipalId,
        label: Option<&str>,
    ) -> CoreResult<(TokenId, String, Envelope)> {
        let tx = self.conn.transaction()?;
        let acting = ensure_actor(&tx, actor)?;
        raw::principal(&tx, principal.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("principal {principal}")))?;
        if actor != principal && acting.kind != PrincipalKind::Human {
            return Err(CoreError::Forbidden(format!(
                "{actor} may not mint tokens for {principal}: only the principal itself or a human"
            )));
        }
        let token = TokenId::generate();
        let secret = random_token_secret();
        let env = append(
            &tx,
            actor,
            Event::TokenMinted {
                token: token.clone(),
                principal: principal.clone(),
                label: label.map(str::to_owned),
                hash: token_hash(&secret),
            },
        )?;
        tx.commit()?;
        Ok((token, secret, env))
    }

    /// Revoke a token, effective immediately. The owner or any human.
    pub fn revoke_token(&mut self, actor: &PrincipalId, token: &TokenId) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        let acting = ensure_actor(&tx, actor)?;
        let current = raw::token(&tx, token.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("token {token}")))?;
        if current.principal != *actor && acting.kind != PrincipalKind::Human {
            return Err(CoreError::Forbidden(format!(
                "{actor} may not revoke a token of {}: only the owner or a human",
                current.principal
            )));
        }
        if current.revoked {
            return Err(CoreError::Conflict(format!(
                "token {token} is already revoked"
            )));
        }
        let env = append(
            &tx,
            actor,
            Event::TokenRevoked {
                token: token.clone(),
            },
        )?;
        tx.commit()?;
        Ok(env)
    }

    /// Issue a capability grant. Only humans delegate — agents cannot
    /// widen their own authority or another agent's.
    pub fn issue_grant(
        &mut self,
        actor: &PrincipalId,
        grantee: &PrincipalId,
        repo: Option<&str>,
        actions: Vec<Capability>,
        until: Option<&str>,
    ) -> CoreResult<(GrantId, Envelope)> {
        let tx = self.conn.transaction()?;
        let acting = ensure_actor(&tx, actor)?;
        if acting.kind != PrincipalKind::Human {
            return Err(CoreError::Forbidden(format!(
                "{actor} may not issue grants: delegation is a human act"
            )));
        }
        raw::principal(&tx, grantee.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("principal {grantee}")))?;
        if let Some(repo) = repo {
            raw::repo(&tx, repo)?.ok_or_else(|| CoreError::NotFound(format!("repo {repo}")))?;
        }
        require(!actions.is_empty(), || {
            "a grant must carry at least one capability".into()
        })?;
        let mut actions = actions;
        actions.sort_by_key(|c| c.as_str());
        actions.dedup();
        // Store expiry canonically so lexicographic comparison is sound.
        let until = until
            .map(|raw| {
                raw.parse::<jiff::Timestamp>()
                    .map(|ts| ts.to_string())
                    .map_err(|e| CoreError::Invalid(format!("bad expiry {raw:?}: {e}")))
            })
            .transpose()?;
        let grant = GrantId::generate();
        let env = append(
            &tx,
            actor,
            Event::GrantIssued {
                grant: grant.clone(),
                grantee: grantee.clone(),
                repo: repo.map(str::to_owned),
                actions,
                until,
            },
        )?;
        tx.commit()?;
        Ok((grant, env))
    }

    /// Revoke a grant, effective immediately. The grantor or any human.
    pub fn revoke_grant(
        &mut self,
        actor: &PrincipalId,
        grant: &GrantId,
        reason: &str,
    ) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        let acting = ensure_actor(&tx, actor)?;
        require(!reason.trim().is_empty(), || {
            "revocation reason must not be empty".into()
        })?;
        let current = raw::grant(&tx, grant.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("grant {grant}")))?;
        if current.grantor != *actor && acting.kind != PrincipalKind::Human {
            return Err(CoreError::Forbidden(format!(
                "{actor} may not revoke a grant issued by {}",
                current.grantor
            )));
        }
        if current.revoked {
            return Err(CoreError::Conflict(format!(
                "grant {grant} is already revoked"
            )));
        }
        let env = append(
            &tx,
            actor,
            Event::GrantRevoked {
                grant: grant.clone(),
                reason: reason.to_owned(),
            },
        )?;
        tx.commit()?;
        Ok(env)
    }
}
