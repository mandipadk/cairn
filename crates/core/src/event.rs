//! The event log's vocabulary.
//!
//! Every fact in the system enters as exactly one of these events. The
//! payloads are the canonical wire format: they appear verbatim in the
//! log, in the API's event feed, and in SSE streams, so additive change
//! is the only kind allowed once an event kind ships.

use crate::id::{
    ChangeId, ClaimId, GrantId, PrincipalId, SessionId, TaskId, TokenId, VerdictId, VerificationId,
};
use crate::policy::PolicyTrace;
use crate::types::{
    Capability, ClaimKind, Disposition, Mirror, ObjectFormat, Policy, PrincipalKind, ReviewDomain,
    SessionState, TaskState, Visibility,
};
use serde::{Deserialize, Serialize};

/// Position in the append-only log. The cursor agents resume from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EventSeq(pub i64);

/// An event as recorded: what happened, when, and on whose authority.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub seq: EventSeq,
    /// RFC 3339, UTC.
    pub ts: String,
    /// The principal whose action produced this event.
    pub actor: PrincipalId,
    #[serde(flatten)]
    pub event: Event,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    PrincipalRegistered {
        principal: PrincipalId,
        principal_kind: PrincipalKind,
        display: String,
        /// Model identity, for agents. Policy uses this to require
        /// independent judgment across model families.
        model: Option<String>,
        harness: Option<String>,
    },

    /// A human set a password, theirs or (as an admin) someone's.
    ///
    /// The fact belongs in the log — it is worth knowing that somebody's
    /// credential changed, and when, and on whose authority. The
    /// credential does not: the log is append-only, so a hash written
    /// here could never be rotated out or erased, and a password whose
    /// old hash survives every change is a password that was never
    /// really changed. The hash lives in the credentials table instead.
    ///
    /// The optional field exists only to *read* events written before
    /// that was understood, and is never serialised again: those events
    /// are in the log for good, but the event feed and the web UI hand
    /// their payloads to any authenticated caller, and a credential is
    /// not something to publish because it is already recorded.
    PasswordSet {
        principal: PrincipalId,
        #[serde(default, skip_serializing)]
        hash: Option<String>,
    },

    TokenMinted {
        token: TokenId,
        principal: PrincipalId,
        label: Option<String>,
        /// SHA-256 of the secret. The secret itself never enters the
        /// log; it exists once, in the mint response.
        hash: String,
    },
    TokenRevoked {
        token: TokenId,
    },

    GrantIssued {
        grant: GrantId,
        grantee: PrincipalId,
        repo: Option<String>,
        actions: Vec<Capability>,
        until: Option<String>,
    },
    GrantRevoked {
        grant: GrantId,
        reason: String,
    },

    RepoCreated {
        repo: String,
        default_branch: String,
        #[serde(default)]
        object_format: ObjectFormat,
    },

    /// History that predates this forge, brought in whole. Recorded as
    /// its own kind rather than dressed up as a merge: nothing here was
    /// reviewed under this repository's policy, and the log says so
    /// instead of implying otherwise.
    HistoryImported {
        repo: String,
        branch: String,
        /// Where it came from, credentials excluded.
        source: String,
        /// The tip the branch was set to.
        tip_oid: String,
        /// How many commits arrived without ever facing a policy.
        commits: i64,
    },

    /// A repository became readable without credentials, or stopped
    /// being so. Recorded like every other decision, because who may
    /// read a repository is exactly the kind of thing someone will need
    /// to reconstruct later.
    VisibilitySet {
        repo: String,
        visibility: Visibility,
    },
    /// The owner offered the repository to somebody. Nothing changes
    /// until they accept.
    RepoTransferOffered {
        repo: String,
        to: PrincipalId,
    },
    /// The offeree accepted: the actor is the new owner from here on.
    RepoTransferAccepted {
        repo: String,
    },
    /// The offer was declined by the offeree, or withdrawn by the owner.
    RepoTransferDeclined {
        repo: String,
    },

    /// A repository set the rules everything on it must meet.
    PolicySet {
        repo: String,
        policy: Policy,
    },

    /// A repository started, stopped, or changed where it mirrors.
    MirrorSet {
        repo: String,
        mirror: Option<Mirror>,
    },
    /// One attempt at copying a landed branch outward.
    MirrorPushed {
        repo: String,
        branch: String,
        commit_oid: String,
        ok: bool,
        /// What the remote said, when it refused.
        detail: Option<String>,
    },

    TaskCreated {
        task: TaskId,
        repo: Option<String>,
        title: String,
        /// The durable intent: the instruction or spec the work serves.
        spec: String,
        parent: Option<TaskId>,
    },
    TaskClaimed {
        task: TaskId,
    },
    TaskStateChanged {
        task: TaskId,
        state: TaskState,
    },

    SessionOpened {
        session: SessionId,
        task: TaskId,
    },
    /// A session declared which paths it expects to touch.
    PathsDeclared {
        session: SessionId,
        repo: String,
        paths: Vec<String>,
    },

    SessionEnded {
        session: SessionId,
        state: SessionState,
        /// What happened, written for the next reader — human or agent —
        /// who was not present: outcome, dead ends, discovered constraints.
        outcome: String,
    },

    ChangeOpened {
        change: ChangeId,
        repo: String,
        number: i64,
        target: String,
        title: String,
        task: Option<TaskId>,
        /// Stack parent: this change builds on another open change.
        parent_change: Option<ChangeId>,
        /// Client-chosen stable key (e.g. a Change-Id commit trailer),
        /// letting git pushes address the same change across amends.
        #[serde(default)]
        external_key: Option<String>,
    },
    RevisionPushed {
        change: ChangeId,
        revision: i64,
        commit_oid: String,
        session: Option<SessionId>,
        message: String,
    },

    ClaimAttached {
        claim: ClaimId,
        change: ChangeId,
        revision: i64,
        claim_kind: ClaimKind,
        /// Reproducible spec of the check (e.g. the exact command), so
        /// policy may later demand the claim be re-verified, not trusted.
        command: Option<String>,
        passed: bool,
        summary: String,
        /// What this claim deliberately does not cover. Structured honesty
        /// is what makes reviewing high-volume agent work tractable.
        unchecked: Vec<String>,
    },

    /// A runner re-executed a claim and reported what it saw. The
    /// claim stops being an assertion and becomes a contract.
    ClaimVerified {
        verification: VerificationId,
        claim: ClaimId,
        change: ChangeId,
        revision: i64,
        agrees: bool,
        command: String,
        observed: String,
    },

    VerdictGiven {
        verdict: VerdictId,
        change: ChangeId,
        revision: i64,
        domain: ReviewDomain,
        disposition: Disposition,
        rationale: String,
    },

    /// The change entered the landing queue: from here, landing it —
    /// rebasing if the target moved — is the forge's responsibility.
    ChangeEnqueued {
        change: ChangeId,
    },
    /// The change left the queue without merging; the reason says
    /// exactly why (conflict, policy regression, cancellation).
    ChangeDequeued {
        change: ChangeId,
        reason: String,
    },
    ChangeMerged {
        change: ChangeId,
        revision: i64,
        /// The commit that actually landed on the target, when the
        /// queue rebased it past the reviewed revision's oid.
        #[serde(default)]
        merged_as: Option<String>,
        /// The full policy evaluation that justified this merge. A merge
        /// is always explainable after the fact from the log alone.
        trace: PolicyTrace,
    },
    /// The forge tried to carry an open child of a merged change onto
    /// the new tip and could not: the stack needs a person.
    RebaseFailed {
        change: ChangeId,
        onto: String,
        files: Vec<String>,
    },

    ChangeAbandoned {
        change: ChangeId,
        reason: String,
    },
}

impl Event {
    /// Stable name of the event kind, as stored in the log's `kind`
    /// column and used in subscription filters.
    pub fn kind(&self) -> &'static str {
        match self {
            Event::PrincipalRegistered { .. } => "principal_registered",
            Event::PasswordSet { .. } => "password_set",
            Event::TokenMinted { .. } => "token_minted",
            Event::TokenRevoked { .. } => "token_revoked",
            Event::GrantIssued { .. } => "grant_issued",
            Event::GrantRevoked { .. } => "grant_revoked",
            Event::RepoCreated { .. } => "repo_created",
            Event::HistoryImported { .. } => "history_imported",
            Event::VisibilitySet { .. } => "visibility_set",
            Event::RepoTransferOffered { .. } => "repo_transfer_offered",
            Event::RepoTransferAccepted { .. } => "repo_transfer_accepted",
            Event::RepoTransferDeclined { .. } => "repo_transfer_declined",
            Event::PolicySet { .. } => "policy_set",
            Event::MirrorSet { .. } => "mirror_set",
            Event::MirrorPushed { .. } => "mirror_pushed",
            Event::TaskCreated { .. } => "task_created",
            Event::TaskClaimed { .. } => "task_claimed",
            Event::TaskStateChanged { .. } => "task_state_changed",
            Event::SessionOpened { .. } => "session_opened",
            Event::PathsDeclared { .. } => "paths_declared",
            Event::SessionEnded { .. } => "session_ended",
            Event::ChangeOpened { .. } => "change_opened",
            Event::RevisionPushed { .. } => "revision_pushed",
            Event::ClaimAttached { .. } => "claim_attached",
            Event::ClaimVerified { .. } => "claim_verified",
            Event::VerdictGiven { .. } => "verdict_given",
            Event::ChangeEnqueued { .. } => "change_enqueued",
            Event::ChangeDequeued { .. } => "change_dequeued",
            Event::ChangeMerged { .. } => "change_merged",
            Event::RebaseFailed { .. } => "rebase_failed",
            Event::ChangeAbandoned { .. } => "change_abandoned",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_matches_serde_tag() {
        let e = Event::RepoCreated {
            repo: "demo".into(),
            default_branch: "main".into(),
            object_format: ObjectFormat::Sha1,
        };
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["kind"], e.kind());
    }

    #[test]
    fn envelope_flattens_event() {
        let env = Envelope {
            seq: EventSeq(7),
            ts: "2026-08-09T00:00:00Z".into(),
            actor: PrincipalId("ada".into()),
            event: Event::TaskClaimed {
                task: TaskId("t-x".into()),
            },
        };
        let v = serde_json::to_value(&env).unwrap();
        assert_eq!(v["seq"], 7);
        assert_eq!(v["kind"], "task_claimed");
        assert_eq!(v["task"], "t-x");
    }
}
