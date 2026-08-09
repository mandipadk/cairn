//! The event log's vocabulary.
//!
//! Every fact in the system enters as exactly one of these events. The
//! payloads are the canonical wire format: they appear verbatim in the
//! log, in the API's event feed, and in SSE streams, so additive change
//! is the only kind allowed once an event kind ships.

use crate::id::{ChangeId, ClaimId, PrincipalId, SessionId, TaskId, VerdictId};
use crate::policy::PolicyTrace;
use crate::types::{
    ClaimKind, Disposition, ObjectFormat, PrincipalKind, ReviewDomain, SessionState, TaskState,
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

    RepoCreated {
        repo: String,
        default_branch: String,
        #[serde(default)]
        object_format: ObjectFormat,
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

    VerdictGiven {
        verdict: VerdictId,
        change: ChangeId,
        revision: i64,
        domain: ReviewDomain,
        disposition: Disposition,
        rationale: String,
    },

    ChangeMerged {
        change: ChangeId,
        revision: i64,
        /// The full policy evaluation that justified this merge. A merge
        /// is always explainable after the fact from the log alone.
        trace: PolicyTrace,
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
            Event::RepoCreated { .. } => "repo_created",
            Event::TaskCreated { .. } => "task_created",
            Event::TaskClaimed { .. } => "task_claimed",
            Event::TaskStateChanged { .. } => "task_state_changed",
            Event::SessionOpened { .. } => "session_opened",
            Event::SessionEnded { .. } => "session_ended",
            Event::ChangeOpened { .. } => "change_opened",
            Event::RevisionPushed { .. } => "revision_pushed",
            Event::ClaimAttached { .. } => "claim_attached",
            Event::VerdictGiven { .. } => "verdict_given",
            Event::ChangeMerged { .. } => "change_merged",
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
