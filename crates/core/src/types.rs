//! Projection types: the current state of the graph, derived from the log.

use crate::id::{ChangeId, ClaimId, PrincipalId, SessionId, TaskId, VerdictId};
use serde::{Deserialize, Serialize};

macro_rules! str_enum {
    ($(#[$doc:meta])* $name:ident { $($(#[$vdoc:meta])* $variant:ident => $s:literal),+ $(,)? }) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name {
            $($(#[$vdoc])* $variant),+
        }

        impl $name {
            pub fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $s),+ }
            }

            pub fn parse(s: &str) -> Option<Self> {
                match s { $($s => Some(Self::$variant)),+, _ => None }
            }
        }
    };
}

str_enum!(PrincipalKind { Human => "human", Agent => "agent" });

str_enum!(TaskState {
    Open => "open",
    Claimed => "claimed",
    /// The task's work merged.
    Landed => "landed",
    Abandoned => "abandoned",
});

str_enum!(SessionState {
    Active => "active",
    Completed => "completed",
    /// Ended without achieving the task; the outcome text says why —
    /// failed sessions are knowledge, not embarrassments.
    Failed => "failed",
});

str_enum!(ChangeState { Open => "open", Merged => "merged", Abandoned => "abandoned" });

str_enum!(ClaimKind {
    Test => "test",
    Lint => "lint",
    Typecheck => "typecheck",
    Build => "build",
    /// A human looked at something with their eyes.
    Manual => "manual",
    /// An argument, not an execution; the weakest kind and marked as such.
    Reasoning => "reasoning",
});

str_enum!(ReviewDomain {
    Correctness => "correctness",
    Security => "security",
    Design => "design",
    Style => "style",
});

str_enum!(Disposition {
    Approve => "approve",
    /// Non-blocking reservation, visible to policy but not a veto.
    Concern => "concern",
    Block => "block",
});

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Principal {
    pub id: PrincipalId,
    pub kind: PrincipalKind,
    pub display: String,
    pub model: Option<String>,
    pub harness: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Repo {
    pub name: String,
    pub default_branch: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub id: TaskId,
    pub repo: Option<String>,
    pub title: String,
    pub spec: String,
    pub parent: Option<TaskId>,
    pub state: TaskState,
    pub claimed_by: Option<PrincipalId>,
    pub created_by: PrincipalId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: SessionId,
    pub task: TaskId,
    pub agent: PrincipalId,
    pub state: SessionState,
    pub outcome: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Change {
    pub id: ChangeId,
    pub repo: String,
    /// Per-repo human-friendly number; the id is what stays stable.
    pub number: i64,
    pub target: String,
    pub title: String,
    pub task: Option<TaskId>,
    pub parent_change: Option<ChangeId>,
    pub state: ChangeState,
    pub owner: PrincipalId,
    /// Highest revision number, 0 when nothing has been pushed yet.
    pub latest_revision: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Revision {
    pub change: ChangeId,
    pub number: i64,
    pub commit_oid: String,
    pub session: Option<SessionId>,
    pub message: String,
}

/// A claim as submitted: what was checked, how, and what wasn't.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimSpec {
    pub kind: ClaimKind,
    /// Reproducible spec of the check (e.g. the exact command).
    pub command: Option<String>,
    pub passed: bool,
    pub summary: String,
    /// What this claim deliberately does not cover.
    #[serde(default)]
    pub unchecked: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claim {
    pub id: ClaimId,
    pub change: ChangeId,
    pub revision: i64,
    pub kind: ClaimKind,
    pub command: Option<String>,
    pub passed: bool,
    pub summary: String,
    pub unchecked: Vec<String>,
    pub by: PrincipalId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub id: VerdictId,
    pub change: ChangeId,
    pub revision: i64,
    pub domain: ReviewDomain,
    pub disposition: Disposition,
    pub rationale: String,
    pub by: PrincipalId,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn str_enum_round_trips() {
        for k in [
            ClaimKind::Test,
            ClaimKind::Lint,
            ClaimKind::Typecheck,
            ClaimKind::Build,
            ClaimKind::Manual,
            ClaimKind::Reasoning,
        ] {
            assert_eq!(ClaimKind::parse(k.as_str()), Some(k));
        }
        assert_eq!(TaskState::parse("nope"), None);
    }

    #[test]
    fn serde_matches_as_str() {
        let v = serde_json::to_value(Disposition::Approve).unwrap();
        assert_eq!(v, Disposition::Approve.as_str());
    }
}
