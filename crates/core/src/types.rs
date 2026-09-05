//! Projection types: the current state of the graph, derived from the log.

use crate::id::{
    ChangeId, ClaimId, GrantId, PrincipalId, SessionId, TaskId, ThreadId, TokenId, VerdictId,
    VerificationId,
};
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

// A team is a principal that never acts: it holds grants, and its
// members act with them. Authority given to a team is authority given
// to whoever is on it today, and taken from whoever leaves.
str_enum!(PrincipalKind { Human => "human", Agent => "agent", Team => "team" });

str_enum!(
    /// Hash function of a repo's git object database.
    #[derive(Default)]
    ObjectFormat {
        #[default]
        Sha1 => "sha1",
        Sha256 => "sha256",
    }
);

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

str_enum!(
    /// Who may read a repository without proving who they are.
    ///
    /// Private is the default, and deliberately: a repository readable
    /// by accident is worse than one that is awkward to share, so
    /// "nobody said" has to mean "closed".
    #[derive(Default)]
    Visibility {
        #[default]
        Private => "private",
        Public => "public",
    }
);

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

str_enum!(
    /// What a principal may do. Humans hold every capability
    /// implicitly; agents act only under grants.
    Capability {
        /// Create, claim, and work tasks (sessions included).
        Task => "task",
        /// Produce output: open changes, push revisions, attach claims.
        Push => "push",
        /// Judge: give verdicts.
        Review => "review",
        /// Land or abandon changes.
        Merge => "merge",
        /// Re-execute claims and record what was actually observed.
        Verify => "verify",
        /// Register principals, create repos, manage grants and tokens.
        Admin => "admin",
    }
);

str_enum!(Disposition {
    Approve => "approve",
    /// Non-blocking reservation, visible to policy but not a veto.
    Concern => "concern",
    Block => "block",
});

str_enum!(
    /// What a discussion thread is for. The kind is a commitment, not a
    /// label: a concern has to be resolved before the change lands.
    ThreadKind {
        /// Something the author should answer; landing does not wait on it.
        Question => "question",
        /// Something that has to be dealt with before the change lands.
        Concern => "concern",
        /// For the record. Nobody owes a reply.
        Note => "note",
    }
);

str_enum!(
    /// How a thread was closed. Every resolution says which kind of
    /// closure it was, so "resolved" is never a euphemism.
    Resolution {
        /// Settled in the thread: answered, or found unfounded.
        Answered => "answered",
        /// A later revision dealt with it; the resolution names which.
        Fixed => "fixed",
        /// Whoever opened it took it back.
        Withdrawn => "withdrawn",
        /// The change's owner or a reviewer proceeded over it, on the record.
        Overruled => "overruled",
    }
);

str_enum!(
    /// Which side of a diff a line number counts on.
    Side {
        Old => "old",
        New => "new",
    }
);

/// What a thread is about. Discussion is anchored to a thing in the
/// graph, never to a page: a line of a revision's diff, a claim, a
/// verdict, or the change as a whole.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "on", rename_all = "snake_case")]
pub enum Anchor {
    Change,
    Line { path: String, side: Side, line: i64 },
    Claim { claim: ClaimId },
    Verdict { verdict: VerdictId },
}

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
    #[serde(default)]
    pub visibility: Visibility,
    /// Whoever created it. Ownership is the one authority nobody has to
    /// be granted: it comes with having made the thing.
    #[serde(default)]
    pub owner: PrincipalId,
    /// Somebody the owner has offered the repository to, until they
    /// answer. Ownership moves only when the other side says yes: a
    /// repository is not something you can leave on someone's doorstep.
    #[serde(default)]
    pub pending_owner: Option<PrincipalId>,
    pub object_format: ObjectFormat,
    pub policy: Policy,
    /// Set when landed branches are copied somewhere else.
    pub mirror: Option<Mirror>,
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

/// A change as requested: where it lands, what it does, what it serves.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeSpec {
    pub repo: String,
    pub target: String,
    pub title: String,
    #[serde(default)]
    pub task: Option<TaskId>,
    /// Stack parent: an open change this one builds on.
    #[serde(default)]
    pub parent_change: Option<ChangeId>,
    /// Client-chosen stable key (e.g. a Change-Id commit trailer).
    #[serde(default)]
    pub external_key: Option<String>,
}

impl ChangeSpec {
    pub fn new(
        repo: impl Into<String>,
        target: impl Into<String>,
        title: impl Into<String>,
    ) -> Self {
        ChangeSpec {
            repo: repo.into(),
            target: target.into(),
            title: title.into(),
            task: None,
            parent_change: None,
            external_key: None,
        }
    }
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
    /// Client-chosen stable key (e.g. a Change-Id commit trailer).
    pub external_key: Option<String>,
    /// The commit this change put on its target branch, once merged.
    pub landed_oid: Option<String>,
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

/// A capability delegation: grantor gives grantee the right to act,
/// optionally scoped to one repo and bounded in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Grant {
    pub id: GrantId,
    pub grantor: PrincipalId,
    pub grantee: PrincipalId,
    /// None scopes the grant to every repo, including repo-less work.
    pub repo: Option<String>,
    pub actions: Vec<Capability>,
    /// RFC 3339 expiry; None means until revoked.
    pub until: Option<String>,
    pub revoked: bool,
}

/// Token metadata — the secret itself is never stored or shown again.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenInfo {
    pub id: TokenId,
    pub principal: PrincipalId,
    pub label: Option<String>,
    /// RFC 3339 expiry; None means until revoked.
    pub until: Option<String>,
    pub revoked: bool,
}

/// An independent re-execution of a claim: someone other than the
/// claimant ran the recorded command and reported what happened.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verification {
    pub id: VerificationId,
    pub claim: ClaimId,
    pub change: ChangeId,
    pub revision: i64,
    /// Whether the re-run reproduced the claim's result.
    pub agrees: bool,
    /// The command the runner actually executed.
    pub command: String,
    /// What the runner observed, in its own words.
    pub observed: String,
    pub by: PrincipalId,
}

/// What the graph knows about a change that landed: the judgment
/// behind the code, gathered for attribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provenance {
    pub change: Change,
    pub claims: Vec<Claim>,
    pub verdicts: Vec<Verdict>,
}

impl Provenance {
    /// Did anything actually run against this revision, or was it
    /// argued for? Reasoning-only claims are the weakest kind.
    pub fn executed_check(&self) -> bool {
        self.claims
            .iter()
            .any(|c| c.kind != ClaimKind::Reasoning && c.passed)
    }

    /// Everything the claims declared out of scope. The question no
    /// other forge can answer: which lines were never verified?
    pub fn unchecked(&self) -> Vec<&str> {
        let mut out: Vec<&str> = self
            .claims
            .iter()
            .flat_map(|c| c.unchecked.iter().map(String::as_str))
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }

    pub fn approvals(&self) -> Vec<&Verdict> {
        self.verdicts
            .iter()
            .filter(|v| v.disposition == Disposition::Approve)
            .collect()
    }
}

str_enum!(
    /// How much independence a landing requires. Every option is a
    /// position on the same question: whose judgment counts as
    /// somebody else's.
    Independence {
        /// Anyone but the owner, human or agent.
        Anyone => "anyone",
        /// One human, or two agents of distinct models. The default.
        HumanOrTwoModels => "human_or_two_models",
        /// A human, and only a human.
        HumanOnly => "human_only",
        /// Nothing. Suitable for a scratch repo, and nowhere else.
        None => "none",
    }
);

/// What a repository requires before anything lands on it.
///
/// The defaults are the rules the forge shipped with, so a repo that
/// never says anything behaves exactly as it always did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    /// A passing, executed check must exist on the landing revision.
    pub require_executed_check: bool,
    /// Who must approve, besides the owner.
    pub independence: Independence,
    /// A runner must have reproduced at least one claim.
    pub require_runner_verification: bool,
    /// Reviewers may be required to cover particular domains.
    pub required_domains: Vec<ReviewDomain>,
    /// No concern raised in discussion may be left unresolved.
    #[serde(default = "yes")]
    pub require_concerns_resolved: bool,
}

fn yes() -> bool {
    true
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            require_executed_check: true,
            independence: Independence::HumanOrTwoModels,
            require_runner_verification: false,
            required_domains: Vec::new(),
            require_concerns_resolved: true,
        }
    }
}

/// Where a repository's landed branches are copied, so somewhere else
/// can keep reading them while the work moves here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mirror {
    /// Push URL, without credentials.
    pub url: String,
    /// Whether pushes are currently attempted.
    pub enabled: bool,
}

/// What one attempt learned, kept so the next one does not re-walk it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lesson {
    pub session: SessionId,
    pub agent: PrincipalId,
    pub state: SessionState,
    /// The intent the attempt was serving.
    pub task: TaskId,
    pub task_title: String,
    /// The repository the task belonged to, if it belonged to one; a
    /// lesson from forge-wide work has none and is everybody's.
    pub repo: Option<String>,
    /// What the agent recorded on its way out.
    pub outcome: String,
}

/// Something that happened to your work or your authority, addressed to
/// you. Derived from the log like every projection; whether you have
/// read it is operational state, since a log cannot forget on your
/// behalf.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notice {
    pub seq: i64,
    pub ts: String,
    pub kind: String,
    pub actor: PrincipalId,
    pub repo: Option<String>,
    pub change: Option<ChangeId>,
    pub number: Option<i64>,
    pub what: String,
    pub read: bool,
}

/// Where a person can be reached. An address counts only once a link
/// mailed to it has been followed; until then it is pending, and a
/// reset will not go to it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Contact {
    pub email: Option<String>,
    pub verified: bool,
    pub pending: Option<String>,
}

/// A passkey as its owner sees it. The credential itself is opaque to
/// the core; the server that speaks WebAuthn keeps it as JSON here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyRecord {
    pub cred_id: String,
    pub label: String,
    pub created: String,
    pub last_used: Option<String>,
}

/// A browser session as its owner sees it: enough to recognise it and
/// end it, never the secret. `id` is a prefix of the secret's hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserSession {
    pub id: String,
    pub created: String,
    pub expires: String,
    pub last_seen: Option<String>,
    pub agent: Option<String>,
    pub current: bool,
}

/// A session's declared intent over paths, live while the session is.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lease {
    pub session: SessionId,
    pub repo: String,
    pub holder: PrincipalId,
    pub paths: Vec<String>,
}

/// One change waiting in a branch's landing queue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueEntry {
    pub change: ChangeId,
    pub repo: String,
    pub target: String,
    pub enqueued_by: PrincipalId,
    pub enqueued_seq: i64,
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

/// A discussion thread on a change, with everything said in it and how
/// it was closed, if it was.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Thread {
    pub id: ThreadId,
    pub change: ChangeId,
    /// The revision the thread was opened on. A line anchor counts on
    /// this revision's diff; a concern stands, whatever revision is
    /// current, until it is resolved.
    pub revision: i64,
    pub anchor: Anchor,
    pub kind: ThreadKind,
    pub body: String,
    pub by: PrincipalId,
    pub at: String,
    pub replies: Vec<Reply>,
    pub resolved: Option<Resolved>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reply {
    pub by: PrincipalId,
    pub body: String,
    pub at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resolved {
    pub how: Resolution,
    /// The revision that dealt with it, when `how` is `fixed`.
    pub revision: Option<i64>,
    pub note: String,
    pub by: PrincipalId,
    pub at: String,
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
