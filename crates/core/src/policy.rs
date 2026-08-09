//! Merge policy: the law that decides when a change may land.
//!
//! Nothing merges on ambient authority. A merge is the outcome of an
//! evaluation over the graph — claims, verdicts, and the principals
//! behind them — and the full [`PolicyTrace`] is embedded in the
//! `ChangeMerged` event, so every merge is explainable from the log
//! alone, forever.
//!
//! This is the fixed default policy; per-repo configurable policy is a
//! planned layer on the same trace shape.

use crate::error::CoreResult;
use crate::queries::raw;
use crate::types::{Change, ClaimKind, Disposition, PrincipalKind};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Requirement {
    pub description: String,
    pub satisfied: bool,
    /// What the evaluation actually saw, in terms of graph object ids.
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyTrace {
    pub satisfied: bool,
    pub requirements: Vec<Requirement>,
}

impl PolicyTrace {
    /// One-line summary of what's missing, for error messages.
    pub fn unmet_summary(&self) -> String {
        self.requirements
            .iter()
            .filter(|r| !r.satisfied)
            .map(|r| r.description.as_str())
            .collect::<Vec<_>>()
            .join("; ")
    }
}

/// Evaluate the default policy for a change at its latest revision.
pub(crate) fn evaluate(conn: &Connection, change: &Change) -> CoreResult<PolicyTrace> {
    let mut requirements = Vec::new();
    let revision = change.latest_revision;

    requirements.push(Requirement {
        description: "change has at least one revision".into(),
        satisfied: revision >= 1,
        evidence: format!("latest revision is {revision}"),
    });

    let claims = raw::claims_on(conn, change.id.as_str(), revision)?;
    let passing_tests: Vec<_> = claims
        .iter()
        .filter(|c| c.kind == ClaimKind::Test && c.passed)
        .collect();
    requirements.push(Requirement {
        description: "latest revision carries a passing test claim".into(),
        satisfied: !passing_tests.is_empty(),
        evidence: if passing_tests.is_empty() {
            format!(
                "{} claim(s) on revision {revision}, none a passing test",
                claims.len()
            )
        } else {
            passing_tests
                .iter()
                .map(|c| c.id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        },
    });

    let verdicts = raw::verdicts_on(conn, change.id.as_str(), revision)?;
    let blocks: Vec<_> = verdicts
        .iter()
        .filter(|v| v.disposition == Disposition::Block)
        .collect();
    requirements.push(Requirement {
        description: "no blocking verdict on the latest revision".into(),
        satisfied: blocks.is_empty(),
        evidence: if blocks.is_empty() {
            "no blocks".into()
        } else {
            blocks
                .iter()
                .map(|v| format!("{} blocked by {}", v.id, v.by))
                .collect::<Vec<_>>()
                .join(", ")
        },
    });

    // Independent approval: one human, or two agents of distinct models.
    // "Distinct models" is the point — two instances of the same model
    // are one reviewer with extra steps.
    let mut human_approvals = Vec::new();
    let mut agent_models = Vec::new();
    for verdict in &verdicts {
        if verdict.disposition != Disposition::Approve || verdict.by == change.owner {
            continue;
        }
        let Some(principal) = raw::principal(conn, verdict.by.as_str())? else {
            continue;
        };
        match principal.kind {
            PrincipalKind::Human => human_approvals.push(verdict.by.as_str().to_owned()),
            PrincipalKind::Agent => {
                let model = principal.model.unwrap_or_else(|| principal.id.0.clone());
                if !agent_models.iter().any(|(m, _)| *m == model) {
                    agent_models.push((model, verdict.by.as_str().to_owned()));
                }
            }
        }
    }
    let independent = !human_approvals.is_empty() || agent_models.len() >= 2;
    requirements.push(Requirement {
        description:
            "approved independently of the owner: one human, or two agents of distinct models"
                .into(),
        satisfied: independent,
        evidence: format!(
            "human approvals: [{}]; agent approvals by model: [{}]",
            human_approvals.join(", "),
            agent_models
                .iter()
                .map(|(model, who)| format!("{who} ({model})"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    });

    Ok(PolicyTrace {
        satisfied: requirements.iter().all(|r| r.satisfied),
        requirements,
    })
}
